/**
 * @file secure_store.c
 * @brief 安全存储实现（DataFlash / EEPROM），对应开发计划 2.5
 *
 * 物理约束全部来自 Peripheral/ch58x/inc/ISP583.h 的官方说明，未做假设：
 *   - EEPROM_MAX_SIZE = 0x8000，地址即 DataFlash 内字节偏移
 *   - EEPROM_MIN_ER_SIZE = EEPROM_PAGE_SIZE = 256（最小擦除单位）
 *   - EEPROM_MIN_WR_SIZE = 1（最小写 1 字节，256 的倍数最佳）
 *   - EEPROM_READ / EEPROM_WRITE 的 Buffer 必须 4 字节对齐
 *
 * 因此：头部占 1 页；每个凭证槽占 2 页（512B）且 256 对齐，
 * 更新一条凭证只擦它自己那 2 页，不波及其它记录。
 */

#include "config.h"
#include "stdint.h"
#include "string.h"
#include "flash_layout.h"
#include "secure_store.h"
#include "storage.h"
#include "app_crypto.h"

#define SS_PAGE_SIZE        ((uint32_t)EEPROM_PAGE_SIZE)        /* 256 */
#define SS_VERSION          0x0001UL

/* 头部字段偏移（占 1 页） */
#define SS_HDR_MAGIC_OFF    0
#define SS_HDR_VER_OFF      4
#define SS_HDR_SALT_OFF     8
#define SS_HDR_KEYCHK_OFF   24                                    /* salt(16) 之后 */

/* 密文区暂存：EEPROM 读写要求 4 字节对齐，统一经此中转 */
__attribute__((aligned(4))) static uint8_t ss_page[SS_PAGE_SIZE];
__attribute__((aligned(4))) static ss_cred_t ss_tmp;

static uint8_t ss_key[16];     /* 由 UID + 盐值派生的 AES-128 存储密钥 */
static uint8_t ss_ready = 0;

/* 当前存储后端；切换 SPI NOR 时只需改 secure_store_init 里的 storage_init 入参 */
#define SS_BE()   storage_get()

/* ---- 编译期自检 ---- */
/* 凭证槽结构必须刚好 512 字节（字段顺序已保证无填充） */
typedef char ss_cred_size_check[(sizeof(ss_cred_t) == SS_SLOT_SIZE) ? 1 : -1];
/* 最后一个槽的末尾绝不能越过 BLE SNV 的起点 0x7E00 */
typedef char ss_layout_check[((SS_SLOTS_OFF + (uint32_t)SS_MAX_CRED_SLOTS * SS_SLOT_SIZE)
                              <= FLASH_BLE_SNV_OFFSET) ? 1 : -1];

/*********************************************************************
 * @fn      ss_load_key
 *
 * @brief   由头部盐值派生存储密钥并校验
 */
static int8_t ss_load_key(void)
{
    uint8_t zeros[16];
    uint8_t chk[16];

    if(crypto_derive_storage_key(ss_page + SS_HDR_SALT_OFF, ss_key) != 0)
    {
        return -3;
    }

    memset(zeros, 0, sizeof(zeros));
    if(aes_encrypt(ss_key, zeros, chk) != 0)
    {
        return -3;
    }

    /* key_check 存的是 E_key(0^16)：对不上说明盐值/UID 变了 */
    if(memcmp(chk, ss_page + SS_HDR_KEYCHK_OFF, 16) != 0)
    {
        memset(ss_key, 0, sizeof(ss_key));
        return -3;
    }

    return 0;
}

/*********************************************************************
 * @fn      secure_store_init
 */
int8_t secure_store_init(void)
{
    uint32_t magic;
    uint32_t ver;
    uint8_t  zeros[16];
    uint8_t  chk[16];

    ss_ready = 0;

    /* 注册存储后端（当前为片内 DataFlash；换 SPI NOR 时改这一行） */
    if(storage_init(&g_storage_eeprom) != 0)
    {
        return -1;
    }

    /* 校验槽位布局与擦除粒度兼容 —— 这是迁移 SPI NOR 时最容易踩的地方：
     * 若槽大小不是擦除单位的整数倍，写一条记录会连带擦掉同一擦除单元里的其它记录。 */
    {
        const storage_backend_t *be = SS_BE();

        if(be == NULL)
        {
            return -1;
        }
        if((SS_SLOT_SIZE % be->erase_size) != 0 ||
           (SS_SLOTS_OFF % be->erase_size) != 0)
        {
            return -1;
        }
        if((SS_SLOTS_OFF + (uint32_t)SS_MAX_CRED_SLOTS * SS_SLOT_SIZE) > be->capacity)
        {
            return -1;
        }
    }

    if(SS_BE()->read(SS_HEADER_OFF, ss_page, SS_PAGE_SIZE) != 0)
    {
        return -1;
    }

    memcpy(&magic, ss_page + SS_HDR_MAGIC_OFF, 4);

    if(magic == SS_HDR_MAGIC)
    {
        /* 已有头部：直接派生并校验密钥 */
        if(ss_load_key() != 0)
        {
            return -3;
        }
        ss_ready = 1;
        return 0;
    }

    /* ---- 首次使用：生成盐值与密钥校验值，写入头部 ---- */
    memset(ss_page, 0xFF, SS_PAGE_SIZE);

    magic = SS_HDR_MAGIC;
    memcpy(ss_page + SS_HDR_MAGIC_OFF, &magic, 4);
    ver = SS_VERSION;
    memcpy(ss_page + SS_HDR_VER_OFF, &ver, 4);

    if(get_random_bytes(ss_page + SS_HDR_SALT_OFF, 16) != 0)
    {
        return -2;
    }

    if(crypto_derive_storage_key(ss_page + SS_HDR_SALT_OFF, ss_key) != 0)
    {
        return -2;
    }

    memset(zeros, 0, sizeof(zeros));
    if(aes_encrypt(ss_key, zeros, chk) != 0)
    {
        return -2;
    }
    memcpy(ss_page + SS_HDR_KEYCHK_OFF, chk, 16);

    if(SS_BE()->erase(SS_HEADER_OFF, SS_PAGE_SIZE) != 0)
    {
        return -2;
    }
    if(SS_BE()->write(SS_HEADER_OFF, ss_page, SS_PAGE_SIZE) != 0)
    {
        return -2;
    }

    ss_ready = 1;
    return 0;
}

/*********************************************************************
 * @fn      secure_store_read_cred
 */
int8_t secure_store_read_cred(uint16_t slot, ss_cred_t *rec)
{
    uint32_t addr;

    if(rec == NULL || slot >= SS_MAX_CRED_SLOTS)
    {
        return -1;
    }
    if(!ss_ready)
    {
        return -2;
    }

    addr = SS_SLOTS_OFF + (uint32_t)slot * SS_SLOT_SIZE;

    if(SS_BE()->read(addr, &ss_tmp, SS_SLOT_SIZE) != 0)
    {
        return -1;
    }
    if(ss_tmp.magic != SS_CRED_MAGIC)
    {
        return 1;               /* 空槽（擦除后是 0xFF） */
    }

    memcpy(rec, &ss_tmp, sizeof(ss_cred_t));
    return 0;
}

/*********************************************************************
 * @fn      secure_store_write_cred
 */
int8_t secure_store_write_cred(uint16_t slot, const ss_cred_t *rec)
{
    uint32_t addr;

    if(rec == NULL || slot >= SS_MAX_CRED_SLOTS)
    {
        return -1;
    }
    if(!ss_ready)
    {
        return -2;
    }

    addr = SS_SLOTS_OFF + (uint32_t)slot * SS_SLOT_SIZE;

    /* 经对齐中转缓冲拷贝，避免调用方缓冲未按 4 字节对齐 */
    memcpy(&ss_tmp, rec, sizeof(ss_cred_t));

    /* 先擦本槽的 2 页（256 的整数倍，符合最小擦除单位） */
    if(SS_BE()->erase(addr, SS_SLOT_SIZE) != 0)
    {
        return -3;
    }
    if(SS_BE()->write(addr, &ss_tmp, SS_SLOT_SIZE) != 0)
    {
        return -4;
    }

    /* 读回校验 */
    {
        uint32_t expect_magic = SS_CRED_MAGIC;
        if(SS_BE()->read(addr, &ss_tmp, SS_SLOT_SIZE) != 0)
        {
            return -5;
        }
        if(memcmp(&ss_tmp, rec, sizeof(ss_cred_t)) != 0 || ss_tmp.magic != expect_magic)
        {
            return -6;
        }
    }

    return 0;
}

/*********************************************************************
 * @fn      secure_store_erase_cred
 */
int8_t secure_store_erase_cred(uint16_t slot)
{
    uint32_t addr;

    if(slot >= SS_MAX_CRED_SLOTS)
    {
        return -1;
    }
    if(!ss_ready)
    {
        return -2;
    }

    addr = SS_SLOTS_OFF + (uint32_t)slot * SS_SLOT_SIZE;
    return (SS_BE()->erase(addr, SS_SLOT_SIZE) == 0) ? 0 : -3;
}

/*********************************************************************
 * @fn      secure_store_encrypt_priv
 *
 * @brief   用存储密钥加密 32 字节私钥，按槽号加扰
 *
 * @note    对每个 16 字节块先与 tweak = E_key(槽号填充) 异或再加密，
 *          这样同一份私钥落在不同槽位会得到不同密文，避免从 Flash 上
 *          直接看出"哪两条记录用了同一把私钥"。
 *          （纯 ECB 的固有问题，但 ECB 是 583 硬件唯一提供的模式。）
 */
int8_t secure_store_encrypt_priv(uint16_t slot, const uint8_t *priv32, uint8_t *out64)
{
    uint8_t blk[16];
    uint8_t tweak[16];
    uint8_t i;

    if(priv32 == NULL || out64 == NULL)
    {
        return -1;
    }
    if(!ss_ready)
    {
        return -2;
    }

    memset(blk, 0, sizeof(blk));
    blk[0] = (uint8_t)(slot & 0xFF);
    blk[1] = (uint8_t)(slot >> 8);
    if(aes_encrypt(ss_key, blk, tweak) != 0)
    {
        return -3;
    }

    for(i = 0; i < 16; i++)
    {
        blk[i] = (uint8_t)(priv32[i] ^ tweak[i]);
    }
    if(aes_encrypt(ss_key, blk, out64) != 0)
    {
        return -3;
    }

    for(i = 0; i < 16; i++)
    {
        blk[i] = (uint8_t)(priv32[16 + i] ^ tweak[i]);
    }
    if(aes_encrypt(ss_key, blk, out64 + 16) != 0)
    {
        return -3;
    }

    memset(blk, 0, sizeof(blk));
    memset(tweak, 0, sizeof(tweak));
    return 0;
}

/*********************************************************************
 * @fn      secure_store_decrypt_priv
 */
int8_t secure_store_decrypt_priv(uint16_t slot, const ss_cred_t *rec, uint8_t *priv32)
{
    uint8_t blk[16];
    uint8_t tweak[16];
    uint8_t plain[16];
    uint8_t i;

    if(rec == NULL || priv32 == NULL)
    {
        return -1;
    }
    if(!ss_ready)
    {
        return -2;
    }

    memset(blk, 0, sizeof(blk));
    blk[0] = (uint8_t)(slot & 0xFF);
    blk[1] = (uint8_t)(slot >> 8);
    if(aes_encrypt(ss_key, blk, tweak) != 0)
    {
        return -3;
    }

    if(aes_decrypt(ss_key, rec->priv_enc, plain) != 0)
    {
        return -3;
    }
    for(i = 0; i < 16; i++)
    {
        priv32[i] = (uint8_t)(plain[i] ^ tweak[i]);
    }

    if(aes_decrypt(ss_key, rec->priv_enc + 16, plain) != 0)
    {
        return -3;
    }
    for(i = 0; i < 16; i++)
    {
        priv32[16 + i] = (uint8_t)(plain[i] ^ tweak[i]);
    }

    memset(plain, 0, sizeof(plain));
    memset(tweak, 0, sizeof(tweak));
    return 0;
}

/*********************************************************************
 * @fn      secure_store_selftest
 */
int8_t secure_store_selftest(void)
{
    ss_cred_t rec;
    ss_cred_t back;
    uint8_t   priv[SS_PRIV_KEY_LEN];
    uint8_t   priv2[SS_PRIV_KEY_LEN];
    uint16_t  slot = SS_MAX_CRED_SLOTS - 1;      /* 用最后一个槽做测试 */
    uint8_t   i;

    if(!ss_ready)
    {
        return -1;
    }

    memset(&rec, 0, sizeof(rec));
    rec.magic = SS_CRED_MAGIC;
    rec.sign_count = 0x12345678UL;
    rec.cred_id_len = 16;
    rec.user_id_len = 8;
    for(i = 0; i < 16; i++)
    {
        rec.cred_id[i] = (uint8_t)(0xA0 + i);
    }
    for(i = 0; i < SS_RP_ID_HASH_LEN; i++)
    {
        rec.rp_id_hash[i] = (uint8_t)(i ^ 0x5A);
    }
    for(i = 0; i < 8; i++)
    {
        rec.user_id[i] = (uint8_t)(0x10 + i);
    }
    for(i = 0; i < 64; i++)
    {
        rec.pub_key[i] = (uint8_t)(0x30 + i);
    }
    for(i = 0; i < SS_PRIV_KEY_LEN; i++)
    {
        priv[i] = (uint8_t)(i * 7 + 1);
    }

    /* 1) 私钥加密 */
    if(secure_store_encrypt_priv(slot, priv, rec.priv_enc) != 0)
    {
        return -2;
    }
    /* 2) 写入 */
    if(secure_store_write_cred(slot, &rec) != 0)
    {
        return -3;
    }
    /* 3) 读回 */
    if(secure_store_read_cred(slot, &back) != 0)
    {
        return -4;
    }
    /* 4) 整条记录一致 */
    if(memcmp(&rec, &back, sizeof(ss_cred_t)) != 0)
    {
        return -5;
    }
    /* 5) 私钥解密还原 */
    if(secure_store_decrypt_priv(slot, &back, priv2) != 0)
    {
        return -6;
    }
    if(memcmp(priv, priv2, SS_PRIV_KEY_LEN) != 0)
    {
        return -7;
    }
    /* 6) 擦除后应识别为空槽 */
    if(secure_store_erase_cred(slot) != 0)
    {
        return -8;
    }
    if(secure_store_read_cred(slot, &back) != 1)
    {
        return -9;
    }

    return 0;
}
