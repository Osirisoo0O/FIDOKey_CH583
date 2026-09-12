/**
 * @file secure_store.h
 * @brief 安全存储（DataFlash / EEPROM）接口，对应开发计划 2.5
 *
 * 物理约束（依据 Peripheral/ch58x/inc/ISP583.h 的说明，非推测）：
 *   - 地址是 DataFlash 内的偏移，范围 0 ~ 0x7FFF（EEPROM_MAX_SIZE = 0x8000）
 *   - 最小擦除单位 EEPROM_MIN_ER_SIZE = EEPROM_PAGE_SIZE = 256 字节
 *   - 写入最小 1 字节，但按 256 的倍数最好；EEPROM_READ/WRITE 的 Buffer
 *     必须 4 字节对齐
 *
 * 因此本模块把凭证槽固定为 2 页 = 512 字节并对齐放置，
 * 更新一条凭证只需擦除它自己那 2 页。
 *
 * 布局（偏移均相对 DataFlash 起点，见 flash_layout.h）：
 *
 *   0x0000  256B   头部：魔数 + 版本 + 盐值 + 密钥校验值
 *   0x0100  512B   凭证槽 0
 *   0x0300  512B   凭证槽 1
 *   ...
 *   最大槽号 SS_MAX_CRED_SLOTS-1，其末尾不超过 0x7E00（BLE SNV 起点，禁止越界）
 *
 * 私钥保护方式：由 UID + 盐值派生 AES-128 密钥（crypto_derive_storage_key），
 * 私钥在落盘前用该密钥加密，并按槽号做加扰以隐藏"相同私钥"。
 * 🔒 安全边界见 app_crypto.c：这是设备绑定，防的是"Flash 内容被拷到别的芯片"。
 */

#ifndef __SECURE_STORE_H
#define __SECURE_STORE_H

#include "stdint.h"

/* ---- 槽与容量 ---- */
#define SS_SLOT_SIZE            512                             /* 2 × 256 */
#define SS_HEADER_OFF           0x0000UL
#define SS_SLOTS_OFF            0x0100UL                        /* 256 对齐 */
#define SS_MAX_CRED_SLOTS       62                              /* 0x0100 + 62*512 = 0x7D00 ≤ 0x7E00 */

/* ---- 字段上限 ---- */
#define SS_CRED_ID_MAX          64
#define SS_USER_ID_MAX          64
#define SS_RP_ID_HASH_LEN       32
#define SS_PRIV_KEY_LEN         32
#define SS_PRIV_ENC_LEN         64                              /* 32B 私钥 → 2 个 AES 块 */

/* ---- 魔数 ---- */
#define SS_HDR_MAGIC            0x534B4559UL                    /* "SKEY" */
#define SS_CRED_MAGIC           0x43524544UL                    /* "CRED" */

/* 一条凭证记录（512 字节，字段顺序已保证无填充） */
typedef struct
{
    uint32_t magic;                                             /* SS_CRED_MAGIC 表示槽内有效 */
    uint32_t sign_count;                                        /* 签名计数器（计划 3.6） */
    uint8_t  cred_id[SS_CRED_ID_MAX];
    uint8_t  cred_id_len;
    uint8_t  rp_id_hash[SS_RP_ID_HASH_LEN];
    uint8_t  user_id[SS_USER_ID_MAX];
    uint8_t  user_id_len;
    uint8_t  priv_enc[SS_PRIV_ENC_LEN];                         /* AES 加密后的私钥 */
    uint8_t  pub_key[64];                                       /* X ‖ Y，未压缩 */
    uint8_t  reserved[214];                                     /* 补齐到 512 */
} ss_cred_t;

/**
 * @brief 初始化安全存储：读/建头部，派生并校验存储密钥
 * @return 0=成功, 负数=失败（-1 读失败, -2 头部损坏且重建失败, -3 密钥校验不通过）
 * @note  首次上电（头部魔数无效）会自动生成盐值并写入头部。
 */
int8_t secure_store_init(void);

/**
 * @brief 读取凭证槽
 * @param slot 槽号 0 ~ SS_MAX_CRED_SLOTS-1
 * @return 0=成功且槽内有效, 1=槽为空, 负数=失败
 */
int8_t secure_store_read_cred(uint16_t slot, ss_cred_t *rec);

/**
 * @brief 写入凭证槽（先擦除该槽的 2 页再写）
 * @return 0=成功, 负数=失败
 */
int8_t secure_store_write_cred(uint16_t slot, const ss_cred_t *rec);

/**
 * @brief 擦除凭证槽（写回全 0xFF）
 */
int8_t secure_store_erase_cred(uint16_t slot);

/**
 * @brief 用存储密钥加密 32 字节私钥（按槽号加扰），结果 64 字节
 * @note  供上层在构造 ss_cred_t 时使用
 */
int8_t secure_store_encrypt_priv(uint16_t slot, const uint8_t *priv32, uint8_t *out64);

/**
 * @brief 解密 ss_cred_t.priv_enc 得到 32 字节私钥
 */
int8_t secure_store_decrypt_priv(uint16_t slot, const ss_cred_t *rec, uint8_t *priv32);

/**
 * @brief 安全存储自测：写测试槽 → 读回比对 → 擦除
 * @return 0=通过, 负数=第几步失败
 * @note  使用最后一个槽，会破坏该槽原有内容（开发期自测用）。
 */
int8_t secure_store_selftest(void);

#endif /* __SECURE_STORE_H */
