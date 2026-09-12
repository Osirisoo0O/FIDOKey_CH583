/********************************** (C) COPYRIGHT *******************************
 * File Name          : app_crypto.c
 * Author             : SecureKey
 * Version            : V1.0
 * Date               : 2024/01/01
 * Description        : 核心加密与安全模块实现
 *******************************************************************************/

#include "config.h"
#include "stdint.h"
#include "stdbool.h"
#include "string.h"
#include "app_crypto.h"

// 外部函数声明（来自BLE_LIB）
extern uint32_t tmos_rand(void);
extern bStatus_t LL_Encrypt(uint8_t *key, uint8_t *plaintextData, uint8_t *encryptData);
extern bStatus_t LL_Decrypt(uint8_t *key, uint8_t *plaintextData, uint8_t *decryptData);

// AAGUID (16字节 - 自定义认证器GUID)
const uint8_t g_aaguid[16] = {
    0xA9, 0x5E, 0x8F, 0x3A, 0x1B, 0x2C, 0x4D, 0x6E,
    0x7F, 0x8A, 0x9B, 0x0C, 0x1D, 0x2E, 0x3F, 0x40
};

// 芯片UID存储
static uint8_t g_chip_uid[12];
static uint8_t g_uid_read_done = 0;

/**
 * @brief 简单的SHA-256实现（使用CH583的硬件SHA模块或软件实现）
 * @note CH583无硬件SHA，使用纯软件实现
 */
/* SHA-256 轮常量 K[0..63] */
static const uint32_t sha256_k[64] = {
    0x428A2F98UL, 0x71374491UL, 0xB5C0FBCFUL, 0xE9B5DBA5UL,
    0x3956C25BUL, 0x59F111F1UL, 0x923F82A4UL, 0xAB1C5ED5UL,
    0xD807AA98UL, 0x12835B01UL, 0x243185BEUL, 0x550C7DC3UL,
    0x72BE5D74UL, 0x80DEB1FEUL, 0x9BDC06A7UL, 0xC19BF174UL,
    0xE49B69C1UL, 0xEFBE4786UL, 0x0FC19DC6UL, 0x240CA1CCUL,
    0x2DE92C6FUL, 0x4A7484AAUL, 0x5CB0A9DCUL, 0x76F988DAUL,
    0x983E5152UL, 0xA831C66DUL, 0xB00327C8UL, 0xBF597FC7UL,
    0xC6E00BF3UL, 0xD5A79147UL, 0x06CA6351UL, 0x14292967UL,
    0x27B70A85UL, 0x2E1B2138UL, 0x4D2C6DFCUL, 0x53380D13UL,
    0x650A7354UL, 0x766A0ABBUL, 0x81C2C92EUL, 0x92722C85UL,
    0xA2BFE8A1UL, 0xA81A664BUL, 0xC24B8B70UL, 0xC76C51A3UL,
    0xD192E819UL, 0xD6990624UL, 0xF40E3585UL, 0x106AA070UL,
    0x19A4C116UL, 0x1E376C08UL, 0x2748774CUL, 0x34B0BCB5UL,
    0x391C0CB3UL, 0x4ED8AA4AUL, 0x5B9CCA4FUL, 0x682E6FF3UL,
    0x748F82EEUL, 0x78A5636FUL, 0x84C87814UL, 0x8CC70208UL,
    0x90BEFFFAUL, 0xA4506CEBUL, 0xBEF9A3F7UL, 0xC67178F2UL
};

#define SHA256_ROTR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))

/**
 * @brief SHA-256 压缩函数：处理一个 64 字节块
 *
 * @note  原实现有两个致命错误，已重写：
 *        1) 压缩循环里每轮都使用同一个常量 0x428A2F98，而不是 K[i]；
 *        2) 填充部分的长度域位置按 pad_len-4 计算，不是固定的末尾 8 字节。
 */
static void sha256_transform(uint32_t *state, const uint8_t *block) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    uint8_t  i;

    for(i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
    }
    for(i = 16; i < 64; i++) {
        uint32_t s0 = SHA256_ROTR(w[i - 15], 7) ^ SHA256_ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = SHA256_ROTR(w[i - 2], 17) ^ SHA256_ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for(i = 0; i < 64; i++) {
        uint32_t S1 = SHA256_ROTR(e, 6) ^ SHA256_ROTR(e, 11) ^ SHA256_ROTR(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t S0 = SHA256_ROTR(a, 2) ^ SHA256_ROTR(a, 13) ^ SHA256_ROTR(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);

        t1 = h + S1 + ch + sha256_k[i] + w[i];
        t2 = S0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/**
 * @brief SHA-256 哈希（FIPS 180-4，纯软件实现；CH583 无硬件 SHA）
 *
 * @param data 输入数据（len 为 0 时允许为 NULL）
 * @param len  输入字节数
 * @param hash 输出 32 字节摘要
 * @return 0=成功, -1=参数错误
 *
 * @note 已用 NIST 标准向量自测，见 sha256_selftest()。
 */
int8_t sha256(const uint8_t *data, uint32_t len, uint8_t *hash) {
    uint32_t state[8];
    uint8_t  block[64];
    uint32_t i;
    uint32_t rem;
    uint32_t bits_hi;
    uint32_t bits_lo;

    if(hash == NULL || (data == NULL && len != 0)) {
        return -1;
    }

    state[0] = 0x6A09E667UL; state[1] = 0xBB67AE85UL;
    state[2] = 0x3C6EF372UL; state[3] = 0xA54FF53AUL;
    state[4] = 0x510E527FUL; state[5] = 0x9B05688CUL;
    state[6] = 0x1F83D9ABUL; state[7] = 0x5BE0CD19UL;

    /* 1) 只处理完整的 64 字节块，剩余部分留给填充阶段 */
    for(i = 0; (i + 64) <= len; i += 64) {
        sha256_transform(state, data + i);
    }

    /* 2) 尾部剩余数据 + 填充 0x80 */
    rem = len - i;
    memset(block, 0, sizeof(block));
    if(rem != 0) {
        memcpy(block, data + i, rem);
    }
    block[rem] = 0x80;

    /* 剩余空间放不下 8 字节长度域时（rem >= 56），先补一个整块 */
    if(rem >= 56) {
        sha256_transform(state, block);
        memset(block, 0, sizeof(block));
    }

    /* 3) 末尾 8 字节写入原始比特长度（大端，高 32 位在前） */
    bits_hi = len >> 29;        /* (len * 8) >> 32 */
    bits_lo = len << 3;         /* (len * 8) & 0xFFFFFFFF */
    block[56] = (uint8_t)(bits_hi >> 24);
    block[57] = (uint8_t)(bits_hi >> 16);
    block[58] = (uint8_t)(bits_hi >> 8);
    block[59] = (uint8_t)(bits_hi);
    block[60] = (uint8_t)(bits_lo >> 24);
    block[61] = (uint8_t)(bits_lo >> 16);
    block[62] = (uint8_t)(bits_lo >> 8);
    block[63] = (uint8_t)(bits_lo);
    sha256_transform(state, block);

    /* 4) 输出摘要（大端） */
    for(i = 0; i < 8; i++) {
        hash[i * 4]     = (uint8_t)(state[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)(state[i]);
    }

    return 0;
}

/**
 * @brief SHA-256 自测（NIST 标准向量）
 *
 *   ""                                                     -> e3b0c442...
 *   "abc"                                                  -> ba7816bf...
 *   "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (56B) -> 248d6a61...
 *
 * @note 第三个向量长度恰好 56 字节，rem >= 56 需要补两个块，
 *       专门用来覆盖原实现算错的那个填充边界。
 *
 * @return 0=通过, -1=调用失败, 负数=与向量不符
 */
int8_t sha256_selftest(void) {
    static const uint8_t exp_empty[32] = {
        0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14,
        0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
        0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C,
        0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55
    };
    static const uint8_t exp_abc[32] = {
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
        0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
        0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
        0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
    };
    static const uint8_t exp_56[32] = {
        0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8,
        0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39,
        0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67,
        0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1
    };
    static const char vec56[] =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t out[32];

    if(sha256(NULL, 0, out) != 0)            { return -1; }
    if(memcmp(out, exp_empty, 32) != 0)      { return -2; }

    if(sha256((const uint8_t *)"abc", 3, out) != 0) { return -1; }
    if(memcmp(out, exp_abc, 32) != 0)        { return -3; }

    if(sha256((const uint8_t *)vec56, 56, out) != 0) { return -1; }
    if(memcmp(out, exp_56, 32) != 0)         { return -4; }

    return 0;
}

/**
 * @brief 初始化加密模块
 */
/* ---------------- AES-128 硬件加解密封装 ----------------
 *
 * 约束与注意事项：
 *  1) LL_Encrypt/LL_Decrypt 来自 BLE 库(libCH58xBLE.a)，必须在 CH58X_BLEInit()
 *     之后才能调用；crypto_init() 置位 crypto_ready 作为调用闸门。
 *  2) 两者都是单块 AES-128(16 字节)。WCH 头文件未写明参数对齐要求，
 *     这里统一经 __attribute__((aligned(16))) 的静态中转缓冲，
 *     无论真实要求是 4 还是 16 字节都满足。
 *  3) 因为用了静态缓冲，本模块**不可重入**：所有 AES 调用都应在主循环
 *     上下文完成，不要从 USB/BLE 中断里调用。
 *  4) 若将来在 BLE 已连接状态下调用 AES 出现异常，需考虑与 BLE 协议栈
 *     自身 AES 运算的资源竞争（LE 加密链路也用同一硬件单元）。
 */
__attribute__((aligned(16))) static uint8_t aes_key_buf[16];
__attribute__((aligned(16))) static uint8_t aes_in_buf[16];
__attribute__((aligned(16))) static uint8_t aes_out_buf[16];

/* AES 可用性闸门：0=BLE 库未初始化 */
static uint8_t crypto_ready = 0;

/**
 * @brief 初始化加密模块
 * @note  必须在 CH58X_BLEInit() 之后调用：AES 接口以本函数置位的
 *        crypto_ready 为前置条件，未初始化时 aes_encrypt/aes_decrypt 返回 -2。
 */
int8_t crypto_init(void) {
    // 读取芯片UID（安全存储的密钥派生会用到，见开发计划 2.3 / 2.5）
    read_chip_uid(g_chip_uid);
    g_uid_read_done = 1;

    // 打开 AES 闸门
    crypto_ready = 1;


    return 0;
}

/**
 * @brief 从 ADC 内部温度传感器采样中提取低位热噪声
 *
 * @note  CH583 **没有硬件 TRNG**：SDK 未暴露任何 RNG 寄存器，
 *        Peripheral/ch58x 下也没有 rng 驱动（只有 clk/uart/gpio/i2c/flash/
 *        pwr/pwm/adc/sys/timer/spi/usb 这些模块）。因此这里用 ADC 采样抖动
 *        作为"物理熵"来源，它只有最低若干位真正带噪声，必须与其它来源混合后再使用。
 */
static uint32_t rng_adc_noise(void)
{
    uint8_t  saved_cfg;
    uint8_t  saved_ch;
    uint8_t  saved_ts;
    uint32_t acc = 0;
    uint8_t  i;

    /* 保存并恢复 ADC 配置，避免破坏其它模块（例如 BLE 的温度漂移校准）的设置 */
    saved_cfg = R8_ADC_CFG;
    saved_ch  = R8_ADC_CHANNEL;
    saved_ts  = R8_TEM_SENSOR;

    ADC_InterTSSampInit();
    for(i = 0; i < 8; i++)
    {
        R8_ADC_CONVERT |= RB_ADC_START;
        while(R8_ADC_CONVERT & RB_ADC_START)
        {
            ;
        }
        acc = (acc << 4) ^ ((uint32_t)R16_ADC_DATA) ^ SYS_GetSysTickCnt();
    }

    R8_TEM_SENSOR  = saved_ts;
    R8_ADC_CHANNEL = saved_ch;
    R8_ADC_CFG     = saved_cfg;

    return acc;
}

/**
 * @brief xorshift32 扩散，避免直接输出底层序列
 */
static uint32_t rng_mix(uint32_t x)
{
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
}

/**
 * @brief 生成随机字节
 *
 * @note  **熵源与安全边界**：
 *        CH583 无硬件 TRNG，本函数采用多源混合：
 *          1) tmos_rand()        —— BLE 库伪随机（由 SysTick 播种）
 *          2) ADC 采样抖动        —— 热噪声（本次调用采一次，供每个 4 字节块复用）
 *          3) SYS_GetSysTickCnt() —— 调用时刻的时钟抖动
 *          4) 递增计数器          —— 保证重复调用不会得到相同序列
 *        混合后经两轮 xorshift32 扩散再输出。
 *
 *        ⚠️ 这不是密码学安全的真随机源。用于 FIDO2 私钥生成时熵的**质量上限取决于
 *        tmos_rand() 的熵池**，而不取决于本函数。若该产品要正式商用/过认证，
 *        应考虑外挂安全元件（SE）或换用带硬件 TRNG 的型号。
 *
 * @param buf 输出缓冲区
 * @param len 长度（必须 <= 64 字节）
 * @return 0=成功, -1=参数错误
 */
int8_t get_random_bytes(uint8_t *buf, uint8_t len) {
    static uint32_t rng_counter = 0;
    uint32_t noise;
    uint32_t v;
    uint8_t  n;
    uint8_t  i;

    if(buf == NULL || len == 0 || len > 64)
    {
        return -1;
    }

    noise = rng_adc_noise();

    for(i = 0; i < len; i += 4)
    {
        n = (uint8_t)(((len - i) < 4) ? (len - i) : 4);

        v  = tmos_rand();
        v ^= noise;
        v ^= SYS_GetSysTickCnt();
        v ^= (++rng_counter * 0x9E3779B9UL);

        v = rng_mix(v);
        v = rng_mix(v);

        memcpy(buf + i, &v, n);
    }

    return 0;
}

/**
 * @brief 读取芯片UID
 */
int8_t read_chip_uid(uint8_t *uid) {
    __attribute__((aligned(4))) uint8_t rom_info[8];

    // CH583 没有 0x1FFFF000 这类系统信息区(那是 CH32V/Cortex-M 系列的地址)，
    // 按指针访问未映射地址可能触发总线异常并卡死在异常处理里，
    // 使已使能的 USB 中断无法响应 -> Windows 报“请求 USB 设备描述符失败”(代码 43)。
    // 改用 SDK 提供的 GET_UNIQUE_ID()（内部通过 FLASH_EEPROM_CMD 读 ROM 配置区，8 字节）。
    GET_UNIQUE_ID(rom_info);
    memcpy(uid, rom_info, 8);
    memset(uid + 8, 0, 4);

    return 0;
}


/**
 * @brief 由芯片唯一 ID 与盐值派生 AES-128 存储密钥（开发计划 2.3）
 *
 *        K = SHA-256( UID(12B) ‖ salt(16B) ) 的前 16 字节
 *
 * @param salt 16 字节盐值（存放于 DataFlash，见 flash_layout.h）
 * @param key  输出 16 字节 AES-128 密钥
 * @return 0=成功, -1=参数错误, -2=UID 尚未读取, -3=哈希失败
 *
 * @note  🔒 **安全边界**：这是"设备绑定"而不是"口令绑定"——
 *        UID 由 GET_UNIQUE_ID() 读出、对同一颗芯片固定，知道 UID 和盐值的人
 *        可以重算出密钥。因此本方案防的是"把 DataFlash 内容整体拷到另一颗芯片
 *        上解密"，**防不住**"拿到 Flash 内容就能解密"。
 *        要更强需要引入不可导出的主密钥（由 TRNG 生成并存于受保护区），
 *        而 CH583 无硬件 TRNG（见计划 2.1 的记录），此处如实标注该限制。
 */
int8_t crypto_derive_storage_key(const uint8_t *salt, uint8_t *key) {
    uint8_t material[12 + 16];
    uint8_t digest[32];

    if(salt == NULL || key == NULL) {
        return -1;
    }
    if(!g_uid_read_done) {
        return -2;
    }

    memcpy(material, g_chip_uid, 12);
    memcpy(material + 12, salt, 16);

    if(sha256(material, (uint32_t)sizeof(material), digest) != 0) {
        return -3;
    }

    memcpy(key, digest, 16);

    /* 不把中间值留在栈上 */
    memset(digest, 0, sizeof(digest));
    memset(material, 0, sizeof(material));

    return 0;
}

/**
 * @brief AES-128加密
 */
/**
 * @brief AES-128 加密单个 16 字节块（硬件 AES）
 * @param key        密钥（16 字节）
 * @param plaintext  明文（16 字节）
 * @param ciphertext 密文输出（16 字节）
 * @return 0=成功, -1=参数错误, -2=BLE 库未初始化, -3=硬件 AES 返回错误
 */
int8_t aes_encrypt(const uint8_t *key, const uint8_t *plaintext, uint8_t *ciphertext) {
    bStatus_t status;

    if(key == NULL || plaintext == NULL || ciphertext == NULL) {
        return -1;
    }
    if(!crypto_ready) {
        return -2;
    }

    memcpy(aes_key_buf, key, 16);
    memcpy(aes_in_buf, plaintext, 16);

    status = LL_Encrypt(aes_key_buf, aes_in_buf, aes_out_buf);
    if(status != SUCCESS) {
        return -3;
    }

    memcpy(ciphertext, aes_out_buf, 16);
    return 0;
}

/**
 * @brief AES-128 加密多个 16 字节块（逐块 ECB）
 * @param key 密钥（16 字节）
 * @param in  输入（长度为 16 的整数倍）
 * @param out 输出；允许 in == out 原地操作
 * @param len 字节数，必须为 16 的整数倍且 > 0
 * @return 0=成功, 其它=失败（见 aes_encrypt）
 *
 * @note 纯 ECB 模式下**相同的明文块会产生相同的密文块**。
 *       多块数据在调用前应对每块做与位置相关的加扰，
 *       具体的存储加密方案见开发计划 2.5。
 */
int8_t aes_encrypt_blocks(const uint8_t *key, const uint8_t *in, uint8_t *out, uint16_t len) {
    uint16_t off;

    if(key == NULL || in == NULL || out == NULL) {
        return -1;
    }
    if(len == 0 || (len % 16) != 0) {
        return -1;
    }

    for(off = 0; off < len; off += 16) {
        int8_t r = aes_encrypt(key, in + off, out + off);
        if(r != 0) {
            return r;
        }
    }
    return 0;
}

/**
 * @brief AES-128解密
 */
/**
 * @brief AES-128 解密单个 16 字节块（硬件 AES）
 * @return 0=成功, -1=参数错误, -2=BLE 库未初始化, -3=硬件 AES 返回错误
 */
int8_t aes_decrypt(const uint8_t *key, const uint8_t *ciphertext, uint8_t *plaintext) {
    bStatus_t status;

    if(key == NULL || ciphertext == NULL || plaintext == NULL) {
        return -1;
    }
    if(!crypto_ready) {
        return -2;
    }

    memcpy(aes_key_buf, key, 16);
    memcpy(aes_in_buf, ciphertext, 16);

    status = LL_Decrypt(aes_key_buf, aes_in_buf, aes_out_buf);
    if(status != SUCCESS) {
        return -3;
    }

    memcpy(plaintext, aes_out_buf, 16);
    return 0;
}

/**
 * @brief AES-128 解密多个 16 字节块（逐块 ECB），允许 in == out
 */
int8_t aes_decrypt_blocks(const uint8_t *key, const uint8_t *in, uint8_t *out, uint16_t len) {
    uint16_t off;

    if(key == NULL || in == NULL || out == NULL) {
        return -1;
    }
    if(len == 0 || (len % 16) != 0) {
        return -1;
    }

    for(off = 0; off < len; off += 16) {
        int8_t r = aes_decrypt(key, in + off, out + off);
        if(r != 0) {
            return r;
        }
    }
    return 0;
}

/**
 * @brief AES 硬件自测（FIPS-197 附录 B 的 AES-128 已知向量）
 *
 *   key        = 000102030405060708090a0b0c0d0e0f
 *   plaintext  = 00112233445566778899aabbccddeeff
 *   ciphertext = 69c4e0d86a7b0430d8cdb78070b4c55a
 *
 * @return 0=通过, -1=AES 调用失败, -2=结果与已知向量不符
 * @note  供开发阶段自检使用（计划 5.1），启动流程默认不调用。
 */
int8_t aes_selftest(void) {
    static const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    static const uint8_t plain[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };
    static const uint8_t expect[16] = {
        0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30,
        0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A
    };
    uint8_t out[16];
    uint8_t back[16];

    if(aes_encrypt(key, plain, out) != 0) {
        return -1;
    }
    if(memcmp(out, expect, 16) != 0) {
        return -2;
    }
    /* 顺带验证解密（链路对称性） */
    if(aes_decrypt(key, out, back) != 0) {
        return -1;
    }
    if(memcmp(back, plain, 16) != 0) {
        return -2;
    }
    return 0;
}
