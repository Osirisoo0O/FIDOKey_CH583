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
static void sha256_transform(uint32_t *state, const uint8_t *data) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    
    // 准备调度表
    for (uint8_t i = 0; i < 16; i++) {
        w[i] = (uint32_t)data[i*4] << 24 | (uint32_t)data[i*4+1] << 16 |
               (uint32_t)data[i*4+2] << 8 | (uint32_t)data[i*4+3];
    }
    for (uint8_t i = 16; i < 64; i++) {
        uint32_t s0 = ((w[i-15] >> 7) | (w[i-15] << 25)) ^ 
                      ((w[i-15] >> 18) | (w[i-15] << 14)) ^ (w[i-15] >> 3);
        uint32_t s1 = ((w[i-2] >> 17) | (w[i-2] << 15)) ^ 
                      ((w[i-2] >> 19) | (w[i-2] << 13)) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    
    // 初始哈希值
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    
    // 压缩函数
    for (uint8_t i = 0; i < 64; i++) {
        uint32_t s1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7));
        uint32_t ch = (e & f) ^ (~e & g);
        t1 = h + s1 + ch + 0x428A2F98 + w[i];
        uint32_t s0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10));
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = s0 + maj;
        
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

int8_t sha256(const uint8_t *data, uint32_t len, uint8_t *hash) {
    uint32_t state[8];
    uint32_t bit_len;
    uint32_t pad_len;
    
    // 初始哈希值（SHA-256标准）
    state[0] = 0x6A09E667; state[1] = 0xBB67AE85;
    state[2] = 0x3C6EF372; state[3] = 0xA54FF53A;
    state[4] = 0x510E527F; state[5] = 0x9B05688C;
    state[6] = 0x1F83D9AB; state[7] = 0x5BE0CD19;
    
    // 处理数据
    for (uint32_t i = 0; i < len; i += 64) {
        uint32_t chunk = (len - i) < 64 ? (len - i) : 64;
        uint8_t block[64];
        memset(block, 0, 64);
        memcpy(block, data + i, chunk);
        sha256_transform(state, block);
    }
    
    // 填充
    uint8_t pad[128]; // 最大128字节（两个块）
    memset(pad, 0, sizeof(pad));
    
    bit_len = len * 8;
    pad_len = 64 - (len % 64);
    if (pad_len == 64) pad_len = 128; // 需要额外的块
    
    // 复制剩余数据
    uint32_t remainder = len % 64;
    if (remainder > 0) {
        memcpy(pad, data + (len - remainder), remainder);
    }
    pad[remainder] = 0x80; // 填充字节
    
    // 在末尾添加64位原始长度
    uint32_t *last_word = (uint32_t *)(pad + pad_len - 4);
    *last_word = bit_len;
    
    // 处理填充块
    for (uint32_t i = 0; i < pad_len; i += 64) {
        sha256_transform(state, pad + i);
    }
    
    // 输出哈希
    for (uint8_t i = 0; i < 8; i++) {
        hash[i*4] = (state[i] >> 24) & 0xFF;
        hash[i*4+1] = (state[i] >> 16) & 0xFF;
        hash[i*4+2] = (state[i] >> 8) & 0xFF;
        hash[i*4+3] = state[i] & 0xFF;
    }
    
    return 0;
}

/**
 * @brief 初始化加密模块
 */
int8_t crypto_init(void) {
    // 读取芯片UID
    read_chip_uid(g_chip_uid);
    g_uid_read_done = 1;
    
    // 初始化随机数种子
    // tmos_rand()已经由TMOS初始化
    return 0;
}

/**
 * @brief 生成随机字节
 */
int8_t get_random_bytes(uint8_t *buf, uint8_t len) {
    if (len > 64) return -1;
    
    uint32_t rand_val;
    for (uint8_t i = 0; i < len; i += 4) {
        rand_val = tmos_rand();
        uint8_t copy_len = (len - i) < 4 ? (len - i) : 4;
        memcpy(buf, &rand_val, copy_len);
        buf += copy_len;
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
 * @brief AES-128加密
 */
int8_t aes_encrypt(const uint8_t *key, const uint8_t *plaintext, uint8_t *ciphertext) {
    bStatus_t status = LL_Encrypt((uint8_t *)key, (uint8_t *)plaintext, ciphertext);
    return (status == SUCCESS) ? 0 : -1;
}

/**
 * @brief AES-128解密
 */
int8_t aes_decrypt(const uint8_t *key, const uint8_t *ciphertext, uint8_t *plaintext) {
    bStatus_t status = LL_Decrypt((uint8_t *)key, (uint8_t *)ciphertext, plaintext);
    return (status == SUCCESS) ? 0 : -1;
}
