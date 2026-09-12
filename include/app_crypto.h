/********************************** (C) COPYRIGHT *******************************
 * File Name          : app_crypto.h
 * Author             : SecureKey
 * Version            : V1.0
 * Date               : 2024/01/01
 * Description        : 核心加密与安全模块接口
 *******************************************************************************/

#ifndef _APP_CRYPTO_H
#define _APP_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

// AAGUID (16 bytes - 自定义认证器GUID)
extern const uint8_t g_aaguid[16];

/**
 * @brief 初始化加密模块
 * @return 0=成功, 其他=失败
 */
int8_t crypto_init(void);

/**
 * @brief 生成随机字节
 *
 * @note CH583 无硬件 TRNG，本函数用 tmos_rand() + ADC 采样抖动 +
 *       SysTick + 递增计数器 多源混合后扩散输出（实现见 app_crypto.c）。
 *       **不是密码学安全的真随机源**，私钥熵上限取决于 tmos_rand() 的熵池；
 *       商用/过认证建议外挂安全元件或换带硬件 TRNG 的型号。
 *
 * @param buf 输出缓冲区
 * @param len 长度（必须<=64字节）
 * @return 0=成功, -1=参数错误
 */
int8_t get_random_bytes(uint8_t *buf, uint8_t len);

/**
 * @brief 读取芯片UID
 * @param uid 输出缓冲区（必须≥12字节）
 * @return 0=成功
 */
int8_t read_chip_uid(uint8_t *uid);

/**
 * @brief 由芯片 UID + 盐值派生 AES-128 存储密钥（计划 2.3）
 *
 *        K = SHA-256( UID(12B) || salt(16B) ) 前 16 字节
 *
 * @note 安全边界见 app_crypto.c 中的详细说明：这是"设备绑定"，
 *       防"Flash 内容被拷到另一颗芯片"，防不住"拿到 Flash 就能解密"。
 *
 * @param salt 16 字节盐值
 * @param key  输出 16 字节密钥
 * @return 0=成功, -1=参数错误, -2=UID 尚未读取, -3=哈希失败
 */
int8_t crypto_derive_storage_key(const uint8_t *salt, uint8_t *key);

/*********************************************************************
 * AES-128（CH583 内置硬件加解密单元，经 BLE 库 LL_Encrypt/LL_Decrypt 调用）
 *
 * 前置条件：必须先完成 CH58X_BLEInit() 与 crypto_init()，
 *           否则返回 -2（BLE 库未初始化）。
 * 对齐：参数经内部 aligned(16) 静态缓冲中转，调用方无需关心对齐。
 * 可重入性：内部使用静态缓冲，**不可重入**，勿在中断中调用。
 */

/**
 * @brief AES-128 加密单个 16 字节块
 * @return 0=成功, -1=参数错误, -2=BLE 库未初始化, -3=硬件 AES 返回错误
 */
int8_t aes_encrypt(const uint8_t *key, const uint8_t *plaintext, uint8_t *ciphertext);

/**
 * @brief AES-128 解密单个 16 字节块
 * @return 0=成功, -1=参数错误, -2=BLE 库未初始化, -3=硬件 AES 返回错误
 */
int8_t aes_decrypt(const uint8_t *key, const uint8_t *ciphertext, uint8_t *plaintext);

/**
 * @brief AES-128 逐块 ECB 加密多个块（len 必须为 16 的整数倍，允许原地）
 * @note  纯 ECB 下相同明文块产生相同密文块，多块数据请先做位置相关加扰（见计划 2.5）
 */
int8_t aes_encrypt_blocks(const uint8_t *key, const uint8_t *in, uint8_t *out, uint16_t len);

/**
 * @brief AES-128 逐块 ECB 解密多个块（len 必须为 16 的整数倍，允许原地）
 */
int8_t aes_decrypt_blocks(const uint8_t *key, const uint8_t *in, uint8_t *out, uint16_t len);

/**
 * @brief AES 硬件自测（FIPS-197 附录 B 已知向量），供开发自检用（计划 5.1）
 * @return 0=通过, -1=AES 调用失败, -2=结果不符
 */
int8_t aes_selftest(void);

/**
 * @brief SHA-256哈希
 * @param data 输入数据
 * @param len 数据长度
 * @param hash 输出哈希（32字节）
 * @return 0=成功
 */
int8_t sha256(const uint8_t *data, uint32_t len, uint8_t *hash);

/**
 * @brief SHA-256 自测（NIST 标准向量：""/"abc"/56 字节串），供开发自检（计划 5.1）
 * @return 0=通过, -1=调用失败, 负数=与向量不符
 */
int8_t sha256_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* _APP_CRYPTO_H */
