/**
 * @file app_ecdsa.h
 * @brief ECDSA P-256（secp256r1）接口，基于 lib/micro-ecc
 *
 * 对应开发计划 2.4。
 *
 * 数据布局（与 FIDO2/CTAP2 的 COSE_Key / ES256 一致）：
 *   private_key : 32 字节标量 d
 *   public_key  : 64 字节 X ‖ Y（未压缩点，去掉 0x04 前缀）
 *   hash        : 32 字节（SHA-256）
 *   signature   : r ‖ s，各 32 字节（CTAP2 要求大端定长，无 DER 包装）
 *
 * ⚠️ 密钥与签名均依赖 RNG 的熵质量——CH583 无硬件 TRNG，
 *    熵的上限见 app_crypto.c 中 get_random_bytes() 的说明。
 */

#ifndef __APP_ECDSA_H
#define __APP_ECDSA_H

#include "stdint.h"

#define ECDSA_P256_PRIV_LEN     32
#define ECDSA_P256_PUB_LEN      64      /* X ‖ Y */
#define ECDSA_P256_SIG_LEN      64      /* r ‖ s */
#define ECDSA_P256_HASH_LEN     32

/**
 * @brief 初始化 ECDSA 模块（把 micro-ecc 的 RNG 挂到 get_random_bytes）
 * @note  必须在 crypto_init() 之后调用：RNG 依赖加密模块。
 * @return 0=成功
 */
int8_t ecdsa_init(void);

/**
 * @brief 生成 P-256 密钥对
 * @param private_key 输出 32 字节私钥
 * @param public_key  输出 64 字节公钥（X ‖ Y）
 * @return 0=成功, -1=参数错误, -2=未初始化, -3=micro-ecc 失败
 */
int8_t ecdsa_generate_keypair(uint8_t *private_key, uint8_t *public_key);

/**
 * @brief 由私钥推导公钥（确定性，可用于自检与去重）
 */
int8_t ecdsa_compute_public_key(const uint8_t *private_key, uint8_t *public_key);

/**
 * @brief 对 32 字节摘要签名（ES256），r/s 分别输出
 * @param signature_r 输出 32 字节
 * @param signature_s 输出 32 字节
 * @return 0=成功, -1=参数错误, -2=未初始化, -3=签名失败
 */
int8_t ecdsa_sign(const uint8_t *private_key, const uint8_t *hash,
                  uint8_t *signature_r, uint8_t *signature_s);

/**
 * @brief 验证签名
 * @return 0=有效, -1=参数错误, -3=无效
 */
int8_t ecdsa_verify(const uint8_t *public_key, const uint8_t *hash,
                    const uint8_t *signature_r, const uint8_t *signature_s);

/**
 * @brief ECDSA 自测（RFC 6979 / NIST P-256 已知向量）
 *
 *   覆盖四项：
 *     1) 私钥 → 公钥必须匹配已知向量（确定性）
 *     2) 用外部已知签名验证本实现的 verify
 *     3) 篡改摘要后 verify 必须失败（负向）
 *     4) 本机 sign → verify 闭环
 *
 * @return 0=通过, 负数=第几步失败（-1 调用失败, -2 公钥不符, -3 已知签名未通过,
 *         -4 篡改后竟然通过, -5 签名失败, -6 闭环验签失败）
 */
int8_t ecdsa_selftest(void);

#endif /* __APP_ECDSA_H */
