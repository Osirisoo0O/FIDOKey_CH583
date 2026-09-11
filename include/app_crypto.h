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

// CTAP错误码
#define CTAP_SUCCESS                    0x00
#define CTAP_ERR_INVALID_CBOR           0x01
#define CTAP_ERR_INVALID_MESSAGE        0x02
#define CTAP_ERR_INVALID_OPTION         0x03
#define CTAP_ERR_INVALID_PARAMETER      0x20
#define CTAP_ERR_INVALID_LENGTH         0x21
#define CTAP_ERR_INVALID_SEQ            0x22
#define CTAP_ERR_MSG_TIMEOUT            0x23
#define CTAP_ERR_CHANNEL_BUSY           0x24
#define CTAP_ERR_LOCK_REQUIRED          0x25
#define CTAP_ERR_INVALID_CHANNEL        0x26
#define CTAP_ERR_CBOR_UNEXPECTED_TYPE   0x31
#define CTAP_ERR_INVALID_CBOR_TYPE      0x32
#define CTAP_ERR_NO_CREDENTIALS         0x33
#define CTAP_ERR_CREDENTIAL_EXCLUDED    0x34
#define CTAP_ERR_ATTESTATION_DENIED     0x35
#define CTAP_ERR_RP_INFORMATION_UNKNOWN 0x36
#define CTAP_ERR_INSUFFICIENT_CAPACITY  0x37
#define CTAP_ERR_USER_PROMPT_TIMEOUT    0x38
#define CTAP_ERR_USER_DENIED            0x39
#define CTAP_ERR_USER_ACTION_PENDING    0x3A
#define CTAP_ERR_USER_ACTION_ERROR      0x3B
#define CTAP_ERR_OPERATION_DENIED       0x40
#define CTAP_ERR_OTHER                  0x7F
#define CTAP_ERR_SPEC_LAST              0xFE
#define CTAP_ERR_UNPROCESSABLE            0x38
#define CTAP_ERR_ENTITY_SIZE_TOO_LARGE    0x39
#define CTAP_ERR_KEY_STORE_FULL           0x3A

// CTAPHID命令码
#define CTAPHID_KEEPALIVE               0x4C
#define CTAPHID_NONCE                   0x44
#define CTAPHID_VERSION_STRING          0x43
#define CTAPHID_VERSION                 0x03
#define CTAPHID_LOCK                    0x04
#define CTAPHID_NONCE                     0x44
#define CTAPHID_MSG                     0x10
#define CTAPHID_CBOR                    0x11
#define CTAPHID_INIT                    0x12
#define CTAPHID_PING                   0x13
#define CTAPHID_CANCEL                  0x14
#define CTAPHID_GET_VERSION             0x20
#define CTAPHID_GET_VERSION_STRING      0x21
#define CTAPHID_ERROR                   0x3F

// CTAP命令码
#define CTAP_CBOR_GET_INFO              0x01
#define CTAP_CBOR_MAKE_CREDENTIAL       0x02
#define CTAP_CBOR_GET_ASSERTION         0x03
#define CTAP_CBOR_CLIENT_PIN            0x04
#define CTAP_CBOR_RESET                 0x05
#define CTAP_CBOR_CREDENTIAL_MGMT       0x06
#define CTAP_CBOR_AUTHN_MGMT            0x07
#define CTAP_CBOR_LARGE_BLOB_ARRAY      0x08
#define CTAP_CBOR_GET_NEXT_CREDENTIAL   0x09

// CTAPHID消息类型（CTAPHID_MSG加密通道）
#define CTAPHID_MSG_CBOR                0x10

// CTAP Pin User Verification
#define CTAP_PIN_USE_PIN                0x01
#define CTAP_PIN_GET_KEY_AGREEMENT      0x01
#define CTAP_PIN_GET_CHALLENGE          0x02
#define CTAP_PIN_REGISTER               0x03
#define CTAP_PIN_SET_PIN                0x04
#define CTAP_PIN_CHANGE_PIN             0x05
#define CTAP_PIN_GET_KEY_AGREEMENT_TWO  0x11
#define CTAP_PIN_GET_CHALLENGE_TWO      0x12
#define CTAP_PIN_REGISTER_TWO           0x13
#define CTAP_PIN_SET_PIN_TWO            0x14
#define CTAP_PIN_CHANGE_PIN_TWO         0x15
#define CTAP_PIN_GET_STATUS             0x07
#define CTAP_PIN_GET_KEY_COUNT          0x08

// CTAPHID channel ID
#define CTAPHID_DEFAULT_CHANNEL_ID      0xFFFFFFFF

// CTAP options
#define CTAP_OPT_UV                     0x01
#define CTAP_OPT_UP                     0x02
#define CTAP_OPT_RK                     0x04
#define CTAP_OPT_PIN                    0x08
#define CTAP_OPT_HMAC_SECRET            0x10
#define CTAP_OPT_LARGE_BLOB             0x20

#define CTAP_MAX_MSG_SIZE               1200
#define CTAP_MAX_CRED_ID_LENGTH         1023
#define CTAP_MAX_RP_ID_LENGTH           255
#define CTAP_MAX_USER_ID_LENGTH         1023

// AAGUID (16 bytes - 自定义认证器GUID)
extern const uint8_t g_aaguid[16];

/**
 * @brief 初始化加密模块
 * @return 0=成功, 其他=失败
 */
int8_t crypto_init(void);

/**
 * @brief 生成随机字节
 * @param buf 输出缓冲区
 * @param len 长度（必须≤64字节）
 * @return 0=成功
 */
int8_t get_random_bytes(uint8_t *buf, uint8_t len);

/**
 * @brief 读取芯片UID
 * @param uid 输出缓冲区（必须≥12字节）
 * @return 0=成功
 */
int8_t read_chip_uid(uint8_t *uid);

/**
 * @brief AES-128加密
 * @param key 密钥（16字节）
 * @param plaintext 明文输入缓冲区
 * @param ciphertext 密文输出缓冲区
 * @return 0=成功
 */
int8_t aes_encrypt(const uint8_t *key, const uint8_t *plaintext, uint8_t *ciphertext);

/**
 * @brief AES-128解密
 * @param key 密钥（16字节）
 * @param ciphertext 密文输入缓冲区
 * @param plaintext 明文输出缓冲区
 * @return 0=成功
 */
int8_t aes_decrypt(const uint8_t *key, const uint8_t *ciphertext, uint8_t *plaintext);

/**
 * @brief SHA-256哈希
 * @param data 输入数据
 * @param len 数据长度
 * @param hash 输出哈希（32字节）
 * @return 0=成功
 */
int8_t sha256(const uint8_t *data, uint32_t len, uint8_t *hash);

#ifdef __cplusplus
}
#endif

#endif /* _APP_CRYPTO_H */
