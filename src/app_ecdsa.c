/**
 * @file app_ecdsa.c
 * @brief ECDSA P-256（secp256r1）实现，基于 lib/micro-ecc
 *
 * 对应开发计划 2.4。
 *
 * micro-ecc 在 RISC-V 上走纯 C 路径（types.h 判定 uECC_PLATFORM == uECC_arch_other，
 * 不会包含 asm_arm.inc / asm_avr.inc；curve-specific.inc 里的 asm_* 引用全部包在
 * #if ... && !asm_* 条件中，未定义时按 0 处理），因此本目录源码未经修改。
 */

#include "config.h"
#include "stdint.h"
#include "string.h"
#include "uECC.h"
#include "app_ecdsa.h"
#include "app_crypto.h"

#define ECDSA_HASH_LEN      ECDSA_P256_HASH_LEN
#define ECDSA_SIG_LEN       ECDSA_P256_SIG_LEN
#define ECDSA_HALF          (ECDSA_P256_SIG_LEN / 2)

/* ECDSA 模块是否可用（ecdsa_init 之后置位） */
static uint8_t ecdsa_ready = 0;

/*********************************************************************
 * @fn      ecdsa_rng
 *
 * @brief   micro-ecc 的随机数回调（返回 1=成功，0=失败）
 *
 * @note    micro-ecc 要求每一次调用都提供足够熵。这里转发到
 *          app_crypto.c 的多源混合熵。注意 get_random_bytes() 单次上限
 *          为 64 字节，且每次调用都会做一次 ADC 采样（约百微秒级）。
 */
static int ecdsa_rng(uint8_t *dest, unsigned size)
{
    while(size > 0)
    {
        uint8_t chunk = (size > 64U) ? (uint8_t)64U : (uint8_t)size;

        if(get_random_bytes(dest, chunk) != 0)
        {
            return 0;
        }
        dest += chunk;
        size -= chunk;
    }
    return 1;
}

/*********************************************************************
 * @fn      ecdsa_init
 */
int8_t ecdsa_init(void)
{
    uECC_set_rng(&ecdsa_rng);
    ecdsa_ready = 1;


    return 0;
}

/*********************************************************************
 * @fn      ecdsa_generate_keypair
 */
int8_t ecdsa_generate_keypair(uint8_t *private_key, uint8_t *public_key)
{
    if(private_key == NULL || public_key == NULL)
    {
        return -1;
    }
    if(!ecdsa_ready)
    {
        return -2;
    }

    /* 注意 micro-ecc 的参数顺序是 (public_key, private_key, curve) */
    if(!uECC_make_key(public_key, private_key, uECC_secp256r1()))
    {
        return -3;
    }
    return 0;
}

/*********************************************************************
 * @fn      ecdsa_compute_public_key
 */
int8_t ecdsa_compute_public_key(const uint8_t *private_key, uint8_t *public_key)
{
    if(private_key == NULL || public_key == NULL)
    {
        return -1;
    }

    if(!uECC_compute_public_key(private_key, public_key, uECC_secp256r1()))
    {
        return -3;
    }
    return 0;
}

/*********************************************************************
 * @fn      ecdsa_sign
 */
int8_t ecdsa_sign(const uint8_t *private_key, const uint8_t *hash,
                  uint8_t *signature_r, uint8_t *signature_s)
{
    uint8_t sig[ECDSA_SIG_LEN];

    if(private_key == NULL || hash == NULL ||
       signature_r == NULL || signature_s == NULL)
    {
        return -1;
    }
    if(!ecdsa_ready)
    {
        return -2;
    }

    if(!uECC_sign(private_key, hash, (unsigned)ECDSA_HASH_LEN, sig, uECC_secp256r1()))
    {
        return -3;
    }

    memcpy(signature_r, sig, ECDSA_HALF);
    memcpy(signature_s, sig + ECDSA_HALF, ECDSA_HALF);
    memset(sig, 0, sizeof(sig));

    return 0;
}

/*********************************************************************
 * @fn      ecdsa_verify
 */
int8_t ecdsa_verify(const uint8_t *public_key, const uint8_t *hash,
                    const uint8_t *signature_r, const uint8_t *signature_s)
{
    uint8_t sig[ECDSA_SIG_LEN];

    if(public_key == NULL || hash == NULL ||
       signature_r == NULL || signature_s == NULL)
    {
        return -1;
    }

    memcpy(sig, signature_r, ECDSA_HALF);
    memcpy(sig + ECDSA_HALF, signature_s, ECDSA_HALF);

    return uECC_verify(public_key, hash, (unsigned)ECDSA_HASH_LEN,
                       sig, uECC_secp256r1()) ? 0 : -3;
}

/*********************************************************************
 * @fn      ecdsa_selftest
 *
 * @brief   ECDSA 自测
 *
 * 用的向量来自 RFC 6979 A.2.5（P-256 + SHA-256，message = "sample"）：
 *   d   = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
 *   Q.x = 60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
 *   Q.y = 7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
 *   hash= SHA-256("sample") = AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF
 *   r   = EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
 *   s   = F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
 *
 * 这组向量在纳入前已用独立的 P-256 实现交叉验证过：
 *   路径 A：用 (r,s) 验签 -> R.x mod n == r 成立
 *   路径 B：用 RFC6979 的 k 反算 -> r、s 均与记录值一致
 */
int8_t ecdsa_selftest(void)
{
    static const uint8_t kPriv[ECDSA_P256_PRIV_LEN] = {
        0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16,
        0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6, 0x93,
        0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12,
        0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21
    };
    static const uint8_t kPub[ECDSA_P256_PUB_LEN] = {
        /* Q.x */
        0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31,
        0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35, 0x6D, 0x68,
        0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C,
        0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F, 0xB6,
        /* Q.y */
        0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99,
        0xA4, 0x1A, 0xE9, 0xE9, 0x56, 0x28, 0xBC, 0x64,
        0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51,
        0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22, 0x99
    };
    static const uint8_t kHash[ECDSA_P256_HASH_LEN] = {
        0xAF, 0x2B, 0xDB, 0xE1, 0xAA, 0x9B, 0x6E, 0xC1,
        0xE2, 0xAD, 0xE1, 0xD6, 0x94, 0xF4, 0x1F, 0xC7,
        0x1A, 0x83, 0x1D, 0x02, 0x68, 0xE9, 0x89, 0x15,
        0x62, 0x11, 0x3D, 0x8A, 0x62, 0xAD, 0xD1, 0xBF
    };
    static const uint8_t kSigR[ECDSA_P256_HASH_LEN] = {
        0xEF, 0xD4, 0x8B, 0x2A, 0xAC, 0xB6, 0xA8, 0xFD,
        0x11, 0x40, 0xDD, 0x9C, 0xD4, 0x5E, 0x81, 0xD6,
        0x9D, 0x2C, 0x87, 0x7B, 0x56, 0xAA, 0xF9, 0x91,
        0xC3, 0x4D, 0x0E, 0xA8, 0x4E, 0xAF, 0x37, 0x16
    };
    static const uint8_t kSigS[ECDSA_P256_HASH_LEN] = {
        0xF7, 0xCB, 0x1C, 0x94, 0x2D, 0x65, 0x7C, 0x41,
        0xD4, 0x36, 0xC7, 0xA1, 0xB6, 0xE2, 0x9F, 0x65,
        0xF3, 0xE9, 0x00, 0xDB, 0xB9, 0xAF, 0xF4, 0x06,
        0x4D, 0xC4, 0xAB, 0x2F, 0x84, 0x3A, 0xCD, 0xA8
    };

    uint8_t pub[ECDSA_P256_PUB_LEN];
    uint8_t bad_hash[ECDSA_P256_HASH_LEN];
    uint8_t sr[ECDSA_P256_HASH_LEN];
    uint8_t ss[ECDSA_P256_HASH_LEN];
    uint8_t gen_priv[ECDSA_P256_PRIV_LEN];
    uint8_t gen_pub[ECDSA_P256_PUB_LEN];
    uint8_t re_pub[ECDSA_P256_PUB_LEN];

    /* 1) 私钥 -> 公钥 必须匹配已知向量（确定性路径） */
    if(ecdsa_compute_public_key(kPriv, pub) != 0)
    {
        return -1;
    }
    if(memcmp(pub, kPub, ECDSA_P256_PUB_LEN) != 0)
    {
        return -2;
    }

    /* 2) 用外部已知签名验证本实现的 verify */
    if(ecdsa_verify(kPub, kHash, kSigR, kSigS) != 0)
    {
        return -3;
    }

    /* 3) 篡改摘要后必须验签失败（负向用例） */
    memcpy(bad_hash, kHash, ECDSA_P256_HASH_LEN);
    bad_hash[0] ^= 0x01;
    if(ecdsa_verify(kPub, bad_hash, kSigR, kSigS) == 0)
    {
        return -4;
    }

    /* 4) 本机 sign -> verify 闭环（k 由 RNG 决定，签名值不固定） */
    if(ecdsa_sign(kPriv, kHash, sr, ss) != 0)
    {
        return -5;
    }
    if(ecdsa_verify(kPub, kHash, sr, ss) != 0)
    {
        return -6;
    }

    /* 5) 现场生成密钥对：重算公钥须一致，且新密钥也要能完成签名闭环 */
    if(ecdsa_generate_keypair(gen_priv, gen_pub) != 0)
    {
        return -7;
    }
    if(ecdsa_compute_public_key(gen_priv, re_pub) != 0)
    {
        return -8;
    }
    if(memcmp(gen_pub, re_pub, ECDSA_P256_PUB_LEN) != 0)
    {
        return -9;
    }
    if(ecdsa_sign(gen_priv, kHash, sr, ss) != 0)
    {
        return -10;
    }
    if(ecdsa_verify(gen_pub, kHash, sr, ss) != 0)
    {
        return -11;
    }

    return 0;
}
