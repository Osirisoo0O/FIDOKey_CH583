/**
 * @file selftest.c
 * @brief 上电自测统一入口实现（开发计划 5.1）
 *
 * 换行统一用 PRINT("%c", 10)，不在源码里写反斜杠转义——
 * 之前吃过工具链传递转义出错的亏（见 4.4 的记录）。
 */

#include "config.h"
#include "stdint.h"
#include "selftest.h"
#include "app_crypto.h"
#include "app_ecdsa.h"
#include "secure_store.h"
#include "cbor_lite.h"

typedef struct
{
    const char *name;
    int8_t    (*fn)(void);
} selftest_entry_t;

/* 顺序有依赖：加密模块必须先可用（ECDSA 依赖它做 RNG），
 * 安全存储又依赖 UID 派生密钥。 */
static const selftest_entry_t s_tests[] = {
    { "AES   ", aes_selftest          },
    { "SHA256", sha256_selftest       },
    { "ECDSA ", ecdsa_selftest        },
    { "STORE ", secure_store_selftest },
    { "CBOR  ", cbor_selftest         },
};

#define SELFTEST_N  ((int)(sizeof(s_tests) / sizeof(s_tests[0])))

int8_t selftest_run_all(void)
{
    int   i;
    int   failed = 0;

    PRINT("%c", 10);
    PRINT("--- selftest ---");
    PRINT("%c", 10);

    for(i = 0; i < SELFTEST_N; i++)
    {
        int8_t rc = s_tests[i].fn();

        PRINT("%s = %d", s_tests[i].name, rc);
        PRINT("%c", 10);

        if(rc != 0)
        {
            failed++;
        }
    }

    PRINT("passed %d/%d", SELFTEST_N - failed, SELFTEST_N);
    PRINT("%c", 10);

    return (int8_t)failed;
}
