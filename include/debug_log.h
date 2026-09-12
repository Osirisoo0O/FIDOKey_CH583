/**
 * @file debug_log.h
 * @brief 关键路径日志开关（开发计划 4.4）
 *
 * 与 DEBUG **分开**控制，原因是两者代价不同：
 *   - DEBUG 控制上电自检（AES/SHA-256/ECDSA/安全存储/CBOR）。
 *     其中 secure_store_selftest() 会**擦写 DataFlash**，正式固件必须关掉。
 *   - SK_LOG_ENABLE 只控制串口日志，不影响 Flash 寿命。
 * 因此需要能独立开关（例如"要日志但不要自检"）。
 * 生产固件两者都应为 0。
 */

#ifndef __DEBUG_LOG_H
#define __DEBUG_LOG_H

#include "config.h"     /* PRINT */

#ifndef SK_LOG_ENABLE
#define SK_LOG_ENABLE   0
#endif

#if SK_LOG_ENABLE
/* 统一在末尾补一个换行：用 PRINT("%c", 10) 而不是反斜杠转义，
 * 避免源码里出现转义序列（工具链在传递反斜杠时容易出问题）。 */
#define SK_LOG(...)     do { PRINT(__VA_ARGS__); PRINT("%c", 10); } while(0)
#else
#define SK_LOG(...)     do { } while(0)
#endif

#endif /* __DEBUG_LOG_H */
