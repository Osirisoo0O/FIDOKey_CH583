/**
 * @file auth_sm.h
 * @brief 认证器用户存在（UP）等待状态机，对应开发计划 4.1 / 4.2
 *
 * 为什么需要独立状态机：FIDO2 要求 MakeCredential / GetAssertion 必须由**真实用户动作**
 * 取得 UP，设备在未取得 UP 时必须返回 CTAP_ERR_ACTION_TIMEOUT。
 * 但 USB 必须持续响应 CTAPHID 轮询，所以**不能用阻塞等待**——
 * 否则主循环停摆，主机会因为拿不到 KEEPALIVE 而先超时。
 *
 * 因此把"等待用户按键"做成挂起式：CTAP 命令处理到需要 UP 时先挂起并返回，
 * 由主循环反复调用 auth_sm_poll() 推进，取得 UP（或超时）后再续完剩余步骤。
 */

#ifndef __AUTH_SM_H
#define __AUTH_SM_H

#include "stdint.h"

/* UP 等待超时（毫秒）。CTAP 规范建议 30~60s，取 15s 便于开发调试。 */
#define AUTH_UP_TIMEOUT_MS      15000

/* 连续采样到"按下"多少次才认定为真的按下 */
#define AUTH_UP_DEBOUNCE_CNT    2

/* 相邻两次采样的最小间隔（毫秒）。
 * 主循环是忙等的（两次调用间隔只有微秒级），若不加这个节流，
 * "连续 N 次确认"实际上等价于一次采样，起不到任何消抖作用。 */
#define AUTH_UP_SAMPLE_MS       20

typedef enum
{
    AUTH_WAIT_NONE = 0,     /* 没有在等待 */
    AUTH_WAIT_ACTIVE,       /* 正在等待用户按键 */
    AUTH_WAIT_GRANTED,      /* 用户已确认 */
    AUTH_WAIT_TIMEOUT       /* 等待超时 */
} auth_wait_t;

/**
 * @brief 初始化（清状态）
 */
void auth_sm_init(void);

/**
 * @brief 开始等待用户存在确认（会点亮/闪烁 LED 提示）
 */
void auth_sm_request_up(void);

/**
 * @brief 主循环调用：推进等待状态（检查按键与超时）
 */
void auth_sm_poll(void);

/**
 * @brief 当前等待状态
 */

auth_wait_t auth_sm_get(void);

/**
 * @brief 结束本次等待并清状态
 */
void auth_sm_clear(void);

#endif /* __AUTH_SM_H */
