/**
 * @file auth_sm.c
 * @brief UP 等待状态机实现（开发计划 4.1 / 4.2）
 *
 * 设计要点：
 *   - 非阻塞：由主循环反复调用 auth_sm_poll() 推进，不占用 USB 处理时间
 *   - 有消抖：需连续 AUTH_UP_DEBOUNCE_CNT 次采样到按下才认定
 *   - 有超时：超过 AUTH_UP_TIMEOUT_MS 未按键则转 AUTH_WAIT_TIMEOUT，
 *     调用方据此返回 CTAP_ERR_ACTION_TIMEOUT
 *   - 有指示：等待时 LED 慢闪 1Hz，取得 UP 后转快闪 5Hz，超时闪 3 次
 */

#include "config.h"
#include "stdint.h"
#include "auth_sm.h"
#include "KEY.h"      /* 官方 HAL 按键：HAL_PUSH_BUTTON2() = KEY2 = PB4 */
#include "LED.h"      /* 官方 HAL LED：HalLedSet / HalLedBlink（LED1 = PB18，本板实测） */
#include "debug_log.h"

extern uint32_t TMOS_GetSystemClock(void);

static auth_wait_t s_state = AUTH_WAIT_NONE;
static uint32_t    s_deadline = 0;
static uint32_t    s_last_sample = 0;
static uint8_t     s_press_cnt = 0;

void auth_sm_init(void)
{
    /* 复用 clear()：既清等待状态，又把 LED 置回"就绪常亮"。
     * 不能只清变量 —— 那样 LED 会停在 HAL_LedInit() 设的 OFF 状态，
     * 上电后看起来像"LED 坏了"。 */
    auth_sm_clear();
}

void auth_sm_request_up(void)
{
    s_state       = AUTH_WAIT_ACTIVE;
    s_press_cnt   = 0;
    s_last_sample = TMOS_GetSystemClock();
    s_deadline    = s_last_sample + AUTH_UP_TIMEOUT_MS;

    /* 提示用户：等待确认 */
    HalLedBlink(HAL_LED_1, 0, 50, 500);          /* 慢闪 1Hz：等待用户确认 */
    SK_LOG("auth: wait UP (%d ms)", AUTH_UP_TIMEOUT_MS);
}

void auth_sm_poll(void)
{
    uint32_t now;

    if(s_state != AUTH_WAIT_ACTIVE)
    {
        return;
    }

    now = TMOS_GetSystemClock();

    /* 采样节流：主循环是忙等的，两次调用间隔只有微秒级，
     * 若不按时间间隔采样，"连续 N 次确认"就挡不住任何抖动。
     * 这里保证相邻两次采样至少相隔 AUTH_UP_SAMPLE_MS。 */
    if((now - s_last_sample) < AUTH_UP_SAMPLE_MS)
    {
        return;
    }
    s_last_sample = now;
    if(HAL_PUSH_BUTTON2())          /* PB4；KEY2_IN 已由 ACTIVE_LOW 归一为「按下=1」 */
    {
        s_press_cnt++;
        if(s_press_cnt >= AUTH_UP_DEBOUNCE_CNT)
        {
            s_state = AUTH_WAIT_GRANTED;
            HalLedBlink(HAL_LED_1, 0, 50, 100);          /* 快闪 5Hz：已取得 UP，处理中 */
            SK_LOG("auth: UP granted");
        }
        return;
    }
    s_press_cnt = 0;

    /* 无符号回绕安全的超时判断 */
    if((int32_t)(now - s_deadline) >= 0)
    {
        s_state = AUTH_WAIT_TIMEOUT;
        HalLedBlink(HAL_LED_1, 3, 50, 500);          /* 闪 3 次：超时/错误 */
        SK_LOG("auth: UP timeout");
    }
}

auth_wait_t auth_sm_get(void)
{
    return s_state;
}

void auth_sm_clear(void)
{
    s_state     = AUTH_WAIT_NONE;
    s_press_cnt = 0;
    HalLedSet(HAL_LED_1, HAL_LED_MODE_ON);       /* 常亮：就绪 */
}
