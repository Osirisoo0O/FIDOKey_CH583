/**
 * @file app_led.h
 * @brief LED 状态指示驱动接口
 */

#ifndef __APP_LED_H
#define __APP_LED_H

#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief LED 状态枚举
 */
typedef enum {
    LED_STATE_OFF = 0,        // 熄灭
    LED_STATE_ENUM_DONE,      // 枚举完成（短闪）
    LED_STATE_READY,          // 就绪（常亮）
    LED_STATE_WAITING,        // 等待用户确认（慢闪 1Hz）
    LED_STATE_SIGNING,        // 正在签名（快闪 5Hz）
    LED_STATE_ERROR           // 错误（闪烁提示）
} led_state_t;

/**
 * @brief 初始化 LED
 */
void app_led_init(void);

/**
 * @brief 设置 LED 状态
 */
void app_led_set_state(led_state_t state);

/**
 * @brief 获取当前 LED 状态
 */
led_state_t app_led_get_state(void);

/**
 * @brief 闪烁 LED 表示错误
 */
void app_led_blink_error(void);

/**
 * @brief 闪烁 LED 表示成功
 */
void app_led_blink_success(void);

#ifdef __cplusplus
}
#endif

#endif /* __APP_LED_H */
