/**
 * @file app_led.c
 * @brief LED 状态指示驱动（事件驱动）
 * 
 * 用于 SecureKey FIDO2 安全密钥的状态指示：
 * - LED1 (PB15): 设备状态指示
 *   * 常亮: 设备就绪，等待用户按键
 *   * 慢闪 (1Hz): 正在等待用户确认 (UP)
 *   * 快闪 (5Hz): 正在签名/处理中
 *   * 熄灭: 设备未枚举/错误
 * 
 * LED 库的 HalLedBlink 本身就是事件驱动的，不需要 delay 函数
 */

#include "app_led.h"
#include "LED.h"
#include "config.h"

// LED 状态机
static led_state_t current_state = LED_STATE_OFF;

/**
 * @brief 初始化 LED
 */
void app_led_init(void)
{
    HalLedSet(HAL_LED_1, HAL_LED_MODE_OFF);
    current_state = LED_STATE_OFF;
}

/**
 * @brief 设置 LED 状态
 * 
 * LED 库的 HalLedBlink 是事件驱动的，不需要 delay
 */
void app_led_set_state(led_state_t state)
{
    if (state == current_state) return;
    
    current_state = state;
    
    switch (state) {
        case LED_STATE_OFF:
            HalLedSet(HAL_LED_1, HAL_LED_MODE_OFF);
            break;
            
        case LED_STATE_READY:
            // 就绪状态：LED 常亮
            HalLedSet(HAL_LED_1, HAL_LED_MODE_ON);
            break;
            
        case LED_STATE_WAITING:
            // 等待用户确认：慢闪 1Hz
            HalLedBlink(HAL_LED_1, 0, 50, 500); // 0=持续闪烁, 50% 占空比, 500ms 周期
            break;
            
        case LED_STATE_SIGNING:
            // 正在签名：快闪 5Hz
            HalLedBlink(HAL_LED_1, 0, 50, 100); // 100ms 周期 = 5Hz
            break;
            
        case LED_STATE_ERROR:
            // 错误状态：每 500ms 闪一次
            HalLedBlink(HAL_LED_1, 3, 50, 500); // 闪烁 3 次
            break;
            
        case LED_STATE_ENUM_DONE:
            // 枚举完成：短闪一次
            HalLedBlink(HAL_LED_1, 1, 10, 100); // 快速短闪
            break;
            
        default:
            break;
    }
}

/**
 * @brief 获取当前 LED 状态
 */
led_state_t app_led_get_state(void)
{
    return current_state;
}

/**
 * @brief 闪烁 LED 表示错误（事件驱动）
 */
void app_led_blink_error(void)
{
    // 使用 LED 库的事件驱动闪烁
    HalLedBlink(HAL_LED_1, 3, 50, 500); // 闪烁 3 次，每次 500ms 周期
}

/**
 * @brief 闪烁 LED 表示成功（事件驱动）
 */
void app_led_blink_success(void)
{
    // 使用 LED 库的事件驱动闪烁
    HalLedBlink(HAL_LED_1, 2, 50, 500); // 闪烁 2 次，每次 500ms 周期
}
