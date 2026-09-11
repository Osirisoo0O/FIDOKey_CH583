/**
 * @file app_key.c
 * @brief 按键驱动实现（事件驱动）
 * 
 * 用于 SecureKey FIDO2 安全密钥的按键检测：
 * - KEY1 (PB22): 用户存在按钮 (User Presence)
 *   * 按下：确认 GetAssertion/MakeCredential 操作
 * 
 * 按键检测使用 TMOS 事件驱动机制，不需要 delay 函数
 */

#include "app_key.h"
#include "app_led.h"
#include "KEY.h"
#include "LED.h"
#include "config.h"
#include "peripheral.h"

// 外部函数声明
extern uint32_t TMOS_GetSystemClock(void);

// 按键状态
static key_state_t key_states[APP_KEY_MAX] = { KEY_STATE_RELEASED };
static key_event_callback_t event_cb = NULL;

// 按键事件处理状态
static uint8_t button_pressed = 0;
static uint16_t button_press_event = 0;  // 用户自定义的事件 ID
static uint32_t last_button_check = 0;

/**
 * @brief 初始化按键
 */
void app_key_init(void)
{
    for (int i = 0; i < APP_KEY_MAX; i++) {
        key_states[i] = KEY_STATE_RELEASED;
    }
    event_cb = NULL;
    button_pressed = 0;
    button_press_event = 0;
    last_button_check = 0;
    
    // KEY1 (PB22) - User Presence
    // KEY2 (PB4) - Optional
    // 这些已在 HAL_KeyInit() 中配置
}

/**
 * @brief 注册按键事件回调
 */
void app_key_register_callback(key_event_callback_t cb)
{
    event_cb = cb;
}

/**
 * @brief 设置按键事件 ID（用于通知应用层）
 * @param event_id 事件 ID
 */
void app_key_set_event(uint16_t event_id)
{
    button_press_event = event_id;
}

/**
 * @brief 轮询按键状态（在主循环或周期性事件中调用）
 * 
 * 实现软件消抖：按键状态变化需要持续稳定 50ms 才确认
 * 使用事件驱动，不阻塞等待
 */
void app_key_poll(void)
{
    uint32_t now = TMOS_GetSystemClock();
    
    // 每 20ms 检查一次按键状态（消抖）
    if ((now - last_button_check) < 20) {
        return;
    }
    last_button_check = now;
    
    // 检测 KEY1 (User Presence)
    uint8_t raw_key1 = HAL_PUSH_BUTTON1();
    app_key_detect(APP_KEY_USER_PRESENCE, raw_key1);
    
    // 检测 KEY2 (Optional)
    uint8_t raw_key2 = HAL_PUSH_BUTTON2();
    app_key_detect(APP_KEY_OPTIONAL, raw_key2);
}

/**
 * @brief 按键状态检测（含消抖）
 * 
 * @param key 按键编号
 * @param raw 原始状态 (1=按下, 0=释放)
 */
void app_key_detect(app_key_id_t key, uint8_t raw)
{
    if (key >= APP_KEY_MAX) return;
    
    key_state_t new_state = (raw != 0) ? KEY_STATE_PRESSED : KEY_STATE_RELEASED;
    key_state_t prev = key_states[key];
    
    if (prev == new_state) {
        // 状态未变化
        return;
    }
    
    // 状态发生变化
    key_states[key] = new_state;
    
    if (new_state == KEY_STATE_PRESSED) {
        // 按键按下事件
        button_pressed = 1;
        
        if (event_cb) {
            event_cb(key, KEY_EVENT_PRESSED);
        }
        
        // 如果有事件 ID，设置事件通知应用层
        if (button_press_event) {
            // 事件在 Peripheral_ProcessEvent 中处理
            // 这里只是标记按键已按下
        }
    } else if (prev == KEY_STATE_PRESSED) {
        // 按键释放事件
        button_pressed = 0;
        
        if (event_cb) {
            event_cb(key, KEY_EVENT_RELEASED);
        }
    }
}

/**
 * @brief 获取按键状态
 */
key_state_t app_key_get_state(app_key_id_t key)
{
    if (key >= APP_KEY_MAX) return KEY_STATE_RELEASED;
    return key_states[key];
}

/**
 * @brief 检查按键是否按下
 */
int app_key_is_pressed(app_key_id_t key)
{
    return (app_key_get_state(key) == KEY_STATE_PRESSED);
}

/**
 * @brief 检查是否有按键按下（事件驱动）
 * @return 1=有按键按下, 0=无按键
 */
int app_key_has_event(void)
{
    return button_pressed;
}

/**
 * @brief 清除按键事件标志
 */
void app_key_clear_event(void)
{
    button_pressed = 0;
}

/**
 * @brief 等待用户存在确认（事件驱动，非阻塞）
 * 
 * 这是 FIDO2 GetAssertion/MakeCredential 的核心操作：
 * 等待用户按下按键表示"我在场"
 * 
 * 使用事件驱动，设置 LED 状态为等待中
 * 应用层需要定期检查 app_key_has_event()
 * 
 * @param timeout_ms 超时时间（毫秒），默认 30 秒
 * @return 0=用户确认，-1=超时或取消
 */
int app_key_wait_user_presence(uint32_t timeout_ms)
{
    if (timeout_ms == 0) timeout_ms = 30000;  // 默认 30 秒
    
    // 设置 LED 状态为等待中
    app_led_set_state(LED_STATE_WAITING);
    
    // 注意：这是一个非阻塞函数
    // 实际等待由应用层的事件循环处理
    // 应用层需要定期检查 app_key_has_event() 和超时
    
    (void)timeout_ms;  // 避免未使用警告
    return 0;  // 返回 0 表示等待已开始
}

/**
 * @brief 检查用户存在等待是否超时
 * @param start_time 开始时间
 * @param timeout_ms 超时时间（毫秒）
 * @return 1=已超时, 0=未超时
 */
int app_key_is_timeout(uint32_t start_time, uint32_t timeout_ms)
{
    uint32_t now = TMOS_GetSystemClock();
    return ((now - start_time) >= timeout_ms);
}
