/**
 * @file app_key.h
 * @brief 按键驱动接口
 */

#ifndef __APP_KEY_H
#define __APP_KEY_H

#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 按键 ID 枚举
 */
typedef enum {
    APP_KEY_USER_PRESENCE = 0,  // KEY1: 用户存在按钮
    APP_KEY_OPTIONAL = 1,       // KEY2: 可选辅助按钮
    APP_KEY_MAX = 2
} app_key_id_t;

/**
 * @brief 按键状态枚举
 */
typedef enum {
    KEY_STATE_RELEASED = 0,  // 释放
    KEY_STATE_PRESSED        // 按下
} key_state_t;

/**
 * @brief 按键事件类型
 */
typedef enum {
    KEY_EVENT_PRESSED = 0,   // 按键按下
    KEY_EVENT_RELEASED        // 按键释放
} key_event_t;

/**
 * @brief 按键事件回调函数类型
 */
typedef void (*key_event_callback_t)(app_key_id_t key, key_event_t event);

/**
 * @brief 初始化按键
 */
void app_key_init(void);

/**
 * @brief 注册按键事件回调
 */
void app_key_register_callback(key_event_callback_t cb);

/**
 * @brief 轮询按键状态（在主循环中调用）
 */
void app_key_poll(void);

/**
 * @brief 查询是否有待处理的按键事件
 */
int app_key_has_event(void);

/**
 * @brief 清除已处理的按键事件
 */
void app_key_clear_event(void);

/**
 * @brief 按键状态检测（含消抖）
 */
void app_key_detect(app_key_id_t key, uint8_t raw);

/**
 * @brief 获取按键状态
 */
key_state_t app_key_get_state(app_key_id_t key);

/**
 * @brief 检查按键是否按下
 */
int app_key_is_pressed(app_key_id_t key);

/**
 * @brief 等待按键按下（带超时）
 */
int app_key_wait_press(app_key_id_t key, uint32_t timeout_ms);

/**
 * @brief 等待按键释放（带超时）
 */
int app_key_wait_release(app_key_id_t key, uint32_t timeout_ms);

/**
 * @brief 等待用户存在确认
 */
int app_key_wait_user_presence(uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* __APP_KEY_H */
