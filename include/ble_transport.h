/**
 * @file ble_transport.h
 * @brief FIDO BLE 传输层（帧编解码 + 分片重组）
 *
 * 规范依据：FIDO U2F BT Protocol v1.1 §5（帧格式）、§11（分片）、
 *           ITU-T X.1278.2 §13.4
 *
 * 与 CTAPHID 的关系：两者是**并列**的传输层，帧格式完全不同，
 * 不共用代码。本层与 ctaphid.c 结构对称：
 *
 *   ctaphid.c        <- USB HID 上的 CTAPHID 分片/重组
 *   ble_transport.c  <- BLE GATT 上的 FIDO 帧分片/重组
 *            \       /
 *             ctap.c（CTAP2 核心，两者共用）
 *
 * 帧格式：
 *   初始帧  [CMD(1B, bit7=1)] [HLEN(1B)] [LLEN(1B)] [DATA]
 *   续帧    [SEQ(1B, bit7=0)] [DATA]
 *   HLEN:LLEN 是整个帧的数据长度（大端），不是本分片的长度。
 */

#ifndef __BLE_TRANSPORT_H
#define __BLE_TRANSPORT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"
#include "stdint.h"

/*********************************************************************
 * CONSTANTS
 */

/* 命令码 —— 取自 CTAP 2.1 §11.4.4.3（"Command, Status, and Error constants"）
 *
 * ★ BLE 传输层有**自己的**命令码表，与 USB HID（CTAPHID）不同，不能混用：
 *
 *     PING       0x81      ← 与 HID 相同
 *     KEEPALIVE  0x82      ← ★ 与 HID 的 0xBB 不同
 *     MSG        0x83      ← 与 HID 相同
 *     CANCEL     0xbe      ← ★ 与 HID 的 0x91 不同
 *     ERROR      0xbf      ← 与 HID 相同
 *
 * 规范 §11.4.4.3 的原表就是上面这五个值，并注明 "These values are identical
 * to the HID transport values." —— 那句指的是**常量体系同源**，不是数值逐个
 * 相同；表里的值才是权威。
 *
 * （曾有一次性把 KEEPALIVE/CANCEL 改成 HID 的 0xBB/0x91，那是错的，已改回。）
 *
 * 另：§11.4.4.3 的 KEEPALIVE 状态字节 ——
 *     PROCESSING 0x01
 *     UP_NEEDED  0x02
 */
#define FIDO_BLE_CMD_PING               0x81    /* PING      */
#define FIDO_BLE_CMD_KEEPALIVE          0x82    /* KEEPALIVE */
#define FIDO_BLE_CMD_MSG                0x83    /* MSG       */
#define FIDO_BLE_CMD_CANCEL             0xBE    /* CANCEL    */
#define FIDO_BLE_CMD_ERROR              0xBF    /* ERROR     */

/* KEEPALIVE 的状态字节 */
#define FIDO_BLE_KA_PROCESSING          0x01
#define FIDO_BLE_KA_UP_NEEDED           0x02

/* 默认 ATT MTU（未协商时）。maxLen = MTU - 3 */
#define FIDO_BLE_DEFAULT_MTU            23

/* 可处理的最大消息长度。
 * 规范建议至少 1024，但那是"单条消息"的上限；本实现的实际消息
 * （CTAP2 请求/响应）在 200 字节上下，MakeCredential 的响应约 178 字节。
 * 取 512 既留足余量，又避免在 RAM 已紧张时再吃掉 1KB（见下方说明）。
 * 若将来遇到更长的消息，改大此值即可（每增加 N 就多占 2N 字节 RAM）。 */
#define FIDO_BLE_MAX_MSG                512

/* 封装层 ERROR 帧的错误码（CTAP 2.1 §11.4.4.3）
 *
 * ★ ERROR 帧的格式是  STAT(0xBF) | HLEN | LLEN | <错误码>
 *   最后那个 DATA 字段是**错误码**，不是 STAT 的值 —— 两者容易写混，
 *   写错会让客户端读到未定义错误码（0xBF 在表里没有定义）。
 * 规范只定义了下面这几个（0x0a/0x0b 是 HID 保留值，BLE 不用）。 */
#define FIDO_BLE_EC_INVALID_CMD         0x01    /* 命令未知/无效 */
#define FIDO_BLE_EC_INVALID_PAR         0x02    /* 参数无效或缺失 */
#define FIDO_BLE_EC_INVALID_LEN         0x03    /* 请求长度无效 */
#define FIDO_BLE_EC_INVALID_SEQ         0x04    /* 序号无效 */
#define FIDO_BLE_EC_REQ_TIMEOUT         0x05    /* 请求超时 */
#define FIDO_BLE_EC_BUSY                0x06    /* 设备忙，客户端可稍后重试 */
#define FIDO_BLE_EC_OTHER               0x7F    /* 其它未指定错误 */

/*********************************************************************
 * PUBLIC FUNCTIONS
 */

/**
 * @brief 初始化传输层（注册到 fido_service，清空状态）
 */
void ble_transport_init(void);

/**
 * @brief 记录当前连接句柄（连接建立时调用）
 */
void ble_transport_set_conn(uint16_t connHandle);

/**
 * @brief 更新 ATT MTU（MTU 协商完成时调用，影响每帧能装多少字节）
 */
void ble_transport_set_mtu(uint16_t mtu);

/**
 * @brief 连接断开/复位时清理状态
 */
void ble_transport_clear(void);

/**
 * @brief 收到 fidoControlPoint 写入（由 fido_service 回调转来）
 */
void ble_transport_on_write(uint16_t connHandle, const uint8_t *data, uint16_t len);

/**
 * @brief 发送调度：由主循环调用，把待发内容按 MTU 逐帧送出
 */
void ble_transport_pump(void);

/**
 * @brief 推进被挂起的 CTAP 操作（由主循环调用）
 *
 * 取得 UP 后重放挂起的命令；超时回填 CTAP_ERR_ACTION_TIMEOUT。
 * 等待期间每 500ms 上报 KEEPALIVE(UP_NEEDED)。
 */
void ble_transport_pending_poll(void);

/**
 * @brief 当前每帧可承载的最大字节数
 */
uint16_t ble_transport_max_frame(void);

/**
 * @brief 客户端完成 CCCD 订阅后触发参数更新（由 fido_service 回调转来）
 *
 * 在 FIDO_EVT_STATUS_NOTI_ENABLED 事件中调用，此时客户端已完成
 * GATT 发现和 CCCD 订阅，参数更新不会干扰 GATT 操作。
 */
void ble_transport_on_cccd_enabled(void);

#ifdef __cplusplus
}
#endif

#endif /* __BLE_TRANSPORT_H */
