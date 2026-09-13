/**
 * @file fido_service.h
 * @brief FIDO GATT 服务的对外接口（BLE CTAP2 传输，对应开发计划 3.7）
 *
 * 规范依据：FIDO U2F BT Protocol v1.1 §12、ITU-T X.1278.2 §13.4
 *
 * 服务结构（5 个特征）：
 *   fidoControlPoint            Write    客户端写入请求帧
 *   fidoStatus                  Notify   设备回送响应帧
 *   fidoControlPointLength      Read     单次写入上限
 *   fidoServiceRevision         Read     固定值（16-bit UUID 0x2A28）
 *   fidoServiceRevisionBitfield Read/Write 协议版本协商
 */

#ifndef __FIDO_SERVICE_H
#define __FIDO_SERVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"
#include "stdint.h"

/*********************************************************************
 * CONSTANTS
 */

/* fidoServiceRevisionBitfield 的位定义 */
#define FIDO_REV_BIT_U2F_V11        0x80    /* bit7 */
#define FIDO_REV_BIT_U2F_V12        0x40    /* bit6 */
#define FIDO_REV_BIT_FIDO2          0x20    /* bit5 —— 本实现只支持这个 */

/* 本实现宣告的版本：纯 CTAP2 */
#define FIDO_SUPPORTED_REVISIONS    (FIDO_REV_BIT_FIDO2)

/* fidoControlPointLength：单次写入的最大字节数。
 * 规范允许 20~512。取 512 可让多数请求一帧装下。 */
#define FIDO_CONTROL_POINT_LENGTH   512

/*********************************************************************
 * TYPEDEFS
 */

/** 服务向上层（传输层）上报的事件 */
typedef enum
{
    FIDO_EVT_STATUS_NOTI_ENABLED = 0,   /* 客户端订阅了 fidoStatus 通知 */
    FIDO_EVT_STATUS_NOTI_DISABLED,      /* 客户端取消订阅 */
    FIDO_EVT_CONTROL_POINT_WRITE,       /* 收到 fidoControlPoint 写入 */
} fido_evt_type_t;

typedef struct
{
    fido_evt_type_t type;
    uint16_t        connHandle;
    const uint8_t  *data;               /* CONTROL_POINT_WRITE 时的写入内容 */
    uint16_t        len;
} fido_evt_t;

/** 上层事件回调 */
typedef void (*fido_ServiceCB_t)(fido_evt_t *p_evt);

/*********************************************************************
 * PUBLIC FUNCTIONS
 */

/**
 * @brief 注册 FIDO GATT 服务
 *
 * @param cb  事件回调（可为 NULL，此时只提供 GATT 骨架，不处理数据）
 * @return SUCCESS 或失败码
 */
bStatus_t fido_add_service(fido_ServiceCB_t cb);

/**
 * @brief 通过 fidoStatus 发送一段通知（响应帧）
 *
 * @param connHandle 连接句柄
 * @param p_data     数据
 * @param len        长度（调用方负责确保不超过 ATT_MTU-3）
 * @return SUCCESS 或失败码
 *
 * @note 若客户端尚未订阅通知，返回 bleIncorrectMode。
 */
bStatus_t fido_status_notify(uint16_t connHandle, const uint8_t *p_data, uint16_t len);

/**
 * @brief 客户端是否已订阅 fidoStatus 通知
 */
uint8_t fido_status_notify_is_ready(uint16_t connHandle);

/**
 * @brief 当前协商到的协议版本位（0 表示客户端尚未写入）
 */
uint8_t fido_get_revision_bitfield(void);

/**
 * @brief 更新 fidoControlPointLength 的返回值
 *
 * @param len 单次写入的最大字节数，应当等于 ATT_MTU - 3
 *
 * @note 规范要求这个特征反映"客户端一次能写多少"，
 *       客户端会读它来决定请求的分片方式。声明过大的值会导致
 *       客户端写出 ATT 层无法传输的长度。
 */
void fido_set_control_point_length(uint16_t len);

#ifdef __cplusplus
}
#endif

#endif /* __FIDO_SERVICE_H */
