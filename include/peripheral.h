/********************************** (C) COPYRIGHT *******************************
 * File Name          : peripheral.h
 * Author             : WCH
 * Version            : V1.0
 * Date               : 2018/12/11
 * Description        :
 * Copyright (c) 2021 Nanjing Qinheng Microelectronics Co., Ltd.
 * SPDX-License-Identifier: Apache-2.0
 *******************************************************************************/

#ifndef PERIPHERAL_H
#define PERIPHERAL_H

#ifdef __cplusplus
extern "C" {
#endif

/*********************************************************************
 * INCLUDES
 */

/*********************************************************************
 * CONSTANTS
 */

// Peripheral Task Events
#define SBP_START_DEVICE_EVT    0x0001
#define SBP_PERIODIC_EVT        0x0002
#define SBP_READ_RSSI_EVT       0x0004
#define SBP_PARAM_UPDATE_EVT    0x0008
#define SBP_PHY_UPDATE_EVT      0x0010

/*********************************************************************
 * MACROS
 */
typedef struct
{
    uint16_t connHandle; // Connection handle of current connection
    uint16_t connInterval;
    uint16_t connSlaveLatency;
    uint16_t connTimeout;
} peripheralConnItem_t;

/*********************************************************************
 * FUNCTIONS
 */

/*
 * Task Initialization for the BLE Application
 */
extern void Peripheral_Init(void);

/*
 * Task Event Processor for the BLE Application
 */
extern uint16_t Peripheral_ProcessEvent(uint8_t task_id, uint16_t events);
void app_usb_notify(uint8_t *SendBuf, uint8_t l);

/* FIDO 配对模式轮询（CTAP 2.1 规范 §11.4.7/§11.4.13.2）：
 * 检测长按 KEY2 满 5 秒进入配对模式，30 秒无配对自动退出。
 * 需在主循环中持续调用。 */
extern void Peripheral_PairingModePoll(void);

/* 客户端有活动时续上配对窗口（避免交互中途配对模式过期） */
extern void Peripheral_PairingKeepAlive(void);

/* 触发连接参数更新请求（在 CCCD 订阅完成后调用） */
extern void Peripheral_RequestParamUpdate(void);

/*********************************************************************
*********************************************************************/

#ifdef __cplusplus
}
#endif

#endif
