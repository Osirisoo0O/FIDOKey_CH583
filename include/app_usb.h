/********************************** (C) COPYRIGHT *******************************
 * File Name          : APP_USB.h
 * Author             : WCH
 * Version            : V1.1
 * Date               : 2022/01/19
 * Description        :
 * Copyright (c) 2021 Nanjing Qinheng Microelectronics Co., Ltd.
 * SPDX-License-Identifier: Apache-2.0
 *******************************************************************************/

#ifndef _APP_USB_H
#define _APP_USB_H

#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif



extern void app_usb_init(void);

extern void app_usb_hid_process(void);

// HID IN 数据发送函数
extern int app_usb_hid_send(const uint8_t *data, uint8_t len);

// 兼容旧接口：把数据放到 HID IN 端点待发
extern void USBSendData(uint8_t *SendBuf, uint8_t l);

// 获取接收到的数据
extern uint8_t app_usb_hid_get_data(uint8_t *buf, uint8_t *len);

// 重置接收标志
extern void app_usb_hid_reset_rx(void);

/*********************************************************************
*********************************************************************/

#ifdef __cplusplus
}
#endif

#endif /* _APP_USB_H */
