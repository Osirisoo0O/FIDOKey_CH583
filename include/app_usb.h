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

// 兼容入口：实际处理在 ctaphid.c（多帧收发 + CTAP 分发）
extern void app_usb_hid_process(void);

/*********************************************************************
*********************************************************************/

#ifdef __cplusplus
}
#endif

#endif /* _APP_USB_H */
