/********************************** (C) COPYRIGHT *******************************
 * File Name          : main.c
 * Author             : WCH
 * Version            : V1.1
 * Date               : 2020/08/06
 * Description        : 锟斤拷锟斤拷踊锟接︼拷锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷锟较低筹拷锟绞硷拷锟�
 * Copyright (c) 2021 Nanjing Qinheng Microelectronics Co., Ltd.
 * SPDX-License-Identifier: Apache-2.0
 *******************************************************************************/

/******************************************************************************/
/* 头锟侥硷拷锟斤拷锟斤拷 */
#include "config.h"
#include "HAL.h"
#include "gattprofile.h"
#include "peripheral.h"
#include "app_usb.h"
#include "ctaphid.h"
#include "LED.h"
#include "app_crypto.h"
#include "app_ecdsa.h"
#include "secure_store.h"
#include "cbor_lite.h"
#include "selftest.h"
#include "auth_sm.h"
#include "ctap.h"

/*********************************************************************
 * GLOBAL TYPEDEFS
 */
__attribute__((aligned(4))) uint32_t MEM_BUF[BLE_MEMHEAP_SIZE / 4];

#if(defined(BLE_MAC)) && (BLE_MAC == TRUE)
const uint8_t MacAddr[6] = {0x84, 0xC2, 0xE4, 0x03, 0x02, 0x02};
#endif

/*********************************************************************
 * @fn      Main_Circulation
 *
 * @brief   主循环
 *
 * @return  none
 */
__HIGH_CODE
__attribute__((noinline))
void Main_Circulation()
{
    while(1)
    {
        TMOS_SystemProcess();
        // USB HID 处理 (CTAPHID 多帧收发 + CTAP 分发)
        app_usb_hid_process();
        // 用户存在等待：推进按键/超时判断，并完成被挂起的 CTAP 操作
        auth_sm_poll();
        ctap_pending_poll();
    }
}

/*********************************************************************
 * @fn      main
 *
 * @brief   主函数
 *
 * @return  none
 */

int main(void)
{
#if(defined(DCDC_ENABLE)) && (DCDC_ENABLE == TRUE)
    PWR_DCDCCfg(ENABLE);
#endif
    SetSysClock(CLK_SOURCE_PLL_60MHz);
#if(defined(HAL_SLEEP)) && (HAL_SLEEP == TRUE)
    GPIOA_ModeCfg(GPIO_Pin_All, GPIO_ModeIN_PU);
    GPIOB_ModeCfg(GPIO_Pin_All, GPIO_ModeIN_PU);
#endif
#ifdef DEBUG
    GPIOA_SetBits(bTXD1);
    GPIOA_ModeCfg(bTXD1, GPIO_ModeOut_PP_5mA);
    UART1_DefInit();
#endif
    PRINT("%s\n", VER_LIB);
    CH58X_BLEInit();
    HAL_Init();

    /* 官方 HAL_LedInit() 里留有一句测试代码：
     *     HalLedBlink(HAL_LED_1, 10, 30, 4000);
     * 它会让 LED 在上电后自行慢闪 10 次（约 40 秒）再熄灭，干扰我们的状态指示。
     * 这里立刻清掉它；稍后 auth_sm_init() 会把 LED 设成就绪常亮。
     * （不改 lib/ 下的官方文件，只在调用方覆盖。） */
    HalLedSet(HAL_LED_ALL, HAL_LED_MODE_OFF);
    GAPRole_PeripheralInit();
    Peripheral_Init();
    app_usb_init();
    crypto_init();
    ecdsa_init();       // 必须在 crypto_init 之后（RNG 依赖加密模块）
    secure_store_init();
    auth_sm_init();
#ifdef DEBUG
    /* 统一自测入口：逐项打印结果（含会擦写 Flash 的安全存储自测） */
    (void)selftest_run_all();
#endif
    Main_Circulation();
}

/******************************** endfile @ main ******************************/
