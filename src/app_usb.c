/********************************** (C) COPYRIGHT *******************************
 * File Name          : app_usb.c
 * Author             : WCH (modified for CTAPHID)
 * Version            : V1.1
 * Date               : 2022/01/19
 * Description        : CH583 FIDO2 Secure Key - CTAPHID over USB HID
 *******************************************************************************/

#include "config.h"
#include "gattprofile.h"
#include "stdint.h"
#include "ble_usb_service.h"
#include "app_usb.h"
#include "peripheral.h"
#include "app_crypto.h"
#include "ctaphid.h"
#include "ctap.h"

/* CTAPHID / CTAP 的命令码与错误码统一见 ctaphid.h / ctap.h */

/*********************************************************************
 * CONSTANTS
 */
uint8_t DevConfig, Ready = 0;
uint8_t SetupReqCode;
uint16_t SetupReqLen;
const uint8_t *pDescr;

// 支持的最大接口数量
#define USB_INTERFACE_MAX_NUM       1
// 接口号的最大值，例程只有一个接口，接口号为0
#define USB_INTERFACE_MAX_INDEX      0
#define DevEP0SIZE  0x40
#define DevEP1SIZE  0x40
// 设备描述符
const uint8_t MyDevDescr[] = { 0x12,0x01,0x10,0x01,0x00,0x00,0x00,DevEP0SIZE,
                             0x86,0x1A,0x08,0xE0,0x00,0x00,0x01,0x02,0x00,0x01 };

const uint8_t MyCfgDescr[] = {
    0x09,0x02,0x29,0x00,USB_INTERFACE_MAX_NUM,0x01,0x04,0xA0,0x23,               //配置描述符
    0x09,0x04,0x00,0x00,0x02,0x03,0x00,0x00,0x05,               //接口描述符
    0x09,0x21,0x00,0x01,0x00,0x01,0x22,0x22,0x00,               //HID类描述符
    0x07,0x05,0x81,0x03,DevEP1SIZE,0x00,0x01,              //端点描述符
    0x07,0x05,0x01,0x03,DevEP1SIZE,0x00,0x01               //端点描述符
};
/*字符串描述符略*/
/* HID 报告描述符（FIDO CTAPHID，CTAP 2.3 §11.2.4）
 *
 * ⚠️ Usage Page 必须是 0xF1D0（FIDO Alliance）、Usage 为 0x01，
 *    否则主机侧（Chrome / Windows / python-fido2）按 FIDO 用法页筛选时
 *    根本发现不了这个设备 —— 这就是"python-fido2 报 0 个设备"的原因。
 *    原先抄的是 WCH HID_CompliantDev 例程的厂商自定义用法页(0xFF00)。
 *
 * 本报文共 34 字节，与配置描述符里声明的 wDescriptorLength(0x0022) 一致。 */
const uint8_t HIDDescr[] = {  0x06, 0xD0,0xF1,        // Usage Page (FIDO Alliance 0xF1D0)
                              0x09, 0x01,            // Usage (Authenticator Device)
                              0xa1, 0x01,            // Collection (Application)
                              0x09, 0x20,            //   Usage (Input Report Data)
                              0x15, 0x00,            //   Logical Minimum (0)
                              0x26, 0x00,0xff,       //   Logical Maximum (255)
                              0x75, 0x08,            //   Report Size (8)
                              0x95, 0x40,            //   Report Count (64)
                              0x81, 0x02,            //   Input (Data,Var,Abs)
                              0x09, 0x21,            //   Usage (Output Report Data)
                              0x15, 0x00,            //   Logical Minimum (0)
                              0x26, 0x00,0xff,       //   Logical Maximum (255)
                              0x75, 0x08,            //   Report Size (8)
                              0x95, 0x40,            //   Report Count (64)
                              0x91, 0x02,            //   Output (Data,Var,Abs)
                              0xC0};                 // End Collection
// 语言描述符
const uint8_t MyLangDescr[] = {0x04, 0x03, 0x09, 0x04};
// 厂家信息
const uint8_t MyManuInfo[] = {0x0E, 0x03, 'w', 0, 'c', 0, 'h', 0, '.', 0, 'c', 0, 'n', 0};
const uint8_t MyProdInfo[] = {0x22, 0x03,
  'S',0,'e',0,'c',0,'u',0,'r',0,'e',0,
  'K',0,'e',0,'y',0,' ',0,
  'D',0,'e',0,'v',0,'i',0,'c',0,'e',0};
// 产品信息
//const uint8_t MyProdInfo[] = {0x0C, 0x03, 'C', 0, 'H', 0, '5', 0, '8', 0, '3', 0};

/*********************************************************************
 * LOCAL VARIABLES
 */

/* 收发缓冲与状态机统一由 ctaphid.c 管理，此处不再保留单帧缓冲 */

// 端点RAM分配
__attribute__((aligned(4))) uint8_t EP0_Databuf[64 + 64 + 64]; // ep0(64)+ep4_out(64)+ep4_in(64)
__attribute__((aligned(4))) uint8_t EP1_Databuf[64 + 64];      // ep1_out(64)+ep1_in(64)
__attribute__((aligned(4))) uint8_t EP2_Databuf[64 + 64];      // ep2_out(64)+ep2_in(64)
__attribute__((aligned(4))) uint8_t EP3_Databuf[64 + 64];      // ep3_out(64)+ep3_in(64)

/*********************************************************************
 * PUBLIC FUNCTIONS
 */

void app_usb_init()
{
    pEP0_RAM_Addr = EP0_Databuf;
    pEP1_RAM_Addr = EP1_Databuf;
    pEP2_RAM_Addr = EP2_Databuf;
    pEP3_RAM_Addr = EP3_Databuf;

    USB_DeviceInit();
    PFIC_EnableIRQ(USB_IRQn);

    ctaphid_init();
}

/**
 * @brief CTAPHID协议处理
 */
void app_usb_hid_process(void)
{
    /* CTAPHID 多帧收发与 CTAP 命令分发都在 ctaphid.c */
    ctaphid_process();

    /* 新响应产生后：先装载第一帧到 EP1 IN 缓冲，再置端点为 ACK。
     *
     * 两个要点：
     *  1) BUS_RST / CLEAR_FEATURE 把 EP1 置成 NAK 后没人恢复，响应会递不出去（主机一直等）；
     *  2) 必须先装载再置 ACK —— 只置 ACK 不填缓冲的话，主机读到的是全 0
     *     （ISR 里的取帧逻辑只在收到 IN 令牌后才跑，那时已经太晚了）。
     * 后续帧由 EP1 IN 中断里的 ctaphid_next_report_out() 链式推进。 */
    if (ctaphid_ready_to_load() && ctaphid_next_report_out(pEP1_IN_DataBuf))
    {
        R8_UEP1_T_LEN = CTAPHID_HID_REPORT;
        R8_UEP1_CTRL  = (R8_UEP1_CTRL & ~MASK_UEP_T_RES) | UEP_T_RES_ACK;
    }
}

/*********************************************************************
 * USB传输处理函数 (仿照WCH参考代码)
 */
void USB_DevTransProcess(void)
{
    uint8_t len, chtype;
    uint8_t intflag, errflag = 0;

    intflag = R8_USB_INT_FG;

    if (intflag & RB_UIF_TRANSFER)
    {
        if ((R8_USB_INT_ST & MASK_UIS_TOKEN) != MASK_UIS_TOKEN)
        {
            switch (R8_USB_INT_ST & (MASK_UIS_TOKEN | MASK_UIS_ENDP))
            {
                case UIS_TOKEN_IN:
                {
                    switch (SetupReqCode)
                    {
                        case USB_GET_DESCRIPTOR:
                            len = SetupReqLen >= DevEP0SIZE ? DevEP0SIZE : SetupReqLen;
                            memcpy(pEP0_DataBuf, pDescr, len);
                            SetupReqLen -= len;
                            pDescr += len;
                            R8_UEP0_T_LEN = len;
                            R8_UEP0_CTRL ^= RB_UEP_T_TOG;
                            break;
                        case USB_SET_ADDRESS:
                            /* SET_ADDRESS 的状态阶段完成后才把设备地址写入 R8_USB_DEV_AD
                             * (SetupReqLen 在 SETUP 阶段已保存新地址的低 8 位)。
                             * 漏掉这一句，设备会一直只用地址 0 应答；主机改用新地址读取
                             * 描述符时得不到响应 -> Windows 报“请求 USB 设备描述符失败”(代码 43)。 */
                            R8_USB_DEV_AD = (R8_USB_DEV_AD & RB_UDA_GP_BIT) | (SetupReqLen & 0x7F);
                            R8_UEP0_CTRL = UEP_R_RES_ACK | UEP_T_RES_NAK;
                            Ready = 1;
                            break;
                        default:
                            R8_UEP0_T_LEN = 0;
                            R8_UEP0_CTRL = UEP_R_RES_ACK | UEP_T_RES_NAK;
                            Ready = 1;
                            break;
                    }
                    break;
                }

                case UIS_TOKEN_OUT:
                {
                    len = R8_USB_RX_LEN;
                    break;
                }

                case UIS_TOKEN_OUT | 1:
                {
                    if (R8_USB_INT_ST & RB_UIS_TOG_OK)
                    {
                        /* R_TOG 由 EP1 的 RB_UEP_AUTO_TOG 硬件翻转 */
                        len = R8_USB_RX_LEN;
                        if (len > CTAPHID_HID_REPORT)
                            len = CTAPHID_HID_REPORT;
                        ctaphid_report_in(pEP1_OUT_DataBuf, len);
                    }
                    break;
                }

                case UIS_TOKEN_IN | 1:
                {
                    /* T_TOG 由 EP1 的 RB_UEP_AUTO_TOG 硬件翻转；
                     * 有下一帧就 ACK 上传，否则回 NAK */
                    if (ctaphid_next_report_out(pEP1_IN_DataBuf))
                    {
                        R8_UEP1_T_LEN = CTAPHID_HID_REPORT;
                        R8_UEP1_CTRL = (R8_UEP1_CTRL & ~MASK_UEP_T_RES) | UEP_T_RES_ACK;
                    }
                    else
                    {
                        R8_UEP1_T_LEN = 0;
                        R8_UEP1_CTRL = (R8_UEP1_CTRL & ~MASK_UEP_T_RES) | UEP_T_RES_NAK;
                    }
                    Ready = 1;
                    break;
                }

                case UIS_TOKEN_OUT | 2:
                {
                    if (R8_USB_INT_ST & RB_UIS_TOG_OK)
                    {
                        len = R8_USB_RX_LEN;
                    }
                    break;
                }

                case UIS_TOKEN_IN | 2:
                    R8_UEP2_CTRL = (R8_UEP2_CTRL & ~MASK_UEP_T_RES) | UEP_T_RES_NAK;
                    break;

                case UIS_TOKEN_OUT | 3:
                {
                    if (R8_USB_INT_ST & RB_UIS_TOG_OK)
                    {
                        len = R8_USB_RX_LEN;
                    }
                    break;
                }

                case UIS_TOKEN_IN | 3:
                    R8_UEP3_CTRL = (R8_UEP3_CTRL & ~MASK_UEP_T_RES) | UEP_T_RES_NAK;
                    break;

                default:
                    break;
            }
            R8_USB_INT_FG = RB_UIF_TRANSFER;
        }

        if (R8_USB_INT_ST & RB_UIS_SETUP_ACT)
        {
            R8_UEP0_CTRL = RB_UEP_R_TOG | RB_UEP_T_TOG | UEP_R_RES_ACK | UEP_T_RES_NAK;
            SetupReqLen = pSetupReqPak->wLength;
            SetupReqCode = pSetupReqPak->bRequest;
            chtype = pSetupReqPak->bRequestType;

            len = 0;
            errflag = 0;

            if ((pSetupReqPak->bRequestType & USB_REQ_TYP_MASK) != USB_REQ_TYP_STANDARD)
            {
                // HID类请求处理
                if ((pSetupReqPak->bRequestType & 0x60) == 0x20)  // 类请求 Host->Device
                {
                    switch (SetupReqCode)
                    {
                        case 0x0A:  // SET_IDLE
                            break;
                        case 0x0B:  // SET_PROTOCOL
                            break;
                        default:
                            errflag = 0xFF;
                            break;
                    }
                }
                else if ((pSetupReqPak->bRequestType & 0x60) == 0x40)  // 类请求 Device->Host
                {
                    errflag = 0xFF;
                }
                else
                {
                    errflag = 0xFF;
                }

                if (errflag != 0xFF) {
                    memcpy(pEP0_DataBuf, pDescr, len);
                }
            }
            else /* 标准请求 */
            {
                switch (SetupReqCode)
                {
                    case USB_GET_DESCRIPTOR:
                    {
                        switch (((pSetupReqPak->wValue) >> 8))
                        {
                            case USB_DESCR_TYP_DEVICE:
                                pDescr = MyDevDescr;
                                len = sizeof(MyDevDescr);
                                break;

                            case USB_DESCR_TYP_CONFIG:
                                pDescr = MyCfgDescr;
                                len = sizeof(MyCfgDescr);
                                break;

                            case USB_DESCR_TYP_HID:
                                switch ((pSetupReqPak->wIndex) & 0xff)
                                {
                                    case 0:
                                        pDescr = (uint8_t *)(&MyCfgDescr[18]);
                                        len = 9;
                                        break;
                                    default:
                                        errflag = 0xff;
                                        break;
                                }
                                break;

                            case USB_DESCR_TYP_REPORT:
                                if ((pSetupReqPak->wIndex & 0xff) == 0)
                                {
                                    pDescr = HIDDescr;
                                    len = sizeof(HIDDescr);
                                }
                                else
                                    len = 0xff;
                                break;

                            case USB_DESCR_TYP_STRING:
                                switch ((pSetupReqPak->wValue) & 0xff)
                                {
                                    case 1:
                                        pDescr = MyManuInfo;
                                        len = MyManuInfo[0];
                                        break;
                                    case 2:
                                        pDescr = MyProdInfo;
                                        len = MyProdInfo[0];
                                        break;
                                    case 0:
                                        pDescr = MyLangDescr;
                                        len = MyLangDescr[0];
                                        break;
                                    default:
                                        errflag = 0xFF;
                                        break;
                                }
                                break;

                            default:
                                errflag = 0xff;
                                break;
                        }
                        if (SetupReqLen > len)
                            SetupReqLen = len;
                        len = (SetupReqLen >= DevEP0SIZE) ? DevEP0SIZE : SetupReqLen;
                        memcpy(pEP0_DataBuf, pDescr, len);
                        pDescr += len;
                        break;
                    }

                    case USB_SET_ADDRESS:
                        /* 与官方 HID_CompliantDev 一致：这里只暂存主机分配的地址，
                         * 等状态阶段结束后（下一条 EP0 IN 令牌）再写入 R8_USB_DEV_AD */
                        SetupReqLen = (pSetupReqPak->wValue) & 0xff;
                        Ready = 1;
                        break;

                    case USB_GET_CONFIGURATION:
                        pEP0_DataBuf[0] = DevConfig;
                        if (SetupReqLen > 1)
                            SetupReqLen = 1;
                        break;

                    case USB_SET_CONFIGURATION:
                        DevConfig = (pSetupReqPak->wValue) & 0xff;
                        break;

                    case USB_CLEAR_FEATURE:
                    {
                        if ((pSetupReqPak->bRequestType & USB_REQ_RECIP_MASK) == USB_REQ_RECIP_ENDP)
                        {
                            switch ((pSetupReqPak->wIndex) & 0xff)
                            {
                                case 0x81:
                                    R8_UEP1_CTRL = (R8_UEP1_CTRL & ~(RB_UEP_T_TOG | MASK_UEP_T_RES)) | UEP_T_RES_NAK;
                                    break;
                                case 0x01:
                                    R8_UEP1_CTRL = (R8_UEP1_CTRL & ~(RB_UEP_R_TOG | MASK_UEP_R_RES)) | UEP_R_RES_ACK;
                                    break;
                                default:
                                    errflag = 0xFF;
                                    break;
                            }
                        }
                        else
                            errflag = 0xFF;
                    }
                        break;

                    case USB_GET_INTERFACE:
                        pEP0_DataBuf[0] = 0x00;
                        if (SetupReqLen > 1)
                            SetupReqLen = 1;
                        break;

                    case USB_GET_STATUS:
                        pEP0_DataBuf[0] = 0x00;
                        pEP0_DataBuf[1] = 0x00;
                        if (SetupReqLen > 2)
                            SetupReqLen = 2;
                        break;

                    default:
                        errflag = 0xff;
                        break;
                }
            }

            if (errflag == 0xff)
            {
                R8_UEP0_CTRL = RB_UEP_R_TOG | RB_UEP_T_TOG | UEP_R_RES_STALL | UEP_T_RES_STALL;
            }
            else
            {
                if (chtype & 0x80)
                {
                    len = (SetupReqLen > DevEP0SIZE) ? DevEP0SIZE : SetupReqLen;
                    SetupReqLen -= len;
                }
                else
                    len = 0;
                R8_UEP0_T_LEN = len;
                R8_UEP0_CTRL = RB_UEP_R_TOG | RB_UEP_T_TOG | UEP_R_RES_ACK | UEP_T_RES_ACK;
            }

            R8_USB_INT_FG = RB_UIF_TRANSFER;
        }
    }
    else if (intflag & RB_UIF_BUS_RST)
    {
        R8_USB_DEV_AD = 0;
        R8_UEP0_CTRL = UEP_R_RES_ACK | UEP_T_RES_NAK;
        R8_UEP1_CTRL = UEP_R_RES_ACK | UEP_T_RES_NAK | RB_UEP_AUTO_TOG;
        R8_UEP2_CTRL = UEP_R_RES_ACK | UEP_T_RES_NAK | RB_UEP_AUTO_TOG;
        R8_UEP3_CTRL = UEP_R_RES_ACK | UEP_T_RES_NAK | RB_UEP_AUTO_TOG;
        ctaphid_reset();
        Ready = 0;
        DevConfig = 0;
        R8_USB_INT_FG = RB_UIF_BUS_RST;
    }
    else if (intflag & RB_UIF_SUSPEND)
    {
        if (R8_USB_MIS_ST & RB_UMS_SUSPEND)
        {
            ;
        }
        else
        {
            ;
        }
        R8_USB_INT_FG = RB_UIF_SUSPEND;
    }
    else
    {
        R8_USB_INT_FG = intflag;
    }
}

/**
 * @brief USB中断函数
 */
__attribute__((interrupt("WCH-Interrupt-fast")))
__attribute__((section(".highcode")))
void USB_IRQHandler(void)
{
    USB_DevTransProcess();
}

/* handle_get_info / handle_make_credential / handle_get_assertion
 * 已迁移到 ctap.c（CTAP2 命令层，CBOR 编码符合 CTAP 2.3） */
