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

// CTAPHID/CTAP 命令常量（取值见 FIDO CTAPHID 规范）
#ifndef CTAPHID_PING
#define CTAPHID_PING                    0x01
#endif
#ifndef CTAPHID_MSG
#define CTAPHID_MSG                     0x03
#endif
#ifndef CTAPHID_LOCK
#define CTAPHID_LOCK                    0x04
#endif
#ifndef CTAPHID_INIT
#define CTAPHID_INIT                    0x06
#endif
#ifndef CTAPHID_WINK
#define CTAPHID_WINK                    0x08
#endif
#ifndef CTAPHID_CBOR
#define CTAPHID_CBOR                    0x10
#endif
#ifndef CTAPHID_CANCEL
#define CTAPHID_CANCEL                  0x11
#endif
#ifndef CTAPHID_KEEPALIVE
#define CTAPHID_KEEPALIVE               0x3B
#endif
#ifndef CTAPHID_ERROR
#define CTAPHID_ERROR                   0x3F
#endif
// CTAPHID 协议版本号（INIT 响应中返回）
#ifndef CTAPHID_PROTOCOL_VERSION
#define CTAPHID_PROTOCOL_VERSION        2
#endif
// CTAPHID 报文头：4 字节 Channel ID + 1 字节命令
#ifndef CTAPHID_HEADER_LEN
#define CTAPHID_HEADER_LEN              5
#endif
// CTAPHID_ERROR 错误码
#ifndef CTAPHID_ERR_INVALID_CMD
#define CTAPHID_ERR_INVALID_CMD         0x01
#endif
#ifndef CTAPHID_ERR_INVALID_LEN
#define CTAPHID_ERR_INVALID_LEN         0x03
#endif
#ifndef CTAP_CBOR_GET_INFO
#define CTAP_CBOR_GET_INFO              0x01
#endif
#ifndef CTAP_CBOR_MAKE_CREDENTIAL
#define CTAP_CBOR_MAKE_CREDENTIAL       0x02
#endif
#ifndef CTAP_CBOR_GET_ASSERTION
#define CTAP_CBOR_GET_ASSERTION         0x03
#endif
#ifndef CTAP_ERR_INVALID_MESSAGE
#define CTAP_ERR_INVALID_MESSAGE        0x02
#endif
#ifndef CTAP_SUCCESS
#define CTAP_SUCCESS                    0x00
#endif
#ifndef CTAP_ERR_INVALID_CBOR_TYPE
#define CTAP_ERR_INVALID_CBOR_TYPE      0x32
#endif
#ifndef CTAP_ERR_NO_CREDENTIALS
#define CTAP_ERR_NO_CREDENTIALS         0x33
#endif
#ifndef CTAP_MAX_MSG_SIZE
#define CTAP_MAX_MSG_SIZE               1200
#endif

// 函数前置声明
extern uint8_t handle_get_info(uint8_t *buf, uint8_t buf_len);
extern uint8_t handle_make_credential(uint8_t *buf, uint8_t buf_len);
extern uint8_t handle_get_assertion(uint8_t *buf, uint8_t buf_len);

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
/*HID类报表描述符*/
const uint8_t HIDDescr[] = {  0x06, 0x00,0xff,
                              0x09, 0x01,
                              0xa1, 0x01,                                                   //集合开始
                              0x09, 0x02,                                                   //Usage Page  用法
                              0x15, 0x00,                                                   //Logical  Minimun
                              0x26, 0x00,0xff,                                              //Logical  Maximun
                              0x75, 0x08,                                                   //Report Size
                              0x95, 0x40,                                                   //Report Counet
                              0x81, 0x06,                                                   //Input
                              0x09, 0x02,                                                   //Usage Page  用法
                              0x15, 0x00,                                                   //Logical  Minimun
                              0x26, 0x00,0xff,                                              //Logical  Maximun
                              0x75, 0x08,                                                   //Report Size
                              0x95, 0x40,                                                   //Report Counet
                              0x91, 0x06,                                                   //Output
                              0xC0};
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

// CTAPHID协议缓冲区
uint8_t hid_out_buffer[64];  // OUT端点接收数据
uint8_t hid_out_len = 0;     // 接收数据长度
volatile uint8_t hid_rx_ready = 0;  // RX完成标志

uint8_t hid_in_buffer[64];   // IN端点发送数据
uint8_t hid_in_len = 0;
uint8_t hid_in_offset = 0;
volatile uint8_t hid_in_sent = 1;  // 1 = 空闲（上一帧已上传完），0 = 正在向主机上传

uint32_t hid_channel_id = 0xFFFFFFFF;
uint8_t hid_init_done = 0;

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
}

/**
 * @brief 通过HID IN端点发送数据给主机
 */
void USBSendData(uint8_t *SendBuf, uint8_t l)
{
    if (l > 64) l = 64;
    memcpy(hid_in_buffer, SendBuf, l);
    hid_in_len = l;
    hid_in_offset = 0;
    hid_in_sent = 0;
}

/**
 * @brief 获取主机下发的HID数据
 */
uint8_t app_usb_hid_get_data(uint8_t *buf, uint8_t *len)
{
    if (hid_rx_ready == 0) {
        return -1;
    }
    *len = hid_out_len;
    memcpy(buf, hid_out_buffer, hid_out_len);
    return 0;
}

/**
 * @brief 发送HID响应给主机 (非阻塞)
 */
int app_usb_hid_send(const uint8_t *data, uint8_t len)
{
    if (len > 64) len = 64;
    if (hid_in_sent == 0) {
        return -1;  // 正在上传中，忙
    }
    memcpy(hid_in_buffer, data, len);
    hid_in_len = len;
    hid_in_offset = 0;
    hid_in_sent = 0;
    return 0;
}

/**
 * @brief 重置接收标志
 */
void app_usb_hid_reset_rx(void)
{
    hid_rx_ready = 0;
    hid_out_len = 0;
}

/**
 * @brief CTAPHID协议处理
 */
void app_usb_hid_process(void)
{
    uint8_t response[64];
    uint32_t channel_id;
    uint8_t msg_type;
    uint8_t payload_len;
    uint8_t resp_len = 0;

    if (hid_rx_ready == 0) {
        return;
    }
    if (hid_out_len < CTAPHID_HEADER_LEN) {
        hid_rx_ready = 0;
        hid_out_len = 0;
        return;
    }

    // 解析Channel ID (小端序)
    channel_id = (uint32_t)hid_out_buffer[3] << 24 |
                 (uint32_t)hid_out_buffer[2] << 16 |
                 (uint32_t)hid_out_buffer[1] << 8 |
                 (uint32_t)hid_out_buffer[0];

    // 解析Message Type
    msg_type = hid_out_buffer[4];
    payload_len = hid_out_len - CTAPHID_HEADER_LEN;

    hid_channel_id = channel_id;

    memset(response, 0, sizeof(response));

    // 所有 CTAPHID 响应都以 4 字节 Channel ID + (命令 | 0x80) 开头
    response[0] = (uint8_t)(channel_id);
    response[1] = (uint8_t)(channel_id >> 8);
    response[2] = (uint8_t)(channel_id >> 16);
    response[3] = (uint8_t)(channel_id >> 24);
    response[4] = msg_type | 0x80;

    switch (msg_type) {
        case CTAPHID_PING:
            // 回显 payload（单帧内最大 64 - 5 = 59 字节）
            if (payload_len > sizeof(response) - CTAPHID_HEADER_LEN) {
                payload_len = sizeof(response) - CTAPHID_HEADER_LEN;
            }
            memcpy(response + CTAPHID_HEADER_LEN,
                   hid_out_buffer + CTAPHID_HEADER_LEN, payload_len);
            resp_len = CTAPHID_HEADER_LEN + payload_len;
            break;

        case CTAPHID_INIT:
            // nonce(8) 回显 + newCID(4) + 协议版本(1) + 设备版本(3) + caps(1)
            if (payload_len < 8) {
                response[4] = CTAPHID_ERROR;
                response[5] = CTAPHID_ERR_INVALID_LEN;
                resp_len = CTAPHID_HEADER_LEN + 1;
                break;
            }
            memcpy(response + 5, hid_out_buffer + 5, 8);   // nonce 原样回显
            // newCID 全 0：不分配新通道，主机继续沿用原 Channel ID
            response[13] = 0x00;
            response[14] = 0x00;
            response[15] = 0x00;
            response[16] = 0x00;
            response[17] = CTAPHID_PROTOCOL_VERSION;       // CTAPHID 协议版本
            response[18] = 0x00;                           // 设备版本 major
            response[19] = 0x01;                           // 设备版本 minor
            response[20] = 0x00;                           // 设备版本 build
            response[21] = 0x05;                           // caps: WINK(0x01) | CBOR(0x04)
            hid_init_done = 1;
            resp_len = 22;
            break;

        case CTAPHID_WINK:
            resp_len = CTAPHID_HEADER_LEN;                 // 空响应
            break;

        case CTAPHID_CANCEL:
            resp_len = CTAPHID_HEADER_LEN;                 // CANCEL 无需响应体
            break;

        case CTAPHID_MSG:
        case CTAPHID_CBOR:
            if (msg_type == CTAPHID_CBOR && payload_len > 0) {
                uint8_t ctap_cmd = hid_out_buffer[5];
                uint8_t ctap_resp_code;

                switch (ctap_cmd) {
                    case CTAP_CBOR_GET_INFO:
                        ctap_resp_code = handle_get_info(response + CTAPHID_HEADER_LEN,
                                                         sizeof(response) - CTAPHID_HEADER_LEN);
                        break;
                    case CTAP_CBOR_MAKE_CREDENTIAL:
                        ctap_resp_code = handle_make_credential(response + CTAPHID_HEADER_LEN,
                                                                sizeof(response) - CTAPHID_HEADER_LEN);
                        break;
                    case CTAP_CBOR_GET_ASSERTION:
                        ctap_resp_code = handle_get_assertion(response + CTAPHID_HEADER_LEN,
                                                              sizeof(response) - CTAPHID_HEADER_LEN);
                        break;
                    default:
                        ctap_resp_code = CTAP_ERR_INVALID_MESSAGE;
                        break;
                }

                if (ctap_resp_code == CTAP_SUCCESS) {
                    // CTAP 响应数据过大时本实现暂不支持 CTAPHID 续帧
                    resp_len = CTAPHID_HEADER_LEN;
                } else {
                    response[4] = CTAPHID_ERROR;
                    response[5] = ctap_resp_code;
                    resp_len = CTAPHID_HEADER_LEN + 1;
                }
            } else {
                response[4] = CTAPHID_ERROR;
                response[5] = CTAPHID_ERR_INVALID_CMD;
                resp_len = CTAPHID_HEADER_LEN + 1;
            }
            break;

        default:
            response[4] = CTAPHID_ERROR;
            response[5] = CTAPHID_ERR_INVALID_CMD;
            resp_len = CTAPHID_HEADER_LEN + 1;
            break;
    }

    if (resp_len > 0) {
        app_usb_hid_send(response, resp_len);
    }

    hid_rx_ready = 0;
    hid_out_len = 0;
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
                        /* EP1 已使能 RB_UEP_AUTO_TOG，R_TOG 由硬件翻转，软件不得再手动翻转 */
                        len = R8_USB_RX_LEN;
                        if (len > sizeof(hid_out_buffer))
                            len = sizeof(hid_out_buffer);
                        memcpy(hid_out_buffer, pEP1_OUT_DataBuf, len);
                        hid_out_len = len;
                        hid_rx_ready = 1;
                    }
                    break;
                }

                case UIS_TOKEN_IN | 1:
                {
                    /* EP1 已使能 RB_UEP_AUTO_TOG，T_TOG 由硬件翻转，软件不得再手动翻转 */
                    if (hid_in_sent == 0 && hid_in_len > 0) {
                        len = hid_in_len > 64 ? 64 : hid_in_len;
                        memcpy(pEP1_IN_DataBuf, hid_in_buffer + hid_in_offset, len);
                        hid_in_offset += len;
                        hid_in_len -= len;
                        if (hid_in_len == 0) {
                            hid_in_sent = 1;
                            hid_in_offset = 0;
                        }
                        R8_UEP1_T_LEN = len;
                        R8_UEP1_CTRL = (R8_UEP1_CTRL & ~MASK_UEP_T_RES) | UEP_T_RES_ACK;
                    } else {
                        /* 没有待发数据：回 NAK，避免向主机发送 0 长度 HID 报告 */
                        hid_in_sent = 1;
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
        hid_rx_ready = 0;
        hid_in_sent = 1;
        hid_init_done = 0;
        hid_channel_id = 0xFFFFFFFF;
        hid_out_len = 0;
        hid_in_len = 0;
        hid_in_offset = 0;
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

/**
 * @brief GetInfo CTAP命令处理
 */
uint8_t handle_get_info(uint8_t *buf, uint8_t buf_len)
{
    if (buf_len < 100) return CTAP_ERR_INVALID_CBOR_TYPE;
    
    // 构建GetInfo响应 CBOR编码
    buf[0] = 0x04; // array (4 items)
    buf[1] = 0x68; // text string 8 bytes
    buf[2] = 'F';  // "FIDO_2.0"
    buf[3] = 'I';
    buf[4] = 'D';
    buf[5] = 'O';
    buf[6] = '_';
    buf[7] = '2';
    buf[8] = '.';
    buf[9] = '0';
    buf[10] = 0x68;
    buf[11] = 'F';
    buf[12] = 'I';
    buf[13] = 'D';
    buf[14] = 'O';
    buf[15] = '_';
    buf[16] = '2';
    buf[17] = '.';
    buf[18] = '1';
    buf[19] = 0x80; // empty array (extensions)
    buf[20] = 0x50; // bytes 16 (aaguid)
    memcpy(buf + 21, g_aaguid, 16);
    buf += 37;
    
    // options map
    buf[0] = 0xA2; // map with 2 entries
    buf[1] = 0x62; // "up"
    buf[2] = 'u';
    buf[3] = 'p';
    buf[4] = 0xF5; // true
    buf[5] = 0x62; // "rk"
    buf[6] = 'r';
    buf[7] = 'k';
    buf[8] = 0xF5; // true
    buf += 9;
    
    // maxMsgSize
    buf[0] = 0x69; // "maxMsgSize"
    buf[1] = 'm';
    buf[2] = 'a';
    buf[3] = 'x';
    buf[4] = 'M';
    buf[5] = 's';
    buf[6] = 'g';
    buf[7] = 'S';
    buf[8] = 'i';
    buf[9] = 'z';
    buf[10] = 'e';
    buf[11] = ' ';
    buf[12] = 0x1A; // uint32
    uint32_t max_size = CTAP_MAX_MSG_SIZE;
    buf[13] = (max_size >> 24) & 0xFF;
    buf[14] = (max_size >> 16) & 0xFF;
    buf[15] = (max_size >> 8) & 0xFF;
    buf[16] = max_size & 0xFF;
    buf += 17;
    
    // transports
    buf[0] = 0x81; // array with 1 item
    buf[1] = 0x63; // "usb"
    buf[2] = 'u';
    buf[3] = 'S';
    buf[4] = 'B';
    
    return CTAP_SUCCESS;
}

/**
 * @brief MakeCredential CTAP命令处理
 */
uint8_t handle_make_credential(uint8_t *buf, uint8_t buf_len)
{
    return CTAP_ERR_INVALID_OPTION;
}

/**
 * @brief GetAssertion CTAP命令处理
 */
uint8_t handle_get_assertion(uint8_t *buf, uint8_t buf_len)
{
    return CTAP_ERR_NO_CREDENTIALS;
}
