/**
 * @file ctap.h
 * @brief CTAP2 命令层接口（CBOR over CTAPHID）
 *
 * 对应开发计划 阶段三：FIDO2 CTAP 协议实现
 */

#ifndef __CTAP_H
#define __CTAP_H

#include "stdint.h"

/*********************************************************************
 * CTAP2 命令码（CTAP 2.3 §11.2 authenticatorMakeCredential 等）
 */
#define CTAP_CMD_MAKE_CREDENTIAL        0x01
#define CTAP_CMD_GET_ASSERTION          0x02
#define CTAP_CMD_GET_INFO               0x04
#define CTAP_CMD_CLIENT_PIN             0x06
#define CTAP_CMD_RESET                  0x07
#define CTAP_CMD_GET_NEXT_ASSERTION     0x08
#define CTAP_CMD_CREDENTIAL_MGMT        0x0A

/*********************************************************************
 * CTAP2 状态码（CTAP 2.3 §6.3）
 */
#define CTAP_SUCCESS                    0x00
#define CTAP_ERR_INVALID_COMMAND        0x01
#define CTAP_ERR_INVALID_PARAMETER      0x02
#define CTAP_ERR_INVALID_LEN            0x03
#define CTAP_ERR_INVALID_SEQ            0x04
#define CTAP_ERR_TIMEOUT                0x05
#define CTAP_ERR_CHANNEL_BUSY           0x06
#define CTAP_ERR_CREDENTIAL_EXCLUDED    0x19
#define CTAP_ERR_KEY_STORE_FULL         0x28
#define CTAP_ERR_UNSUPPORTED_OPTION     0x2B
#define CTAP_ERR_CBOR_UNEXPECTED_TYPE   0x11
#define CTAP_ERR_INVALID_CBOR           0x12
#define CTAP_ERR_MISSING_PARAMETER      0x14
#define CTAP_ERR_LIMIT_EXCEEDED         0x15
#define CTAP_ERR_UNSUPPORTED_ALGORITHM  0x26
#define CTAP_ERR_OPERATION_DENIED       0x27
#define CTAP_ERR_NO_CREDENTIALS         0x2E
#define CTAP_ERR_ACTION_TIMEOUT         0x3A    /* 未在超时内取得用户存在 */
#define CTAP_ERR_OTHER                  0x7F

/* ---- 内部状态（非 CTAP 协议码，仅用于层间传递）---- */
/* CTAP 命令处理到需要等待用户存在（UP）时返回此值：
 * 上层不应发送响应，而应稍后通过 ctaphid_ctap_reply() 回填。 */
#define CTAP_STATUS_PENDING             0xFD

/* 本实现对外声明的最大消息长度 */
#define CTAP_MAX_MSG_SIZE               1200

/**
 * @brief  处理一条 CTAP2 CBOR 请求
 *
 * @param  cmd        CTAP 命令码（CTAP_CMD_*）
 * @param  param      CBOR 编码的参数（不含命令字节），可为 NULL
 * @param  param_len  参数长度
 * @param  resp       输出缓冲
 * @param  resp_max   输出缓冲可用长度
 * @param  resp_len   输出：实际写入的响应长度
 *
 * @return CTAP_SUCCESS 成功；否则为 CTAP2 状态码（此时 resp_len 无意义，
 *        调用方应把状态码作为 1 字节响应体返回）
 */
uint8_t ctap_handle_cbor(uint8_t cmd,
                         const uint8_t *param, uint16_t param_len,
                         uint8_t *resp, uint16_t resp_max,
                         uint16_t *resp_len);

/**
 * @brief 推进被挂起的 CTAP 操作（等用户按键的那种）
 * @note  由主循环反复调用；取得 UP 或超时后会自动把响应回填给 ctaphid 层。
 */
void ctap_pending_poll(void);

/**
 * @brief 中止挂起的操作（CTAPHID_CANCEL 用）
 * @note  清掉 UP 等待状态让设备回到空闲。按规范不产生任何响应。
 */
void ctap_abort_pending(void);

#endif /* __CTAP_H */
