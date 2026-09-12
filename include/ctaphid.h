/**
 * @file ctaphid.h
 * @brief CTAPHID 传输层（USB HID 64 字节报文 <-> 分片消息）
 *
 * 对应开发计划 3.1 CTAP 协议框架。
 *
 * CTAPHID 报文格式（FIDO CTAPHID 规范）：
 *   初始帧: ChannelID(4) | CMD|0x80(1) | BCNTH(1) | BCNTL(1) | DATA(<=57)
 *   续  帧: ChannelID(4) | SEQ(1)       |           DATA(<=59)
 * 一个 CTAPHID 消息最长 7609 字节，必须分片到多个 64 字节 HID 报告里。
 */

#ifndef __CTAPHID_H
#define __CTAPHID_H

#include "stdint.h"

/* USB HID 中断端点的报告长度（与报告描述符一致） */
#define CTAPHID_HID_REPORT              64
/* CTAPHID 报文头长度：4 字节 ChannelID + 1 字节命令 */
#define CTAPHID_HEADER_LEN              5
/* 初始帧头部：ChannelID(4) + CMD(1) + BCNTH(1) + BCNTL(1) */
#define CTAPHID_INIT_HEADER_LEN         7

/* 本实现支持的最大 CTAPHID 消息长度（规范上限为 7609） */
#define CTAPHID_MAX_MSG                 1024

/*********************************************************************
 * CTAPHID 命令码
 */
#define CTAPHID_CMD_PING                0x01
#define CTAPHID_CMD_MSG                 0x03
#define CTAPHID_CMD_LOCK                0x04
#define CTAPHID_CMD_INIT                0x06
#define CTAPHID_CMD_WINK                0x08
#define CTAPHID_CMD_CBOR                0x10
#define CTAPHID_CMD_CANCEL              0x11
#define CTAPHID_CMD_KEEPALIVE           0x3B

/* CTAPHID_KEEPALIVE 的状态码（KEEPALIVE 的载荷就是这一个字节） */
#define CTAPHID_KEEPALIVE_STATUS_PROCESSING  0x01   /* 正在处理 */
#define CTAPHID_KEEPALIVE_STATUS_UPNEEDED    0x02   /* 正在等待用户确认 */
#define CTAPHID_CMD_ERROR               0x3F

/* 初始帧标记（命令字节最高位） */
#define CTAPHID_CMD_INIT_FLAG           0x80

/*********************************************************************
 * CTAPHID 错误码
 */
#define CTAPHID_ERR_INVALID_CMD         0x01
#define CTAPHID_ERR_INVALID_PARAM       0x02
#define CTAPHID_ERR_INVALID_LEN         0x03
#define CTAPHID_ERR_INVALID_SEQ         0x04
#define CTAPHID_ERR_MSG_TIMEOUT         0x05
#define CTAPHID_ERR_CHANNEL_BUSY        0x06
#define CTAPHID_ERR_LOCK_REQUIRED       0x0A
#define CTAPHID_ERR_INVALID_CHANNEL     0x0B
#define CTAPHID_ERR_OTHER               0x7F

/* CTAPHID 协议版本 + 能力位 */
#define CTAPHID_PROTOCOL_VERSION        2
#define CTAPHID_CAP_WINK                0x01
#define CTAPHID_CAP_LOCK                0x02
#define CTAPHID_CAP_CBOR                0x04
#define CTAPHID_CAP_NMSG                0x08

/* 广播通道（未建立通道前主机使用的 ChannelID） */
#define CTAPHID_BROADCAST_CID           0xFFFFFFFF

/**
 * @brief  初始化 CTAPHID 层
 */
void ctaphid_init(void);

/**
 * @brief  USB 总线复位时清空收发状态机
 */
void ctaphid_reset(void);

/**
 * @brief  主机下发了一个 64 字节 HID 报告（在 EP1 OUT 中断里调用）
 *
 * @param  report  报告数据（>= len 字节）
 * @param  len     实际收到的字节数
 */
void ctaphid_report_in(const uint8_t *report, uint8_t len);

/**
 * @brief  主循环调用：把已收齐的请求交给 CTAP 处理并准备响应
 */
void ctaphid_process(void);

/**
 * @brief  EP1 IN 中断里调用：取下一个待发给主机的 64 字节报告
 *
 * @param  report  输出缓冲，必须能容纳 CTAPHID_HID_REPORT 字节
 *
 * @return 1 = 已填入一帧（应 ACK 上传），0 = 无数据（应回 NAK）
 */
int ctaphid_next_report_out(uint8_t *report);

/**
 * @brief  查询是否有待上传的数据
 */
int ctaphid_has_pending_out(void);

/**
 * @brief  是否有"尚未装载到 HID 缓冲"的新响应第一帧
 *
 * 主循环用它判断：该先把第一帧填进 EP1 IN 缓冲、再置端点为 ACK。
 */
int ctaphid_ready_to_load(void);

/**
 * @brief CTAP 命令是否处于挂起状态（等待异步完成，例如等用户按键）
 */
int ctaphid_ctap_is_pending(void);

/**
 * @brief 异步完成后回填 CTAP 响应
 * @param ctap_status CTAP_SUCCESS 或错误码
 * @param body        成功时的响应体（会拷入内部 TX 缓冲）
 * @param body_len    响应体长度
 * @return 0=成功, -1=当前没有挂起的请求或参数错误
 */
int ctaphid_ctap_reply(uint8_t ctap_status, const uint8_t *body, uint16_t body_len);

/**
 * @brief 用保留的请求报体重跑一次 CTAP 处理（供取得 UP 后重放）
 *
 * 配合 ctap_pending_poll() 使用：CTAP 命令因未取得 UP 而挂起后，
 * 用户按键确认时调用本函数重跑同一个命令。
 *
 * @return 0=已产生响应, -1=没有挂起请求或仍在等待
 */
int ctaphid_reprocess(void);

#endif /* __CTAPHID_H */
