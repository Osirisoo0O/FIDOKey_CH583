/**
 * @file ctaphid.c
 * @brief CTAPHID 传输层实现：USB HID 64 字节报告 <-> 分片消息
 *
 * 对应开发计划 3.1 CTAP 协议框架。
 *
 * 发送方向（设备->主机）：初始帧 + 依次递增序号的续帧，每帧恰好 64 字节。
 * 接收方向（主机->设备）：按 BCNTH/BCNTL 收满指定长度后交给 ctap 层。
 */

#include "stdint.h"
#include "string.h"
#include "ctaphid.h"
#include "debug_log.h"
#include "ctap.h"

/* 待发响应缓冲（GetInfo 41B、含签名的断言响应约 300B，512 足够且有 RAM 余量） */
#define CTAPHID_MAX_TX_MSG              512

/* ---------------- 接收状态机 ---------------- */
static uint8_t  rx_buf[CTAPHID_MAX_MSG];
static uint16_t rx_len;          /* 已收字节数           */
static uint16_t rx_total;        /* 本消息期望总长       */
static uint8_t  rx_seq;          /* 下一个期望的续帧序号 */
static uint8_t  rx_cmd;          /* 命令码（去掉初始帧位）*/
static uint8_t  rx_active;       /* 正在接收             */
static uint32_t rx_cid;          /* 本次传输的通道       */

/* ---------------- 已收齐、待处理的请求 ---------------- */
static uint8_t  req_ready;
static uint32_t req_cid;
static uint8_t  req_cmd;
static uint16_t req_len;

/* ---------------- 发送状态机 ---------------- */
static uint8_t  tx_buf[CTAPHID_MAX_TX_MSG];
static uint32_t tx_cid;
static uint8_t  tx_cmd;
static uint16_t tx_len;
static uint16_t tx_offset;
static uint8_t  tx_seq;
static uint8_t  tx_active;

/* ---- 挂起的 CTAP 请求（等待异步完成，如等用户按键） ---- */
static uint32_t s_pend_cid;

static uint8_t  s_ctap_pending;

/* 等待用户确认期间，CTAP 规范要求定期上报 CTAPHID_KEEPALIVE，
 * 否则主机会在自身超时（Chrome 约 10s）后放弃整个操作 ——
 * 表现就是"LED 在闪，但按了键网页没反应"。 */
static uint32_t s_keepalive_last = 0;
extern uint32_t TMOS_GetSystemClock(void);

/*********************************************************************
 * 内部辅助
 */

static void ctaphid_clear(void)
{
    rx_len = 0;
    rx_total = 0;
    rx_seq = 0;
    rx_cmd = 0;
    rx_active = 0;
    rx_cid = 0;

    req_ready = 0;
    req_cid = 0;
    req_cmd = 0;
    req_len = 0;

    tx_len = 0;
    tx_offset = 0;
    tx_seq = 0;
    tx_active = 0;
    tx_cid = 0;
    tx_cmd = 0;

    s_pend_cid = 0;
    s_ctap_pending = 0;
}

static void ctaphid_tx_start(uint32_t cid, uint8_t cmd, uint16_t len)
{
    if (len > sizeof(tx_buf)) {
        len = sizeof(tx_buf);
    }
    tx_cid    = cid;
    tx_cmd    = cmd;
    tx_len    = len;
    tx_offset = 0;
    tx_seq    = 0;
    tx_active = 1;
}

static void ctaphid_send_error(uint32_t cid, uint8_t err)
{
    tx_buf[0] = err;
    ctaphid_tx_start(cid, CTAPHID_CMD_ERROR, 1);
}

/*********************************************************************
 * @fn      ctaphid_init
 */
void ctaphid_init(void)
{
    ctaphid_clear();
}

/*********************************************************************
 * @fn      ctaphid_reset
 *
 * @brief   USB 总线复位：清空所有收发状态
 */
void ctaphid_reset(void)
{
    ctaphid_clear();
}

/*********************************************************************
 * @fn      ctaphid_report_in
 *
 * @brief   主机下发了一个 64 字节 HID 报告（EP1 OUT 中断中调用）
 */
void ctaphid_report_in(const uint8_t *report, uint8_t len)
{
    uint32_t cid;
    uint8_t  cmd;

    if (report != NULL && len >= CTAPHID_HEADER_LEN) {
    }

    if (report == NULL || len < CTAPHID_HEADER_LEN) {
        return;
    }
    /* 上一个请求还没被主循环取走：丢弃，避免破坏 rx_buf */
    if (req_ready) {
        return;
    }
    /* 有 CTAP 操作正在等用户按键：rx_buf 必须原样保留以便重放，其余报文一律丢弃。
     * 唯一例外是同通道的 CTAPHID_CANCEL —— 用户点了"取消"就该立即停止等待，
     * 而不是让设备干等到 UP 超时。CANCEL 按规范不产生响应。 */
    if (s_ctap_pending) {
        uint32_t pcid = (uint32_t)report[0] |
                        ((uint32_t)report[1] << 8) |
                        ((uint32_t)report[2] << 16) |
                        ((uint32_t)report[3] << 24);
        uint8_t  pcmd = (uint8_t)(report[4] & (uint8_t)(~CTAPHID_CMD_INIT_FLAG));

        if (pcid == s_pend_cid && pcmd == CTAPHID_CMD_CANCEL) {
            s_ctap_pending = 0;
            ctap_abort_pending();       /* 清 CTAP 侧的 UP 等待状态 */
        }
        return;
    }

    cid = (uint32_t)report[0] |
          ((uint32_t)report[1] << 8) |
          ((uint32_t)report[2] << 16) |
          ((uint32_t)report[3] << 24);
    cmd = report[4];

    if (cmd & CTAPHID_CMD_INIT_FLAG)
    {
        /* ---------------- 初始帧 ---------------- */
        uint16_t total;
        uint8_t  n;

        if (len < CTAPHID_INIT_HEADER_LEN) {
            return;
        }
        total = ((uint16_t)report[5] << 8) | report[6];

        if (total > CTAPHID_MAX_MSG) {
            /* 超出本实现能力 */
            ctaphid_send_error(cid, CTAPHID_ERR_INVALID_LEN);
            return;
        }

        rx_cid    = cid;
        rx_cmd    = (uint8_t)(cmd & ~CTAPHID_CMD_INIT_FLAG);
        rx_total  = total;
        rx_seq    = 0;
        rx_len    = 0;
        rx_active = 1;

        n = (uint8_t)(len - CTAPHID_INIT_HEADER_LEN);
        if ((uint16_t)n > total) {
            n = (uint8_t)total;
        }
        memcpy(rx_buf, report + CTAPHID_INIT_HEADER_LEN, n);
        rx_len = n;
    }
    else
    {
        /* ---------------- 续帧 ---------------- */
        uint8_t seq = (uint8_t)(cmd & ~CTAPHID_CMD_INIT_FLAG);
        uint8_t n;

        if (!rx_active || cid != rx_cid) {
            /* 没有匹配的初始帧：忽略，不影响当前传输 */
            return;
        }
        if (seq != rx_seq) {
            /* 序号不连续：放弃本次传输 */
            rx_active = 0;
            ctaphid_send_error(cid, CTAPHID_ERR_INVALID_SEQ);
            return;
        }
        rx_seq++;

        n = (uint8_t)(len - CTAPHID_HEADER_LEN);
        if ((uint16_t)(rx_len + n) > rx_total) {
            n = (uint8_t)(rx_total - rx_len);
        }
        memcpy(rx_buf + rx_len, report + CTAPHID_HEADER_LEN, n);
        rx_len += n;
    }


    if (rx_active && rx_len >= rx_total) {
        rx_active = 0;
        req_cid   = rx_cid;
        req_cmd   = rx_cmd;
        req_len   = rx_total;
        req_ready = 1;
    }
}

/*********************************************************************
 * @fn      ctaphid_process
 *
 * @brief   主循环调用：处理已收齐的请求并准备好响应
 */
void ctaphid_process(void)
{
    uint32_t cid;
    uint8_t  cmd;

    /* 挂起等用户确认期间：每 500ms 主动上报一次 KEEPALIVE(UPNEEDED)。
     * 这一步必须放在 req_ready 判断之前 —— 等待期间没有新请求，
     * 否则这段逻辑永远不会被执行。 */
    if (s_ctap_pending)
    {
        uint32_t now = TMOS_GetSystemClock();

        if ((now - s_keepalive_last) >= 500)
        {
            s_keepalive_last = now;
            tx_buf[0] = CTAPHID_KEEPALIVE_STATUS_UPNEEDED;
            ctaphid_tx_start(s_pend_cid, CTAPHID_CMD_KEEPALIVE, 1);
        }
        return;
    }

    if (!req_ready) {
        return;
    }
    req_ready = 0;

    cid = req_cid;
    cmd = req_cmd;


    switch (cmd)
    {
        case CTAPHID_CMD_PING:
            if (req_len > sizeof(tx_buf)) {
                req_len = sizeof(tx_buf);
            }
            memcpy(tx_buf, rx_buf, req_len);
            ctaphid_tx_start(cid, CTAPHID_CMD_PING, req_len);
            break;

        case CTAPHID_CMD_INIT:
        {
            if (req_len < 8) {
                ctaphid_send_error(cid, CTAPHID_ERR_INVALID_LEN);
                break;
            }
            memcpy(tx_buf, rx_buf, 8);          /* nonce 原样回显 */
            memset(tx_buf + 8, 0, 4);           /* newCID = 0：不分配新通道 */
            tx_buf[12] = CTAPHID_PROTOCOL_VERSION;
            tx_buf[13] = 0x00;                  /* 设备版本 major */
            tx_buf[14] = 0x01;                  /* 设备版本 minor */
            tx_buf[15] = 0x00;                  /* 设备版本 build */
            tx_buf[16] = (uint8_t)(CTAPHID_CAP_WINK | CTAPHID_CAP_CBOR);
            ctaphid_tx_start(cid, CTAPHID_CMD_INIT, 17);
            break;
        }

        case CTAPHID_CMD_WINK:
            ctaphid_tx_start(cid, CTAPHID_CMD_WINK, 0);
            break;

        case CTAPHID_CMD_CANCEL:
            /* CTAPHID 规范：CANCEL 不产生响应 */
            break;

        case CTAPHID_CMD_CBOR:
        {
            uint8_t  status;
            uint16_t resp_len = 0;

            if (req_len < 1) {
                ctaphid_send_error(cid, CTAPHID_ERR_INVALID_LEN);
                break;
            }

#ifdef CTAPHID_DUMP
            /* 调试：打印收到的 CTAP 请求全文（每 32 字节一行）。
             * 用 -D CTAPHID_DUMP 打开；会阻塞串口，仅排障时使用。 */
            {
                uint16_t k;
                PRINT("[REQ] cmd=%02X len=%u cid=%08lX%c",
                      rx_buf[0], (unsigned)req_len, (unsigned long)cid, 10);
                for (k = 1; k < req_len; k++) {
                    if (((k - 1) % 32) == 0) { PRINT("  %04X:", (unsigned)(k - 1)); }
                    PRINT(" %02X", rx_buf[k]);
                    if (((k - 1) % 32) == 31 || k == (uint16_t)(req_len - 1)) { PRINT("%c", 10); }
                }
            }
#endif


            /* CTAP2 响应格式是 [status(1B)] + [CBOR]：
             * CBOR 必须写到 tx_buf + 1，把首字节留给状态码。 */
            status = ctap_handle_cbor(rx_buf[0],
                                      rx_buf + 1, (uint16_t)(req_len - 1),
                                      tx_buf + 1, (uint16_t)(sizeof(tx_buf) - 1),
                                      &resp_len);

            if (status == CTAP_STATUS_PENDING) {
                /* 等用户按键：先不发响应，记下通道，稍后回填 */
                s_pend_cid = cid;
                s_ctap_pending = 1;
                s_keepalive_last = TMOS_GetSystemClock();
                break;
            }
            if (status == CTAP_SUCCESS) {
#ifdef CTAPHID_DUMP
                uint16_t k;
#endif
                tx_buf[0] = CTAP_SUCCESS;      /* 状态码前缀 */
#ifdef CTAPHID_DUMP
                /* 调试：写状态码之后再打印，否则 tx_buf[0] 是上次残留值 */
                PRINT("[RSP] status=%02X len=%u%c", status, (unsigned)(resp_len + 1), 10);
                for (k = 0; k < (uint16_t)(resp_len + 1); k++) {
                    if ((k % 32) == 0) { PRINT("  %04X:", (unsigned)k); }
                    PRINT(" %02X", tx_buf[k]);
                    if ((k % 32) == 31 || k == (uint16_t)resp_len) { PRINT("%c", 10); }
                }
#endif
                ctaphid_tx_start(cid, CTAPHID_CMD_CBOR, (uint16_t)(resp_len + 1));
            } else {
                /* CTAP 错误：CTAPHID_CBOR 响应体就是 1 字节状态码 */
                tx_buf[0] = status;
                ctaphid_tx_start(cid, CTAPHID_CMD_CBOR, 1);
            }
            break;
        }

        case CTAPHID_CMD_MSG:
            /* CTAP1/U2F APDU 通道，尚未实现 */
            ctaphid_send_error(cid, CTAPHID_ERR_INVALID_CMD);
            break;

        default:
            ctaphid_send_error(cid, CTAPHID_ERR_INVALID_CMD);
            break;
    }
}

/*********************************************************************
 * @fn      ctaphid_reprocess
 *
 * @brief   用保留的请求报体重跑一次 CTAP 处理（供取得 UP 后重放）
 *
 * @note    之所以能安全重放：命令处理在产生任何副作用之前就被 UP 闸门挡住并返回
 *          CTAP_STATUS_PENDING，因此第一次调用没有做任何事（也没写 Flash）。
 *          重放时 ctap_up_gate() 会放行，命令正常执行到底。
 *
 * @return  0=已产生响应, -1=没有挂起请求或仍在等待
 */
int ctaphid_reprocess(void)
{
    uint8_t  status;
    uint16_t resp_len = 0;

    if (!s_ctap_pending) {
        return -1;
    }
    if (req_len < 1) {
        s_ctap_pending = 0;
        tx_buf[0] = CTAPHID_ERR_INVALID_LEN;
        ctaphid_tx_start(s_pend_cid, CTAPHID_CMD_ERROR, 1);
        return 0;
    }

    status = ctap_handle_cbor(rx_buf[0],
                              rx_buf + 1, (uint16_t)(req_len - 1),
                              tx_buf + 1, (uint16_t)(sizeof(tx_buf) - 1),
                              &resp_len);

    if (status == CTAP_STATUS_PENDING) {
        return -1;              /* 仍在等待（正常流程不会走到这里） */
    }

    s_ctap_pending = 0;

    if (status == CTAP_SUCCESS) {
        tx_buf[0] = CTAP_SUCCESS;          /* 状态码前缀 */
        ctaphid_tx_start(s_pend_cid, CTAPHID_CMD_CBOR, (uint16_t)(resp_len + 1));
    } else {
        tx_buf[0] = status;
        ctaphid_tx_start(s_pend_cid, CTAPHID_CMD_CBOR, 1);
    }
    return 0;
}

/*********************************************************************
 * @fn      ctaphid_next_report_out
 *
 * @brief   EP1 IN 中断中调用：取下一帧待发给主机的 64 字节报告
 */
int ctaphid_next_report_out(uint8_t *report)
{
    uint8_t n;
    uint8_t i;

    if (!tx_active || report == NULL) {
        return 0;
    }

    /* HID 报告定长：短帧必须补 0 到 64 字节 */
    for (i = 0; i < CTAPHID_HID_REPORT; i++) {
        report[i] = 0;
    }

    report[0] = (uint8_t)(tx_cid);
    report[1] = (uint8_t)(tx_cid >> 8);
    report[2] = (uint8_t)(tx_cid >> 16);
    report[3] = (uint8_t)(tx_cid >> 24);

    if (tx_offset == 0)
    {
        /* 初始帧 */
        report[4] = (uint8_t)(tx_cmd | CTAPHID_CMD_INIT_FLAG);
        report[5] = (uint8_t)(tx_len >> 8);
        report[6] = (uint8_t)(tx_len & 0xFF);

        n = (tx_len > (CTAPHID_HID_REPORT - CTAPHID_INIT_HEADER_LEN))
              ? (uint8_t)(CTAPHID_HID_REPORT - CTAPHID_INIT_HEADER_LEN)
              : (uint8_t)tx_len;
        memcpy(report + CTAPHID_INIT_HEADER_LEN, tx_buf, n);
        tx_offset = n;
        tx_seq    = 0;
    }
    else
    {
        /* 续帧 */
        report[4] = (uint8_t)(tx_seq++ & 0x7F);   /* SEQ 低 7 位，bit7 必须为 0 */

        n = ((uint16_t)(tx_len - tx_offset) >
             (uint16_t)(CTAPHID_HID_REPORT - CTAPHID_HEADER_LEN))
              ? (uint8_t)(CTAPHID_HID_REPORT - CTAPHID_HEADER_LEN)
              : (uint8_t)(tx_len - tx_offset);
        memcpy(report + CTAPHID_HEADER_LEN, tx_buf + tx_offset, n);
        tx_offset += n;
    }

    if (tx_offset >= tx_len) {
        tx_active = 0;
    }
    return 1;
}

/*********************************************************************
 * @fn      ctaphid_has_pending_out
 */
int ctaphid_has_pending_out(void)
{
    return tx_active;
}

/* 是否是新响应的第一帧（尚未装载到 HID 缓冲） */
int ctaphid_ready_to_load(void)
{
    return (tx_active && tx_offset == 0) ? 1 : 0;
}

int ctaphid_ctap_is_pending(void)
{
    return s_ctap_pending;
}

int ctaphid_ctap_reply(uint8_t ctap_status, const uint8_t *body, uint16_t body_len)
{
    if(!s_ctap_pending)
    {
        return -1;
    }
    s_ctap_pending = 0;

    if(ctap_status == CTAP_SUCCESS)
    {
        if(body == NULL || body_len == 0 || body_len > (uint16_t)(sizeof(tx_buf) - 1))
        {
            return -1;
        }
        tx_buf[0] = CTAP_SUCCESS;          /* 状态码前缀 */
        memcpy(tx_buf + 1, body, body_len);
        ctaphid_tx_start(s_pend_cid, CTAPHID_CMD_CBOR, (uint16_t)(body_len + 1));
    }
    else
    {
        tx_buf[0] = ctap_status;
        ctaphid_tx_start(s_pend_cid, CTAPHID_CMD_CBOR, 1);
    }
    return 0;
}

