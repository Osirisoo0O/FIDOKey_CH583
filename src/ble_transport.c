/**
 * @file ble_transport.c
 * @brief FIDO BLE 传输层实现（阶段 2：帧编解码 + 分片 + PING 回显）
 *
 * 规范依据：FIDO U2F BT Protocol v1.1 §5/§11、ITU-T X.1278.2 §13.4
 *
 * ── 帧格式 ──
 *   初始帧  [CMD(1B, bit7=1)] [HLEN(1B)] [LLEN(1B)] [DATA]
 *   续帧    [SEQ(1B, bit7=0)] [DATA]
 *
 *   HLEN:LLEN 是**整个帧的数据长度**（大端），不是本分片的长度。
 *   初始帧由首字节 bit7=1 标识 —— 这也是所有命令码都 >= 0x80 的原因。
 *
 * ── 发送调度 ──
 *   响应可能超过一帧的容量，而通知在 GATT 回调里连发并不合适，
 *   因此收到完整请求后只把响应放进 tx 缓冲，由主循环的
 *   ble_transport_pump() 逐帧送出。
 */

/*********************************************************************
 * INCLUDES
 */

#include "config.h"
#include "stdint.h"
#include "string.h"
#include "ble_transport.h"
#include "fido_service.h"
#include "peripheral.h"   /* Peripheral_PairingKeepAlive() */
#include "ctap.h"
#include "auth_sm.h"
#include "debug_log.h"

/*********************************************************************
 * LOCAL VARIABLES
 */

/* ---- 接收（客户端 -> 设备） ---- */
static uint8_t  rx_buf[FIDO_BLE_MAX_MSG];
static uint16_t rx_len;             /* 已收数据字节数 */
static uint16_t rx_total;           /* 本帧声明的总长度 */
static uint8_t  rx_seq;             /* 下一个期望的 SEQ */
static uint8_t  rx_active;          /* 是否处于一次接收中 */
static uint8_t  rx_cmd;             /* 命令码 */

/* ---- 发送（设备 -> 客户端） ---- */
/* tx 缓冲：初始帧的整帧内容（含 3 字节帧头）都放在这里。
 * 续帧发送时**原地**把 SEQ 插到第 0 字节之前是不行的（会覆盖未发内容），
 * 因此这里额外留 1 字节，发送续帧时把 SEQ 写在 buf 末尾的空位上，
 * 用"从末尾临时搬移"的方式组帧 —— 见 ble_transport_pump()。 */
static uint8_t  tx_buf[FIDO_BLE_MAX_MSG + 3 + 1];   /* 整帧 + 1(续帧插入 SEQ) */
static uint16_t tx_len;             /* 待发送的总字节数（含帧头） */
static uint16_t tx_offset;          /* 已发送到哪 */
static uint8_t  tx_seq;             /* 下一个续帧序号 */
static uint8_t  tx_active;          /* 是否有待发送内容 */
static uint8_t  tx_cmd;             /* 当前待发内容的命令码（用于判断能否被抢占） */

/* ---- 连接与 MTU ---- */
extern uint32_t TMOS_GetSystemClock(void);

static uint16_t s_conn;             /* 当前连接句柄 */
static uint16_t s_mtu = FIDO_BLE_DEFAULT_MTU;

/* ---- 挂起的 CTAP 操作（等待用户按键） ----
 * 与 ctaphid.c 的结构对称：命令在副作用之前过 UP 闸门，未取得则返回
 * CTAP_STATUS_PENDING；本层保留请求报文（就在 rx_buf 里）不发响应，
 * 取得 UP 后用同一份报文重跑。首次调用未写 Flash，故重放安全。 */
static uint16_t s_pend_conn;        /* 响应要发回哪个连接 */
static uint8_t  s_ctap_pending;
static uint32_t s_keepalive_last;   /* 上次 KEEPALIVE 时间（TMOS 时基） */

/*********************************************************************
 * LOCAL FUNCTIONS
 */

static void     ble_transport_event_cb(fido_evt_t *p_evt);
static void     handle_frame(void);
static void     send_frame(uint8_t cmd, const uint8_t *data, uint16_t len);
static void     send_frame_inplace(uint8_t cmd, uint16_t len);
static uint16_t max_payload_init(void);

/**
 * @brief 初始化传输层
 */
void ble_transport_init(void)
{
    ble_transport_clear();

    /* 把自己注册为 GATT 服务层的事件接收者。
     * 服务的注册（fido_add_service）由本函数完成，peripheral.c 不再单独调用，
     * 避免同一服务被注册两次。 */
    (void)fido_add_service(ble_transport_event_cb);
}

/**
 * @brief 清理所有状态（复位 / 断开时调用）
 */
void ble_transport_clear(void)
{
    rx_len     = 0;
    rx_total   = 0;
    rx_seq     = 0;
    rx_active  = 0;
    rx_cmd     = 0;

    tx_len     = 0;
    tx_offset  = 0;
    tx_seq     = 0;
    tx_cmd     = 0;
    tx_active  = 0;

    s_ctap_pending = 0;
    s_pend_conn    = 0;
}

/**
 * @brief 记录连接句柄
 */
void ble_transport_set_conn(uint16_t connHandle)
{
    s_conn = connHandle;
}

/**
 * @brief 更新 ATT MTU
 */
void ble_transport_set_mtu(uint16_t mtu)
{
    if(mtu >= FIDO_BLE_DEFAULT_MTU && mtu <= FIDO_BLE_MAX_MSG)
    {
        s_mtu = mtu;

        /* fidoControlPointLength 必须反映真实能力：客户端读它来决定
         * 单次写入多大。声明过大会让客户端写出 ATT 层传不了的长度。 */
        fido_set_control_point_length((uint16_t)(s_mtu - 3));
    }
}

/**
 * @brief 客户端完成 CCCD 订阅后触发参数更新
 *
 * 在 FIDO_EVT_STATUS_NOTI_ENABLED 回调中调用，此时客户端已完成
 * GATT 发现和 CCCD 订阅，参数更新不会干扰 GATT 操作。
 */
void ble_transport_on_cccd_enabled(void)
{
    /* 调用 peripheral.c 的参数更新入口 */
    extern void Peripheral_RequestParamUpdate(void);
    Peripheral_RequestParamUpdate();
}

/**
 * @brief 单次通知能承载的最大字节数 = ATT_MTU - 3（ATT 层的 3 字节头）
 */
static uint16_t s_notify_max(void)
{
    return (uint16_t)(s_mtu - 3);
}

/**
 * @brief 初始帧能装的载荷字节数 = 通知上限 - 3(帧头) = MTU - 6
 */
static uint16_t max_payload_init(void)
{
    return (uint16_t)(s_mtu - 6);
}

uint16_t ble_transport_max_frame(void)
{
    return max_payload_init();
}

/**
 * @brief 帧头已在 tx_buf[0..2]、载荷已在 tx_buf[3..] 时，直接排队发送
 *
 * 用于 CTAP 响应：ctap_handle_cbor() 的输出直接写进 tx_buf+3，
 * 省掉一次整体拷贝，也省下一块 512 字节的独立响应缓冲。
 *
 * @param cmd 命令码
 * @param len 载荷长度（不含 3 字节帧头）
 */
static void send_frame_inplace(uint8_t cmd, uint16_t len)
{
    if(tx_active)
    {
        /* 同上：响应可以抢占正在发送的 KEEPALIVE */
        if(tx_cmd == FIDO_BLE_CMD_KEEPALIVE)
        {
            tx_active = 0;
        }
        else
        {
            SK_LOG("ble: tx busy, drop inplace cmd=%02X", cmd);
            return;
        }
    }
    if((uint32_t)len + 3u > (uint32_t)sizeof(tx_buf))
    {
        return;
    }

    tx_buf[0] = cmd;
    tx_buf[1] = (uint8_t)(len >> 8);
    tx_buf[2] = (uint8_t)(len & 0xFF);

    tx_len    = (uint16_t)(len + 3u);
    tx_offset = 0;
    tx_seq    = 0;
    tx_cmd    = cmd;
    tx_active = 1;

}

/**
 * @brief 组装并发送一个完整的帧（自动分片）
 *
 * @param cmd   命令码（bit7 必须为 1）
 * @param data  载荷
 * @param len   载荷长度
 */
static void send_frame(uint8_t cmd, const uint8_t *data, uint16_t len)
{
    if(tx_active)
    {
        /* KEEPALIVE 是"插播"性质的，不能挤掉真正的响应：
         * 若当前正在发的是 KEEPALIVE 而新帧是响应（MSG/ERROR），
         * 直接抢占（KEEPALIVE 丢了无所谓，客户端只是少一次保活提示）。
         * 反之若当前在发响应，则丢弃新帧。 */
        if(cmd != FIDO_BLE_CMD_KEEPALIVE && tx_cmd == FIDO_BLE_CMD_KEEPALIVE)
        {
            SK_LOG("ble: preempt keepalive with cmd=%02X", cmd);
            tx_active = 0;
        }
        else
        {
            SK_LOG("ble: tx busy, drop new frame cmd=%02X", cmd);
            return;
        }
    }
    if((uint32_t)len + 3u > (uint32_t)(FIDO_BLE_MAX_MSG + 3))
    {
        return;
    }

    /* 把**整个帧**（3 字节帧头 + 全部载荷）放进 tx_buf，
     * 分片发送由 ble_transport_pump() 负责。
     *
     * 曾经的写法是只把"初始帧能装下的那部分"放进去，导致长响应
     * 丢掉了后续载荷 —— 短请求能过、长请求无响应。 */
    tx_buf[0] = cmd;
    tx_buf[1] = (uint8_t)(len >> 8);
    tx_buf[2] = (uint8_t)(len & 0xFF);
    if(len > 0)
    {
        memcpy(tx_buf + 3, data, len);
    }

    tx_len    = (uint16_t)(len + 3u);
    tx_offset = 0;
    tx_seq    = 0;
    tx_cmd    = cmd;
    tx_active = 1;

}

/**
 * @brief fido_service 的事件回调：把 GATT 事件转成传输层的输入
 */
static void ble_transport_event_cb(fido_evt_t *p_evt)
{
    if(p_evt == NULL)
    {
        return;
    }

    switch(p_evt->type)
    {
        case FIDO_EVT_CONTROL_POINT_WRITE:
            /* 客户端在发请求 == 它在正常使用设备：续上配对窗口，
             * 避免长交互（注册/认证）中途窗口过期导致客户端放弃。 */
            Peripheral_PairingKeepAlive();
            ble_transport_on_write(p_evt->connHandle, p_evt->data, p_evt->len);
            break;

        case FIDO_EVT_STATUS_NOTI_ENABLED:
            /* 记下订阅的连接，通知要发到同一个连接上 */
            s_conn = p_evt->connHandle;
            /* 客户端已完成 GATT 发现和 CCCD 订阅，此时触发参数更新是安全的 */
            ble_transport_on_cccd_enabled();
            break;

        case FIDO_EVT_STATUS_NOTI_DISABLED:
            break;

        default:
            break;
    }
}

/**
 * @brief 处理一个已完整接收的帧
 *
 * 阶段 2 只实现 PING（回显），其余命令回 ERROR。
 */
static void handle_frame(void)
{
    const uint8_t *data = rx_buf;
    uint16_t       len  = rx_total;

    switch(rx_cmd)
    {
        case FIDO_BLE_CMD_PING:
            /* 按规范原样回显：STAT 与请求的 CMD 相同 */
            PRINT("[BLE] PING rx len=%u -> echo", (unsigned)len);
            PRINT("%c", 10);
            send_frame(FIDO_BLE_CMD_PING, data, len);
            break;

        case FIDO_BLE_CMD_MSG:
        {
            PRINT("[BLE] MSG rx len=%u ctap_cmd=%02X",
                  (unsigned)rx_total, (rx_total > 0) ? rx_buf[0] : 0);
            PRINT("%c", 10);
            /* MSG 的载荷就是 CTAP2 消息： [CTAP cmd(1B)] [CBOR 参数...]
             * 响应同样是 CTAP2 消息： [status(1B)] [CBOR 响应...]
             *
             * 注意与 CTAPHID 的差别：CTAPHID 需要在帧外另加一层，
             * 而 BLE 的 MSG 载荷**本身就是** CTAP2 消息，无需额外前缀 ——
             * 状态码是 CTAP2 消息自身的一部分，不是封装层的东西。
             *
             * 这里直接用 tx_buf 的空闲区做响应缓冲（严格请求-响应，
             * 收到请求时 tx_buf 必然空闲），以省下一块 512 字节的 RAM。
             */
            uint8_t *resp     = tx_buf + 3;     /* 跳过 3 字节帧头，稍后批量装帧 */
            uint16_t resp_len = 0;
            uint8_t  status;

            PRINT("[BLE RX] len=%u first=%02X cmd=%02X",
                  (unsigned)rx_total, rx_buf[0], (uint8_t)(rx_buf[0] & 0xFF));
            PRINT("%c", 10);

            if(len < 1)
            {
                /* 封装层错误：载荷连 CTAP 命令字节都没有。
                 * §11.4.4.2：ERROR 帧的 DATA 是**错误码**（这里取 ERR_INVALID_LEN
                 * 更贴切：请求载荷长度不合法），不是 STAT 的值 —— 早期误把
                 * FIDO_BLE_CMD_ERROR(0xBF) 填进 DATA，客户端会读到一个未定义的错误码。 */
                uint8_t err[1];
                err[0] = FIDO_BLE_EC_INVALID_LEN;
                send_frame(FIDO_BLE_CMD_ERROR, err, 1);
                break;
            }

            status = ctap_handle_cbor(data[0],
                                      data + 1, (uint16_t)(len - 1),
                                      resp + 1, (uint16_t)(sizeof(tx_buf) - 3 - 1),
                                      &resp_len);

            if(status == CTAP_STATUS_PENDING)
            {
                /* 等用户按键：保留请求报文（仍在 rx_buf 里），不发响应。
                 * 取得 UP 后由 ble_transport_pending_poll() 重放。 */
                PRINT("[BLE] ctap pending (UP needed)");
                PRINT("%c", 10);
                s_pend_conn      = s_conn;
                s_ctap_pending   = 1;
                s_keepalive_last = TMOS_GetSystemClock();
                SK_LOG("ble: ctap pending (UP)");
                break;
            }

            if(status == CTAP_SUCCESS)
            {
                resp[0] = CTAP_SUCCESS;
                /* 直接把 [status][CBOR] 作为 MSG 载荷装帧 */
                send_frame_inplace(FIDO_BLE_CMD_MSG, (uint16_t)(resp_len + 1));
                PRINT("[BLE] MSG resp OK len=%u%c", (unsigned)(resp_len + 1), 10);
            }
            else
            {
                resp[0] = status;
                send_frame_inplace(FIDO_BLE_CMD_MSG, 1);
                /* 失败时把状态码打出来 —— 它是定位 CTAP 层问题的关键 */
                PRINT("[BLE] MSG resp FAIL status=0x%02X%c", status, 10);
            }
            break;
        }

        case FIDO_BLE_CMD_CANCEL:
            /* §11.4.8：收到 CANCEL 时，若有可取消的挂起请求，
             *   - 必须取消它，且**被取消的那个请求**必须回
             *     CTAP2_ERR_KEEPALIVE_CANCEL（CTAP 2.3 §6.3 = 0x2D）
             *   - 而 CANCEL 本身**绝不能**有任何响应
             * 客户端依赖 0x2D 区分"用户取消"与"设备失联"，不能只静默丢弃。 */
            SK_LOG("ble: cancel");
            if(s_ctap_pending)
            {
                uint8_t body[1];
                s_ctap_pending = 0;
                body[0] = CTAP_ERR_KEEPALIVE_CANCEL;
                send_frame(FIDO_BLE_CMD_MSG, body, 1);   /* 回的是被取消的请求 */
                ctap_abort_pending();
            }
            break;                                        /* CANCEL 自身不回复 */

        default:
        {
            /* 不支持的命令用 ERROR 帧回应。
             * §11.4.4.2：DATA 是**错误码**，不是 STAT 的值。 */
            uint8_t err[1];
            err[0] = FIDO_BLE_EC_INVALID_CMD;
            send_frame(FIDO_BLE_CMD_ERROR, err, 1);
            SK_LOG("ble: unsupported cmd %02X", rx_cmd);
            break;
        }
    }
}

/**
 * @brief 收到 fidoControlPoint 写入：解析分片
 */
void ble_transport_on_write(uint16_t connHandle, const uint8_t *data, uint16_t len)
{
    uint8_t first;

    if(data == NULL || len == 0)
    {
        return;
    }
    /* 挂起期间要保留 rx_buf 以便重放，其它帧一律丢弃；
     * 只放行 CANCEL（用户点了取消就该立刻停止等待）。 */
    if(s_ctap_pending)
    {
        if((data[0] & 0x80) && data[0] == FIDO_BLE_CMD_CANCEL)
        {
            /* §11.4.8：被取消的请求必须回 CTAP2_ERR_KEEPALIVE_CANCEL(0x2D)，
             * CANCEL 本身不回复。这里与 handle_frame() 的 CANCEL 分支同理 ——
             * 挂起期间 CANCEL 走的是这条快路径（不等整帧收完）。 */
            uint8_t body[1];
            s_ctap_pending = 0;
            body[0] = CTAP_ERR_KEEPALIVE_CANCEL;
            send_frame(FIDO_BLE_CMD_MSG, body, 1);
            ctap_abort_pending();
            SK_LOG("ble: cancelled while pending -> 0x2D");
        }
        return;
    }

    s_conn = connHandle;
    first  = data[0];

#ifdef BLE_TRANSPORT_DUMP
    {
        uint16_t k;
        for (k = 0; k < len && k < 24; k++) { PRINT(" %02X", data[k]); }
        PRINT("%c", 10);
    }
#endif

    if(first & 0x80)
    {
        /* ---------------- 初始帧 ---------------- */
        uint8_t  cmd;
        uint16_t total;
        uint16_t n;

        if(len < 3)
        {
            return;                         /* 帧头都不完整 */
        }
        cmd   = first;
        total = ((uint16_t)data[1] << 8) | data[2];

        if(total > FIDO_BLE_MAX_MSG)
        {
            return;                         /* 超出本实现能力 */
        }

        rx_cmd    = cmd;
        rx_total  = total;
        rx_len    = 0;
        rx_seq    = 0;
        rx_active = 1;

        n = (uint16_t)(len - 3);
        if(n > total)
        {
            n = total;
        }
        if(n > 0)
        {
            memcpy(rx_buf, data + 3, n);
            rx_len = n;
        }
    }
    else
    {
        /* ---------------- 续帧 ---------------- */
        uint8_t seq = first;
        uint16_t n;

        if(!rx_active || seq != rx_seq)
        {
            /* 没有对应的初始帧，或序号不连续：放弃本次接收 */
            rx_active = 0;
            return;
        }
        /* §11.4.10：期望的 SEQ 也按 0x00..0x7f 回绕（与发送侧对称） */
        rx_seq = (uint8_t)((rx_seq + 1) & 0x7F);

        n = (uint16_t)(len - 1);
        if((uint16_t)(rx_len + n) > rx_total)
        {
            n = (uint16_t)(rx_total - rx_len);
        }
        if(n > 0)
        {
            memcpy(rx_buf + rx_len, data + 1, n);
            rx_len += n;
        }
    }

    if(rx_active && rx_len >= rx_total)
    {
        rx_active = 0;
        handle_frame();
    }
}

/**
 * @brief 发送调度（由主循环调用）
 *
 * 每次调用尽量把待发内容推出去；一帧一个通知，避免在 GATT 回调里连发。
 *
 * ★ 通知发送失败时**丢弃整个帧**，不保留重试。
 *   失败最常见的原因是客户端尚未订阅 fidoStatus（cccd=0x0000）——
 *   而按 §11.4.14，客户端必须先启用通知并等待 ATT 确认才能发 FIDO 消息。
 *   这是客户端违规，设备没有义务为它空转：旧实现的"保留待发"会让主循环
 *   每轮重试一次，既费电又把日志刷爆（实测未订阅时同一行连打数十次）。
 */
void ble_transport_pump(void)
{
    uint16_t n;

    if(!tx_active)
    {
        return;
    }

    /* 一次通知能承载的最大字节数 = ATT_MTU - 3（ATT 层的 3 字节头）。
     * 之前误按 MTU 发，导致 23 字节的通知被拒、反复失败 —— 短帧能过、
     * 长帧静默失败。（见 docs 记录：实测 n=23 时 GATT_Notification 失败） */
    if(tx_offset == 0)
    {
        /* 初始帧：整帧已在 tx_buf（含 3 字节帧头） */
        n = (tx_len > s_notify_max()) ? s_notify_max() : tx_len;
        if(fido_status_notify(s_conn, tx_buf, n) != SUCCESS)
        {
            /* 通知发送失败 —— 最常见的原因是客户端尚未订阅 fidoStatus
             * （cccd=0x0000）。按 §11.4.14，客户端必须先启用通知并等 ATT 确认
             * 才能发 FIDO 消息，所以这是**客户端违规**，设备没有义务为它空转：
             * 直接**丢弃**该帧，不再重试。
             *
             * （旧实现是"保留待发"，结果主循环每轮都重试一次 —— 忙等 + 日志
             *   刷屏；实测未订阅时同一条 "notify SKIP" 会连打数十次。） */
            SK_LOG("ble: notify failed -> drop frame cmd=%02X", tx_cmd);
            tx_active = 0;
            tx_offset = 0;
            tx_seq    = 0;
            return;
        }
        tx_offset = n;
    }
    else
    {
        /* 续帧：[SEQ(1B)] + 载荷。
         * 为避免再开一块 1KB 的发送缓冲（RAM 已很紧张），这里把 SEQ
         * 写进 tx_buf 末尾预留的那 1 字节，并用 s_tx_cont 做一次
         * "头部拼装" —— 即先把 SEQ 放在预留位，再把载荷紧随其后。
         * 由于载荷在缓冲里是连续的，只要预留位紧邻当前偏移即可。 */
        uint16_t avail = (uint16_t)(tx_len - tx_offset);

        n = (uint16_t)(s_notify_max() - 1);      /* 通知上限扣掉 SEQ 那一字节 */
        if(n > avail)
        {
            n = avail;
        }

        /* 把 SEQ 放到 tx_buf 的末尾预留字节，然后把 [SEQ] + n 字节载荷
         * 通过一次通知送出。为此把载荷整体后移到预留位之后 —— 载荷不大
         * （<= MTU），这次搬运的代价可以接受。 */
        memmove(tx_buf + tx_offset + 1, tx_buf + tx_offset, n);
        /* §11.4.10：序号 0x00..0x7f，**到 0x7f 后必须回绕到 0**。
         * 直接 tx_seq++ 会走到 0x80（bit7 被置起，客户端会把它当成新的初始帧）。
         * 本实现的响应长度远达不到 128 个续帧，但仍按规范掩码。 */
        tx_buf[tx_offset] = tx_seq;
        tx_seq = (uint8_t)((tx_seq + 1) & 0x7F);
        if(fido_status_notify(s_conn, tx_buf + tx_offset, (uint16_t)(n + 1)) != SUCCESS)
        {
            /* 同上：整个帧作废，不再回滚重试。
             * tx_buf 里的内容会被下一个请求覆盖，所以上面为插 SEQ 做的
             * memmove 后移位不必还原。 */
            SK_LOG("ble: notify failed (cont) -> drop frame cmd=%02X", tx_cmd);
            tx_active = 0;
            tx_offset = 0;
            tx_seq    = 0;
            return;
        }
        tx_offset += n;
    }

    if(tx_offset >= tx_len)
    {
        tx_active = 0;
        tx_offset = 0;
        tx_seq    = 0;
    }
}

/**
 * @brief 推进被挂起的 CTAP 操作（由主循环调用）
 *
 * 命令因未取得 UP 而挂起后：
 *   - 用户按键（AUTH_WAIT_GRANTED）：用保留的报文重跑该命令
 *   - 超时（AUTH_WAIT_TIMEOUT）    ：按规范回填 CTAP_ERR_ACTION_TIMEOUT
 * 等待期间每 500ms 上报 KEEPALIVE(UP_NEEDED)，避免客户端自行超时放弃。
 *
 * 结构与会 ctaphid_pending_poll() 对称；两者各持自己的挂起状态，互不干扰。
 */
void ble_transport_pending_poll(void)
{
    uint32_t now;

    if(!s_ctap_pending)
    {
        return;
    }

    /* 等待期间定期上报 KEEPALIVE */
    now = TMOS_GetSystemClock();
    if((uint32_t)(now - s_keepalive_last) >= 500u)
    {
        uint8_t ka = FIDO_BLE_KA_UP_NEEDED;
        s_keepalive_last = now;
        send_frame(FIDO_BLE_CMD_KEEPALIVE, &ka, 1);
    }

    switch(auth_sm_get())
    {
        case AUTH_WAIT_GRANTED:
        {
            /* 用户已确认：重跑挂起的命令（重跑时 ctap_up_gate() 会放行）。
             * clear 必须在重跑之后 —— 先清会导致重跑时再次要求按键。 */
            uint8_t  status;
            uint16_t resp_len = 0;
            uint8_t *resp     = tx_buf + 3;

            SK_LOG("ble: UP granted, reprocess");

            /* 先告诉客户端"开始处理了"。MakeCredential 里的 P-256 运算
             * 可能耗时数百毫秒，规范用 KEEPALIVE(PROCESSING) 表达这个状态，
             * 同时也有助于维持连接活跃。 */
            {
                uint8_t ka = FIDO_BLE_KA_PROCESSING;
                send_frame(FIDO_BLE_CMD_KEEPALIVE, &ka, 1);
            }

            status = ctap_handle_cbor(rx_buf[0],
                                      rx_buf + 1, (uint16_t)(rx_total - 1),
                                      resp + 1, (uint16_t)(sizeof(tx_buf) - 4),
                                      &resp_len);
            s_ctap_pending = 0;
            auth_sm_clear();

            if(status == CTAP_STATUS_PENDING)
            {
                break;                      /* 正常流程不会走到这里 */
            }
            if(status == CTAP_SUCCESS)
            {
                resp[0] = CTAP_SUCCESS;
                send_frame_inplace(FIDO_BLE_CMD_MSG, (uint16_t)(resp_len + 1));
            }
            else
            {
                resp[0] = status;
                send_frame_inplace(FIDO_BLE_CMD_MSG, 1);
            }
            break;
        }

        case AUTH_WAIT_TIMEOUT:
        {
            uint8_t body[1];

            SK_LOG("ble: UP timeout -> 0x3A");
            s_ctap_pending = 0;
            auth_sm_clear();
            body[0] = CTAP_ERR_ACTION_TIMEOUT;
            send_frame(FIDO_BLE_CMD_MSG, body, 1);
            break;
        }

        default:
            break;                          /* 仍在等待用户 */
    }
}

/*********************************************************************
*********************************************************************/
