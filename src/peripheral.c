/********************************** (C) COPYRIGHT *******************************
 * File Name          : peripheral.C
 * Author             : WCH
 * Version            : V1.0
 * Date               : 2018/12/10
 * Description        : ����ӻ�������Ӧ�ó��򣬳�ʼ���㲥���Ӳ�����Ȼ��㲥������������
 *                      ����������Ӳ�����ͨ���Զ������������
 * Copyright (c) 2021 Nanjing Qinheng Microelectronics Co., Ltd.
 * SPDX-License-Identifier: Apache-2.0
 *******************************************************************************/

/*********************************************************************
 * INCLUDES
 */
#include "config.h"
#include "devinfoservice.h"
#include "gattprofile.h"
#include "peripheral.h"
#include "KEY.h"      /* HAL_PUSH_BUTTON2() = KEY2 = PB4 */
#include "auth_sm.h"  /* auth_sm_get()：判断当前是否在等 UP */
#include "LED.h"      /* 配对模式的 LED 提示 */
#include "fido_service.h"
#include "dbg_service.h"   /* 调试服务：写 0x01 清除 BLE 绑定 */
#include "ble_transport.h"
#include "app_usb.h"

/*********************************************************************
 * MACROS
 */

/*********************************************************************
 * CONSTANTS
 */

// How often to perform periodic event
#define SBP_PERIODIC_EVT_PERIOD              1600

// How often to perform read rssi event
#define SBP_READ_RSSI_EVT_PERIOD             3200

// Parameter update delay
#define SBP_PARAM_UPDATE_DELAY               6400

// PHY update delay
#define SBP_PHY_UPDATE_DELAY                 2400

// What is the advertising interval when device is discoverable (units of 625us, 80=50ms)
#define DEFAULT_ADVERTISING_INTERVAL         80

// Limited discoverable mode advertises for 30.72s, and then stops
// General discoverable mode advertises indefinitely
#define DEFAULT_DISCOVERABLE_MODE            GAP_ADTYPE_FLAGS_GENERAL

/* ---------------------------------------------------------------------------
 * FIDO 配对模式（CTAP 2.1 规范 §11.4.7 / §11.4.13.2）
 *
 * 规范要求：
 *   "The method to put the authenticator into Pairing Mode should be such that
 *    it is not easy for the user to do accidentally especially if the pairing
 *    method is Just Works. ... A visible or audible cue that the authenticator
 *    is in Pairing Mode should be considered."
 *   "When advertising in pairing mode, the authenticator SHALL either:
 *    (1) set the LE Limited Mode bit to zero and the LE General Discoverable
 *        bit to one OR (2) set the LE Limited Mode bit to one and the LE
 *        General Discoverable bit to zero.
 *    When advertising in non-pairing mode, the authenticator SHALL set both
 *    the LE Limited Mode bit and the LE General Discoverable Mode bit to zero."
 *
 * 实现：长按 KEY2(PB4) 满 PAIRING_HOLD_MS 才进入（"不易误触发"），
 *       进入后 LED 快闪（可见提示），30 秒内无配对则自动退出。
 *       同时在广播的 Service Data 里置 bit7（客户端主要靠它判断）。
 * ------------------------------------------------------------------------- */
#if defined(DEBUG) && DEBUG
/* 调试构建（-D DEBUG=1，platformio.ini 的默认环境即是）：200ms 即进入配对模式。
 * 排查阶段要反复"进配对模式 -> 在客户端操作 -> 重来"，每次都按满 5 秒会明显
 * 拖慢节奏。200ms 仍不容许"无意间碰到"，但按下去就能进。
 * 正式构建走下面的 5000。 */
#define PAIRING_HOLD_MS         200
#else
#define PAIRING_HOLD_MS         5000    /* 长按满 5 秒进入配对模式（防误触发）*/
#endif
#define PAIRING_SAMPLE_MS       50      /* 按键采样间隔（节流） */

#define PAIRING_WINDOW_MS       30000   /* 配对模式持续 30 秒 */
/* 说明：曾改为 120 秒，实测过长，改回 30 秒。
 *
 * 但窗口不能太短 —— 从长按到客户端完成"扫描->连接->配对->特征发现"可能
 * 接近这个上限，窗口若在交互中途过期，客户端会认为"设备退出了配对模式"
 * 而停止（日志里 pairing window expired 之后再无动作，曾多次重现）。
 *
 * 为此只要设备在活动（连接着、有 FIDO 读写）就由
 * Peripheral_PairingKeepAlive() 自动续期，不依赖窗口本身够长。 */

// Minimum connection interval (units of 1.25ms, 6=7.5ms)
#define DEFAULT_DESIRED_MIN_CONN_INTERVAL    6

// Maximum connection interval (units of 1.25ms, 100=125ms)
/* 连接间隔上限：原为 200（=250ms），对 FIDO 交互太慢 ——
 * 日志里实测协商到 Int c0（192 = 240ms），客户端每次读写特征都要等一个
 * 连接事件，一次完整的发现+订阅+请求会累积成数秒，容易触发客户端超时
 * （表现为读完 CPLength 就放弃）。改为 24（=30ms），与大多数 FIDO 认证器
 * 和 BLE 外设的常用值一致；下限 6（=7.5ms）不变，由客户端决定最终值。 */
#define DEFAULT_DESIRED_MAX_CONN_INTERVAL    24

// Slave latency to use parameter update
#define DEFAULT_DESIRED_SLAVE_LATENCY        0

// Supervision timeout value (units of 10ms, 100=1s)
/* 连接监督超时（单位 10ms）。
 *
 * 原值 100 = 1 秒，对 FIDO 场景太短：MakeCredential 要做 P-256 密钥生成 +
 * 签名 + Flash 写入，micro-ecc 在 60MHz 上可能耗时超过 1 秒，期间设备无法
 * 响应链路层心跳，连接会被判定超时断开（实测表现为 notify 返回
 * bleNotConnected、CCCD 被清零）。
 *
 * 规范上限是 32 秒（3200）。这里取 6 秒，给耗时操作留足余量。 */
/* 连接监督超时：600（6 秒）-> 3000（30 秒）。
 * 6 秒对交互式调试太短 —— 扫描、配对、服务发现再加上人工看输出，
 * 很容易超过，连接会被判超时而断开（实测 Windows 上表现为
 * OSError 0x800704CD"远程设备已断开"，紧跟在服务发现之后）。
 * BLE 规范允许的最大值是 3200（32 秒），这里取 3000 留一点余量。
 * 注意：这是"建议值"，最终由客户端决定。 */
#define DEFAULT_DESIRED_CONN_TIMEOUT         3000

// Company Identifier: WCH
#define WCH_COMPANY_ID                       0x07D7

/*********************************************************************
 * TYPEDEFS
 */

/*********************************************************************
 * GLOBAL VARIABLES
 */

/*********************************************************************
 * EXTERNAL VARIABLES
 */

/*********************************************************************
 * EXTERNAL FUNCTIONS
 */

/*********************************************************************
 * LOCAL VARIABLES
 */
static uint8_t Peripheral_TaskID = INVALID_TASK_ID; // Task ID for internal task/event processing

// GAP - 扫描响应数据（最大 31 字节）
//
// 这里只放"设备名 + 连接间隔期望 + 发射功率"。
// 设备名从 WCH 默认的 "Simple Peripheral" 缩短为 "SecureKey"。
//
// 注：FIDO 的 Service Data **不在这里**，它在 advertData 里
//     （那样客户端在主动扫描时就能一并拿到，见 advertData 的说明）。
static uint8_t scanRspData[] = {
    // 完整设备名（9 字符）—— 客户端扫描结果里显示的就是它
    0x0A, // length: 1(type) + 9(name)
    GAP_ADTYPE_LOCAL_NAME_COMPLETE,
    'S', 'e', 'c', 'u', 'r', 'e', 'K', 'e', 'y',

    // 期望的连接间隔范围
    0x05, // length of this data
    GAP_ADTYPE_SLAVE_CONN_INTERVAL_RANGE,
    LO_UINT16(DEFAULT_DESIRED_MIN_CONN_INTERVAL),
    HI_UINT16(DEFAULT_DESIRED_MIN_CONN_INTERVAL),
    LO_UINT16(DEFAULT_DESIRED_MAX_CONN_INTERVAL),
    HI_UINT16(DEFAULT_DESIRED_MAX_CONN_INTERVAL),

    // 发射功率
    0x02, // length of this data
    GAP_ADTYPE_POWER_LEVEL,
    0 // 0dBm
};
/* scanRspData 合计 11 + 6 + 3 = 20 字节，未超过 B_MAX_ADV_LEN(31)。 */

// GAP - 主广播数据（最大 31 字节；为省电应尽量短）
static uint8_t advertData[] = {
    // AD Flags —— 其值由 Peripheral_SetPairingMode() 动态改写（见下）。
    // 注意与 WCH 默认注释的差别：本设备**不**使用 limited discoverable
    // （那只广播 30 秒）。配对模式的切换靠 Service Data 的 bit7 表达 ——
    // 平台通常不向应用暴露 AD Flags 的 Discoverable 位。
    0x02, // length of this data
    GAP_ADTYPE_FLAGS,
    DEFAULT_DISCOVERABLE_MODE | GAP_ADTYPE_FLAGS_BREDR_NOT_SUPPORTED,

    // ---- FIDO 服务 UUID（128-bit）----
    // 客户端靠广播里的服务 UUID 筛选目标设备，所以必须放在**主广播**里
    // （若只放扫描响应，部分客户端不主动扫响应就看不到它）。
    // 0000fffd-0000-1000-8000-00805f9b34fb，16 字节**整体反序**存放
    // （WCH 栈不用 BLE 规范的分段反序，见 fido_service.c 的说明）。
    0x11,                      // length: 1(type) + 16(uuid)
    GAP_ADTYPE_128BIT_COMPLETE,
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0xfd, 0xff, 0x00, 0x00,
    //0xff, 0xfd, 0x00, 0x00,0x00, 0x00, 0x00, 0x10,0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
    // ---- FIDO Service Data（配对模式标志）----
    // CTAP 2.1 规范 §11.4.7 "Authenticator Advertising Format"：
    //   "Some client platforms (most notably iOS) do not expose the AD Flag
    //    LE Limited and General Discoverable Mode bits to applications. For
    //    this reason, authenticators are also strongly RECOMMENDED to include
    //    the Service Data field in the Scan Response.
    //    The first 2 bytes contain the FIDO Service UUID, the following bytes
    //    are flag bytes."
    //
    //   bit7 = Device is in pairing mode     ← 本设备用这一位
    //   bit6 = Device requires Passkey Entry
    //
    // 为什么必须有：客户端的"请按住按键 5 秒"提示就是这个判断的产物 ——
    // 读不到"设备处于配对模式"的信号它就不肯继续（表现为配对成功后停在
    // 原地，一步 GATT 操作都不做）。
    // 该标志字节的位置由 ADVERT_SD_FLAGS_OFFSET 指定，并在
    // Peripheral_SetPairingMode() 里随配对模式开关改写。
    0x04,                                  // length: 1(type) + 2(uuid) + 1(flags)
    GAP_ADTYPE_SERVICE_DATA,               // 0x16
    LO_UINT16(FIDO_SERVICE_UUID16),
    HI_UINT16(FIDO_SERVICE_UUID16),
    FIDO_SERVICE_DATA_FLAGS,
};
/* advertData 合计 3 + 18 + 5 = 26 字节，未超过 B_MAX_ADV_LEN(31)。
 *
 * 说明：原先这里还有 WCH 示例服务的 16-bit UUID（SimpleProfile），作为
 * "蓝牙连接本身是否正常"的参照物保留；FIDO 服务已跑通且广播空间紧张，
 * 故已移除。 */

/* ---- FIDO 配对模式状态 ---- */
static uint8_t  s_pairing_mode  = 0;    /* 0=非配对模式, 1=配对模式 */
static uint32_t s_pairing_deadline = 0;
static uint32_t s_key_sample    = 0;    /* 长按检测的上次采样时刻 */
static uint32_t s_key_hold_start = 0;   /* 按住起点；0 = 未按住 */

/* advertData 里两个"会被 Peripheral_SetPairingMode() 动态改写"的字节偏移。
 * 改动 advertData 的内容或顺序时，必须同步核对这两个值：
 *
 *   advertData[0..2]   0x02, GAP_ADTYPE_FLAGS, <flags>
 *                      -> AD Flags 在 [2]
 *   advertData[3..20]  0x11, GAP_ADTYPE_128BIT_COMPLETE, <16 字节 FIDO UUID>
 *   advertData[21..25] 0x04, GAP_ADTYPE_SERVICE_DATA,
 *                      LO(FIDO_SERVICE_UUID16), HI(FIDO_SERVICE_UUID16), <flags>
 *                      -> Service Data 的配对模式标志在 [25]
 */
#define ADVERT_FLAGS_OFFSET     2
#define ADVERT_SD_FLAGS_OFFSET  25

/* 关于 Service Data 的 bit7（CTAP 2.1 §11.4.13.2）：
 *   "bit7 = Device is in pairing mode"
 *
 * 语义严格按规范 —— **只**反映配对模式，与是否有连接无关：
 *     配对模式 ON  -> 0x80
 *     配对模式 OFF -> 0x00
 * 由 Peripheral_SetPairingMode() 直接改写（见该函数）。
 *
 * 曾一度让它 = "配对模式 或 已连接"（当时怀疑客户端连上后重新扫描时
 * 读到 0x00 会以为设备不可用）。但那偏离了规范的语义，已回到严格实现。 */

// GAP GATT Attributes —— 设备名（GAP 服务的 0x2A00 特征）
//
// 必须与广播里 scanRspData 的名字**一致**，否则会出现这种问题：
// Windows 的 WebAuthn 从 GAP 服务读名字、把它存进配对记录
// （事件日志里显示 PairedName: Simple Peripheral），而广播里报的是
// SecureKey —— 两侧名称不同会让客户端把该配对记录与广播设备视为
// 不同对象，进而在服务查找时报 NTE_NOT_FOUND (0x80090011)。
static uint8_t attDeviceName[GAP_DEVICE_NAME_LEN] = "SecureKey";

// Connection item list
static peripheralConnItem_t peripheralConnList;

/* 注意类型必须是 uint16_t：ATT_MTU 可达 517（BLE 5.0），
 * uint8_t 会在 MTU > 255 时溢出（256 变 0），导致 ble_transport_set_mtu()
 * 因"mtu < FIDO_BLE_DEFAULT_MTU"而直接返回，fidoControlPointLength 停在
 * 初始的 20（23-3）。这就是实测中 MTU 协商为 256 却读出 0x14 的原因。 */
static uint16_t peripheralMTU = ATT_MTU_SIZE;
/*********************************************************************
 * LOCAL FUNCTIONS
 */
static void Peripheral_ProcessTMOSMsg(tmos_event_hdr_t *pMsg);
static void peripheralStateNotificationCB(gapRole_States_t newState, gapRoleEvent_t *pEvent);
static void performPeriodicTask(void);
static void peripheralParamUpdateCB(uint16_t connHandle, uint16_t connInterval,
                                    uint16_t connSlaveLatency, uint16_t connTimeout);
static void peripheralInitConnItem(peripheralConnItem_t *peripheralConnList);
static void peripheralRssiCB(uint16_t connHandle, int8_t rssi);

/*********************************************************************
 * PROFILE CALLBACKS
 */

// GAP Role Callbacks
static gapRolesCBs_t Peripheral_PeripheralCBs = {
    peripheralStateNotificationCB, // Profile State Change Callbacks
    peripheralRssiCB,              // When a valid RSSI is read from controller (not used by application)
    peripheralParamUpdateCB
};

// Broadcast Callbacks
static gapRolesBroadcasterCBs_t Broadcaster_BroadcasterCBs = {
    NULL, // Not used in peripheral role
    NULL  // Receive scan request callback
};

/** 配对状态回调：把配对过程打出来，便于定位"配对卡在哪一步" */
/* ---------------------------------------------------------------------------
 * FIDO 配对模式状态机
 * ------------------------------------------------------------------------- */

/* 打开/关闭配对模式：同步更新广播的 Service Data 标志与 AD Flags。 */
static void Peripheral_SetPairingMode(uint8_t on)
{
    uint8_t flags;

    if(s_pairing_mode == on)
    {
        return;
    }
    s_pairing_mode = on;

    /* 1) Service Data 的 bit7（CTAP 2.1 §11.4.13.2：bit7 = "Device is in
     *    pairing mode"）。严格按语义来 —— **只**反映配对模式，与是否有
     *    连接无关：
     *        配对模式 ON  -> 0x80
     *        配对模式 OFF -> 0x00
     *    这是客户端判断"设备能否配对"的主要依据（规范指出平台通常不向
     *    应用暴露 AD Flags 的 Discoverable 位，只能靠 Service Data）。 */
    advertData[ADVERT_SD_FLAGS_OFFSET] =
        on ? FIDO_SD_BIT_PAIRING_MODE : 0x00;
    GAPRole_SetParameter(GAPROLE_ADVERT_DATA, sizeof(advertData), advertData);

    /* 2) AD Flags（规范 §11.4.7）：
     *      配对模式   -> General Discoverable = 1
     *      非配对模式 -> Limited 与 General 均清零 */
    flags = GAP_ADTYPE_FLAGS_BREDR_NOT_SUPPORTED;
    if(on)
    {
        flags |= GAP_ADTYPE_FLAGS_GENERAL;
    }
    advertData[ADVERT_FLAGS_OFFSET] = flags;
    GAPRole_SetParameter(GAPROLE_ADVERT_DATA, sizeof(advertData), advertData);

    /* 3) 可见提示（规范要求"a visible or audible cue"）：快闪 2Hz */
    if(on)
    {
        HalLedBlink(HAL_LED_1, 0, 50, 250);
        s_pairing_deadline = TMOS_GetSystemClock() + PAIRING_WINDOW_MS;
    }
    else
    {
        HalLedSet(HAL_LED_1, HAL_LED_MODE_ON);
        s_pairing_deadline = 0;
    }

    PRINT("[BLE] pairing mode %s", on ? "ON (long-press detected)" : "OFF");
    PRINT("%c", 10);

    /* 无条件打印广播的实际内容，作为"是否真的生效"的凭据
     * （只看 PRINT 里的意图值不够 —— 必须看数组里的实际字节）。
     *   AD flags：配对模式=0x06(GENERAL|BREDR_NOT_SUPPORTED)、非配对=0x04
     *   svc bit7：配对模式=0x80、非配对=0x00 */
    PRINT("[BLE]   AD flags=0x%02X  svc bit7=0x%02X  (pairing=%u)",
          advertData[ADVERT_FLAGS_OFFSET], advertData[ADVERT_SD_FLAGS_OFFSET],
          s_pairing_mode);
    PRINT("%c", 10);
}

/* 供 ble_transport 在收到 FIDO 请求/读写时调用：只要客户端还在活动，
 * 就续上配对窗口，避免交互中途"配对模式过期"。
 * 若当前不在配对模式则什么都不做（不能凭空进入）。 */
void Peripheral_PairingKeepAlive(void)
{
    if(s_pairing_mode)
    {
        s_pairing_deadline = TMOS_GetSystemClock() + PAIRING_WINDOW_MS;
    }
}


void Peripheral_PairingModePoll(void)
{
    uint32_t now = TMOS_GetSystemClock();

    /* 采样节流：主循环是忙等的 */
    if((now - s_key_sample) < PAIRING_SAMPLE_MS)
    {
        return;
    }
    s_key_sample = now;

    /* 诊断：按键状态变化时打印一次（不刷屏）。
     *   按下 -> 报一次起点；按住满 5 秒 -> 报一次；
     *   若一直只看到 down/up 而没有 held 满，说明是"没按住"或采样被饿死。 */
    {
        static uint8_t s_last_btn = 0;
        uint8_t btn = HAL_PUSH_BUTTON2() ? 1 : 0;
        if(btn != s_last_btn)
        {
            s_last_btn = btn;
            PRINT("[KEY] %s (auth_sm=%u)", btn ? "down" : "up", auth_sm_get());
            PRINT("%c", 10);
        }
    }

    if(HAL_PUSH_BUTTON2())
    {
        if(s_key_hold_start == 0)
        {
            s_key_hold_start = now;
        }

        /* 正在等待 UP 时不做长按判定：那段时间按键的语义是"用户在场确认"，
         * 若同时触发配对模式会误操作（auth_sm 已把按键消费掉了）。 */
        if(!s_pairing_mode && auth_sm_get() != AUTH_WAIT_ACTIVE)
        {
            if((now - s_key_hold_start) >= PAIRING_HOLD_MS)
            {
                Peripheral_SetPairingMode(1);
            }
        }
        else
        {
            /* 诊断：长按被这两个条件之一挡住了（每 1 秒提示一次，不刷屏） */
            static uint32_t s_last_hint = 0;
            if((now - s_last_hint) >= 1000)
            {
                s_last_hint = now;
                PRINT("[KEY] held but blocked: pairing=%u auth_sm=%u",
                      s_pairing_mode, auth_sm_get());
                PRINT("%c", 10);
            }
        }
    }
    else
    {
        s_key_hold_start = 0;
    }

    /* 配对模式超时退出 */
    if(s_pairing_mode && s_pairing_deadline != 0 &&
       (int32_t)(now - s_pairing_deadline) >= 0)
    {
        Peripheral_SetPairingMode(0);
        PRINT("[BLE] pairing window expired");
        PRINT("%c", 10);
    }
}

static void Peripheral_PairStateCB(uint16_t connHandle, uint8_t state, uint8_t status)
{
    PRINT("[BLE] pair state=%u status=0x%02X conn=%u", state, (unsigned)status, connHandle);
    PRINT("%c", 10);

    /* 注意：这里**不要**在配对成功时退出配对模式。
     *
     * 曾经这样做过（理由是"避免长期停在可配对状态"），但实测发现：客户端在配对
     * 完成后仍会继续做特征发现/服务遍历，此时若广播里的 Service Data bit7 已经
     * 清零，它会认为"设备退出了配对模式"而直接放弃 —— 表现为连上、MTU 交换完毕
     * 之后一步 GATT 操作都不做（日志里 pairing mode OFF 紧跟在 pair state=3 之后）。
     *
     * 配对模式的退出交给两条既有路径：
     *   1) 窗口超时（PAIRING_WINDOW_MS，期间只要客户端有活动就会自动续期）
     *   2) 设备重启
     * 这样客户端在整个交互期间都能看到 bit7=1。规范也只要求"进入配对模式的动作
     * 不易误触发 + 有可见提示"，并未要求配对成功即退出。 */
    if(state == GAPBOND_PAIRING_STATE_BOND_SAVED)
    {
        PRINT("[BLE] bond saved (pairing mode stays ON until window expires)");
        PRINT("%c", 10);
    }
}

// GAP Bond Manager Callbacks
static gapBondCBs_t Peripheral_BondMgrCBs = {
    NULL,                          // Passcode callback（Just Works 不需要）
    Peripheral_PairStateCB         // Pairing / Bonding state Callback
};

/*********************************************************************
 * PUBLIC FUNCTIONS
 */

/*********************************************************************
 * @fn      Peripheral_Init
 *
 * @brief   Initialization function for the Peripheral App Task.
 *          This is called during initialization and should contain
 *          any application specific initialization (ie. hardware
 *          initialization/setup, table initialization, power up
 *          notificaiton ... ).
 *
 * @param   task_id - the ID assigned by TMOS.  This ID should be
 *                    used to send messages and set timers.
 *
 * @return  none
 */
void Peripheral_Init()
{
    Peripheral_TaskID = TMOS_ProcessEventRegister(Peripheral_ProcessEvent);

    // Setup the GAP Peripheral Role Profile
    {
        uint8_t  initial_advertising_enable = TRUE;
        uint16_t desired_min_interval = DEFAULT_DESIRED_MIN_CONN_INTERVAL;
        uint16_t desired_max_interval = DEFAULT_DESIRED_MAX_CONN_INTERVAL;

        // Set the GAP Role Parameters
        GAPRole_SetParameter(GAPROLE_ADVERT_ENABLED, sizeof(uint8_t), &initial_advertising_enable);
        GAPRole_SetParameter(GAPROLE_SCAN_RSP_DATA, sizeof(scanRspData), scanRspData);
        GAPRole_SetParameter(GAPROLE_ADVERT_DATA, sizeof(advertData), advertData);

        /* 上电后处于"非配对模式"：AD Flags 两位清零、Service Data bit7 清零。
         * 用户需长按 5 秒才进入配对模式（规范要求进入动作"不易误触发"）。
         * 这里先按非配对模式改写广播数据，随后由协议栈启用广播。 */
        advertData[ADVERT_FLAGS_OFFSET] = GAP_ADTYPE_FLAGS_BREDR_NOT_SUPPORTED;
        advertData[ADVERT_SD_FLAGS_OFFSET] = 0x00;
        GAPRole_SetParameter(GAPROLE_ADVERT_DATA, sizeof(advertData), advertData);
        GAPRole_SetParameter(GAPROLE_MIN_CONN_INTERVAL, sizeof(uint16_t), &desired_min_interval);
        GAPRole_SetParameter(GAPROLE_MAX_CONN_INTERVAL, sizeof(uint16_t), &desired_max_interval);
    }

    // Set the GAP Characteristics
    GGS_SetParameter(GGS_DEVICE_NAME_ATT, GAP_DEVICE_NAME_LEN, attDeviceName);

    {
        uint16_t advInt = DEFAULT_ADVERTISING_INTERVAL;

        // Set advertising interval
        GAP_SetParamValue(TGAP_DISC_ADV_INT_MIN, advInt);
        GAP_SetParamValue(TGAP_DISC_ADV_INT_MAX, advInt);

        // Enable scan req notify
        GAP_SetParamValue(TGAP_ADV_SCAN_REQ_NOTIFY, ENABLE);
    }


#if defined(BLE_ERASE_BONDS_ON_BOOT)
    /* 临时调试开关（-D BLE_ERASE_BONDS_ON_BOOT 打开）：每次上电清除所有绑定。
     *
     * 为什么需要：绑定记录持久化在 SNV Flash 里，光重启设备不会清掉。
     * 两侧绑定不一致时（换过配对参数、或客户端保留了旧 LTK），加密阶段会
     * 以 MIC Failure（断开原因 0x3D）失败 —— 表现为连上就断、不发任何
     * FIDO 请求，很难与代码问题区分。
     *
     * 清完 SNV 后应当**移除本开关再配对**，否则下次上电又清一次。 */
    GAPBondMgr_SetParameter(GAPBOND_ERASE_ALLBONDS, 0, NULL);
    PRINT("[BLE] bonds erased on boot (debug)%c", 10);
#endif

    // Setup the GAP Bond Manager
    //
    // 配对级别：**Security Mode 1, Level 2**（加密的未认证配对，即 Just Works）。
    //
    // 依据 CTAP 2.1 规范（BLE 传输章节）：
    //   "For Bluetooth Low Energy Technology connections, the authenticator
    //    [SHALL use] Security Mode 1, Level 2 (unauthenticated pairing with
    //    encryption) or Security Mode 1, Level 3 (authenticated pairing with
    //    encryption) before any FIDO messages."
    // 规范允许 Level 2 或 Level 3。本设备选 Level 2。
    //
    // 为什么不是 Level 3：那要求"认证配对"（显示/输入配对码或带外信道），
    // 而 Peripheral_BondMgrCBs 的 passcodeCB 为 NULL —— 设备不具备该能力。
    // 原先的 mitm=TRUE + DISPLAY_ONLY 属于"声称 Level 3 却无法完成认证"，
    // 客户端会在配对阶段卡住（实测 Android 提示"按住按键 5 秒"后无后续）。
    //
    // 另：规范要求"只接受已绑定客户端的连接"，由 bonding=TRUE 满足。
    {
        uint32_t passkey = 0; // passkey "000000"
        uint8_t  pairMode = GAPBOND_PAIRING_MODE_WAIT_FOR_REQ;
        uint8_t  mitm = FALSE;
        uint8_t  bonding = TRUE;
        uint8_t  ioCap = GAPBOND_IO_CAP_NO_INPUT_NO_OUTPUT;
        GAPBondMgr_SetParameter(GAPBOND_PERI_DEFAULT_PASSCODE, sizeof(uint32_t), &passkey);
        GAPBondMgr_SetParameter(GAPBOND_PERI_PAIRING_MODE, sizeof(uint8_t), &pairMode);
        GAPBondMgr_SetParameter(GAPBOND_PERI_MITM_PROTECTION, sizeof(uint8_t), &mitm);
        GAPBondMgr_SetParameter(GAPBOND_PERI_IO_CAPABILITIES, sizeof(uint8_t), &ioCap);
        GAPBondMgr_SetParameter(GAPBOND_PERI_BONDING_ENABLED, sizeof(uint8_t), &bonding);
    }

    // Initialize GATT attributes
    GGS_AddService(GATT_ALL_SERVICES);           // GAP
    GATTServApp_AddService(GATT_ALL_SERVICES);   // GATT attributes
    DevInfo_AddService();                        // Device Information Service
    /* 说明（FIDO 认证器的服务清单，CTAP 2.1 规范 §11.4.5）：
     *   必需 —— GAP、DIS（上面两行）、FIDO GATT 服务（ble_transport_init 里注册）
     *   可选 —— GATT attributes（GATTServApp）
     * 原先这里还注册了 WCH 示例的 SimpleProfile 和一个已废弃的 ble_usb_service，
     * 两者都不是规范要求，且在服务发现时会多出无关条目，故移除。 */
    ble_transport_init();

    /* 调试服务（f0000001-…）：写 0x01 即清除所有 BLE 绑定。
     * 省去"改 -D BLE_ERASE_BONDS_ON_BOOT 宏 -> 重烧 -> 上电"的循环。
     * 发布前可整段移除（连同 src/dbg_service.c / include/dbg_service.h）。 */
    dbg_add_service();

    // Init Connection Item
    peripheralInitConnItem(&peripheralConnList);

    // Register receive scan request callback
    GAPRole_BroadcasterSetCB(&Broadcaster_BroadcasterCBs);

    // Setup a delayed profile startup
    tmos_set_event(Peripheral_TaskID, SBP_START_DEVICE_EVT);
}

/*********************************************************************
 * @fn      peripheralInitConnItem
 *
 * @brief   Init Connection Item
 *
 * @param   peripheralConnList -
 *
 * @return  NULL
 */
static void peripheralInitConnItem(peripheralConnItem_t *peripheralConnList)
{
    peripheralConnList->connHandle = GAP_CONNHANDLE_INIT;
    peripheralConnList->connInterval = 0;
    peripheralConnList->connSlaveLatency = 0;
    peripheralConnList->connTimeout = 0;
}

/*********************************************************************
 * @fn      Peripheral_ProcessEvent
 *
 * @brief   Peripheral Application Task event processor.  This function
 *          is called to process all events for the task.  Events
 *          include timers, messages and any other user defined events.
 *
 * @param   task_id - The TMOS assigned task ID.
 * @param   events - events to process.  This is a bit map and can
 *                   contain more than one event.
 *
 * @return  events not processed
 */
uint16_t Peripheral_ProcessEvent(uint8_t task_id, uint16_t events)
{
    //  VOID task_id; // TMOS required parameter that isn't used in this function

    if(events & SYS_EVENT_MSG)
    {
        uint8_t *pMsg;

        if((pMsg = tmos_msg_receive(Peripheral_TaskID)) != NULL)
        {
            Peripheral_ProcessTMOSMsg((tmos_event_hdr_t *)pMsg);
            // Release the TMOS message
            tmos_msg_deallocate(pMsg);
        }
        // return unprocessed events
        return (events ^ SYS_EVENT_MSG);
    }

    if(events & SBP_START_DEVICE_EVT)
    {
        // Start the Device
        GAPRole_PeripheralStartDevice(Peripheral_TaskID, &Peripheral_BondMgrCBs, &Peripheral_PeripheralCBs);
        return (events ^ SBP_START_DEVICE_EVT);
    }

    if(events & SBP_PERIODIC_EVT)
    {
        // Restart timer
        if(SBP_PERIODIC_EVT_PERIOD)
        {
            tmos_start_task(Peripheral_TaskID, SBP_PERIODIC_EVT, SBP_PERIODIC_EVT_PERIOD);
        }
        // Perform periodic application task
        performPeriodicTask();
        return (events ^ SBP_PERIODIC_EVT);
    }

    if(events & SBP_PARAM_UPDATE_EVT)
    {
        // Send connect param update request
        GAPRole_PeripheralConnParamUpdateReq(peripheralConnList.connHandle,
                                             DEFAULT_DESIRED_MIN_CONN_INTERVAL,
                                             DEFAULT_DESIRED_MAX_CONN_INTERVAL,
                                             DEFAULT_DESIRED_SLAVE_LATENCY,
                                             DEFAULT_DESIRED_CONN_TIMEOUT,
                                             Peripheral_TaskID);

        return (events ^ SBP_PARAM_UPDATE_EVT);
    }

    if(events & SBP_PHY_UPDATE_EVT)
    {
        // start phy update
        PRINT("PHY Update %x...\n", GAPRole_UpdatePHY(peripheralConnList.connHandle, 0, 
                    GAP_PHY_BIT_LE_2M, GAP_PHY_BIT_LE_2M, GAP_PHY_OPTIONS_NOPRE));

        return (events ^ SBP_PHY_UPDATE_EVT);
    }

    if(events & SBP_READ_RSSI_EVT)
    {
        GAPRole_ReadRssiCmd(peripheralConnList.connHandle);
        tmos_start_task(Peripheral_TaskID, SBP_READ_RSSI_EVT, SBP_READ_RSSI_EVT_PERIOD);
        return (events ^ SBP_READ_RSSI_EVT);
    }

    // Discard unknown events
    return 0;
}

/*********************************************************************
 * @fn      Peripheral_ProcessGAPMsg
 *
 * @brief   Process an incoming task message.
 *
 * @param   pMsg - message to process
 *
 * @return  none
 */
static void Peripheral_ProcessGAPMsg(gapRoleEvent_t *pEvent)
{
    switch(pEvent->gap.opcode)
    {
        case GAP_SCAN_REQUEST_EVENT:
        {
            // PRINT("Receive scan req from %x %x %x %x %x %x  ..\n", pEvent->scanReqEvt.scannerAddr[0],
            //       pEvent->scanReqEvt.scannerAddr[1], pEvent->scanReqEvt.scannerAddr[2], pEvent->scanReqEvt.scannerAddr[3],
            //       pEvent->scanReqEvt.scannerAddr[4], pEvent->scanReqEvt.scannerAddr[5]);
            break;
        }

        case GAP_PHY_UPDATE_EVENT:
        {
            PRINT("Phy update Rx:%x Tx:%x ..\n", pEvent->linkPhyUpdate.connRxPHYS, pEvent->linkPhyUpdate.connTxPHYS);
            break;
        }

        default:
            break;
    }
}

/*********************************************************************
 * @fn      Peripheral_ProcessTMOSMsg
 *
 * @brief   Process an incoming task message.
 *
 * @param   pMsg - message to process
 *
 * @return  none
 */
static void Peripheral_ProcessTMOSMsg(tmos_event_hdr_t *pMsg)
{
    switch(pMsg->event)
    {
        case GAP_MSG_EVENT:
        {
            Peripheral_ProcessGAPMsg((gapRoleEvent_t *)pMsg);
            break;
        }

        case GATT_MSG_EVENT:
        {
            gattMsgEvent_t *pMsgEvent;

            pMsgEvent = (gattMsgEvent_t *)pMsg;
            if(pMsgEvent->method == ATT_MTU_UPDATED_EVENT)
            {
                peripheralMTU = pMsgEvent->msg.exchangeMTUReq.clientRxMTU;
                /* BLE 传输层按 MTU 决定分片粒度 */
                ble_transport_set_mtu(peripheralMTU);
                PRINT("mtu exchange: %d\n", pMsgEvent->msg.exchangeMTUReq.clientRxMTU);
            }
            break;
        }

        default:
            break;
    }
}

/*********************************************************************
 * @fn      Peripheral_LinkEstablished
 *
 * @brief   Process link established.
 *
 * @param   pEvent - event to process
 *
 * @return  none
 */
static void Peripheral_LinkEstablished(gapRoleEvent_t *pEvent)
{
    gapEstLinkReqEvent_t *event = (gapEstLinkReqEvent_t *)pEvent;

    // See if already connected
    if(peripheralConnList.connHandle != GAP_CONNHANDLE_INIT)
    {
        GAPRole_TerminateLink(pEvent->linkCmpl.connectionHandle);
        PRINT("Connection max...\n");
    }
    else
    {
        peripheralConnList.connHandle = event->connectionHandle;
        PRINT("[BLE] link ESTABLISHED conn=%u timeout=%u",
              event->connectionHandle, event->connTimeout);
        PRINT("%c", 10);
        Peripheral_PairingKeepAlive();   /* 有连接即续期 */
        /* 通知要发到这个连接上，传输层必须知道句柄 */
        ble_transport_set_conn(event->connectionHandle);
        PRINT("[BLE] transport conn set to %u\n", event->connectionHandle);

        /* 关于链路加密（CTAP 2.1 §11.4.3）：
         *   "the authenticator SHALL enforce Security Mode 1, Level 2 ... or
         *    Level 3 ... before any FIDO messages are exchanged"
         *
         * 本设备靠 GATT_PERMIT_ENCRYPT_* 满足这一条 —— 未加密的连接读写
         * FIDO 属性会被拒（实测 ATT 5 Insufficient Authentication），
         * 从"拒绝明文访问"的角度强制了加密。
         *
         * ★ 曾在此处调用 GAPBondMgr_PeriSecurityReq() 由外设主动发
         *   LL Security Request，**实测效果是负面的**：
         *     - 有它：连接后**立刻**断开（reason=0x13），连 mtu exchange
         *       都来不及做，约 30 次循环无一成功
         *     - 去掉后：连接稳定，能完成 mtu exchange 与特征读取
         *   原因是它把"客户端自己决定何时加密"变成"设备强迫立即加密"，
         *   客户端不接受这个节奏就直接放弃连接。
         *   规范并未要求由哪一侧发起加密，故不再主动发请求，
         *   改为"客户端发起 + 权限位兜底"。
         */

        peripheralConnList.connInterval = event->connInterval;
        peripheralConnList.connSlaveLatency = event->connLatency;
        peripheralConnList.connTimeout = event->connTimeout;

        // Set timer for periodic event
        tmos_start_task(Peripheral_TaskID, SBP_PERIODIC_EVT, SBP_PERIODIC_EVT_PERIOD);
        PRINT("[BLE] started PERIODIC_EVT (1.6s)\n");

        // Set timer for param update event
        tmos_start_task(Peripheral_TaskID, SBP_PARAM_UPDATE_EVT, SBP_PARAM_UPDATE_DELAY);

        // Start read rssi
        tmos_start_task(Peripheral_TaskID, SBP_READ_RSSI_EVT, SBP_READ_RSSI_EVT_PERIOD);
        PRINT("[BLE] started READ_RSSI_EVT\n");

        PRINT("Conn %u - Int %u SlaveLat %u Timeout %u",
              event->connectionHandle, event->connInterval,
              event->connLatency, event->connTimeout);
        PRINT("%c", 10);
    }
}

/*********************************************************************
 * @fn      Peripheral_LinkTerminated
 *
 * @brief   Process link terminated.
 *
 * @param   pEvent - event to process
 *
 * @return  none
 */
static void Peripheral_LinkTerminated(gapRoleEvent_t *pEvent)
{
    gapTerminateLinkEvent_t *event = (gapTerminateLinkEvent_t *)pEvent;
    PRINT("[BLE] link TERMINATED conn=%u reason=0x%02X",
          event->connectionHandle, event->reason);
    PRINT("%c", 10);

    if(event->connectionHandle == peripheralConnList.connHandle)
    {
        peripheralConnList.connHandle = GAP_CONNHANDLE_INIT;
        peripheralConnList.connInterval = 0;
        peripheralConnList.connSlaveLatency = 0;
        peripheralConnList.connTimeout = 0;
        /* 丢弃半截的收发状态，避免下次连接时串味 */
        ble_transport_clear();
        tmos_stop_task(Peripheral_TaskID, SBP_PERIODIC_EVT);
        tmos_stop_task(Peripheral_TaskID, SBP_READ_RSSI_EVT);

        // Restart advertising
        {
            uint8_t advertising_enable = TRUE;
            GAPRole_SetParameter(GAPROLE_ADVERT_ENABLED, sizeof(uint8_t), &advertising_enable);
        }
    }
    else
    {
        PRINT("ERR..\n");
    }
}

/*********************************************************************
 * @fn      peripheralRssiCB
 *
 * @brief   RSSI callback.
 *
 * @param   connHandle - connection handle
 * @param   rssi - RSSI
 *
 * @return  none
 */
static void peripheralRssiCB(uint16_t connHandle, int8_t rssi)
{
    PRINT("RSSI -%d dB Conn  %x \n", -rssi, connHandle);
}

/*********************************************************************
 * @fn      peripheralParamUpdateCB
 *
 * @brief   Parameter update complete callback
 *
 * @param   connHandle - connect handle
 *          connInterval - connect interval
 *          connSlaveLatency - connect slave latency
 *          connTimeout - connect timeout
 *
 * @return  none
 */
static void peripheralParamUpdateCB(uint16_t connHandle, uint16_t connInterval,
                                    uint16_t connSlaveLatency, uint16_t connTimeout)
{
    if(connHandle == peripheralConnList.connHandle)
    {
        peripheralConnList.connInterval = connInterval;
        peripheralConnList.connSlaveLatency = connSlaveLatency;
        peripheralConnList.connTimeout = connTimeout;

        PRINT("[BLE] param update SUCCESS int=%d latency=%d timeout=%d\n",
              connInterval, connSlaveLatency, connTimeout);
    }
    else
    {
        PRINT("[BLE] param update ERR: conn mismatch\n");
    }
}


/*********************************************************************
 * @fn      peripheralStateNotificationCB
 *
 * @brief   Notification from the profile of a state change.
 *
 * @param   newState - new state
 *
 * @return  none
 */
static void peripheralStateNotificationCB(gapRole_States_t newState, gapRoleEvent_t *pEvent)
{
    switch(newState & GAPROLE_STATE_ADV_MASK)
    {
        case GAPROLE_STARTED:
            PRINT("Initialized..\n");
            break;

        case GAPROLE_ADVERTISING:
            if(pEvent->gap.opcode == GAP_LINK_TERMINATED_EVENT)
            {
                Peripheral_LinkTerminated(pEvent);
                PRINT("Disconnected.. Reason:%x\n", pEvent->linkTerminate.reason);
                PRINT("Advertising..\n");
            }
            else if(pEvent->gap.opcode == GAP_MAKE_DISCOVERABLE_DONE_EVENT)
            {
                PRINT("Advertising..\n");
            }
            break;

        case GAPROLE_CONNECTED:
            if(pEvent->gap.opcode == GAP_LINK_ESTABLISHED_EVENT)
            {
                Peripheral_LinkEstablished(pEvent);
                PRINT("Connected..\n");
            }
            break;

        case GAPROLE_CONNECTED_ADV:
            if(pEvent->gap.opcode == GAP_MAKE_DISCOVERABLE_DONE_EVENT)
            {
                PRINT("Connected Advertising..\n");
            }
            break;

        case GAPROLE_WAITING:
            if(pEvent->gap.opcode == GAP_END_DISCOVERABLE_DONE_EVENT)
            {
                PRINT("Waiting for advertising..\n");
            }
            else if(pEvent->gap.opcode == GAP_LINK_TERMINATED_EVENT)
            {
                Peripheral_LinkTerminated(pEvent);
                PRINT("Disconnected.. Reason:%x\n", pEvent->linkTerminate.reason);
            }
            else if(pEvent->gap.opcode == GAP_LINK_ESTABLISHED_EVENT)
            {
                if(pEvent->gap.hdr.status != SUCCESS)
                {
                    PRINT("Waiting for advertising..\n");
                }
                else
                {
                    PRINT("Error..\n");
                }
            }
            else
            {
                PRINT("Error..%x\n", pEvent->gap.opcode);
            }
            break;

        case GAPROLE_ERROR:
            PRINT("Error..\n");
            break;

        default:
            break;
    }
}

/*********************************************************************
 * @fn      performPeriodicTask
 *
 * @brief   Perform a periodic application task. This function gets
 *          called every five seconds as a result of the SBP_PERIODIC_EVT
 *          TMOS event. In this example, the value of the third
 *          characteristic in the SimpleGATTProfile service is retrieved
 *          from the profile, and then copied into the value of the
 *          the fourth characteristic.
 *
 * @param   none
 *
 * @return  none
 */
static void performPeriodicTask(void)
{
    /* 按键改由官方 HAL 的 KEY 服务管理（HAL_KEY=TRUE 时 HAL_Init() 会调
     * HAL_KeyInit() 配置 KEY2/PB4 为上拉输入）。用户存在的判定与 LED 提示
     * 统一由 auth_sm 负责，这里不再自行轮询，避免与 UP 等待期间的 LED 状态打架。 */
}


