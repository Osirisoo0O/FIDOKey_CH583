# FIDO BLE 操作流程详解

> 基于 CH583 (RISC-V) + WCH BLE_LIB_V1.50 栈，FIDO2 安全密钥认证器实现。

---

## 目录

1. [整体架构概览](#1-整体架构概览)
2. [完整操作流程](#2-完整操作流程)
3. [各阶段详解](#3-各阶段详解)
4. [回调链与数据流](#4-回调链与数据流)
5. [属性表与句柄映射](#5-属性表与句柄映射)
6. [CCCD 订阅与通知发送](#6-cccd-订阅与通知发送)
7. [参数更新流程](#7-参数更新流程)
8. [帧编解码与分片](#8-帧编解码与分片)
9. [调试日志解读](#9-调试日志解读)
10. [已知问题与排查](#10-已知问题与排查)

---

## 1. 整体架构概览

```
┌─────────────────────────────────────────────────────────────┐
│                    应用层 (Application)                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ USB HID  │  │ BLE GATT │  │ CTAP2    │  │ Flash    │   │
│  │ Transport│  │ Transport│  │ Handler  │  │ Storage  │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│       │             │             │             │           │
│  ┌────┴─────────────┴─────────────┴─────────────┴─────┐   │
│  │              auth_sm (权限闸门 / UP 等待)            │   │
│  └────────────────────────────────────────────────────┘   │
├────────────────────────────────────────────────────────────┤
│              BLE 传输层 (ble_transport.c)                    │
│  帧编解码 | 分片重组 | PING/MSG/CANCEL | 发送调度 (pump)    │
├────────────────────────────────────────────────────────────┤
│              GATT 服务层 (fido_service.c)                    │
│  FIDO GATT 服务注册 | 读写回调 | CCCD | 通知发送            │
├────────────────────────────────────────────────────────────┤
│           GAP 角色层 (peripheral.c)                          │
│  广播 | 连接管理 | 参数更新 | MTU 交换 | RSSI 采样          │
├────────────────────────────────────────────────────────────┤
│         WCH BLE_LIB_V1.50 协议栈 (底层)                      │
│  GAP Role (Peripheral) | GATT Server | Link Manager         │
└─────────────────────────────────────────────────────────────┘
```

### 核心文件职责

| 文件 | 职责 |
|------|------|
| `src/peripheral.c` | GAP 角色管理、广播、连接建立/断开、参数更新、配对模式 |
| `src/fido_service.c` | FIDO GATT 服务注册、属性读写回调、CCCD 处理、通知发送 |
| `src/ble_transport.c` | BLE FIDO 帧编解码、分片重组、PING/MSG/CANCEL 处理、发送调度 |
| `src/ctap.c` / `src/cbor_lite.c` | CTAP2 协议处理、CBOR 编解码 |
| `src/auth_sm.c` | 权限闸门（UP 等待/KEEPALIVE） |
| `src/cred_mgr.c` | 凭证管理（MakeCredential/GetAssertion） |
| `src/secure_store.c` | 安全存储（ECC 私钥、签名） |

---

## 2. 完整操作流程

```mermaid
flowchart TB
    subgraph BOOT["上电启动"]
        B1[Peripheral_Init] --> B2[GAP/GATT/DevInfo 服务注册]
        B2 --> B3[ble_transport_init]
        B3 --> B4[fido_add_service]
        B4 --> B5[注册 GATT 属性表<br/>4 个特征]
        B5 --> B6[注册 linkDB 回调]
        B6 --> B7[设置初始 CPLength=20<br/>(23-3)]
        B7 --> B8[启动广播<br/>非配对模式 flags=0x00]
    end

    subgraph ADV["等待连接"]
        A1[广播周期 50ms] --> A2[扫描响应含<br/>连接间隔+设备名]
        A2 --> A3[客户端扫描发现]
        A3 --> A4[客户端发起连接]
    end

    subgraph CONNECT["连接建立"]
        C1[GAP_LINK_ESTABLISHED_EVENT] --> C2[Peripheral_LinkEstablished]
        C2 --> C3[保存 connHandle]
        C3 --> C4[设置传输层连接句柄<br/>ble_transport_set_conn]
        C4 --> C5[启动周期事件<br/>SBP_PERIODIC_EVT 1.6s]
        C5 --> C6[启动 RSSI 采样<br/>SBP_READ_RSSI_EVT 3.2s]
        C6 --> C7[续期配对窗口<br/>Peripheral_PairingKeepAlive]
    end

    subgraph GATT_DISCOVERY["GATT 发现 (客户端触发)"]
        D1[客户端 FIND_INFO_REQ /<br/>READ_BY_GRP_TYPE_REQ] --> D2[发现 FIDO 服务 UUID]
        D2 --> D3[客户端 READ_BY_TYPE_REQ<br/>发现特征]
        D3 --> D4[客户端 ATT_MTU_Exchange_REQ]
        D4 --> D5[GATT_MSG_EVENT<br/>MTU 更新通知]
        D5 --> D6[ble_transport_set_mtu<br/>更新 CPLength]
    end

    subgraph CCCD["CCCD 订阅"]
        E1[客户端 WRITE_REQ<br/>CCCD = 0x0001] --> E2[fido_WriteAttrCB]
        E2 --> E3[GATTServApp_ProcessCCCDWriteReq]
        E3 --> E4[CCCD 写入成功]
        E4 --> E5[触发 FIDO_EVT_STATUS_NOTI_ENABLED]
        E5 --> E6[ble_transport_event_cb]
        E6 --> E7[ble_transport_on_cccd_enabled]
        E7 --> E8[Peripheral_RequestParamUpdate]
        E8 --> E9[GAPRole_PeripheralConnParamUpdateReq]
    end

    subgraph FIDO_OPS["FIDO 操作"]
        F1[客户端 WRITE_REQ<br/>fidoControlPoint] --> F2[fido_WriteAttrCB]
        F2 --> F3[触发 FIDO_EVT_CONTROL_POINT_WRITE]
        F3 --> F4[ble_transport_event_cb]
        F4 --> F5[ble_transport_on_write]
        F5 --> F6[帧解析]
        
        F6 --> F7A{命令类型}
        F7A -->|PING| F8[原样回显]
        F7A -->|MSG| F9[CTAP2 处理<br/>ctap_handle_cbor]
        F7A -->|CANCEL| F10[ctap_abort_pending]
        F7A -->|其他| F11[ERROR 帧]
        
        F9 --> F12{CTAP 状态}
        F12 -->|SUCCESS| F13[组装 MSG 响应帧]
        F12 -->|PENDING| F14[保留请求<br/>等待 UP]
        F12 -->|ERROR| F15[组装 ERROR 帧]
        
        F8 --> F16[ble_transport_pump<br/>逐帧发送通知]
        F13 --> F16
        F15 --> F16
        F14 --> F17[KEEPALIVE 保活]
    end

    subgraph DISCONNECT["连接断开"]
        G1[客户端断开 / 超时] --> G2[GAP_LINK_TERMINATED_EVENT]
        G2 --> G3[Peripheral_LinkTerminated]
        G3 --> G4[清除 connHandle]
        G4 --> G5[ble_transport_clear]
        G5 --> G6[停止周期事件]
        G6 --> G7[重启广播]
    end

    BOOT --> ADV --> CONNECT --> GATT_DISCOVERY --> CCCD --> FIDO_OPS --> DISCONNECT
```

---

## 3. 各阶段详解

### 3.1 上电启动阶段

**入口**: `peripheral.c → Peripheral_Init()`

```
Peripheral_Init()
  ├─ TMOS_ProcessEventRegister()          // 注册任务
  ├─ GAP Role Profile 配置
  │   ├─ 广播使能 = TRUE
  │   ├─ 广播数据: Flags + FIDO UUID + Service Data (flags=0x00)
  │   ├─ 扫描响应: 设备名 "SecureKey" + 连接间隔 + 功率
  │   └─ 连接间隔: min=6 (7.5ms), max=24 (30ms)
  ├─ GAP Bond Manager 配置
  │   ├─ 配对模式: WAIT_FOR_REQ
  │   ├─ MITM: FALSE (Just Works)
  │   ├─ IO Cap: NO_INPUT_NO_OUTPUT
  │   └─ Bonding: TRUE
  ├─ GATT 服务注册
  │   ├─ GAP 服务 (GGS_AddService)
  │   ├─ GATT 属性服务 (GATTServApp_AddService)
  │   └─ Device Information Service (DevInfo_AddService)
  └─ ble_transport_init()                  // FIDO GATT 服务
       └─ fido_add_service(callback)
            ├─ fido_set_control_point_length(20)  // 初始值 23-3
            ├─ CCCD 初始化为 INVALID_CONNHANDLE
            ├─ linkDB_Register(fido_HandleConnStatusCB)
            └─ GATTServApp_RegisterService()
```

**关键初始状态**:
- 广播模式: **非配对模式** (Service Data flags = `0x00`, AD Flags = `0x02`)
- CPLength: **20 字节** (未协商 MTU 时的保守值)
- CCCD: **未订阅** (INVALID_CONNHANDLE)

### 3.2 等待连接阶段

设备进入广播状态，广播间隔 50ms（`DEFAULT_ADVERTISING_INTERVAL`）。

**广播数据结构** (26 字节):
```
[0x02] GAP_ADTYPE_FLAGS
       GAP_ADTYPE_FLAGS_BREDR_NOT_SUPPORTED | GAP_ADTYPE_FLAGS_GENERAL

[0x11] GAP_ADTYPE_128BIT_COMPLETE (FIDO 服务 UUID)
       fb 34 9b 5f 80 00 00 80 00 10 00 00 fd ff 00 00

[0x04] GAP_ADTYPE_SERVICE_DATA
       LO(FIDO_SERVICE_UUID16) HI(FIDO_SERVICE_UUID16)
       flags (bit7=配对模式, bit6=需要Passkey)
```

**扫描响应数据** (20 字节):
```
[0x09] GAP_ADTYPE_LOCAL_NAME_COMPLETE
       "SecureKey"

[0x05] GAP_ADTYPE_SLAVE_CONN_INTERVAL_RANGE
       06 00  (min 7.5ms)
       18 00  (max 30ms)

[0x02] GAP_ADTYPE_POWER_LEVEL
       0x00   (0 dBm)
```

### 3.3 连接建立阶段

**触发**: 客户端发起 GAP 连接请求 → `GAP_LINK_ESTABLISHED_EVENT`

```
peripheralStateNotificationCB(GAPROLE_CONNECTED)
  └─ Peripheral_LinkEstablished(pEvent)
       ├─ peripheralConnList.connHandle = event->connectionHandle
       ├─ ble_transport_set_conn(connHandle)
       ├─ peripheralConnList.connInterval = event->connInterval
       ├─ tmos_start_task(SBP_PERIODIC_EVT, 1600ms)
       ├─ tmos_start_task(SBP_READ_RSSI_EVT, 3200ms)
       └─ Peripheral_PairingKeepAlive()  // 续期配对窗口
```

**注意**: 连接建立后**不再立即触发参数更新**，推迟到 CCCD 订阅后。

### 3.4 GATT 发现阶段

**触发**: 客户端连接成功后自动进行 GATT 服务发现。

**客户端操作序列**:
1. `FIND_INFO_REQ` (0x04) — 发现描述符
2. `READ_BY_GRP_TYPE_REQ` (0x10) — 发现主服务
3. `READ_BY_TYPE_REQ` (0x08) — 发现特征及描述符
4. `ATT_MTU_Exchange_REQ` — MTU 协商

**MTU 交换流程**:
```
客户端 → 设备: ATT_MTU_Exchange_REQ (clientRxMTU = 256)
设备 → 客户端: ATT_MTU_Exchange_RSP (serverRxMTU = 256)
设备内部: GATT_MSG_EVENT → Peripheral_ProcessTMOSMsg
          → peripheralMTU = 256
          → ble_transport_set_mtu(256)
          → fido_set_control_point_length(256-3=253)
```

**MTU 对 CPLength 的影响**:
- 初始 (未协商): CPLength = 20 (基于 ATT_MTU_SIZE=23)
- 协商后 (MTU=256): CPLength = 253 (256-3)
- 客户端根据 CPLength 决定单次写入的最大数据长度

### 3.5 CCCD 订阅阶段

**触发**: 客户端向 fidoStatus CCCD (handle 0x0026) 写入 `0x0100` (启用通知)。

```
客户端 → 设备: WRITE_REQ (handle=0x0026, value=0x0100)
  └─ fido_WriteAttrCB(connHandle, pAttr, ...)
       ├─ pAttr->handle == CCCD handle
       ├─ GATTServApp_ProcessCCCDWriteReq()
       │   └─ s_StatusCCCD[connHandle] = GATT_CLIENT_CFG_NOTIFY
       ├─ 触发 FIDO_EVT_STATUS_NOTI_ENABLED
       │   └─ s_appCBs(FIDO_EVT_STATUS_NOTI_ENABLED)
       │        └─ ble_transport_event_cb()
       │             ├─ s_conn = connHandle  // 记录订阅连接
       │             └─ ble_transport_on_cccd_enabled()
       │                  └─ Peripheral_RequestParamUpdate()
       │                       └─ GAPRole_PeripheralConnParamUpdateReq()
       └─ 返回 SUCCESS
```

**为什么推迟到 CCCD 订阅后**:
- Windows BLE FIDO 客户端在连接后立即开始 GATT 发现
- 过早的参数更新会导致连接事件间隔变化，GATT 操作超时 → disconnect 0x13
- CCCD 订阅发生在 GATT 发现完成后，此时参数更新是安全的

### 3.6 FIDO 操作阶段

#### PING 命令

```
客户端 → 设备: WRITE_REQ (fidoControlPoint)
  帧: [0x81] [0x00] [0x08] <8字节数据>
       CMD=PING  LEN=8  DATA=<ping data>
  └─ ble_transport_on_write()
       ├─ 解析初始帧 (bit7=1)
       ├─ rx_cmd = FIDO_BLE_CMD_PING
       ├─ rx_total = 8
       └─ handle_frame()
            └─ case FIDO_BLE_CMD_PING:
                 send_frame(PING, data, 8)
                      └─ ble_transport_pump()
                           └─ fido_status_notify() → GATT_Notification()
```

#### MSG 命令 (CTAP2)

```
客户端 → 设备: WRITE_REQ (fidoControlPoint)
  帧: [0x82] [0x00] [0xXX] <CTAP2 消息>
       CMD=MSG  LEN=XX  DATA=[CTAP cmd][CBOR params]
  └─ ble_transport_on_write()
       └─ handle_frame()
            └─ case FIDO_BLE_CMD_MSG:
                 ctap_handle_cbor(cmd, data, ...)
                      ├─ MakeCredential / GetAssertion / ...
                      ├─ auth_sm 权限检查
                      ├─ P-256 密钥生成 + 签名
                      └─ 返回 [status][CBOR response]
                 send_frame(MSG, response, len)
                      └─ ble_transport_pump() → fido_status_notify()
```

#### PENDING 状态 (需要用户确认)

```
ctap_handle_cbor() → CTAP_STATUS_PENDING
  └─ s_ctap_pending = 1
  └─ s_pend_conn = s_conn
  └─ s_keepalive_last = TMOS_GetSystemClock()
  └─ SK_LOG("ble: ctap pending (UP)")
  └─ 不发响应，等待用户按键

auth_sm 取得 UP 后:
  └─ ble_transport_pending_poll()
       ├─ 重放 rx_buf 中的请求
       ├─ ctap_handle_cbor() → CTAP_SUCCESS
       └─ send_frame(MSG, response, len)
```

#### KEEPALIVE 保活

```
每次收到 FIDO 请求:
  └─ Peripheral_PairingKeepAlive()
       └─ if (s_pairing_mode)
            s_pairing_deadline = now + PAIRING_WINDOW_MS

周期事件 (1.6s):
  └─ performPeriodicTask()
       └─ if (s_ctap_pending && now - s_keepalive_last > KEEPALIVE_INTERVAL)
            send_frame(KEEPALIVE, ..., keepaliveValue)
```

### 3.7 连接断开阶段

**触发**: 客户端主动断开 / 超时 / 参数更新失败

```
GAP_LINK_TERMINATED_EVENT
  └─ peripheralStateNotificationCB(GAPROLE_CONNECTED_ADV → WAITING)
       └─ Peripheral_LinkTerminated(pEvent)
            ├─ peripheralConnList.connHandle = GAP_CONNHANDLE_INIT
            ├─ ble_transport_clear()  // 清除收发状态
            ├─ tmos_stop_task(SBP_PERIODIC_EVT)
            ├─ tmos_stop_task(SBP_READ_RSSI_EVT)
            └─ GAPRole_SetParameter(GAPROLE_ADVERT_ENABLED, TRUE)
```

**常见断开原因码**:
| 原因码 | 含义 | 常见场景 |
|--------|------|----------|
| 0x13 | Supervision Timeout | GATT 发现冲突、连接间隔过大 |
| 0x16 | Connection Timeout | 监督超时 (missed connection events) |
| 0x3D | MIC Failure | 绑定不一致、加密失败 |
| 0x08 | Authentication Failure | 配对认证失败 |

---

## 4. 回调链与数据流

### 4.1 写入回调链

```
客户端 WRITE_REQ (fidoControlPoint)
  │
  ├─▶ WCH BLE_LIB GATT Server
  │     └─ GATTServApp_ProcessWriteReq()
  │           └─ 调用注册回调: s_ProfileCBs.writeCB
  │                 └─ fido_WriteAttrCB()
  │                       ├─ 检查 handle → ATTR_IDX_CONTROL_POINT_VALUE
  │                       ├─ 保存 pValue[0..len-1] 到全局缓冲区
  │                       └─ 触发事件: s_appCBs(FIDO_EVT_CONTROL_POINT_WRITE)
  │
  ├─▶ ble_transport_event_cb()          [ble_transport.c]
  │     ├─ Peripheral_PairingKeepAlive()  // 续期配对窗口
  │     └─ ble_transport_on_write()
  │           ├─ s_conn = connHandle
  │           ├─ 解析帧格式 (初始帧/续帧)
  │           ├─ 重组完整消息
  │           └─ handle_frame()
  │                 ├─ PING → send_frame(PING, ...)
  │                 ├─ MSG → ctap_handle_cbor() → send_frame(MSG, ...)
  │                 ├─ CANCEL → ctap_abort_pending()
  │                 └─ 其他 → send_frame(ERROR, ...)
  │
  └─▶ ble_transport_pump()              [主循环调用]
        ├─ GATT_Notification() → fidoStatus CCCD
        └─ 逐帧发送 (初始帧 + 续帧)
```

### 4.2 CCCD 订阅回调链

```
客户端 WRITE_REQ (fidoStatus CCCD, handle=0x0026)
  │
  ├─▶ fido_WriteAttrCB()
  │     ├─ handle == CCCD handle
  │     ├─ GATTServApp_ProcessCCCDWriteReq()
  │     │   └─ s_StatusCCCD[connHandle] = GATT_CLIENT_CFG_NOTIFY
  │     └─ 触发事件: s_appCBs(FIDO_EVT_STATUS_NOTI_ENABLED)
  │
  ├─▶ ble_transport_event_cb()
  │     ├─ s_conn = connHandle
  │     └─ ble_transport_on_cccd_enabled()
  │           └─ Peripheral_RequestParamUpdate()
  │                 └─ GAPRole_PeripheralConnParamUpdateReq()
  │
  └─▶ peripheralParamUpdateCB()         [参数更新完成回调]
        ├─ connHandle 匹配
        ├─ 更新 peripheralConnList 参数
        └─ PRINT("[BLE] param update SUCCESS")
```

### 4.3 通知发送流程

```
send_frame(cmd, data, len)
  ├─ 组装初始帧: [CMD][HLEN][LLEN][DATA] → tx_buf
  ├─ tx_len = len + 3
  ├─ tx_offset = 0
  ├─ tx_active = 1
  └─ tx_cmd = cmd

ble_transport_pump()                    [主循环定期调用]
  ├─ if (!tx_active) return
  ├─ if (tx_offset == 0):
  │   └─ 发送初始帧: fido_status_notify(conn, tx_buf, n)
  │         ├─ 检查 CCCD 订阅
  │         ├─ GATT_bm_alloc() 分配缓冲
  │         ├─ GATT_Notification() 发送
  │         └─ 失败时 GATT_bm_free() 释放
  └─ if (tx_offset < tx_len):
     └─ 发送续帧: [SEQ][DATA]
           ├─ SEQ = tx_seq (bit7=0)
           ├─ 从 tx_buf[tx_offset] 取数据
           ├─ tx_seq++
           └─ tx_offset += sent_len
```

---

## 5. 属性表与句柄映射

### 5.1 FIDO GATT 服务属性表

```
服务 UUID: 0000fffd-0000-1000-8000-00805f9b34fb

┌──────┬──────────────────────────┬──────────────────────────┬────────────┐
│ 索引 │ 属性                     │ UUID                     │ 权限/操作  │
├──────┼──────────────────────────┼──────────────────────────┼────────────┤
│ [0]  │ Service Declaration      │ fffd-...-34fb (FIDO)     │ Read       │
│ [1]  │ fidoControlPoint Char    │ 0000 (Characteristic)    │ Read       │
│ [2]  │ fidoControlPoint Value   │ f1d0fff1-...-d0f1        │ Write      │
│ [3]  │ fidoStatus Char          │ 0000 (Characteristic)    │ Read       │
│ [4]  │ fidoStatus Value         │ f1d0fff2-...-d0f1        │ Notify     │
│ [5]  │ fidoStatus CCCD          │ 0000 (ClientCharCfg)     │ R/W        │
│ [6]  │ fidoControlPointLen Char │ 0000 (Characteristic)    │ Read       │
│ [7]  │ fidoControlPointLen Value│ f1d0fff3-...-d0f1        │ Read       │
│ [8]  │ RevBitfield Char         │ 0000 (Characteristic)    │ Read       │
│ [9]  │ RevBitfield Value        │ f1d0fff4-...-d0f1        │ R/W        │
└──────┴──────────────────────────┴──────────────────────────┴────────────┘

注: 实际 handle 值从 0x0001 开始递增，上述索引 [N] 对应 handle ≈ 0x000N+1
具体 handle 值取决于属性表排序和 CCCD 分配。
```

### 5.2 特征 UUID 与操作

| 特征 | UUID | 属性 | 操作 | 用途 |
|------|------|------|------|------|
| fidoControlPoint | `f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb` | Write | 客户端写入 | 发送 FIDO 命令 (PING/MSG/CANCEL) |
| fidoStatus | `f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb` | Notify | 设备发送 | 回送 FIDO 响应帧 |
| fidoControlPointLength | `f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb` | Read | 客户端读取 | 告知客户端单次写入上限 |
| fidoServiceRevisionBitfield | `f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb` | R/W | 读写 | 版本协商 |

### 5.3 FIDO 命令码

| 命令码 | 名称 | 说明 |
|--------|------|------|
| `0x80` | PING | 原样回显数据 |
| `0x82` | MSG | CTAP2 消息 |
| `0x83` | KEEPALIVE | 等待用户确认时的保活通知 |
| `0x84` | CANCEL | 取消当前操作 |
| `0x8F` | ERROR | 不支持的命令 |

**帧格式**:
- **初始帧**: `[CMD(1B, bit7=1)] [HLEN(1B)] [LLEN(1B)] [DATA]`
- **续帧**: `[SEQ(1B, bit7=0)] [DATA]`
- HLEN:LLEN 是整个帧的数据长度（大端），不是本分片的长度

---

## 6. CCCD 订阅与通知发送

### 6.1 CCCD 处理流程

```
fido_status_notify(connHandle, data, len)
  │
  ├─ GATTServApp_ReadCharCfg(connHandle, s_StatusCCCD)
  │   └─ 返回: GATT_CLIENT_CFG_NOTIFY (0x0001) 或 0
  │
  ├─ if (!(value & GATT_CLIENT_CFG_NOTIFY)):
  │   └─ PRINT("[FIDO] notify SKIP: not subscribed")
  │   └─ return bleIncorrectMode
  │
  ├─ GATT_bm_alloc() 分配通知缓冲
  ├─ tmos_memcpy(noti.pValue, data, len)
  ├─ GATT_Notification(connHandle, &noti, FALSE)
  │   └─ FALSE = 不需要客户端确认 (非请求模式)
  │
  └─ if (status != SUCCESS):
       └─ GATT_bm_free() 释放缓冲 (防止泄漏)
```

### 6.2 CCCD 状态管理

**连接建立时**:
- `fido_HandleConnStatusCB(GAP_LINK_TERMINATED_EVENT)`
- 重置 CCCD: `GATTServApp_InitCharCfg(connHandle, s_StatusCCCD)` → INVALID_CONNHANDLE

**订阅时**:
- `fido_WriteAttrCB` → `GATTServApp_ProcessCCCDWriteReq` → 写入 `GATT_CLIENT_CFG_NOTIFY`

**取消订阅时**:
- 客户端写入 `0x0000` → `FIDO_EVT_STATUS_NOTI_DISABLED`

### 6.3 通知发送限制

**关键**: `GATT_Notification` 的最大载荷 = `ATT_MTU - 3` (ATT 层头部)。

- MTU=23 时: 最大 20 字节/通知
- MTU=256 时: 最大 253 字节/通知

**分片发送**:
```
响应数据 > MTU-3 时:
  第1包: [CMD][HLEN][LLEN][DATA[0..N-1]]       // 初始帧
  第2包: [0x00][DATA[N..2N-1]]                  // 续帧 SEQ=0
  第3包: [0x01][DATA[2N..3N-1]]                 // 续帧 SEQ=1
  ...
```

---

## 7. 参数更新流程

### 7.1 参数更新请求

```
Peripheral_RequestParamUpdate()
  │
  ├─ if (connHandle == GAP_CONNHANDLE_INIT) return
  │
  ├─ PRINT("[BLE] request param update conn=%d")
  │
  └─ GAPRole_PeripheralConnParamUpdateReq(
         connHandle,
         DEFAULT_DESIRED_MIN_CONN_INTERVAL,    // 6  (7.5ms)
         DEFAULT_DESIRED_MAX_CONN_INTERVAL,    // 24  (30ms)
         DEFAULT_DESIRED_SLAVE_LATENCY,        // 0
         DEFAULT_DESIRED_CONN_TIMEOUT,         // 3000 (30s)
         Peripheral_TaskID
     )
```

### 7.2 参数更新完成

```
peripheralParamUpdateCB(connHandle, interval, latency, timeout)
  │
  ├─ if (connHandle == peripheralConnList.connHandle):
  │   ├─ 更新 peripheralConnList 参数
  │   └─ PRINT("[BLE] param update SUCCESS int=%d latency=%d timeout=%d")
  │
  └─ else:
       PRINT("[BLE] param update ERR: conn mismatch")
```

### 7.3 参数说明

| 参数 | 值 | 含义 | 单位 |
|------|------|------|------|
| Min Interval | 6 | 最小连接间隔 | 1.25ms → 7.5ms |
| Max Interval | 24 | 最大连接间隔 | 1.25ms → 30ms |
| Latency | 0 | 从机可跳过的连接事件数 | 个 |
| Timeout | 3000 | 监督超时 | 10ms → 30s |

**注意**: 最终参数由**客户端**决定，设备只是建议值。

---

## 8. 帧编解码与分片

### 8.1 接收流程 (客户端 → 设备)

```
ble_transport_on_write(connHandle, data, len)
  │
  ├─ if (s_ctap_pending):
  │   └─ if (CANCEL) → s_ctap_pending=0, ctap_abort_pending()
  │   └─ return (丢弃其他帧)
  │
  ├─ s_conn = connHandle
  │
  ├─ if (data[0] & 0x80):  // 初始帧
  │   ├─ cmd = data[0]
  │   ├─ total = (data[1]<<8) | data[2]   // 大端总长度
  │   ├─ if (total > FIDO_BLE_MAX_MSG) return
  │   ├─ rx_cmd = cmd, rx_total = total
  │   ├─ rx_len = 0, rx_seq = 0
  │   ├─ rx_active = 1
  │   └─ memcpy(rx_buf, data+3, len-3)
  │   └─ rx_len = len-3
  │
  └─ else:  // 续帧
       ├─ if (!rx_active || seq != rx_seq) → rx_active=0, return
       ├─ rx_seq++
       ├─ memcpy(rx_buf+rx_len, data+1, len-1)
       └─ rx_len += len-1
       
  if (rx_active && rx_len >= rx_total):
       rx_active = 0
       handle_frame()    // 完整帧到达，处理
```

### 8.2 发送流程 (设备 → 客户端)

```
send_frame(cmd, data, len)
  │
  ├─ tx_buf[0] = cmd
  ├─ tx_buf[1] = (len >> 8)   // HLEN
  ├─ tx_buf[2] = (len & 0xFF) // LLEN
  ├─ memcpy(tx_buf+3, data, len)
  ├─ tx_len = len + 3
  ├─ tx_offset = 0
  ├─ tx_seq = 0
  ├─ tx_active = 1
  └─ tx_cmd = cmd

ble_transport_pump()
  │
  ├─ if (!tx_active) return
  │
  ├─ if (tx_offset == 0):  // 初始帧
  │   ├─ n = min(tx_len, s_notify_max())
  │   ├─ fido_status_notify(conn, tx_buf, n)
  │   └─ tx_offset = n
  │
  └─ else:  // 续帧
       ├─ avail = tx_len - tx_offset
       ├─ n = min(s_notify_max()-1, avail)  // -1 for SEQ byte
       ├─ tx_buf[tx_offset + n] = tx_seq    // 写 SEQ
       ├─ fido_status_notify(conn, tx_buf+tx_offset-1, n+1)
       │   // 注意: SEQ 插在数据前面
       ├─ tx_offset += n
       └─ tx_seq++
```

---

## 9. 调试日志解读

### 9.1 正常流程日志示例

```
[BLE] link ESTABLISHED conn=1 timeout=3000
[BLE] transport conn set to 1
[BLE] started PERIODIC_EVT (1.6s)
[BLE] started READ_RSSI_EVT
Connected..
[FIDO] read  h=0x0014 method=0x04 (FIND_INFO_REQ)     ← 客户端发现描述符
[FIDO]   -> other 16-bit attr read (pass through)
[FIDO] read  h=0x0015 method=0x04 (FIND_INFO_REQ)
[FIDO]   -> other 16-bit attr read (pass through)
...
[FIDO] read  h=0x0026 method=0x08 (READ_BY_TYPE_REQ)   ← 发现特征
[FIDO] read  h=0x0028 method=0x08 (READ_BY_TYPE_REQ)
[FIDO] read  h=0x002A method=0x08 (READ_BY_TYPE_REQ)
mtu exchange: 256                                       ← MTU 协商
[FIDO] read  h=0x0026 method=0x04 (FIND_INFO_REQ)      ← 发现 CCCD
[FIDO]   -> len=2 cccd=00 00                            ← 初始 CCCD 值
[FIDO] read  h=0x0028 method=0x04 (FIND_INFO_REQ)
[FIDO] read  h=0x002A method=0x04 (FIND_INFO_REQ)
[FIDO] read  h=0x0026 method=0x08 (READ_BY_TYPE_REQ)
[FIDO] read  h=0x0028 method=0x08 (READ_BY_TYPE_REQ)
[FIDO] read  h=0x002A method=0x08 (READ_BY_TYPE_REQ)
[FIDO] read  h=0x0026 method=0x06 (READ_REQ)            ← 读 CCCD 当前值
[FIDO]   -> len=2 cccd=00 00
[FIDO] read  h=0x0026 method=0x02 (WRITE_REQ)            ← 写 CCCD 订阅
[BLE] request param update conn=1                       ← 参数更新触发
[BLE] param update SUCCESS int=18 latency=0 timeout=3000 ← 参数更新成功
Phy update Rx:2 Tx:2                                    ← PHY 更新
RSSI -68 dB Conn  1
[BLE] PING rx len=8 -> echo                             ← PING 请求
[BLE] MSG rx len=63 ctap_cmd=0x01                       ← MSG 请求 (MakeCredential)
[BLE] RX len=63 first=82 cmd=01
[BLE] MSG resp OK len=55                                ← MSG 响应成功
```

### 9.2 关键日志标识

| 日志关键字 | 含义 |
|-----------|------|
| `link ESTABLISHED` | 连接建立成功 |
| `transport conn set` | 传输层已记录连接句柄 |
| `started PERIODIC_EVT` | 周期事件已启动 |
| `mtu exchange: 256` | MTU 协商完成 |
| `cccd=00 00` → `cccd=01 00` | CCCD 从未订阅到已订阅 |
| `request param update` | 参数更新触发 |
| `param update SUCCESS` | 参数更新成功 |
| `PING rx len=X -> echo` | PING 请求收到并回显 |
| `MSG rx len=X ctap_cmd=0xXX` | CTAP2 命令收到 |
| `ctap pending (UP)` | CTAP 操作等待用户确认 |
| `MSG resp OK len=X` | CTAP2 响应成功发送 |
| `notify SKIP: not subscribed` | 通知被跳过 (CCCD 未订阅) |
| `link TERMINATED conn=X reason=0xXX` | 连接断开及原因码 |

### 9.3 异常日志解读

**Windows 客户端快速断开**:
```
[BLE] link ESTABLISHED conn=1
[BLE] transport conn set to 1
[BLE] started PERIODIC_EVT (1.6s)
[BLE] started READ_RSSI_EVT
Connected..
RSSI -65 dB Conn  1
[BLE] link TERMINATED conn=1 reason=0x13     ← 监督超时
Disconnected.. Reason:13
Advertising..
```
**分析**: 连接建立后无 GATT 操作日志 → 客户端在 GATT 发现前就断开了。可能原因:
- 客户端未识别 FIDO 服务 UUID
- 广播数据不完整
- 连接参数不兼容

**nRF Connect 10秒后断开**:
```
[FIDO] read  h=0x0026 method=0x02 (WRITE_REQ)  ← CCCD 订阅成功
[BLE] request param update conn=1
[BLE] param update SUCCESS
[BLE] PING rx len=8 -> echo
...
[BLE] link TERMINATED conn=1 reason=0x13        ← 约10秒后
```
**分析**: CCCD 订阅成功、PING 正常，但 10 秒后断开。可能原因:
- 客户端超时 (无更多 GATT 操作)
- 监督超时参数过短
- 需要检查客户端是否期望更多操作

---

## 10. 已知问题与排查

### 10.1 Windows BLE FIDO 快速断开 (0x13)

**现象**: Windows 连接后立即断开，无 GATT 操作日志。

**已实施修复**:
1. ✅ 参数更新推迟到 CCCD 订阅后
2. ✅ 连接间隔 max=30ms (原 250ms)
3. ✅ 监督超时=30s

**待排查**:
- Windows 是否能识别 FIDO GATT 服务 UUID
- 广播数据中 Service Data flags 是否正确
- 客户端是否要求加密连接

### 10.2 nRF Connect 10秒后断开

**现象**: CCCD 订阅成功、PING 正常，但约 10 秒后断开 (0x13)。

**分析**:
- 客户端完成基本 GATT 操作后等待用户输入
- 监督超时 30s 但实际约 10s 断开
- 可能是客户端自身超时机制

**建议**:
- 检查 nRF Connect 是否等待 MSG 输入
- 尝试发送 MSG 命令看是否响应
- 检查监督超时实际值

### 10.3 调试技巧

**1. 检查广播数据**:
```
nRF Connect → 扫描 → 查看 Advertised Data
应看到: FIDO 服务 UUID + Service Data
```

**2. 检查服务发现**:
```
查看日志中的 method 序列:
FIND_INFO_REQ → READ_BY_GRP_TYPE_REQ → READ_BY_TYPE_REQ
→ MTU_Exchange → READ/WRITE CCCD
```

**3. 检查 CCCD 状态**:
```
读 CCCD (method=0x06):
  cccd=00 00 → 未订阅
  cccd=01 00 → 已订阅通知
```

**4. 检查参数更新**:
```
请求后应看到:
[BLE] request param update conn=X
[BLE] param update SUCCESS int=Y latency=Z timeout=T
```

---

## 附录 A: 配置常量

| 常量 | 值 | 含义 |
|------|-----|------|
| `DEFAULT_ADVERTISING_INTERVAL` | 80 (50ms) | 广播间隔 |
| `DEFAULT_DESIRED_MIN_CONN_INTERVAL` | 6 (7.5ms) | 最小连接间隔 |
| `DEFAULT_DESIRED_MAX_CONN_INTERVAL` | 24 (30ms) | 最大连接间隔 |
| `DEFAULT_DESIRED_SLAVE_LATENCY` | 0 | 从机跳过次数 |
| `DEFAULT_DESIRED_CONN_TIMEOUT` | 3000 (30s) | 监督超时 |
| `PAIRING_HOLD_MS` | 5000 (200调试) | 长按进入配对模式 |
| `PAIRING_WINDOW_MS` | 120000 (120s) | 配对模式窗口 |
| `SBP_PERIODIC_EVT_PERIOD` | 1600 (1.6s) | 周期事件间隔 |
| `SBP_READ_RSSI_EVT_PERIOD` | 3200 (3.2s) | RSSI 采样间隔 |
| `FIDO_BLE_MAX_MSG` | 512 | 最大消息长度 |
| `FIDO_BLE_DEFAULT_MTU` | 23 | 默认 MTU |

## 附录 B: 规范引用

| 规范 | 引用 |
|------|------|
| FIDO U2F BT Protocol v1.1 | §5 (帧格式), §11 (传输层), §12 (GATT 服务), §13 (CCCD) |
| CTAP 2.1 Specification | §11.4 (BLE 传输), §11.4.5 (服务清单), §11.4.7 (广播), §11.4.13 (配对模式) |
| ITU-T X.1278.2 | §13.4 (BLE FIDO) |
| BLE Core Spec v5.3 | ATT, GATT, GAP 规范 |

---

*文档版本: 1.0*
*最后更新: 2025-01-XX*
*基于代码版本: CH583 FIDO2 BLE Transport Phase 3*
