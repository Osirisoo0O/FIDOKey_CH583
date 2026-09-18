# BLE 频繁连接/断开问题分析

> 分析时间：2026-09-18
> 现象：连接建立后立即断开，断开原因 `0x13`

---

## 断开原因 `0x13` 的含义

在 WCH BLE 栈中，`0x13` (19 decimal) 对应 **`0x13 = 连接超时`** (Connection Timeout)。

具体对应 BLE 规范中的 `0x08` (Link Timeout) 或栈内自定义的超时码。关键证据：

```
peripheral.c:
  DEFAULT_DESIRED_CONN_TIMEOUT = 3000  // 30 秒 (10ms 单位)
  
  但客户端侧（Windows BLE FIDO）可能在参数更新完成前就超时断开
```

---

## 问题 1：参数更新请求过早发送（核心问题）

### 时序分析

```
T=0     连接建立 (Peripheral_LinkEstablished)
T+6.4s  发送参数更新请求 (SBP_PARAM_UPDATE_EVT, 延迟 6400 ticks ≈ 6.4s)
T+?     参数更新完成回调 (peripheralParamUpdateCB)
```

**问题**：参数更新请求在连接建立后 **6.4 秒**才发送。Windows BLE FIDO 栈的典型行为：

1. 连接建立后立即开始 GATT 发现
2. GATT 发现完成后（通常 1-2 秒内）发送 CCCD 订阅
3. 等待设备响应（通常超时 5-10 秒）
4. 如果超时未收到响应，断开连接

**关键代码**：

```c
// peripheral.c:776
tmos_start_task(Peripheral_TaskID, SBP_PARAM_UPDATE_EVT, SBP_PARAM_UPDATE_DELAY); // 6400

// peripheral.c:636-646
if(events & SBP_PARAM_UPDATE_EVT)
{
    GAPRole_PeripheralConnParamUpdateReq(peripheralConnList.connHandle,
                                         DEFAULT_DESIRED_MIN_CONN_INTERVAL,   // 6 (7.5ms)
                                         DEFAULT_DESIRED_MAX_CONN_INTERVAL,   // 24 (30ms)
                                         DEFAULT_DESIRED_SLAVE_LATENCY,       // 0
                                         DEFAULT_DESIRED_CONN_TIMEOUT,        // 3000 (30s)
                                         Peripheral_TaskID);
}
```

**请求的参数**：
- 最小间隔：6 × 1.25ms = **7.5ms**
- 最大间隔：24 × 1.25ms = **30ms**
- 从默认间隔（通常 50-75ms）降到 7.5ms，变化较大

**Windows 行为**：Windows BLE GATT 客户端在参数更新期间（通常 3-5 秒）可能暂停 GATT 操作，如果参数更新超时或失败，可能导致 GATT 发现未完成，最终断开。

---

## 问题 2：CCCD 订阅与首次通知的竞态

### 时序分析

```
T=0     连接建立
T+1s    客户端 GATT 发现完成
T+1.1s  客户端发送 CCCD 订阅 (WRITE_REQ)
T+?     设备响应 WRITE_CFM
T+?     设备发送首次通知 (fidoStatus)
```

**关键代码**：

```c
// fido_service.c:277-290
bStatus_t fido_status_notify(uint16_t connHandle, const uint8_t *p_data, uint16_t len)
{
    value = GATTServApp_ReadCharCfg(connHandle, s_StatusCCCD);
    if(!(value & GATT_CLIENT_CFG_NOTIFY))
    {
        PRINT("[FIDO] notify SKIP: not subscribed (cccd=0x%04X)", value);
        return bleIncorrectMode;
    }
    // ... 发送通知
}
```

**问题**：
1. `s_StatusCCCD` 初始化为 `INVALID_CONNHANDLE`（零）
2. 如果设备在客户端订阅前发送了首次通知，会被跳过
3. 客户端可能等待超时后断开

**但更关键的是**：如果 `ble_transport.c` 在连接建立后立即尝试发送通知（如 PING 响应），而客户端尚未完成 GATT 发现和 CCCD 订阅，会导致：
- 通知被跳过
- 客户端等待超时
- 断开连接

---

## 问题 3：连接断开时 CCCD 重置

### 代码分析

```c
// fido_service.c:505-513
static void fido_HandleConnStatusCB(uint16_t connHandle, uint8_t changeType)
{
    if(connHandle != LOOPBACK_CONNHANDLE)
    {
        if((changeType == LINKDB_STATUS_UPDATE_REMOVED) ||
           ((changeType == LINKDB_STATUS_UPDATE_STATEFLAGS) && (!linkDB_Up(connHandle))))
        {
            GATTServApp_InitCharCfg(connHandle, s_StatusCCCD);  // 重置 CCCD
        }
    }
}
```

**行为**：每次连接断开，CCCD 被重置为零。这是**正确的**行为（每个连接独立订阅状态）。

**但问题**：如果断开-重连周期过快（如 Windows 自动重试），新连接建立后客户端需要重新发送 CCCD 订阅。如果设备在订阅前超时断开，形成死循环。

---

## 问题 4：参数更新失败后的行为

### 代码分析

```c
// peripheral.c:851-880
static void peripheralParamUpdateCB(uint16_t connHandle, uint16_t connInterval,
                                    uint16_t connSlaveLatency, uint16_t connTimeout)
{
    if(connHandle == peripheralConnList.connHandle)
    {
        // 更新成功
        PRINT("Update %x - Int %x \n", connHandle, connInterval);
    }
    else
    {
        PRINT("ERR..\n");
    }
}
```

**问题**：参数更新回调**没有处理失败情况**。如果参数更新请求发送后，客户端拒绝或超时：
- 栈内部可能断开连接
- 设备端没有明确的失败处理
- 日志中只显示 `reason=0x13`

---

## 综合时序图

```
设备端                          Windows BLE FIDO 客户端
  |                                    |
  |<--- 广播发现 --->|                 |
  |                                    |
  |<--- 连接建立 --->|                 | T=0
  | [connHandle=1, timeout=30s]        |
  | [启动参数更新定时器 6.4s]          |
  |                                    |
  |          |<--- GATT 发现 --->|     | T+0.5s
  |          |<--- 服务发现 --->|      |
  |          |<--- 特征发现 --->|      |
  |          |<--- CCCD 订阅 --->|     | T+1s
  | [CCCD 写入回调: FIDO_EVT_STATUS_NOTI_ENABLED]
  |          |--- WRITE_CFM --->|     |
  |                                    |
  |          |<--- GetInfo --->|      | T+1.5s
  |          |--- NOTIFY (响应) --->|  |
  |                                    |
  |          |<--- 等待 PING/MSG --->| |
  |                                    |
  |--- 参数更新请求 --->|              | T+6.4s
  |          |--- 参数更新响应 --->|    |
  |                                    |
  |          |--- 超时断开 --->|       | T+10s (假设)
  |<--- reason=0x13 ---|               |
  |                                    |
  |--- 重启广播 ---|                    |
  |                                    |
  |<--- 重试连接 --->|                 |
```

**关键窗口**：连接建立后 **1-5 秒**是 GATT 发现和 CCCD 订阅的关键窗口。如果设备在此期间：
1. 发送了未订阅的通知 → 被跳过
2. 参数更新请求发送 → 客户端暂停 GATT 操作
3. 客户端超时未收到响应 → 断开连接

---

## 解决方案

### 方案 A：延迟参数更新（推荐）

将参数更新请求推迟到**首次 FIDO 交互完成后**发送，避免干扰 GATT 发现。

```c
// peripheral.c:776
// 原代码：
tmos_start_task(Peripheral_TaskID, SBP_PARAM_UPDATE_EVT, SBP_PARAM_UPDATE_DELAY); // 6.4s

// 改为：
// 不在连接建立时启动参数更新定时器
// 在 FIDO_EVT_STATUS_NOTI_ENABLED 回调中启动（客户端完成订阅后）
```

在 `fido_service.c` 的 CCCD 启用回调中启动参数更新：

```c
// fido_service.c: s_appCBs 回调中
case FIDO_EVT_STATUS_NOTI_ENABLED:
    // 客户端已订阅 fidoStatus，GATT 发现完成
    // 此时发送参数更新请求是安全的
    tmos_start_task(Peripheral_TaskID, SBP_PARAM_UPDATE_EVT, 100); // 延迟 1s
    break;
```

### 方案 B：降低参数更新幅度

使用更温和的连接参数，减少 Windows 客户端的超时风险。

```c
// peripheral.c
#define DEFAULT_DESIRED_MIN_CONN_INTERVAL    12  // 15ms (原 6 = 7.5ms)
#define DEFAULT_DESIRED_MAX_CONN_INTERVAL    30  // 37.5ms (原 24 = 30ms)
```

### 方案 C：添加参数更新失败重试

```c
// peripheral.c: peripheralParamUpdateCB
static void peripheralParamUpdateCB(uint16_t connHandle, ...)
{
    if(connHandle == peripheralConnList.connHandle)
    {
        PRINT("Update %x - Int %x \n", connHandle, connInterval);
        // 更新成功，可启动 PHY 更新或其他操作
    }
    else
    {
        // 连接已断开，参数更新失败
        PRINT("Update ERR: conn closed\n");
    }
}
```

### 方案 D：验证 CCCD 订阅后再发送通知

确保 `ble_transport.c` 在发送首次通知前，客户端已完成 CCCD 订阅。

```c
// ble_transport.c
if(fido_status_notify_is_ready(connHandle))
{
    fido_status_notify(connHandle, data, len);
}
```

---

## 推荐实施顺序

1. **方案 A**（延迟参数更新）— 最可能解决问题
2. **方案 B**（降低参数幅度）— 作为备选
3. **方案 D**（验证 CCCD）— 防御性改进
4. **方案 C**（失败处理）— 可观测性改进

---

## 调试建议

### 添加日志

```c
// peripheral.c: Peripheral_LinkEstablished
PRINT("[BLE] conn ESTABLISHED: start param update in 6.4s\n");

// peripheral.c: peripheralParamUpdateCB
PRINT("[BLE] param update SUCCESS: int=%d latency=%d timeout=%d\n",
      connInterval, connSlaveLatency, connTimeout);

// fido_service.c: fido_WriteAttrCB (CCCD 写入)
PRINT("[FIDO] CCCD subscribed: conn=%u cccd=0x%04X\n",
      connHandle, BUILD_UINT16(pValue[0], pValue[1]));
```

### 使用 nRF 协议分析仪

1. 安装 nRF Sniffer for Bluetooth LE
2. 配置 Wireshark 捕获 BLE 数据包
3. 观察：
   - GATT 发现时序
   - CCCD 订阅时机
   - 参数更新请求/响应
   - 断开原因码

### 使用手机 App 测试

1. 安装 nRF Connect App
2. 连接设备
3. 观察：
   - GATT 服务是否完整发现
   - CCCD 订阅是否成功
   - 通知是否正常发送

---

## 总结

**根本原因**：参数更新请求在连接建立后 6.4 秒发送，与 Windows BLE FIDO 客户端的 GATT 发现/CCCD 订阅时序冲突，导致客户端超时断开。

**核心修复**：将参数更新推迟到客户端完成 GATT 发现和 CCCD 订阅后（`FIDO_EVT_STATUS_NOTI_ENABLED` 回调中）。

**辅助修复**：降低参数更新幅度，添加失败处理日志。
