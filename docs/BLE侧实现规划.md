# BLE 侧 CTAP2 传输实现规划

> 状态：**规划**（尚未开始实现）
> 对应《详细软件开发计划》3.7「BLE CTAP 传输」
> 规范依据：FIDO U2F BT Protocol v1.1 §5/§11、ITU-T X.1278.2 §13.4（CTAP2 over BLE）
> 三个决策点的详细分析见《[BLE侧实现分析](BLE侧实现分析.md)》

---

## 1. 目标与范围

### 目标

让设备通过 **BLE** 提供与 USB 侧**等价的 CTAP2 能力**，使支持 BLE 安全密钥的客户端
（Android Chrome、Windows 的 BLE FIDO 栈等）能够完成注册与登录。

### 范围

**做**：

- FIDO GATT 服务的完整实现（服务与 5 个特征）
- FIDO BLE 传输层的帧解析、分片与重组
- 复用现有 `ctap.c` 的 CTAP2 命令处理（**这是关键收益**）
- UP 挂起与 KEEPALIVE 在 BLE 上的对应实现

**不做**（本期）：

- U2F 相关的 APDU 编码（`fidoServiceRevisionBitfield` 只声明 FIDO2）
- caBLE / hybrid transport（CTAP 2.2，那是另一套截然不同的机制）
- 配对管理的 UI（沿用 BLE 栈默认行为）

### 前置条件

- USB 侧已完成并验证（**已达成**，见计划 5.2.1）
- 现有 `ctap.c` / `auth_sm.c` / `secure_store.c` 可原样复用（**需确认一处耦合，见 §4.3**）

---

## 2. 规范要点

### 2.1 GATT 服务与特征

设备作为 **GATT Server**，客户端为 GATT Client。

| 项 | UUID | 属性 | 说明 |
|---|---|---|---|
| **FIDO Service** | `0000fffd-0000-1000-8000-00805f9b34fb` | Primary | 服务本体 |
| `fidoControlPoint` | `f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb` | **Write** | 客户端写入请求 |
| `fidoStatus` | `f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb` | **Notify** | 设备回送响应 |
| `fidoControlPointLength` | `f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb` | Read | 单次写入上限（20~512 字节） |
| `fidoServiceRevision` | `00002a28-0000-1000-8000-00805f9b34fb` | Read | 固定 `0x0100`（U2F 1.1）与 `0x0120`（FIDO2） |
| `fidoServiceRevisionBitfield` | `f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb` | Read/Write | 位域选择协议版本 |

**版本选择**：`fidoServiceRevisionBitfield` 的位定义 —— **bit5 = FIDO2**、bit6 = U2F 1.2、
bit7 = U2F 1.1。**纯 CTAP2 设备写入单字节 `0x20`**。客户端在发命令前写入单 bit 值
选定版本；本实现只接受 `0x20`，其余返回错误。

**另需实现**：Device Information Service（已存在，见 `devinfoservice.c`）与
GAP 服务，并在广播中包含 FIDO 服务 UUID。

### 2.2 帧格式

请求与响应结构对称，**所有多字节字段为大端**。

**请求（客户端 → 设备）**

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 1 | `CMD` | 命令码 |
| 1 | 1 | `HLEN` | 数据长度高字节 |
| 2 | 1 | `LLEN` | 数据长度低字节 |
| 3 | S | `DATA` | 载荷，S = 长度 |

**响应（设备 → 客户端）**

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 1 | `STAT` | **等于请求的 CMD 表示成功**；`0xBF` 表示封装层错误 |
| 1 | 1 | `HLEN` | |
| 2 | 1 | `LLEN` | |
| 3 | S | `DATA` | |

**命令码**

| 命令 | 值 | 方向 | 说明 |
|---|---|---|---|
| `PING` | `0x81` | 请求/响应 | 回显，用于测连通与最大长度 |
| `KEEPALIVE` | `0x82` | **仅设备 → 客户端** | 忙时每 500ms 上报 |
| `MSG` | `0x83` | 请求/响应 | **载荷即 CTAP2 的 CBOR 命令/响应** |
| `CANCEL` | `0xBE` | 请求 | 取消未完成的操作，**设备不回应它本身** |
| `ERROR` | `0xBF` | 响应 | 封装层错误，`DATA` 为大端错误码 |

**注意**：所有命令码的 bit7 均为 1 —— 这**同时是初始帧的标志**（见下）。

**`KEEPALIVE` 的载荷**是单字节状态：`0x01` = PROCESSING、`0x02` = **UP_NEEDED**。

**时间常量**：`kMaxCommandTransmitDelayMillis` = 1500ms、
`kErrorWaitMillis` = 2000ms、**`kKeepAliveMillis` = 500ms**。

### 2.3 分片

单个 ATT 载荷放不下时需要分片，规则与 CTAPHID **完全不同**：

| | 初始帧 | 续帧 |
|---|---|---|
| 第 0 字节 | `CMD`（**bit7 = 1**） | `SEQ`（**bit7 = 0**） |
| 第 1 字节 | `HLEN` | `DATA` |
| 第 2 字节 | `LLEN` | `DATA` |
| 其余 | `DATA` | `DATA` |

**关键规则**：

1. **初始帧由首字节 bit7 = 1 标识**（这正是 PING/KEEPALIVE/MSG/CANCEL/ERROR
   的值都 ≥ `0x80` 的原因）。
2. `HLEN:LLEN` 是**整个帧的总长度**（大端），**不是本分片的长度**。
3. 续帧从 `SEQ = 0x00` 开始递增，到 `0x7f` 后回绕到 `0`。
4. `maxLen` 受 `fidoControlPointLength` 与协商的 ATT MTU 约束；
   `fidoStatus` 通知受 `ATT_MTU - 3` 限制。

**规范示例**（40 字节 PING 数据，`maxLen` = 20）：
```
[81 00 28][17 字节数据]
[00][19 字节数据]
[01][4 字节数据]
```

**单一 CTAPHID 与 BLE 分片的关键差异**：

| | CTAPHID（USB） | FIDO BLE |
|---|---|---|
| 通道 | 4 字节 `CID` | **无**（每连接一个） |
| 长度字段 | 初始帧 2 字节，**表示总长** | 2 字节，**也是总长** |
| 续帧首字节 | `SEQ \| 0x80` | `SEQ`（**无 0x80**） |
| 命令语义 | `CTAPHID_CBOR = 0x10` | `MSG = 0x83` |
| CBOR 前缀 | 需 1 字节 CTAP 状态码 | **无**（`MSG` 的载荷直接是响应 CBOR） |

---

## 3. 架构设计

### 3.1 分层

现有的传输分层是清晰的，BLE 应作为**并列的第二个传输层**接入，而非改造 `ctaphid.c`：

```
               ┌──────────────────────────────┐
   USB HID ───▶│  ctaphid.c                   │
               │  （CTAPHID 分片/重组/通道）   │
               └──────────────┬───────────────┘
                              │
               ┌──────────────▼───────────────┐
   BLE GATT ──▶│  ble_transport.c   （新增）  │
               │  （FIDO BLE 帧/分片/重组）    │
               └──────────────┬───────────────┘
                              │
               ┌──────────────▼───────────────┐
               │  ctap.c  （CTAP2 核心）       │  ← 原样复用
               │  ctap_handle_cbor(...)        │
               └──────────────┬───────────────┘
                              │
               ┌──────────────▼───────────────┐
               │ auth_sm.c / secure_store.c    │  ← 原样复用
               └──────────────────────────────┘
```

**复用点**：`ctap.c` 的对外接口是

```c
uint8_t ctap_handle_cbor(uint8_t cmd, const uint8_t *param, uint16_t param_len,
                         uint8_t *resp, uint16_t resp_max, uint16_t *resp_len);
```

它**不认识任何传输层**，正好可以直接被 BLE 调用。这是当初分层设计的收益。

### 3.2 新增文件

| 文件 | 职责 |
|---|---|
| `include/fido_service.h` / `src/fido_service.c` | FIDO GATT 服务：属性表、5 个特征、读写回调 |
| `include/ble_transport.h` / `src/ble_transport.c` | FIDO BLE 帧编解码、分片与重组、KEEPALIVE 上报 |

**`fido_service.c` 参考 `gattprofile.c` 的结构**（`gattAttribute_t` 数组 +
`ReadAttrCB`/`WriteAttrCB`），但**改用 128-bit UUID**——
注意现有 `ble_usb_service.c` 用的是 16-bit UUID（`ATT_BT_UUID_SIZE`），
FIDO 的长 UUID 必须用 `ATT_UUID_SIZE`（16 字节），并确认 WCH 栈对该长度的支持。

### 3.3 与现有 BLE 代码的关系

`peripheral.c` 的 `Peripheral_Init()` 当前注册了：

```c
GGS_AddService(GATT_ALL_SERVICES);           // GAP      -> 保留
GATTServApp_AddService(GATT_ALL_SERVICES);   // GATT     -> 保留
SimpleProfile_AddService(GATT_ALL_SERVICES); // WCH 例程 -> 可移除
ble_usb_add_service(ble_usb_ServiceEvt);     // BLE↔USB 透传 -> 应移除
```

**处理方式**：

- `SimpleProfile_AddService`：WCH 示例服务，与 FIDO 无关。**可移除**，
  但先确认无其他引用（`peripheral.c` 里可能有 `SimpleProfile_SetParameter` 调用）。
- `ble_usb_add_service`：**BLE→USB 透传，在 FIDO2 双模下语义是错的**（BLE 侧的 CTAP
  应由设备自己处理）。代码里已断开调用路径，本次实现新服务后**应整体删除**。
- **设备信息服务（DIS）保留**——BLE 规范要求实现它。

---

## 4. 关键设计决策

### 4.1 并发：USB 与 BLE 同时连接

设备是双模的，**USB 与 BLE 可能同时连接**。需要明确策略，否则 UP 状态机会互相干扰。

**问题场景**：USB 侧有一个请求在等 UP，此时 BLE 侧也发来请求——两者都在等同一个按键。

**建议策略（待确认）**：

- **允许同时服务，但 UP 等待串行化**：`auth_sm` 本身是单一状态机，
  第二个请求进入时会发现 `AUTH_WAIT_ACTIVE` 已在等待，此时应返回 `PENDING`
  并**由各自传输层保留报文**（当前的 CTAPHID 重放机制正是如此）。
- **按键只消一次，两个请求都会被满足**：语义上可以接受（用户在场是全局事实）。
- **或者更严格**：BLE 有连接时拒绝/降级 USB（或反之）——**不建议**，
  会带来难以解释的行为。

**这一条需要在实现前明确**，因为它影响 `auth_sm` 是否要改成多个等待者。

### 4.2 KEEPALIVE：两套不同的机制

| | USB（CTAPHID） | BLE |
|---|---|---|
| 命令码 | `CTAPHID_KEEPALIVE = 0x3B` | `KEEPALIVE = 0x82` |
| 触发时机 | 等待 UP 期间 | 操作耗时期间 |
| 载荷 | 单字节状态（`0x02` = UPNEEDED） | 单字节状态（`0x02` = UP_NEEDED） |
| 周期 | 500ms | 500ms |

**结论**：语义相同但**帧与命令码不同**，因此 KEEPALIVE 必须由**各传输层**上报，
不能放在 `ctap.c` 里。`ctap.c` 只需继续提供「是否有挂起操作」的查询
（现有 `ctaphid_ctap_is_pending()` 就是这类接口）。

### 4.3 需要确认的耦合点

**`ctaphid.c` 里的 `s_ctap_pending` / `s_pend_cid` / UP 重放逻辑目前与 USB 传输绑在一起。**

BLE 需要同样的机制（挂起时保留报文，取得 UP 后重跑命令）。两种做法：

- **A（推荐）**：在 BLE 传输层实现一份等价的挂起/重放逻辑。相同模式的代码重复一次，
  但两个传输层互不影响，`ctaphid.c` 无需改动。
- **B**：把挂起状态与重放**上移到 `ctap.c`**，传输层只负责「取一帧 / 送一帧」。
  更干净，但要改动已验证的 USB 路径，**有回归风险**。

**建议先用 A**（不动已验证的代码），若后续发现重复过多再考虑 B。

### 4.4 广播与配对

- 广播中需包含 **FIDO 服务 UUID**（128-bit），部分客户端靠它筛选设备。
- 配对与加密（LTK）沿用 BLE 栈行为。**规范建议设备只自动接受已配对过的客户端**。
- 规范推荐使用可解析私有地址（RPA）以保护隐私——WCH 栈是否支持需确认。

---

## 5. 分阶段实施

### 阶段 1：GATT 服务骨架

- [ ] 实现 `fido_service.c`：服务与 5 个特征的属性表（**128-bit UUID**）
- [ ] 实现 `fidoServiceRevision` / `fidoServiceRevisionBitfield` 的读写
- [ ] 实现 `fidoControlPointLength`（先写死为协商值，如 512）
- [ ] 在 `Peripheral_Init()` 注册新服务，移除 `ble_usb_service`
- [ ] **验收**：用 BLE 调试 App（如 nRF Connect）能发现 FIDO 服务并读到 5 个特征

### 阶段 2：帧层与 PING

- [ ] `ble_transport.c`：帧编解码（`CMD/HLEN/LLEN/DATA`）
- [ ] 分片重组（初始帧 bit7、续帧 SEQ 回绕）
- [ ] `fidoControlPoint` 写入 → 交由传输层解析
- [ ] 实现 `PING`（回显）——**这是最简单可验证的命令**
- [ ] 通过 `fidoStatus` 通知回送响应（注意 `ATT_MTU - 3` 上限，需分片）
- [ ] **验收**：BLE 调试工具发 40 字节 PING（`maxLen` = 20 时产生 3 个分片），
      能收到完整回显

### 阶段 3：接入 CTAP2

- [ ] `MSG` 帧 → 剥离 3 字节头 → `ctap_handle_cbor()`
- [ ] 响应：**直接是 CTAP CBOR**（注意：**没有** CTAPHID 那样的 1 字节状态码前缀，
      但它本身就是 `ctap_handle_cbor` 的返回码 + CBOR，需按 BLE 规范组织）
- [ ] 版本协商：只接受 `fidoServiceRevisionBitfield = 0x20`
- [ ] **验收**：能完成 `GetInfo`

### 阶段 4：UP 与 KEEPALIVE

- [ ] BLE 传输层的挂起/重放逻辑（见 §4.3 方案 A）
- [ ] 等待 UP 期间每 500ms 上报 `KEEPALIVE(0x02)`
- [ ] 处理 `CANCEL`（`0xBE`）：取消挂起操作，**且不回应 CANCEL 本身**
- [ ] **验收**：注册/登录时 LED 慢闪、按键生效；`CANCEL` 能中断等待

### 阶段 5：真机验证

- [ ] Android Chrome（BLE 安全密钥）
- [ ] Windows（若系统的 BLE FIDO 栈可用）
- [ ] 双模共存：USB 与 BLE 同时连接时的行为（按 §4.1 的决策验证）

---

## 6. 风险与未决问题

| 项 | 风险 | 说明 |
|---|---|---|
| **128-bit UUID** | 中 | WCH 栈的属性表示例都用 16-bit UUID。需确认 `ATT_UUID_SIZE` 路径可用，否则要自己拼属性表 |
| **通知的 MTU 限制** | 中 | `fidoStatus` 受 `ATT_MTU - 3` 限制，长响应（如 MakeCredential 的 178 字节）必然要多帧通知。需确认 WCH 栈的通知分片能力 |
| **UP 并发语义** | **高** | §4.1 未决：USB/BLE 同时等待同一次按键的策略。**实现前必须明确** |
| **`ctaphid.c` 耦合** | 中 | §4.3 的 A/B 方案选择。选 B 会触碰已验证的 USB 路径 |
| **蓝牙配对体验** | 低 | 规范建议只用已配对连接；WCH 栈的配对行为需实测 |
| **BLE 栈资源占用** | 低 | RAM 已占 79.0%，新增服务与缓冲需要评估 |

### 需要明确的决策（实现前）

> **详细分析见《[BLE侧实现分析](BLE侧实现分析.md)》**，那里给出了每个问题的
> 备选方案、取舍与推荐，并额外发现了一个更根本的架构问题（`ctap.c` 对
> `ctaphid.c` 的反向依赖，建议作为"阶段 0"先解决）。


1. **USB 与 BLE 同时连接时的 UP 策略**（§4.1）
2. **挂起/重放放在传输层还是上移**（§4.3）
3. **`ble_usb_service` 是删除还是保留**（建议删除）

---

## 7. 参考

- FIDO U2F BT Protocol v1.1 — §5（帧格式）、§11（分片）、§12（GATT 服务）
- ITU-T X.1278.2（CTAP2 over BLE 的规范转写）— §13.4
- Chromium `device/fido/cable/fido_ble_uuids.cc` — UUID 与常量的实现参考
- 本项目《详细软件开发计划》3.7、5.2.1（USB 侧已有实现，可作分层参照）


---

## 实施进度

### 阶段 0：拆分 `ctap_pending_poll()` —— 已完成

**目的**：解除 `ctap.c`（协议核心）对 `ctaphid.c`（USB 传输层）的反向依赖。

| 文件 | 改动 |
|---|---|
| `src/ctap.c` | 删除 `ctap_pending_poll()`；只保留被动的 `ctap_abort_pending()` |
| `include/ctap.h` | 删除对应声明 |
| `src/ctaphid.c` | 新增 `ctaphid_pending_poll()`、`s_need_abort_up` 标志；`ctaphid_reset()` 置标志 |
| `include/ctaphid.h` | 声明新函数 |
| `src/peripheral_main.c` | 主循环改用 `ctaphid_pending_poll()` |

**设计改进**：原方案打算在 `ctap.c` 保留一个 `ctap_reap_dangling_up()` 处理
"USB 复位后 UP 悬空"。实际实现改为**由传输层自己消化**——`ctaphid_reset()`
（中断上下文）只置标志，由 `ctaphid_pending_poll()`（主循环上下文）消费后调
`ctap_abort_pending()`。这样 `ctap.c` 完全不需知道传输层，BLE 侧照做即可。

**验证**：编译通过、零警告；`fido2_cred_test.py` 全部 PASS（用户实测确认无回归）。

### 阶段 0.5：验证 SDK 对 128-bit UUID 的支持 —— 已完成

SDK 头文件位于项目内 `lib/BLE_LIB/CH58xBLE_LIB.h`（不在 platformio 包目录）。

| 检查项 | 结果 |
|---|---|
| 属性的 128-bit UUID | 支持：`attAttrType_t.len` 可为 2 或 16，`uuid[]` 为 `ATT_UUID_SIZE`(16) |
| 广播中的 128-bit UUID | 支持：`GAP_ADTYPE_128BIT_COMPLETE = 0x07` |
| 广播包空间 | 够用：Flags(3) + UUID128(18) + UUID16(4) = 25 ≤ `B_MAX_ADV_LEN`(31) |

**结论**：原计划无需调整。

### 阶段 1：FIDO GATT 服务骨架 —— 代码完成，待真机验证

**新增文件**：

| 文件 | 内容 |
|---|---|
| `include/fido_service.h` | 对外接口：`fido_add_service` / `fido_status_notify` / 版本位查询 |
| `src/fido_service.c` | 12 项属性表（服务 + 5 个特征）、读写回调、通知发送 |

**改动**：

- `src/peripheral.c`：注册 `fido_add_service(NULL)`（阶段 1 不接传输层，回调传 NULL）；
  广播数据加入 FIDO 服务 UUID
- `SimpleProfile` 与 `ble_usb_*` **暂时保留**（按《BLE侧实现分析》§3 的建议，
  留作"蓝牙连接本身是否正常"的参照物）

**实现要点**：

- **128-bit UUID 的字节序**：按 4-2-2-2-6 分段，前四段反序、最后 6 字节保持。
  这个规则容易出错，已用脚本逐一核对 5 个 UUID 的字节序列。
  **过程中确实发现并修正了一处错误**（Service UUID 的第 8-9 字节写反）。
- **属性表下标**：每个特征占 Declaration + Value（`fidoStatus` 另有 CCCD），
  共 12 项。写回调按 handle 反查，下标定义已修正（初版数错导致越界警告）。
- **版本协商**：`fidoServiceRevisionBitfield` 只接受 `0x20`（FIDO2 单 bit），
  其余返回 `ATT_ERR_UNLIKELY`。

**资源占用**：`Flash 35.4%`（+1116 字节）、**`RAM 79.9%`（+276 字节，已接近 80%）**。

**验收方式**（需真机）：

1. 烧录后用 **nRF Connect**（或同类 BLE 调试 App）扫描
2. 应能看到广播里含 **FIDO 服务 UUID `0xFFFD`**
3. 连接后应能发现 **5 个特征**：
   `fidoControlPoint`(Write) / `fidoStatus`(Notify) / `fidoControlPointLength`(Read) /
   `fidoServiceRevision`(Read) / `fidoServiceRevisionBitfield`(Read+Write)
4. 读 `fidoControlPointLength` 应得 `512`（小端 `00 02`）
5. 读 `fidoServiceRevisionBitfield` 应得 `0x20`；写入非 `0x20` 的值应被拒绝
6. **同时确认 `SimpleProfile` 等既有服务仍在**（确保没有破坏原有 BLE 行为）

**下一步（阶段 2）**：`ble_transport.c` 的帧编解码与 `PING` 回显。


---

# 实施结果（阶段 0~4 全部完成）

> 本节为实际实现后的总结。规范分析与设计取舍见前述章节。

## 完成情况

| 阶段 | 内容 | 状态 |
|---|---|---|
| 0 | 拆分 `ctap_pending_poll()`，解除 `ctap.c` → `ctaphid.c` 反向依赖 | 完成 |
| 0.5 | 验证 SDK 支持 128-bit UUID（属性 + 广播） | 完成 |
| 1 | FIDO GATT 服务骨架 | 完成 |
| 2 | 帧编解码 + 分片 + `PING` 回显 | 完成 |
| 3 | 接入 `ctap.c`（`MSG` 帧 → CTAP2） | 完成 |
| 4 | UP 挂起 + KEEPALIVE + CANCEL | 完成 |

## 新增文件

| 文件 | 说明 |
|---|---|
| `include/fido_service.h` / `src/fido_service.c` | FIDO GATT 服务（4 个特征） |
| `include/ble_transport.h` / `src/ble_transport.c` | FIDO BLE 帧编解码、分片、发送调度 |

## 服务结构（最终）

只提供现行规范要求的 4 个特征：

| 特征 | UUID | 属性 |
|---|---|---|
| `fidoControlPoint` | `f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb` | Write |
| `fidoStatus` | `f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb` | Notify |
| `fidoControlPointLength` | `f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb` | Read |
| `fidoServiceRevisionBitfield` | `f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb` | Read/Write（`0x20`） |

**不提供 `fidoServiceRevision`（`0x2A28`）** —— 该特征已被取代，同时提供新旧两者会让部分客户端判定设备不合规。

## 实机验证（nRF Connect 手工测试）

| 项 | 结果 |
|---|---|
| 服务与特征发现 | 通过（UUID、属性正确） |
| `PING` 单帧回显（10 字节） | 通过 |
| `PING` 多帧（40 字节，分 3 帧） | 通过 |
| `MSG` → `GetInfo` | 通过（响应与 USB 侧内容一致） |
| `MSG` → `MakeCredential` | 通过（走到 UP 闸门） |
| UP 挂起 + KEEPALIVE（`0x82`） | 通过 |
| CANCEL（`0xBE`） | 通过 |
| BLE 配对 | 通过（`pair state` 0→1→3） |

**最有说服力的一次**：Windows 的 FIDO 栈完整发起了 `MakeCredential`——

```
[FIDO] write handle=0x003A len=68              ← 客户端写入 68 字节请求
[BLE RX] len=68 first=83: 83 00 41 01 A5 ...   ← 收到完整 CTAP 请求
ctap: cmd=0x01 param=64                        ← CTAP 层处理
[CTAP] mc parsed: cdh=1 rp=1 user=1 es256=1    ← 参数解析完整
auth: wait UP (15000 ms)                       ← 进入 UP 等待
```

**这说明帧解析、分片、CTAP 复用、UP 闸门全部工作**。

## 实现过程中修掉的问题

| 问题 | 现象 | 修复 |
|---|---|---|
| **128-bit UUID 字节序** | nRF 显示的服务 UUID 完全颠倒 | WCH 栈用**整体反序**，非 BLE 规范的分段反序 |
| **特征值缺长度** | `fidoControlPointLength` 读出空值 | `gattAttribute_t` 无长度字段，须在回调里设 `*pLen` |
| **`ble_transport_pump()` 未调用** | 响应只入队不发送 | 加入主循环 |
| **通知长度超限** | 长响应静默失败 | 通知上限是 `ATT_MTU - 3`，不能按 `MTU` 算 |
| **`send_frame()` 丢载荷** | 长响应只发出第一帧的内容 | 改为把整帧放入缓冲，由 pump 分片 |
| **通知失败未释放缓冲** | 首次失败后内存池耗尽，后续全败 | `GATT_Notification` 失败时调 `GATT_bm_free` |
| **`FFF3` 返回值不真实** | 声明 512 而实际只收 20 | 改为返回真实的 `MTU - 3` |
| **`BLE_BUFF_MAX_LEN` 默认 27** | `ATT_MTU` 恒为 23，请求被切得很碎 | 改为 100 → MTU 96 |
| **`MakeCredential` 自检耗时** | `make_key 1719ms + sign 1807ms + verify 2022ms` | 去掉自检（`attStmt` 为空，签名结果本就没用）→ 1.75s |

## 遗留问题：客户端集成

**设备侧实现完整，但主流客户端的接入受阻。**

| 客户端 | 现象 |
|---|---|
| **Android（Chrome/Edge）** | 能配对、设备出现在列表，但卡在 Google Play Services 的"按住按键 5 秒"提示 |
| **Windows（Edge）** | 曾完整发起过 `MakeCredential`；后改为"连上、读特征后放弃"，不再发请求 |

**排查过的方向**：配对方式（Just Works / MITM）、绑定残留（双向清理）、MTU、废弃特征、广播内容。**均非根因。**

**行业背景**（来自资料检索）：经典 BLE GATT FIDO **本身长期不可靠** —— Google 的 OpenSK 以 USB HID 为主、Chrome 曾在 Mac/ChromeOS 移除 BLE 支持、业界已转向 **caBLE（hybrid transport）**。开发者社区也记录了 Android/iOS 的 BLE 配对问题。

**因此这不是本实现特有的缺陷**，而是该技术方向的普遍困难。

## 调研过的方向：BLE HID —— **已排除，不可行**

**曾考虑的思路**：把已在 USB 侧跑通的 CTAPHID 协议搬到蓝牙 HID（HOGP）上——
HID 报告 64 字节与 CTAPHID 帧长度正好一致，`ctaphid.c`/`ctap.c` 可原样复用。

**当时的可行性检查全部通过**：

| 检查项 | 结果 |
|---|---|
| WCH 栈支持 HOGP | 是（`HID_SERV_UUID = 0x1812`，SDK 自带 4 个 HID 例程） |
| 报告描述符可否自定义 | 可以（应用层普通数组） |
| 报告长度能否 64 字节 | 可以 |

**但进一步调研后确认这条路从规范上就不成立**：

> **"CTAP2 over HID" refers specifically to USB HID, the wired transport — not Bluetooth.**
> **CTAP2's Bluetooth transport uses BLE with a FIDO-specific GATT service (a restricted UUID), not HID/HOGP.**
> **HOGP is a different, unrelated Bluetooth profile.**

**FIDO 规范里 CTAP2 只有三种传输**：**USB HID**、**NFC**、**BLE + FIDO GATT 服务**。
**蓝牙 HID（HOGP）从来不是 FIDO 的传输方式**，客户端也不会通过它去发现认证器。

**旁证**：`webauthn-authenticator-rs` 的后端列表是
`usb` / `bluetooth`（btleplug，即 GATT）/ `nfc` / `cable` —— **没有 HID**。

**结论**：本项目的 GATT 实现（`0xFFFD` + 4 个特征）**就是规范要求的做法，也是唯一可行的做法**。
BLE HID 方向**不应实现**。

> ⚠️ 这一节曾把 BLE HID 标为"若不继续调 GATT 则首选的方向"——
> 那是在只验证了"技术可行性"、未验证"客户端是否认"的情况下做出的判断，**现已纠正**。

---

## 客户端兼容性的根因（调研补充）

设备侧实现正确，但两个平台的接入均受阻。**调研发现这两者都有明确的外部原因**：

### Android：系统层面的显式限制

> **Android restricts access to FIDO-related BLE GATT service UUIDs (via `isFidoSrvcUuid`),
> which blocks third-party apps from managing BLE security keys.**

**即：Android 系统主动限制了第三方对 FIDO GATT 服务的访问。** 这解释了为什么设备能被扫描到、
能配对，却在 Play Services 那一步卡住（"按住按键 5 秒"提示后无后续）。

### Windows：Windows Hello 对蓝牙密钥支持不完善

Mozilla 工程师的实测记录：

> **"As far as I can tell Windows Hello does not support Bluetooth security keys
> (when I try to add a security key it asks to insert it in the USB port)."**
> — Bugzilla 1768622

以及 FIDO Dev 邮件列表（2025-07）的报告：**Windows 11 的 BLE 密钥管理
（设置 → 账户 → 登录选项 → 安全密钥 → 管理）出现过回归并崩溃**，微软方面已确认该回归。

### 行业现状

- **Chrome 的 BLE 认证器支持在 2020 年前后被移除**（Mac / ChromeOS）；
  其他平台交给系统 API。Chrome 官方工程师范畴内的表述是"**decided not to ship**"
- **OpenSK**（Google 的 FIDO2 实现）**以 USB HID 为主**，BLE 需要额外挂一个服务
- 业界已转向 **caBLE / hybrid transport**（二维码 + BLE 接近，密码学载荷走加密隧道）
- 社区共识：经典 CTAP over BLE "**quite unreliable and has a poor user experience**"

**因此本项目遇到的不是实现缺陷，而是该技术方向在主流平台上"规范有、实现弱"的整体状态。**

---

## 可行的验证途径（若将来有条件）

| 途径 | 说明 |
|---|---|
| **Linux + `fido2ble`** | 用 [PoneBiometrics/fido2ble](https://github.com/PoneBiometrics/fido2ble) 把 BLE FIDO 设备桥接成 USB HID——**绕过 Windows/Android 的平台限制，最干净** |
| **旧版 Android（8~10）** | 在系统限制收紧之前可能可用 |
| **FIDO Conformance Tool** | 按规范测试，不依赖操作系统 |
| **Android + 系统级 FIDO 管理界面** | 而非浏览器发起 |

> `fido2ble` 的实现已核对：它使用的 **UUID（4 个，无 `0x2A28`）、命令码、
> 分片逻辑与本项目完全一致**——这从另一个角度印证了设备侧实现的正确性。

---

## 保留的配置

```ini
; platformio.ini —— 真实修复，非临时
-D BLE_BUFF_MAX_LEN=100     ; ATT_MTU: 23 -> 96
```

**临时诊断均已清理**（`BLE_TRANSPORT_DUMP`、`BLE_ERASE_BONDS_ON_BOOT` 及各处 `PRINT`）。

---

# 调试过程与最终结论（2026-02 续）

> 本节记录"让浏览器真正用起来"这一阶段的完整调试。结论是：
> **设备侧完整且正确，两个主流平台的客户端都无法完成经典 BLE FIDO 流程。**

## 一、决定性验证：脚本化 GATT 客户端

浏览器路径反复失败后，改用 **`tools/ble_gatt_client.py`**（基于 `bleak`）——
**直接作为标准 GATT 客户端**按 CTAP 2.1 §11.4.6 的规范流程操作设备，
**绕开浏览器/系统的 FIDO 集成层**。

### 结果：六项全部通过

```
[1] 特征发现        ✓ fidoControlPoint(write) fidoStatus(notify)
                      fidoControlPointLength(read) fidoServiceRevisionBitfield(read,write)
[2] 版本位          ✓ 读 0x20 -> 写 0x20 -> 回读 0x20
[3] CPLength        ✓ 253（FD 00）
[4] 订阅通知        ✓
[5] PING            ✓ 回显正确
[6] GetInfo         ✓ CTAP 状态成功，CBOR 完整（含 FIDO_2_0 声明）
```

**这一步的意义**：**同一固件、同一个 Windows 系统**，

| 路径 | 结果 |
|---|---|
| **`bleak` → winrt → Windows BLE 栈** | **✅ 六步全通** |
| **浏览器 → Windows WebAuthn（Windows Hello）→ BLE** | **❌ 读特征后放弃** |

**所以 BLE 适配层没有问题，问题在 WebAuthn 层。**

**其中 [2] 是首次验证**：此前没有任何客户端写过 `fidoServiceRevisionBitfield`，
设备日志确认写入路径正常（`[FIDO] write h=0x0028 len=1 method=0x12`）。

## 二、两个平台的实测行为

### Windows（PC 网页）

```
新配对时  -> 读 fidoControlPointLength -> 读 fidoServiceRevisionBitfield -> 停止
已绑定时  -> 什么都不读（连特征都不访问）
```

**从不订阅通知、从不写请求。** 与 Mozilla 工程师的实测记录一致：

> **"As far as I can tell Windows Hello does not support Bluetooth security keys
> (when I try to add a security key it asks to insert it in the USB port)."**
> — Bugzilla 1768622

**Windows 能识别 BLE 认证器，但没有能力完成完整交互。**

### Android

```
读 fidoControlPointLength -> 停止
```

**比 Windows 更早退出，且从不读版本位。**

**结论**：经典 CTAP over BLE 在桌面/移动端都处于"规范有、实现弱"的状态 ——
Chrome 自带实现已于 2020 年移除、OpenSK 以 USB 为主、业界转向 caBLE。
**这是平台侧的限制，不是本项目的实现缺陷。**

## 三、这个阶段修掉的真实缺陷

**虽然它们都不是平台受阻的原因，但每一个都是真问题：**

| # | 缺陷 | 症状 | 修复 |
|---|---|---|---|
| 1 | **`peripheralMTU` 声明为 `uint8_t`** | MTU > 255 时溢出为 0，`ble_transport_set_mtu()` 直接返回 | 改为 **`uint16_t`** |
| 2 | **`fidoControlPointLength` 停留在初始值 20** | 上面第 1 条的直接后果（23-3） | 随上条修复，现返回 **253** |
| 3 | **ATT_MTU 仅 96（CPLength 93）** | 装不下 `MakeCredential` 请求（100~200 字节） | `BLE_BUFF_MAX_LEN` 100 → **260**（MTU 256）|
| 4 | **配对成功即退出配对模式** | 广播的 Service Data bit7 立刻清零，客户端认为设备不可用 | **只在窗口超时/重启时退出** |
| 5 | **缺少 Service Data 配对模式标志** | 规范 §11.4.7 明确要求（平台不读 AD Flags 的 Discoverable 位）| 在**扫描响应**中加入 `16 FD FF <flags>` |
| 6 | **配对级别超出设备能力** | 声称 Security Mode 1 Level 3（`mitm=TRUE`）却无 `passcodeCB` | 降为 **Level 2**（`mitm=FALSE` + `NO_INPUT_NO_OUTPUT`）|
| 7 | **连接监督超时仅 6 秒** | 调试/交互时频繁断连 | 600 → **3000**（30 秒）|
| 8 | **连接间隔上限 250ms** | 每次特征读写要等一个连接事件，累积成数秒 | 200 → **24**（30ms）|
| 9 | **128-bit 属性读取未设 `*pLen`** | 读 `fidoControlPoint`/`fidoStatus` 会拿到未初始化的长度 | 明确返回 `ATT_ERR_READ_NOT_PERMITTED` |
| 10 | **多余的 GATT 服务** | 保留 WCH 示例的 `SimpleProfile` 与已废弃的 `ble_usb_service` | **移除**（规范只要求 GAP + DIS + FIDO）|
| 11 | **DIS 值是占位文本** | 字面就是 `"Model Number"` 等 | 改为真实值（`CH583-FIDO2` / `1.0.0` / `SecureKey`）|

### 调试中排除的假设

| 假设 | 依据 | 结果 |
|---|---|---|
| 配对模式标志（Service Data）| 客户端在配对后立刻停止 | 改善但非根因 |
| 连接参数太慢 | `Update 1 - Int c0`（240ms）| **否** |
| CPLength 值太小 | 客户端读完它就停 | **否**（253 仍停）|
| 特征在属性表中的顺序 | 客户端按 handle 遍历 | **否** |
| 绑定记录不一致 | `reason=0x3D`（MIC Failure）| 新配对后改善，但仍停 |

## 四、`tools/ble_gatt_client.py`

**保留为验证工具**（不属于固件构建）。用途：

```bash
pip install bleak
# 长按 PB4 满 5 秒进入配对模式，然后：
python tools/ble_gatt_client.py --scan   # 只扫描，看广播与 Service Data
python tools/ble_gatt_client.py          # 完整流程（[1]~[8]）
```

**它能做的事**：

- **按规范顺序验证 4 个特征**（UUID、属性）
- **验证版本位读写**
- **验证订阅通知 + PING + GetInfo**
- **验证 MakeCredential / GetAssertion**（需按住 PB4 提供 UP）
- **分片收发与设备侧实现对齐**（初始帧 `MTU-3`、续帧 `MTU-4`）

**它是本项目"设备侧是否可用"的判定工具** —— 当浏览器表现异常时，
先用它排除设备侧。

## 五、最终状态

**设备侧（BLE 传输层）**：

- **GATT 服务、帧编解码、分片收发、UP 挂起、KEEPALIVE、CANCEL** —— 全部实现并验证
- **CTAP2 逻辑层与 USB 侧共用**（`ctap.c` 未改动）
- **nRF Connect 手工测试 + `bleak` 脚本测试均通过**

**客户端侧**：

- **Windows（WebAuthn）与 Android 都无法完成经典 BLE FIDO 流程**
- **原因在平台，非实现**（调研依据见本文档前文"客户端兼容性的根因"）

**后续若要在真实客户端上验证**，可行路径仍是：

| 途径 | 说明 |
|---|---|
| **Linux + `fido2ble`** | 把 BLE FIDO 桥接成 USB HID，绕开平台限制 |
| **FIDO Conformance Tool** | 按规范测试，不依赖操作系统 |
| **继续用 `ble_gatt_client.py`** | 设备侧回归测试 |
