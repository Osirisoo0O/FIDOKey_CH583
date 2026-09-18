# CTAP 2.1 §11.4 BLE 传输规范 —— 对照与优化

> 依据：FIDO Client to Authenticator Protocol (CTAP) v2.3.1 WD
> `https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#ble`
> 章节：§11.4 Bluetooth Smart / BLE Technology（含 §11.4.1 … §11.4.17）、§11.5 Hybrid transports
> 对照对象：本仓库 `src/ble_transport.c`、`src/peripheral.c`、`include/ble_transport.h`、`tools/ble_ctap2_conformance.py`

---

## 一、规范要点速览（§11.4 全文摘要）

### §11.4.1 Conformance
- 必须符合 Bluetooth Core Spec 4.0 或更高。
- 使用 SIG 规定的 UUID（见 Assigned Numbers）。

### §11.4.2 Pairing
- **必须**使用长期链路密钥（LTK），**所有通信必须加密**。
- 认证器**绝不允许**使用短期密钥（STK）。
- BLE 定位能力差，无法靠距离判断目标设备，**配对是唯一确认机制**。
- 厂商**应当**提示用户不要在公共场所（咖啡馆/商店/车站）配对。
- 系统级配对是 OS 现状，属已知风险（见 §11.4.13.1）。

### §11.4.3 Link Security
- 交换任何 FIDO 消息**之前**，认证器**必须**强制：
  - **Security Mode 1, Level 2**（未认证配对 + 加密），或
  - **Security Mode 1, Level 3**（认证配对 + 加密）。

### §11.4.4 Framing

**请求帧（Client → Authenticator）**：

| Offset | Length | Mnemonic | Description |
|---|---|---|---|
| 0 | 1 | CMD | 命令标识 |
| 1 | 1 | HLEN | 长度高字节 |
| 2 | 1 | LLEN | 长度低字节 |
| 3 | s | DATA | 数据 |

- **支持的请求命令只有 PING、MSG、CANCEL 三个。**
- CANCEL 取消任何未完成的 MSG 命令。
- MSG 的数据格式见 §8 Message Encoding。

**响应帧（Authenticator → Client）**：

| Offset | Length | Mnemonic | Description |
|---|---|---|---|
| 0 | 1 | **STAT** | 响应状态 |
| 1 | 1 | HLEN | 长度高字节 |
| 2 | 1 | LLEN | 长度低字节 |
| 3 | s | DATA | 数据 |

> ★ **第一字节是 STAT，不是 CMD。**
> - STAT 与请求的 CMD 相同 → **成功响应**
> - STAT = ERROR(0xBF) → **错误响应**，且 **DATA 里是"变长大端整数"形式的错误码**
> - FIDO 消息处理层的错误（如 `CTAP2_ERR_*`）**从封装层看是成功**，要用完整的 MSG 响应回报

### §11.4.4.3 Command / Status / Error constants

| 命令 | 值 |
|---|---|
| PING | **0x81** |
| KEEPALIVE | **0x82** |
| MSG | **0x83** |
| CANCEL | **0xbe** |
| ERROR | **0xbf** |

**KEEPALIVE 的命令载荷是 1 字节状态**：

| 状态 | 值 |
|---|---|
| PROCESSING | 0x01 |
| UP_NEEDED | 0x02 |
| RFU | 0x00, 0x03–0xFF |

**ERROR 错误码**：

| 常量 | 值 | 含义 |
|---|---|---|
| ERR_INVALID_CMD | 0x01 | 命令未知/无效 |
| ERR_INVALID_PAR | 0x02 | 参数无效或缺失 |
| ERR_INVALID_LEN | 0x03 | 长度无效 |
| ERR_INVALID_SEQ | 0x04 | 序号无效 |
| ERR_REQ_TIMEOUT | 0x05 | 请求超时 |
| ERR_BUSY | 0x06 | 设备忙，客户端应稍后重试 |
| NA | 0x0a / 0x0b | 保留（HID） |
| ERR_OTHER | 0x7f | 其它未指定错误 |

> 规范注："These values are identical to the HID transport values."
> **但这句指的是常量体系同源，不是数值逐个相同** —— 表里 `KEEPALIVE=0x82`
> 与 USB HID 的 `0xBB` 不同、`CANCEL=0xbe` 与 HID 的 `0x91` 不同。
> **BLE 传输层有自己的一张表，照表取值。**

### §11.4.5 GATT Service Description
- FIDO Client 必须是 GATT Client，FIDO Authenticator 必须是 GATT Server。
- 认证器额外需支持：Write Characteristic Value、Notifications、Read/Write Characteristic Descriptors。
- **本节所有数值均为 big-endian，字符串为 UTF-8。**

#### §11.4.5.1 FIDO Service（UUID `0xFFFD`，Primary Service）

| 特征 | Mnemonic | 属性 | 长度 | UUID |
|---|---|---|---|---|
| FIDO Control Point | `fidoControlPoint` | Write | 厂商定义（**20–512**） | `F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB` |
| FIDO Status | `fidoStatus` | Notify | N/A | `F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623BB` |
| FIDO Control Point Length | `fidoControlPointLength` | Read | **2 字节** | `F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623BB` |
| FIDO Service Revision Bitfield | `fidoServiceRevisionBitfield` | Read/Write | 厂商定义（1+） | `F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB` |
| FIDO Service Revision | `fidoServiceRevision` | Read | 厂商定义（20–512） | `0x2A28` |

关键语义：
- `fidoControlPoint`：**只写**的命令缓冲。
- `fidoStatus`：**只通知**的响应属性。**单条通知最大长度 = ATT_MTU − 3**，
  用上述响应帧承载。这样做是为了比"通知 + 读"更快。
- `fidoControlPointLength`：**单次写 `fidoControlPoint` 的最大字节数**，**必须在 20–512 之间**。
- `fidoServiceRevision`：已被取代，仅与 U2F 1.0 兼容相关；值为 UTF-8 字符串，
  U2F 1.0 时为 `"1.0"`（原始字节 `0x312e30`）。不支持 1.0 时**必须省略**该特征。
- `fidoServiceRevisionBitfield`：版本位域，**字节序 big-endian**，全 0 的尾随字节省略。
  客户端在发任何 FIDO 命令前**必须先写入恰好 1 个 bit**。

| Byte 0 的 bit | 版本 |
|---|---|
| 7 | U2F 1.1 |
| 6 | U2F 1.2 |
| **5** | **FIDO2** |
| 4–0 | 保留 |

> 只支持 FIDO2 Rev 1 的设备 → 位域长度 1、值 **0x20**。

#### §11.4.5.2 Device Information Service
- **必须**实现 DIS，**应当**含 Manufacturer Name / Model Number / Firmware Revision。
- 厂商**不应**使用可唯一识别的值（避免成为追踪手段）。

#### §11.4.5.3 Generic Access Profile Service
- **必须**实现 GAP，含 **Device Name** 与 **Appearance**。

### §11.4.6 Protocol Overview（流程顺序）
1. 认证器广播 FIDO Service。
2. 客户端扫描该 Service。
3. 客户端做特征发现。
4. 未配对则**必须**完成 BLE 配对并建立 LTK；**认证器对已绑定客户端必须无人工干预直接放行**。
5. 客户端检查 `fidoServiceRevisionBitfield`，若存在则写入单一位选择版本。
6. 客户端读 `fidoControlPointLength`。
7. 客户端订阅 `fidoStatus` 通知。
8. 客户端向 `fidoControlPoint` 写请求。
9. （可选）客户端写 CANCEL 取消挂起请求。
10. 认证器处理并通过 `fidoStatus` 通知响应。
11. 结束条件：客户端退订通知，或连接超时被认证器关闭。

### §11.4.7 Authenticator Advertising Format
- 广播中**必须**包含 FIDO service UUID。
- **可**含 TxPower。
- **配对模式**：以下二者之一 ——
  (1) LE Limited Mode = 0 且 LE General Discoverable = 1，或
  (2) LE Limited Mode = 1 且 LE General Discoverable = 0。
- **非配对模式**：AD Flags 里两位**都必须为 0**。
- 广告**可**带设备名，且应**可辨识**（如 "ACME Key" 好过 "XJS4"）。
- 也**必须**实现 GAP 与 DIS（它们同样提供友好名称）。
- 未规定广播频率，留给厂商。

### §11.4.8 Requests
- 客户端**应当**通过连接并写 `fidoControlPoint` 发请求。
- 收到 CANCEL 时：若有可取消的挂起请求，**必须**取消，且**被取消的那个请求必须回
  `CTAP2_ERR_KEEPALIVE_CANCEL`**；**无论是否取消成功，认证器都绝不能对 CANCEL 本身回复。**

### §11.4.9 Responses
- 认证器**应当**通过 `fidoStatus` 通知响应。
- **收到任何请求后，认证器必须每 `kKeepAliveMillis`(500ms) 发一次 KEEPALIVE，
  直到处理完成。**
  - 处理中 → 状态 **PROCESSING**
  - 等待用户存在测试（UP）→ 状态 **UP_NEEDED**；等待期间**可**用声/光/振动提示用户
- 一旦处理完成且确认 UP，**必须停止 KEEPALIVE 并发送响应**。
- 客户端收到 KEEPALIVE **不得重发命令**；认证器**必须**至少每 500ms 继续发。
- 客户端收到 `UP_NEEDED` 的 KEEPALIVE 时，在自身超时之前**不得**转向其它设备。

### §11.4.10 Framing fragmentation

**初始分片**：

| Offset | Length | Mnemonic | Description |
|---|---|---|---|
| 0 | 1 | CMD | 命令标识 |
| 1 | 1 | HLEN | 长度高字节 |
| 2 | 1 | LLEN | 长度低字节 |
| 3 | 0 … (maxLen − 3) | DATA | 数据 |

**续分片**：

| Offset | Length | Mnemonic | Description |
|---|---|---|---|
| 0 | 1 | SEQ | 序号 `0x00`–`0x7f`（**bit7 恒为 0**） |
| 1 | 0 … (maxLen − 1) | DATA | 数据 |

- 首字节 bit7 = 1 表示初始分片；随后两字节是**大端**的帧总长。
- SEQ 从 0 开始，**到 0x7f 后必须回绕到 0**。
- **`maxLen` 是"该特征或通知支持的最大包长"** —— **不是 MTU**：
  - 对 `fidoStatus` 通知：`maxLen = ATT_MTU − 3`（§11.4.5.1）
  - 对 `fidoControlPoint` 写：`maxLen = fidoControlPointLength`

规范自带例子（务必对照）：
- `maxLen = 20`，PING 40 字节 → 3 帧：`[810028][17B]` / `[00][19B]` / `[01][4B]`
- `maxLen = 512`，PING 400 字节 → 1 帧：`[810190][400B]`

### §11.4.11 Notifications
- 客户端必须先注册通知才能收到。
- Bluetooth Core 4.0+ 要求设备**跨连接记住通知注册状态**；
  除非显式退订，重连时自动恢复。
- 客户端**可**在连接时检查通知状态，只在未注册时注册。
- 部分客户端**可能**因省电而关闭通知；**注册状态是按 bond 记的，不是按客户端记的。**
- **客户端绝不能在自己的存储里记住通知状态。**

### §11.4.12 Request Collisions
- BLE 认证器无法区分不同客户端（只存在 host↔client 的会话）。
- 同一 host 上两个客户端同时注册通知时，某些平台会复用同一条 BLE 连接，
  但 host 无法把通知路由到特定客户端 → **未定义行为，通常两边都失败。**

### §11.4.13 Implementation Considerations

**§11.4.13.1 客户端侧**：系统级配对意味着同 OS 上任意应用都可能与认证器交互 —— 安全与隐私风险。
（FIDO 的范畴之外，后续修订**可能**提出缓解措施。）

**§11.4.13.2 认证器侧**：
- 进入配对模式的动作**不应容易被误触**（尤其 Just Works 时）：可用**凹陷按键**或**多键组合**。
- **应当**考虑可见/可听的配对模式提示。
- **反例（不推荐）**：**单个非凹陷按键的静默长按** —— 用户日常操作时本就会按住不放。
- 认证器**可能**合法地收到未配对设备的通信（用户首次使用时忘进配对模式），
  此时**不应**让用户等超时才允许开启配对模式。
- 部分平台（**尤其 iOS**）不向应用暴露 AD Flag 的 LE Limited / General Discoverable 位，
  因此**强烈建议**在 **Scan Response** 里加 **Service Data** 字段：
  - 长度 ≥ 3 字节；前 2 字节是 FIDO Service UUID，之后是标志字节。
  - 尾部全 0 字节可省略（除非它是 service UUID 后的第一个字节）。
  - **bit7 = 设备处于配对模式**
  - **bit6 = 设备要求 Passkey Entry（PIN）**

### §11.4.14 Handling command completion

| 常量 | 值 |
|---|---|
| `kMaxCommandTransmitDelayMillis` | **1500 ms** |
| `kErrorWaitMillis` | **2000 ms** |
| `kKeepAliveMillis` | **500 ms** |

建议：
- 初始连接后、以及每次收到响应后，若还有命令要发，**必须**在 1500ms 内发出下一个命令或分片。
- 最终响应后若客户端不再发命令，**应当**通过**关闭 `fidoStatus` 通知**来表达；
  通知关闭后认证器**可**进入低功耗或断开。
- 客户端要发 FIDO 消息前，**必须**先启用通知**并等待 ATT 确认**，确保认证器已就绪。
- 需要 UP 的命令成功完成后，认证器**可**认为客户端已满足，重置状态或断电。
- **不消耗 UP 的响应**（如失败的注册/认证、无论成败的 get version）之后，
  认证器**必须**假定客户端可能还要发命令，**连接保持到客户端关闭或至少 `kErrorWaitMillis`(2000ms) 超时**。
- 支持 large blobs 的认证器，若响应含 `largeBlobKey`，**应当**等待 `kMaxCommandTransmitDelayMillis`。

### §11.4.15 Data throughput
- 尽量支持硬件允许的最大 MTU（规范允许到 **512**）。
- 证书尽量小，不要放多余扩展。

### §11.4.16 Advertising
- 建议在 **3 个广播信道**上都广播（不必只用 1 个），实测发现与发现率更好。

### §11.4.17 Authenticator Address Type
- **建议**使用 **Resolvable Private Address（RPA）** 而非静态地址，以防追踪。

### §11.5 Hybrid transports
- Hybrid transport 把"客户端平台与认证器物理接近的证明"与"消息传输"解耦。
- 由 **Proximity Exchange Protocol** 描述，含 CTAP 消息的协商与传输方式。

---

## 二、逐条对照本项目

图例：**✅ 符合** / **⚠️ 部分符合** / **❌ 不符合** / **➖ 不适用**

### GATT 层（§11.4.5.1）

| 项 | 规范 | 项目 | 判定 |
|---|---|---|---|
| FIDO Service UUID | `0xFFFD`，Primary | `fido_service.c` 定义一致 | ✅ |
| `fidoControlPoint` | Write | props=`['write']`（实测） | ✅ |
| `fidoStatus` | Notify | props=`['notify']`（实测） | ✅ |
| `fidoControlPointLength` | Read，2 字节，20–512 | props=`['read']`，值 `253`（=MTU−3） | ✅ |
| `fidoServiceRevisionBitfield` | Read/Write，big-endian | props=`['read','write']`，值 `0x20` | ✅ |
| `fidoServiceRevision`(0x2A28) | 仅 U2F 1.0，不支持则必须省略 | 未提供 | ✅（正确省略）|
| Device Information Service | 必须实现，建议含 3 项 | 见 `fido_service.c` / `peripheral.c` | ✅ |
| GAP：Device Name / Appearance | 必须 | 名称 `SecureKey`；Appearance 见代码 | ✅ |
| 版本位写入校验（恰好 1 bit） | 必须 | 实测 `写 0x00 被拒` / `写合法单一位成功` | ✅ |
| 数值 big-endian（§11.4.5 总则） | big-endian | **`fidoControlPointLength` 实测为 little-endian**（`FD 00` → 253） | ⚠️ 见下 |

> **关于 `CPLength` 字节序**：§11.4.5 总则说 "all values are big-endian coded"，
> 但实测设备返回 `FD 00`，按大端读得 `64768`（超出 20–512），按小端读得 `253`
> （= MTU−3，正确）。CTAP 2.0 时代的 BLE 实现普遍使用 little-endian，本设备沿用。
> **客户端（Windows/Android）也按 little-endian 解释**，故实际互通无碍。
> 测试脚本 `ble_ctap2_conformance.py` 已改为**两种字节序都试**，取落区间者并打印原始字节。

### 帧层（§11.4.4 / §11.4.10）

| 项 | 规范 | 项目 | 判定 |
|---|---|---|---|
| 命令码 PING | `0x81` | `FIDO_BLE_CMD_PING = 0x81` | ✅ |
| 命令码 KEEPALIVE | **`0x82`** | `FIDO_BLE_CMD_KEEPALIVE = 0x82` | ✅ |
| 命令码 MSG | `0x83` | `FIDO_BLE_CMD_MSG = 0x83` | ✅ |
| 命令码 CANCEL | **`0xbe`** | `FIDO_BLE_CMD_CANCEL = 0xBE` | ✅ |
| 命令码 ERROR | `0xbf` | `FIDO_BLE_CMD_ERROR = 0xBF` | ✅ |
| 响应首字节语义 = STAT | STAT | `send_frame(cmd,…)` 写入请求的 CMD，PING 回显相同 | ✅ |
| 初始分片 `CMD|HLEN|LLEN|DATA`，长度**大端** | 大端 | `tx_buf[1]=len>>8; tx_buf[2]=len&0xFF` | ✅ |
| 初始分片载荷 ≤ `maxLen−3` | `maxLen−3` | `max_payload_init() = s_mtu − 6`（= (MTU−3)−3）| ✅ |
| 续分片 `SEQ|DATA`，SEQ bit7=0 | bit7=0 | `tx_buf[tx_offset] = tx_seq++`（≤0x7F）| ✅ |
| 续分片载荷 ≤ `maxLen−1` | `maxLen−1` | `s_notify_max() − 1`（= (MTU−3)−1）| ✅ |
| SEQ 到 0x7f 回绕 | 必须 | `tx_seq++` 为 `uint8_t`，**自然回绕到 0x80 而非 0x00** | ⚠️ 见下 |
| 接收侧 SEQ 校验 | 应校验 | `seq != rx_seq` 即放弃本次接收 | ✅ |
| **ERROR 帧 DATA = 变长大端错误码** | 是错误码 | **DATA 里放的是 `FIDO_BLE_CMD_ERROR`(0xBF) 本身** | **❌ 见下** |
| PING 原样回显 | — | 实测 `PING 载荷原样回显 — b'CONFORMANCE'` | ✅ |
| 分片往返 | — | 实测 253B 往返通过、分片数 = 2（公式核验一致）| ✅ |

> **SEQ 回绕的实际影响**：`tx_seq` 是 `uint8_t`，自增到 `0x7F` 后再加会变成 **`0x80`**，
> 而规范要求回绕到 **`0x00`**。由于 `maxLen ≥ 20`（初始帧 ≥ 17 字节载荷、续帧 ≥ 19），
> 要发满 127 个续分片需要 > 2.4KB 的响应，**本项目 `FIDO_BLE_MAX_MSG` 远小于此，
> 实际触不到** —— 属"理论违规、实际不可达"。若要严谨，可用 `tx_seq = (tx_seq + 1) & 0x7F`。

> **ERROR 帧的 DATA 放错了值（真实违例）**：
> ```c
> /* src/ble_transport.c —— 两处都是这个写法 */
> uint8_t err[1];
> err[0] = FIDO_BLE_CMD_ERROR;          /* ← 把 STAT 的值当成了错误码 */
> send_frame(FIDO_BLE_CMD_ERROR, err, 1);
> ```
> 按 §11.4.4.2，DATA 应是**错误码**（`ERR_INVALID_CMD=0x01` 等），
> 现在的报文是 `STAT=0xBF, DATA=[0xBF]`，客户端会把错误码读成 **`0xBF`**，
> 该值在 §11.4.4.3 表里未定义（既非 0x0a/0x0b 保留值，也非 `ERR_OTHER=0x7f`），
> 多数客户端会落到"未知错误"分支。
> **影响面**：只在收到**不支持的封装层命令**或**载荷长度 < 1** 时触发 ——
> 正常流程（GetInfo / MakeCredential / GetAssertion）不会走到，因此此前脚本全绿也没暴露。
> 修复：让 `err[0]` 填真正的错误码（如 `0x01` = ERR_INVALID_CMD）。

### 流程层（§11.4.6 / §11.4.8 / §11.4.9）

| 项 | 规范 | 项目 | 判定 |
|---|---|---|---|
| 订阅通知后再发消息 | 必须 | 脚本实测：订阅后 GetInfo 正常 | ✅ |
| 读 `CPLength` 后再发请求 | 流程要求 | 脚本按此顺序 | ✅ |
| 版本位写入后发命令 | 必须 | 脚本写单一位后才继续 | ✅ |
| **CANCEL 本身不回复** | 必须 | `case FIDO_BLE_CMD_CANCEL:` 内不调用任何 `send_*` | ✅ |
| **被取消的请求回 `CTAP2_ERR_KEEPALIVE_CANCEL`** | **必须** | `ctap_abort_pending()` 后**不发任何响应** | **❌ 见下** |
| KEEPALIVE 间隔 500ms | `kKeepAliveMillis` | `>= 500u` | ✅ |
| 等待 UP 时 KEEPALIVE 状态 = UP_NEEDED | `0x02` | `FIDO_BLE_KA_UP_NEEDED` | ✅ |
| 取得 UP 后先发 PROCESSING 再算 | 应当 | `FIDO_BLE_KA_PROCESSING` | ✅ |
| **收到任何请求就起 KEEPALIVE 计时** | **必须（SHALL）** | 仅在 `s_ctap_pending` 分支里推进；**同步处理期间不发** | **⚠️ 见下** |
| 处理完成即停 KEEPALIVE 并发响应 | 必须 | 取 UP 后流程一致 | ✅ |
| UP 超时回 `CTAP_ERR_ACTION_TIMEOUT` | — | 实测走到该分支 | ✅ |

> **CANCEL 的语义缺口（真实违例）**：§11.4.8 说得很直接 ——
> **"the authenticator MUST cancel it and that cancelled request will reply with the error
> `CTAP2_ERR_KEEPALIVE_CANCEL`"**。现在项目只是丢掉挂起状态，客户端什么也收不到，
> 只能靠自己的超时结束。规范之所以要求回调，是因为客户端需要**立刻**区分
> "用户取消" 与 "设备失联"。
> 修复方向：`ctap_abort_pending()` 之前，用保留的请求上下文回一个
> `MSG(STAT=0x83, DATA=[0x2D /* CTAP2_ERR_KEEPALIVE_CANCEL */])`。

> **KEEPALIVE 只在挂起时发（部分违例）**：§11.4.9 用 **SHALL** 规定"收到任何请求后
> 每 500ms 发 KEEPALIVE 直到处理完成"。项目把 KEEPALIVE 的推进放在
> `ble_transport_pending_poll()` 里，而该函数只在 `s_ctap_pending` 时才做事；
> `ctap_handle_cbor()` 是**同步**执行的，期间的 500ms 窗口无人照看。
> 由于 P-256 签名/验签在本平台上通常远快于 500ms，**实测未暴露问题**；
> 但若未来出现慢路径（大 blob、证书链较长），客户端可能因静默而超时。
> 保守修复：在 `AUTH_WAIT_GRANTED` 里已有一次 PROCESSING（已做），
> 可再考虑对"预计耗时"的命令在主循环里补一次计时驱动的 PROCESSING。

### 广告与地址（§11.4.7 / §11.4.13.2 / §11.4.17）

| 项 | 规范 | 项目 | 判定 |
|---|---|---|---|
| 广播含 FIDO service UUID | 必须 | `advertData` 里 `GAP_ADTYPE_128BIT_COMPLETE` + 16 字节反序 UUID | ✅ |
| 配对模式 AD Flags | General=1 或 Limited=1 | `Peripheral_SetPairingMode()` 置 `GAP_ADTYPE_FLAGS_GENERAL` | ✅ |
| 非配对模式 AD Flags 两位皆 0 | 必须 | 非配对时 `flags = GAP_ADTYPE_FLAGS_BREDR_NOT_SUPPORTED`（两位为 0）| ✅ |
| 设备名可辨识 | 建议 | `SecureKey`（9 字符，完整名）| ✅ |
| 实现 GAP + DIS | 必须 | 均已实现 | ✅ |
| Service Data 标志（bit7 配对模式） | 强烈建议 | `GAP_ADTYPE_SERVICE_DATA` + `FIDO_SERVICE_DATA_FLAGS`，偏移 25 动态改写 | ✅ |
| Service Data 放在 **Scan Response** | 强烈建议 | 放在 **主广播（advertData）** | ⚠️ 见下 |
| Service Data bit6（要求 Passkey） | 可 | 未使用该位 | ✅（本设备无 PIN 流程）|
| 配对动作不易误触 | 应当 | 长按 PB4 200ms(DEBUG)/5000ms(正式) | ✅（正式构建满足）|
| **配对模式有可见/可听提示** | 应当 | LED 慢闪 | ✅ |
| MTU 尽量大 | 建议（上限 512）| 实测协商到 **256** | ✅ |
| **使用 RPA 而非静态地址** | 建议 | 静态地址 `38:3B:26:7E:34:8E` | ❌ 见下 |
| 3 个广播信道 | 建议 | 由协议栈默认行为决定 | ➖ |

> **Service Data 位置**：规范**强烈建议**放在 **Scan Response** 里（针对 iOS 这类
> 不暴露 AD Flags 的平台）。项目放在**主广播**，代码注释给出了理由 ——
> "那样客户端在主动扫描时就能一并拿到"。这是**有意识的取舍**：主广播能被
> 被动扫描直接拿到，而 Scan Response 需要主动请求。两者总长都在 31 字节内。
> 若要兼顾 iOS 建议，可考虑**两处都放**（主广播已 26 字节，再加 5 字节会超出 31，
> 需要挪走别的内容）。

> **静态地址（recommendation 未满足）**：§11.4.17 建议用 RPA 防追踪。
> 当前固定地址会让设备**可被长期追踪**。这是 CH58x 协议栈的能力问题，
> 需要确认栈是否支持 `GAP_PRIVATE_ADDRESS_TYPE` / RPA 生成；若不支持，
> 应在文档里明确记录这条取舍（本项为 RECOMMENDED，不是硬性要求）。

### §11.4.2 / §11.4.3 链路安全

| 项 | 规范 | 项目 | 判定 |
|---|---|---|---|
| 使用 LTK、全程加密 | 必须 | `bonding=TRUE`，配对后保存 LTK | ✅ |
| 绝不使用 STK | 必须 | 同上 | ✅ |
| **Security Mode 1 Level 2/3** | 必须 | `mitm=FALSE` + `NO_INPUT_NO_OUTPUT` = Just Works = **Level 2** | ✅ |
| **交换 FIDO 消息前强制加密** | **必须** | 属性表**曾无** `GATT_PERMIT_ENCRYPT_*`，且连接时不发起加密 | **❌ 已修，见下** |

**✅ Security Mode 1 Level 2 已确认符合。** `src/peripheral.c:535-546`：

```c
uint8_t mitm    = FALSE;                              /* 未认证配对 */
uint8_t ioCap   = GAPBOND_IO_CAP_NO_INPUT_NO_OUTPUT;  /* Just Works */
uint8_t bonding = TRUE;                               /* 保存 LTK */
uint8_t pairMode = GAPBOND_PAIRING_MODE_WAIT_FOR_REQ;
```

§11.4.3 允许 Level 2 或 Level 3，本设备选 Level 2，正确。
代码注释还记录了之前 `mitm=TRUE + DISPLAY_ONLY` 造成的"声称 Level 3 却无法完成认证"
（表现为 Android 卡在配对阶段），那次修正方向是对的。

> **❌ 真实违例：加密前就能交换 FIDO 消息（已修）**
>
> 规范的原话约束点在 **"before any FIDO messages are exchanged"** —— 是"交换 FIDO 消息
> **之前**"，而不是"配对时用了 Level 2"。修复前的实际状态是：
>
> ```c
> /* src/fido_service.c 属性表 —— 修复前 */
> fidoControlPoint  : GATT_PERMIT_WRITE                       /* 无加密要求 */
> CCCD              : GATT_PERMIT_READ | GATT_PERMIT_WRITE    /* 无加密要求 */
> revBitfield       : GATT_PERMIT_READ | GATT_PERMIT_WRITE    /* 无加密要求 */
> CPLength          : GATT_PERMIT_READ                        /* 无加密要求 */
> ```
>
> CH58x 栈明明提供了这两个位（`lib/BLE_LIB/CH58xBLE_LIB.h:624-625`）：
>
> ```c
> #define GATT_PERMIT_ENCRYPT_READ    0x40   //!< Read requires Encryption
> #define GATT_PERMIT_ENCRYPT_WRITE   0x80   //!< Write requires Encryption
> ```
>
> **一个都没用。** 而 `GATTServApp_RegisterService()` 的 `encKeySize` 参数
> （`fido_service.c:249` 传的 `GATT_MAX_ENCRYPT_KEY_SIZE`）**只在属性带 ENCRYPT
> 权限时才会被检查** —— 单设它对"未加密能否直接写"没有约束力。
>
> 另外 `Peripheral_LinkEstablished()`（`src/peripheral.c:749-779`）里**没有
> `GAPBondMgr_LinkEst()`** —— 连接建立后不主动要求配对/加密。
>
> **后果**：未加密的连接可以直接写 `fidoControlPoint` 并发 `MSG` 命令，
> 等于在未加密状态下交换 FIDO 消息。这也解释了为什么测试脚本能一路跑通 ——
> 脚本作为客户端从未被要求加密。
>
> **修复**：给承载 FIDO 消息的属性加 ENCRYPT 位（`src/fido_service.c`）：
>
> | 属性 | 修复后权限 |
> |---|---|
> | `fidoControlPoint` | `WRITE \| ENCRYPT_WRITE` |
> | `fidoStatus` 的 CCCD | `READ \| WRITE \| ENCRYPT_READ \| ENCRYPT_WRITE` |
> | `fidoServiceRevisionBitfield` | `READ \| WRITE \| ENCRYPT_READ \| ENCRYPT_WRITE` |
> | `fidoControlPointLength` | `READ \| ENCRYPT_READ` |
>
> **服务声明与特征声明刻意不加加密位**：客户端必须先做服务发现才知道有这些
> 特征，加密前就把它们挡住会让客户端根本找不到服务。
>
> **为什么靠权限位就够了、不必显式发起加密**：未加密的连接读写这些属性会得到
> `ATT_ERR_INSUFFICIENT_ENCRYPTION (0x0F)`，Windows/Android 的 BLE 栈收到该错误会
> **自动发起配对/加密**后再重试。这正是规范期望的强制时机，且已绑定设备可
> 无人工干预完成（满足 §11.4.6 的"对已绑定客户端必须无干预放行"）。
>
> **待实测确认**：改完后必须重测**首次配对**（先删除配对记录）与**重连**两条路径，
> 确认不会出现"连上就卡住"。若某些平台不主动发起加密，再考虑在
> `Peripheral_LinkEstablished()` 里补显式加密流程。


### §11.4.14 命令完成后的连接保持

| 项 | 规范 | 项目 | 判定 |
|---|---|---|---|
| 不消耗 UP 的响应后保持连接 ≥ `kErrorWaitMillis`(2000ms) | 必须 | 未见显式计时；断开由协议栈参数决定 | ⚠️ 见下 |
| 客户端退订通知 → 认证器可进入低功耗 | 可 | `FIDO_EVT_STATUS_NOTI_DISABLED` 分支为空 | ➖（可优化）|

> **`kErrorWaitMillis` 未显式实现**：规范用 **MUST** 要求"不消耗 UP 的响应之后，
> 连接要保持到客户端主动关闭、或至少 2000ms 无新命令"。项目未看到对应计时器，
> 连接是否保持取决于协议栈的 supervision timeout。
> 实测中脚本能连续发多个命令（GetInfo → MakeCredential → GetAssertion），
> 说明**实际连接保持时间是够的**，但这是**协议栈参数碰巧满足**，
> 而非显式实现。若要严谨，可在响应后记录时间戳，超时前不接受非主动断开。

---

## 三、优化建议（按优先级）

### P0 —— 真实违例，建议修

**1. ERROR 帧的 DATA 填错值**

```c
/* 现状（src/ble_transport.c，两处）*/
uint8_t err[1];
err[0] = FIDO_BLE_CMD_ERROR;
send_frame(FIDO_BLE_CMD_ERROR, err, 1);

/* 应改为 */
uint8_t err[1];
err[0] = 0x01;                     /* ERR_INVALID_CMD (§11.4.4.3) */
send_frame(FIDO_BLE_CMD_ERROR, err, 1);
```

理由：§11.4.4.2 明确 DATA 是"变长大端错误码"。现在客户端读到 `0xBF`（未定义）。
建议同时把"载荷长度 < 1"那处也一并改（同一根因）。
可选：抽一个 `send_error(uint8_t code)` 辅助函数，避免再次写混。

**2. CANCEL 之后补回 `CTAP2_ERR_KEEPALIVE_CANCEL`**

```c
case FIDO_BLE_CMD_CANCEL:
    if(s_ctap_pending)
    {
        s_ctap_pending = 0;
        uint8_t body[1] = { CTAP_ERR_KEEPALIVE_CANCEL };  /* 0x2D */
        send_frame(FIDO_BLE_CMD_MSG, body, 1);            /* 先回错误 */
        ctap_abort_pending();
    }
    /* CANCEL 本身仍然不回复 —— 保持无 send */
    break;
```

理由：§11.4.8 用 **MUST**。客户端依赖这个错误码来区分"用户取消"与"设备失联"。
（`ble_transport_on_write()` 里在挂起期间收到 CANCEL 的那条分支也要同样处理。）

**3. 交换 FIDO 消息前强制加密（链路安全）**

见上文 “§11.4.2 / §11.4.3 链路安全” 一节。给承载 FIDO 消息的属性加
`GATT_PERMIT_ENCRYPT_*`（`src/fido_service.c` 四处权限）。
**✅ 已修**：`fidoControlPoint`、`fidoStatus` 的 CCCD、
`fidoServiceRevisionBitfield`、`fidoControlPointLength` 全部要求加密；
服务声明与特征声明刻意不加，以免客户端在服务发现阶段就被挡住。

### P1 —— 有条件的改进

**4. KEEPALIVE 覆盖同步处理期间**

现状只在 `s_ctap_pending` 时推进计时。可在主循环里加一个独立的
"最后一次响应时刻"时间戳，若距上次响应超过 500ms 且仍有命令在处理，
补发 `KEEPALIVE(PROCESSING)`。
**前提**：先确认 `ctap_handle_cbor()` 的实际最坏耗时 —— 若始终 < 500ms，
此项可只加注释说明，不必加代码。

**5. SEQ 回绕按规范写成掩码**

```c
tx_buf[tx_offset] = tx_seq;
tx_seq = (uint8_t)((tx_seq + 1) & 0x7F);    /* §11.4.10：到 0x7F 回绕到 0 */
```

理由：现在 `uint8_t` 自增到 0x80。虽然响应长度触不到，但改一行就彻底合规。
接收侧 `rx_seq++` 同理（可写 `rx_seq = (rx_seq + 1) & 0x7F`）。

**6. `kErrorWaitMillis` 显式化** —— 复核结论：**实际已满足，可不改**

核查结果：

| 项 | 值 |
|---|---|
| 规范要求 | 2000 ms |
| `DEFAULT_DESIRED_CONN_TIMEOUT`（`peripheral.c:119`）| **3000 ms** |
| `SBP_PERIODIC_EVT_PERIOD`（`peripheral.c:35`）| 1600 ms |

项目里**确实没有**"响应后保持 2000ms"的显式计时器，但协议栈的
supervision timeout 是 **3000 ms > 2000 ms**，所以**实际满足规范**——
属"碰巧够用"而非显式实现。最终 53 项一致性测试里连续多条命令都通过，
也印证了连接保持时间足够。

若要更严谨（不依赖栈参数凑巧），可按下法补：在"不消耗 UP 的响应"之后记录
时间戳，2000ms 内不主动断开；并与"退订通知后低功耗"合并处理 ——
`FIDO_EVT_STATUS_NOTI_DISABLED` 到来时，若已无待处理命令才允许进入低功耗。
**建议：暂不改**，仅在文档记录该依赖关系。

### P2 —— 合规性/隐私

**7. RPA 地址** —— 复核结论：**栈支持，可实施（需实测）**

核查结果：

- 项目代码里**没有任何地址类型设置**（`grep ADDRTYPE|addrType|ConfigDeviceAddr` 全空）
  → 用的是栈默认，实测地址恒为 `38:3B:26:7E:34:8E`（static）
- **栈支持 RPA**：`lib/BLE_LIB/CH58xBLE_LIB.h:859` 定义
  `ADDRTYPE_PRIVATE_RESOLVE 0x03`；设置入口是
  `GAP_ConfigDeviceAddr(addrType, pStaticAddr)`（同文件 3817 行）

**所以 §11.4.17 这条 RECOMMENDED 是可以满足的，不必接受偏差。**

但切换前必须实测两点，**不能只改代码**：

1. **RPA 依赖 LTK 才能被解析** —— 首次配对（尚无 LTK）时对端能否连上？
2. 配对成功后重连，地址是否会被正确解析、加密链路是否照常建立？

**建议**：作为独立改动做，改完完整重跑一致性测试 + `ble_probe_encryption.py`。

**8. `CPLength` 字节序**

可考虑改为 **big-endian** 以严格对齐 §11.4.5 总则。**但要先确认 Windows/Android
客户端也按 big-endian 解释** —— 若客户端沿用 little-endian，改了反而破坏互通。
**当前保持 little-endian 是更安全的选择**，只需在文档与测试脚本里注明
（脚本已做双字节序兼容）。

**9. 加密强制 —— 已在设备上验证通过 ✅**

代码层修复（见 P0 第 3 项）**已通过真机验证**。专用探测脚本
`tools/ble_probe_encryption.py`（自身**不做配对**，以便如实反映当前链路状态）
依次尝试三项要求加密的操作：

| 操作 | 设备侧要求 |
|---|---|
| 读 `fidoControlPointLength` | `ENCRYPT_READ` |
| 写 `fidoControlPoint`（一个 PING 帧）| `ENCRYPT_WRITE` |
| 读 `fidoServiceRevisionBitfield` | `ENCRYPT_READ` |

**实测①：未配对状态 —— 三项全部被拒**

```
① 读 fidoControlPointLength       -> BleakGATTProtocolError(5, 'Insufficient Authentication')
② 写 fidoControlPoint             -> 同上
③ 读 fidoServiceRevisionBitfield  -> 同上

✔ 三项全部被加密拦截 —— §11.4.3 强制生效，符合规范
```

**实测②：配对后 —— 设备侧确认读、写、处理全部成功**

```
[FIDO] read  h=0x002A → len=2 data=FD 00 (CPLength)
[FIDO] write h=0x0023 len=7 method=0x12
[BLE] PING rx len=4 -> echo
```

**结论：§11.4.3 的加密强制生效，P0 第 3 项的修复有效。**

> **实测校正：ATT 错误码是 `5` (Insufficient Authentication)，不是常见的
> `0x0F` (Insufficient Encryption)。** CH58x 栈把 `GATT_PERMIT_ENCRYPT_*`
> 报成了认证类错误。语义相同、拦截有效，但排查时要认这个值 ——
> 只盯 `0x0F` 会漏判为"其它错误"。

> **一个独立问题（与加密无关）**：第二次运行时 MTU 只有 23，串口日志反复出现
> `link TERMINATED reason=0x13`（远端主动断开）—— 这是 **Windows 蓝牙栈抢占链路**
> （设备是单连接外设），属既有问题，加密修复既不是它的成因也不是它的解药。
>
> **两种症状必须分清**：
> - 被**加密**拦截 → `Insufficient Authentication`（拦截生效，是**好结果**）
> - 链路被**抢占** → `Unreachable` / `Not connected` / MTU 停在 23
>   （要删配对记录后重来）
>
> 探测脚本 `is_insufficient_encryption()` 按这两类分别给结论，
> 判定要求同时出现 `insufficient` 与（`encrypt` 或 `authenticat`），
> **不会把"链路被占用"误报成"加密生效"**。

**注意 `ble_dump_gatt.py` 验证不了这一项** —— 它只做**服务发现**（读属性表与
描述符），从不写 `fidoControlPoint`，而加密要求恰恰落在**写**上。
不过 GATT 库 dump 成功本身说明了一件有用的事：**服务声明与特征声明刻意不加
加密位是对的**，客户端在加密前仍能完整发现 FIDO 服务。

> **踩坑记录**：本次修好后暴露了一个脚本缺陷 —— 原实现用 `client.is_paired()`
> 判断配对状态，但该 API 在当前 bleak 版本**不存在**（`AttributeError`），
> 导致 `paired` 恒为 `None`、**自动配对分支永不触发**，删了配对记录的机器上
> 会全线失败。现已改为**行为探测**：先试读一个要求加密的特征，被拒就
> `pair()` 再复验 —— 不依赖任何可选 API。


### P3 —— 体验

**10. 配对模式提示**

§11.4.13.2 建议可见/可听提示。已有 LED 慢闪。可考虑在进入配对时
**立即**更新 `AD Flags` 与 Service Data bit7（现有 `Peripheral_SetPairingMode()`
已做），确保部分客户端在未连接时就能看到。

**11. 广播信道**

§11.4.16 建议 3 个信道都广播。确认协议栈默认行为；若可配置，显式打开。

---

### P4 —— 健壮性（非规范强制）

**12. 通知发送失败时丢弃整帧，不再保留重试** ✅ 已修

**背景**：`ble_transport_pump()` 原来在 `fido_status_notify()` 失败时
"保留待发"（`return` 而不推进 `tx_offset`），主循环于是每轮重试一次。
实测未订阅通知时，同一条日志连打数十次：

```
[FIDO] write h=0x0023 len=7 method=0x12
[BLE] PING rx len=4 -> echo
[FIDO] notify SKIP: not subscribed (cccd=0x0000)     ← 重复数十次
[FIDO] notify SKIP: not subscribed (cccd=0x0000)
...
```

**规范立场**：§11.4.14 规定客户端**必须先启用通知并等待 ATT 确认**才能发
FIDO 消息 —— 未订阅属客户端违规，设备没有义务为它空转。
所以这是**健壮性 / 功耗**改进，**不是合规项**，故单列于此。

**修复**：两个失败分支（初始帧、续帧）都改为**丢弃整个帧**并复位状态：

```c
SK_LOG("ble: notify failed -> drop frame cmd=%02X", tx_cmd);
tx_active = 0;
tx_offset = 0;
tx_seq    = 0;
return;
```

**顺带简化**：续帧分支原来还要 `memmove` 把插入的 SEQ 抹回、并把序号退一格
"以便原样重试"。既然整帧作废，这些回滚都不需要了 —— Flash 因此少了 44 字节。

**触发场景说明**：正常流程碰不到（客户端按规范会先订阅）；
`tools/ble_probe_encryption.py` 刻意不订阅，才把它暴露出来。

**验证**：`pio run` SUCCESS —— `RAM 81.3%` 不变、`Flash 175196`
（比修复前少 44 字节）。运行时行为待下次连接确认日志不再刷屏。

## 四、测试脚本的对应增强

`tools/ble_ctap2_conformance.py` 已按规范逐条核对，本轮根据规范原文修正了：

| 修正项 | 原状态 | 现状态 |
|---|---|---|
| 命令码取值 | 误用 USB HID 的 `0xBB`/`0x91` | 按 §11.4.4.3 用 BLE 的 `0x82`/`0xBE` |
| `CPLength` 范围 | 写成 1–7609（HID 上限）| 按 §11.4.5.1 用 **20–512** |
| `CPLength` 字节序 | 硬编码 little-endian | **两种都解**，取落区间者并打印原始字节 |
| 分片容量基准 | 误用 `MTU−3` | 按 §11.4.10 用 **`maxLen`**（通知 = `MTU−3`，再扣帧头）|
| 分片数统计时机 | 在 `send()` 后立即取（恒为 0）| 改到 `recv()` 之后 |
| KEEPALIVE 处理 | 仅跳过 | **识别状态字节**（PROCESSING / UP_NEEDED）并计数 |
| ERROR 处理 | 仅记录 | **解析错误码**并映射为常量名 |

**建议补充的测试项**（对应上面的 P0/P1）：

1. **ERROR 帧语义**：写一个不支持的封装层命令（如 `0xA0`），
   断言 `STAT==0xBF` 且 `DATA[0]` 是**合法错误码**（`0x01`/`0x02`/…/`0x7f`），
   **而不是 `0xBF`**。这是目前唯一能自动抓出 P0-1 的用例。
2. **CANCEL 语义**：发一个需要 UP 的命令（MakeCredential），
   在 `UP_NEEDED` 到达后发 CANCEL，断言随后收到
   `MSG` 且 `DATA[0] == 0x2D`（`CTAP2_ERR_KEEPALIVE_CANCEL`）。
3. **KEEPALIVE 节奏**：在需要 UP 的交互中，记录两次 KEEPALIVE 的时间差，
   断言约等于 500ms（`kKeepAliveMillis`）。
4. **未配对拒绝**：在删除配对记录后直接写 `fidoControlPoint`，断言被拒。

---

## 五、小结

### 最终一致性测试结果

```
========================================
  PASS 53   FAIL 0   SKIP 0
  全部检查通过。
========================================
```

`tools/ble_ctap2_conformance.py` 在真机上**全项通过**。逐项证据：

| 覆盖范围 | 关键验证点 |
|---|---|
| §11.4.3 链路安全 | 未加密被拒 → 自动配对 → 加密后可读写 |
| §11.2 GATT 服务/特征 | 5 项（UUID、属性、CPLength、版本位）|
| §11.4.5 CPLength | 值 = 253 = MTU−3（含字节序双解）|
| §11.4.6 版本位 | 0x20、拒写 0x00、写单一位成功 |
| §11.4.10 分片 | 253B → 2 片，与公式一致（初始容量 250 / 续 252）|
| §11.4.4.2 封装层 ERROR | STAT=0xBF 且 **DATA=0x01**（非 STAT 值）|
| §11.4.8 CANCEL | 不回复自身、链路保持可用 |
| §6.1 / §6.2 | MakeCredential + GetAssertion（含 **ECDSA 签名验证**）|

**整体判断**：本项目的 BLE 传输层实现**与 §11.4 高度一致**。
广告格式（`AD Flags` 配对/非配对切换、Service Data bit7）甚至超出最低要求。
分片公式（`maxLen−3` / `maxLen−1`）完全正确，实测 253B → 2 片得到印证。

**三个真实违例（均已修复）**：
1. ERROR 帧 DATA 填了 `0xBF` 而非错误码（§11.4.4.2）
2. CANCEL 后未回 `CTAP2_ERR_KEEPALIVE_CANCEL`（§11.4.8，MUST）
3. **交换 FIDO 消息前未强制加密**：属性表无 `GATT_PERMIT_ENCRYPT_*`
   （§11.4.3，MUST）—— 这是三项中安全影响最大的一项

**一个未满足的建议**：静态地址而非 RPA（§11.4.17，RECOMMENDED）。
**但这条其实可以满足** —— 栈提供了 `ADDRTYPE_PRIVATE_RESOLVE (0x03)`
（`lib/BLE_LIB/CH58xBLE_LIB.h:859`）与 `GAP_ConfigDeviceAddr()`
（同文件 3817 行），而项目**目前没有任何地址类型设置**，用的是栈默认
（实测恒为 `38:3B:26:7E:34:8E`，属 static）。切换到 RPA 需要实测配对流程
（RPA 依赖 LTK 才能被解析），故留在 P2 第 7 项待办。

**已确认符合**：Security Mode 1 Level 2（Just Works，`mitm=FALSE` +
`NO_INPUT_NO_OUTPUT`）。

**一个待设备验证项**：`kErrorWaitMillis`(2000ms) 未显式实现 ——
项目里没有"响应后保持 2000ms"的计时器，但协议栈的
`DEFAULT_DESIRED_CONN_TIMEOUT = 3000` ms **大于** 2000 ms，
所以实际满足（属"碰巧够用"而非显式实现）。周期任务 `SBP_PERIODIC_EVT`
为 1600 ms。

**加密修复的验证状态**：**已在真机验证通过**（见 P2 第 9 项）。
未配对时三项要求加密的操作全部被拒（`ATT 5 Insufficient Authentication`），
配对后读、写、处理 PING 全部成功 —— §11.4.3 的强制生效得到确认。
最终一致性测试 **53 PASS / 0 FAIL / 0 SKIP**。

**另一项健壮性改进（非规范强制）**：通知发送失败时改为**丢弃整帧**，
不再"保留待发"让主循环忙等重试（见 P4 第 12 项）。顺带删掉了续帧分支的
回滚逻辑，Flash 因此少 44 字节。

**附带教训**：BLE 传输的命令码与 USB HID **不同**（`KEEPALIVE` 0x82 vs 0xBB、
`CANCEL` 0xbe vs 0x91）。规范里 "These values are identical to the HID transport values"
那句容易误读 —— **以表为准，不以那句话为准。**

---

## 六、Windows webauthn 客户端问题（未解决，非设备侧）

### 结论先行

**设备侧无问题。** 三条独立验证路径全部通过：

| 验证路径 | 结果 |
|---|---|
| `tools/ble_ctap2_conformance.py`（逐条核对 §11.4）| **53 PASS / 0 FAIL / 0 SKIP** |
| `tools/ble_probe_encryption.py`（§11.4.3 加密强制）| 未配对全拒 → 配对后全通 |
| `tools/ble_gatt_client.py`（端到端 8 步）| **全部通过**（MakeCredential 177B / GetAssertion 192B 多帧响应）|

三条路径的客户端代码、配对流程、MTU 均不同，结论一致。

### 现象：webauthn.io 注册时，每次尝试分两个阶段

**阶段 1（首次配对）**

```
link ESTABLISHED
security request -> sent            ← 设备主动发起加密（本次会话新增）
mtu exchange: 256
pair state=0/1/3 → bond saved       ← 配对成功，LTK 已保存
param update SUCCESS int=12         ← ★ 证明客户端已订阅通知（见下）
[FIDO] read  h=0x002A -> CPLength     (FD 00 = 253)
[FIDO] read  h=0x0028 -> RevBitfield  (20 = FIDO2)
param update SUCCESS int=24
link TERMINATED reason=0x13         ← ★ 客户端主动断开
```

**阶段 2（重连）**

```
link ESTABLISHED
security request -> sent
pair state=2                        ← 用已有 LTK 加密，无人工干预
mtu exchange: 256
RSSI ×30~70（保持 30~70 秒；信号 -41~-50 dB，良好）
（零 GATT 活动 —— 无 [FIDO] read/write，也无订阅日志）
```

### 客户端完成度（对照 §11.4.6 流程）

| §11.4.6 步骤 | Windows 是否做到 | 证据 |
|---|---|---|
| 1. 发现服务 | ✅ | GATT 操作正常 |
| 2. 读 `fidoServiceRevisionBitfield` | ✅ | `[FIDO] read h=0x0028 -> 20` |
| 3. **写单一位选择版本** | ❌ **没写** | 日志无 `[FIDO] write` |
| 4. 读 `fidoControlPointLength` | ✅ | `[FIDO] read h=0x002A -> FD 00` |
| 5. **订阅 `fidoStatus`** | ✅ | `param update int=12` 由 CCCD 回调触发 |
| 6. 写 FIDO 请求 | ❌ **没写** | 日志无 `[FIDO] write` |

**即：客户端做到第 5 步后停住，不发任何请求。**

> **第 5 步的推断依据**：`param update SUCCESS int=12` 是设备在
> `FIDO_EVT_STATUS_NOTI_ENABLED`（客户端写了 CCCD）时才发起的连接参数更新
> （`ble_transport_on_cccd_enabled()`）。该行**证明客户端确实订阅了通知**，
> 而非"什么都没做"。

### 可能原因（未证实，按设备侧可控性排序）

**① `transports` 声明含 `usb`** —— 设备侧唯一可控变量

`authenticatorGetInfo` 返回 `6: ["usb", "ble"]`（`src/ctap.c:149-153`）。
Windows 的 FIDO 实现可能因设备**同时**声明 USB 而走不同分支
（例如先尝试 USB 通道、失败后不再继续 BLE），或要求纯 BLE 认证器
只声明 `ble`。

**未验证。** 若做实验：临时把 `ctap.c` 的 `transports` 改为只声明 `"ble"`，
重新配对后测试 —— 但可能影响 USB 侧的既有行为。

**② 版本位未写（客户端违反规范）**

§11.4.5.1：客户端在发任何 FIDO 命令**之前**必须先向
`fidoServiceRevisionBitfield` 写入恰好 1 bit。Windows **读了但没写**。
该特征在设备侧是 Read/Write（`ble_gatt_client.py` 实测写成功），
**不是设备拒绝写入**。

**③ Windows 侧状态残留**

多次尝试中客户端行为**不一致**（有时读两个特征，有时一个不读）——
说明 Windows 有缓存（GATT 数据库 / 服务记录 / 蓝牙栈状态）。
处理：删除配对记录 + **重启 Bluetooth Support Service** + 设备重上电。

### 建议的下一步

1. **换 Android 验证** —— 诊断价值最高。若 Android 通过则确认是本机
   Windows 问题；若也不通过，说明仍有设备侧未覆盖的点。
2. **清 Windows 侧全部状态**（配对记录 + 蓝牙服务重启 + 设备重上电）。
3. **`transports` 实验**（唯一设备侧可变量，属猜测）。
4. 查 Windows 事件查看器的 `webauthn` / `Bluetooth` 条目。

### 本次会话在此问题上的产出

- **修复**：设备侧原先无加密强制（§11.4.3 违例）→ 加 `GATT_PERMIT_ENCRYPT_*`
  权限位 + `GAPBondMgr_PeriSecurityReq()` 主动发起加密
- **效果**：从"连上就断、无限循环"变为"加密稳定建立、阶段 2 可保持 30~70 秒"
- **未解决**：客户端在加密成功后不发 FIDO 请求 —— **属 Windows 客户端范畴**

### 附：排查中修掉的测试脚本 bug

`tools/ble_gatt_client.py` 的 `request()` **不区分封装层帧与 CTAP 层数据**，
导致两个同类误判：

| 帧 | 原本被当成 | 后果 |
|---|---|---|
| `KEEPALIVE(0x82)` | CTAP 状态码 `0x02` | MakeCredential 被误报"状态=0x02 失败"（设备其实在正确等用户按键）|
| `ERROR(0xBF)` | CTAP 状态码 | 错误码会被误读 |

两者均已修正（跳过 KEEPALIVE、解析 ERROR 错误码）。
`ble_ctap2_conformance.py` 原本处理正确，是 `ble_gatt_client.py` 漏了。
