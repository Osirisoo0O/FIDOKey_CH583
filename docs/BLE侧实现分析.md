# BLE 侧实现：三个决策点的分析

> 配套《[BLE侧实现规划](BLE侧实现规划.md)》
> 结论先行：**原定的三个决策点里，第 1 个（并发 UP）是真正的设计问题；
> 第 2 个（挂起重放位置）在查代码时发现了一个更根本的架构问题，必须先解决；
> 第 3 个（示例服务处置）是低风险的实施顺序问题。**

---

## 结论速览

| 问题 | 结论 | 风险 |
|---|---|---|
| **0. `ctap.c` → `ctaphid.c` 的反向依赖**（查代码时发现） | 把挂起推进逻辑下放到各传输层；`ctap.c` 只留全局性的兜底清理 | 低 |
| **1. USB / BLE 并发等待同一次按键** | 采用「授权窗口期」（方案 A2），并说明为何不选另外两种 | 中 |
| **2. 挂起/重放放在哪** | 与问题 0 是同一件事，随其一并解决 | 低 |
| **3. `ble_usb_service` / `SimpleProfile`** | 新建 `fido_service.c`；示例服务**先保留一轮**再移除 | 低 |

---

## 0. 先解决一个更根本的问题：反向依赖

### 现状

查代码发现 `ctap.c`（**协议核心**）直接调用了 `ctaphid.c`（**USB 传输层**）：

```c
/* src/ctap.c  ctap_pending_poll() */
1081:    if(!ctaphid_ctap_is_pending())          { ... }
1102:            (void)ctaphid_reprocess();
1109:            (void)ctaphid_ctap_reply(CTAP_ERR_ACTION_TIMEOUT, NULL, 0);
```

这是**反向依赖**——协议核心不该知道传输层的存在。加 BLE 后它会立刻成为障碍：
`ctap_pending_poll()` 不知道该让谁重放。

### 这个依赖是怎么来的

因为「挂起重放」这个机制被**劈成了两半**：

| 部分 | 位置 | 职责 |
|---|---|---|
| **挂起状态与报文** | `ctaphid.c` | `s_ctap_pending` / `s_pend_cid` / `rx_buf`（保留报文以供重放） |
| **推进挂起操作的时机** | `ctap.c` | 在 `ctap_pending_poll()` 里观察 `auth_sm` 状态 |

**问题在于：推进逻辑必须访问挂起状态**，而挂起状态在传输层 —— 于是协议核心不得不反向调用。

### 分析

挂起状态天然属于**传输层**，因为：
- 报文缓冲（`rx_buf`）是传输层的资源
- 「保留报文、不发响应」是传输层的动作
- 通道标识（`s_pend_cid`）是传输层的概念

所以**推进逻辑也该在传输层**。三种解法：

#### 方案 A：回调注册

```c
/* ctap.h */
typedef struct {
    int (*is_pending)(void);
    int (*reprocess)(void);
    int (*reply)(uint8_t status, const uint8_t *body, uint16_t len);
} ctap_transport_t;
void ctap_set_transport(const ctap_transport_t *t);
```

**问题**：设备是双模的，**两个传输层都要注册**，单一 `ctap_set_transport()` 会互相覆盖，
需要改成多路（数组或链表）——反而更复杂。**不推荐。**

#### 方案 B：把挂起状态上移到 `ctap.c`

`ctap.c` 自己保存挂起的请求报文与响应通道，传输层退化为「收一帧 / 发一帧」。

**优点**：分层最干净，两个传输层完全对称。

**缺点**：**要改动已验证的 USB 路径**。挂起重放是 USB 侧调通过程中最微妙的部分
（见《FIDO2端到端验证记录》里的 EP1 死锁、KEEPALIVE、`up=false` 等一连串问题），
动它意味着**重新验证一遍**。

#### 方案 C：推进逻辑下放到各传输层（**推荐**）

把 `ctap_pending_poll()` 的推进部分**移入各传输层**，`ctap.c` 只保留**不依赖传输层**的全局清理。

```c
/* ctaphid.c —— 逻辑从这里搬过来，职责不变 */
void ctaphid_pending_poll(void);

/* ble_transport.c —— 新增，结构对称 */
void ble_pending_poll(void);

/* ctap.c —— 只留这一个：处理"UP 等待悬空"这种全局状态 */
void ctap_reap_dangling_up(void);
```

**为什么推荐**：

1. **改动是搬运，不是重写**。`ctap_pending_poll()` 里
   `switch(auth_sm_get())` 那段原样搬到 `ctaphid_pending_poll()` 即可。
2. **`ctap.c` 从此不认识任何传输层**，BLE 直接并列接入。
3. **不动已验证的挂起/重放机制本身**（只是换了宿主文件），回归风险小。

**唯一要注意的点**：`ctap_pending_poll()` 里有一段**全局性的兜底逻辑**——

```c
/* 没有挂起的 CTAP 请求，但 UP 等待还开着——典型场景是 USB 总线复位 */
if(!ctaphid_ctap_is_pending()) {
    if(auth_sm_get() == AUTH_WAIT_ACTIVE) {
        auth_sm_clear();
    }
    return;
}
```

**这段是为 USB 复位设计的**，但它处理的是 `auth_sm`（全局状态）的悬空。
搬到传输层后，**两个传输层各写一份会重复**，且语义不清（BLE 侧复位不该由 USB 的 poll 处理）。

**所以这段单独留在 `ctap.c`，作为 `ctap_reap_dangling_up()`**，由主循环调用一次。
它只看 `auth_sm`，不看任何传输层状态——**没有反向依赖**。

### 结论

采用**方案 C**。改动量：

| 文件 | 改动 |
|---|---|
| `ctap.c` | `ctap_pending_poll()` 拆分：推进部分移出，保留 `ctap_reap_dangling_up()` |
| `ctaphid.c` | 新增 `ctaphid_pending_poll()`（搬入推进逻辑） |
| `peripheral_main.c` | 主循环改为调用 `ctap_reap_dangling_up()` + `ctaphid_pending_poll()` |
| `ble_transport.c` | 新增 `ble_pending_poll()`（对称实现） |

**这一步应作为 BLE 实现的第 0 阶段**——它独立于 BLE，且能在纯 USB 环境下先验证
没有回归（跑一遍 `fido2_cred_test.py` 即可）。

---

## 1. USB / BLE 并发等待同一次按键

### 现状

`auth_sm` 是**单一状态机**，而 `AUTH_WAIT_GRANTED` 是**全局可见**的：

```c
/* ctap.c  ctap_up_gate() —— 两个传输层都走这里 */
if(auth_sm_get() == AUTH_WAIT_GRANTED) { return 0; }   /* 已有 UP，放行 */
if(auth_sm_get() != AUTH_WAIT_ACTIVE)  { auth_sm_request_up(); }
return 1;                                              /* 需要挂起 */
```

### 并发场景的实际行为

设备是双模的，USB 与 BLE 可能同时连接。假设两边都有请求：

| 步骤 | USB 侧 | BLE 侧 | `auth_sm` |
|---|---|---|---|
| 1 | 请求到达 → 闸门 → 发起等待 | — | `ACTIVE` |
| 2 | — | 请求到达 → 闸门发现**已在等待** → 返回 `PENDING` | `ACTIVE` |
| 3 | **用户按一次键** | — | `GRANTED` |
| 4 | poll 看到 `GRANTED` → 重放 → **`auth_sm_clear()`** | — | `NONE` |
| 5 | — | poll 看到的已是 `NONE` → **只能等超时** | `NONE` |

**问题在第 4/5 步**：`auth_sm_clear()` 由先完成的一方调用，
**后完成的一方就再也看不到 `GRANTED` 了**，只能超时失败。

### 三种处理方式

#### A1：引用计数

`auth_sm` 记录等待者数量，全部完成才 `clear`。

- **优点**：语义准确
- **缺点**：`auth_sm` 要改造成支持多等待者；引入计数就有配平问题
  （某个传输层异常断开时计数不归零 → UP 永不释放）

#### A2：授权窗口期（**推荐**）

`GRANTED` 状态**保持一小段时间**（如 100ms）再清除，让两个传输层都能观察到。

```c
/* auth_sm.c 概念示意 */
case AUTH_WAIT_GRANTED:
    if (now - s_granted_at >= AUTH_GRANT_HOLD_MS) {  /* 100ms 窗口 */
        s_state = AUTH_WAIT_NONE;
    }
    /* 窗口内保持 GRANTED，两个 poll 都能看到 */
```

- **优点**：改动小；语义合理（"用户在场"本就是**全局事实**，不是某个传输层独占的资源）
- **缺点**：需要一个时间窗口常量；两个请求都会被执行（见下）

#### A3：先到先得

第一个 poll 消费掉授权，第二个超时失败。

- **优点**：最保守——**一次按键只授权一个操作**
- **缺点**：用户体验差（第二个要重新按）；且行为取决于**主循环里 poll 的调用顺序**，
  是隐式的、难解释的

### 推荐与理由

**推荐 A2（授权窗口期）**，理由：

1. **语义正确**。用户按了键，就是「用户在场」这一事实成立。
   两个操作都由「用户在场」授权，各自合法。
2. **实现代价小**，不需要给 `auth_sm` 加多等待者的复杂度。
3. **避免 A3 的隐式顺序依赖**——谁先被服务不该取决于主循环里两行代码的先后。

**需要如实说明的取舍**：A2 下，**用户一次按键可能同时授权两个操作**（USB 一个、BLE 一个）。
这在安全上是否可接受，取决于使用场景：

- 若认为「用户在场是关键，用户按了键就代表同意」→ **A2 可接受**
- 若要求「每次操作都必须有独立的用户确认」→ **应选 A3**

**这一条建议由项目负责人决定**，因为它涉及安全策略而非纯技术。

### 另一个更简单的替代方案

如果认为双连接场景罕见，可以**从一开始就限制**：

- **BLE 已连接时，USB 侧的新请求直接返回 `CTAP2_ERR_CHANNEL_BUSY (0x06)`**
- 或反之

**优点**：完全绕开并发问题，实现最简单，行为明确。

**缺点**：用户可能不理解为什么插着 USB 就不能用 BLE。

**若不想在并发语义上花时间，这是务实的起点**——后续有需要再放开。

---

## 2. 挂起/重放放在哪

**与问题 0 是同一件事**，结论随其一并给出：**放在各传输层（方案 C）**。

不再单独展开。补充一点实现细节上的对称性说明：

| 动作 | CTAPHID | BLE |
|---|---|---|
| 保留报文 | `rx_buf`（已有） | 新增等价的接收缓冲 |
| 记录响应目标 | `s_pend_cid`（通道号） | 连接句柄（BLE 每连接一个） |
| 等待期上报 | `KEEPALIVE(0x3B)` | `KEEPALIVE(0x82)` |
| 超时回填 | `ctaphid_ctap_reply(0x3A)` | 组装 `MSG` 帧回送 `0x3A` |
| 重放 | `ctaphid_reprocess()` | 等价的 `ble_reprocess()` |

**两个传输层的结构会高度相似，但帧格式完全不同**（见规划 §2.3 的对比表），
**不能共用代码**——这正是规划里选择「各写一份」的原因。

---

## 3. `ble_usb_service` 与 `SimpleProfile` 的处置

### `ble_usb_service`：改造而非删除

**当前状态**：透传逻辑**已经被注释掉了**，只留一行占位：

```c
/* peripheral.c  ble_usb_ServiceEvt() */
case BLE_USB_EVT_BLE_DATA_RECIEVED:
    PRINT("BLE RX DATA len:%d\r\n", p_evt->data.length);
    /* 原为官方 ble-usb-cdc 示例的「BLE 数据透传到 USB」。
     * 在 FIDO2 双模下这条路径是错的：BLE 侧的 CTAP 应当由本设备自己处理
     * （CTAP 2.3 的 BLE 传输帧格式与 CTAPHID 不同，见计划 3.7），
     * 转发给 USB 主机只会往 HID IN 端点注入主机无法理解的报文。
     * 因此不再转发；待 3.7 实现 BLE CTAP 适配层后，把数据接到设备自身的
     * 消息层（而不是 USB）即可。 */
    (void)p_evt->data.p_data;
    break;
```

**注释里已经把意图写清楚了**——等 BLE CTAP 适配层实现后，把数据接到设备自身。
所以这不是要删的东西，而是**待替换的骨架**。

**依赖情况**（已核实）：

| 位置 | 引用 |
|---|---|
| `app_usb.c:12` | 仅 `#include`，**无实际使用** |
| `peripheral.c:19` | `#include` |
| `peripheral.c:256` | `ble_usb_add_service(ble_usb_ServiceEvt)` |
| `peripheral.c:745-790` | 事件回调实现 |
| `peripheral.c:794` | `ble_usb_notify()` |

**结论**：新增 `fido_service.c` 后，`ble_usb_*` 可以整体移除（含 `app_usb.c` 里那行
无用的 include）。**但不必急着删**——先并存，确认 FIDO 服务工作后再清理。

### `SimpleProfile`：先保留一轮

**依赖情况**：`peripheral.c` 里有 6 处调用（`AddService` / 5×`SetParameter` / `RegisterAppCBs`），
都是 WCH 示例的用法，**与 FIDO 无关**。

**为什么建议先保留**：

1. **它是 WCH 示例里唯一验证过「BLE 能被客户端连上」的服务**。
   在 FIDO 服务尚未跑通时，它是排查「蓝牙连接本身是否正常」的**参照物**。
2. 移除它要同时改 6 处代码，**如果新服务同时有问题，会难以区分是哪个改动导致的**。

**建议顺序**：

1. 新增 FIDO 服务（`SimpleProfile` 并存）
2. 用 nRF Connect 确认 FIDO 服务可被发现、`PING` 能通
3. **确认之后**再移除 `SimpleProfile` 与 `ble_usb_*`
4. 移除后重跑一次验证

### 一个需要注意的技术点

`ble_usb_service.c` 用的是 **16-bit UUID**（`ATT_BT_UUID_SIZE`），而 FIDO 需要
**128-bit UUID**（`ATT_UUID_SIZE`，16 字节）：

```c
/* ble_usb_service.c —— 现有的写法 */
const uint8_t ble_usb_ServiceUUID[ATT_BT_UUID_SIZE] = { ... };   /* 2 字节 */

/* fido_service.c —— 需要的写法 */
const uint8_t fido_ServiceUUID[ATT_UUID_SIZE] = {
    /* 0000fffd-0000-1000-8000-00805f9b34fb，小端存放 */
};
```

**WCH 栈的属性表示例全部基于 16-bit UUID**，128-bit 的路径**需要先验证**。
**这应该是阶段 1 的第一个验证点**——如果栈不支持，整个 GATT 层要换实现方式，
越早发现越好。

---

## 建议的实施顺序

综合以上分析，建议调整规划里的阶段划分，在最前面插入一个**独立于 BLE 的重构阶段**：

| 阶段 | 内容 | 可独立验证 |
|---|---|---|
| **0** | 拆分 `ctap_pending_poll()`：推进逻辑下放到 `ctaphid.c`，`ctap.c` 只留 `ctap_reap_dangling_up()` | **是**——纯 USB 环境下跑 `fido2_cred_test.py` 即可 |
| **0.5** | 验证 WCH 栈支持 **128-bit UUID**（写一个最小服务试一次） | **是** |
| 1 | FIDO GATT 服务骨架（`SimpleProfile` 并存） | 是（nRF Connect 能发现） |
| 2 | 帧层 + `PING` | 是 |
| 3 | 接入 `ctap.c`（`MSG` → `GetInfo`） | 是 |
| 4 | UP + KEEPALIVE + CANCEL | 是 |
| 5 | 移除 `SimpleProfile` / `ble_usb_*`，真机验证 | 是 |

**阶段 0 和 0.5 都是低风险、可独立验证的**，且能提前暴露最大的两个不确定性
（架构耦合、128-bit UUID 支持）。**建议先做这两个。**

---

## 仍然需要项目负责人决定的一件事

**并发 UP 的语义**（§1）：

- **选 A2（授权窗口期）**：一次按键可授权两个操作，语义是「用户在场是全局事实」
- **选 A3（先到先得）**：一次按键只授权一个操作，更保守，但行为依赖轮询顺序
- **或选「限制并发」**：BLE 连接时 USB 新请求返回 `CHANNEL_BUSY`，绕开问题

**这是安全策略问题，不是技术问题**——三种都能实现，取决于你对「用户确认」的定义。
