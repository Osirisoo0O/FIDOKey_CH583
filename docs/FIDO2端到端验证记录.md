# FIDO2 端到端验证记录（USB / CTAPHID）

> 补充《详细软件开发计划》阶段五。本文件记录 **USB 侧 FIDO2 流程首次完整跑通**的
> 验证结果，以及打通过程中定位并修复的几个关键缺陷。
> 真机环境：CH583 自制板 + Windows，`python-fido2` 作为主机侧测试工具。

---

## 1. 验证结果

工具：`tools/fido2_cred_test.py`（管理员权限运行，Windows 的 FIDO 驱动会独占设备）

```
[T4] MakeCredential
  [PASS] 注册成功
         fmt        : none
         credId 长度: 32
         signCount  : 0
         UP 标志    : True      <- 用户确认真的生效
         AT 标志    : True      <- 带 attested 数据

[T5] GetAssertion
  [PASS] 登录成功
         signCount  : 1         <- 从 0 递增，签名计数器正常
         UP 标志    : True

[T4-超时] 故意不按键
  [PASS] 按预期超时 (0x3A)
```

配套的 `tools/fido2_ctaphid_test.py`（底层 CTAPHID 命令）：

```
[T2.1] CTAPHID_INIT        [PASS] ×5  (nonce 回显 / newCID / 协议版本 2 / caps)
[T2.2] PING 100 字节        [PASS] ×2  (多帧接收 + 多帧发送)
[T2.3] WINK                [PASS]
[T2.4] 未定义命令           [PASS] 被正确拒绝
[T3]   CTAP2 GetInfo       [PASS]
```

**至此 USB 侧全链路贯通**：USB 枚举 → CTAPHID 分片/重组 → CTAP CBOR 解析 →
UP 闸门（按键 + LED 提示）→ ECDSA 签名 → Flash 存储 → 响应编码。

---

## 2. 打通过程中修复的缺陷

四个缺陷都是**只有在主机真正发起请求时才会暴露**的，此前所有"通过"的测试
（上电自测、按键读取）都不经过这条路径，因此一直没被发现。

### 2.1 HID 用法页不是 FIDO 的（`app_usb.c`）

**现象**：`hid_enum.py` 报"发现 0 个设备"，但设备管理器显示 `Status=OK`。

**根因**：报告描述符抄自 WCH `HID_CompliantDev` 例程，用法页是**厂商自定义 `0xFF00`**。
而主机侧（Chrome / Windows / python-fido2）**一律按 `0xF1D0`（FIDO Alliance）筛选** FIDO 设备。

**影响范围比测试脚本更大**：不只是工具列不出来，**浏览器同样认不出**它是安全密钥。
设备描述符与接口描述符本身合规，所以设备管理器里看起来一切正常——这也是它难被发现的原因。

**修复**：报告描述符改为 CTAP 2.3 §11.2.4 规定的形式，仍是 34 字节
（与配置描述符声明的 `wDescriptorLength(0x0022)` 一致，配置描述符无需改动）：

| 位置 | 原值 | 改为 |
|---|---|---|
| Usage Page | `0xFF00` | **`0xF1D0`** |
| Input 的 Usage | `0x02` | **`0x20`** |
| Input 标志 | `0x81, 0x06`（Data,Var,Rel） | `0x81, **0x02**`（Data,Var,Abs） |
| Output 的 Usage | `0x02` | **`0x21`** |
| Output 标志 | `0x91, 0x06` | `0x91, **0x02**` |

修复后 Windows 将其识别为 **`HID-compliant fido`**。

### 2.2 EP1 IN 端点被永久置为 NAK，响应送不出去（`app_usb.c`）

**现象**：主机发命令后**永久卡住**；设备侧诊断显示 `in=1`（收到了）`proc=1`（处理了）
但 **`out=0`**（响应一帧都没发出）。

**根因**：主机枚举过程中必然发送 `CLEAR_FEATURE(ENDPOINT_HALT, EP1)`，
我们的代码把它实现为"把 EP1 IN 的 `UEP_T_RES` 设为 **NAK**"——**之后没有任何地方再改回 ACK**。
而回 NAK 的 IN 事务不会让主机取走数据，`UIS_TOKEN_IN` 分支里的"取下一帧"逻辑
**永远没有机会被执行**：响应备好了，却没有任何机制递出去。

**修复**：在 `app_usb_hid_process()`（主循环上下文）里，一旦有响应待发就主动把端点置为 ACK：

```c
if (ctaphid_ready_to_load() && ctaphid_next_report_out(pEP1_IN_DataBuf)) {
    R8_UEP1_T_LEN = CTAPHID_HID_REPORT;
    R8_UEP1_CTRL  = (R8_UEP1_CTRL & ~MASK_UEP_T_RES) | UEP_T_RES_ACK;
}
```

> ⚠️ **顺序很关键**：必须**先装载第一帧到 IN 缓冲，再置 ACK**。
> 只置 ACK 不填缓冲的话，主机读到的是**全 0**（ISR 里的取帧逻辑只在收到 IN 令牌后才跑，
> 那时已经太晚）。这一点是实测踩出来的，不是推断。

### 2.3 CTAP2 响应缺少状态码前缀（`ctaphid.c`）

**现象**：`GetInfo` 返回 `CTAP error: 0xA4`。

**根因**：`0xA4` 不是合法 CTAP 状态码，它是 **CBOR "4 对元素 map" 的头字节**。
CTAP2 响应格式是 `[status(1字节)] + [CBOR payload]`，而我们把 CBOR 直接放在了首字节。
**成功路径漏了状态码前缀**，失败路径（`tx_buf[0] = status`）反而是对的。

**修复**：三处成功路径统一改为把 CBOR 写到 `tx_buf + 1`，首字节留作状态码，
长度相应 `+1`：

| 函数 | 改动 |
|---|---|
| `ctaphid_process()` | `ctap_handle_cbor(..., tx_buf + 1, ...)` |
| `ctaphid_reprocess()` | 同上 |
| `ctaphid_ctap_reply()` | `tx_buf[0]=0x00; memcpy(tx_buf+1, body, ...)` |

> 这个缺陷之前被 2.1/2.2 挡着——传输层不通，请求根本走不到成功路径。

### 2.4 CBOR 嵌套 map 的键被当成整数读取（`ctap.c`）

**现象**：`MakeCredential` 返回 `CTAP error: 0x12 - INVALID_CBOR`，
而请求字节经 dump 确认**完全合法**。

**根因**：CBOR 里**两种 map 的键类型不同**，而我们混淆了：

| 位置 | 键类型 | 编码实例 |
|---|---|---|
| CTAP 请求的**顶层** map | **整数** | `01` `02` `03` `04` `07` |
| `rp` / `user` / `pubKeyCredParams` / `excludeList` 内的元素 | **文本** | `"id"` `"alg"` `"type"` |

顶层用了 `cbor_read_uint()`（正确），但**嵌套层也用了它**——
`cbor_read_uint` 读到 `0x63`（text(3) 头）直接返回 `CBOR_ERR_TYPE`，冒泡成 `INVALID_CBOR`。

**关键**：`ctap_check_options()` 是**唯一写对的**（它用 `cbor_read_text` 读键）。
正确做法本来就在代码里，只是没有统一应用。

**修复**：5 处嵌套 map 的键改为按文本读取（照 `ctap_check_options` 的写法）：

| 函数 | 期望的键 |
|---|---|
| `ctap_parse_rp()` | `"id"` |
| `ctap_parse_user()` | `"id"`（值为 bytes） |
| `ctap_check_algs()` | `"alg"` |
| `ctap_check_exclude_list()` | `"id"` |
| `ctap_get_assertion()` 的 allowList 元素 | `"id"` |

### 2.5 LED 相关：从未工作过（`LED.h` / `auth_sm.c` / `main()`）

**现象**：LED 完全不亮、也不闪。

**根因（三个叠加）**：

1. **`HAL_LED` 宏为 `FALSE`** → `HAL_LedInit()` **从未被编译**，
   `HalLedUpdate()` 也从未被 `HAL_LED_EVENT` 驱动。**LED 从来没有工作过**。
2. **`HAL_LedInit()` 里留有官方示例代码** `HalLedBlink(HAL_LED_1, 10, 30, 4000)`——
   会让 LED 在上电后自行慢闪 10 次（约 40 秒）再熄灭，干扰状态指示。
3. **`LED.h` 的 `LED1_BV = BV(15)` 与实物不符**——
   WCH 模板假定 LED 在 PB15，**本板实测在 PB18**。

**修复**：

- `build_flags` 加 `-D HAL_LED=TRUE`
- `HAL_Init()` 之后加 `HalLedSet(HAL_LED_ALL, HAL_LED_MODE_OFF)` 清掉示例闪烁
- `LED.h` 的 `LED1_BV` 改为 `BV(18)`（**改了官方库文件**，见下方说明）
- `auth_sm_init()` 改为复用 `auth_sm_clear()`（原来只清变量、不设 LED，
  导致上电后 LED 停在 `HAL_LedInit()` 设的 OFF）

**引脚是实测确定的**：写了一个临时扫描程序（`#ifdef LED_PIN_SCAN`，
逐引脚输出低电平 1 秒、每 5 个停顿 2 秒分段），观察后确认 **PB18、低电平点亮**。
扫描代码已删除。

> ⚠️ **`LED.h` 是官方库文件**。此前 `HAL_KEY` 的替换都是通过 `build_flags` 绕开的，
> 但这里绕不过去：`LED.c` 直接使用 `LED1_BV` 宏，且该宏没有 `#ifndef` 保护，
> 无法用 `-D` 覆盖。**将来升级官方库时需要重新应用这处改动。**

---

## 3. 经验

1. **内部逻辑全对，不代表对外契约正确。** 上电自测（AES/SHA256/ECDSA/STORE/CBOR）
   全绿、按键读数正确，但设备**从未被主机识别为 FIDO 设备**——
   因为那些测试都不经过"主机如何发现并使用这个设备"这一层。

2. **"设备看起来正常"和"设备能被使用"是两回事。**
   设备管理器 `Status=OK`、驱动绑定正常，但 HID 用法页不是 FIDO 的，主机就不会把它当安全密钥。
   **端到端识别测试要尽量早做**（哪怕只是一句 `list_devices()`）。

3. **主机侧"卡住"这类现象，必须让设备自己报告状态。**
   主机只能给出"超时"这一个事实。往固件里加**收发计数器**（只在 ISR 里自增，
   打印放到主循环）是定位这类问题的关键手段——它一次就把故障分成了三类：
   没收到 / 收到了没处理 / 处理了没发出去。

4. **自测向量容易测不到自己理解错的地方。**
   `cbor_selftest()` 测的是独立数据项，没测"CTAP 实际请求结构"
   （顶层整数键 + 内层文本键混用），所以全绿却在真机第一帧就崩。

5. **多个缺陷会互相遮挡。** 2.3（缺状态码）一直存在，但被 2.1/2.2 挡着，
   直到传输层修好才显形。修完一个，下一个才会露出来——**要预期不止一个**。

6. **不要写在主机侧没有依据的判断。**
   过程中的"LED 在 PB15"、"设备已正常枚举"都曾经是**推断而非实测**，
   后来被证明是错的。硬件相关的结论要以原理图或实测为准。

---

## 4. 遗留

- [ ] **浏览器（Chrome / Edge）实测**：`GETINFO` 的障碍已除，理论上应能识别。
      建议用 `https://demo.yubico.com/webauthn-technical/registration`
      （有明确的 resident key 选项，可选 discouraged）。
      `webauthn.io` 默认 `residentKey: "preferred"`，一般不强制 rk，也可直接试。
- [ ] 生产构建需去掉 `-D DEBUG=1`（否则每次上电都会运行自测、擦写 DataFlash）
- [ ] `signCount` 每次登录擦写 2 页 DataFlash，单槽约 5 万次登录后可能失效（待 5.5 优化）


---

# 更新（本轮）：USB 侧全链路打通 + 浏览器登录待查

> 本节内容的主文档版本见《详细软件开发计划》**5.2.1 / 5.2.2 / 5.2.3**，
> 那里有更完整的缺陷分析与排查清单。这里只做要点补充。

## 结论摘要

| 层面 | 状态 |
|---|---|
| USB 枚举 / CTAPHID 传输 / CTAP 协议 | **全部通过** |
| 经由 `fido2` 的**完整服务端验证**（注册 + 登录） | **两项通过** |
| 浏览器（`webauthn.io`）**登录** | **失败**：签名验证不通过 |
| 浏览器（`webauthn.io`）注册 | 通过 |

## 新增的验证工具

| 脚本 | 用途 | 备注 |
|---|---|---|
| `tools/fido2_server_test.py` | 用 `fido2` 的 `Fido2Server` 走完整服务端验证 | **最关键**，最接近真实站点 |
| `tools/fido2_cred_test.py` | 注册/登录 + 用注册公钥独立验证签名 | |
| `tools/fido2_ctaphid_test.py` | 底层 CTAPHID 命令与 GetInfo | |
| `tools/hid_enum.py` | 枚举 HID 接口及 usage_page | 判断是否被识别为 FIDO 设备 |
| `tools/raw_init.py` | 手工发一次 CTAPHID_INIT，打印原始字节 | 排查 nonce/帧格式 |

**全部需管理员权限**——Windows 的 FIDO 驱动以独占方式持有设备，普通权限枚举不到。

## 关键规律（本轮反复踩到）

1. **CTAP2 的键编码是分层的**：顶层用**整数键**，嵌套结构（`rp`/`user`/`credential`/
   `pubKeyCredParams` 元素）用**文本键**。混淆会得到 `INVALID_CBOR` 或"数据类型无效"。

2. **状态码前缀**：CTAP2 响应是 `[status(1B)] + [CBOR]`。失败路径容易写对、
   成功路径容易漏（我们就是漏的三个成功路径）。

3. **签名格式**：设备返回 **raw `r‖s`（64 字节）**，符合 CTAP2 规范；
   WebAuthn 服务端期望 **ASN.1 DER**。转换是主机的职责。
   **DER 编码要注意**：`r`/`s` 最高位为 1 时须补 `0x00`。

4. **主机侧"卡住"必须让设备自报状态**：往固件加收发计数器（ISR 里只自增，
   打印放主循环）是定位这类问题的关键手段——它把故障分成"没收到/收到没处理/处理了没发出"。

5. **多个缺陷会互相遮挡**：状态码前缀缺陷一直存在，但被传输层的两个故障挡着，
   直到传输修好才显形。

## 串口调试开关

```ini
; platformio.ini 的 build_flags 里加：
-D CTAPHID_DUMP
```

打开后会打印收到的 CTAP 请求与发出的响应全文（每 32 字节一行）。
**会阻塞串口，仅排障时使用**；默认关闭。

## 遗留技术债

- [ ] **浏览器登录的签名校验**（当前唯一未通项，详见计划 5.2.3）
- [ ] `signCount` 每次登录擦写 2 页 DataFlash，单槽约 5 万次登录寿命（待 5.5 优化）
- [ ] 生产构建须去掉 `-D DEBUG=1`（否则每次上电运行自测、擦写 DataFlash）
- [ ] `lib/BLE_HAL/include/LED.h` 被改过（`LED1_BV` 15→18），**升级官方库时需重新应用**
- [ ] 临时诊断已改为宏控制（`CTAPHID_DUMP`），确认无需再排查后可整段删除

## 运行时配置现状

```ini
; platformio.ini build_flags
-D DEBUG=1          ; 开发期：上电自检
-D HAL_KEY=TRUE     ; 官方按键服务 → KEY2 = PB4
-D HAL_LED=TRUE     ; 官方 LED 服务 → LED1 = PB18（已改 LED.h）
```

硬件约定（本板实测）：

| 功能 | 引脚 | 说明 |
|---|---|---|
| 按键（UP） | **PB4** | 官方 `KEY2`，低电平按下 |
| LED | **PB18** | 低电平点亮（官方模板默认 PB15，已修正） |
| 串口 | PA9 (UART1 TX) | 115200 8N1 |
