# FIDOKey_CH583

基于 **WCH CH583**（RISC-V 青稞 V4，RV32IMAC）实现的 **FIDO2 / WebAuthn 安全密钥**。

设备通过 **USB HID** 提供标准 CTAP2 能力，可在浏览器中完成注册与登录；**BLE 侧也实现了
完整的 CTAP2 GATT 传输**（设备侧已通过脚本化客户端逐项验证，见下文"BLE 侧"一节）。
内置 P-256 密钥生成与签名、用户在场确认（按键 + LED 提示）、加密的凭证存储。

---

## 目录

- [特性与当前状态](#特性与当前状态)
- [硬件要求](#硬件要求)
- [目录结构](#目录结构)
- [构建与烧录](#构建与烧录)
- [使用](#使用)
- [配置开关](#配置开关)
- [测试](#测试)
- [架构简述](#架构简述)
- [已知限制与待办](#已知限制与待办)
- [文档索引](#文档索引)

---

## 特性与当前状态

| 功能 | 状态 |
|---|---|
| USB 枚举（HID / FIDO） | 已完成 |
| CTAPHID 传输层（含多帧收发、KEEPALIVE） | 已完成 |
| CTAP2 `authenticatorGetInfo` | 已完成 |
| CTAP2 `authenticatorMakeCredential` | 已完成 |
| CTAP2 `authenticatorGetAssertion` | 已完成 |
| 用户在场确认（UP）——按键 + LED 提示 + 超时 | 已完成 |
| ECDSA P-256 签名（micro-ecc） | 已完成 |
| 凭证加密存储（AES + UID 派生密钥） | 已完成 |
| 上电自测（AES / SHA256 / ECDSA / STORE / CBOR） | 已完成 |
| CTAP2 `credentialManagement` | 未实现（需 PIN/UV 认证，本实现无 PIN） |
| Resident Key（可驻留凭证） | 未支持，请求 `rk=true` 时按规范拒绝（`0x2B`） |
| Attestation | `none`（`attStmt` 为空 map） |
| BLE 侧 CTAP 传输（GATT） | **已实现并验证**，但主流客户端接入受阻（见下）|

**实机验证**：`webauthn.io` 与 `demo.yubico.com` 两个站点的注册与登录均正常。

代码规模约 **5200 行**（`src/` + `include/`，不含 SDK 移植文件与第三方库）。
默认构建占用：**Flash 35.1%**（172740 / 491520 字节）、**RAM 79.0%**（25896 / 32768 字节）。

> RAM 占用偏高，其中 3072 字节是栈（micro-ecc 的 P-256 运算需要）。

### 凭证存储

使用片内 DataFlash，**每条凭证固定占 2 页 = 512 字节**，共 **62 个槽**：

| 项 | 值 |
|---|---|
| 槽大小 | 512 字节（2 × 256 页） |
| 槽数量 | 62 |
| 起始偏移 | `0x0100`（256 对齐） |
| 私钥保护 | AES 加密，密钥由芯片 UID + 盐值现场派生（**不落盘**） |

分区布局见 [`include/flash_layout.h`](include/flash_layout.h) 与
[`ldscripts/SecureKey_CH58x.ld`](ldscripts/SecureKey_CH58x.ld)。

---

## 硬件要求

- **主控**：CH583（或 CH582/CH581，需相应调整链接脚本）
- **下载器**：WCH-Link（`upload_protocol = wch-link`）

### 引脚约定（本板实测）

| 功能 | 引脚 | 说明 |
|---|---|---|
| 按键（用户在场确认） | **PB4** | 官方 `KEY1`/`KEY2` 中的 **KEY2**，低电平按下 |
| LED（状态指示） | **PB18** | **低电平点亮**。WCH 模板默认 PB15，本项目已修正 |
| 串口日志 | **PA9**（UART1 TX） | 115200 8N1 |
| USB | 专用引脚 | 设备身份 `VID_1A86 & PID_E008` |

> **LED 引脚是按实物扫描确定的**，不是照抄官方模板。若更换硬件，请重新确认。
> 详见 `lib/BLE_HAL/include/LED.h` 中 `LED1_BV` 的改动说明。

### LED 状态语义

| 时机 | 表现 |
|---|---|
| 上电 / 空闲 | 常亮（就绪） |
| 收到需要用户确认的请求 | **慢闪 1Hz**（此时按 PB4） |
| 已取得用户确认，正在处理 | 快闪 5Hz |
| 等待超时 / 错误 | 闪 3 次后回到常亮 |

---

## 目录结构

```
.
├── platformio.ini              PlatformIO 配置（构建开关在此）
├── ldscripts/
│   └── SecureKey_CH58x.ld      自定义链接脚本（Flash 分区、栈大小）
├── include/                    本项目头文件
│   ├── ctap.h                  CTAP2 命令与状态码
│   ├── ctaphid.h               CTAPHID 传输层常量
│   ├── cbor_lite.h             精简 CBOR 编解码器
│   ├── secure_store.h          凭证加密存储
│   ├── flash_layout.h          DataFlash 分区布局
│   ├── storage.h               存储后端抽象（便于迁移到 SPI NOR）
│   ├── auth_sm.h               UP 等待状态机
│   ├── app_ecdsa.h             ECDSA P-256 封装
│   ├── app_crypto.h            AES / SHA-256 / 随机数
│   ├── cred_mgr.h              凭证管理
│   ├── selftest.h              上电自测
│   └── debug_log.h             串口日志开关
├── src/                        实现
│   ├── ctap.c                  CTAP2 命令处理（最大文件）
│   ├── ctaphid.c               CTAPHID 分片/重组与命令分发
│   ├── cbor_lite.c             CBOR 编解码
│   ├── secure_store.c          凭证的加密存取
│   ├── storage.c / storage_eeprom.c   存储后端
│   ├── cred_mgr.c              凭证查找与管理
│   ├── auth_sm.c               UP 状态机（按键消抖、超时、LED）
│   ├── app_ecdsa.c             micro-ecc 封装
│   ├── app_crypto.c            AES / SHA-256 / 熵源
│   ├── app_usb.c               USB 描述符与端点处理
│   ├── selftest.c              自测入口
│   ├── peripheral_main.c       主程序入口与主循环
│   └── peripheral.c / gattprofile.c / devinfoservice.c / ble_usb_service.c
│                               BLE 外设（来自 WCH 例程，本项目做了裁剪）
├── lib/
│   ├── micro-ecc/              ECDSA 实现（源码未修改，仅启用 secp256r1）
│   ├── BLE_HAL/                WCH HAL（按键 / LED 服务）
│   └── BLE_LIB/                WCH BLE 协议栈
├── tools/                      测试脚本（Python）
├── docs/                       开发文档
└── test/                       测试相关
```

---

## 构建与烧录

### 环境准备

- Visual Studio Code + PlatformIO 插件
- 或命令行：`pio`（Python 3）

### 构建

```bash
pio run
```

### 烧录

```bash
pio run -t upload
```

### 串口日志

```bash
pio device monitor -b 115200
```

日志开关见 [`include/debug_log.h`](include/debug_log.h) 的 `SK_LOG_ENABLE`（默认关闭）。
它是阻塞式输出，**开着会影响 USB 时序，正式使用务必关闭**。

---

## 使用

### 浏览器

1. 烧录后插到目标机器（**直插主板 USB 口**，避免廉价 Hub）
2. 打开任意支持 WebAuthn 的站点，例如：
   - <https://webauthn.io>
   - <https://demo.yubico.com/webauthn-technical/registration>
3. 注册或登录时，**LED 慢闪表示等待确认，此时按 PB4**
4. 15 秒内未按键将超时（返回 `ACTION_TIMEOUT 0x3A`）

> **注意**：本实现不支持 Resident Key。站点若强制要求（`residentKey: "required"`），
> 会被拒绝并返回 `0x2B`。请在站点侧选择 `discouraged` / 非必须。

### Python 脚本

需要 **管理员权限**（Windows 的 FIDO 驱动以独占方式持有设备，普通权限枚举不到）：

```bash
python tools/fido2_cred_test.py      # 注册 / 登录 + 独立签名验证
python tools/fido2_server_test.py    # 完整服务端验证（最接近真实站点）
```

---

## 配置开关

全部在 `platformio.ini` 的 `build_flags`，或在命令行用 `-D` 覆盖。

| 开关 | 默认 | 说明 |
|---|---|---|
| `DEBUG` | `1` | 上电自测。**会擦写 DataFlash，生产构建须置 0** |
| `HAL_KEY` | `TRUE` | 启用官方按键服务（`KEY2` = PB4） |
| `HAL_LED` | `TRUE` | 启用官方 LED 服务（`LED1` = PB18） |
| `SK_LOG_ENABLE` | `0` | 串口日志（见 `debug_log.h`） |
| `CTAPHID_DUMP` | 未定义 | 打印 CTAP 请求/响应全文，**排障用，会阻塞串口** |
| `SK_SIG_DER` | `1` | 签名输出格式，见下 |
| `BLE_BUFF_MAX_LEN` | `260` | BLE 数据包缓冲，`ATT_MTU = 值 - 4` → 256；`fidoControlPointLength = 253`。**必须容得下客户端的完整请求** |
| `PAIRING_HOLD_MS` | 随 `DEBUG` 变 | **按 PB4 进入配对模式所需的时长**：`DEBUG=1` 时为 **200ms**（便于反复排查），否则 **5000ms**（防误触发）。见 `src/peripheral.c` 顶部 |

### `SK_SIG_DER`：签名格式（重要）

| 值 | 输出 | 适用 |
|---|---|---|
| `1`（默认） | ASN.1 DER | **浏览器可用** |
| `0` | raw `r‖s`（CTAP2 / COSE 规范） | 规范符合性；`fido2` 脚本验证规范行为时 |

**背景**：按 CTAP2 / COSE (RFC 8152) 规范，设备返回 raw `r‖s`，转 DER 是主机
（Windows / Chrome）的职责。但实测本平台的主机链路**不做该转换**，浏览器与
服务端均报签名无效；设备改为直接输出 DER 后站点恢复正常。

**这是规范层面的让步**，换平台（macOS / Linux / 其他浏览器）测试时，
建议先用 `SK_SIG_DER=0` 对照。完整分析见
《[详细软件开发计划](docs/详细软件开发计划.md)》5.2.3。

```bash
pio run                                            # DER 模式（浏览器可用）
PLATFORMIO_BUILD_FLAGS="-D SK_SIG_DER=0" pio run   # 规范 raw 模式
```

---

## 测试

### 脚本工具（`tools/`）

| 脚本 | 用途 | 权限 |
|---|---|---|
| `fido2_cred_test.py` | 注册 / 登录，并用注册公钥**独立验证签名** | 管理员 |
| `fido2_server_test.py` | 用 `fido2` 的 `Fido2Server` 走**完整服务端验证** | 管理员 |
| `fido2_ctaphid_test.py` | 底层 CTAPHID 命令（INIT / PING / WINK）与 GetInfo | 管理员 |
| `hid_enum.py` | 枚举 HID 接口及 `usage_page`，判断是否被识别为 FIDO 设备 | 管理员 |
| **`ble_gatt_client.py`** | **BLE FIDO GATT 客户端验证（脚本化，判定设备侧是否可用）** |
| `raw_init.py` | 手工发一次 CTAPHID_INIT，打印原始字节 | 管理员 |

### 上电自测

`DEBUG=1` 时上电会运行自测并打印结果：

```
--- selftest ---
AES    = 0
SHA256 = 0
ECDSA  = 0
STORE  = 0
CBOR   = 0
passed 5/5
```

### 排查手段

- **串口日志**：`SK_LOG_ENABLE=1`（按键变化、UP 等待/授予/超时、命令收发）
- **报文全文**：`-D CTAPHID_DUMP`（打印 CTAP 请求与响应，每 32 字节一行）
- **设备状态**：`chrome://device-log`、Windows 事件日志
  `Microsoft-Windows-WebAuthN/Operational`

---

## 架构简述

```
                        ┌─────────────────────────┐
     浏览器 / 主机  ───▶ │  USB HID (CTAPHID)      │  app_usb.c
                        │  分片 / 重组 / KEEPALIVE │  ctaphid.c
                        └───────────┬─────────────┘
                                    │ CBOR
                        ┌───────────▼─────────────┐
                        │  CTAP2 命令处理          │  ctap.c
                        │  GetInfo / MakeCredential│
                        │  / GetAssertion          │
                        └───────┬─────────┬───────┘
                                │         │
                ┌───────────────▼──┐   ┌──▼──────────────┐
                │ UP 状态机         │   │ CBOR 编解码      │  cbor_lite.c
                │ 按键 + LED + 超时 │   │                 │
                └──────────────────┘   └─────────────────┘
                                │
                ┌───────────────▼─────────────────────┐
                │ 凭证存储（加密） / ECDSA / AES / SHA │
                │ secure_store.c / app_ecdsa.c / ...  │
                └─────────────────────────────────────┘
```

**几个设计要点**：

- **UP 采用可重入重放**：命令在任何副作用之前过闸门，未取得 UP 则返回
  `PENDING`；CTAPHID 保留报文不响应，主循环在取得 UP 时重跑。因首次调用未写
  Flash，重放安全，无需保存挂起上下文。
- **主存储密钥不落盘**：由芯片 UID + 盐值现场派生。
- **存储后端抽象**（`storage.h`）：为后续迁移到 SPI NOR 铺路。
- **micro-ecc 源码零修改**：RISC-V 走纯 C 路径，仅启用 `secp256r1`。
- **栈 3072 字节**：micro-ecc 的 P-256 运算栈需求较大（见链接脚本）。

---

## 已知限制与待办

### 功能限制

- **不支持 Resident Key**：请求 `rk=true` 时返回 `0x2B`（如实拒绝，非静默忽略）
- **不支持 `credentialManagement`**：该命令要求 PIN/UV，本实现无 PIN
- **Attestation 为 `none`**：不提供 `packed` 等可验证的 attestation
- **BLE 侧 CTAP 传输：设备侧完整实现并验证，但客户端受平台限制**
  - **设备侧已通过脚本化 GATT 客户端完整验证**（`tools/ble_gatt_client.py`，
    基于 `bleak`）：特征发现、版本位读写、`CPLength`、订阅通知、`PING`、
    `GetInfo`、**`MakeCredential`、`GetAssertion` 八项全通** —— 覆盖 CTAP2
    的全部公开命令，且与 nRF Connect 手工测试结果一致
  - **`tools/ble_dump_gatt.py` 把设备的 GATT 库原样打印**（不做 UUID 查找，
    避免循环论证）：**四个服务（GAP/GATT/DIS/FIDO）、四个特征、CCCD 描述符，
    UUID 全部是规范值** —— 设备侧无任何不合规之处
  - **`tools/ble_probe_windows.py`** 用 6 种"连接姿势"复现 Windows 的行为，
    **在干净配对状态下全部通过**（含特征读写、订阅）
  - **Windows（WebAuthn）无法完成经典 BLE FIDO 流程**，且已有**本机三层证据**：
    - **CtapSrv 有 BLE 提供程序，但创建 FIDO 上下文时报 CNG 层错误
      `0x80090011`（`NTE_NOT_FOUND`）**，`AAGuid` 恒为全零
      （= 一个 CTAP 命令都没发出去）
    - **系统设备树里只注册为蓝牙 LE 设备**（`DEVPKEY_Device_Service: BthLEEnum`），
      **没有任何 FIDO / WebAuthn 设备接口**
    - **必须先做系统级蓝牙配对**，否则浏览器弹窗**完全不出现蓝牙选项**
    - **失败点在 `webauthn.dll`，与浏览器无关** ——
      **Windows 自带的 FIDO 管理界面同样卡在"打开蓝牙密钥或者插入 USB"**，
      而它与 Edge 共用同一套 `webauthn.dll`；`bleak` 之所以能通，
      正因为它**绕过** `webauthn.dll` 直连 WinRT BLE API
    - **设备确实进入了候选池**（弹窗与完整请求日志补证）：
      - **弹窗是"传输选择器"的提示（"打开蓝牙密钥或将其插入 USB"），
        不是 Windows Hello 的 PIN/指纹界面** —— 后者意味着平台认证器被选中、
        BLE 设备根本没进候选；而前者说明它在**等一个 BLE/USB 安全密钥**
      - **CtapSrv 并行拉起 BLE / USB / NFC 三个提供程序**，
        `DevicePath: ble:383b267e348e_0021`、`PairedName: SecureKey` 都正常
      - **请求里的 `filterHybridTransport = false`** —— Edge 并未过滤混合传输，
        BLE 路径是开放的
      - **`GetPluginAuthenticatorList` 返回 "Microsoft Password Manager"** ——
        Win11 24H2+ 的插件认证器机制；候选池实为
        **平台（Hello）+ 插件（Password Manager）+ 传输提供程序（USB/NFC/BLE）** 三类
      - 失败码有两种：**`0x80090011`（NTE_NOT_FOUND，服务列表里找不到 FIDO 服务）**
        与 **`0x80070141`（ERROR_DEVICE_NOT_CONNECTED，链路未建立，位置 `Unreachable`）**
      - 整个流程约 20 秒后由**用户取消**（`0x4C7`），而非 CTAP 层超时
        （请求给的是 `TimeoutMilliseconds: 300000`）
  - **Android** 系统**显式限制**第三方访问 FIDO GATT 服务（`isFidoSrvcUuid`）
  - **Chrome 自带的 BLE 认证器支持已于 2020 年移除**，业界转向 caBLE
  - 外部记录一致：**Mozilla Bug 1768622**（"只提示插入 USB"）、Windows 11
    BLE 密钥管理界面的已知回归（FIDO Dev 邮件列表 2025-07）
  - **`webauthn.dll` 层面的已知限制**（kanidm/webauthn-rs 的反汇编研究）
    与**逐条实测结论**：
    - `MicrosoftCtapBleProvider` **确实存在**（Win10 1903+ / Win11 都有），
      而 `_BleCreateContext` 正是它的一部分 —— 即我们失败的那个函数
    - **"Windows 阻止非管理员访问 BTLE FIDO 令牌"** —— **实测不适用**：
      以管理员身份运行 Edge 后行为完全不变（该限制针对第三方应用经普通
      蓝牙 API 访问，而 `MicrosoftCtapBleProvider` 在系统服务内运行）
    - **"某些版本的 `webauthn.dll` 不带 BLE 支持"** —— **实测排除**：
      本机 `10.0.26100.9278`（Windows 11 25H2 / `10.0.26200`），极新
    - **"蓝牙适配器不支持 advertising"** —— **实测排除**：
      本机为 Intel 无线 Bluetooth，能同时承载多个设备的 GATT 服务
    - 功能标志 **`FidoBleAddressRotation` 仅 Windows 11 存在**，
      也用在 `_BleCreateContext` 中 —— 目前唯一未排除的具体机制，
      但因果关系不明确（见文档）
  - **依 Microsoft Learn 的 passkeys 文档做过延伸排查，全部正常**：
    Passkey 访问隐私开关（Win11 24H2+ 新增）、Windows Hello 已配置、
    无企业蓝牙策略（`HKLM\...\Bluetooth` 为空）、`Get-Tpm` 各项均 `True`。
    **该文档列出的 USB 提示常见原因（无 TPM / Hello 未配置 / PC 无蓝牙）
    在本机三条都不成立** —— 说明本项目的现象不在其覆盖范围内。
  - **设备侧自加事件也不干扰客户端发现**：用受控实验关掉连接后自启的
    `SBP_PERIODIC_EVT` / `SBP_READ_RSSI_EVT` 与 CCCD 订阅后的主动参数更新，
    **行为逐行不变**（它们只走 HCI 层，不碰 GATT）

  **结论：根因在平台侧，非本项目实现缺陷。**
  需要在真实客户端上验证时，建议走 **Linux + `fido2ble`**
  （把 BLE FIDO 桥接成 USB HID，绕开平台限制），
  或用 **FIDO Conformance Tool** 验证设备合规性。
  完整的排查过程（**含已排除的 17 个假设**、Windows 侧三层证据链、
  `webauthn.dll` 内部机制调研）见
  [BLE 侧实现规划 §客户端兼容性的根因](docs/BLE侧实现规划.md)
- **`up=false` 的探测请求会直接放行**：不做用户确认（符合浏览器自动填充探测的需求）

### 待办

- [ ] 补充测试：`rk` 拒绝（`0x2B`）、快速插拔、等待中拔 USB、取消立即生效、压力测试
- [ ] **`signCount` 的 Flash 寿命**：每次登录擦写 2 页 DataFlash，单槽约 5 万次登录
      后可能失效。计划改为页内追加（擦除频率降约 64 倍）
- [ ] 生产构建去掉 `-D DEBUG=1`
- [ ] 跨平台验证（macOS / Linux / Edge / Firefox），注意 `SK_SIG_DER` 开关
- [ ] **BLE 客户端验证**：需 Linux（`fido2ble`）或旧版 Android，绕开当前平台限制

### 需要注意的维护点

- **`lib/BLE_HAL/include/LED.h` 被改动过**（`LED1_BV` 由 `BV(15)` 改为 `BV(18)`）。
  升级 WCH 官方库时**需要重新应用**这处改动。
- 本项目在规范层面做了两处让步，均已在文档中标注：签名输出 DER（`SK_SIG_DER`）、
  以及固定使用 `attestation = none`。

---

## 文档索引

| 文档 | 内容 |
|---|---|
| [详细软件开发计划](docs/详细软件开发计划.md) | 开发计划与各阶段进度；**5.2.1~5.2.3** 为 USB 侧验证结果与缺陷分析 |
| [BLE 侧实现规划](docs/BLE侧实现规划.md) | BLE CTAP2 传输的规范要点、设计、**实施结果与客户端兼容性分析** |
| [BLE 侧实现分析](docs/BLE侧实现分析.md) | 三个决策点的方案对比与推荐；含反向依赖等架构问题分析 |
| [FIDO2 端到端验证记录](docs/FIDO2端到端验证记录.md) | 验证过程、关键规律、签名格式专题 |
| [真机测试步骤](docs/真机测试步骤.md) | T1~T7 测试清单与结果记录、问题排查 |
| [基于 CH583 的 FIDO2 安全密钥开发](docs/基于CH583的FIDO2安全密钥开发.md) | 总体设计 |
| [USB Code 43 排查总结](docs/USB_Code43_排查总结.md) | 枚举失败问题的定位过程 |
| [USB Code 45 排查总结](docs/USB_Code45_排查总结.md) | 设备未连接问题的定位过程 |

---

## 许可与来源

- WCH 官方 SDK、`BLE_HAL` / `BLE_LIB`：遵循其原始许可（Apache-2.0 等）
- `lib/micro-ecc`：遵循其原始许可，本项目未修改其源码
- 本项目自行编写的部分：见仓库内文件头说明
