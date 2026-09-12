# SecureKey_WCH — USB 代码 43 问题排查与修复总结

> 项目：基于 CH583 的 FIDO2 安全密钥（BLE + USB 双模，USB 侧为 CTAPHID/HID）
> 本文件记录 USB 设备枚举报 **代码 43 / "请求 USB 设备描述符失败"** 的完整排查过程与最终修复（承接 `USB_Code45_排查总结.md`）。
> 修复提交：`8d2c8b7 hid pass`

---

## 1. 现象

- 烧录固件后，Windows 设备管理器显示：
  - **"由于该设备有问题，Windows 已将其停止。(代码 43)"**
  - **"请求 USB 设备描述符失败。"**
- 与历史上的 **代码 45**（"这个硬件设备没有连接到计算机"）不同：
  - 代码 45 = 主机**物理层看不到设备**（当时结论是 USB2 控制器引脚没接到 USB 座）
  - **代码 43 + 描述符请求失败 = 主机能看到 D+ 上拉、完成了端口复位，但拿不到描述符**
- 环境：PlatformIO，board `genericCH583M`，framework `noneos-sdk`，`upload_protocol = wch-link`

---

## 2. 排查方法：用两条基线做增量分析

排查没有从零猜测，而是建立了两条**已知正确的基线**做对比：

| 基线 | 说明 |
|---|---|
| `H:\WCH32\CH583EVT\EXAM\USB\Device\HID_CompliantDev` | WCH 官方示例，纯 USB、实测可正常枚举（用户指定参考） |
| `git show HEAD:src/peripheral_main.c` / `src/app_usb.c`（`d21f1c6 usb function pass`） | 本项目自己的 USB1 + BLE 版本，历史上可枚举 |

**关键一步是核对基线本身，而不是凭 git diff 的上下文推断。** 例如一开始误以为"HEAD 版本把 BLE 初始化注释掉了"，实际读 `git show HEAD:src/peripheral_main.c` 后确认：

```c
PRINT("%s\n", VER_LIB);
CH58X_BLEInit();
HAL_Init();
GAPRole_PeripheralInit();
Peripheral_Init();
app_usb_init();
```

即 **HEAD 能枚举的版本本身就带着 BLE 初始化，且 USB 在 BLE 之后初始化**。所以"BLE 与 USB 冲突"被排除，`app_usb_init()` 的调用位置也不需调整。

于是差异范围被压缩到：`app_usb.c` 的 HID 改造 + `peripheral.c` + 三个新增调用（`app_key_init()` / `app_led_init()` / `crypto_init()`）。

---

## 3. 根因一（决定性）：`read_chip_uid()` 访问 CH583 未映射地址

### 3.1 问题代码

`src/app_crypto.c`：

```c
int8_t read_chip_uid(uint8_t *uid) {
    // CH583的唯一ID位于0x1FFFF000-0x1FFFF00B
    // 使用寄存器读取
    uint32_t *uid_ptr = (uint32_t *)0x1FFFF000;

    uid[0] = uid_ptr[0];
    uid[1] = uid_ptr[0] >> 8;
    ...
}
```

`0x1FFFF000` 是 **CH32V 系列（Cortex-M 内核）的系统信息区地址**（如 CH32V307 的 UID 在 `0x1FFFF7E8` 一带）。

**CH583 是 RISC-V（青稞内核），地址映射只有：**

| 区域 | 地址 |
|---|---|
| Code Flash | `0x00000000` ~ `0x0007FFFF` |
| SRAM | `0x20000000` ~ `0x20007FFF` |
| 外设 | `0x40000000` ~ |
| 内核私有 | `0xE0000000` ~ |

`0x1FFFF000` **没有任何映射**。

### 3.2 为什么会导致代码 43

调用链：

```c
// peripheral_main.c
app_usb_init();     // 内部 PFIC_EnableIRQ(USB_IRQn)，D+ 上拉生效，设备对主机可见
app_key_init();
app_led_init();
crypto_init();      // ← 这里读未映射地址
```

- `app_usb_init()` 之后 USB 已对主机可见，Windows 立刻开始复位 + 发 `GET_DESCRIPTOR`
- 紧接着执行的 `crypto_init()` → `read_chip_uid()` 读未映射地址，可能触发**总线异常**
- CH58x 启动文件里未定义的异常处理是死循环，且进入异常后中断被屏蔽

**结果：已使能的 USB 中断再也得不到响应 → 主机读不到描述符 → 代码 43 / "请求 USB 设备描述符失败"。**

### 3.3 修复

改用 SDK 官方 API `GET_UNIQUE_ID()`（声明在 `CH58x_flash.h`，内部通过 `FLASH_EEPROM_CMD(CMD_GET_ROM_INFO, ROM_CFG_MAC_ADDR, ...)` 读取 ROM 配置区，写 8 字节并要求 4 字节对齐）：

```c
int8_t read_chip_uid(uint8_t *uid) {
    __attribute__((aligned(4))) uint8_t rom_info[8];

    GET_UNIQUE_ID(rom_info);        // 读取 8 字节芯片信息（要求 4 字节对齐）
    memcpy(uid, rom_info, 8);
    memset(uid + 8, 0, 4);          // 其余补 0

    return 0;
}
```

> **交叉验证**：这是相对 HEAD（`usb function pass`，可枚举）**唯一新增的硬件访问**——HEAD 中没有 `crypto_init()` 调用，自然也没有这次非法访问。

---

## 4. 根因二（必要但不充分）：`SET_ADDRESS` 后未写入 `R8_USB_DEV_AD`

修完根因一之前，第一轮修复命中的是这个缺陷，但它单独并不足以解决现象（修完仍报代码 43），所以列为次要根因。

### 4.1 问题代码

`src/app_usb.c` 的 `USB_DevTransProcess()`，`UIS_TOKEN_IN` 分支：

```c
case USB_SET_ADDRESS:
    SetupReqLen = (pSetupReqPak->wValue) & 0xff;
    R8_UEP0_CTRL = UEP_R_RES_ACK | UEP_T_RES_NAK;
    R8_UEP1_CTRL = UEP_R_RES_ACK | UEP_T_RES_NAK | RB_UEP_AUTO_TOG;
    R8_UEP2_CTRL = UEP_R_RES_ACK | UEP_T_RES_NAK | RB_UEP_AUTO_TOG;
    Ready = 1;
    break;
```

**全文件对 `R8_USB_DEV_AD` 的写操作只有 `BUS_RST` 里的 `R8_USB_DEV_AD = 0;`** —— 设备地址从未被真正写入硬件。

### 4.2 后果

主机在 `SET_ADDRESS` 之后改用新地址寻址，而设备**仍只应答地址 0**：

- 地址 0 阶段读取设备描述符前 8 字节 → 成功
- `SET_ADDRESS(addr)` 后读取完整描述符 / 配置描述符 → 无响应 → 枚举失败

这也是历史上"短暂出现过设备随后消失"的原因。

### 4.3 修复（与官方 `HID_CompliantDev` 一致）

```c
case USB_SET_ADDRESS:
    /* SET_ADDRESS 的状态阶段完成后才把设备地址写入 R8_USB_DEV_AD
     * (SetupReqLen 在 SETUP 阶段已保存新地址的低 8 位) */
    R8_USB_DEV_AD = (R8_USB_DEV_AD & RB_UDA_GP_BIT) | (SetupReqLen & 0x7F);
    R8_UEP0_CTRL = UEP_R_RES_ACK | UEP_T_RES_NAK;
    Ready = 1;
    break;
```

同时把 SETUP 阶段的同名分支按官方简化为"只暂存地址"：

```c
case USB_SET_ADDRESS:
    /* 官方写法：这里只暂存主机分配的地址，
     * 等状态阶段结束后（下一条 EP0 IN 令牌）再写入 R8_USB_DEV_AD */
    SetupReqLen = (pSetupReqPak->wValue) & 0xff;
    Ready = 1;
    break;
```

> 注意顺序：地址必须在**状态阶段（ZLP）之后**才生效，这是 USB 规范要求，不能提前写。

---

## 5. 一并修复的 HID 数据通路 / CTAPHID 协议缺陷

排查过程中发现，即使枚举通过，HID 通路仍然不可用。这些属于实现错误，非新功能：

| 位置 | 问题 | 修复 |
|---|---|---|
| `UIS_TOKEN_IN \| 1` / `UIS_TOKEN_OUT \| 1` | EP1 已使能 `RB_UEP_AUTO_TOG`（硬件翻转 DATA0/DATA1），ISR 里又手动 `^= RB_UEP_T_TOG` / `^= RB_UEP_R_TOG`，**toggle 双重翻转让主机丢弃所有数据包** | 去掉手动翻转，改用显式 `UEP_T_RES_ACK/NAK`；空闲时回 NAK 而不是发 0 长度 HID 报告（0 长度 input report 违反 HID 规范） |
| `hid_in_sent` | 初值 0 表示"未发送"，但 `app_usb_hid_send()` 把 `== 1` 当"忙"→ 语义反转。`BUS_RST` 里置 1，导致**复位后任何响应都发不出去**（死锁，只能发一帧） | 统一为 `1 = 空闲`（初值 1、`BUS_RST` 置 1），忙判断改为 `hid_in_sent == 0` |
| CTAPHID 命令码 | 全部不符合 FIDO 规范：`PING=0x06 / INIT=0x02 / MSG=0x10 / CBOR=0x11 / WAKE=0x07 / KEEPALIVE=0x4C / CANCEL=0x14` | 按规范重定义：`PING=0x01 / MSG=0x03 / LOCK=0x04 / INIT=0x06 / WINK=0x08 / CBOR=0x10 / CANCEL=0x11 / KEEPALIVE=0x3B`，协议版本 `CTAPHID_PROTOCOL_VERSION=2` |
| `app_usb_hid_process()` | 响应帧缺 4 字节 Channel ID 前缀；INIT 响应格式不符规范；PING 按 `hid_out_len` 发送但只填了 `hid_out_len-4` 字节（**越界多发 4 字节**） | 响应统一为 `ChannelID(4) + (cmd \| 0x80) + payload`；INIT 改为规范 22 字节；PING 长度钳制；`hid_out_len < 5` 直接丢弃 |
| `include/app_usb.h` | include guard 写成 `_APP_USBE_H`（拼写错误，保护失效）；`USBSendData` 声明被删但 `peripheral.c` 仍在调用；`app_usb_hid_has_data` 只有声明无定义 | 修正为 `_APP_USB_H`、补回 `USBSendData` 声明、删除空声明、补 `#include "stdint.h"` |
| `include/app_key.h` | 缺 `app_key_has_event` / `app_key_clear_event` 声明（`peripheral.c` 隐式声明） | 补声明（编译器警告随之清零） |

---

## 6. 与官方 `HID_CompliantDev` 的逐项比对结论

| 项目 | 结论 |
|---|---|
| `MyDevDescr`(18B) / `MyCfgDescr`(41B) / `HIDDescr`(34B) / 语言·厂家·产品字符串 | **逐字节一致**，无需改动 |
| `USB_DeviceInit()` | 同一份 SDK 实现（`Peripheral/ch58x/src/CH58x_usbdev.c`） |
| `USB_IRQHandler` | 均为 `interrupt("WCH-Interrupt-fast")` + `section(".highcode")` |
| EP0 `USB_GET_DESCRIPTOR` 的 SETUP / IN 两段（含 `SetupReqLen`、`pDescr` 的扣减与前进） | 一致 |
| EP0 `USB_SET_ADDRESS` | 已对齐（见 §4.3） |
| EP1~EP3 的 DATA0/DATA1 翻转 | 官方用**手动** `^= RB_UEP_x_TOG`；本项目用 `RB_UEP_AUTO_TOG`（硬件翻转）。两者各自自洽，已复核 `BUS_RST` / `SET_ADDRESS` / ISR 三处状态一致，**未混用** |
| `main()` 初始化顺序 | 官方无 BLE；本项目 BLE 先、USB 后，与可枚举的 HEAD 一致，无需改动 |

排查中顺带确认的两个非问题：

- `app_key_init()` 只清软件状态，不碰 GPIO；
- `app_led_init()` / `HalLedSet()` 只操作 PB15（LED1），与 USB 引脚无冲突；且 `HAL_KEY` / `HAL_LED` 宏为 `FALSE`，`HAL_KeyInit()` / `HAL_LedInit()` 根本没被编译进去。

---

## 7. 验证

```
pio run  →  RAM 58.9% (19300/32768)   Flash 31.8% (156168/491520)   [SUCCESS]
```

- `app_crypto.o`、`app_usb.o` 重新编译，**零警告**（原先 `peripheral.c` 的 3 条 `-Wimplicit-function-declaration` 警告全部消失）
- 上机烧录后：**代码 43 消失，设备正常枚举，USB HID 工作正常** ✅

---

## 8. 经验教训

1. **代码 43 与代码 45 是两类问题，别混**：
   - 45 = 物理层/引脚（主机看不到设备）
   - 43 + "请求 USB 设备描述符失败" = 主机看得到但拿不到描述符（EP0 / 中断响应 / CPU 卡死）
2. **未映射地址访问是"静默杀手"**：它不报编译错误，也不会打印日志，只会让 CPU 卡在异常处理里，表现成"USB 莫名其妙不响应"。移植 Cortex-M 代码到 RISC-V（CH583）时，**地址常量必须重新核对**。
3. **`git diff` 的上下文只有 3 行，不能用来推断"某处没被改动"**。判断基线状态必须用 `git show HEAD:<path>` 读全文——本次差点因此误判"BLE 与 USB 冲突"的方向。
4. **外设初始化之后新增的任何初始化调用都要审查**：`crypto_init()` 看起来与 USB 无关，却因为一个非法地址读把整个枚举打死了。
5. **`R8_USB_DEV_AD` 必须在状态阶段之后写**，且很多例程把它放在 EP0 IN 分支里，容易在移植时丢掉。
6. **`RB_UEP_AUTO_TOG` 与手动翻转 `^= RB_UEP_x_TOG` 不能混用**，同一端点只能用一种方式管理 DATA0/DATA1。
7. 对照 WCH 官方例程时优先用 `EXAM\USB\Device\...` 下实测可跑的最小例程（如 `HID_CompliantDev`）当基线。

---

## 9. 遗留事项（未实现，非本次范围）

- [ ] **CTAPHID 多帧（续帧 / CONCAT）未实现**：当前只支持单帧 64 字节报文
- [ ] **`handle_get_info()` 必然返回错误**：其首行判断是 `if (buf_len < 100) return CTAP_ERR_INVALID_CBOR_TYPE;`，而 HID 报告只有 64 字节（实际传入 59），因此 GetInfo 永远失败——**浏览器 / Windows Hello 目前还认不出它是 FIDO2 认证器**
- [ ] `handle_get_info()` 的 CBOR 编码本身也不符合 CTAP2 规范（应为 map，当前是 `array(4)`，且字段顺序与长度声明有误）
- [ ] `handle_make_credential()` / `handle_get_assertion()` 仅有错误桩实现
- [ ] 上述两项需要先做 CTAPHID 续帧收发与重组，再重写 GetInfo 的 CBOR 编码
