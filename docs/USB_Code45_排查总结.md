# SecureKey_WCH — USB Code45 问题排查总结

> 项目：基于 CH583 的 FIDO2 安全密钥（BLE + USB 双模）
> 本文件记录 USB 设备枚举报 **代码 45** 的完整排查过程与最终结论（2025 会话记录）。

---

## 1. 项目背景

- 芯片：**WCH CH583**（RISC-V，BLE 2.4G + 双 USB 控制器）
- 工程基础：官方 `ble-usb-cdc-ch58x`（git HEAD 即官方 base，**USB1** 控制器实现）
- 目标：CH583 通过 USB 模拟 **CH375** 设备（VID=0x4348, PID=0x55E0），供 CH375 驱动
  （`oem42.inf` / `CH375_A64`）与 SecureKey 上位机识别通信
- 开发环境：PlatformIO，board `genericCH583M`，framework `noneos-sdk`

---

## 2. 现象

- 烧录固件后设备管理器显示 **代码 45**（"目前，这个硬件设备没有连接到计算机"）
- 曾经短暂出现过 "USB Module" 后几秒消失变 Code45
- 设备管理器识别出 `USB\VID_4348&PID_55E0`，驱动 `oem42.inf`，服务 `CH375_A64`

---

## 3. 排查过程

### 3.1 描述符层面
- 设备描述符 `bDeviceSubClass=0x80 / bDeviceProtocol=0x55` 是非标准值
  → 已按官方 base 修正为厂商类标准 `0xFF / 0x00 / 0x00`
- 配置描述符从被改坏的 8 端点（0x4A=74B）还原为官方 CH375 兼容 3 端点结构
  （39B：EP2 bulk IN/OUT 32B + EP1 interrupt IN 8B）

### 3.2 代码层面（USB1 → USB2 迁移中引入的多个 bug）
| 问题 | 说明 | 修复 |
|---|---|---|
| Setup 包用错宏 | USB2 代码仍用 USB1 的 `pSetupReqPak`（指向未赋值缓冲=NULL） | 全部改 `pU2SetupReqPak` |
| 端点缓冲地址错 | 一度把 DMA 指向 `0x40000000`（那是寄存器区！） | 恢复普通 SRAM 数组 |
| 上传函数用错 | `USBSendData()` 调用 USB1 的 `DevEP2_IN_Deal`（操作 USB1 寄存器） | 改 USB2 的 `U2DevEP2_IN_Deal` |
| GET_DESCRIPTOR 拷贝位置 | 公共段对 `pDescr==NULL` 的 GET_STATUS 等做 memcpy 覆盖数据 | 改为 case 内拷贝、公共段只算长度 |
| 厂商命令 0x95 未知 wValue | 会把 EP0 残留数据当应答发出 | 未知一律 STALL，仅成功才 memcpy |

### 3.3 中断链路验证（关键测试）
- 寄存器打印：`CTRL=29 DEV=a1 ANA=0030 MIS=20` → USB 初始化全部正确
- D+ 上拉生效：`DEV=0xA1` bit5=1（U2D+ 为高）
- `PFIC_SetPendingIRQ(USB2_IRQn)` 软件触发 → ISR 正常执行（中断链路通）
- 但插拔 USB 后只有 SUSPEND，**从不收到 BUS_RST** → 主机物理上看不到设备

### 3.4 根因确定（硬件/控制器匹配问题）
对照 CH583 数据手册（17 章）与官方例程：

- **CH583 内嵌 2 个完全独立的 USB 控制器及收发器**：
  - USB1：基址 `0x40008000`，引脚 `UD+/UD-`（`RB_PIN_USB_IE`=0x80）
  - USB2：基址 `0x40008400`，引脚 `U2DP/U2DM`（`RB_PIN_USB2_IE`=0x20）
- 官方例程对比：
  - `EXAM\USB\Device\COM` → 用 **USB1**（`USB_IRQn`/`R8_USB_*`）→ **官方板枚举正常**
  - `EXAM\USB\Device\CompoundU2Dev` → 用 **USB2**（`USB2_IRQn`/`R8_USB2_*`）→ **一直 Code45**
- 结论：**官方开发板的 USB 座只接到 USB1 收发器引脚（UD+/UD-）**
  USB2 控制器初始化得再好，引脚也没连到 USB 座 → 主机永远看不到设备 → Code45

**不是固件枚举/描述符/驱动问题，而是"USB2 控制器对应的物理引脚未接到 USB 座"。**

---

## 4. 最终方案：改回 USB1

SecureKey 板（基于官方板）USB 座走的是 USB1 引脚，因此固件改回官方 base 的 **USB1**
实现，仅保留 CH375 模拟所需的最小差异。

### 4.1 `src/app_usb.c`（以 git HEAD 官方 USB1 base 为准）
- 全部 USB1 写法恢复：`pEPx_RAM_Addr` + `USB_DeviceInit()` +
  `PFIC_EnableIRQ(USB_IRQn)`；`USB_IRQHandler` → `USB_DevTransProcess()`
- 寄存器 `R8_USB_CTRL/R8_USB_INT_FG/R8_USB_DEV_AD/R8_UEPx_*`
- Setup 宏 `pSetupReqPak`、数据宏 `pEPx_DataBuf`
- 适配 CH375 的两处最小修改：
  1. `MyDevDescr` → idVendor=0x4348, idProduct=0x55E0
  2. `DevEP2_OUT_Deal` 在 BLE 未启用时打印而非调用未初始化的 BLE 栈

### 4.2 `src/peripheral_main.c`
- 注释 BLE 初始化：`CH58X_BLEInit()`、`HAL_Init()`、
  `GAPRole_PeripheralInit()`、`Peripheral_Init()`
- 主循环纯忙等（`while(1){}` 空转，永不睡眠，保证 USB 时钟运行）

### 4.3 编译结果
```
RAM:   11.7% (3840/32768 B)
Flash:  2.1% (10236/491520 B)
BUILD SUCCESS
```

---

## 5. 恢复蓝牙的预留开关

蓝牙未初始化时 USB 枚举不受影响。后续恢复 BLE 只需：

1. 打开 `peripheral_main.c` 中被注释的 4 行 BLE 初始化
2. 定义宏 `BLE_ENABLE=TRUE`（`DevEP2_OUT_Deal` 内已预留条件编译，
   BLE 启用时自动改回 `app_usb_notify` 转发）

---

## 6. 关键经验教训

1. **CH583 的 USB1 与 USB2 是两套独立引脚**，改控制器必须确认硬件接线对应
2. 端点 DMA 缓冲是**普通 SRAM**（`R16_UEPn_DMA` 取低 15 位），不是 `0x40000000`
3. USB1/USB2 各自有独立的 `pSetupReqPak`/`pU2SetupReqPak` 宏，不能混用
4. `DevEPn_IN_Deal`(USB1) 与 `U2DevEPn_IN_Deal`(USB2) 操作不同寄存器
5. 用 `PFIC_SetPendingIRQ` 软件触发 + 串口打印 `R8_USBx_MIS_ST/INT_FG`，
   可快速区分"中断链路问题"与"物理层未连接"
6. 设备能显示 VID/PID + "USB Module" 说明枚举层正常，Code45 常在驱动/物理层

---

## 7. 待验证事项

- [ ] 烧录 USB1 固件后设备管理器是否出现 `VID_4348&PID_55E0` 且不再 Code45
- [ ] CH375 厂商命令握手（0x5F/0x95 应答值）是否与 SecureKey 上位机匹配
- [ ] BLE 功能恢复后的双模联调
