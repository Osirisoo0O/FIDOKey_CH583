# 基于CH583的FIDO2安全密钥开发

## 一、项目概述与技术选型

本项目旨在基于沁恒微电子的**CH583**芯片，开发一款符合FIDO2标准的USB安全密钥。

**核心硬件：CH583**
- **内核**：32位RISC-V处理器（青稞V4A），支持RV32IMAC指令集
- **存储**：512KB Flash（用户可用448KB），32KB SRAM
- **USB**：2组独立的全速USB 2.0主机/设备控制器及收发器
- **安全特性**：内置AES-128硬件加解密单元、芯片唯一ID
- **封装**：QFN48或QFN28
- **可选功能**：集成BLE 5.3无线通讯模块，支持蓝牙FIDO2（手机端认证）

## 二、完整开发流程

### **第一阶段：开发环境搭建**
1.  **下载官方SDK (EVT包)**：这是所有开发的基础，包含例程、驱动和文档。
    - **官方下载**：[CH583EVT.ZIP](https://www.wch.cn/downloads/CH583EVT_ZIP.html)
2.  **安装集成开发环境(IDE)**：沁恒官方推荐使用**MounRiver Studio**，它基于Eclipse并集成了RISC-V GCC工具链。
3.  **获取技术文档**：
    - **数据手册**：[CH583DS1.PDF](https://www.wch.cn/downloads/CH583DS1_PDF.html)—— 硬件规格、引脚定义、电气特性。
    - **处理器手册**：[QingKeV4_Processor_Manual.PDF](https://www.wch.cn/downloads/QingKeV4_Processor_Manual_PDF.html)—— 内核架构与指令集。
4.  **熟悉例程**：重点研究SDK中的USB-HID（`USB\HID`）和复合设备（`USB\CompoundDev`）例程。

### **第二阶段：硬件电路设计**
1.  **获取参考设计**：在下载的`CH583EVT.ZIP`文件中，找到`PUB\CH583SCH`目录，内有官方评估板原理图。
2.  **核心电路**：设计CH583的最小系统（电源、时钟、复位）。
3.  **USB接口**：
    - USB_DP和USB_DM引脚正确连接。
    - DP脚通过1.5kΩ电阻上拉。
    - D+和D-线上串联22Ω匹配电阻。
    - VBUS引脚建议加入5V过压保护电路。
4.  **安全与交互**：
    - **用户交互**：至少设计一个物理按键（用于“用户存在”测试）和一个LED指示灯。
    - **物理安全**：PCB设计时，可考虑为芯片添加**屏蔽罩**，以增强物理安全性，防止侧信道攻击。
5.  **可选外设**：如需支持蓝牙FIDO2，需设计2.4GHz天线匹配电路。

### **第三阶段：软件开发（核心）**
这是整个项目中最复杂、最核心的部分。

1.  **实现USB HID设备**：
    - **修改HID报告描述符**：根据FIDO2规范（`FIDO_CTAPHID`协议），定义输入、输出和特性报告（Feature Report）的格式。
    - **处理HID报告**：在`USB_Device`例程基础上，编写代码解析来自主机的HID报告，并封装响应数据回传。

2.  **实现FIDO2核心协议**：
    - **CTAP协议**：完整实现客户端到认证器（Client to Authenticator Protocol）协议。
    - **核心命令**：重点实现`MakeCredential`（注册）和`GetAssertion`（登录）命令的处理逻辑。

3.  **实现加密与安全存储**：
    - **密钥生成**：利用硬件随机数发生器生成符合FIDO2要求的公私钥对（如ECDSA P-256）。
    - **安全存储**：将私钥等敏感数据存储在Flash中，利用**芯片唯一ID**和**AES-128硬件加密**进行加密保护。
    - **签名操作**：实现使用私钥对挑战（Challenge）数据进行签名的函数。

4.  **实现用户交互**：
    - 将物理按键的中断与`MakeCredential`和`GetAssertion`操作绑定，实现“用户存在”（User Presence）测试。

5.  **（可选）实现蓝牙功能**：
    - 如需支持手机端，需实现BLE GATT服务，与FIDO2手机应用（如Google Smart Lock）通信。

### **第四阶段：调试、测试与认证**
1.  **固件烧录**：使用沁恒的**WCHISPTool**工具，通过USB或串口烧录固件。
2.  **调试**：使用MounRiver Studio配合**WCH-Link**调试器进行在线调试。
3.  **功能测试**：
    - **系统识别**：将设备连接到电脑，检查是否被正确识别为HID设备。
    - **协议一致性**：使用**FIDO2 Conformance Testing Tool**进行官方协议一致性测试。
    - **兼容性测试**：在Windows、macOS、Linux等操作系统及Chrome、Edge等浏览器上进行兼容性测试。
4.  **FIDO2认证（可选但建议）**：如计划将产品商业化，需向FIDO联盟提交产品进行官方认证测试，以获得“FIDO Certified”标志。

### **第五阶段：生产准备**
1.  **量产烧录工具**：开发专用的量产烧录工具，用于批量烧录固件和写入每台设备唯一的公私钥对、证书等。
2.  **生产测试**：制定生产测试流程，确保每个产品的USB通信、加密功能和用户交互都正常。

## 三、资源下载汇总

| 资源名称 | 描述 | 下载地址 |
| :--- | :--- | :--- |
| **CH583EVT.ZIP** | **核心开发包**：包含评估板说明、原理图、所有外设驱动和示例代码。 | [沁恒官网](https://www.wch.cn/downloads/CH583EVT_ZIP.html) |
| **CH583DS1.PDF** | **芯片数据手册**：硬件规格、引脚定义、电气特性等。 | [沁恒官网](https://www.wch.cn/downloads/CH583DS1_PDF.html) |
| **QingKeV4 Processor Manual** | **处理器手册**：青稞V4内核的架构与指令集详解。 | [沁恒官网](https://www.wch.cn/downloads/QingKeV4_Processor_Manual_PDF.html) |
| **WCHISPTool** | **烧录工具**：用于通过USB或串口烧录固件。 | 沁恒官网工具软件页面 |
| **MounRiver Studio** | **集成开发环境(IDE)**：基于Eclipse的RISC-V开发环境。 | [MounRiver官网](http://www.mounriver.com) |

## ⚠️ 重要提示
1.  **无现成方案**：沁恒官方**没有**提供现成的FIDO2示例代码。上述所有FIDO2协议逻辑（CTAP、加密、签名等）都需要你根据官方标准自行实现。
2.  **安全是核心**：私钥的**生成、存储和使用**是整个项目的安全基石。务必深入研究CH583的**AES-128加密单元**和**芯片唯一ID**，设计可靠的安全存储方案。
3.  **从基础开始**：建议从**USB HID通信**和**基础加密功能**开始逐步构建，每完成一个模块都进行充分测试，再叠加更复杂的功能。