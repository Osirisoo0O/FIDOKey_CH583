/**
 * @file flash_layout.h
 * @brief CH583 片内 Flash 分区定义（开发计划 1.1 / 2.5）
 *
 * 芯片总计 480KB Flash，划分为互不重叠的两块：
 *
 *   0x00000 - 0x6FFFF   Code Flash   448KB    固件（由 ldscripts/SecureKey_CH58x.ld 管理）
 *   0x70000 - 0x77FFF   DataFlash     32KB    非易失数据（由 EEPROM API 访问）
 *
 * DataFlash 内部：
 *   0x0000 - 0x7DFF     安全存储区            31.5KB
 *   0x7E00 - 0x7FFF     BLE 协议栈 SNV         0.5KB
 *
 * 依据：
 *   Peripheral/ch58x/inc/ISP583.h : FLASH_ROM_MAX_SIZE = 0x070000 (448KB)
 *   lib/BLE_HAL/include/config.h  : BLE_SNV_ADDR = 0x77E00 - FLASH_ROM_MAX_SIZE = 0x7E00
 */

#ifndef __FLASH_LAYOUT_H
#define __FLASH_LAYOUT_H

#include "stdint.h"

/*********************************************************************
 * Code Flash（固件区）
 */
#define FLASH_CODE_BASE             0x00000000UL
#define FLASH_CODE_SIZE             0x00070000UL    /* 448KB */

/* Bootloader 预留（开发计划 1.1 的可选项）。
 * 当前**未启用**：固件仍从 0x00000000 启动，值为 0。
 * 将来启用时必须同时修改：
 *   1) ldscripts/SecureKey_CH58x.ld 里 FLASH 的 ORIGIN
 *   2) 本宏
 * 否则固件会从错误地址启动。 */
#define FLASH_BOOT_RESERVE_SIZE     0x00000000UL

/* 最大可链接固件体积 */
#define FLASH_FIRMWARE_MAX_SIZE     (FLASH_CODE_SIZE - FLASH_BOOT_RESERVE_SIZE)

/*********************************************************************
 * DataFlash（EEPROM API 的地址空间，偏移从 0 开始）
 */
#define FLASH_DATAFLASH_BASE        0x00070000UL
#define FLASH_DATAFLASH_SIZE        0x00008000UL    /* 32KB */

/* BLE 协议栈 SNV 占用 DataFlash 末尾 512 字节。
 * 安全存储**绝不能**越过 FLASH_BLE_SNV_OFFSET，否则会破坏 BLE 的绑定/配对信息。 */
#define FLASH_BLE_SNV_OFFSET        0x00007E00UL
#define FLASH_BLE_SNV_SIZE          0x00000200UL    /* 512B */

/* 安全存储可用区间（DataFlash 起始 ~ SNV 之前） */
#define SECURE_STORE_BASE           0x00000000UL
#define SECURE_STORE_MAX_SIZE       0x00007E00UL    /* 31.5KB */

/*********************************************************************
 * 安全存储内部布局（开发计划 2.5）
 *
 *   +0x00  16B   魔数 "SKEY" + 版本 + 保留
 *   +0x10  16B   主密钥（AES-128，由芯片 UID 派生后混淆存储）
 *   +0x20  16B   盐值
 *   +0x30  可变  加密后的凭证记录
 */
#define SECURE_STORE_MAGIC          0x534B4559UL    /* "SKEY" (小端) */
#define SECURE_STORE_VERSION        0x0001UL
#define SECURE_STORE_HDR_SIZE       0x00000010UL    /* 头部 16B */

#define SECURE_STORE_MASTER_KEY_OFF (SECURE_STORE_HDR_SIZE)
#define SECURE_STORE_SALT_OFF       (SECURE_STORE_MASTER_KEY_OFF + 16)
#define SECURE_STORE_CRED_OFF       (SECURE_STORE_SALT_OFF + 16)     /* 凭证区起点 0x30 */

#endif /* __FLASH_LAYOUT_H */
