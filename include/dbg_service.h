/*********************************************************************
 * @file  dbg_service.h
 * @brief 调试用 BLE 服务：写一个特征即可清除 BLE 绑定（SNV Flash）
 *
 * 为什么需要它：
 *   调试配对流程时经常要把"两侧配对记录彻底重置"——
 *   原本只能打开 -D BLE_ERASE_BONDS_ON_BOOT 宏、重烧固件、再上电，
 *   一轮下来几十秒，而且清完还得再烧回去（否则留不住 bond）。
 *   这个服务把这个动作变成一次 GATT 写入，几秒就能完成。
 *
 * 用法（nRF Connect 或任意 BLE 客户端）：
 *   连接设备 → 找到服务 f0000001-0000-1000-8000-00805f9b34fb
 *   → 向特征 f0000002-... 写入 0x01 → 设备清除所有绑定
 *   → 随后需在主机侧（Windows/Android）也删除配对记录，再重新配对
 *
 * 安全：写权限要求**加密**（GATT_PERMIT_ENCRYPT_WRITE），
 *       未配对的设备无法随意清空绑定。
 */
#ifndef DBG_SERVICE_H
#define DBG_SERVICE_H

#include "CONFIG.h"

/**
 * @brief 注册调试服务（在其它服务注册之后调用）
 */
bStatus_t dbg_add_service(void);

#endif /* DBG_SERVICE_H */
