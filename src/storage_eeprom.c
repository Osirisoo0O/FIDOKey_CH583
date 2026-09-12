/**
 * @file storage_eeprom.c
 * @brief 存储后端：CH583 片内 DataFlash（EEPROM API）
 *
 * 约束来自 Peripheral/ch58x/inc/ISP583.h：
 *   - 地址是 DataFlash 内字节偏移，范围 0 ~ EEPROM_MAX_SIZE-1（0x7FFF）
 *   - 最小擦除单位 EEPROM_MIN_ER_SIZE = EEPROM_PAGE_SIZE = 256
 *   - 写入最小 1 字节，但按 256 的倍数最好
 *   - EEPROM_READ / EEPROM_WRITE 的 Buffer 必须 4 字节对齐
 *
 * 注意 capacity 只声明到 0x7E00：紧随其后的 0x7E00~0x7FFF 是 BLE 协议栈的 SNV，
 * 归属安全存储之外的区域，擦写会破坏 BLE 绑定信息。
 */

#include "config.h"
#include "stdint.h"
#include "storage.h"

/* 安全存储可用的上界：到此为止，再往后是 BLE SNV */
#define EE_USABLE_LIMIT     0x00007E00UL

static int8_t ee_init(void)
{
    return 0;
}

static int8_t ee_read(uint32_t off, void *buf, uint32_t len)
{
    if(buf == NULL || len == 0)
    {
        return -1;
    }
    if(off >= EE_USABLE_LIMIT || (off + len) > EE_USABLE_LIMIT)
    {
        return -1;                      /* 越界（含踩到 BLE SNV） */
    }
    return (EEPROM_READ(off, buf, len) == 0) ? 0 : -1;
}

static int8_t ee_write(uint32_t off, const void *buf, uint32_t len)
{
    if(buf == NULL || len == 0)
    {
        return -1;
    }
    if(off >= EE_USABLE_LIMIT || (off + len) > EE_USABLE_LIMIT)
    {
        return -1;
    }
    /* EEPROM_WRITE 要求源缓冲 4 字节对齐，调用方需保证 */
    if(((uint32_t)buf & 0x3U) != 0)
    {
        return -1;
    }
    return (EEPROM_WRITE(off, (void *)buf, len) == 0) ? 0 : -1;
}

static int8_t ee_erase(uint32_t off, uint32_t len)
{
    if(len == 0)
    {
        return -1;
    }
    if((len % (uint32_t)EEPROM_MIN_ER_SIZE) != 0)
    {
        return -1;                      /* 必须是擦除单位的整数倍 */
    }
    if(off >= EE_USABLE_LIMIT || (off + len) > EE_USABLE_LIMIT)
    {
        return -1;
    }
    return (EEPROM_ERASE(off, len) == 0) ? 0 : -1;
}

const storage_backend_t g_storage_eeprom = {
    "eeprom",
    (uint32_t)EEPROM_MIN_ER_SIZE,       /* 256 */
    EE_USABLE_LIMIT,                    /* 0x7E00，避开 BLE SNV */
    ee_init,
    ee_read,
    ee_write,
    ee_erase
};
