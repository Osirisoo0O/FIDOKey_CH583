/**
 * @file storage.h
 * @brief 非易失存储后端接口（开发计划 2.5；为后续 SPI NOR 迁移预留）
 *
 * 当前后端：片内 DataFlash（EEPROM API），erase_size = 256B，capacity = 32KB
 * 规划后端：外部 SPI NOR，**erase_size 通常是 4KB**
 *
 * ⚠️ 迁移到 SPI NOR 时，擦除粒度的变化会直接影响 secure_store 的槽位布局。
 *    secure_store 的槽固定 512B，代码依赖一个前提：
 *        **槽大小必须是 erase_size 的整数倍**
 *    当前 512 / 256 = 2 ✓ 成立。
 *    换成 4KB 擦除的 SPI NOR 后就必须二选一：
 *      a) 把 SS_SLOT_SIZE 调整为 4096（实现简单，但每槽占满 4KB）
 *      b) 实现擦除单元的 read-modify-write（需要一个 erase_size 大小的缓冲，
 *         按 4KB 算是 4KB RAM —— 当前 RAM 余量下这个代价不小）
 *    secure_store_init() 会显式校验该前提，不满足时直接报错，
 *    而不是在擦除时静默毁掉同单元的其它记录。
 */

#ifndef __STORAGE_H
#define __STORAGE_H

#include "stdint.h"

typedef struct
{
    const char *name;

    /** 最小擦除单位（字节）。片内 DataFlash = 256，典型 SPI NOR = 4096 */
    uint32_t erase_size;

    /** 总容量（字节） */
    uint32_t capacity;

    int8_t (*init)(void);

    /** 读取 [off, off+len) */
    int8_t (*read)(uint32_t off, void *buf, uint32_t len);

    /** 写入 [off, off+len)。注意：只能把 1 改成 0；要置 1 必须先 erase。
     *  片内 DataFlash 还要求 buf 按 4 字节对齐。 */
    int8_t (*write)(uint32_t off, const void *buf, uint32_t len);

    /** 擦除 [off, off+len)，len 应为 erase_size 的整数倍 */
    int8_t (*erase)(uint32_t off, uint32_t len);
} storage_backend_t;

/**
 * @brief 注册存储后端（在 secure_store_init 之前调用）
 */
int8_t storage_init(const storage_backend_t *backend);

/**
 * @brief 取当前后端；未注册返回 NULL
 */
const storage_backend_t *storage_get(void);

/* 内置后端：片内 DataFlash（32KB，256B 擦除） */
extern const storage_backend_t g_storage_eeprom;

#endif /* __STORAGE_H */
