/**
 * @file cred_mgr.h
 * @brief 凭证管理：增 / 删 / 查 / 列 / 统计（开发计划 3.5）
 *
 * 定位：这是**设备内部的凭证管理接口**，供 CTAP 命令层使用，
 *       不等于 CTAP2 的 credentialManagement 扩展命令（0x0A）——
 *       后者按规范要求 PIN/UV 认证，本实现尚无 PIN 支持，故不对外暴露该命令。
 *
 * 槽位约定：末槽（SS_MAX_CRED_SLOTS-1）固定留给 secure_store 自检，
 *           本模块只操作 0 ~ CRED_TOTAL_SLOTS-1。
 */

#ifndef __CRED_MGR_H
#define __CRED_MGR_H

#include "stdint.h"
#include "secure_store.h"

/* 生产可用的槽位数（已扣除保留槽） */
#define CRED_TOTAL_SLOTS        (SS_MAX_CRED_SLOTS - 1)

typedef struct
{
    uint16_t total_slots;
    uint16_t used_slots;
    uint16_t free_slots;
    uint16_t max_cred_id_len;       /* 已用凭证中最长的 credId */
    uint16_t max_user_id_len;
} cred_meta_t;

/**
 * @brief 初始化凭证管理（依赖 secure_store_init 已完成）
 */
int8_t cred_mgr_init(void);

/**
 * @brief 新增凭证：写入第一个空槽
 * @param rec       记录（magic 会被强制设为 SS_CRED_MAGIC）
 * @param slot_out  输出实际写入的槽号，可为 NULL
 * @return 0=成功, -1=参数错误, -2=无空槽, -3=写入失败
 */
int8_t cred_add(const ss_cred_t *rec, uint16_t *slot_out);

/**
 * @brief 读取指定槽
 * @return 0=成功, 1=空槽, 负数=失败
 */
int8_t cred_read(uint16_t slot, ss_cred_t *rec);

/**
 * @brief 覆写指定槽（更新 signCount 等）
 */
int8_t cred_write(uint16_t slot, const ss_cred_t *rec);

/**
 * @brief 按 credId 查找
 * @return 0=找到, 1=未找到, 负数=参数错误
 */
int8_t cred_find_by_id(const uint8_t *cred_id, uint32_t len,
                       uint16_t *slot_out, ss_cred_t *rec);

/**
 * @brief 按 rpIdHash 查找首个匹配凭证（GetAssertion 的 allowList 为空路径）
 * @return 0=找到, 1=未找到, 负数=参数错误
 */
int8_t cred_find_by_rp(const uint8_t *rp_id_hash,
                       uint16_t *slot_out, ss_cred_t *rec);

/**
 * @brief 列出所有已用槽号（最多 max 个）
 */
int8_t cred_list_slots(uint16_t *slots, uint16_t max, uint16_t *count);

/**
 * @brief 列出某 rpIdHash 下的所有凭证槽号
 */
int8_t cred_list_by_rp(const uint8_t *rp_id_hash,
                       uint16_t *slots, uint16_t max, uint16_t *count);

/**
 * @brief 统计信息
 */
int8_t cred_meta(cred_meta_t *meta);

/**
 * @brief 删除单个凭证
 */
int8_t cred_delete(uint16_t slot);

/**
 * @brief 清空全部凭证（恢复出厂）
 */
int8_t cred_delete_all(void);

#endif /* __CRED_MGR_H */
