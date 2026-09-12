/**
 * @file cred_mgr.c
 * @brief 凭证管理实现（开发计划 3.5）
 *
 * 所有遍历都会跳过末槽（保留给 secure_store 自检）。
 * 每次访问都要读 DataFlash，因此遍历成本与槽数成正比；
 * 当前实现优先保证正确与简单，性能优化留到计划 5.5。
 */

#include "config.h"
#include "stdint.h"
#include "string.h"
#include "cred_mgr.h"
#include "secure_store.h"

int8_t cred_mgr_init(void)
{
    /* 实际的存储初始化在 secure_store_init() 中完成 */
    return 0;
}

int8_t cred_add(const ss_cred_t *rec, uint16_t *slot_out)
{
    uint16_t  i;
    ss_cred_t tmp;

    if(rec == NULL)
    {
        return -1;
    }

    for(i = 0; i < CRED_TOTAL_SLOTS; i++)
    {
        if(secure_store_read_cred(i, &tmp) == 1)        /* 1 = 空槽 */
        {
            ss_cred_t w;

            memcpy(&w, rec, sizeof(ss_cred_t));
            w.magic = SS_CRED_MAGIC;                    /* 强制有效标记 */

            if(secure_store_write_cred(i, &w) != 0)
            {
                return -3;
            }
            if(slot_out != NULL)
            {
                *slot_out = i;
            }
            return 0;
        }
    }
    return -2;                                          /* 无空槽 */
}

int8_t cred_read(uint16_t slot, ss_cred_t *rec)
{
    if(slot >= CRED_TOTAL_SLOTS || rec == NULL)
    {
        return -1;
    }
    return secure_store_read_cred(slot, rec);
}

int8_t cred_write(uint16_t slot, const ss_cred_t *rec)
{
    if(slot >= CRED_TOTAL_SLOTS || rec == NULL)
    {
        return -1;
    }
    return secure_store_write_cred(slot, rec);
}

int8_t cred_find_by_id(const uint8_t *cred_id, uint32_t len,
                       uint16_t *slot_out, ss_cred_t *rec)
{
    uint16_t  i;
    ss_cred_t tmp;

    if(cred_id == NULL || len == 0 || len > SS_CRED_ID_MAX)
    {
        return -1;
    }

    for(i = 0; i < CRED_TOTAL_SLOTS; i++)
    {
        if(secure_store_read_cred(i, &tmp) != 0)
        {
            continue;
        }
        if(tmp.cred_id_len == len && memcmp(tmp.cred_id, cred_id, len) == 0)
        {
            if(slot_out != NULL) { *slot_out = i; }
            if(rec != NULL)      { memcpy(rec, &tmp, sizeof(ss_cred_t)); }
            return 0;
        }
    }
    return 1;                                           /* 未找到 */
}

int8_t cred_find_by_rp(const uint8_t *rp_id_hash,
                       uint16_t *slot_out, ss_cred_t *rec)
{
    uint16_t  i;
    ss_cred_t tmp;

    if(rp_id_hash == NULL)
    {
        return -1;
    }

    for(i = 0; i < CRED_TOTAL_SLOTS; i++)
    {
        if(secure_store_read_cred(i, &tmp) != 0)
        {
            continue;
        }
        if(memcmp(tmp.rp_id_hash, rp_id_hash, SS_RP_ID_HASH_LEN) == 0)
        {
            if(slot_out != NULL) { *slot_out = i; }
            if(rec != NULL)      { memcpy(rec, &tmp, sizeof(ss_cred_t)); }
            return 0;
        }
    }
    return 1;
}

int8_t cred_list_slots(uint16_t *slots, uint16_t max, uint16_t *count)
{
    uint16_t  i;
    uint16_t  n = 0;
    ss_cred_t tmp;

    if(count == NULL && slots == NULL)
    {
        return -1;
    }

    for(i = 0; i < CRED_TOTAL_SLOTS && n < max; i++)
    {
        if(secure_store_read_cred(i, &tmp) != 0)
        {
            continue;
        }
        if(slots != NULL) { slots[n] = i; }
        n++;
    }
    if(count != NULL) { *count = n; }
    return 0;
}

int8_t cred_list_by_rp(const uint8_t *rp_id_hash,
                       uint16_t *slots, uint16_t max, uint16_t *count)
{
    uint16_t  i;
    uint16_t  n = 0;
    ss_cred_t tmp;

    if(rp_id_hash == NULL || count == NULL)
    {
        return -1;
    }

    for(i = 0; i < CRED_TOTAL_SLOTS && n < max; i++)
    {
        if(secure_store_read_cred(i, &tmp) != 0)
        {
            continue;
        }
        if(memcmp(tmp.rp_id_hash, rp_id_hash, SS_RP_ID_HASH_LEN) == 0)
        {
            if(slots != NULL) { slots[n] = i; }
            n++;
        }
    }
    *count = n;
    return 0;
}

int8_t cred_meta(cred_meta_t *meta)
{
    uint16_t  i;
    uint16_t  used = 0;
    uint16_t  max_cid = 0;
    uint16_t  max_uid = 0;
    ss_cred_t tmp;

    if(meta == NULL)
    {
        return -1;
    }

    for(i = 0; i < CRED_TOTAL_SLOTS; i++)
    {
        if(secure_store_read_cred(i, &tmp) != 0)
        {
            continue;
        }
        used++;
        if(tmp.cred_id_len > max_cid) { max_cid = tmp.cred_id_len; }
        if(tmp.user_id_len > max_uid) { max_uid = tmp.user_id_len; }
    }

    meta->total_slots      = CRED_TOTAL_SLOTS;
    meta->used_slots       = used;
    meta->free_slots       = (uint16_t)(CRED_TOTAL_SLOTS - used);
    meta->max_cred_id_len  = max_cid;
    meta->max_user_id_len  = max_uid;
    return 0;
}

int8_t cred_delete(uint16_t slot)
{
    if(slot >= CRED_TOTAL_SLOTS)
    {
        return -1;
    }
    return secure_store_erase_cred(slot);
}

int8_t cred_delete_all(void)
{
    uint16_t i;

    for(i = 0; i < CRED_TOTAL_SLOTS; i++)
    {
        if(secure_store_erase_cred(i) != 0)
        {
            return -3;
        }
    }
    return 0;
}
