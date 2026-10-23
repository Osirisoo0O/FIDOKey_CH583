/*********************************************************************
 * @file  dbg_service.c
 * @brief 调试用 BLE 服务：写 0x01 即清除所有 BLE 绑定（SNV Flash）
 *
 * 用途与用法见 dbg_service.h。
 */
#include "config.h"
#include "gattprofile.h"
#include "stdint.h"
#include "string.h"
#include "dbg_service.h"

/*********************************************************************
 * UUID（自定义）
 *
 *   服务  f0000001-0000-1000-8000-00805f9b34fb
 *   特征  f0000002-0000-1000-8000-00805f9b34fb
 *
 * 存放形式沿用本项目约定：标准 UUID 的 16 字节**整体反序**
 * （WCH 栈不用 BLE 规范的分段反序，详见 fido_service.c 的说明）。
 *   标准 f0000001-0000-1000-8000-00805f9b34fb
 *   ->   fb 34 9b 5f 80 00 00 80 00 10 00 00 01 00 00 f0
 */
static const uint8_t dbg_ServiceUUID[ATT_UUID_SIZE] = {
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
    0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0xf0
};

static const uint8_t dbg_ResetBondsUUID[ATT_UUID_SIZE] = {
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
    0x00, 0x10, 0x00, 0x00, 0x02, 0x00, 0x00, 0xf0
};

/*********************************************************************
 * 属性表
 */
static const gattAttrType_t s_DbgService = {ATT_UUID_SIZE, dbg_ServiceUUID};

/* 特征的 Properties 字节：只写（与属性的实际权限分开声明，这是 BLE 的惯例） */
static uint8_t s_ResetBondsProps = GATT_PROP_WRITE;

/* 值缓冲：内容不缓存，写回调即时处理；保留一个字节是为了属性表结构完整 */
static uint8_t s_ResetBondsValue;

/* 属性表下标（回调按 handle 反查用） */
#define DBG_IDX_SERVICE              0
#define DBG_IDX_RESET_DECL           1
#define DBG_IDX_RESET_VALUE          2

static gattAttribute_t s_DbgAttrTbl[] = {
    /* 服务声明 */
    {
        {ATT_BT_UUID_SIZE, primaryServiceUUID},
        GATT_PERMIT_READ,
        0,
        (uint8_t *)&s_DbgService
    },
    /* 特征声明 */
    {
        {ATT_BT_UUID_SIZE, characterUUID},
        GATT_PERMIT_READ,
        0,
        &s_ResetBondsProps
    },
    /* 特征值：写入 0x01 = 清除所有绑定。
     * 要求加密（ENCRYPT_WRITE）—— 避免未配对的设备随意清空绑定。 */
    {
        {ATT_UUID_SIZE, dbg_ResetBondsUUID},
        GATT_PERMIT_WRITE | GATT_PERMIT_ENCRYPT_WRITE,
        0,
        &s_ResetBondsValue
    },
};

/*********************************************************************
 * LOCAL FUNCTIONS
 */

/**
 * @brief 写属性回调：收到 0x01 就清除所有 BLE 绑定
 */
static bStatus_t dbg_WriteAttrCB(uint16_t connHandle, gattAttribute_t *pAttr,
                                 uint8_t *pValue, uint16_t len, uint16_t offset,
                                 uint8_t method)
{
    if(pAttr->handle != s_DbgAttrTbl[DBG_IDX_RESET_VALUE].handle)
    {
        return ATT_ERR_ATTR_NOT_FOUND;
    }
    if(offset != 0)
    {
        return ATT_ERR_INVALID_OFFSET;
    }
    if(len < 1)
    {
        return ATT_ERR_INVALID_VALUE_SIZE;
    }

    PRINT("[DBG] write reset-bonds key=0x%02X len=%u", pValue[0], (unsigned)len);
    PRINT("%c", 10);

    if(pValue[0] == 0x01)
    {
        PRINT("[DBG] ERASE ALL BONDS (主机侧也需删除配对记录)");
        PRINT("%c", 10);
        GAPBondMgr_SetParameter(GAPBOND_ERASE_ALLBONDS, 0, NULL);
    }
    return SUCCESS;
}

static gattServiceCBs_t s_DbgCBs = {
    NULL,               /* 读回调（本服务只写） */
    dbg_WriteAttrCB,
    NULL
};

/*********************************************************************
 * PUBLIC FUNCTIONS
 */

bStatus_t dbg_add_service(void)
{
    bStatus_t status = GATTServApp_RegisterService(s_DbgAttrTbl,
                                                   GATT_NUM_ATTRS(s_DbgAttrTbl),
                                                   GATT_MAX_ENCRYPT_KEY_SIZE,
                                                   &s_DbgCBs);
    if(status != SUCCESS)
    {
        PRINT("[DBG] add dbg service failed! rc=%d", status);
        PRINT("%c", 10);
    }
    return status;
}

/*********************************************************************
*********************************************************************/
