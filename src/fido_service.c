/**
 * @file fido_service.c
 * @brief FIDO GATT 服务实现（BLE CTAP2 传输的服务层）
 *
 * 规范依据：FIDO U2F BT Protocol v1.1 §12、ITU-T X.1278.2 §13.4
 *
 * 本文件只负责 GATT 层：服务与特征的注册、读写分发、通知发送。
 * 帧格式的编解码与 CTAP2 的对接在 ble_transport.c（阶段 2/3）。
 *
 * ── 关于 128-bit UUID 的字节序 ──
 * BLE 属性表里 128-bit UUID 按小端存放，但**只有前 8 字节参与反序**
 * （按 4-2-2-2 分组分别反序），**后 6 字节保持原序**。以
 *   f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb
 * 为例，存放顺序是
 *   f1 ff d0 f1 | aa de | ee ec | 2f b4 | c9 ba 7e d6 23 bb
 *           (4)      (2)     (2)     (2)   (6，不反序)
 * 下面每个 UUID 都用注释标出转换结果，便于核对。
 */

/*********************************************************************
 * INCLUDES
 */

#include "config.h"
#include "gattprofile.h"
#include "stdint.h"
#include "string.h"
#include "fido_service.h"

/*********************************************************************
 * MACROS
 */

#define SERVAPP_NUM_ATTR_SUPPORTED      12
#define FIDO_TXCCCD_CNT                 4

/* 属性表下标（供回调按 handle 反查用）。
 * 每个特征占：Declaration + Value（fidoStatus 另有一个 CCCD）。
 *
 *   [0] Service          [1] CP 声明        [2] CP 值
 *   [3] Status 声明      [4] Status 值      [5] Status CCCD
 *   [6] CPLen 声明       [7] CPLen 值
 *   [8] Bitfield 声明    [9] Bitfield 值
 */
#define ATTR_IDX_CONTROL_POINT_VALUE    2
#define ATTR_IDX_STATUS_VALUE           4
#define ATTR_IDX_CP_LENGTH_VALUE        7
#define ATTR_IDX_REV_BITFIELD_VALUE     9

/*********************************************************************
 * GLOBAL VARIABLES
 */

/* 128-bit UUID 的存放形式：**16 字节整体反序**。
 *
 * 实测教训（两次踩错，值得记下）：
 *   1. 按 BLE 规范写成 4-2-2-2-6 分段反序 -> nRF 显示仍不对
 *   2. 按标准字节序（不反序）           -> nRF 显示 FB349B5F-...，完全反了
 *   正确做法是把标准 UUID 的 16 字节**整体倒过来**，即
 *     0000fffd-0000-1000-8000-00805f9b34fb   (标准)
 *     -> fb 34 9b 5f 80 00 00 80 00 10 00 00 fd ff 00 00   (存放形式)
 *   WCH 栈不采用 BLE 规范的分段反序，而是简单倒序存放。
 */

/* f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb */
static const uint8_t fido_ControlPointUUID[ATT_UUID_SIZE] = {
    0xbb, 0x23, 0xd6, 0x7e, 0xba, 0xc9, 0x2f, 0xb4,
    0xee, 0xec, 0xaa, 0xde, 0xf1, 0xff, 0xd0, 0xf1
};

/* f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb */
static const uint8_t fido_StatusUUID[ATT_UUID_SIZE] = {
    0xbb, 0x23, 0xd6, 0x7e, 0xba, 0xc9, 0x2f, 0xb4,
    0xee, 0xec, 0xaa, 0xde, 0xf2, 0xff, 0xd0, 0xf1
};

/* f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb */
static const uint8_t fido_ControlPointLengthUUID[ATT_UUID_SIZE] = {
    0xBB, 0x23, 0xd6, 0x7e, 0xba, 0xc9, 0x2f, 0xb4,
    0xee, 0xec, 0xaa, 0xde, 0xf3, 0xff, 0xd0, 0xf1
};

/* f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb */
static const uint8_t fido_ServiceRevisionBitfieldUUID[ATT_UUID_SIZE] = {
    0xbb, 0x23, 0xd6, 0x7e, 0xba, 0xc9, 0x2f, 0xb4,
    0xee, 0xec, 0xaa, 0xde, 0xf4, 0xff, 0xd0, 0xf1
};

/* 0000fffd-0000-1000-8000-00805f9b34fb —— FIDO 服务本体 */
static const uint8_t fido_ServiceUUID[ATT_UUID_SIZE] = {
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
    0x00, 0x10, 0x00, 0x00, 0xfd, 0xff, 0x00, 0x00
};

/* 注意：早期实现里还提供了一个 fidoServiceRevision 特征（16-bit UUID 0x2A28）。
 * 该特征在现行规范中**已被 fidoServiceRevisionBitfield 取代**，客户端会认为
 * 同时提供两者的设备不合规（有报告称这会导致"连上但不发任何 FIDO 请求"）。
 * 现已移除，只保留 fidoServiceRevisionBitfield。 */

/*********************************************************************
 * LOCAL VARIABLES
 */

static fido_ServiceCB_t s_appCBs = NULL;

static const gattAttrType_t s_Service = {ATT_UUID_SIZE, fido_ServiceUUID};

/* fidoControlPoint：Write（客户端写入请求帧） */
static uint8_t s_ControlPointProps = GATT_PROP_WRITE;
static uint8_t s_ControlPointValue = 0;         /* 内容由回调即时取走，不缓存 */

/* fidoStatus：Notify（设备回送响应帧） */
static uint8_t s_StatusProps = GATT_PROP_NOTIFY;
static uint8_t s_StatusValue = 0;
static gattCharCfg_t s_StatusCCCD[FIDO_TXCCCD_CNT];

/* fidoControlPointLength：Read（单次写入上限） */
static uint8_t s_CPLengthProps = GATT_PROP_READ;
static uint8_t s_CPLengthValue[2];

/* fidoServiceRevisionBitfield：Read/Write（版本协商） */
static uint8_t s_RevBitfieldProps = GATT_PROP_READ | GATT_PROP_WRITE;
static uint8_t s_RevBitfieldValue = FIDO_SUPPORTED_REVISIONS;

/* 客户端选定后的版本位；0 = 尚未选择 */
static uint8_t s_selectedRevision = 0;

/*********************************************************************
 * Profile Attributes - Table
 */

static gattAttribute_t s_ProfileAttrTbl[] = {
    /* ---- FIDO Service 声明 ---- */
    {
        {ATT_BT_UUID_SIZE, primaryServiceUUID},
        GATT_PERMIT_READ,
        0,
        (uint8_t *)&s_Service
    },

    /* ---- 特征 1: fidoControlPoint (Write) ---- */
    {
        {ATT_BT_UUID_SIZE, characterUUID},
        GATT_PERMIT_READ,
        0,
        &s_ControlPointProps
    },
    {
        {ATT_UUID_SIZE, fido_ControlPointUUID},      /* idx 2 */
        GATT_PERMIT_WRITE,
        0,
        &s_ControlPointValue
    },

    /* ---- 特征 2: fidoStatus (Notify) ---- */
    {
        {ATT_BT_UUID_SIZE, characterUUID},
        GATT_PERMIT_READ,
        0,
        &s_StatusProps
    },
    {
        {ATT_UUID_SIZE, fido_StatusUUID},            /* idx 5 */
        0,
        0,
        &s_StatusValue
    },
    {
        {ATT_BT_UUID_SIZE, clientCharCfgUUID},       /* idx 6: CCCD */
        GATT_PERMIT_READ | GATT_PERMIT_WRITE,
        0,
        (uint8_t *)s_StatusCCCD
    },

    /* ---- 特征 3: fidoControlPointLength (Read) ---- */
    {
        {ATT_BT_UUID_SIZE, characterUUID},
        GATT_PERMIT_READ,
        0,
        &s_CPLengthProps
    },
    {
        {ATT_UUID_SIZE, fido_ControlPointLengthUUID},/* idx 8 */
        GATT_PERMIT_READ,
        0,
        s_CPLengthValue
    },

    /* ---- 特征 4: fidoServiceRevisionBitfield (Read/Write) ---- */
    {
        {ATT_BT_UUID_SIZE, characterUUID},
        GATT_PERMIT_READ,
        0,
        &s_RevBitfieldProps
    },
    {
        {ATT_UUID_SIZE, fido_ServiceRevisionBitfieldUUID}, /* idx 12 */
        GATT_PERMIT_READ | GATT_PERMIT_WRITE,
        0,
        &s_RevBitfieldValue
    },
};

/*********************************************************************
 * LOCAL FUNCTIONS
 */

static bStatus_t fido_ReadAttrCB(uint16_t connHandle, gattAttribute_t *pAttr,
                                 uint8_t *pValue, uint16_t *pLen,
                                 uint16_t offset, uint16_t maxLen, uint8_t method);
static bStatus_t fido_WriteAttrCB(uint16_t connHandle, gattAttribute_t *pAttr,
                                  uint8_t *pValue, uint16_t len,
                                  uint16_t offset, uint8_t method);
static void      fido_HandleConnStatusCB(uint16_t connHandle, uint8_t changeType);

/*********************************************************************
 * PROFILE CALLBACKS
 */

static gattServiceCBs_t s_ProfileCBs = {
    fido_ReadAttrCB,
    fido_WriteAttrCB,
    NULL
};

/*********************************************************************
 * PUBLIC FUNCTIONS
 */

bStatus_t fido_add_service(fido_ServiceCB_t cb)
{
    uint8_t status;

    /* fidoControlPointLength 是小端 16 位。
     * 初值按未协商时的默认 MTU 推算（23-3=20）；MTU 协商完成后
     * 由 ble_transport_set_mtu() 调 fido_set_control_point_length() 更新。 */
    fido_set_control_point_length((uint16_t)(23 - 3));

    GATTServApp_InitCharCfg(INVALID_CONNHANDLE, s_StatusCCCD);
    linkDB_Register(fido_HandleConnStatusCB);

    status = GATTServApp_RegisterService(s_ProfileAttrTbl,
                                         GATT_NUM_ATTRS(s_ProfileAttrTbl),
                                         GATT_MAX_ENCRYPT_KEY_SIZE,
                                         &s_ProfileCBs);
    if(status != SUCCESS)
    {
        PRINT("Add fido service failed! rc=%d", status);
        PRINT("%c", 10);
    }

    s_appCBs = cb;
    return (status);
}

uint8_t fido_status_notify_is_ready(uint16_t connHandle)
{
    return (GATT_CLIENT_CFG_NOTIFY == GATTServApp_ReadCharCfg(connHandle, s_StatusCCCD));
}

uint8_t fido_get_revision_bitfield(void)
{
    return s_selectedRevision;
}

void fido_set_control_point_length(uint16_t len)
{
    s_CPLengthValue[0] = (uint8_t)(len & 0xFF);
    s_CPLengthValue[1] = (uint8_t)(len >> 8);
}

bStatus_t fido_status_notify(uint16_t connHandle, const uint8_t *p_data, uint16_t len)
{
    attHandleValueNoti_t noti;
    uint16_t             value;
    bStatus_t            status;

    if(p_data == NULL || len == 0)
    {
        return INVALIDPARAMETER;
    }

    value = GATTServApp_ReadCharCfg(connHandle, s_StatusCCCD);
    if(!(value & GATT_CLIENT_CFG_NOTIFY))
    {
        return bleIncorrectMode;        /* 客户端未订阅 */
    }

    noti.handle = s_ProfileAttrTbl[ATTR_IDX_STATUS_VALUE].handle;
    noti.len    = len;
    noti.pValue = GATT_bm_alloc(connHandle, ATT_HANDLE_VALUE_NOTI, len, NULL, 0);
    if(noti.pValue == NULL)
    {
        return bleMemAllocError;
    }
    tmos_memcpy(noti.pValue, p_data, len);

    status = GATT_Notification(connHandle, &noti, FALSE);
    if(status != SUCCESS)
    {
        /* 失败时必须释放，否则这块通知缓冲就泄漏了。
         * 一旦泄漏，后续通知会因内存池耗尽而全部失败 ——
         * 表现就是"响应发出一次后就再也发不出去"。 */
        GATT_bm_free((gattMsg_t *)&noti, ATT_HANDLE_VALUE_NOTI);
    }
    return status;
}

/*********************************************************************
 * LOCAL FUNCTIONS
 */

static bStatus_t fido_ReadAttrCB(uint16_t connHandle, gattAttribute_t *pAttr,
                                 uint8_t *pValue, uint16_t *pLen,
                                 uint16_t offset, uint16_t maxLen, uint8_t method)
{
    uint16_t uuid;

    if(gattPermitAuthorRead(pAttr->permissions))
    {
        return ATT_ERR_INSUFFICIENT_AUTHOR;
    }

    /* 只处理 16-bit UUID 的读取（CCCD 与 fidoServiceRevision）。
     * 客户端的其余读取由 GATT Server 直接用属性表里的值应答。 */
    /* 128-bit UUID 的属性（ControlPointLength / RevisionBitfield）：
     * gattAttribute_t 里没有"值长度"字段，读取时必须在这里显式设置 *pLen，
     * 否则客户端会读到空值（实测就是这样踩到的）。 */
    if(pAttr->type.len != ATT_BT_UUID_SIZE)
    {
        if(pAttr->handle == s_ProfileAttrTbl[ATTR_IDX_CP_LENGTH_VALUE].handle)
        {
            if(offset >= 2) { return ATT_ERR_INVALID_OFFSET; }
            *pLen = (uint16_t)(2 - offset);
            tmos_memcpy(pValue, s_CPLengthValue + offset, *pLen);
        }
        else if(pAttr->handle == s_ProfileAttrTbl[ATTR_IDX_REV_BITFIELD_VALUE].handle)
        {
            if(offset >= 1) { return ATT_ERR_INVALID_OFFSET; }
            *pLen = 1;
            tmos_memcpy(pValue, &s_RevBitfieldValue, 1);
        }
        return SUCCESS;
    }

    uuid = BUILD_UINT16(pAttr->type.uuid[0], pAttr->type.uuid[1]);

    if(uuid == GATT_CLIENT_CHAR_CFG_UUID)
    {
        if(offset != 0)
        {
            return ATT_ERR_ATTR_NOT_LONG;
        }
        *pLen = 2;
        tmos_memcpy(pValue, pAttr->pValue, 2);
    }
    return SUCCESS;
}

static bStatus_t fido_WriteAttrCB(uint16_t connHandle, gattAttribute_t *pAttr,
                                  uint8_t *pValue, uint16_t len,
                                  uint16_t offset, uint8_t method)
{
    uint16_t uuid;
    if(gattPermitAuthorWrite(pAttr->permissions))
    {
        return ATT_ERR_INSUFFICIENT_AUTHOR;
    }

    if(pAttr->type.len != ATT_BT_UUID_SIZE)
    {
        /* 128-bit 的特征（fidoControlPoint / Bitfield）按 handle 分派 */
        if(pAttr->handle == s_ProfileAttrTbl[ATTR_IDX_CONTROL_POINT_VALUE].handle)
        {
            if(s_appCBs)
            {
                fido_evt_t evt;
                evt.type       = FIDO_EVT_CONTROL_POINT_WRITE;
                evt.connHandle = connHandle;
                evt.data       = pValue;
                evt.len        = len;
                s_appCBs(&evt);
            }
            return SUCCESS;
        }

        if(pAttr->handle == s_ProfileAttrTbl[ATTR_IDX_REV_BITFIELD_VALUE].handle)
        {
            if(offset != 0 || len != 1)
            {
                return ATT_ERR_INVALID_VALUE_SIZE;
            }
            /* 只接受本实现支持的单一位（FIDO2）。规范要求客户端写入单 bit 值。 */
            if(pValue[0] == 0 || (pValue[0] & (uint8_t)(~FIDO_SUPPORTED_REVISIONS)))
            {
                return ATT_ERR_UNLIKELY;    /* 不支持的版本 */
            }
            s_selectedRevision = pValue[0];
            s_RevBitfieldValue = pValue[0];
            return SUCCESS;
        }

        return SUCCESS;
    }

    uuid = BUILD_UINT16(pAttr->type.uuid[0], pAttr->type.uuid[1]);
    if(uuid == GATT_CLIENT_CHAR_CFG_UUID)
    {
        bStatus_t status = GATTServApp_ProcessCCCWriteReq(connHandle, pAttr, pValue, len,
                                                          offset, GATT_CLIENT_CFG_NOTIFY);
        if(status == SUCCESS && s_appCBs)
        {
            uint16_t   charCfg = BUILD_UINT16(pValue[0], pValue[1]);
            fido_evt_t evt;

            evt.type       = (charCfg == GATT_CFG_NO_OPERATION)
                             ? FIDO_EVT_STATUS_NOTI_DISABLED
                             : FIDO_EVT_STATUS_NOTI_ENABLED;
            evt.connHandle = connHandle;
            evt.data       = NULL;
            evt.len        = 0;
            s_appCBs(&evt);
        }
        return status;
    }

    return SUCCESS;
}

static void fido_HandleConnStatusCB(uint16_t connHandle, uint8_t changeType)
{
    if(connHandle != LOOPBACK_CONNHANDLE)
    {
        if((changeType == LINKDB_STATUS_UPDATE_REMOVED) ||
           ((changeType == LINKDB_STATUS_UPDATE_STATEFLAGS) && (!linkDB_Up(connHandle))))
        {
            GATTServApp_InitCharCfg(connHandle, s_StatusCCCD);
        }
    }
}

/*********************************************************************
*********************************************************************/
