/**
 * @file ctap.c
 * @brief CTAP2 命令层实现（CBOR over CTAPHID）
 *
 * 对应开发计划 3.2（GetInfo）与 3.3（MakeCredential）；GetAssertion（3.4）尚未实现。
 *
 * attestation 当前使用 "none"（attStmt 为空 map）：无需 attestation 证书，
 * 浏览器仍可完成注册（只是不显示设备型号）。authData 与 credId 的构造已完整按规范实现，
 * 将来切换到 "packed" 只需填充 attStmt，无需改动 authData 结构。
 *
 * authData 布局（CTAP 2.3 §6.1）：
 *   rpIdHash(32) ‖ flags(1) ‖ signCount(4, big-endian) ‖ attestedCredentialData
 *   attestedCredentialData = aaguid(16) ‖ credIdLen(2, BE) ‖ credId ‖ COSE_Key
 */

#include "stdint.h"
#include "string.h"
#include "ctap.h"
#include "cbor_lite.h"
#include "app_crypto.h"
#include "app_ecdsa.h"
#include "secure_store.h"
#include "cred_mgr.h"
#include "auth_sm.h"
#include "ctaphid.h"
#include "debug_log.h"

/* ---------------- 常量 ---------------- */

#define CTAP_GET_INFO_LEN           40

#define COSE_HASH_LEN               32
#define COSE_KEY_LEN                64
#define CRED_ID_LEN                 32

/* authData 最大长度：32+1+4+16+2+32+77 = 164，留出余量 */
#define AUTHDATA_MAX                256
/* attestationObject：map(3) + "none" + bytes 头 + authData + 空 map ≈ 185 */
#define ATTOBJ_MAX                  320

/* authData flags */
#define FLAG_UP                     0x01
#define FLAG_UV                     0x04
#define FLAG_AT                     0x40
#define FLAG_ED                     0x80

/* MakeCredential 请求键（CTAP 2.3 §6.1） */
#define MC_CLIENT_DATA_HASH         0x01
#define MC_RP                       0x02
#define MC_USER                     0x03
#define MC_PUB_KEY_CRED_PARAMS      0x04
#define MC_EXCLUDE_LIST             0x05
#define MC_OPTIONS                  0x07

/* rp / user / pubKeyCredParams / excludeList 元素子键 */
#define SUB_ID                      0x01
#define SUB_NAME                    0x02
#define SUB_DISPLAY_NAME            0x03
#define SUB_TYPE                    0x01
#define SUB_ALG                     0x02

#define COSE_ALG_ES256              (-7)

/* GetAssertion 请求键（CTAP 2.3 6.2） */
#define GA_RP_ID                    0x01
#define GA_CLIENT_DATA_HASH         0x02
#define GA_ALLOW_LIST               0x03
#define GA_OPTIONS                  0x05

/* 末槽留给 secure_store 自测使用，不参与凭证分配 */
#define RESERVED_SLOTS              1

/* ---------------- 静态缓冲（避免消耗栈） ---------------- */
static uint8_t   s_authdata[AUTHDATA_MAX];
static uint8_t   s_attobj[ATTOBJ_MAX];
static uint8_t   s_rp_id_hash[COSE_HASH_LEN];
static uint8_t   s_cdh[COSE_HASH_LEN];
static uint8_t   s_cred_id[CRED_ID_LEN];
static uint8_t   s_priv[ECDSA_P256_PRIV_LEN];
static uint8_t   s_pub[ECDSA_P256_PUB_LEN];
static ss_cred_t s_rec;
static uint8_t   s_sig[64];        /* GetAssertion 的 r||s（连续布局） */
/* authData ‖ clientDataHash 的拼接缓冲：放静态，避免在 micro-ecc 签名
 * 本就吃栈的调用链上再叠加 288 字节 */
static uint8_t   s_signbuf[AUTHDATA_MAX + COSE_HASH_LEN];

/*********************************************************************
 * @fn      ctap_build_get_info
 *
 * @brief   authenticatorGetInfo 的 CBOR 响应
 *
 *   map(4)
 *     1: ["FIDO_2_0"]
 *     3: h'aaguid(16)'
 *     4: { "up": true }
 *     5: 1200
 *
 * @note    刻意不声明 rk / clientPin / pinUvAuthProtocols：
 *          可驻留凭证与 PIN 尚未实现，一旦声明主机就会发起不支持的操作。
 */
static uint16_t ctap_build_get_info(uint8_t *buf, uint16_t buf_max)
{
    uint32_t o;

    o = cbor_put_map_head(buf, buf_max, 0, 4);
    if(o == CBOR_ENC_ERR) { return 0; }

    o = cbor_put_uint(buf, buf_max, o, 1);                  /* 1: versions */
    o = cbor_put_array_head(buf, buf_max, o, 1);
    o = cbor_put_text(buf, buf_max, o, "FIDO_2_0", 8);
    if(o == CBOR_ENC_ERR) { return 0; }

    o = cbor_put_uint(buf, buf_max, o, 3);                  /* 3: aaguid */
    o = cbor_put_bytes(buf, buf_max, o, g_aaguid, 16);
    if(o == CBOR_ENC_ERR) { return 0; }

    o = cbor_put_uint(buf, buf_max, o, 4);                  /* 4: options */
    o = cbor_put_map_head(buf, buf_max, o, 1);
    o = cbor_put_text(buf, buf_max, o, "up", 2);
    o = cbor_put_bool(buf, buf_max, o, 1);
    if(o == CBOR_ENC_ERR) { return 0; }

    o = cbor_put_uint(buf, buf_max, o, 5);                  /* 5: maxMsgSize */
    o = cbor_put_uint(buf, buf_max, o, CTAP_MAX_MSG_SIZE);
    if(o == CBOR_ENC_ERR) { return 0; }

    return (uint16_t)o;
}

/*********************************************************************
 * 请求解析辅助
 */

/**
 * @brief 解析 rp = { id: text, name: text }，对 id 求 SHA-256 填入 rp_id_hash
 */
static int ctap_parse_rp(cbor_reader_t *r, uint8_t *rp_id_hash)
{
    uint32_t    pairs;
    uint32_t    i;
    const char *s;
    uint32_t    slen;
    uint8_t     got = 0;
    int         rc;

    rc = cbor_read_map(r, &pairs);
    if(rc != CBOR_OK) { return rc; }

    for(i = 0; i < pairs; i++)
    {
        const char *key;
        uint32_t    klen;

        rc = cbor_read_text(r, &key, &klen);
        if(rc != CBOR_OK) { return rc; }

        if(klen == 2 && memcmp(key, "id", 2) == 0)
        {
            rc = cbor_read_text(r, &s, &slen);
            if(rc != CBOR_OK) { return rc; }
            if(slen == 0 || slen > 255) { return CBOR_ERR_RANGE; }
            if(sha256((const uint8_t *)s, slen, rp_id_hash) != 0)
            {
                return CBOR_ERR_TYPE;
            }
            got = 1;
        }
        else
        {
            rc = cbor_skip_item(r);
            if(rc != CBOR_OK) { return rc; }
        }
    }
    return got ? CBOR_OK : CBOR_ERR_NOTFOUND;
}

/**
 * @brief 解析 user，取出 user.id（写入 out，返回长度）
 */
static int ctap_parse_user(cbor_reader_t *r, uint8_t *out, uint16_t out_max, uint16_t *out_len)
{
    uint32_t       pairs;
    uint32_t       i;
    const uint8_t *p;
    uint32_t       plen;
    uint8_t        got = 0;
    int            rc;

    rc = cbor_read_map(r, &pairs);
    if(rc != CBOR_OK) { return rc; }

    for(i = 0; i < pairs; i++)
    {
        const char *key;
        uint32_t    klen;

        rc = cbor_read_text(r, &key, &klen);
        if(rc != CBOR_OK) { return rc; }

        if(klen == 2 && memcmp(key, "id", 2) == 0)
        {
            rc = cbor_read_bytes(r, &p, &plen);
            if(rc != CBOR_OK) { return rc; }
            if(plen == 0 || plen > out_max) { return CBOR_ERR_RANGE; }
            memcpy(out, p, plen);
            *out_len = (uint16_t)plen;
            got = 1;
        }
        else
        {
            rc = cbor_skip_item(r);
            if(rc != CBOR_OK) { return rc; }
        }
    }
    return got ? CBOR_OK : CBOR_ERR_NOTFOUND;
}

/**
 * @brief 检查 pubKeyCredParams 是否包含 ES256(alg=-7)
 */
static int ctap_check_algs(cbor_reader_t *r, uint8_t *es256_ok)
{
    uint32_t count;
    uint32_t i;
    int      rc;

    rc = cbor_read_array(r, &count);
    if(rc != CBOR_OK) { return rc; }
    if(count == 0) { return CBOR_ERR_RANGE; }

    for(i = 0; i < count; i++)
    {
        uint32_t pairs;
        uint32_t j;

        rc = cbor_read_map(r, &pairs);
        if(rc != CBOR_OK) { return rc; }

        for(j = 0; j < pairs; j++)
        {
            const char *key;
            uint32_t    klen;

            rc = cbor_read_text(r, &key, &klen);
            if(rc != CBOR_OK) { return rc; }

            if(klen == 3 && memcmp(key, "alg", 3) == 0)
            {
                int32_t alg;

                rc = cbor_read_int(r, &alg);
                if(rc != CBOR_OK) { return rc; }
                if(alg == COSE_ALG_ES256) { *es256_ok = 1; }
            }
            else
            {
                rc = cbor_skip_item(r);
                if(rc != CBOR_OK) { return rc; }
            }
        }
    }
    return CBOR_OK;
}

/**
 * @brief 检查 excludeList 中是否已有本设备已注册的凭证
 * @return 1=已存在（应拒绝）, 0=不存在
 */
static int ctap_cred_exists(const uint8_t *cred_id, uint32_t len)
{
    /* cred_find_by_id 命中返回 0；参数非法返回负值，同样视为"不存在" */
    return (cred_find_by_id(cred_id, len, NULL, NULL) == 0) ? 1 : 0;
}

static int ctap_check_exclude_list(cbor_reader_t *r)
{
    uint32_t count;
    uint32_t i;
    int      rc;

    rc = cbor_read_array(r, &count);
    if(rc != CBOR_OK) { return rc; }

    for(i = 0; i < count; i++)
    {
        uint32_t       pairs;
        uint32_t       j;
        const uint8_t *id = NULL;
        uint32_t       id_len = 0;

        rc = cbor_read_map(r, &pairs);
        if(rc != CBOR_OK) { return rc; }

        for(j = 0; j < pairs; j++)
        {
            const char *key;
            uint32_t    klen;

            rc = cbor_read_text(r, &key, &klen);
            if(rc != CBOR_OK) { return rc; }

            if(klen == 2 && memcmp(key, "id", 2) == 0)
            {
                rc = cbor_read_bytes(r, &id, &id_len);
                if(rc != CBOR_OK) { return rc; }
            }
            else
            {
                rc = cbor_skip_item(r);
                if(rc != CBOR_OK) { return rc; }
            }
        }

        if(id != NULL && id_len > 0 && id_len <= SS_CRED_ID_MAX)
        {
            if(ctap_cred_exists(id, id_len))
            {
                return 1;                   /* 命中已注册凭证 */
            }
        }
    }
    return 0;
}

/**
 * @brief 解析 options，若请求了可驻留凭证（rk=true）则报告不支持
 * @return 1=请求了 rk
 */
static int ctap_check_options(cbor_reader_t *r, uint8_t *up_out)
{
    uint32_t pairs;
    uint32_t i;
    uint8_t  rk = 0;
    uint8_t  up = 1;            /* CTAP2 规范：options.up 缺省为 true */
    int      rc;

    if(up_out != NULL) { *up_out = 1; }

    rc = cbor_read_map(r, &pairs);
    if(rc != CBOR_OK) { return 0; }

    for(i = 0; i < pairs; i++)
    {
        const char *s;
        uint32_t    slen;

        rc = cbor_read_text(r, &s, &slen);
        if(rc != CBOR_OK) { return 0; }

        if(slen == 2 && s[0] == 'r' && s[1] == 'k')
        {
            uint8_t b;

            rc = cbor_read_bool(r, &b);
            if(rc == CBOR_OK && b) { rk = 1; }
        }
        else if(slen == 2 && s[0] == 'u' && s[1] == 'p')
        {
            uint8_t b;

            rc = cbor_read_bool(r, &b);
            if(rc == CBOR_OK) { up = b; }
        }
        else
        {
            rc = cbor_skip_item(r);
            if(rc != CBOR_OK) { return 0; }
        }
    }

    if(up_out != NULL) { *up_out = up; }
    return rk;
}

/**
 * @brief 找第一个空槽；-1 表示无空槽
 */
static int16_t ctap_find_free_slot(void)
{
    uint16_t i;

    for(i = 0; i < (SS_MAX_CRED_SLOTS - RESERVED_SLOTS); i++)
    {
        if(secure_store_read_cred(i, &s_rec) == 1)
        {
            return (int16_t)i;              /* 1 = 空槽 */
        }
    }
    return -1;
}

/*********************************************************************
 * @fn      ctap_build_authdata
 *
 * @brief   构造 authData（含 attestedCredentialData 与 COSE 公钥）
 * @return  写入的字节数；0 表示缓冲不足
 */
static uint16_t ctap_build_authdata(const uint8_t *rp_id_hash,
                                    uint8_t flags,
                                    uint32_t sign_count,
                                    const uint8_t *cred_id, uint16_t cred_id_len,
                                    const uint8_t *pub_key)
{
    uint32_t o = 0;

    if((uint32_t)32 + 1 + 4 + 16 + 2 + cred_id_len + 96 > AUTHDATA_MAX)
    {
        return 0;
    }

    memcpy(s_authdata + o, rp_id_hash, COSE_HASH_LEN);
    o += COSE_HASH_LEN;

    s_authdata[o++] = flags;

    s_authdata[o++] = (uint8_t)(sign_count >> 24);
    s_authdata[o++] = (uint8_t)(sign_count >> 16);
    s_authdata[o++] = (uint8_t)(sign_count >> 8);
    s_authdata[o++] = (uint8_t)(sign_count);

    /* ---- attestedCredentialData ---- */
    memcpy(s_authdata + o, g_aaguid, 16);
    o += 16;

    s_authdata[o++] = (uint8_t)(cred_id_len >> 8);
    s_authdata[o++] = (uint8_t)(cred_id_len);
    memcpy(s_authdata + o, cred_id, cred_id_len);
    o += cred_id_len;

    /* ---- COSE_Key（EC2 / ES256 / P-256）----
     *   { 1: 2, 3: -7, -1: 1, -2: x, -3: y }   —— 共 77 字节 */
    o = cbor_put_map_head(s_authdata, AUTHDATA_MAX, o, 5);
    if(o == CBOR_ENC_ERR) { return 0; }
    o = cbor_put_uint(s_authdata, AUTHDATA_MAX, o, 1);
    o = cbor_put_uint(s_authdata, AUTHDATA_MAX, o, 2);
    o = cbor_put_uint(s_authdata, AUTHDATA_MAX, o, 3);
    o = cbor_put_int(s_authdata, AUTHDATA_MAX, o, COSE_ALG_ES256);
    o = cbor_put_int(s_authdata, AUTHDATA_MAX, o, -1);
    o = cbor_put_uint(s_authdata, AUTHDATA_MAX, o, 1);
    o = cbor_put_int(s_authdata, AUTHDATA_MAX, o, -2);
    o = cbor_put_bytes(s_authdata, AUTHDATA_MAX, o, pub_key, 32);
    o = cbor_put_int(s_authdata, AUTHDATA_MAX, o, -3);
    o = cbor_put_bytes(s_authdata, AUTHDATA_MAX, o, pub_key + 32, 32);
    if(o == CBOR_ENC_ERR) { return 0; }

    return (uint16_t)o;
}

/*********************************************************************
 * @fn      ctap_make_credential
 *
 * @brief   authenticatorMakeCredential（CTAP 2.3 §6.1）
 *
 * 响应：
 *   map(3)
 *     1: fmt      = "none"
 *     2: authData = h'...'
 *     3: attStmt  = {}
 */
/*********************************************************************
 * @fn      ctap_up_gate
 *
 * @brief   用户存在（UP）闸门：所有会产生副作用的 CTAP 命令都必须先过这一关
 *
 * @return  0 = 已取得 UP，可以继续；1 = 需要挂起（本函数已发起等待）
 *
 * @note    这是"可重入重放"方案的核心：命令处理在**任何副作用之前**调用本函数，
 *          未取得 UP 时返回 CTAP_STATUS_PENDING；ctaphid 层保留报文不响应，
 *          等用户按键（或超时）后由 ctap_pending_poll() 重跑同一个命令。
 *          因为第一次调用什么都没做，重放是安全的，也不需要额外的挂起上下文。
 *
 *          ⚠️ 取得 UP（AUTH_WAIT_GRANTED）时这里**不清状态**——清了重放时会再次要求按键。
 *          状态由 ctap_pending_poll() 在完成后统一清除。
 */
static uint8_t ctap_up_gate(uint8_t need_up)
{
    /* 客户端在 options 里声明 up=false 时，不做用户在场确认。
     * 浏览器做"条件式 UI / 自动填充"探测时会这么发 —— 若仍然强制等待按键，
     * 网页会整整卡住一个 UP 超时周期，表现成"无响应"。 */
    if(!need_up)
    {
        return 0;
    }
    if(auth_sm_get() == AUTH_WAIT_GRANTED)
    {
        return 0;                       /* 已有 UP，放行 */
    }
    if(auth_sm_get() != AUTH_WAIT_ACTIVE)
    {
        auth_sm_request_up();           /* 首次进入：发起等待并提示用户 */
    }
    return 1;                           /* 需要挂起 */
}

static uint8_t ctap_make_credential(const uint8_t *param, uint16_t param_len,
                                    uint8_t *resp, uint16_t resp_max, uint16_t *resp_len)
{
    cbor_reader_t r;
    uint32_t      pairs;
    uint32_t      i;
    uint16_t      user_id_len = 0;

    /* 必须在解析参数之前清零：ctap_parse_user() 会把 user.id 直接写进
     * s_rec.user_id —— 如果推迟到"落盘"阶段再 memset，就把刚解析出来的
     * user.id 抹掉了（长度补得回来、内容补不回来），结果是存进 Flash 的
     * user.id 全为 0，登录时主机判定响应无效。 */
    memset(&s_rec, 0, sizeof(s_rec));
    uint8_t       have_cdh = 0;
    uint8_t       have_rp = 0;
    uint8_t       have_user = 0;
    uint8_t       es256_ok = 0;
    uint8_t       need_up = 1;      /* options.up，缺省 true */
    uint32_t      o;
    int           rc;

    /* 注：UP 闸门已移到参数解析之后、任何副作用之前（见下方第 3 步）。
     * 原因是 need_up 来自 options，必须在解析时才能得知。
     * 解析本身不产生副作用，重放安全。 */

    /* 1) 先整体扫一遍，按需跳过未知/不关心的字段 */
    cbor_init(&r, param, param_len);
    rc = cbor_read_map(&r, &pairs);
    if(rc != CBOR_OK) { return CTAP_ERR_INVALID_CBOR; }

    for(i = 0; i < pairs; i++)
    {
        uint32_t key;

        rc = cbor_read_uint(&r, &key);
        if(rc != CBOR_OK) { return CTAP_ERR_INVALID_CBOR; }

        switch(key)
        {
            case MC_CLIENT_DATA_HASH:
            {
                const uint8_t *p;
                uint32_t       l;

                rc = cbor_read_bytes(&r, &p, &l);
                if(rc != CBOR_OK) { return CTAP_ERR_INVALID_CBOR; }
                if(l != COSE_HASH_LEN) { return CTAP_ERR_INVALID_LEN; }
                memcpy(s_cdh, p, COSE_HASH_LEN);
                have_cdh = 1;
                break;
            }

            case MC_RP:
                rc = ctap_parse_rp(&r, s_rp_id_hash);
                if(rc == CBOR_ERR_NOTFOUND) { return CTAP_ERR_MISSING_PARAMETER; }
                if(rc != CBOR_OK) { return CTAP_ERR_INVALID_CBOR; }
                have_rp = 1;
                break;

            case MC_USER:
                rc = ctap_parse_user(&r, s_rec.user_id, SS_USER_ID_MAX, &user_id_len);
                if(rc == CBOR_ERR_NOTFOUND) { return CTAP_ERR_MISSING_PARAMETER; }
                if(rc != CBOR_OK) { return CTAP_ERR_INVALID_PARAMETER; }
                have_user = 1;
                break;

            case MC_PUB_KEY_CRED_PARAMS:
                rc = ctap_check_algs(&r, &es256_ok);
                if(rc != CBOR_OK) { return CTAP_ERR_INVALID_CBOR; }
                break;

            case MC_EXCLUDE_LIST:
                rc = ctap_check_exclude_list(&r);
                if(rc == 1) { return CTAP_ERR_CREDENTIAL_EXCLUDED; }
                if(rc != CBOR_OK) { return CTAP_ERR_INVALID_CBOR; }
                break;

            case MC_OPTIONS:
                /* rk=true 需要可驻留凭证，本实现尚未支持，如实拒绝；
                 * 同时取出 up 标志决定后面是否需要等用户确认。 */
                if(ctap_check_options(&r, &need_up)) { return CTAP_ERR_UNSUPPORTED_OPTION; }
                break;

            default:
                rc = cbor_skip_item(&r);
                if(rc != CBOR_OK) { return CTAP_ERR_INVALID_CBOR; }
                break;
        }
    }

    /* 2) 必备参数检查 */
    if(!have_cdh)  { return CTAP_ERR_MISSING_PARAMETER; }
    if(!have_rp)   { return CTAP_ERR_MISSING_PARAMETER; }
    if(!have_user) { return CTAP_ERR_MISSING_PARAMETER; }
    if(!es256_ok)  { return CTAP_ERR_UNSUPPORTED_ALGORITHM; }

    /* 3) UP 闸门：参数已解析，here 之前无任何副作用 */
    if(ctap_up_gate(need_up) != 0)
    {
        return CTAP_STATUS_PENDING;
    }

    /* 3) 生成密钥对 */
    if(ecdsa_generate_keypair(s_priv, s_pub) != 0)
    {
        return CTAP_ERR_OTHER;
    }

    /* 4) 分配槽位 */
    {
        int16_t slot = ctap_find_free_slot();

        if(slot < 0)
        {
            memset(s_priv, 0, sizeof(s_priv));
            return CTAP_ERR_KEY_STORE_FULL;
        }

        /* 5) 生成 credId（32 字节随机） */
        if(get_random_bytes(s_cred_id, CRED_ID_LEN) != 0)
        {
            memset(s_priv, 0, sizeof(s_priv));
            return CTAP_ERR_OTHER;
        }

        /* 6) 落盘：私钥用存储密钥加密后写入
         *（s_rec 已在函数开头清零，此处不要重复 memset，否则会抹掉
         *  ctap_parse_user() 解析出来的 user.id） */
        s_rec.magic      = SS_CRED_MAGIC;
        s_rec.sign_count = 0;
        memcpy(s_rec.rp_id_hash, s_rp_id_hash, SS_RP_ID_HASH_LEN);
        memcpy(s_rec.pub_key, s_pub, 64);
        s_rec.cred_id_len = CRED_ID_LEN;
        memcpy(s_rec.cred_id, s_cred_id, CRED_ID_LEN);
        s_rec.user_id_len = (uint8_t)user_id_len;

        if(secure_store_encrypt_priv((uint16_t)slot, s_priv, s_rec.priv_enc) != 0)
        {
            memset(s_priv, 0, sizeof(s_priv));
            return CTAP_ERR_OTHER;
        }
        if(secure_store_write_cred((uint16_t)slot, &s_rec) != 0)
        {
            memset(s_priv, 0, sizeof(s_priv));
            return CTAP_ERR_OTHER;
        }
    }

    /* 7) 构造 authData（UP + AT） */
    {
        uint16_t alen = ctap_build_authdata(s_rp_id_hash,
                                            (uint8_t)(FLAG_UP | FLAG_AT),
                                            0,
                                            s_cred_id, CRED_ID_LEN,
                                            s_pub);
        if(alen == 0)
        {
            memset(s_priv, 0, sizeof(s_priv));
            return CTAP_ERR_OTHER;
        }
        /* 8) 对 authData ‖ clientDataHash 求 SHA-256，再用私钥签名 */
        {
            uint8_t  digest[COSE_HASH_LEN];
            uint8_t  sr[32];
            uint8_t  ss[32];

            memcpy(s_signbuf, s_authdata, alen);
            memcpy(s_signbuf + alen, s_cdh, COSE_HASH_LEN);

            if(sha256(s_signbuf, (uint32_t)alen + COSE_HASH_LEN, digest) != 0)
            {
                memset(s_priv, 0, sizeof(s_priv));
                return CTAP_ERR_OTHER;
            }

            /* attestation = "none" 时不做签名，但先验证签名链路可用：
             * 这一步同时作为 MakeCredential 的自检（失败即报错，
             * 避免把不可用的凭证写进 Flash 后才发现）。 */
            if(ecdsa_sign(s_priv, digest, sr, ss) != 0)
            {
                memset(s_priv, 0, sizeof(s_priv));
                return CTAP_ERR_OTHER;
            }
            if(ecdsa_verify(s_pub, digest, sr, ss) != 0)
            {
                memset(s_priv, 0, sizeof(s_priv));
                return CTAP_ERR_OTHER;
            }
        }

        /* 9) 组装 attestationObject = { 1: "none", 2: h'authData', 3: {} } */
        o = cbor_put_map_head(s_attobj, ATTOBJ_MAX, 0, 3);
        if(o == CBOR_ENC_ERR) { memset(s_priv, 0, sizeof(s_priv)); return CTAP_ERR_OTHER; }
        o = cbor_put_uint(s_attobj, ATTOBJ_MAX, o, 1);
        o = cbor_put_text(s_attobj, ATTOBJ_MAX, o, "none", 4);
        o = cbor_put_uint(s_attobj, ATTOBJ_MAX, o, 2);
        o = cbor_put_bytes(s_attobj, ATTOBJ_MAX, o, s_authdata, alen);
        o = cbor_put_uint(s_attobj, ATTOBJ_MAX, o, 3);
        o = cbor_put_map_head(s_attobj, ATTOBJ_MAX, o, 0);
        if(o == CBOR_ENC_ERR) { memset(s_priv, 0, sizeof(s_priv)); return CTAP_ERR_OTHER; }
    }

    memset(s_priv, 0, sizeof(s_priv));

    /* 10) 直接把 attestationObject 作为响应体返回 */
    {
        uint32_t attobj_len = o;

        if(attobj_len > resp_max) { return CTAP_ERR_OTHER; }
        memcpy(resp, s_attobj, attobj_len);
        *resp_len = (uint16_t)attobj_len;
    }

    return CTAP_SUCCESS;
}

/*********************************************************************
 * @fn      ctap_find_cred_by_id
 *
 * @brief   按 credId 查找凭证槽；命中时该记录留在 s_rec
 * @return  槽号，-1 表示未找到
 */
static int16_t ctap_find_cred_by_id(const uint8_t *cid, uint32_t clen)
{
    uint16_t slot = 0;

    if(cred_find_by_id(cid, clen, &slot, &s_rec) != 0)
    {
        return -1;
    }
    return (int16_t)slot;
}

/*********************************************************************
 * @fn      ctap_find_cred_by_rp
 *
 * @brief   按 rpIdHash 查找凭证槽（allowList 为空时的回退路径）
 */
static int16_t ctap_find_cred_by_rp(const uint8_t *rp_hash)
{
    uint16_t slot = 0;

    if(cred_find_by_rp(rp_hash, &slot, &s_rec) != 0)
    {
        return -1;
    }
    return (int16_t)slot;
}

/*********************************************************************
 * @fn      ctap_get_assertion
 *
 * @brief   authenticatorGetAssertion（CTAP 2.3 6.2）
 *
 * 响应：
 *   map(4)
 *     1: credential { 1: h'credId', 2: "public-key" }
 *     2: authData   = rpIdHash(32) | flags(1) | signCount(4,BE)  —— 37 字节，无 attested 数据
 *     3: signature  = r||s（64 字节）
 *     4: user       { 1: h'userId' }
 */
static uint8_t ctap_get_assertion(const uint8_t *param, uint16_t param_len,
                                  uint8_t *resp, uint16_t resp_max, uint16_t *resp_len)
{
    cbor_reader_t r;
    uint32_t      pairs;
    uint32_t      i;
    uint32_t      allow_off = 0;
    uint8_t       have_cdh = 0;
    uint8_t       have_rp = 0;
    uint8_t       have_allow = 0;
    int16_t       slot = -1;
    uint8_t       need_up = 1;      /* options.up，缺省 true */
    uint32_t      o;
    int           rc;

    /* 注：UP 闸门已移到"取到凭证之后、写回 signCount 之前"（见下方）。
     * 这样 options.up=false 的探测请求不会白等一个超时周期。 */

    cbor_init(&r, param, param_len);
    rc = cbor_read_map(&r, &pairs);
    if(rc != CBOR_OK) { return CTAP_ERR_INVALID_CBOR; }

    for(i = 0; i < pairs; i++)
    {
        uint32_t key;

        rc = cbor_read_uint(&r, &key);
        if(rc != CBOR_OK) { return CTAP_ERR_INVALID_CBOR; }

        switch(key)
        {
            case GA_RP_ID:
            {
                const char *t;
                uint32_t    slen;

                rc = cbor_read_text(&r, &t, &slen);
                if(rc != CBOR_OK) { return CTAP_ERR_INVALID_CBOR; }
                if(slen == 0 || slen > 255) { return CTAP_ERR_INVALID_PARAMETER; }
                if(sha256((const uint8_t *)t, slen, s_rp_id_hash) != 0)
                {
                    return CTAP_ERR_OTHER;
                }
                have_rp = 1;
                break;
            }

            case GA_CLIENT_DATA_HASH:
            {
                const uint8_t *bp;
                uint32_t       blen;

                rc = cbor_read_bytes(&r, &bp, &blen);
                if(rc != CBOR_OK) { return CTAP_ERR_INVALID_CBOR; }
                if(blen != COSE_HASH_LEN) { return CTAP_ERR_INVALID_LEN; }
                memcpy(s_cdh, bp, COSE_HASH_LEN);
                have_cdh = 1;
                break;
            }

            case GA_ALLOW_LIST:
                /* 先记住位置：rpId 可能排在其后，需等解析完再回扫匹配 */
                allow_off = r.off;
                have_allow = 1;
                rc = cbor_skip_item(&r);
                if(rc != CBOR_OK) { return CTAP_ERR_INVALID_CBOR; }
                break;

            case GA_OPTIONS:
            {
                /* 复用 makeCredential 的解析：只关心 up，rk 在本处无意义 */
                (void)ctap_check_options(&r, &need_up);
                break;
            }

            default:
                rc = cbor_skip_item(&r);
                if(rc != CBOR_OK) { return CTAP_ERR_INVALID_CBOR; }
                break;
        }
    }

    if(!have_cdh) { return CTAP_ERR_MISSING_PARAMETER; }
    if(!have_rp)  { return CTAP_ERR_MISSING_PARAMETER; }

    /* 1) 定位凭证：allowList 非空则按 credId 匹配，否则按 rpIdHash 回退 */
    if(have_allow)
    {
        cbor_reader_t ar;
        uint32_t      count;

        cbor_init(&ar, param + allow_off, (uint32_t)param_len - allow_off);
        rc = cbor_read_array(&ar, &count);
        if(rc != CBOR_OK) { return CTAP_ERR_INVALID_CBOR; }

        for(i = 0; i < count && slot < 0; i++)
        {
            uint32_t       apairs;
            uint32_t       j;
            const uint8_t *cid = NULL;
            uint32_t       cid_len = 0;

            rc = cbor_read_map(&ar, &apairs);
            if(rc != CBOR_OK) { return CTAP_ERR_INVALID_CBOR; }

            for(j = 0; j < apairs; j++)
            {
                const char *key;
                uint32_t    klen;

                rc = cbor_read_text(&ar, &key, &klen);
                if(rc != CBOR_OK) { return CTAP_ERR_INVALID_CBOR; }

                if(klen == 2 && memcmp(key, "id", 2) == 0)
                {
                    rc = cbor_read_bytes(&ar, &cid, &cid_len);
                    if(rc != CBOR_OK) { return CTAP_ERR_INVALID_CBOR; }
                }
                else
                {
                    rc = cbor_skip_item(&ar);
                    if(rc != CBOR_OK) { return CTAP_ERR_INVALID_CBOR; }
                }
            }
            if(cid != NULL && cid_len > 0)
            {
                slot = ctap_find_cred_by_id(cid, cid_len);
            }
        }
    }
    else
    {
        slot = ctap_find_cred_by_rp(s_rp_id_hash);
    }

    if(slot < 0)
    {
        return CTAP_ERR_NO_CREDENTIALS;
    }

    /* UP 闸门：放在这里而不是函数开头 —— 先确认确实存在匹配的凭证，
     * 避免浏览器那些 options.up=false 的探测请求白等一个 UP 超时周期
     * （那正是网页"无响应"的直接原因）。此后到写回 signCount 之间无副作用。 */
    if(ctap_up_gate(need_up) != 0)
    {
        return CTAP_STATUS_PENDING;
    }

    /* 2) 解密私钥 */
    if(secure_store_decrypt_priv((uint16_t)slot, &s_rec, s_priv) != 0)
    {
        return CTAP_ERR_OTHER;
    }

    /* 3) signCount 递增并持久化（计划 3.6）。
     *    私钥密文的 tweak 只依赖槽号，同槽重写可直接沿用 priv_enc，无需重新加密。 */
    s_rec.sign_count++;
    if(secure_store_write_cred((uint16_t)slot, &s_rec) != 0)
    {
        memset(s_priv, 0, sizeof(s_priv));
        return CTAP_ERR_OTHER;
    }

    /* 4) authData：仅 rpIdHash | flags | signCount（37 字节，不带 AT） */
    memcpy(s_authdata, s_rp_id_hash, COSE_HASH_LEN);
    s_authdata[32] = FLAG_UP;
    s_authdata[33] = (uint8_t)(s_rec.sign_count >> 24);
    s_authdata[34] = (uint8_t)(s_rec.sign_count >> 16);
    s_authdata[35] = (uint8_t)(s_rec.sign_count >> 8);
    s_authdata[36] = (uint8_t)(s_rec.sign_count);

    /* 5) 对 authData(37) | clientDataHash 求 SHA-256 并签名 */
    {
        uint8_t digest[COSE_HASH_LEN];

        memcpy(s_signbuf, s_authdata, 37);
        memcpy(s_signbuf + 37, s_cdh, COSE_HASH_LEN);
        if(sha256(s_signbuf, 37 + COSE_HASH_LEN, digest) != 0)
        {
            memset(s_priv, 0, sizeof(s_priv));
            return CTAP_ERR_OTHER;
        }
        /* r 与 s 连续写入 s_sig，正好满足 CTAP 要求的 r||s 布局 */
        if(ecdsa_sign(s_priv, digest, s_sig, s_sig + 32) != 0)
        {
            memset(s_priv, 0, sizeof(s_priv));
            return CTAP_ERR_OTHER;
        }
    }
    memset(s_priv, 0, sizeof(s_priv));

    /* 6) 组装响应 */
    o = cbor_put_map_head(resp, resp_max, 0, 4);
    if(o == CBOR_ENC_ERR) { return CTAP_ERR_OTHER; }

    o = cbor_put_uint(resp, resp_max, o, 1);                 /* 1: credential */
    /* PublicKeyCredentialDescriptor 用文本键（与主机发来的 allowList 元素一致）：
     * 之前误用整数键 1/2，主机会按 "type" 取到 bytes，报"数据类型无效"。 */
    o = cbor_put_map_head(resp, resp_max, o, 2);
    o = cbor_put_text(resp, resp_max, o, "id", 2);
    o = cbor_put_bytes(resp, resp_max, o, s_rec.cred_id, s_rec.cred_id_len);
    o = cbor_put_text(resp, resp_max, o, "type", 4);
    o = cbor_put_text(resp, resp_max, o, "public-key", 10);
    if(o == CBOR_ENC_ERR) { return CTAP_ERR_OTHER; }

    o = cbor_put_uint(resp, resp_max, o, 2);                 /* 2: authData */
    o = cbor_put_bytes(resp, resp_max, o, s_authdata, 37);
    if(o == CBOR_ENC_ERR) { return CTAP_ERR_OTHER; }

    o = cbor_put_uint(resp, resp_max, o, 3);                 /* 3: signature */
    o = cbor_put_bytes(resp, resp_max, o, s_sig, 64);
    if(o == CBOR_ENC_ERR) { return CTAP_ERR_OTHER; }

    o = cbor_put_uint(resp, resp_max, o, 4);                 /* 4: user */
    /* PublicKeyCredentialUserEntity 同样用文本键 "id" */
    o = cbor_put_map_head(resp, resp_max, o, 1);
    o = cbor_put_text(resp, resp_max, o, "id", 2);
    o = cbor_put_bytes(resp, resp_max, o, s_rec.user_id, s_rec.user_id_len);
    if(o == CBOR_ENC_ERR) { return CTAP_ERR_OTHER; }

    *resp_len = (uint16_t)o;
    return CTAP_SUCCESS;
}

/*********************************************************************
 * @fn      ctap_pending_poll
 *
 * @brief   推进被挂起的 CTAP 操作（由主循环调用）
 *
 * 流程：命令处理在副作用之前调用 ctap_up_gate()，未取得 UP 时返回
 *       CTAP_STATUS_PENDING；ctaphid 层保留报文、不发响应，并置挂起标志。
 *       用户按键（AUTH_WAIT_GRANTED）后本函数让 ctaphid 用保留的报文重跑该命令；
 *       超时（AUTH_WAIT_TIMEOUT）则按规范回填 CTAP_ERR_ACTION_TIMEOUT。
 *
 * 为什么这样是安全的：第一次进入时命令只过了 UP 闸门就返回，
 *       没有产生任何持久化副作用（也没写 Flash），所以重放不会造成重复副作用。
 */
void ctap_pending_poll(void)
{
    if(!ctaphid_ctap_is_pending())
    {
        /* 没有挂起的 CTAP 请求，但 UP 等待可能还开着——典型场景是 USB 总线复位：
         * ctaphid_reset() 清了挂起标志，auth_sm 却仍在等待。若不在这里收掉，
         * LED 会一直慢闪、状态机永远停在 ACTIVE，下一次请求也会被误判。
         * 放在这里（主循环上下文）而不是 ctaphid_reset()（中断上下文）里清，
         * 是因为 auth_sm_clear() 会走 LED 库、涉及 TMOS，不宜在中断里调用。 */
        if(auth_sm_get() == AUTH_WAIT_ACTIVE)
        {
            SK_LOG("ctap: dangling UP wait cleared");
            auth_sm_clear();
        }
        return;
    }

    switch(auth_sm_get())
    {
        case AUTH_WAIT_GRANTED:
            /* 用户已确认：重跑挂起的命令。重跑过程中 ctap_up_gate() 会放行。
             * 注意 clear 必须在重跑之后——先清会导致重跑时再次要求按键。 */
            SK_LOG("ctap: UP granted, reprocess");
            (void)ctaphid_reprocess();
            auth_sm_clear();
            break;

        case AUTH_WAIT_TIMEOUT:
            SK_LOG("ctap: UP timeout -> 0x3A");
            auth_sm_clear();
            (void)ctaphid_ctap_reply(CTAP_ERR_ACTION_TIMEOUT, NULL, 0);
            break;

        default:
            break;                          /* 仍在等待用户 */
    }
}

/*********************************************************************
 * @fn      ctap_abort_pending
 *
 * @brief   中止挂起的操作（CTAPHID_CANCEL 触发）
 *
 * @note    只清"等待用户存在"的状态。因为采用可重入重放方案，
 *          挂起期间并没有保存任何操作上下文（每次重放都从头解析），
 *          也就不需要在别处清理什么。按规范 CANCEL 不产生响应。
 */
void ctap_abort_pending(void)
{
    auth_sm_clear();
}

/*********************************************************************
 * @fn      ctap_handle_cbor
 *
 * @brief   处理一条 CTAP2 CBOR 请求
 */
uint8_t ctap_handle_cbor(uint8_t cmd,
                         const uint8_t *param, uint16_t param_len,
                         uint8_t *resp, uint16_t resp_max,
                         uint16_t *resp_len)
{
    if(resp == NULL || resp_len == NULL)
    {
        return CTAP_ERR_OTHER;
    }

    SK_LOG("ctap: cmd=0x%02x param=%d", cmd, param_len);

    switch(cmd)
    {
        case CTAP_CMD_GET_INFO:
        {
            uint16_t n = ctap_build_get_info(resp, resp_max);
            if(n == 0)
            {
                return CTAP_ERR_OTHER;
            }
            *resp_len = n;
            return CTAP_SUCCESS;
        }

        case CTAP_CMD_MAKE_CREDENTIAL:
            return ctap_make_credential(param, param_len, resp, resp_max, resp_len);

        case CTAP_CMD_GET_ASSERTION:
            return ctap_get_assertion(param, param_len, resp, resp_max, resp_len);

        default:
            return CTAP_ERR_INVALID_COMMAND;
    }
}
