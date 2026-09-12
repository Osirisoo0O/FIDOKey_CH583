/**
 * @file cbor_lite.c
 * @brief 最小可用 CBOR 编解码实现，对应开发计划 2.6
 *
 * 安全立场：解码输入全部来自主机（不可信）。
 *   1. 每次读取前都检查剩余长度，长度字段超出剩余字节即报错，绝不截断使用；
 *   2. 8 字节长度/数值若高 4 字节非 0，直接按超范围拒绝；
 *   3. 不定长编码(ai=31)、tag、float 全部拒绝；
 *   4. cbor_skip_item() 是迭代实现 + 深度上限，不会被恶意嵌套打爆栈。
 */

#include "stdint.h"
#include "string.h"
#include "cbor_lite.h"

/*********************************************************************
 * @fn      cbor_init
 */
void cbor_init(cbor_reader_t *r, const uint8_t *buf, uint32_t len)
{
    if(r == NULL)
    {
        return;
    }
    r->buf = buf;
    r->len = (buf == NULL) ? 0 : len;
    r->off = 0;
}

/*********************************************************************
 * @fn      cbor_read_item
 */
int cbor_read_item(cbor_reader_t *r, cbor_item_t *it)
{
    uint8_t  ib;
    uint8_t  major;
    uint8_t  ai;
    uint8_t  nbytes;
    uint8_t  i;
    uint32_t arg;

    if(r == NULL || it == NULL || r->buf == NULL)
    {
        return CBOR_ERR_ARG;
    }
    if(r->off >= r->len)
    {
        return CBOR_ERR_TRUNC;
    }

    ib    = r->buf[r->off++];
    major = (uint8_t)(ib >> 5);
    ai    = (uint8_t)(ib & 0x1FU);

    arg    = 0;
    nbytes = 0;

    if(ai < 24)
    {
        arg = ai;
    }
    else if(ai == 24) { nbytes = 1; }
    else if(ai == 25) { nbytes = 2; }
    else if(ai == 26) { nbytes = 4; }
    else if(ai == 27) { nbytes = 8; }
    else if(ai == 31) { return CBOR_ERR_INDEF; }
    else              { return CBOR_ERR_TYPE; }   /* 28~30 保留 */

    if(nbytes != 0)
    {
        if((r->len - r->off) < (uint32_t)nbytes)
        {
            return CBOR_ERR_TRUNC;
        }
        if(nbytes == 8)
        {
            /* 高 4 字节必须为 0，否则超过 32 位可表示范围 */
            for(i = 0; i < 4; i++)
            {
                if(r->buf[r->off + i] != 0)
                {
                    return CBOR_ERR_RANGE;
                }
            }
            r->off += 4;
            nbytes = 4;
        }
        for(i = 0; i < nbytes; i++)
        {
            arg = (arg << 8) | (uint32_t)r->buf[r->off++];
        }
    }

    it->type     = major;
    it->arg      = arg;
    it->data     = NULL;
    it->data_len = 0;

    switch(major)
    {
        case CBOR_TYPE_UINT:
        case CBOR_TYPE_NINT:
        case CBOR_TYPE_ARRAY:
        case CBOR_TYPE_MAP:
            /* arg 即数值 / 元素个数，内容由调用方继续读 */
            break;

        case CBOR_TYPE_BYTES:
        case CBOR_TYPE_TEXT:
            if((r->len - r->off) < arg)
            {
                return CBOR_ERR_TRUNC;
            }
            it->data     = r->buf + r->off;
            it->data_len = arg;
            r->off += arg;
            break;

        case CBOR_TYPE_TAG:
            return CBOR_ERR_TYPE;       /* CTAP 不使用 tag */

        case CBOR_TYPE_SIMPLE:
            /* 只接受 simple 值；float16/32/64 拒绝 */
            if(ai == 25 || ai == 26 || ai == 27)
            {
                return CBOR_ERR_TYPE;
            }
            break;

        default:
            return CBOR_ERR_TYPE;
    }

    return CBOR_OK;
}

/*********************************************************************
 * @fn      cbor_skip_item
 *
 * @brief   跳过一个完整数据项（含嵌套容器）
 *
 * @note    迭代实现：pending[] 记录每一层还需跳过的元素数，
 *          深度超过 CBOR_MAX_DEPTH 直接报错，不会递归爆栈。
 */
int cbor_skip_item(cbor_reader_t *r)
{
    uint32_t   pending[CBOR_MAX_DEPTH];
    uint32_t   depth;
    cbor_item_t it;
    int        rc;

    if(r == NULL)
    {
        return CBOR_ERR_ARG;
    }

    pending[0] = 1;
    depth      = 1;

    while(depth > 0)
    {
        while(pending[depth - 1] == 0)
        {
            depth--;
            if(depth == 0)
            {
                return CBOR_OK;
            }
        }
        pending[depth - 1]--;

        rc = cbor_read_item(r, &it);
        if(rc != CBOR_OK)
        {
            return rc;
        }

        if(it.type == CBOR_TYPE_ARRAY || it.type == CBOR_TYPE_MAP)
        {
            uint32_t n = it.arg;

            if(it.type == CBOR_TYPE_MAP)
            {
                if(n > (0xFFFFFFFFUL / 2))
                {
                    return CBOR_ERR_RANGE;
                }
                n *= 2;                 /* map 每对是键 + 值 */
            }
            if(n == 0)
            {
                continue;
            }
            if(depth >= CBOR_MAX_DEPTH)
            {
                return CBOR_ERR_DEPTH;
            }
            pending[depth] = n;
            depth++;
        }
    }

    return CBOR_OK;
}

/*********************************************************************
 * 各类型读取封装
 */

int cbor_read_uint(cbor_reader_t *r, uint32_t *out)
{
    cbor_item_t it;
    int rc;

    if(out == NULL)
    {
        return CBOR_ERR_ARG;
    }
    rc = cbor_read_item(r, &it);
    if(rc != CBOR_OK)
    {
        return rc;
    }
    if(it.type != CBOR_TYPE_UINT)
    {
        return CBOR_ERR_TYPE;
    }
    *out = it.arg;
    return CBOR_OK;
}

int cbor_read_int(cbor_reader_t *r, int32_t *out)
{
    cbor_item_t it;
    int rc;

    if(out == NULL)
    {
        return CBOR_ERR_ARG;
    }
    rc = cbor_read_item(r, &it);
    if(rc != CBOR_OK)
    {
        return rc;
    }
    if(it.type == CBOR_TYPE_UINT)
    {
        if(it.arg > 0x7FFFFFFFUL)
        {
            return CBOR_ERR_RANGE;
        }
        *out = (int32_t)it.arg;
        return CBOR_OK;
    }
    if(it.type == CBOR_TYPE_NINT)
    {
        if(it.arg > 0x7FFFFFFFUL)
        {
            return CBOR_ERR_RANGE;
        }
        *out = (int32_t)(-1 - (int32_t)it.arg);
        return CBOR_OK;
    }
    return CBOR_ERR_TYPE;
}

int cbor_read_bool(cbor_reader_t *r, uint8_t *out)
{
    cbor_item_t it;
    int rc;

    if(out == NULL)
    {
        return CBOR_ERR_ARG;
    }
    rc = cbor_read_item(r, &it);
    if(rc != CBOR_OK)
    {
        return rc;
    }
    if(it.type != CBOR_TYPE_SIMPLE)
    {
        return CBOR_ERR_TYPE;
    }
    if(it.arg == CBOR_SIMPLE_TRUE)
    {
        *out = 1;
        return CBOR_OK;
    }
    if(it.arg == CBOR_SIMPLE_FALSE)
    {
        *out = 0;
        return CBOR_OK;
    }
    return CBOR_ERR_TYPE;
}

int cbor_read_bytes(cbor_reader_t *r, const uint8_t **p, uint32_t *n)
{
    cbor_item_t it;
    int rc;

    if(p == NULL || n == NULL)
    {
        return CBOR_ERR_ARG;
    }
    rc = cbor_read_item(r, &it);
    if(rc != CBOR_OK)
    {
        return rc;
    }
    if(it.type != CBOR_TYPE_BYTES)
    {
        return CBOR_ERR_TYPE;
    }
    *p = it.data;
    *n = it.data_len;
    return CBOR_OK;
}

int cbor_read_text(cbor_reader_t *r, const char **s, uint32_t *n)
{
    cbor_item_t it;
    int rc;

    if(s == NULL || n == NULL)
    {
        return CBOR_ERR_ARG;
    }
    rc = cbor_read_item(r, &it);
    if(rc != CBOR_OK)
    {
        return rc;
    }
    if(it.type != CBOR_TYPE_TEXT)
    {
        return CBOR_ERR_TYPE;
    }
    *s = (const char *)it.data;
    *n = it.data_len;
    return CBOR_OK;
}

int cbor_read_array(cbor_reader_t *r, uint32_t *count)
{
    cbor_item_t it;
    int rc;

    if(count == NULL)
    {
        return CBOR_ERR_ARG;
    }
    rc = cbor_read_item(r, &it);
    if(rc != CBOR_OK)
    {
        return rc;
    }
    if(it.type != CBOR_TYPE_ARRAY)
    {
        return CBOR_ERR_TYPE;
    }
    *count = it.arg;
    return CBOR_OK;
}

int cbor_read_map(cbor_reader_t *r, uint32_t *count)
{
    cbor_item_t it;
    int rc;

    if(count == NULL)
    {
        return CBOR_ERR_ARG;
    }
    rc = cbor_read_item(r, &it);
    if(rc != CBOR_OK)
    {
        return rc;
    }
    if(it.type != CBOR_TYPE_MAP)
    {
        return CBOR_ERR_TYPE;
    }
    *count = it.arg;
    return CBOR_OK;
}

/*********************************************************************
 * @fn      cbor_map_seek
 */
int cbor_map_seek(cbor_reader_t *r, uint32_t pairs, uint32_t key)
{
    uint32_t    i;
    cbor_item_t it;
    int         rc;

    if(r == NULL)
    {
        return CBOR_ERR_ARG;
    }

    for(i = 0; i < pairs; i++)
    {
        rc = cbor_read_item(r, &it);
        if(rc != CBOR_OK)
        {
            return rc;
        }
        if(it.type == CBOR_TYPE_UINT && it.arg == key)
        {
            return CBOR_OK;             /* reader 已停在值之前 */
        }
        rc = cbor_skip_item(r);         /* 不是目标键：跳过它的值 */
        if(rc != CBOR_OK)
        {
            return rc;
        }
    }
    return CBOR_ERR_NOTFOUND;
}

/*********************************************************************
 * 编码
 */

static uint32_t cbor_put_head(uint8_t *buf, uint32_t cap, uint32_t off,
                              uint8_t major, uint32_t arg)
{
    if(buf == NULL)
    {
        return CBOR_ENC_ERR;
    }

    if(arg < 24)
    {
        if((off + 1) > cap) return CBOR_ENC_ERR;
        buf[off++] = (uint8_t)((major << 5) | (uint8_t)arg);
    }
    else if(arg <= 0xFFUL)
    {
        if((off + 2) > cap) return CBOR_ENC_ERR;
        buf[off++] = (uint8_t)((major << 5) | 24);
        buf[off++] = (uint8_t)arg;
    }
    else if(arg <= 0xFFFFUL)
    {
        if((off + 3) > cap) return CBOR_ENC_ERR;
        buf[off++] = (uint8_t)((major << 5) | 25);
        buf[off++] = (uint8_t)(arg >> 8);
        buf[off++] = (uint8_t)arg;
    }
    else
    {
        if((off + 5) > cap) return CBOR_ENC_ERR;
        buf[off++] = (uint8_t)((major << 5) | 26);
        buf[off++] = (uint8_t)(arg >> 24);
        buf[off++] = (uint8_t)(arg >> 16);
        buf[off++] = (uint8_t)(arg >> 8);
        buf[off++] = (uint8_t)arg;
    }
    return off;
}

uint32_t cbor_put_uint(uint8_t *buf, uint32_t cap, uint32_t off, uint32_t v)
{
    return cbor_put_head(buf, cap, off, CBOR_TYPE_UINT, v);
}

uint32_t cbor_put_int(uint8_t *buf, uint32_t cap, uint32_t off, int32_t v)
{
    if(v >= 0)
    {
        return cbor_put_head(buf, cap, off, CBOR_TYPE_UINT, (uint32_t)v);
    }
    return cbor_put_head(buf, cap, off, CBOR_TYPE_NINT, (uint32_t)(-1 - v));
}

uint32_t cbor_put_bytes(uint8_t *buf, uint32_t cap, uint32_t off,
                        const uint8_t *d, uint32_t n)
{
    uint32_t o = cbor_put_head(buf, cap, off, CBOR_TYPE_BYTES, n);

    if(o == CBOR_ENC_ERR)
    {
        return CBOR_ENC_ERR;
    }
    if(n == 0)
    {
        return o;
    }
    if(d == NULL || (o + n) > cap)
    {
        return CBOR_ENC_ERR;
    }
    memcpy(buf + o, d, n);
    return o + n;
}

uint32_t cbor_put_text(uint8_t *buf, uint32_t cap, uint32_t off,
                       const char *s, uint32_t n)
{
    uint32_t o = cbor_put_head(buf, cap, off, CBOR_TYPE_TEXT, n);

    if(o == CBOR_ENC_ERR)
    {
        return CBOR_ENC_ERR;
    }
    if(n == 0)
    {
        return o;
    }
    if(s == NULL || (o + n) > cap)
    {
        return CBOR_ENC_ERR;
    }
    memcpy(buf + o, s, n);
    return o + n;
}

uint32_t cbor_put_array_head(uint8_t *buf, uint32_t cap, uint32_t off, uint32_t n)
{
    return cbor_put_head(buf, cap, off, CBOR_TYPE_ARRAY, n);
}

uint32_t cbor_put_map_head(uint8_t *buf, uint32_t cap, uint32_t off, uint32_t n)
{
    return cbor_put_head(buf, cap, off, CBOR_TYPE_MAP, n);
}

uint32_t cbor_put_bool(uint8_t *buf, uint32_t cap, uint32_t off, uint8_t b)
{
    if(buf == NULL || (off + 1) > cap)
    {
        return CBOR_ENC_ERR;
    }
    buf[off++] = b ? 0xF5U : 0xF4U;
    return off;
}

uint32_t cbor_put_null(uint8_t *buf, uint32_t cap, uint32_t off)
{
    if(buf == NULL || (off + 1) > cap)
    {
        return CBOR_ENC_ERR;
    }
    buf[off++] = 0xF6U;
    return off;
}

/*********************************************************************
 * @fn      cbor_selftest
 *
 * @brief   编解码自测：基本解码 / 容器跳过 / map 按键查找 /
 *          畸形输入负向用例 / 编码容量保护 / 编码-解码往返
 */
int8_t cbor_selftest(void)
{
    static const uint8_t v_uint1[]   = { 0x01 };
    static const uint8_t v_uint100[] = { 0x18, 0x64 };
    static const uint8_t v_uint256[] = { 0x19, 0x01, 0x00 };
    static const uint8_t v_nint7[]   = { 0x26 };
    static const uint8_t v_bytes[]   = { 0x43, 0x01, 0x02, 0x03 };
    static const uint8_t v_text[]    = { 0x63, 'a', 'b', 'c' };
    static const uint8_t v_map[]     = { 0xA2, 0x01, 0x02, 0x03, 0x04 };
    static const uint8_t v_arr[]     = { 0x82, 0x01, 0x02 };
    static const uint8_t v_true[]    = { 0xF5 };
    /* 以下为畸形输入，必须被拒绝 */
    static const uint8_t e_trunc[]   = { 0x18 };
    static const uint8_t e_biglen[]  = { 0x5A, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };
    static const uint8_t e_indef[]   = { 0x1F };
    static const uint8_t e_float[]   = { 0xF9, 0x00, 0x00 };
    static const uint8_t e_tag[]     = { 0xC0, 0x01 };
    static const uint8_t e_biguint[] = { 0x1B, 0x01, 0, 0, 0, 0, 0, 0, 0 };

    cbor_reader_t  r;
    cbor_item_t    it;
    uint32_t       u;
    uint32_t       n;
    const uint8_t *p;
    const char    *t;
    uint8_t        buf[32];
    uint32_t       off;
    int32_t        s;
    uint8_t        bl;

    /* ---- 1) 基本整数 ---- */
    cbor_init(&r, v_uint1, sizeof(v_uint1));
    if(cbor_read_uint(&r, &u) != CBOR_OK || u != 1)             { return -1; }

    cbor_init(&r, v_uint100, sizeof(v_uint100));
    if(cbor_read_uint(&r, &u) != CBOR_OK || u != 100)           { return -2; }

    cbor_init(&r, v_uint256, sizeof(v_uint256));
    if(cbor_read_uint(&r, &u) != CBOR_OK || u != 256)           { return -3; }

    cbor_init(&r, v_nint7, sizeof(v_nint7));
    if(cbor_read_int(&r, &s) != CBOR_OK || s != -7)             { return -4; }

    /* ---- 2) bytes / text ---- */
    cbor_init(&r, v_bytes, sizeof(v_bytes));
    if(cbor_read_bytes(&r, &p, &n) != CBOR_OK)                  { return -5; }
    if(n != 3 || p[0] != 1 || p[2] != 3)                        { return -6; }

    cbor_init(&r, v_text, sizeof(v_text));
    if(cbor_read_text(&r, &t, &n) != CBOR_OK)                   { return -7; }
    if(n != 3 || memcmp(t, "abc", 3) != 0)                      { return -8; }

    /* ---- 3) 容器跳过：必须正好停在末尾 ----
     *
     * ⚠️ 这里原来的写法把自己坑了，真机上报的 "CBOR selftest = -11" 就出在这：
     *    先 cbor_read_map() 读出容器头，**再**调 cbor_skip_item()，
     *    而此时 reader 已经进到容器内部，skip_item 按定义只跳过一个数据项
     *    （也就是 map 的第一个键 0x01），offset 自然到不了末尾。
     *
     *    cbor_skip_item() 的语义是"跳过一个完整数据项"——从容器头调用时
     *    会连同整个容器的内容一起跳过（cbor_map_seek 正是靠它跳过"值"）。
     *    所以正确做法是直接从头跳，不要再自己读一遍容器头。
     *
     *    （编号沿用原有方案，修订后 -9/-10 归 map、-11/-12 归 arr；
     *      由于失败不再发生，其余步骤号保持原值不动。） */
    cbor_init(&r, v_map, sizeof(v_map));
    if(cbor_skip_item(&r) != CBOR_OK)                           { return -9; }
    if(r.off != sizeof(v_map))                                  { return -10; }

    cbor_init(&r, v_arr, sizeof(v_arr));
    if(cbor_skip_item(&r) != CBOR_OK)                           { return -11; }
    if(r.off != sizeof(v_arr))                                  { return -12; }

    cbor_init(&r, v_true, sizeof(v_true));
    if(cbor_read_bool(&r, &bl) != CBOR_OK || bl != 1)           { return -15; }

    /* ---- 4) map 按键查找（键 3 在第二对，值应为 4） ---- */
    cbor_init(&r, v_map, sizeof(v_map));
    if(cbor_read_map(&r, &n) != CBOR_OK)                        { return -16; }
    if(cbor_map_seek(&r, n, 3) != CBOR_OK)                      { return -17; }
    if(cbor_read_uint(&r, &u) != CBOR_OK || u != 4)             { return -18; }

    /* ---- 5) 畸形输入必须被拒绝 ---- */
    cbor_init(&r, e_trunc, sizeof(e_trunc));
    if(cbor_read_uint(&r, &u) != CBOR_ERR_TRUNC)                { return -19; }

    cbor_init(&r, e_biglen, sizeof(e_biglen));
    if(cbor_read_bytes(&r, &p, &n) != CBOR_ERR_TRUNC)           { return -20; }

    cbor_init(&r, e_indef, sizeof(e_indef));
    if(cbor_read_uint(&r, &u) != CBOR_ERR_INDEF)                { return -21; }

    cbor_init(&r, e_float, sizeof(e_float));
    if(cbor_read_item(&r, &it) != CBOR_ERR_TYPE)                { return -22; }

    cbor_init(&r, e_tag, sizeof(e_tag));
    if(cbor_read_item(&r, &it) != CBOR_ERR_TYPE)                { return -23; }

    cbor_init(&r, e_biguint, sizeof(e_biguint));
    if(cbor_read_uint(&r, &u) != CBOR_ERR_RANGE)                { return -24; }

    /* ---- 6) 编码：map(4){ 1: ["FIDO_2_0"], 3: 1200 } ---- */
    off = 0;
    off = cbor_put_map_head(buf, sizeof(buf), off, 4);
    if(off == CBOR_ENC_ERR)                                     { return -25; }
    off = cbor_put_uint(buf, sizeof(buf), off, 1);
    off = cbor_put_array_head(buf, sizeof(buf), off, 1);
    off = cbor_put_text(buf, sizeof(buf), off, "FIDO_2_0", 8);
    off = cbor_put_uint(buf, sizeof(buf), off, 3);
    off = cbor_put_uint(buf, sizeof(buf), off, 1200);
    if(off == CBOR_ENC_ERR)                                     { return -26; }
    if(buf[0] != 0xA4)                                          { return -27; }
    if(buf[off - 3] != 0x19 || buf[off - 2] != 0x04 || buf[off - 1] != 0xB0)
                                                                { return -28; }

    /* ---- 7) 编码容量保护（1200 需 3 字节，cap 只给 1） ---- */
    if(cbor_put_uint(buf, 1, 0, 1200) != CBOR_ENC_ERR)          { return -29; }

    /* ---- 8) 编码 -> 解码 往返 ---- */
    off = 0;
    off = cbor_put_int(buf, sizeof(buf), off, -7);
    off = cbor_put_bool(buf, sizeof(buf), off, 1);
    if(off == CBOR_ENC_ERR)                                     { return -30; }
    cbor_init(&r, buf, off);
    if(cbor_read_int(&r, &s) != CBOR_OK || s != -7)             { return -31; }
    if(cbor_read_bool(&r, &bl) != CBOR_OK || bl != 1)           { return -32; }

    /* ---- 9) 真实 CTAP 风格的嵌套向量 ----
     *
     * 这一组是**有外部依据**的，用来补上此前"照着实现写测试"的漏洞——
     * 那次把 cbor_skip_item 的调用约定套错了，真机报 CBOR selftest = -11。
     *
     * 字节序列按 RFC 8949 手工推导：
     *   { 1: h'0001..0F', 2: "webauthn.io", 3: {"up":true,"rk":false}, 4: [-7,-8,1] }
     * 并用一个**独立的 Python 解码器**验证过「字节 <-> 期望对象」一致。
     *
     * 它顺带覆盖了上次出错的路径：cbor_map_seek() 在跳过"键 1 的 16B bytes"
     * 和"键 3 的嵌套 map"时，都要依赖 cbor_skip_item 的嵌套跳过能力。
     */
    {
        static const uint8_t v_mc[] = {
            0xA4,
            0x01, 0x50,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x02, 0x6B,
            'w', 'e', 'b', 'a', 'u', 't', 'h', 'n', '.', 'i', 'o',
            0x03, 0xA2,
            0x62, 'u', 'p', 0xF5,
            0x62, 'r', 'k', 0xF4,
            0x04, 0x83, 0x26, 0x27, 0x01
        };
        int32_t a1, a2, a3;

        cbor_init(&r, v_mc, sizeof(v_mc));
        if(cbor_read_map(&r, &n) != CBOR_OK || n != 4)          { return -33; }
        if(cbor_map_seek(&r, n, 4) != CBOR_OK)                  { return -34; }
        if(cbor_read_array(&r, &n) != CBOR_OK || n != 3)        { return -35; }
        if(cbor_read_int(&r, &a1) != CBOR_OK || a1 != -7)       { return -36; }
        if(cbor_read_int(&r, &a2) != CBOR_OK || a2 != -8)       { return -37; }
        if(cbor_read_int(&r, &a3) != CBOR_OK || a3 != 1)        { return -38; }

        /* 再取键 2 的文本：这一步必须先跳过键 1 的 16 字节 bytes */
        cbor_init(&r, v_mc, sizeof(v_mc));
        if(cbor_read_map(&r, &n) != CBOR_OK)                    { return -39; }
        if(cbor_map_seek(&r, n, 2) != CBOR_OK)                  { return -40; }
        if(cbor_read_text(&r, &t, &n) != CBOR_OK || n != 11)    { return -41; }
        if(memcmp(t, "webauthn.io", 11) != 0)                   { return -42; }
    }

    return 0;
}
