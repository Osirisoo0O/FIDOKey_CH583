/**
 * @file cbor_lite.h
 * @brief 最小可用 CBOR 编解码（CTAP2 所需子集），对应开发计划 2.6
 *
 * 只实现 CTAP2 实际用到的部分，不追求完整 CBOR：
 *   uint / 负整数 / bytes / text / array / map / bool(NULL)
 *   —— 不支持：tag、不定长(ai=31)、float、bignum
 *
 * ⚠️ 解码侧的输入来自主机，**一律视为不可信数据**：
 *    每个读取函数都做边界检查，长度字段超过剩余字节即报错而不是截断使用；
 *    8 字节长度/数值若超出 32 位可表示范围直接拒绝；
 *    `cbor_skip_item()` 用迭代 + 深度上限，不会因恶意嵌套导致栈溢出。
 */

#ifndef __CBOR_LITE_H
#define __CBOR_LITE_H

#include "stdint.h"

/* ---- 主类型（高 3 位） ---- */
#define CBOR_TYPE_UINT      0
#define CBOR_TYPE_NINT      1
#define CBOR_TYPE_BYTES     2
#define CBOR_TYPE_TEXT      3
#define CBOR_TYPE_ARRAY     4
#define CBOR_TYPE_MAP       5
#define CBOR_TYPE_TAG       6
#define CBOR_TYPE_SIMPLE    7

/* ---- simple 值 ---- */
#define CBOR_SIMPLE_FALSE   20
#define CBOR_SIMPLE_TRUE    21
#define CBOR_SIMPLE_NULL    22
#define CBOR_SIMPLE_UNDEF   23

/* ---- 返回码 ---- */
#define CBOR_OK             0
#define CBOR_ERR_ARG        (-1)
#define CBOR_ERR_TRUNC      (-2)    /* 数据不完整 */
#define CBOR_ERR_TYPE       (-3)    /* 类型不符 / 不支持的类型 */
#define CBOR_ERR_RANGE      (-4)    /* 长度或数值超出可表示范围 */
#define CBOR_ERR_DEPTH      (-5)    /* 嵌套超过 CBOR_MAX_DEPTH */
#define CBOR_ERR_INDEF      (-6)    /* 不定长编码，不支持 */
#define CBOR_ERR_NOTFOUND   (-7)    /* map 中未找到该键 */

/* 最大嵌套深度（防止恶意输入耗尽栈） */
#define CBOR_MAX_DEPTH      16

/* 编码失败返回值 */
#define CBOR_ENC_ERR        0xFFFFFFFFUL

typedef struct
{
    const uint8_t *buf;
    uint32_t       len;
    uint32_t       off;
} cbor_reader_t;

typedef struct
{
    uint8_t        type;        /* CBOR_TYPE_* */
    uint32_t       arg;         /* uint/nint 的数值；array/map 的元素数；simple 值 */
    const uint8_t *data;        /* BYTES/TEXT 指向内容（在 buf 内，不拷贝） */
    uint32_t       data_len;
} cbor_item_t;

/* ---------------- 解码 ---------------- */

void cbor_init(cbor_reader_t *r, const uint8_t *buf, uint32_t len);

/** 读取一个数据项（BYTES/TEXT 会把内容指针填进 item） */
int cbor_read_item(cbor_reader_t *r, cbor_item_t *it);

/** 跳过一个完整数据项（含嵌套容器） */
int cbor_skip_item(cbor_reader_t *r);

/** 读无符号整数（拒绝负数与超 32 位值） */
int cbor_read_uint(cbor_reader_t *r, uint32_t *out);

/** 读整数（含负数） */
int cbor_read_int(cbor_reader_t *r, int32_t *out);

/** 读 bool（false/true） */
int cbor_read_bool(cbor_reader_t *r, uint8_t *out);

/** 读 bytes（返回内部指针，不做拷贝） */
int cbor_read_bytes(cbor_reader_t *r, const uint8_t **p, uint32_t *n);

/** 读 text（返回内部指针，不做拷贝，不带结尾 0） */
int cbor_read_text(cbor_reader_t *r, const char **s, uint32_t *n);

/** 读 array 头，得到元素个数 */
int cbor_read_array(cbor_reader_t *r, uint32_t *count);

/** 读 map 头，得到键值对个数 */
int cbor_read_map(cbor_reader_t *r, uint32_t *count);

/**
 * @brief 在 map 中按键查找：从当前位置开始扫描 count-1 个键值对
 * @note  仅在已读到 map 头之后调用；会跳过不匹配的键值对。
 *        找到则把 reader 定位到该值之前（随后可读值），返回 CBOR_OK。
 */
int cbor_map_seek(cbor_reader_t *r, uint32_t pairs, uint32_t key);

/* ---------------- 编码（均带容量上限 cap，越界返回 CBOR_ENC_ERR） ---------------- */

uint32_t cbor_put_uint(uint8_t *buf, uint32_t cap, uint32_t off, uint32_t v);
uint32_t cbor_put_int(uint8_t *buf, uint32_t cap, uint32_t off, int32_t v);
uint32_t cbor_put_bytes(uint8_t *buf, uint32_t cap, uint32_t off, const uint8_t *d, uint32_t n);
uint32_t cbor_put_text(uint8_t *buf, uint32_t cap, uint32_t off, const char *s, uint32_t n);
uint32_t cbor_put_array_head(uint8_t *buf, uint32_t cap, uint32_t off, uint32_t n);
uint32_t cbor_put_map_head(uint8_t *buf, uint32_t cap, uint32_t off, uint32_t n);
uint32_t cbor_put_bool(uint8_t *buf, uint32_t cap, uint32_t off, uint8_t b);
uint32_t cbor_put_null(uint8_t *buf, uint32_t cap, uint32_t off);

/**
 * @brief CBOR 编解码自测（含畸形输入负向用例）
 * @return 0=通过, 负数=第几组失败
 */
int8_t cbor_selftest(void);

#endif /* __CBOR_LITE_H */
