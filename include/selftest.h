/**
 * @file selftest.h
 * @brief 上电自测统一入口（开发计划 5.1）
 *
 * 各模块各自提供 selftest 函数（返回 0 = 通过，负值 = 第几步失败）。
 * 本入口把它们串起来统一运行并打印结果，方便"烧录一次即可确认全部基础功能"。
 */

#ifndef __SELFTEST_H
#define __SELFTEST_H

#include "stdint.h"

/**
 * @brief 运行全部上电自测并逐项打印结果
 *
 * @return 0 = 全部通过；否则为**失败的项数**
 *
 * @note  ⚠️ 其中 `secure_store_selftest()` 会**擦写 DataFlash**（使用最后一个凭证槽）。
 *        因此本入口只在 `DEBUG` 构建下由 main 调用；正式固件不要调用。
 *
 *        每项打印 "名称 = 结果"，结果为负时对应该项内部的第几步检查失败，
 *        可直接定位（各模块的步骤含义见其 selftest 函数内的注释）。
 */
int8_t selftest_run_all(void);

#endif /* __SELFTEST_H */
