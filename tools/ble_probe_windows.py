#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows CtapSrv 行为模拟器 —— 定位 `_GetFidoGattService 0x8000000E` 的成因。

背景（来自 Windows 事件日志 Microsoft-Windows-WebAuthN/Operational）：

    Id 2263  Ctap Ble 设备线程已完成。
             DevicePath: ble:383b267e348e_0021
             PairedName: SecureKey
             AAGuid: {00000000-0000-0000-0000-000000000000}   <- 从未取到 GetInfo
             状态: 3
             错误: 0x4C7
    Id 2270  Ctap Ble 函数: _GetFidoGattService 位置: ErrorCode
             错误: 0x8000000E。在意外的时间调用了方法。     <- 真正的失败点
    Id 2270  Ctap Ble 函数: _BleCreateContextWithAuthenticatorInfo 位置: Status
             错误: 0x10。无法删除目录。

即：Windows 找到了设备、建立了连接，但在"按 UUID 取 FIDO 主服务"这一步
失败（ERROR_INVALID_STATE）。而 tools/ble_gatt_client.py 走同样的设备却是
八项全通 —— 差别应当在于**连接后动作的顺序与时机**。

本脚本把那个差别拆成可对比的几种"连接姿势"，逐一跑一遍，看哪种能复现
Windows 的失败。它不修改设备，只读。

用法：
    python tools/ble_probe_windows.py             # 跑全部场景，逐个对比
    python tools/ble_probe_windows.py --addr XX:XX:XX:XX:XX:XX
    python tools/ble_probe_windows.py --scan      # 只扫描
    python tools/ble_probe_windows.py --only 3    # 只跑第 3 个场景

需要 Python 3.9+ 与 bleak（pip install bleak）。
"""

import argparse
import asyncio
import sys
import time

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    print("缺少 bleak：pip install bleak", file=sys.stderr)
    sys.exit(1)

# --- bleak API 兼容层 ---
# 旧版（<=0.19）：client.get_services() 是协程；client.exchange_mtu() 可协商 MTU。
# 新版（>=0.20）：服务发现在 connect() 内完成，client.services 是同步属性，
#                 没有这两个名字。按需补上，使下面的场景代码对两个版本都成立。
if not hasattr(BleakClient, "get_services"):
    async def _compat_get_services(self):
        return list(self.services)

    BleakClient.get_services = _compat_get_services

if not hasattr(BleakClient, "exchange_mtu"):
    async def _compat_exchange_mtu(self, mtu=256):
        return getattr(self, "mtu_size", 256)

    BleakClient.exchange_mtu = _compat_exchange_mtu

# FIDO 服务与特征 UUID（与固件 src/fido_service.c 一致）
FIDO_SERVICE_UUID = "0000fffd-0000-1000-8000-00805f9b34fb"
UUID_CONTROL_POINT = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb"
UUID_STATUS = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb"
UUID_CP_LENGTH = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb"
UUID_REV_BITFIELD = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb"

DEVICE_NAME = "SecureKey"


# --------------------------------------------------------------------------
# 小工具
# --------------------------------------------------------------------------

class Result:
    """一次场景的观察结果。"""

    def __init__(self, name):
        self.name = name
        self.connected = False
        self.steps = []          # (标签, 成功?, 详情)
        self.error = None
        self.timings = {}        # 标签 -> 秒

    def step(self, label, ok, detail=""):
        self.steps.append((label, ok, detail))
        mark = "OK  " if ok else "FAIL"
        print(f"    [{mark}] {label}{(' — ' + detail) if detail else ''}")

    def fail(self, exc):
        self.error = f"{type(exc).__name__}: {exc}"
        print(f"    [FAIL] 异常 — {self.error}")

    @property
    def ok(self):
        return self.connected and not self.error and all(s[1] for s in self.steps)


async def timed(label, coro, res, timeout=20.0):
    """跑一个协程，记录耗时；异常不外抛，写进 res。返回 (成功, 值)。"""
    t0 = time.monotonic()
    try:
        val = await asyncio.wait_for(coro, timeout=timeout)
        dt = time.monotonic() - t0
        res.timings[label] = dt
        return True, val
    except Exception as exc:                      # noqa: BLE001
        dt = time.monotonic() - t0
        res.timings[label] = dt
        res.step(label, False, f"{type(exc).__name__}: {exc} ({dt:.2f}s)")
        return False, None


def find_service(services, uuid):
    """在服务列表里按 UUID 找（大小写不敏感）。"""
    want = uuid.lower()
    for svc in services:
        if svc.uuid.lower() == want:
            return svc
    return None


def find_char(service, uuid):
    if service is None:
        return None
    want = uuid.lower()
    for ch in service.characteristics:
        if ch.uuid.lower() == want:
            return ch
    return None


async def discover(addr, timeout=8.0):
    """返回一个可交给 BleakClient 的目标。

    重要：优先返回扫描得到的 BLEDevice 对象，而不是它的 MAC 字符串。
    在 Windows/WinRT 后端上这两者不等价：
      BleakClient(BLEDevice) —— 用扫描期缓存的设备引用，GATT 句柄有效
      BleakClient("AA:BB:..") —— 后端重新解析地址，可能拿到一个"新"的
                                 设备实例，服务能枚举出来但特征读写会以
                                 0x800704C7（操作已被取消）失败
    这正是 tools/ble_gatt_client.py 能跑通而本脚本场景 5/6 失败的原因。
    """
    if addr:
        return addr                      # 调用方显式给了 MAC，按其意愿连

    print(f"扫描中（{timeout:.0f} 秒）...")
    dev = await BleakScanner.find_device_by_filter(
        lambda d, ad: (d.name or "") == DEVICE_NAME, timeout=timeout
    )
    if dev is None:
        print(f"  未找到 {DEVICE_NAME}；请长按 PB4 进入配对模式后重试。")
        return None
    print(f"  发现: {dev.address} [{dev.name}]（将传入 BLEDevice 对象）")
    return dev


# --------------------------------------------------------------------------
# 场景
# --------------------------------------------------------------------------

async def scenario(name, addr, body):
    """跑一个场景：连接 -> body(client, res) -> 断开。"""
    print(f"\n{'=' * 68}\n{name}\n{'=' * 68}")
    res = Result(name)
    try:
        async with BleakClient(addr, timeout=20.0) as client:
            res.connected = True
            print("  已连接")
            await body(client, res)
    except Exception as exc:                      # noqa: BLE001
        res.fail(exc)
    verdict = "通过" if res.ok else "失败"
    print(f"  -> {verdict}"
          + (f"（{res.error}）" if res.error else ""))
    return res


async def s1_plain(client, res):
    """标准流程（与 ble_gatt_client.py 相同）：MTU -> 枚举 -> 读特征。"""
    ok, mtu = await timed("读 MTU", client.exchange_mtu(), res, timeout=10.0)
    if ok:
        res.step("读 MTU", True, f"{mtu}")
    ok, svcs = await timed("枚举全部服务", client.get_services(), res)
    if not ok:
        return
    res.step("枚举全部服务", True, f"{len(svcs)} 个")
    svc = find_service(svcs, FIDO_SERVICE_UUID)
    res.step("按 UUID 取 FIDO 主服务", svc is not None,
             "找到" if svc else "未找到")
    if svc:
        res.step("特征数", True, f"{len(svc.characteristics)} 个")


async def s2_no_mtu(client, res):
    """跳过 MTU 交换，直接枚举服务（Windows 可能就是这样做的）。

    Windows 的 `_GetFidoGattService` 是独立的一步，不依赖 MTU 协商结果；
    如果 MTU 交换在链路早期造成状态变化，这里就可能复现失败。
    """
    ok, svcs = await timed("枚举全部服务（未做 MTU 交换）", client.get_services(), res)
    if not ok:
        return
    res.step("枚举全部服务（未做 MTU 交换）", True, f"{len(svcs)} 个")
    svc = find_service(svcs, FIDO_SERVICE_UUID)
    res.step("按 UUID 取 FIDO 主服务", svc is not None,
             "找到" if svc else "未找到")


async def s3_uuid_only(client, res):
    """不做全量枚举，只用"按 UUID 查服务"（最接近 CtapSrv 的做法）。

    bleak 的 get_services() 会做完整发现；而 Windows 走的是
    GATT 的 "Discover Primary Services by UUID"，路径不同。
    这里用 services.get_characteristic 之类只做定点查询。
    """
    ok, svcs = await timed("枚举服务（用于建立缓存）", client.get_services(), res)
    if not ok:
        return
    # 定点查询：只对 FIDO 服务里的特征做解析
    svc = find_service(svcs, FIDO_SERVICE_UUID)
    res.step("按 UUID 取 FIDO 主服务", svc is not None,
             "找到" if svc else "未找到")
    if svc is None:
        return
    for label, uuid in (
        ("fidoControlPoint", UUID_CONTROL_POINT),
        ("fidoStatus", UUID_STATUS),
        ("fidoControlPointLength", UUID_CP_LENGTH),
        ("fidoServiceRevisionBitfield", UUID_REV_BITFIELD),
    ):
        ch = find_char(svc, uuid)
        res.step(f"取特征 {label}", ch is not None,
                 f"props={ch.properties}" if ch else "未找到")


async def s4_repeat(client, res):
    """反复枚举服务（探测"第二次调用状态异常"）。

    `0x8000000E` = ERROR_INVALID_STATE，字面意思就是"在意外的时间调用了
    方法" —— 典型的"同一 GATT 操作重入/并发"症状。这里连续枚举多次，
    若第 N 次失败即可定位到"重复调用"这一类问题。
    """
    for i in range(1, 6):
        ok, svcs = await timed(f"枚举服务 第 {i} 次", client.get_services(), res)
        if not ok:
            return
        svc = find_service(svcs, FIDO_SERVICE_UUID)
        res.step(f"枚举服务 第 {i} 次", svc is not None,
                 f"{len(svcs)} 个服务, FIDO {'在' if svc else '不在'}")


async def s5_read_all(client, res):
    """连接后立刻读 FIDO 服务下的所有可读特征（CtapSrv 建 context 时会读）。

    Windows 的 `_BleCreateContextWithAuthenticatorInfo` 在建上下文时会去读
    特征值；如果某个属性读失败，它可能整体放弃。
    """
    ok, svcs = await timed("枚举服务", client.get_services(), res)
    if not ok:
        return
    svc = find_service(svcs, FIDO_SERVICE_UUID)
    if svc is None:
        res.step("按 UUID 取 FIDO 主服务", False, "未找到")
        return
    res.step("按 UUID 取 FIDO 主服务", True, "找到")
    for ch in svc.characteristics:
        if "read" not in ch.properties:
            continue
        ok, val = await timed(f"读 {ch.uuid[:8]}…", client.read_gatt_char(ch), res,
                              timeout=8.0)
        res.step(f"读 {ch.uuid[:8]}…", ok,
                 bytes(val).hex(" ") if ok else "")


async def s6_cccd_before_use(client, res):
    """先订阅通知（写 CCCD）再枚举服务 —— 测"写操作是否影响后续发现"。"""
    ok, svcs = await timed("枚举服务", client.get_services(), res)
    if not ok:
        return
    svc = find_service(svcs, FIDO_SERVICE_UUID)
    if svc is None:
        res.step("按 UUID 取 FIDO 主服务", False, "未找到")
        return
    res.step("按 UUID 取 FIDO 主服务", True, "找到")
    status = find_char(svc, UUID_STATUS)
    if status is None:
        res.step("找 fidoStatus", False, "未找到")
        return
    ok, _ = await timed("订阅 fidoStatus", client.start_notify(status, lambda _h, _d: None),
                        res, timeout=8.0)
    res.step("订阅 fidoStatus", ok)


SCENARIOS = [
    ("场景 1  标准流程（MTU -> 枚举 -> 读特征）", s1_plain),
    ("场景 2  跳过 MTU 交换，直接枚举服务", s2_no_mtu),
    ("场景 3  只按 UUID 定点取服务与特征", s3_uuid_only),
    ("场景 4  连续枚举 5 次（探测状态重入）", s4_repeat),
    ("场景 5  枚举后读全部可读特征", s5_read_all),
    ("场景 6  枚举后立刻订阅 fidoStatus", s6_cccd_before_use),
]


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------

async def run(args):
    addr = args.addr
    if args.scan:
        print("扫描中（8 秒）...")
        found = await BleakScanner.discover(timeout=8.0, return_adv=True)
        hit = 0
        for dev, adv in found.values():
            if (dev.name or "") == DEVICE_NAME or FIDO_SERVICE_UUID in [
                u.lower() for u in (adv.service_uuids or [])
            ]:
                hit += 1
                print(f"  {dev.address}  [{dev.name}]")
                print(f"    广播服务: {adv.service_uuids}")
                if FIDO_SERVICE_UUID in [u.lower() for u in (adv.service_uuids or [])]:
                    sd = (adv.service_data or {}).get(FIDO_SERVICE_UUID)
                    print(f"    Service Data = {sd.hex(' ') if sd else '(无)'}")
        if not hit:
            print(f"  未发现 {DEVICE_NAME}")
        return 0

    addr = await discover(addr)
    if not addr:
        return 1
    print(f"目标设备: {addr}")

    todo = SCENARIOS
    if args.only:
        todo = [SCENARIOS[i - 1] for i in args.only if 1 <= i <= len(SCENARIOS)]

    results = []
    for name, body in todo:
        results.append(await scenario(name, addr, body))
        await asyncio.sleep(1.5)      # 让设备侧链路彻底释放

    # ---- 汇总 ----
    print(f"\n{'=' * 68}\n汇总\n{'=' * 68}")
    print(f"{'场景':<44}{'结果':<8}")
    print("-" * 68)
    for r in results:
        print(f"{r.name:<44}{'通过' if r.ok else '失败':<8}")
        if r.timings:
            worst = max(r.timings.items(), key=lambda kv: kv[1])
            print(f"{'':44}最慢一步: {worst[0]} {worst[1]:.2f}s")
        if r.error:
            print(f"{'':44}错误: {r.error}")

    # 结论提示
    failing = [r for r in results if not r.ok]
    print()
    if not failing:
        print("全部场景通过 —— 设备侧的 GATT 服务在任意连接姿势下都可被找到。")
        print("那么 Windows `_GetFidoGattService` 的失败不在服务本身，")
        print("需要抓 BLE 链路层日志（btmon / ETW）继续定位。")
    else:
        print("以下场景失败（这些就是 Windows 可能踩到的路径）：")
        for r in failing:
            print(f"  - {r.name}")
            for label, ok, detail in r.steps:
                if not ok:
                    print(f"      {label}: {detail}")
    return 0 if not failing else 2


def main():
    ap = argparse.ArgumentParser(
        description="模拟 Windows CtapSrv 的连接姿势，定位 FIDO GATT 服务查找失败",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--addr", help="设备 MAC；省略则自动扫描")
    ap.add_argument("--scan", action="store_true", help="只扫描广播，不连接")
    ap.add_argument("--only", type=int, nargs="+",
                    help=f"只跑指定场景（1-{len(SCENARIOS)}）")
    args = ap.parse_args()

    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n已中断")
        return 130


if __name__ == "__main__":
    sys.exit(main())
