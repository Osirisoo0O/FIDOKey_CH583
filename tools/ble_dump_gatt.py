#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
原样打印设备的整个 GATT 数据库 —— 不做任何查找，只看客户端"看到"了什么。

用途：定位 Windows CtapSrv 报
    Ctap Ble 函数: _GetFidoGattServiceFromServicesResult 位置:
        错误: 0x80090011. 找不到对象。
的原因。该函数按 UUID 从服务发现结果里查找 FIDO 服务，却报"找不到"；
与此同时设备侧日志显示 Windows 确实读到了 FIDO 特征的值 —— 这两件事
同时成立，指向"服务 UUID 在 GATT 层的表示与期望不一致"。

本脚本不做 get_service(期望UUID) 这种查找，而是把解析出来的 UUID 原样
打印出来。如果 WCH 栈在把 128-bit UUID 发出去时做了额外变换，这里就会
直接看出来（对比下面的"期望值"）。

用法：
    python tools/ble_dump_gatt.py
    python tools/ble_dump_gatt.py --addr 38:3B:26:7E:34:8E
"""

import argparse
import asyncio
import sys

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    print("缺少 bleak：pip install bleak", file=sys.stderr)
    sys.exit(1)

DEVICE_NAME = "SecureKey"

# 规范期望的值（CTAP 2.1 §11.2）
EXPECTED_SERVICE = "0000fffd-0000-1000-8000-00805f9b34fb"
EXPECTED_CHARS = {
    "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb": "fidoControlPoint",
    "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb": "fidoStatus",
    "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb": "fidoControlPointLength",
    "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb": "fidoServiceRevisionBitfield",
}


def norm(u):
    return str(u).lower()


async def main():
    ap = argparse.ArgumentParser(description="原样打印 GATT 数据库")
    ap.add_argument("--addr", help="设备 MAC；省略则自动扫描")
    args = ap.parse_args()

    target = args.addr
    if not target:
        print("扫描中（8 秒）...")
        target = await BleakScanner.find_device_by_filter(
            lambda d, ad: (d.name or "") == DEVICE_NAME, timeout=8.0
        )
        if target is None:
            print(f"未找到 {DEVICE_NAME}；请长按 PB4 进入配对模式。")
            return 1
        print(f"  发现: {target.address} [{target.name}]")

    async with BleakClient(target, timeout=20.0) as client:
        print(f"已连接（MTU = {getattr(client, 'mtu_size', '?')}）\n")

        services = list(client.services)
        print(f"共 {len(services)} 个服务\n")
        print("=" * 72)

        found_service = False
        for svc in services:
            is_fido = norm(svc.uuid) == EXPECTED_SERVICE
            if is_fido:
                found_service = True
            mark = "  <<< FIDO 服务" if is_fido else ""
            print(f"\n服务  {svc.uuid}{mark}")
            print(f"  handle = 0x{svc.handle:04X}")
            if not is_fido:
                # 非 FIDO 服务只列名字，避免刷屏
                pass

            for ch in svc.characteristics:
                name = EXPECTED_CHARS.get(norm(ch.uuid), "")
                mark = f"  <<< {name}" if name else ""
                print(f"    特征  {ch.uuid}  props={ch.properties}{mark}")
                print(f"      handle = 0x{ch.handle:04X}")
                # 描述符（CCCD 等）也打出来，Windows 订阅通知要靠它
                for d in getattr(ch, "descriptors", []):
                    print(f"      描述符  0x{d.handle:04X}  {d.uuid}")

        print("\n" + "=" * 72)
        print("校验")
        print("=" * 72)
        print(f"FIDO 服务 UUID（期望 {EXPECTED_SERVICE}）")
        print(f"  是否按该 UUID 找到: {'是' if found_service else '否'}")

        # 把实际看到的 UUID 与期望逐个对照
        seen = {norm(s.uuid) for s in services}
        print(f"\n期望服务 UUID 是否出现在结果里: "
              f"{'是' if EXPECTED_SERVICE in seen else '否'}")
        if EXPECTED_SERVICE not in seen:
            print("  实际的服务 UUID 清单：")
            for u in sorted(seen):
                print(f"    {u}")

        print("\n特征 UUID 对照：")
        for uuid, name in EXPECTED_CHARS.items():
            hit = any(norm(c.uuid) == uuid for s in services for c in s.characteristics)
            print(f"  {name:<28} {'找到' if hit else '缺失'}  ({uuid})")

        if found_service:
            print("\n结论：客户端能按规范 UUID 找到 FIDO 服务。")
            print("     那么 Windows 的 NTE_NOT_FOUND 不在 UUID 表示上，")
            print("     需要往别处查（例如它查找的是另一个对象）。")
        else:
            print("\n结论：客户端按规范 UUID ★ 找不到 ★ FIDO 服务。")
            print("     这就是 Windows _GetFidoGattServiceFromServicesResult")
            print("     报 NTE_NOT_FOUND 的直接原因 —— 需要检查 WCH 栈对")
            print("     128-bit UUID 的编码处理。")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\n已中断")
        sys.exit(130)
