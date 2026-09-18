#!/usr/bin/env python3
"""验证 CTAP 2.1 §11.4.3 的链路加密是否真正生效（设备侧实测）。

规范原文：
    "For Bluetooth Low Energy Technology connections, the authenticator SHALL
     enforce Security Mode 1, Level 2 ... or Level 3 ... before any FIDO
     messages are exchanged."

本设备对承载 FIDO 消息的属性设了 GATT_PERMIT_ENCRYPT_*，因此**未加密**的连接：
    - 读 fidoControlPointLength  -> 应被拒 (0x0F INSUFFICIENT_ENCRYPTION)
    - 写 fidoControlPoint        -> 应被拒 (0x0F)
**已加密**（已配对）的连接两者都应成功。

用法：
    # ① 已配对状态（期望：读/写都成功）
    python tools/ble_probe_encryption.py

    # ② 未配对状态（期望：读/写都被拒 0x0F）
    #    先在 Windows 设置 → 蓝牙和其他设备 → 删除 SecureKey，再跑同一个命令

脚本自身不做配对，以便如实反映"当前链路是否已加密"。
"""
import argparse
import asyncio
import sys

try:
    from bleak import BleakClient, BleakScanner
except ImportError:                                          # pragma: no cover
    print("需要 bleak：pip install bleak")
    sys.exit(2)

DEVICE_NAME = "SecureKey"
UUID_CONTROL_POINT = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb"
UUID_CP_LENGTH = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb"
UUID_REV_BITFIELD = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb"


def is_insufficient_encryption(exc: BaseException) -> bool:
    """判断异常是否为"链路未加密/未认证"（CTAP 2.1 §11.4.3 的拦截）。

    实测 Windows + bleak 报的是：
        BleakGATTProtocolError(5, 'GATT Protocol Error: Insufficient Authentication')
    —— ATT 错误码是 **5 (Insufficient Authentication)**，不是规范文档里常见的
    0x0F (Insufficient Encryption)。两者语义相同：链路尚未满足安全要求。

    判定要求同时出现 "insufficient" 与 ("encrypt" 或 "authenticat")，
    以免把 "Not connected"、"Unreachable"、"operation was canceled" 误判进来
    —— 那些是链路被抢占的症状，与加密无关，结论完全不同。
    """
    text = f"{exc!r} {exc}".lower()
    return "insufficient" in text and ("encrypt" in text or "authenticat" in text)


async def probe(target_addr=None):
    target = target_addr
    if not target:
        print("扫描中（8 秒）...")
        target = await BleakScanner.find_device_by_filter(
            lambda d, ad: (d.name or "") == DEVICE_NAME, timeout=8.0
        )
        if target is None:
            print(f"未找到 {DEVICE_NAME}；请长按 PB4 进入配对模式。")
            return 1
        print(f"  发现: {target.address} [{target.name}]")

    print()
    async with BleakClient(target, timeout=20.0) as client:
        try:
            mtu = getattr(client, "mtu_size", None) or 23
        except Exception:                                   # noqa: BLE001
            mtu = 23
        print(f"已连接（MTU = {mtu}）")

        # ★ 不查询配对状态：bleak 的 is_paired() 并非各版本都有（实测 AttributeError）。
        #   直接看**行为** —— 三项要求加密的操作是否被拒、以什么理由被拒。
        #   这比查状态更可靠，也正是我们真正关心的事。
        results = {}
        crypto_denied = []           # 因加密被拒的项

        def record(name, ok, exc=None):
            results[name] = ok
            if not ok and exc is not None and is_insufficient_encryption(exc):
                crypto_denied.append(name)

        # ---- ① 读 fidoControlPointLength（要求 ENCRYPT_READ）----
        print("① 读 fidoControlPointLength（设备侧要求 ENCRYPT_READ）")
        try:
            val = await client.read_gatt_char(UUID_CP_LENGTH)
            record("read", True)
            print(f"   成功 —— 值 = {bytes(val).hex(' ').upper()}")
        except Exception as e:                              # noqa: BLE001
            record("read", False, e)
            kind = "加密拦截" if is_insufficient_encryption(e) else "其它错误"
            print(f"   被拒 —— {kind}：{e!r}")

        # ---- ② 写 fidoControlPoint（要求 ENCRYPT_WRITE）----
        # 写一个合法的 PING 帧：CMD=0x81 | HLEN | LLEN | "PING"
        ping = bytes([0x81, 0x00, 0x04]) + b"PING"
        print("② 写 fidoControlPoint（设备侧要求 ENCRYPT_WRITE）")
        print(f"   载荷：{ping.hex(' ').upper()}  (PING 帧)")
        try:
            await client.write_gatt_char(UUID_CONTROL_POINT, ping, response=True)
            record("write", True)
            print("   成功")
        except Exception as e:                              # noqa: BLE001
            record("write", False, e)
            kind = "加密拦截" if is_insufficient_encryption(e) else "其它错误"
            print(f"   被拒 —— {kind}：{e!r}")

        # ---- ③ 读 fidoServiceRevisionBitfield（要求 ENCRYPT_READ）----
        print("③ 读 fidoServiceRevisionBitfield（设备侧要求 ENCRYPT_READ）")
        try:
            val = await client.read_gatt_char(UUID_REV_BITFIELD)
            record("rev", True)
            print(f"   成功 —— 值 = {bytes(val).hex(' ').upper()}")
        except Exception as e:                              # noqa: BLE001
            record("rev", False, e)
            kind = "加密拦截" if is_insufficient_encryption(e) else "其它错误"
            print(f"   被拒 —— {kind}：{e!r}")

        # ---- 判定 ----
        print()
        print("=" * 70)
        print("判定")
        print("=" * 70)
        ok_all = all(results.values())
        denied = [k for k, v in results.items() if not v]

        if ok_all:
            print("  ✔ 三项全部成功 —— 链路已加密，加密链路工作正常。")
            print("    说明系统蓝牙栈已用 LTK 完成加密（设备已被本机绑定）。")
            print("    这同时印证 §11.4.6 的\"已绑定客户端无人工干预\"成立。")
        elif denied and len(crypto_denied) == len(denied):
            print("  ✔ 三项全部被加密拦截 —— §11.4.3 强制生效，符合规范。")
            print("    设备拒绝在未加密链路上读写承载 FIDO 消息的属性。")
            print()
            print("    下一步：在 Windows 设置 → 蓝牙和其他设备里配对 SecureKey，")
            print("    再跑一次本脚本，应转为\"三项全部成功\"。")
        elif denied and not crypto_denied:
            print("  ⚠ 三项全部失败，但原因**不是**加密 —— 是链路问题。")
            print("    常见原因：系统蓝牙栈占用了链路（设备是单连接外设），")
            print("    表现为 MTU 停在 23、\"Not connected\"、\"Unreachable\"。")
            print(f"    本次 MTU = {mtu}"
                  + ("（未协商，符合该症状）" if mtu <= 23 else ""))
            print("    处理：删除 Windows 配对记录 → 设备重新上电 → 立刻重跑。")
        else:
            ok_items = [k for k, v in results.items() if v]
            print(f"  ⚠ 结果不一致：成功={ok_items}，被拒={denied}")
            if crypto_denied:
                print(f"    其中被加密拦截的：{crypto_denied}")
            print("    部分成功/部分失败通常意味着权限位配置不一致，")
            print("    请检查 src/fido_service.c 的属性表。")

        print()
        print(f"  原始结果：read={results.get('read')} "
              f"write={results.get('write')} rev={results.get('rev')}")
        return 0


def main():
    ap = argparse.ArgumentParser(
        description="验证 CTAP 2.1 §11.4.3 链路加密是否真正生效")
    ap.add_argument("--addr", help="设备 MAC；省略则自动扫描")
    args = ap.parse_args()
    try:
        return asyncio.run(probe(args.addr))
    except KeyboardInterrupt:
        print("\n已中断")
        return 130


if __name__ == "__main__":
    sys.exit(main())
