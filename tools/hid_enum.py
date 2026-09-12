#!/usr/bin/env python3
"""
诊断：枚举系统上所有 HID 接口，确认 SecureKey 是否被正确导出为 FIDO 设备。

用法:
    pip install hidapi
    python tools/hid_enum.py

看两点:
    1) 有没有 VID=0x1A86 PID=0xE008 的 HID 接口
    2) 若有，它的 usage_page 是多少
       FIDO 认证器必须是 0xF1D0 / usage 0x01
       若仍显示 0xFF00 -> 设备还在用旧的报告描述符（Windows 缓存，或没烧进新固件）
"""

import sys

try:
    import hid
except ImportError:
    print("需要 hidapi，请先执行: pip install hidapi")
    sys.exit(2)

VID = 0x1A86
PID = 0xE008
USAGE_PAGE_FIDO = 0xF1D0


def pick(d, *names):
    for n in names:
        if n in d and d[n] is not None:
            return d[n]
    return None


print("%-6s %-6s %-11s %-7s %s" % ("VID", "PID", "usage_page", "usage", "product"))
print("-" * 88)

ours = []
for d in hid.enumerate():
    vid = d.get("vendor_id") or 0
    pid = d.get("product_id") or 0
    up = pick(d, "usage_page", "usagePage")
    us = pick(d, "usage")
    is_ours = (vid == VID and pid == PID)
    if is_ours:
        ours.append((d, up, us))
    print("%04X   %04X   %-11s %-7s %s%s"
          % (vid, pid,
             ("0x%04X" % up) if up is not None else "?",
             ("0x%02X" % us) if us is not None else "?",
             (d.get("product_string") or ""),
             "   <== 我们的设备" if is_ours else ""))

print()
if not ours:
    print("[结论] 没找到 VID=1A86 PID=E008 的 HID 接口。")
    print()
    print("  可能原因:")
    print("   a) 新固件没烧进去（仍跑旧固件）—— 重新 pio run -t upload 并确认串口有 passed 5/5")
    print("   b) 设备管理器里的硬件ID根本不是 VID_1A86&PID_E008")
    print("      -> 请把设备管理器里该设备的【硬件 ID】贴出来")
    print("   c) 设备没被识别为 HID（可能是未知设备/代码 43）")
    sys.exit(1)

print("[结论] 找到 %d 个匹配的 HID 接口。" % len(ours))
for d, up, us in ours:
    if up == USAGE_PAGE_FIDO:
        print("  usage_page = 0xF1D0 -> 报告描述符正确，FIDO 主机应当能识别")
        print("  （若 python-fido2 仍列不出设备，说明是它自己的筛选/权限问题）")
    else:
        print("  usage_page = %s -> 期望 0xF1D0。" % (("0x%04X" % up) if up is not None else "?（读不到）"))
        print("  若为 0xFF00，说明设备仍在用旧的报告描述符。此时按顺序试:")
        print("   1) 把设备插到【另一个 USB 口】（Windows 会为新端口建新的设备实例）")
        print("   2) 或者：设备管理器 -> 右键该设备 -> 卸载设备（勾选删除驱动）-> 重新插入")
        print("   3) 仍不行则说明固件没更新，确认串口打印与重烧是否成功")
