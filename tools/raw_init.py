#!/usr/bin/env python3
"""
手动发一次 CTAPHID_INIT，打印原始响应字节 —— 用于定位 "Wrong nonce"。

不依赖 python-fido2，直接用 hidapi 收发，所以能看到设备真正返回了什么。
不需要重新烧录固件。

用法:
    pip install hidapi
    python tools/raw_init.py
"""

import sys
import time

try:
    import hid
except ImportError:
    print("需要 hidapi: pip install hidapi")
    sys.exit(2)

VID = 0x1A86
PID = 0xE008
CID_BROADCAST = b"\xff\xff\xff\xff"
CMD_INIT = 0x86          # 0x06 | 0x80
HID_REPORT = 64


def find_device():
    for d in hid.enumerate():
        if d.get("vendor_id") == VID and d.get("product_id") == PID:
            return d
    return None


def main():
    d = find_device()
    if not d:
        print("未找到 VID=%04X PID=%04X 的设备。" % (VID, PID))
        print("请用管理员权限运行（Windows 的 FIDO 驱动会以独占方式持有设备）。")
        return 1

    print("设备路径:", d["path"])
    print()

    dev = hid.device()
    try:
        dev.open_path(d["path"])
    except Exception as e:
        print("打开失败: %s" % e)
        print("-> 多半是被独占，请用管理员权限重试。")
        return 1

    nonce = bytes(range(1, 9))          # 01 02 03 04 05 06 07 08
    report = CID_BROADCAST + bytes([CMD_INIT, 0x00, 0x08]) + nonce
    report = report + bytes(HID_REPORT - len(report))

    # Windows 上 hidapi 的 write() 要求第一个字节是 Report ID。
    # 本设备的报告描述符没有 Report ID，因此必须补一个 0x00 前导字节，
    # 实际写入 65 字节 = 1 字节 Report ID + 64 字节报告。
    packet = bytes([0x00]) + report

    print("发送 %d 字节 (1 字节 ReportID + 64 字节报告):" % len(packet))
    print("  " + packet.hex(" "))
    print()

    try:
        dev.write(packet)
    except Exception as e:
        print("写入失败: %s" % e)
        return 1

    resp = None
    for _ in range(10):
        r = dev.read(HID_REPORT, timeout_ms=1000)
        if r:
            resp = bytes(r)
            break
        time.sleep(0.1)

    if not resp:
        print("设备没有响应（IN 端点没数据）。")
        return 1

    print("收到 %d 字节:" % len(resp))
    print("  " + resp.hex(" "))
    print()

    cid = resp[0:4]
    cmd = resp[4]
    total = (resp[5] << 8) | resp[6]
    data = resp[7:7 + total]

    print("解析:")
    print("  CID   = %s   (应为 ffffffff)" % cid.hex())
    print("  CMD   = 0x%02X      (应为 0x86)" % cmd)
    print("  BCNT  = %d        (应为 17)" % total)
    print("  DATA  = %s" % data.hex(" ") if data else "  DATA  = (空)")
    print()
    print("  nonce 发出 = %s" % nonce.hex(" "))
    print("  nonce 回显 = %s" % data[:8].hex(" "))
    print("  -> %s" % ("一致" if data[:8] == nonce else "*** 不一致 ***"))
    print()
    if len(data) >= 17:
        print("  newCID      = %s" % data[8:12].hex())
        print("  协议版本    = %d" % data[12])
        print("  设备版本    = %d.%d.%d" % (data[13], data[14], data[15]))
        print("  caps        = 0x%02X" % data[16])
    else:
        print("  *** 响应体只有 %d 字节，规范要求 17 字节 ***" % len(data))

    return 0


if __name__ == "__main__":
    sys.exit(main())
