#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BLE FIDO 设备 GATT 诊断脚本
绕过 Windows CTAP 栈，直接用 bleak 连接设备并转储 GATT 服务。
用于判断 _GetFidoGattService Unreachable 是设备问题还是 Windows 栈问题。

依赖: pip install bleak
"""

import asyncio
import sys
from bleak import BleakClient, BleakScanner

# 你的设备地址（从原脚本中提取）
TARGET_ADDRESS = "38:3B:26:7E:34:8E"

# 关键 UUID
# 服务用 16-bit 短 UUID（0xFFFD，BLE 规范分配给 FIDO）；
# 四个特征用厂商定义的 128-bit UUID（注意前缀是 **F1D0** 而非 0000）。
FIDO_SERVICE_UUID = "0000fffd-0000-1000-8000-00805f9b34fb"
FIDO_CHARS = {
    "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb": "fidoControlPoint",
    "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb": "fidoStatus",
    "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb": "fidoControlPointLength",
    "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb": "fidoServiceRevisionBitfield",
}

def is_fido_service(uuid: str) -> bool:
    """判断是否为 FIDO 服务 (0xFFFD)，兼容长短 UUID 格式"""
    u = uuid.lower().replace("-", "")
    return u.endswith("0000fffd00001000800000805f9b34fb") or u == "fffd"

def print_separator(title: str):
    print("\n" + "=" * 65)
    print(f"  {title}")
    print("=" * 65)

async def dump_device(address: str):
    print_separator(f"连接设备: {address}")

    client = BleakClient(address, timeout=20.0)
    try:
        await client.connect()
    except Exception as e:
        print(f"[✗] 连接失败: {e}")
        print("\n可能原因:")
        print("  - 设备未处于广播模式（BLE FIDO 通常需要按键唤醒）")
        print("  - 设备已被 Windows 蓝牙栈占用（先删除配对再试）")
        print("  - 设备地址已变化（BLE FIDO 地址可能随机化）")
        return

    if not client.is_connected:
        print("[✗] 连接未建立")
        return

    print("[✓] 连接成功")
    print(f"    地址: {client.address}")

    # 转储所有服务
    services = client.services
    if not services:
        print("\n[✗] 未获取到任何 GATT 服务")
        print("    这通常意味着:")
        print("    - GATT 缓存污染（需要清理 Windows 蓝牙缓存）")
        print("    - 设备固件未正确暴露 GATT 服务")
        await client.disconnect()
        return

    fido_found = False
    print(f"\n共发现 {len(list(services))} 个服务:\n")

    for service in services:
        svc_uuid = service.uuid.lower()
        is_fido = is_fido_service(svc_uuid)
        marker = " ★ FIDO" if is_fido else ""
        print(f"[Service] {service.uuid}{marker}")
        if is_fido:
            fido_found = True

        for char in service.characteristics:
            char_uuid = char.uuid.lower()
            name = FIDO_CHARS.get(char_uuid, "")
            name_str = f" ({name})" if name else ""
            props = ",".join(char.properties)
            print(f"  └─ [Char] {char.uuid}{name_str}  [{props}]")

            # 尝试读取可读特征值
            if "read" in char.properties:
                try:
                    value = bytes(await client.read_gatt_char(char.uuid))
                    print(f"       └─ 值: {value.hex()}  ({value})")
                except Exception as e:
                    print(f"       └─ 读取失败: {e}")

            # 转储描述符
            for desc in char.descriptors:
                try:
                    dv = await client.read_gatt_descriptor(desc.handle)
                    print(f"       └─ [Desc] {desc.uuid}: {bytes(dv).hex()}")
                except Exception as e:
                    print(f"       └─ [Desc] {desc.uuid}: 读取失败 ({e})")

    # 结论
    print_separator("诊断结论")
    if fido_found:
        print("[✓] 设备暴露了 FIDO 服务 (0xFFFD)")
        print("    → 设备固件正常，问题出在 Windows 的 CTAP BLE 栈")
        print("    → 建议清理 Windows 蓝牙 GATT 缓存后重新配对")
    else:
        print("[✗] 未发现 FIDO 服务 (0xFFFD)")
        print("    → 设备固件可能未正确暴露 FIDO 服务")
        print("    → 或设备处于非 FIDO 模式（需要按键/触摸唤醒）")
        print("    → 建议联系设备厂商确认固件版本")

    await client.disconnect()
    print("\n[✓] 已断开连接")

async def scan_and_match(address: str):
    """先扫描，确认设备是否在广播"""
    print_separator("扫描 BLE 设备")
    print("扫描中 (8 秒)...")
    devices = await BleakScanner.discover(timeout=8.0, return_adv=True)
    print(f"发现 {len(devices)} 个设备:\n")

    found = False
    for addr, (dev, adv) in devices.items():
        name = dev.name or "(未知)"
        uuids = adv.service_uuids or []
        has_fido = any(is_fido_service(u) for u in uuids)
        marker = " ★ 含 FIDO 服务" if has_fido else ""
        print(f"  {name}  [{addr}]  RSSI={adv.rssi}{marker}")
        for u in uuids:
            print(f"      └─ 广播服务: {u}")
        if addr.upper() == address.upper():
            found = True
            print(f"      └─ ★ 这是目标设备")
            print(addr)
    if not found:
        print(f"\n[!] 未在扫描结果中找到目标地址 {address}")
        print("    BLE FIDO 设备可能使用随机地址，建议:")
        print("    1. 按设备上的按键唤醒它")
        print("    2. 在下方列表中找到名称含 'SecureKey' 或类似名称的设备")
        print("    3. 用其当前地址替换脚本中的 TARGET_ADDRESS")

async def main():
    # 先扫描
    await scan_and_match(TARGET_ADDRESS)
    # 再连接并转储
    await dump_device(TARGET_ADDRESS)

if __name__ == "__main__":
    if sys.platform != "win32":
        print("此脚本建议在 Windows 上运行（用于诊断 Windows CTAP 问题）")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n已中断")
    except Exception as e:
        print(f"\n运行出错: {e}")
        import traceback
        traceback.print_exc()