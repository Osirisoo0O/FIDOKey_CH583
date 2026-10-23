#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BLE FIDO 安全密钥诊断脚本
用于检测 Windows 环境下 CTAP BLE 设备连接、GATT 服务、系统服务及注册状态。
需以管理员身份运行，以确保能访问所有系统信息和事件日志。

依赖安装:
    pip install bleak wmi pywin32
"""

import asyncio
import subprocess
import sys
import os
import re
import json
from datetime import datetime, timedelta
from typing import Optional

# ---------- 颜色输出辅助 ----------
class Color:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

def ok(msg): print(f"{Color.GREEN}[✓] {msg}{Color.RESET}")
def warn(msg): print(f"{Color.YELLOW}[!] {msg}{Color.RESET}")
def err(msg): print(f"{Color.RED}[✗] {msg}{Color.RESET}")
def info(msg): print(f"{Color.CYAN}[i] {msg}{Color.RESET}")

def run_cmd(cmd: list, timeout: int = 30) -> tuple:
    """执行命令并返回 (stdout, stderr, returncode)"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout, encoding='utf-8', errors='ignore')
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "命令超时", -1
    except Exception as e:
        return "", str(e), -1

# ============================================================
# 1. 系统基础信息
# ============================================================
def check_system_info():
    print("\n" + "="*60)
    info("1. 系统基础信息")
    print("="*60)

    # Windows 版本
    out, _, _ = run_cmd(["cmd", "/c", "ver"])
    print(f"  Windows 版本: {out.strip()}")

    # 系统时间
    out, _, _ = run_cmd(["w32tm", "/query", "/status"])
    if out:
        for line in out.splitlines():
            if "Source" in line or "Last Successful Sync" in line:
                print(f"  时间同步: {line.strip()}")

    # 是否为管理员
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin:
            ok("当前以管理员身份运行")
        else:
            warn("未以管理员身份运行，部分检测可能受限")
    except Exception:
        pass

# ============================================================
# 2. 蓝牙服务状态
# ============================================================
def check_bluetooth_service():
    print("\n" + "="*60)
    info("2. 蓝牙服务状态")
    print("="*60)

    services = {
        "bthserv": "蓝牙支持服务",
        "BluetoothUserService": "蓝牙用户服务",
        "BthAvctpSvc": "蓝牙音频视频控制传输协议服务",
    }

    for svc_name, desc in services.items():
        out, _, code = run_cmd(["sc", "query", svc_name])
        if "RUNNING" in out:
            ok(f"{desc} ({svc_name}): 正在运行")
        elif "STOPPED" in out:
            err(f"{desc} ({svc_name}): 已停止")
        elif "does not exist" in out.lower() or code != 0:
            warn(f"{desc} ({svc_name}): 服务不存在")
        else:
            warn(f"{desc} ({svc_name}): 状态未知")

    # 检查加密服务
    out, _, _ = run_cmd(["sc", "query", "CryptSvc"])
    if "RUNNING" in out:
        ok("Cryptographic Services (CryptSvc): 正在运行")
    else:
        err("Cryptographic Services (CryptSvc): 未运行")

# ============================================================
# 3. 蓝牙适配器与 BLE 支持
# ============================================================
def check_bluetooth_adapter():
    print("\n" + "="*60)
    info("3. 蓝牙适配器与 BLE 支持")
    print("="*60)

    # 通过 PowerShell 获取蓝牙适配器信息
    ps_cmd = (
        'Get-PnpDevice -Class Bluetooth | '
        'Select-Object Status, FriendlyName, InstanceId | '
        'ConvertTo-Json -Compress'
    )
    out, _, _ = run_cmd(["powershell", "-NoProfile", "-Command", ps_cmd])
    if out.strip():
        try:
            devices = json.loads(out)
            if isinstance(devices, dict):
                devices = [devices]
            for dev in devices:
                status = dev.get("Status", "Unknown")
                name = dev.get("FriendlyName", "Unknown")
                if status == "OK":
                    ok(f"蓝牙设备: {name} (状态: {status})")
                else:
                    warn(f"蓝牙设备: {name} (状态: {status})")
        except json.JSONDecodeError:
            warn("无法解析蓝牙适配器信息")
    else:
        err("未检测到蓝牙适配器")

    # 检查蓝牙无线电是否开启
    ps_radio = (
        'Get-PnpDevice -Class Bluetooth | '
        'Where-Object {$_.FriendlyName -match "Radio|Adapter|Bluetooth"} | '
        'Select-Object -First 1 | '
        'ForEach-Object { $_.Status }'
    )
    out, _, _ = run_cmd(["powershell", "-NoProfile", "-Command", ps_radio])
    if "OK" in out:
        ok("蓝牙无线电已开启")
    else:
        warn("蓝牙无线电可能已关闭，请在设置中检查")

# ============================================================
# 4. BLE 设备扫描与 FIDO 服务发现
# ============================================================
async def scan_ble_fido_devices():
    """扫描附近的 BLE 设备，并尝试发现 FIDO GATT 服务 (UUID 0xFFFD)"""
    print("\n" + "="*60)
    info("4. BLE 设备扫描与 FIDO 服务发现")
    print("="*60)

    try:
        from bleak import BleakScanner, BleakClient
    except ImportError:
        err("未安装 bleak 库，请运行: pip install bleak")
        return

    FIDO_SERVICE_UUID = "0000fffd-0000-1000-8000-00805f9b34fb"

    info("正在扫描 BLE 设备 (持续 8 秒)...")
    try:
        devices = await BleakScanner.discover(timeout=8.0)
    except Exception as e:
        err(f"BLE 扫描失败: {e}")
        return

    if not devices:
        warn("未发现任何 BLE 设备。请确认蓝牙已开启且设备处于广播模式。")
        return

    print(f"\n发现 {len(devices)} 个 BLE 设备:")
    fido_candidates = []

    for dev in devices:
        name = dev.name or "未知设备"
        addr = dev.address
        rssi = dev.rssi if hasattr(dev, 'rssi') else "N/A"
        print(f"  - {name} [{addr}] RSSI: {rssi}")

        # 检查广播数据中是否包含 FIDO 服务 UUID
        if hasattr(dev, 'metadata') and dev.metadata:
            uuids = dev.metadata.get('uuids', [])
            if any(FIDO_SERVICE_UUID.lower() in u.lower() for u in uuids):
                fido_candidates.append(dev)
                ok(f"    ↑ 广播中包含 FIDO 服务 UUID (0xFFFD)")

    # 对可能包含 FIDO 服务的设备进行连接测试
    if fido_candidates:
        print(f"\n发现 {len(fido_candidates)} 个 FIDO 候选设备，尝试连接并发现服务...")
        for dev in fido_candidates:
            await _test_gatt_connection(dev)
    else:
        # 如果广播中未发现，尝试连接所有设备（仅测试前3个）
        info("\n广播中未发现 FIDO 服务 UUID，尝试连接前 3 个设备进行 GATT 发现...")
        for dev in devices[:3]:
            await _test_gatt_connection(dev)

async def _test_gatt_connection(device):
    """连接设备并尝试发现 FIDO GATT 服务"""
    from bleak import BleakClient
    FIDO_SERVICE_UUID = "0000fffd-0000-1000-8000-00805f9b34fb"

    name = device.name or "未知设备"
    addr = device.address
    print(f"\n  连接 {name} [{addr}] ...")

    try:
        client = BleakClient(addr, timeout=15.0)
        await client.connect()
        if client.is_connected:
            ok(f"    连接成功")
            services = client.services
            if services:
                fido_found = False
                for svc in services:
                    uuid = svc.uuid.lower()
                    if FIDO_SERVICE_UUID in uuid or uuid.startswith("0000fffd"):
                        fido_found = True
                        ok(f"    发现 FIDO 服务: {svc.uuid}")
                        for char in svc.characteristics:
                            print(f"      特征值: {char.uuid} (属性: {char.properties})")
                if not fido_found:
                    warn(f"    已连接但未发现 FIDO 服务 (0xFFFD)")
                    print(f"    发现的服务列表:")
                    for svc in services:
                        print(f"      - {svc.uuid}")
            else:
                warn(f"    连接成功但未获取到 GATT 服务列表（可能为缓存问题）")
            await client.disconnect()
        else:
            err(f"    连接失败")
    except Exception as e:
        err(f"    连接异常: {e}")

# ============================================================
# 5. 蓝牙配对与 GATT 缓存检查
# ============================================================
def check_bluetooth_pairing_cache():
    print("\n" + "="*60)
    info("5. 蓝牙配对与 GATT 缓存检查")
    print("="*60)

    # 检查已配对的蓝牙设备
    ps_cmd = (
        'Get-PnpDevice -Class Bluetooth | '
        'Where-Object {$_.Status -eq "OK"} | '
        'Select-Object FriendlyName, InstanceId | '
        'ConvertTo-Json -Compress'
    )
    out, _, _ = run_cmd(["powershell", "-NoProfile", "-Command", ps_cmd])
    if out.strip():
        try:
            devices = json.loads(out)
            if isinstance(devices, dict):
                devices = [devices]
            for dev in devices:
                name = dev.get("FriendlyName", "")
                if name and "SecureKey" in name or "FIDO" in name or "Security" in name:
                    ok(f"已配对设备: {name}")
        except json.JSONDecodeError:
            pass

    # 检查注册表中的配对密钥
    reg_path = r"HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Keys"
    out, _, code = run_cmd(["reg", "query", reg_path])
    if code == 0 and out.strip():
        ok(f"注册表配对密钥路径存在: {reg_path}")
        subkeys = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith("HKEY")]
        print(f"    包含 {len(subkeys)} 个设备的配对密钥")
    else:
        warn(f"未找到注册表配对密钥路径或为空: {reg_path}")

    # 检查 GATT 缓存文件
    cache_paths = [
        os.path.expandvars(r"%ProgramData%\Microsoft\Bluetooth"),
        os.path.expandvars(r"%ProgramData%\Microsoft\Bluetooth\GATT"),
    ]
    for path in cache_paths:
        if os.path.exists(path):
            files = os.listdir(path)
            if files:
                warn(f"GATT 缓存目录存在文件: {path} ({len(files)} 个文件)")
            else:
                ok(f"GATT 缓存目录为空: {path}")
        else:
            info(f"GATT 缓存目录不存在: {path}")

# ============================================================
# 6. 事件日志检查 (蓝牙与 FIDO 相关)
# ============================================================
def check_event_logs():
    print("\n" + "="*60)
    info("6. 事件日志检查 (近 7 天)")
    print("="*60)

    # 检查蓝牙相关事件
    ps_cmd = (
        'Get-WinEvent -FilterHashtable @{LogName="System"; '
        'StartTime=(Get-Date).AddDays(-7)} -MaxEvents 200 -ErrorAction SilentlyContinue | '
        'Where-Object {$_.ProviderName -match "BTH|Bluetooth|FIDO|Ctap"} | '
        'Select-Object TimeCreated, Id, LevelDisplayName, Message | '
        'ConvertTo-Json -Compress'
    )
    out, _, _ = run_cmd(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=60)
    if out.strip() and out.strip() != "null":
        try:
            events = json.loads(out)
            if isinstance(events, dict):
                events = [events]
            err_count = 0
            for ev in events:
                level = ev.get("LevelDisplayName", "")
                msg = ev.get("Message", "")
                if "错误" in level or "Error" in level:
                    err_count += 1
                    if err_count <= 5:
                        err(f"[{ev.get('TimeCreated','')}] {msg[:200]}")
            if err_count == 0:
                ok("近 7 天未发现蓝牙/FIDO 相关错误事件")
            else:
                warn(f"近 7 天发现 {err_count} 条蓝牙/FIDO 相关错误事件（仅显示前 5 条）")
        except json.JSONDecodeError:
            info("无法解析事件日志")
    else:
        info("未找到蓝牙/FIDO 相关事件日志")

    # 检查用户设备注册日志
    ps_cmd2 = (
        'Get-WinEvent -LogName "Microsoft-Windows-User Device Registration/Admin" '
        '-MaxEvents 20 -ErrorAction SilentlyContinue | '
        'Select-Object TimeCreated, Id, LevelDisplayName, Message | '
        'ConvertTo-Json -Compress'
    )
    out2, _, _ = run_cmd(["powershell", "-NoProfile", "-Command", ps_cmd2], timeout=60)
    if out2.strip() and out2.strip() != "null":
        try:
            events = json.loads(out2)
            if isinstance(events, dict):
                events = [events]
            print(f"\n  用户设备注册日志 (最近 {len(events)} 条):")
            for ev in events[:5]:
                level = ev.get("LevelDisplayName", "")
                msg = ev.get("Message", "")
                if "错误" in level or "Error" in level:
                    err(f"    [{ev.get('TimeCreated','')}] {msg[:200]}")
                else:
                    info(f"    [{ev.get('TimeCreated','')}] {msg[:200]}")
        except json.JSONDecodeError:
            pass

# ============================================================
# 7. Azure AD / 设备注册状态
# ============================================================
def check_dsreg_status():
    print("\n" + "="*60)
    info("7. Azure AD / 设备注册状态")
    print("="*60)

    out, _, code = run_cmd(["dsregcmd", "/status"])
    if code != 0:
        warn("无法执行 dsregcmd /status")
        return

    important_fields = {
        "AzureAdJoined": "设备是否已加入 Azure AD",
        "EnterpriseJoined": "设备是否已加入企业",
        "DomainJoined": "设备是否已加入域",
        "NgcSet": "Windows Hello 是否已设置",
        "WorkplaceJoined": "是否已加入工作区",
    }

    for line in out.splitlines():
        for field, desc in important_fields.items():
            if field in line:
                value = line.split(":")[-1].strip()
                if value.upper() == "YES":
                    ok(f"{desc}: {value}")
                elif value.upper() == "NO":
                    warn(f"{desc}: {value}")
                else:
                    info(f"{desc}: {value}")

    # 检查 Ngc 文件夹是否存在
    ngc_path = r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc"
    if os.path.exists(ngc_path):
        ok(f"Ngc 文件夹存在: {ngc_path}")
    else:
        info(f"Ngc 文件夹不存在: {ngc_path}")

# ============================================================
# 8. TPM 状态检查
# ============================================================
def check_tpm_status():
    print("\n" + "="*60)
    info("8. TPM 状态检查")
    print("="*60)

    try:
        import wmi
        c = wmi.WMI(namespace="root/cimv2/security/microsofttpm")
        tpm_list = c.Win32_Tpm()
        if tpm_list:
            for tpm in tpm_list:
                ok(f"TPM 存在: 版本 {tpm.SpecVersion}, 已激活: {tpm.IsActivated()}")
                if not tpm.IsActivated():
                    err("TPM 未激活，可能影响 FIDO 密钥功能")
        else:
            warn("未检测到 TPM 设备")
    except ImportError:
        warn("未安装 wmi 库，跳过 TPM 检查 (pip install wmi)")
    except Exception as e:
        warn(f"TPM 检查失败: {e}")

    # 通过 PowerShell 检查 TPM
    ps_cmd = 'Get-Tpm -ErrorAction SilentlyContinue | Select-Object TpmPresent, TpmReady, TpmEnabled | ConvertTo-Json'
    out, _, _ = run_cmd(["powershell", "-NoProfile", "-Command", ps_cmd])
    if out.strip():
        try:
            tpm_info = json.loads(out)
            print(f"  PowerShell TPM 信息: {tpm_info}")
        except json.JSONDecodeError:
            pass

# ============================================================
# 9. FIDO 注册表检查
# ============================================================
def check_fido_registry():
    print("\n" + "="*60)
    info("9. FIDO 注册表检查")
    print("="*60)

    reg_paths = [
        r"HKLM\SOFTWARE\Microsoft\Cryptography\FIDO",
        r"HKLM\SYSTEM\CurrentControlSet\Services\CryptSvc\FIDO",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\WinBio",
    ]

    for path in reg_paths:
        out, _, code = run_cmd(["reg", "query", path])
        if code == 0 and out.strip():
            ok(f"注册表路径存在: {path}")
            for line in out.splitlines():
                line = line.strip()
                if line and not line.startswith("HKEY"):
                    print(f"    {line}")
        else:
            info(f"注册表路径不存在或为空: {path}")

# ============================================================
# 10. 网络连接检查 (Azure AD 注册端点)
# ============================================================
def check_network_endpoints():
    print("\n" + "="*60)
    info("10. 网络连接检查 (Azure AD 注册端点)")
    print("="*60)

    endpoints = [
        "enterpriseregistration.windows.net",
        "login.microsoftonline.com",
        "graph.windows.net",
    ]

    for ep in endpoints:
        # DNS 解析
        out, _, code = run_cmd(["nslookup", ep])
        if code == 0 and "Address" in out:
            ok(f"DNS 解析成功: {ep}")
        else:
            err(f"DNS 解析失败: {ep}")

        # TCP 443 连接
        ps_cmd = f'(Test-NetConnection -ComputerName "{ep}" -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded'
        out, _, _ = run_cmd(["powershell", "-NoProfile", "-Command", ps_cmd])
        if "True" in out:
            ok(f"TCP 443 连接成功: {ep}")
        else:
            err(f"TCP 443 连接失败: {ep}")

# ============================================================
# 主函数
# ============================================================
async def main():
    print("="*60)
    print("  BLE FIDO 安全密钥诊断工具")
    print(f"  运行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    check_system_info()
    check_bluetooth_service()
    check_bluetooth_adapter()
    await scan_ble_fido_devices()
    check_bluetooth_pairing_cache()
    check_event_logs()
    check_dsreg_status()
    check_tpm_status()
    check_fido_registry()
    check_network_endpoints()

    print("\n" + "="*60)
    info("诊断完成")
    print("="*60)
    print("\n建议:")
    print("  1. 如果蓝牙服务未运行，请以管理员身份运行: net start bthserv")
    print("  2. 如果 GATT 缓存目录有文件，请考虑清理蓝牙缓存并重新配对")
    print("  3. 如果 TPM 未就绪，请在 BIOS/UEFI 中启用 TPM 或运行 tpm.msc")
    print("  4. 如果 Azure AD 注册状态异常，请参考事件日志中的具体错误")
    print("  5. 如果未发现 FIDO 服务 (0xFFFD)，请检查设备固件是否为最新版本")

if __name__ == "__main__":
    # 确保在 Windows 上运行
    if sys.platform != "win32":
        print("此脚本仅适用于 Windows 系统。")
        sys.exit(1)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n诊断已中断。")
    except Exception as e:
        print(f"\n诊断过程中发生错误: {e}")
        import traceback
        traceback.print_exc()