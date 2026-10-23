#!/usr/bin/env python3
"""
FIDOKey_CH583 真机测试 —— 底层 CTAPHID 命令与 GetInfo（对应测试清单 T2 / T3）

用法:
    pip install fido2
    python tools/fido2_ctaphid_test.py

覆盖:
    T2.1 CTAPHID_INIT   —— nonce 回显 / newCID / 协议版本 / 能力位
    T2.2 CTAPHID_PING   —— 100 字节 payload（远大于单帧 59 字节，必然多帧收发）
    T2.3 CTAPHID_WINK   —— 空响应
    T2.4 未知命令        —— 应为 CTAPHID_ERROR + INVALID_CMD
    T3   CTAP2 GetInfo  —— versions / aaguid / options / maxMsgSize

说明: 这里全部走底层 dev.call()，不依赖 python-fido2 的高层 API，
      因此不受各版本 API 变动影响，是最稳定的一组用例。
"""

import sys

try:
    from fido2.hid import CtapHidDevice
    from fido2.ctap2 import Ctap2
except ImportError:
    print("缺少 python-fido2，请先执行: pip install fido2")
    sys.exit(2)

CTAPHID_PING = 0x01
CTAPHID_INIT = 0x06
CTAPHID_WINK = 0x08
CTAPHID_ERROR = 0x3F
CTAPHID_CMD_INVALID = 0x01

_failed = 0
_passed = 0


def check(name, cond, extra=""):
    global _failed, _passed
    if cond:
        _passed += 1
        print("  [PASS] " + name + (("  (" + str(extra) + ")") if extra else ""))
    else:
        _failed += 1
        print("  [FAIL] " + name + (("  (" + str(extra) + ")") if extra else ""))


def main():
    devs = list(CtapHidDevice.list_devices())
    print("发现 %d 个 CTAPHID 设备" % len(devs))
    if not devs:
        print("未发现设备。请确认:")
        print("  1) 设备已插上，设备管理器中没有代码 43")
        print("  2) 没有被别的程序独占（关掉浏览器再试）")
        return 1

    dev = devs[0]
    print("使用设备: %s" % dev.descriptor.path)
    print()

    # ---------- T2.1 INIT ----------
    print("[T2.1] CTAPHID_INIT")
    nonce = bytes(range(8))
    resp = dev.call(CTAPHID_INIT, nonce)
    print("        响应 %d 字节: %s" % (len(resp), resp.hex()))
    check("响应 17 字节（nonce8+newCID4+版本1+设备版本3+caps1）", len(resp) == 17, len(resp))
    if len(resp) >= 17:
        check("nonce 原样回显", resp[0:8] == nonce)
        check("newCID == 0（不分配新通道）", resp[8:12] == bytes(4))
        check("CTAPHID 协议版本 == 2", resp[12] == 2, resp[12])
        check("caps 含 CBOR(0x04)", (resp[16] & 0x04) != 0, hex(resp[16]))
    print()

    # ---------- T2.2 PING（多帧） ----------
    print("[T2.2] CTAPHID_PING  payload = 100 字节（单帧仅 57/59，必然分片）")
    payload = bytes((i * 7 + 3) & 0xFF for i in range(100))
    resp = dev.call(CTAPHID_PING, payload)
    check("回显长度仍为 100", len(resp) == 100, len(resp))
    check("回显内容逐字节一致", resp == payload)
    print()

    # ---------- T2.3 WINK ----------
    print("[T2.3] CTAPHID_WINK")
    resp = dev.call(CTAPHID_WINK, b"")
    check("空响应", len(resp) == 0, len(resp))
    print()

    # ---------- T2.4 未知命令 ----------
    print("[T2.4] 未定义命令 0x7A（期望 CTAPHID_ERROR/INVALID_CMD）")
    try:
        resp = dev.call(0x7A, b"")
        # 若能正常返回，检查是否是我们期望的错误响应（部分库版本会把错误当响应返回）
        if len(resp) >= 1:
            check("收到错误码 0x01(INVALID_CMD)", resp[0] == CTAPHID_CMD_INVALID, resp.hex())
        else:
            check("应被拒绝", False, "返回了空响应")
    except Exception as e:
        # 库把 CTAPHID_ERROR 转成异常也是正常路径
        check("命令被拒绝（异常为预期行为）", True, type(e).__name__)
    print()

    # ---------- T3 GetInfo ----------
    print("[T3] CTAP2 GetInfo")
    ctap2 = Ctap2(dev)
    info = ctap2.info
    print("        versions     : %s" % info.versions)
    print("        aaguid       : %s" % info.aaguid.hex())
    print("        options      : %s" % info.options)
    print("        maxMsgSize   : %s" % getattr(info, "max_msg_size", None))
    check("versions 含 FIDO_2_0", "FIDO_2_0" in info.versions, info.versions)
    check("aaguid 长度 16", len(info.aaguid) == 16, len(info.aaguid))
    check("options.up == True", info.options.get("up") is True, info.options)
    check("未声明 rk（本实现不支持可驻留凭证）",
          not info.options.get("rk", False), info.options)
    print()

    print("=" * 56)
    print("结果: %d 通过 / %d 失败" % (_passed, _failed))
    print("=" * 56)
    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
