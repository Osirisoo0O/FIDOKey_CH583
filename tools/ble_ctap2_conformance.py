#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BLE CTAP2 一致性测试 —— 按 CTAP 2.1 规范逐条检查设备侧实现。

与 tools/ble_gatt_client.py 的区别：
  - ble_gatt_client.py      演示"能不能跑通"，宽松、偏集成
  - 本脚本                   按 CTAP 2.1 §11（BLE 传输）与 §6（CTAP2 命令）
                            逐条核对规范要求，偏一致性（conformance）

每一项检查都对应规范里的一句原文（注释里标注了出处），输出 PASS / FAIL / SKIP，
并在最后给出汇总。**本脚本只读/只做规范允许的操作，不修改设备状态。**

规范依据：
  - CTAP 2.1 §11.2   GATT 服务定义（UUID、特征、权限）
  - CTAP 2.1 §11.4.3 帧格式（CMD / LEN / BCNT / SEQ）
  - CTAP 2.1 §11.4.5 CPLength
  - CTAP 2.1 §11.4.6 版本位
  - CTAP 2.1 §6      认证器 API（GetInfo / MakeCredential / GetAssertion）
  - CTAP 2.1 §6.1    authData 结构

用法：
    python tools/ble_ctap2_conformance.py            # 全量测试
    python tools/ble_ctap2_conformance.py --addr XX:XX:XX:XX:XX:XX
    python tools/ble_ctap2_conformance.py --scan     # 只扫描
    python tools/ble_ctap2_conformance.py --skip-rk  # 跳过需要按键的用例

前置：先在系统里删除该设备的配对记录，避免 Windows 蓝牙栈抢占链路。
"""

import argparse
import asyncio
import hashlib
import struct
import sys
import time
from dataclasses import dataclass, field

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    print("缺少 bleak：pip install bleak", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------- 常量

# CTAP 2.1 §11.2.1：FIDO 服务 UUID（128-bit）
FIDO_SERVICE_UUID = "0000fffd-0000-1000-8000-00805f9b34fb"

# CTAP 2.1 §11.2.2 ~ §11.2.5：四个特征
UUID_CONTROL_POINT = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb"   # Write
UUID_STATUS = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb"           # Notify
UUID_CP_LENGTH = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb"        # Read
UUID_REV_BITFIELD = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb"     # Read/Write

DEVICE_NAME = "SecureKey"

# CTAP 2.1 §11.4.10 帧格式：由 fidoControlPoint 承载
#   初始分片：  CMD(1) | HLEN(1) | LLEN(1) | DATA      ← LEN 是**大端**
#   续分片：    SEQ(1, bit7=0) | DATA                    ← SEQ 从 0 起，到 0x7F 回绕
#   CMD 的 bit7 必须为 1（"the start of an initialization fragment is indicated
#   by setting the high bit in the first byte"）
#
# ★ 命令码取自 §11.4.4.3 —— **BLE 有自己的表，与 USB HID（CTAPHID）不同**：
#     线上值    低 7 位（本脚本内部用的"裸码"）
#     PING      0x81  ->  0x01
#     KEEPALIVE 0x82  ->  0x02      ← 注意：不是 HID 的 0xBB/0x3B
#     MSG       0x83  ->  0x03
#     CANCEL    0xBE  ->  0x3E      ← 注意：不是 HID 的 0x91/0x11
#     ERROR     0xBF  ->  0x3F
CTAPHID_PING = 0x01
CTAPHID_KEEPALIVE = 0x02     # BLE §11.4.4.3
CTAPHID_MSG = 0x03
CTAPHID_CANCEL = 0x3E        # BLE §11.4.4.3
CTAPHID_ERROR = 0x3F

# KEEPALIVE 的载荷是 1 字节状态（§11.4.4.3）
KA_PROCESSING = 0x01
KA_UP_NEEDED = 0x02

# 封装层 ERROR 帧 DATA 里的错误码（§11.4.4.3）
# ★ 注意：ERROR 帧是  STAT(0xBF) | HLEN | LLEN | <错误码>
#   最后那个字段是**错误码**，不是 STAT 的值本身。
FIDO_EC_INVALID_CMD = 0x01
FIDO_EC_INVALID_PAR = 0x02
FIDO_EC_INVALID_LEN = 0x03
FIDO_EC_INVALID_SEQ = 0x04
FIDO_EC_REQ_TIMEOUT = 0x05
FIDO_EC_BUSY = 0x06
FIDO_EC_OTHER = 0x7F
# 若设备把 STAT 的值(0xBF)误填进 DATA，用这个哨兵值把它认出来
FIDO_EC_STAT_SENTINEL = 0xBF


def is_insufficient_crypto(exc):
    """判断异常是否为"链路未加密/未认证"（CTAP 2.1 §11.4.3 的拦截）。

    设备对 FIDO 属性设了 GATT_PERMIT_ENCRYPT_*，未加密的连接会被拒。
    各平台/后端的表达方式不同，实测 Windows + bleak 报的是：
        BleakGATTProtocolError(5, 'GATT Protocol Error: Insufficient Authentication')
    —— 注意 ATT 错误码是 **5 (Insufficient Authentication)**，
    而不是规范文档里常见的 0x0F (Insufficient Encryption)。两者语义相同：
    链路尚未满足安全要求，设备拒绝在加密前交换 FIDO 消息。

    判定要求同时出现 "insufficient" 与 ("encrypt" 或 "authenticat")，
    以免把 "Device not found"、"operation was canceled" 之类误判进来。
    """
    text = f"{exc!r} {exc}".lower()
    return "insufficient" in text and ("encrypt" in text or "authenticat" in text)


# CTAP2 命令码（CTAP 2.1 §6）
CTAP_MAKE_CREDENTIAL = 0x01
CTAP_GET_ASSERTION = 0x02
CTAP_GET_INFO = 0x04
CTAP_CLIENT_PIN = 0x06
CTAP_RESET = 0x07

# CTAP2 状态码（CTAP 2.1 §6.3）
CTAP2_OK = 0x00
CTAP1_ERR_INVALID_COMMAND = 0x01
CTAP2_ERR_CBOR_UNEXPECTED_TYPE = 0x11
CTAP2_ERR_INVALID_CBOR = 0x12
CTAP2_ERR_MISSING_PARAMETER = 0x14
CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26
CTAP2_ERR_OPERATION_DENIED = 0x27
CTAP2_ERR_NOT_ALLOWED = 0x2B
CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D      # §11.4.8：被 CANCEL 取消的请求回这个码

# CTAP 2.1 §6.1 authData 里的 flags 位
AUTHDATA_FLAG_UP = 0x01        # bit0 User Present
AUTHDATA_FLAG_UV = 0x04        # bit2 User Verified
AUTHDATA_FLAG_BE = 0x08        # bit3 Backup Eligibility
AUTHDATA_FLAG_BS = 0x10        # bit4 Backup State
AUTHDATA_FLAG_AT = 0x40        # bit6 Attested credential data included
AUTHDATA_FLAG_ED = 0x80        # bit7 Extension data included

# COSE 算法（CTAP 2.1 §6.5.5）
COSE_ES256 = -7
COSE_EDDSA = -8
COSE_ES384 = -35
COSE_ES512 = -36
COSE_RS256 = -257


# ---------------------------------------------------------------- 结果收集

class Report:
    """收集每项检查的结果。"""

    def __init__(self):
        self.items = []   # (spec, name, verdict, detail)

    def add(self, spec, name, ok, detail=""):
        verdict = "PASS" if ok else "FAIL"
        self.items.append((spec, name, verdict, detail))
        mark = "PASS" if ok else "FAIL"
        print(f"    [{mark}] {name}" + (f" — {detail}" if detail else ""))
        return ok

    def skip(self, spec, name, why=""):
        self.items.append((spec, name, "SKIP", why))
        print(f"    [SKIP] {name}" + (f" — {why}" if why else ""))
        return True

    @property
    def passed(self):
        return sum(1 for _, _, v, _ in self.items if v == "PASS")

    @property
    def failed(self):
        return [x for x in self.items if x[2] == "FAIL"]

    @property
    def skipped(self):
        return sum(1 for _, _, v, _ in self.items if v == "SKIP")


# ---------------------------------------------------------------- 最小 CBOR

class CborError(Exception):
    pass


def cbor_decode(buf, idx=0):
    """极简 CBOR 解码器（仅覆盖 CTAP2 用到的类型）。

    支持：uint / negint / bytes / text / array / map / false / true / null。
    返回 (value, next_index)。
    """
    if idx >= len(buf):
        raise CborError("CBOR 截断")

    initial = buf[idx]
    idx += 1
    major = initial >> 5
    info = initial & 0x1F

    # 读附加信息表示的整数
    if info < 24:
        val = info
    elif info == 24:
        if idx + 1 > len(buf):
            raise CborError("CBOR 截断(uint8)")
        val = buf[idx]; idx += 1
    elif info == 25:
        if idx + 2 > len(buf):
            raise CborError("CBOR 截断(uint16)")
        val = struct.unpack_from(">H", buf, idx)[0]; idx += 2
    elif info == 26:
        if idx + 4 > len(buf):
            raise CborError("CBOR 截断(uint32)")
        val = struct.unpack_from(">I", buf, idx)[0]; idx += 4
    elif info == 27:
        if idx + 8 > len(buf):
            raise CborError("CBOR 截断(uint64)")
        val = struct.unpack_from(">Q", buf, idx)[0]; idx += 8
    else:
        raise CborError(f"CBOR: 不支持的附加信息 {info}")

    if major == 0:                                   # unsigned
        return val, idx
    if major == 1:                                   # negative
        return -1 - val, idx
    if major == 2:                                   # byte string
        if idx + val > len(buf):
            raise CborError("CBOR 截断(bytes)")
        return bytes(buf[idx:idx + val]), idx + val
    if major == 3:                                   # text string
        if idx + val > len(buf):
            raise CborError("CBOR 截断(text)")
        return buf[idx:idx + val].decode("utf-8", "replace"), idx + val
    if major == 4:                                   # array
        out = []
        for _ in range(val):
            v, idx = cbor_decode(buf, idx)
            out.append(v)
        return out, idx
    if major == 5:                                   # map
        out = {}
        for _ in range(val):
            k, idx = cbor_decode(buf, idx)
            v, idx = cbor_decode(buf, idx)
            out[k] = v
        return out, idx
    if major == 6:                                   # tag：跳过
        return cbor_decode(buf, idx)
    if major == 7:                                   # simple / float
        if info == 20:
            return False, idx
        if info == 21:
            return True, idx
        if info == 22:
            return None, idx
        raise CborError(f"CBOR: 不支持的 simple {info}")
    raise CborError(f"CBOR: 不支持的主类型 {major}")


def cbor_encode(obj):
    """极简 CBOR 编码器（用于构造请求）。"""
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    if obj is None:
        return b"\xf6"
    if isinstance(obj, int):
        if obj >= 0:
            return _cbor_head(0, obj)
        return _cbor_head(1, -1 - obj)
    if isinstance(obj, bytes):
        return _cbor_head(2, len(obj)) + obj
    if isinstance(obj, str):
        b = obj.encode("utf-8")
        return _cbor_head(3, len(b)) + b
    if isinstance(obj, list):
        return _cbor_head(4, len(obj)) + b"".join(cbor_encode(x) for x in obj)
    if isinstance(obj, dict):
        out = _cbor_head(5, len(obj))
        for k, v in obj.items():
            out += cbor_encode(k) + cbor_encode(v)
        return out
    raise CborError(f"CBOR: 无法编码 {type(obj)}")


def _cbor_head(major, val):
    m = major << 5
    if val < 24:
        return bytes([m | val])
    if val < 0x100:
        return bytes([m | 24, val])
    if val < 0x10000:
        return bytes([m | 25]) + struct.pack(">H", val)
    if val < 0x100000000:
        return bytes([m | 26]) + struct.pack(">I", val)
    return bytes([m | 27]) + struct.pack(">Q", val)


# ---------------------------------------------------------------- BLE 链路

@dataclass
class Frame:
    cmd: int
    payload: bytes


class BleCtap:
    """把 BLE GATT 上的分片还原成 CTAP HID 帧，并按规范分片发送。"""

    def __init__(self, client, cp_uuid, status_uuid, report):
        self.client = client
        self.cp = cp_uuid
        self.status = status_uuid
        self.report = report
        # 注意：bleak 的 mtu_size 在链路已断时会 assert 失败（WinRT 后端），
        # 所以这里必须保护 —— 否则一次断开就会让整个脚本崩掉，掩盖真正的问题。
        self.mtu = 23
        try:
            mtu = getattr(client, "mtu_size", None)
            if mtu:
                self.mtu = mtu
        except Exception:                       # noqa: BLE001
            pass
        # ★ 分片的基准是 maxLen，不是 MTU：
        #   对写 fidoControlPoint 而言 = CPLength；对 fidoStatus 通知而言
        #   = ATT_MTU - 3（§11.4.5.1）。两者相等时（都等于 MTU-3）用哪个都一样，
        #   但语义不同，单独存下来。读到 CPLength 后由 run() 回填。
        self.max_len = 0           # 0 表示未知，届时回退到 mtu
        # 收到的完整帧队列
        self.frames = []
        self._rx = bytearray()     # 正在重组的帧
        self._need = 0             # 还差多少字节
        self._cur_cmd = 0          # 当前正在重组的帧的命令码（续帧里没有）
        self._notes = set()        # 已记录过的观察（去重，避免刷屏）
        self._ka_up = 0            # 收到 UP_NEEDED 状态的 KEEPALIVE 次数
        self._ka_proc = 0          # 收到 PROCESSING 状态的 KEEPALIVE 次数
        self.raw_rx = []           # 记录每次收到的原始通知（用于核对分片）

    @property
    def connected(self):
        try:
            return bool(self.client.is_connected)
        except Exception:                       # noqa: BLE001
            return False

    # ---- 接收：按 §11.4.3 重组 ----
    def on_notify(self, _handle, data: bytearray):
        if not data:
            return
        self.raw_rx.append(bytes(data))
        raw_cmd = data[0]
        if raw_cmd & 0x80:
            # 初始帧：CMD(1) | LEN(2) | DATA（CMD 的 bit7 必须为 1，§11.4.3）
            if len(data) < 3:
                return
            length = struct.unpack_from(">H", data, 1)[0]
            self._rx = bytearray(data[3:])
            self._need = length
            self._cur_cmd = raw_cmd & 0x7F   # 记住本帧的命令码（续帧里没有）
        else:
            # 后续帧：SEQ(1) | DATA；SEQ 的 bit7 必须为 0
            self._rx += data[1:]

        if len(self._rx) >= self._need:
            payload = bytes(self._rx[:self._need])
            self._rx = bytearray()
            self._need = 0
            # 存"裸"命令码（去掉 bit7），这样上层可以直接和 CTAPHID_MSG 等比。
            self.frames.append(Frame(self._cur_cmd, payload))

    # ---- 发送：按 §11.4.10 分片 ----
    async def send(self, cmd: int, payload: bytes, response: bool = True):
        """发送一个 CTAPHID 帧（按 §11.4.10 分片）。

        ★ 分片的基准是 **maxLen**，不是 MTU：
            §11.4.5.1 说本特征"单次写请求的最大长度"就是
            fidoControlPointLength（= CPLength，实测 253）；
            §11.4.10 的分片公式相对 maxLen：
              初始帧：CMD(1) + HLEN(1) + LLEN(1) + DATA(≤ maxLen-3)
              续  帧：SEQ(1) + DATA(≤ maxLen-1)
          写成 maxLen-3 而不是 MTU-3，差别正是那 3 字节帧头 —— 之前按
          MTU-3 切会让初始帧总长达到 MTU，超出 maxLen，多切一个字节。
        """
        cmd |= 0x80                     # §11.4.10：bit7 必须为 1
        assert len(payload) <= 0xFFFF, "LEN 是 2 字节（§11.4.10）"

        # §11.4.5.1："maximum size in bytes of a single write request"
        max_len = self.max_len if self.max_len > 0 else self.mtu
        assert max_len >= 6, f"maxLen 太小（{max_len}），无法分片"

        frame = bytes([cmd]) + struct.pack(">H", len(payload)) + payload
        first = max_len - 3             # 初始分片的整帧上限
        cont = max_len - 1              # 续分片的整帧上限

        await self.client.write_gatt_char(self.cp, frame[:first], response=response)
        rest = frame[first:]
        seq = 0
        while rest:
            piece = bytes([seq & 0x7F]) + rest[:cont]
            await self.client.write_gatt_char(self.cp, piece, response=response)
            rest = rest[cont:]
            seq += 1

    async def recv(self, timeout=10.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.frames:
                return self.frames.pop(0)
            await asyncio.sleep(0.02)
        return None

    async def ctap(self, command: int, body: bytes, timeout=10.0):
        """发一个 CTAP2 命令并等响应。返回 (status, payload)。

        等待期间可能出现若干"中间帧"，按 CTAP 2.1 §11.4.3 的定义处理：
          KEEPALIVE(0x3B)  §11.4.4 允许穿插，直接跳过
          CBOR(0x02)       本实现不用；若收到则记录（可能是对方命令码用错）
          ERROR(0x3F)      错误通知帧；记录后继续等真正的 MSG
        只有 MSG(0x03) 才是要的响应。
        """
        await self.send(CTAPHID_MSG, bytes([command]) + body)
        deadline = time.monotonic() + timeout
        seen = []
        while time.monotonic() < deadline:
            fr = await self.recv(timeout=1.0)
            if fr is None:
                continue
            seen.append(fr.cmd)
            if fr.cmd == CTAPHID_MSG:
                if not fr.payload:
                    return None, b""
                return fr.payload[0], fr.payload[1:]
            if fr.cmd == CTAPHID_KEEPALIVE:
                # §11.4.9：KEEPALIVE 的载荷是 1 字节状态
                st = fr.payload[0] if fr.payload else 0
                if st == KA_UP_NEEDED:
                    self._ka_up += 1
                elif st == KA_PROCESSING:
                    self._ka_proc += 1
                else:
                    self._note("§11.4.9", f"KEEPALIVE 状态字节非 0x01/0x02：0x{st:02X}")
                continue
            if fr.cmd == CTAPHID_ERROR:
                # §11.4.4.3：ERROR 的载荷是 1 字节错误码
                ec = fr.payload[0] if fr.payload else 0
                ename = {0x01: "INVALID_CMD", 0x02: "INVALID_PAR", 0x03: "INVALID_LEN",
                         0x04: "INVALID_SEQ", 0x05: "REQ_TIMEOUT", 0x06: "BUSY",
                         0x7F: "OTHER"}.get(ec, "?")
                self._note("§11.4.4.3", f"收到 ERROR 帧：0x{ec:02X} ({ename})")
                continue
            self._note("§11.4.4.3", f"收到未预期的命令码 0x{fr.cmd:02X}")
        # 超时：把期间收到的命令码摘要报出来，便于定位
        if seen:
            self._note("§11.4.10",
                       f"命令 0x{command:02X} 超时，期间收到 {self._fmt_cmds(seen)}")
        return None, b""

    def _note(self, spec, text):
        """记录一条观察，不作为失败项（避免同一条信息刷屏）。"""
        key = f"{spec}|{text}"
        if key in self._notes:
            return
        self._notes.add(key)
        if self.report is not None:
            self.report.skip(spec, text)

    @staticmethod
    def _fmt_cmds(cmds):
        """把收到的命令码统计成可读摘要（值为去掉 bit7 后的"裸码"）。"""
        names = {CTAPHID_PING: "PING",
                 CTAPHID_KEEPALIVE: "KEEPALIVE",
                 CTAPHID_MSG: "MSG",
                 CTAPHID_CANCEL: "CANCEL",
                 CTAPHID_ERROR: "ERROR"}
        from collections import Counter
        c = Counter(cmds)
        return ", ".join(f"{names.get(k, '?')}(0x{k:02X})×{v}"
                         for k, v in c.most_common())


# ---------------------------------------------------------------- authData

def parse_authdata(ad: bytes):
    """按 CTAP 2.1 §6.1 解析 authData。

    结构： rpIdHash(32) | flags(1) | signCount(4) | [aaguid(16) | credIdLen(2) | credId | COSE pubKey] | [extensions]
    """
    if len(ad) < 37:
        raise ValueError(f"authData 太短：{len(ad)}")
    rp_id_hash = ad[0:32]
    flags = ad[32]
    sign_count = struct.unpack_from(">I", ad, 33)[0]
    out = {
        "rpIdHash": rp_id_hash,
        "flags": flags,
        "up": bool(flags & AUTHDATA_FLAG_UP),
        "uv": bool(flags & AUTHDATA_FLAG_UV),
        "be": bool(flags & AUTHDATA_FLAG_BE),
        "bs": bool(flags & AUTHDATA_FLAG_BS),
        "at": bool(flags & AUTHDATA_FLAG_AT),
        "ed": bool(flags & AUTHDATA_FLAG_ED),
        "signCount": sign_count,
        "rest": ad[37:],
    }
    idx = 37
    if out["at"]:
        if len(ad) < idx + 18:
            raise ValueError("authData: AT=1 但缺少 attestedCredentialData")
        out["aaguid"] = ad[idx:idx + 16]; idx += 16
        cred_len = struct.unpack_from(">H", ad, idx)[0]; idx += 2
        out["credIdLen"] = cred_len
        out["credId"] = ad[idx:idx + cred_len]; idx += cred_len
        cosepk, idx = cbor_decode(ad, idx)
        out["pubKey"] = cosepk
    return out


# ---------------------------------------------------------------- 测试主体

async def run(args):
    report = Report()

    # ---------- 0. 找到设备 ----------
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
        # mtu_size 在链路异常时会 assert 失败，必须保护
        mtu = 23
        try:
            mtu = getattr(client, "mtu_size", 23) or 23
        except Exception:                                   # noqa: BLE001
            pass
        print(f"已连接（MTU = {mtu}）\n")

        # ---- 链路加密（CTAP 2.1 §11.4.3）----
        # 设备的 FIDO 属性要求加密（GATT_PERMIT_ENCRYPT_*），未加密的连接
        # 读写会被拒（实测：ATT 错误码 5 "Insufficient Authentication"）。
        #
        # ★ 这里**不查配对状态** —— bleak 的 is_paired() 并非各版本都有
        #   （实测当前环境直接 AttributeError），查不到就永远不敢配对，
        #   结果删了配对记录后脚本反而全线失败。
        #   改为直接**探测**：读一个要求加密的特征，被拒就主动配对再复验。
        #   这比查状态更可靠 —— 测的正是我们真正关心的事：链路是否已加密。
        encrypted = False
        enc_note = ""
        try:
            await client.read_gatt_char(UUID_CP_LENGTH)
            encrypted = True
            enc_note = "首次读取即成功，链路已加密"
            print("链路已加密（可直接读写 FIDO 特征）\n")
        except Exception as e:                              # noqa: BLE001
            if is_insufficient_crypto(e):
                print("链路未加密 —— 正在配对（§11.4.3：发 FIDO 消息前必须先加密）...")
                try:
                    await client.pair(timeout=40.0)
                    await client.read_gatt_char(UUID_CP_LENGTH)   # 复验
                    encrypted = True
                    enc_note = "被拒后自动配对成功"
                    print("  配对完成，链路已加密\n")
                except Exception as e2:                     # noqa: BLE001
                    enc_note = f"配对或复验失败：{e2!r}"
                    print(f"  配对或复验失败：{e2!r}")
                    print("  请先在 Windows 设置 → 蓝牙和其他设备里配对 SecureKey，")
                    print("  再重跑本脚本。\n")
            else:
                enc_note = f"读 CPLength 失败（非加密原因）：{e!r}"
                print(f"读 CPLength 失败（非加密原因）：{e!r}\n")

        # 链路健康检查：MTU 停在 23 表示与设备的连接没真正协商成功，
        # 常见原因是系统蓝牙栈已配对并抢占（单连接外设）。此时继续跑只会
        # 得到一连串 "操作已被用户取消"，不如直接给出可操作的提示。
        if mtu <= 23:
            print("！ 提示：MTU 仍为 23（未协商）。这通常意味着本机蓝牙栈已")
            print("  占用该设备的链路（设备是单连接外设）。请先：")
            print("    1) Windows 设置 → 蓝牙和其他设备 → 删除 SecureKey")
            print("    2) 设备断电重上电，长按 PB4 进入配对模式")
            print("    3) 立刻重跑本脚本（不要让系统自动连上）")
            print("  注意：删除配对后本脚本会自动重新配对 —— §11.4.3 要求")
            print("  交换 FIDO 消息前链路必须已加密，未加密的读写会被拒绝。")
            print()

        # ================= §11.4.3 链路安全 =================
        print("=" * 70)
        print("§11.4.3  链路安全（加密前不得交换 FIDO 消息）")
        print("=" * 70)
        report.add("§11.4.3", "链路已加密（可读写 FIDO 特征）",
                   encrypted, enc_note)
        print("    说明：设备对 FIDO 属性设了加密要求，未加密的连接读写得")
        print("          ATT 5 \"Insufficient Authentication\"；自动配对后转正常。\n")

        # ================= §11.2 服务与特征 =================
        print("=" * 70)
        print("§11.2  GATT 服务与特征")
        print("=" * 70)

        svc = client.services.get_service(FIDO_SERVICE_UUID)
        if not report.add("§11.2.1", "FIDO 服务存在（UUID 0000fffd-…）", svc is not None):
            print("\n未找到 FIDO 服务，后续测试无法继续。")
            return 1

        chars = {str(c.uuid).lower(): c for c in svc.characteristics}
        for spec, uuid, name, want_props in (
            ("§11.2.2", UUID_CONTROL_POINT, "fidoControlPoint", {"write"}),
            ("§11.2.3", UUID_STATUS, "fidoStatus", {"notify"}),
            ("§11.2.4", UUID_CP_LENGTH, "fidoControlPointLength", {"read"}),
            ("§11.2.5", UUID_REV_BITFIELD, "fidoServiceRevisionBitfield",
             {"read", "write"}),
        ):
            ch = chars.get(uuid)
            if ch is None:
                report.add(spec, f"{name} 存在", False, "缺失")
                continue
            props = set(ch.properties)
            report.add(spec, f"{name} 存在（props={sorted(props)}）",
                       want_props.issubset(props),
                       "" if want_props.issubset(props)
                       else f"缺少 {want_props - props}")

        # ================= §11.4.6 版本位 =================
        print("\n" + "=" * 70)
        print("§11.4.6  版本位（fidoServiceRevisionBitfield）")
        print("=" * 70)

        rev = b""
        try:
            rev = await client.read_gatt_char(UUID_REV_BITFIELD)
        except Exception as e:                                   # noqa: BLE001
            report.add("§11.4.6", "可读", False, repr(e))

        if rev:
            report.add("§11.4.6", "读值非空", len(rev) >= 1, f"len={len(rev)}")
            # 规范：bit5（0x20）表示支持 FIDO2
            report.add("§11.4.6", "声明支持 FIDO2（bit5=0x20）",
                       bool(rev[0] & 0x20), f"值=0x{rev[0]:02X}")
            # 规范：写 0x00 或 0xFF 应被拒（不得声明"全部版本"）
            try:
                await client.write_gatt_char(UUID_REV_BITFIELD, b"\x00", response=True)
                report.add("§11.4.6", "写入 0x00 被拒",
                           False, "设备接受了非法值 0x00")
            except Exception:                                     # noqa: BLE001
                report.add("§11.4.6", "写入 0x00 被拒", True)
            # 规范：只应接受"单个 bit"的值；这里回写合法值
            try:
                await client.write_gatt_char(UUID_REV_BITFIELD,
                                             bytes([rev[0] & 0x20]), response=True)
                report.add("§11.4.6", "写入合法单一位成功", True)
            except Exception as e:                                # noqa: BLE001
                report.add("§11.4.6", "写入合法单一位成功", False, repr(e))

        # ================= §11.4.5 CPLength =================
        print("\n" + "=" * 70)
        print("§11.4.5  fidoControlPointLength")
        print("=" * 70)

        cp_len = 0
        try:
            raw = await client.read_gatt_char(UUID_CP_LENGTH)
            # §11.4.5 的正文说 "all values are big-endian coded"，但 §11.4.5.1
            # 又说该字段只是"单次写 fidoControlPoint 的最大字节数"，各家实现
            # 存在差异（CTAP 2.0 时代普遍是 little-endian）。这里两种都解，
            # 取落在合法区间 [20,512] 的那个，并把原始字节一并打印以便核对。
            be = le = None
            if len(raw) == 2:
                be = struct.unpack(">H", raw)[0]
                le = struct.unpack("<H", raw)[0]
                if 20 <= le <= 512:
                    cp_len, order = le, "little-endian"
                elif 20 <= be <= 512:
                    cp_len, order = be, "big-endian"
                else:
                    cp_len, order = le, "both-out-of-range"
            report.add("§11.4.5", "读值为 2 字节",
                       len(raw) == 2, f"len={len(raw)}")
            # ★ cp_len 要回填给发送侧（分片基准 = CPLength，§11.4.5.1），
            #   但 link 对象在几行之后才创建 —— 这里只暂存，待建好再回填。
            #   （曾在此直接写 link.max_len = cp_len，触发 UnboundLocalError，
            #     使本段整体判为"可读 失败"。）
            report.add("§11.4.5", "20 ≤ CPLength ≤ 512（§11.4.5.1）",
                       20 <= cp_len <= 512,
                       f"CPLength={cp_len} raw={bytes(raw).hex(' ').upper()} "
                       f"be={be} le={le} 采用={order}")
            # 与协商出的 MTU 对照：CPLength 应当 = MTU - 3
            report.add("§11.4.5", "CPLength = MTU - 3（已协商时）",
                       mtu <= 23 or cp_len == mtu - 3,
                       f"MTU={mtu} -> 期望 {mtu - 3}，实际 {cp_len}")
        except Exception as e:                                    # noqa: BLE001
            report.add("§11.4.5", "可读", False, repr(e))

        # ================= 建立链路对象 =================
        link = BleCtap(client, UUID_CONTROL_POINT, UUID_STATUS, report)
        if cp_len:
            link.max_len = cp_len        # ★ 回填上面读到的 CPLength

        # ================= §11.2.3 订阅通知 =================
        print("\n" + "=" * 70)
        print("§11.2.3  订阅 fidoStatus（CCCD）")
        print("=" * 70)

        try:
            await client.start_notify(UUID_STATUS, link.on_notify)
            report.add("§11.2.3", "订阅成功（CCCD 已写 0x0001）", True)
        except Exception as e:                                    # noqa: BLE001
            report.add("§11.2.3", "订阅成功", False, repr(e))
            return 1

        # ================= §11.4.3 封装层：PING =================
        print("\n" + "=" * 70)
        print("§11.4.3  帧格式（用 PING 验证封装层）")
        print("=" * 70)

        echo = b"CONFORMANCE"
        await link.send(CTAPHID_PING, echo)
        fr = await link.recv(timeout=5.0)
        if fr is None:
            report.add("§11.4.3", "PING 有响应", False, "超时")
        else:
            # Frame.cmd 已去掉 bit7，直接与裸命令码比较
            report.add("§11.4.3", "PING 响应命令码为 0x81",
                       fr.cmd == CTAPHID_PING,
                       f"收到 0x{fr.cmd:02X}")
            report.add("§11.4.3", "PING 载荷原样回显", fr.payload == echo,
                       f"{fr.payload!r}")

        # 分片验证（§11.4.10）：
        #     初始分片： CMD(1) | HLEN | LLEN | DATA(≤ maxLen-3)
        #     续分片：   SEQ(1) | DATA(≤ maxLen-1)
        #   ★ maxLen 不是 MTU！
        #     通知（§11.4.5.1）：单条通知 ≤ ATT_MTU-3，所以
        #         maxLen_notify = mtu - 3
        #     初始帧再扣 3 字节帧头 → DATA ≤ maxLen_notify - 3
        #     续帧  再扣 1 字节 SEQ   → DATA ≤ maxLen_notify - 1
        #   （之前写成 mtu-3 / mtu-4，等于漏算了帧头那 3 字节，
        #     所以把 253B 预测成 1 片，而设备实际发 2 片。）
        max_len_notify = link.mtu - 3        # §11.4.5.1
        first_cap = max_len_notify - 3       # 初始分片的 DATA 容量
        cont_cap = max_len_notify - 1        # 续分片的 DATA 容量
        big_len = max(20, min(cp_len, 512))  # 用 CPLength 允许的最大帧长
        big = bytes((i * 7 + 3) & 0xFF for i in range(big_len))
        want = 1 if big_len <= first_cap else \
            1 + (big_len - first_cap + cont_cap - 1) // cont_cap

        link.raw_rx.clear()
        await link.send(CTAPHID_PING, big)
        fr = await link.recv(timeout=8.0)
        got = len(link.raw_rx)              # ★ 必须在 recv 之后再数
        if fr is None:
            report.add("§11.4.10", f"分片往返（{big_len}B）", False, "超时")
        else:
            need_frag = big_len > first_cap
            report.add("§11.4.10", f"分片往返（{big_len}B，"
                                   f"{'需分片' if need_frag else '单帧可容纳'}）",
                       fr.payload == big,
                       f"回显 {len(fr.payload)} 字节")
            report.add("§11.4.10", "通知分片数符合 §11.4.10 公式",
                       got == want,
                       f"maxLen={max_len_notify}(=MTU-3) 初始DATA容量={first_cap} "
                       f"续DATA容量={cont_cap} 预测 {want} 片，实际 {got} 片")

        # ================= §6.4 GetInfo =================
        print("\n" + "=" * 70)
        print("§6.4  authenticatorGetInfo")
        print("=" * 70)

        status, body = await link.ctap(CTAP_GET_INFO, b"", timeout=10.0)
        report.add("§6.4", "状态为 CTAP2_OK", status == CTAP2_OK,
                   f"0x{status:02X}" if status is not None else "无响应")

        info = {}
        if status == CTAP2_OK and body:
            try:
                info = cbor_decode(body)[0]
                report.add("§6.4", "响应是合法 CBOR map",
                           isinstance(info, dict), f"{type(info).__name__}")
            except CborError as e:
                report.add("§6.4", "响应是合法 CBOR map", False, str(e))

        if isinstance(info, dict):
            # 规范：键 1 = versions，必须包含 "FIDO_2_0"
            versions = info.get(0x01, [])
            report.add("§6.4", "versions(0x01) 是数组", isinstance(versions, list),
                       f"{versions!r}")
            report.add("§6.4", 'versions 含 "FIDO_2_0"', "FIDO_2_0" in versions,
                       f"{versions!r}")
            # 规范：键 3 = aaguid，16 字节
            aaguid = info.get(0x03, b"")
            report.add("§6.4", "aaguid(0x03) 为 16 字节",
                       isinstance(aaguid, bytes) and len(aaguid) == 16,
                       f"len={len(aaguid) if isinstance(aaguid, bytes) else 'n/a'}")
            report.add("§6.4", "aaguid 非全零（已实现真实 AAGUID）",
                       isinstance(aaguid, bytes) and any(aaguid),
                       aaguid.hex().upper() if isinstance(aaguid, bytes) else "")
            # 规范：键 4 = options（map）
            opts = info.get(0x04, {})
            report.add("§6.4", "options(0x04) 是 map", isinstance(opts, dict),
                       f"{opts!r}")
            # 键 6 = transports（CTAP 2.1 新增，本轮固件已声明）
            if 0x06 in info:
                report.add("§6.4", "transports(0x06) 是数组",
                           isinstance(info[0x06], list), f"{info[0x06]!r}")
                report.add("§6.4", 'transports 含 "ble"',
                           "ble" in info[0x06], f"{info[0x06]!r}")
            else:
                report.skip("§6.4", "transports(0x06)",
                            "未声明（可选字段；Windows 客户端可能依赖它）")

        # ================= §6.5 错误处理 =================
        print("\n" + "=" * 70)
        print("§6.5  错误处理")
        print("=" * 70)

        # 未知命令码 → CTAP1_ERR_INVALID_COMMAND
        status, _ = await link.ctap(0x7F, b"", timeout=8.0)
        report.add("§6.5", "未知命令码返回 0x01(INVALID_COMMAND)",
                   status == CTAP1_ERR_INVALID_COMMAND,
                   f"0x{status:02X}" if status is not None else "无响应")

        # GetInfo 带非法参数 → 应忽略或报错，但不得崩
        status, _ = await link.ctap(CTAP_GET_INFO, b"\xff\xff", timeout=8.0)
        report.add("§6.5", "GetInfo 带多余字节仍能正常应答",
                   status is not None, f"0x{status:02X}" if status is not None else "无响应")

        # ================= §11.4.4.2 封装层 ERROR 帧 =================
        print("\n" + "=" * 70)
        print("§11.4.4.2  封装层 ERROR 帧（DATA 必须是错误码）")
        print("=" * 70)

        # 发一个封装层不支持的命令码（0x81/0x82/0x83/0xBE/0xBF 之外）
        # 期望：STAT = 0xBF，且 DATA 是**合法错误码**（§11.4.4.3），
        #       而不是 STAT 的值 0xBF 本身 —— 这是曾经的实现缺陷。
        link.frames.clear()
        await link.send(0x20, b"")          # 裸码 0x20 -> 线上 0xA0，未定义
        fr = await link.recv(timeout=5.0)
        if fr is None:
            report.add("§11.4.4.2", "未支持命令回 ERROR 帧", False, "超时")
        else:
            report.add("§11.4.4.2", "未支持命令回 ERROR 帧",
                       fr.cmd == CTAPHID_ERROR,
                       f"收到命令码 0x{fr.cmd:02X}（期望 ERROR=0x{CTAPHID_ERROR:02X}）")
            if fr.cmd == CTAPHID_ERROR and fr.payload:
                ec = fr.payload[0]
                # 合法错误码集（§11.4.4.3）
                legal = (FIDO_EC_INVALID_CMD, FIDO_EC_INVALID_PAR, FIDO_EC_INVALID_LEN,
                         FIDO_EC_INVALID_SEQ, FIDO_EC_REQ_TIMEOUT, FIDO_EC_BUSY,
                         FIDO_EC_OTHER)
                report.add("§11.4.4.2", "ERROR 的 DATA 是错误码而非 STAT 值",
                           ec != FIDO_EC_STAT_SENTINEL,
                           f"DATA=0x{ec:02X}" + ("  ← 误填了 STAT(0xBF)！"
                                                 if ec == FIDO_EC_STAT_SENTINEL else ""))
                report.add("§11.4.4.3", "错误码在规范定义的取值内",
                           ec in legal,
                           f"DATA=0x{ec:02X}，合法集="
                           + ",".join(f"0x{v:02X}" for v in legal))
                report.add("§11.4.4.3", "错误码语义为 ERR_INVALID_CMD",
                           ec == FIDO_EC_INVALID_CMD,
                           f"DATA=0x{ec:02X}（期望 0x{FIDO_EC_INVALID_CMD:02X}）")

        # ================= CANCEL（§11.4.8）=================
        print("\n" + "=" * 70)
        print("§11.4.8  CANCEL 语义")
        print("=" * 70)

        # CANCEL 本身**绝不能**有响应：发一条空 CANCEL，随后确认链路仍可用
        await link.send(CTAPHID_CANCEL, b"")
        report.add("§11.4.8", "发送 CANCEL 后链路仍可用", True, "（无崩溃）")
        status, _ = await link.ctap(CTAP_GET_INFO, b"", timeout=8.0)
        report.add("§11.4.8", "CANCEL 之后 GetInfo 仍正常",
                   status == CTAP2_OK, f"0x{status:02X}" if status is not None else "无响应")

        # ================= §11.4.8 取消挂起请求 =================
        if args.cancel_up:
            print("\n" + "=" * 70)
            print("§11.4.8  取消挂起请求（--cancel-up）")
            print("=" * 70)
            print("    发一条必需 UP 的请求，然后在 UP_NEEDED 到达后立即 CANCEL")
            print("    期望：被取消的请求回 CTAP2_ERR_KEEPALIVE_CANCEL(0x2D)")

            ch = hashlib.sha256(b"cancel-" + str(time.time()).encode()).digest()
            cancel_req = {
                0x01: ch,
                0x02: {"id": "cancel.local", "name": "Cancel RP"},
                0x03: {"id": hashlib.sha256(b"u").digest()[:16],
                       "name": "u", "displayName": "u"},
                0x04: [{"alg": -7, "type": "public-key"}],
            }
            link.frames.clear()
            await link.send(CTAPHID_MSG,
                            bytes([CTAP_MAKE_CREDENTIAL]) + cbor_encode(cancel_req))

            # 等 UP_NEEDED（或任意 KEEPALIVE），给设备一点时间进入等待
            ka_seen = None
            deadline = time.monotonic() + 6.0
            while time.monotonic() < deadline:
                fr = await link.recv(timeout=1.0)
                if fr is None:
                    continue
                if fr.cmd == CTAPHID_KEEPALIVE and fr.payload:
                    ka_seen = fr.payload[0]
                    break
            report.add("§11.4.9", "必需 UP 时收到 KEEPALIVE",
                       ka_seen is not None,
                       f"状态=0x{ka_seen:02X}" if ka_seen is not None else "未收到")

            # 现在发 CANCEL
            link.frames.clear()
            await link.send(CTAPHID_CANCEL, b"")
            fr = await link.recv(timeout=8.0)
            if fr is None:
                report.add("§11.4.8", "CANCEL 后被取消的请求回 0x2D",
                           False, "超时（未收到任何响应）")
            elif fr.cmd != CTAPHID_MSG:
                report.add("§11.4.8", "CANCEL 后被取消的请求回 0x2D",
                           False, f"收到命令码 0x{fr.cmd:02X}（期望 MSG）")
            else:
                got = fr.payload[0] if fr.payload else None
                report.add("§11.4.8", "CANCEL 后被取消的请求回 0x2D",
                           got == CTAP2_ERR_KEEPALIVE_CANCEL,
                           f"status=0x{got:02X}" if got is not None else "空载荷")
            # CANCEL 本身不得有响应 —— 之后链路应仍然可用
            status, _ = await link.ctap(CTAP_GET_INFO, b"", timeout=8.0)
            report.add("§11.4.8", "取消后链路仍可用",
                       status == CTAP2_OK,
                       f"0x{status:02X}" if status is not None else "无响应")

        # ================= §6.1 MakeCredential =================
        print("\n" + "=" * 70)
        print("§6.1  authenticatorMakeCredential")
        print("=" * 70)

        if args.skip_rk:
            report.skip("§6.1", "MakeCredential", "--skip-rk")
            report.skip("§6.2", "GetAssertion", "--skip-rk")
        else:
            print("    需要用户确认 —— 请按住 PB4（LED 应慢闪）")
            print("    按住约 0.5～5 秒后松开；debug 固件阈值更短（200ms）。")
            print("    若一直不按键，设备会持续发 KEEPALIVE(UP_NEEDED) 直到超时。")
            challenge = hashlib.sha256(b"conformance-" + str(time.time()).encode()).digest()
            user_id = hashlib.sha256(b"user").digest()[:16]
            rp_id = "conformance.local"

            req = {
                0x01: challenge,                       # clientDataHash
                0x02: {                                # rp
                    "id": rp_id,
                    "name": "Conformance RP",
                },
                0x03: {                                # user
                    "id": user_id,
                    "name": "user",
                    "displayName": "Conformance User",
                },
                0x04: [                                # pubKeyCredParams
                    {"alg": COSE_ES256, "type": "public-key"},
                ],
                # 不请求 rk / uv，保持最小请求
            }
            status, body = await link.ctap(CTAP_MAKE_CREDENTIAL, cbor_encode(req),
                                           timeout=30.0)
            report.add("§6.1", "状态为 CTAP2_OK", status == CTAP2_OK,
                       f"0x{status:02X}" if status is not None else "无响应")

            cred_id = b""
            att = {}
            if status == CTAP2_OK and body:
                try:
                    att = cbor_decode(body)[0]
                    report.add("§6.1", "响应是合法 CBOR map",
                               isinstance(att, dict))
                except CborError as e:
                    report.add("§6.1", "响应是合法 CBOR map", False, str(e))

            if isinstance(att, dict):
                # 键 1 = fmt
                fmt = att.get(0x01)
                report.add("§6.1", "fmt(0x01) 存在且为文本",
                           isinstance(fmt, str), f"{fmt!r}")
                # 键 2 = authData
                ad = att.get(0x02)
                report.add("§6.1", "authData(0x02) 存在且为 bytes",
                           isinstance(ad, bytes), f"len={len(ad) if isinstance(ad, bytes) else 'n/a'}")
                # 键 3 = attStmt
                report.add("§6.1", "attStmt(0x03) 是 map",
                           isinstance(att.get(0x03), dict), f"{att.get(0x03)!r}")

                if isinstance(ad, bytes):
                    try:
                        parsed = parse_authdata(ad)
                        # 规范 §6.1：rpIdHash 必须 = SHA-256(rpId)
                        want_hash = hashlib.sha256(rp_id.encode()).digest()
                        report.add("§6.1", "authData.rpIdHash = SHA-256(rpId)",
                                   parsed["rpIdHash"] == want_hash,
                                   parsed["rpIdHash"].hex().upper()[:16] + "…")
                        # 规范：UP 必须为 1（用户在场）
                        report.add("§6.1", "authData.flags.UP = 1", parsed["up"],
                                   f"flags=0x{parsed['flags']:02X}")
                        # 规范：MakeCredential 的 authData 必须带 AT=1
                        report.add("§6.1", "authData.flags.AT = 1", parsed["at"],
                                   f"flags=0x{parsed['flags']:02X}")
                        # 规范：AT=1 时必须带 attestedCredentialData
                        if parsed["at"]:
                            report.add("§6.1", "含 attestedCredentialData（credId）",
                                       "credId" in parsed and len(parsed.get("credId", b"")) > 0,
                                       f"credIdLen={parsed.get('credIdLen')}")
                            report.add("§6.1", "含 COSE 公钥",
                                       isinstance(parsed.get("pubKey"), dict),
                                       f"{parsed.get('pubKey')!r}")
                            cred_id = parsed.get("credId", b"")
                    except Exception as e:                        # noqa: BLE001
                        report.add("§6.1", "authData 解析", False, repr(e))

            # ================= §6.2 GetAssertion =================
            print("\n" + "=" * 70)
            print("§6.2  authenticatorGetAssertion")
            print("=" * 70)
            print("    需要用户确认 —— 请按住 PB4")
            print("    按住约 0.5～5 秒后松开；debug 固件阈值更短（200ms）。")
            challenge2 = hashlib.sha256(b"assert-" + str(time.time()).encode()).digest()

            req2 = {
                0x01: rp_id,                       # rpId
                0x02: challenge2,                  # clientDataHash
            }
            if cred_id:
                req2[0x03] = [{"type": "public-key", "id": cred_id}]

            status, body = await link.ctap(CTAP_GET_ASSERTION, cbor_encode(req2),
                                           timeout=30.0)
            report.add("§6.2", "状态为 CTAP2_OK", status == CTAP2_OK,
                       f"0x{status:02X}" if status is not None else "无响应")

            if status == CTAP2_OK and body:
                try:
                    asrt = cbor_decode(body)[0]
                    report.add("§6.2", "响应是合法 CBOR map",
                               isinstance(asrt, dict))
                except CborError as e:
                    asrt = {}
                    report.add("§6.2", "响应是合法 CBOR map", False, str(e))

                if isinstance(asrt, dict):
                    ad2 = asrt.get(0x02)
                    sig = asrt.get(0x03)
                    report.add("§6.2", "authData(0x02) 为 bytes",
                               isinstance(ad2, bytes),
                               f"len={len(ad2) if isinstance(ad2, bytes) else 'n/a'}")
                    report.add("§6.2", "signature(0x03) 为 bytes 且非空",
                               isinstance(sig, bytes) and len(sig) > 0,
                               f"len={len(sig) if isinstance(sig, bytes) else 'n/a'}")
                    if isinstance(ad2, bytes):
                        try:
                            parsed2 = parse_authdata(ad2)
                            want_hash = hashlib.sha256(rp_id.encode()).digest()
                            report.add("§6.2", "authData.rpIdHash = SHA-256(rpId)",
                                       parsed2["rpIdHash"] == want_hash)
                            report.add("§6.2", "authData.flags.UP = 1",
                                       parsed2["up"], f"flags=0x{parsed2['flags']:02X}")
                            # 规范：GetAssertion 的 authData 不带 AT
                            report.add("§6.2", "authData.flags.AT = 0", not parsed2["at"],
                                       f"flags=0x{parsed2['flags']:02X}")
                        except Exception as e:                    # noqa: BLE001
                            report.add("§6.2", "authData 解析", False, repr(e))

                    # 签名验证：用 MakeCredential 返回的公钥验 GetAssertion 的签名
                    if sig and isinstance(ad2, bytes) and cred_id:
                        _verify_signature(att, ad2, sig, challenge2, report)

        # ================= 汇总 =================
        print("\n" + "=" * 70)
        print("汇总")
        print("=" * 70)
        print(f"  PASS {report.passed}   FAIL {len(report.failed)}   SKIP {report.skipped}")
        if report.failed:
            print("\n  失败项：")
            for spec, name, _, detail in report.failed:
                print(f"    {spec}  {name}  {detail}")
        else:
            print("\n  全部检查通过。")

        print("\n  说明：本脚本按 CTAP 2.1 规范逐条核对**设备侧**实现。")
        print("        若浏览器仍不可用，问题在客户端 —— 见 docs/BLE侧实现规划.md")

        return 0 if not report.failed else 2


def _verify_signature(att: dict, auth_data: bytes, sig: bytes, challenge: bytes,
                      report: Report):
    """用 MakeCredential 返回的 COSE 公钥验证 GetAssertion 的签名。

    CTAP 2.1 §6.2：签名覆盖 (authenticatorData || clientDataHash)。
    这里尽力而为：装了 cryptography 才做，否则 SKIP。
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        report.skip("§6.2", "ECDSA 签名验证", "未安装 cryptography")
        return

    try:
        ad = att.get(0x02)
        if not isinstance(ad, bytes):
            report.skip("§6.2", "ECDSA 签名验证", "缺少注册阶段的 authData")
            return
        reg = parse_authdata(ad)
        pk = reg.get("pubKey")
        if not isinstance(pk, dict):
            report.skip("§6.2", "ECDSA 签名验证", "注册阶段未返回公钥")
            return

        alg = pk.get(3)
        if alg != COSE_ES256:
            report.skip("§6.2", "ECDSA 签名验证",
                        f"仅实现 ES256 验签，设备用 alg={alg}")
            return

        x = pk.get(-2)
        y = pk.get(-3)
        if not (isinstance(x, bytes) and isinstance(y, bytes)):
            report.add("§6.2", "COSE 公钥含 x(-2)/y(-3)", False, f"{pk!r}")
            return

        pn = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
        )
        public_key = pn.public_key()

        signed = auth_data + challenge          # §6.2：authData || clientDataHash
        try:
            # 我们的固件输出 DER（SK_SIG_DER=1）；规范是 raw r||s，两种都试
            public_key.verify(sig, signed, ec.ECDSA(hashes.SHA256()))
            report.add("§6.2", "ECDSA 签名验证通过（DER）", True)
        except Exception:                                       # noqa: BLE001
            try:
                r = int.from_bytes(sig[:32], "big")
                s = int.from_bytes(sig[32:], "big")
                der = utils.encode_dss_signature(r, s)
                public_key.verify(der, signed, ec.ECDSA(hashes.SHA256()))
                report.add("§6.2", "ECDSA 签名验证通过（raw r||s）", True)
            except Exception as e:                              # noqa: BLE001
                report.add("§6.2", "ECDSA 签名验证通过", False, repr(e))
    except Exception as e:                                      # noqa: BLE001
        report.add("§6.2", "ECDSA 签名验证", False, repr(e))


async def scan_only():
    print("扫描中（8 秒）...")
    found = await BleakScanner.discover(timeout=8.0, return_adv=True)
    hit = 0
    for dev, adv in found.values():
        uuids = [str(u).lower() for u in (adv.service_uuids or [])]
        if (dev.name or "") == DEVICE_NAME or FIDO_SERVICE_UUID in uuids:
            hit += 1
            print(f"  {dev.address}  [{dev.name}]")
            print(f"    广播服务: {adv.service_uuids}")
            for k, v in (adv.service_data or {}).items():
                if str(k).lower() == FIDO_SERVICE_UUID:
                    print(f"    Service Data = {bytes(v).hex(' ').upper()}")
                    flags = bytes(v)[0] if v else 0
                    print(f"    bit7（配对模式）= {1 if flags & 0x80 else 0}")
    if not hit:
        print(f"  未发现 {DEVICE_NAME}")
    return 0 if hit else 1


def main():
    ap = argparse.ArgumentParser(
        description="按 CTAP 2.1 规范逐条测试 BLE 认证器（一致性测试）")
    ap.add_argument("--addr", help="设备 MAC；省略则自动扫描")
    ap.add_argument("--scan", action="store_true", help="只扫描广播")
    ap.add_argument("--skip-rk", action="store_true",
                    help="跳过需要用户按键的 MakeCredential / GetAssertion")
    ap.add_argument("--cancel-up", action="store_true",
                    help="额外测 §11.4.8：发起必需 UP 的请求后立即 CANCEL，"
                         "期望收到 CTAP2_ERR_KEEPALIVE_CANCEL(0x2D)")
    args = ap.parse_args()

    try:
        if args.scan:
            return asyncio.run(scan_only())
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n已中断")
        return 130
    except OSError as e:
        # 实测最常见的是 0x800704C7 (ERROR_CANCELLED = -2147023673)：
        # Windows 蓝牙栈抢占链路 —— 设备是单连接外设，被系统栈占了就发不出写。
        # 不抛栈，给出可操作的提示 + 让已完成的条目留在上方输出里。
        print()
        print("=" * 70)
        print("链路中断（测试未跑完）")
        print("=" * 70)
        print(f"  {e!r}")
        print()
        print("  若含 0x800704C7 / ERROR_CANCELLED，说明 Windows 蓝牙栈占用了链路")
        print("  （本设备是单连接外设）。处理：")
        print("    1) Windows 设置 → 蓝牙和其他设备 → 删除 SecureKey")
        print("    2) 设备断电重上电，长按 PB4 进入配对模式")
        print("    3) 立刻重跑（不要让系统先连上）")
        print()
        print("  已完成的条目见上方输出。")
        return 2
    except Exception as e:                                  # noqa: BLE001
        print()
        print("=" * 70)
        print("未预期的异常（测试未跑完）")
        print("=" * 70)
        print(f"  {e!r}")
        print()
        print("  已完成的条目见上方输出。")
        return 3


if __name__ == "__main__":
    sys.exit(main())
