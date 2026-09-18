# -*- coding: utf-8 -*-
"""
FIDO BLE GATT 客户端验证脚本（基于 bleak）

用途：绕过浏览器/Android 的 FIDO 集成，直接用标准 GATT 客户端按
CTAP 2.1 规范 §11.4.6 的流程操作设备，从而判定"设备侧是否完整可用"。

    Client performs characteristic discovery
    Client checks if fidoServiceRevisionBitfield is present
        -> If so, writes a value with a single bit set
    Client reads fidoControlPointLength
    Client registers for notifications on fidoStatus
    Client writes a request into fidoControlPoint

与 nRF Connect 手工测试的区别：这里是脚本化的、可重复的，而且带超时与
逐帧校验，能把"设备没响应"和"响应格式不对"分开。

依赖：
    pip install bleak

用法：
    1. 长按设备按键 5 秒进入配对模式（串口应出现 pairing mode ON）
    2. python tools/ble_gatt_client.py            # 自动扫描并连接
       python tools/ble_gatt_client.py --scan     # 只扫描，列出设备

注意：Windows 上首次连接会触发系统配对，可能需要几秒。
"""

import argparse
import asyncio
import struct
import sys
import time

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    print("缺少依赖：pip install bleak")
    sys.exit(1)

# ---- FIDO GATT（CTAP 2.1 §11.4.5）----
SERVICE_UUID = "0000fffd-0000-1000-8000-00805f9b34fb"
CP_UUID = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb"   # fidoControlPoint   Write
STATUS_UUID = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb"   # fidoStatus         Notify
CP_LEN_UUID = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb"   # fidoControlPointLength  Read
BITFIELD_UUID = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb"  # fidoServiceRevisionBitfield

# ---- FIDO BLE 封装（与本项目 ble_transport.c 保持一致）----
CMD_PING = 0x81
CMD_MSG = 0x83
CMD_KEEPALIVE = 0x82
CMD_CANCEL = 0xBE
CMD_ERROR = 0xBF

DEVICE_NAME_HINT = "SecureKey"


# --------------------------------------------------------------------------
# 帧收发
# --------------------------------------------------------------------------

class FidoBleLink:
    """把 GATT 的写/通知包装成 FIDO BLE 帧的收发。"""

    def __init__(self, client, cp_uuid, status_uuid):
        self.client = client
        self.cp_uuid = cp_uuid
        self.status_uuid = status_uuid

        self._rx = bytearray()      # 当前正在拼装的帧载荷
        self._rx_cmd = 0
        self._rx_len = 0            # 帧头声明的载荷总长
        self._rx_have = 0           # 已收载荷字节数
        self._frames = asyncio.Queue()

    def on_notify(self, _handle, data: bytearray):
        if not data:
            return
        b0 = data[0]

        if b0 & 0x80:
            # 初始帧：[CMD|0x80][HLEN][LLEN][DATA...]
            if len(data) < 3:
                print("  帧头不足 3 字节:", data.hex())
                return
            self._rx_cmd = b0
            self._rx_len = (data[1] << 8) | data[2]
            self._rx = bytearray(data[3:])
            self._rx_have = len(self._rx)
        else:
            # 续帧：[SEQ][DATA...]（SEQ 从 0 开始，高位为 0）
            self._rx += data[1:]
            self._rx_have = len(self._rx)

        if self._rx_have >= self._rx_len:
            payload = bytes(self._rx[: self._rx_len])
            self._frames.put_nowait((self._rx_cmd, payload))
            self._rx = bytearray()
            self._rx_have = 0
            self._rx_len = 0

    async def recv(self, timeout=5.0):
        return await asyncio.wait_for(self._frames.get(), timeout)

    async def write_frame(self, cmd: int, payload: bytes):
        """按 MTU 分片写入 fidoControlPoint。"""
        mtu = getattr(self.client, "mtu_size", None) or 23
        assert cmd & 0x80, "命令码 bit7 必须为 1"
        assert len(payload) <= 0xFFFF

        frame = bytes([cmd, len(payload) >> 8, len(payload) & 0xFF]) + payload
        # 初始帧容量 = MTU-3（ATT 头）；续帧容量 = MTU-4（多一个 SEQ 字节）
        first = mtu - 3
        cont = mtu - 4

        chunk = frame[:first]
        await self.client.write_gatt_char(self.cp_uuid, chunk, response=True)

        rest = frame[first:]
        seq = 0
        while rest:
            piece = bytes([seq & 0x7F]) + rest[:cont]
            await self.client.write_gatt_char(self.cp_uuid, piece, response=True)
            rest = rest[cont:]
            seq += 1

    async def request(self, cmd: int, payload: bytes, timeout=5.0):
        """发一个命令并等**真正的响应**。

        ★ 必须跳过 KEEPALIVE(0x82)。设备在等待用户按确认(UP)期间会按
        §11.4.9 每 500ms 发一次保活帧，载荷是 1 字节状态：
            0x01 PROCESSING —— 处理中
            0x02 UP_NEEDED  —— 等用户按键
        这些**不是命令响应**。旧实现直接返回收到的第一帧，于是把
        KEEPALIVE(UP_NEEDED) 当成了 CTAP 状态码 0x02 报错 ——
        实测 MakeCredential 因此被误判为"状态=0x02 失败"，
        而设备其实已正确进入等待确认状态。
        """
        await self.write_frame(cmd, payload)
        deadline = time.monotonic() + timeout
        hinted = False
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise asyncio.TimeoutError()
            got_cmd, got = await self.recv(left)
            if got_cmd == CMD_KEEPALIVE:
                st = got[0] if got else 0
                if st == 0x02 and not hinted:
                    hinted = True
                    print("    （设备在等用户确认 —— 请按住 PB4 按键）")
                continue
            if got_cmd == CMD_ERROR:
                # 封装层错误帧（CTAP 2.1 §11.4.4.2）：DATA 是错误码，不是 CTAP 状态。
                # 同样不能当成命令响应用。
                ec = got[0] if got else 0
                ename = {0x01: "ERR_INVALID_CMD", 0x02: "ERR_INVALID_PAR",
                         0x03: "ERR_INVALID_LEN", 0x04: "ERR_INVALID_SEQ",
                         0x05: "ERR_REQ_TIMEOUT", 0x06: "ERR_BUSY",
                         0x7F: "ERR_OTHER"}.get(ec, "?")
                print("    （设备回 ERROR 帧：0x%02X %s）" % (ec, ename))
                return got_cmd, got
            return got_cmd, got


# --------------------------------------------------------------------------
# 检查项
# --------------------------------------------------------------------------

async def find_device(scan_only=False):
    print("扫描中（5 秒）...")
    devices = await BleakScanner.discover(timeout=5.0, return_adv=True)
    found = []
    for dev, adv in devices.values():
        name = adv.local_name or dev.name or ""
        svc = [str(u).lower() for u in (adv.service_uuids or [])]
        if DEVICE_NAME_HINT.lower() in name.lower() or SERVICE_UUID in svc:
            found.append((dev, adv, name, svc))

    if not found:
        print("  未找到设备。请确认：")
        print("    - 设备已上电并在广播")
        print("    - 已长按按键 5 秒进入配对模式")
        return None

    for dev, adv, name, svc in found:
        print("  发现: %s  [%s]" % (dev.address, name))
        print("    广播服务: %s" % (svc or "(无)"))
        sd = adv.service_data or {}
        for u, d in sd.items():
            print("    Service Data %s = %s" % (u, bytes(d).hex(" ").upper()))
        mfg = adv.manufacturer_data or {}
        for k, v in mfg.items():
            print("    厂商数据 0x%04X = %s" % (k, bytes(v).hex(" ").upper()[:64]))

    if scan_only:
        return None
    return found[0][0]


async def run(address=None):
    dev = None
    if address:
        dev = address
    else:
        dev = await find_device()
        if dev is None:
            return 1

    print("\n连接 %s ..." % dev)
    async with BleakClient(dev, timeout=20.0) as client:
        print("  已连接，MTU（GATT 层）= %s" % getattr(client, "mtu_size", "?"))

        link = FidoBleLink(client, CP_UUID, STATUS_UUID)

        # ---- 1. 特征发现 ----
        print("\n[1] 特征发现")
        want = {
            CP_UUID: "fidoControlPoint",
            STATUS_UUID: "fidoStatus",
            CP_LEN_UUID: "fidoControlPointLength",
            BITFIELD_UUID: "fidoServiceRevisionBitfield",
        }
        svc = client.services.get_service(SERVICE_UUID)
        if svc is None:
            print("  ✗ 找不到 FIDO 服务 %s" % SERVICE_UUID)
            return 1
        have = {str(c.uuid).lower(): c for c in svc.characteristics}
        for u, label in want.items():
            c = have.get(u)
            if c:
                print("  ✓ %-28s props=%s" % (label, c.properties))
            else:
                print("  ✗ %-28s 缺失" % label)
        if len(have) < 4:
            print("  特征数量不足，终止")
            return 1

        # ---- 2. fidoServiceRevisionBitfield ----
        print("\n[2] 版本位（规范：读，然后写恰好 1 位）")
        rev = await client.read_gatt_char(BITFIELD_UUID)
        print("  读 = %s" % rev.hex(" ").upper())
        if not rev or not (rev[0] & 0x20):
            print("  ✗ 未声明支持 FIDO2（bit5）")
            return 1
        try:
            await client.write_gatt_char(BITFIELD_UUID, bytes([0x20]), response=True)
            print("  写 0x20 = 成功")
        except Exception as e:
            print("  ✗ 写失败: %r" % e)
            return 1
        again = await client.read_gatt_char(BITFIELD_UUID)
        print("  回读 = %s" % again.hex(" ").upper())

        # ---- 3. fidoControlPointLength ----
        print("\n[3] fidoControlPointLength")
        raw = await client.read_gatt_char(CP_LEN_UUID)
        cp_len = struct.unpack("<H", raw)[0] if len(raw) == 2 else None
        print("  读 = %s -> %s" % (raw.hex(" ").upper(), cp_len))
        if cp_len is None or not (20 <= cp_len <= 512):
            print("  ✗ 值不在规范范围 20-512")
            return 1

        # ---- 4. 订阅 fidoStatus ----
        print("\n[4] 订阅 fidoStatus 通知")
        await client.start_notify(STATUS_UUID, link.on_notify)
        print("  已订阅")

        # ---- 5. PING ----
        print("\n[5] PING（回显，验证封装层）")
        try:
            cmd, payload = await link.request(CMD_PING, b"PING", timeout=5.0)
            print("  收到 cmd=0x%02X payload=%s" % (cmd, payload))
            ok = (cmd == CMD_PING and payload == b"PING")
            print("  %s" % ("✓ 回显正确" if ok else "✗ 回显不符"))
        except asyncio.TimeoutError:
            print("  ✗ 超时（没有收到通知）")
            return 1

        # ---- 6. GetInfo ----
        print("\n[6] GetInfo（MSG 通路 + CTAP2 解析）")
        try:
            cmd, payload = await link.request(CMD_MSG, bytes([0x04, 0xA0]), timeout=10.0)
        except asyncio.TimeoutError:
            print("  ✗ 超时")
            return 1
        print("  收到 cmd=0x%02X len=%d" % (cmd, len(payload)))
        print("  原始: %s" % payload.hex(" ").upper())
        if payload and payload[0] == 0x00:
            print("  ✓ CTAP 状态 = 成功")
            print("  CBOR: %s" % payload[1:].hex(" ").upper())
            # 简易解码：找 "FIDO_2_0"
            if b"FIDO_2_0" in payload:
                print("  ✓ 声明支持 FIDO_2_0")
        else:
            print("  ✗ CTAP 状态 = 0x%02X" % (payload[0] if payload else -1))
            return 1

        # ---- 7. MakeCredential（UP 闸门 + 分片发送 + 写 Flash）----
        print("\n[7] MakeCredential（注册流程）")
        print("    需要用户确认 —— 请按住 PB4 按键（LED 应慢闪）")

        cdh = bytes(range(32))                      # clientDataHash（内容随意）
        rp_id = b"example.com"
        user_id = bytes(range(16))
        req = bytearray()
        req += bytes([0x01])                        # authenticatorMakeCredential
        req += bytes([0xA4])                        # map(4)
        req += bytes([0x01, 0x58, 0x20]) + cdh      # 1: clientDataHash
        # 注意：顶层键是整数，但内层 map 的键是**文本**
        # （CTAP 2.1 §6.1；写成整数键会被 ctap.c 判为 INVALID_CBOR 0x12）
        req += bytes([0x02, 0xA2])                  # 2: rp
        req += bytes([0x62]) + b"id"                #    "id": "example.com"
        req += bytes([0x6B]) + rp_id
        req += bytes([0x64]) + b"name"              #    "name": "Example"
        req += bytes([0x67]) + b"Example"
        req += bytes([0x03, 0xA3])                  # 3: user
        req += bytes([0x62]) + b"id"                #    "id": h'..'
        req += bytes([0x50]) + user_id
        req += bytes([0x64]) + b"name"              #    "name": "u"
        req += bytes([0x61]) + b"u"
        req += bytes([0x6B]) + b"displayName"       #    "displayName": "U"
        req += bytes([0x61]) + b"U"
        req += bytes([0x04, 0x81])                  # 4: pubKeyCredParams array(1)
        req += bytes([0xA2])                        #    map(2)
        req += bytes([0x63]) + b"alg"               #    "alg": -7 (ES256)
        req += bytes([0x26])
        req += bytes([0x64]) + b"type"              #    "type": "public-key"
        req += bytes([0x6A]) + b"public-key"
        print("    CTAP 消息 %d 字节，封装后 %d 字节" % (len(req), len(req) + 3))

        try:
            cmd, payload = await link.request(CMD_MSG, bytes(req), timeout=30.0)
        except asyncio.TimeoutError:
            print("  ✗ 超时（若未按键，请按住 PB4 后重试）")
            return 1
        print("  收到 cmd=0x%02X len=%d" % (cmd, len(payload)))
        print("  原始: %s" % payload.hex(" ").upper())
        if not payload:
            print("  ✗ 空响应")
            return 1
        if payload[0] == 0x00:
            print("  ✓ CTAP 状态 = 成功（凭证已创建）")
            print("  CBOR: %s" % payload[1:].hex(" ").upper())
            if len(payload) > 40:
                print("  ✓ 响应 %d 字节 —— 多帧通知发送路径已验证" % len(payload))
        else:
            print("  ✗ CTAP 状态 = 0x%02X" % payload[0])
            return 1

        # ---- 8. GetAssertion（验证凭证确实落盘）----
        print("\n[8] GetAssertion（认证流程）")
        print("    同样需要按住 PB4")
        req2 = bytearray()
        req2 += bytes([0x02])                       # authenticatorGetAssertion
        req2 += bytes([0xA2])                       # map(2)
        req2 += bytes([0x01, 0x6B]) + rp_id         # 1: rpId
        req2 += bytes([0x02, 0x58, 0x20]) + cdh     # 2: clientDataHash
        try:
            cmd, payload = await link.request(CMD_MSG, bytes(req2), timeout=30.0)
        except asyncio.TimeoutError:
            print("  ✗ 超时")
            return 1
        print("  收到 cmd=0x%02X len=%d" % (cmd, len(payload)))
        if payload and payload[0] == 0x00:
            print("  ✓ CTAP 状态 = 成功（找到了上一步写入的凭证）")
            print("  CBOR: %s" % payload[1:].hex(" ").upper())
        elif payload and payload[0] == 0x2E:
            print("  ✗ 0x2E NO_CREDENTIALS —— 上一步的凭证没找到")
            return 1
        else:
            print("  ✗ CTAP 状态 = 0x%02X" % (payload[0] if payload else -1))
            return 1

        print("\n全部通过 —— 设备侧对标准 GATT 客户端完整可用。")
        print("若浏览器仍失败，问题在客户端的 FIDO-BLE 集成，而非设备。")
        await client.stop_notify(STATUS_UUID)
    return 0


def main():
    ap = argparse.ArgumentParser(description="FIDO BLE GATT 客户端验证")
    ap.add_argument("--scan", action="store_true", help="只扫描不连接")
    ap.add_argument("--address", help="直接连接指定 MAC/UUID")
    args = ap.parse_args()

    async def _main():
        if args.scan:
            await find_device(scan_only=True)
            return 0
        return await run(args.address)

    try:
        sys.exit(asyncio.run(_main()))
    except KeyboardInterrupt:
        print("\n已中断")


if __name__ == "__main__":
    main()
