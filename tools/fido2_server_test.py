#!/usr/bin/env python3
"""
服务端视角的完整 FIDO2 验证（注册 + 登录）。

用途：定位"设备签名验证通过、但网站报签名错误"这类问题。
它用 fido2 自带的 Fido2Server 扮演服务端，走完 register_complete /
authenticate_complete 两个验证步骤，从而复现网站侧的判定。

与 fido2_cred_test.py 的区别：
  - fido2_cred_test.py 只验"签名对不对"（用注册的公钥验证登录签名）
  - 本脚本验"服务端能不能接受"（含 rpIdHash、challenge、origin、userHandle 等）

必须用管理员权限运行（Windows 的 FIDO 驱动独占设备）。

用法:
    # 以管理员身份打开 PowerShell
    python tools\\fido2_server_test.py
"""

import base64
import hashlib
import json
import sys
import traceback

try:
    from fido2.server import Fido2Server
    from fido2.webauthn import (
        PublicKeyCredentialRpEntity,
        PublicKeyCredentialUserEntity,
    )
    from fido2.hid import CtapHidDevice
    from fido2.ctap2 import Ctap2
    from fido2 import cbor
except ImportError:
    print("缺少 python-fido2，请先执行: pip install fido2")
    sys.exit(2)

RP_ID = "test.local"
ORIGIN = "https://test.local"


def b64(b):
    return base64.urlsafe_b64encode(bytes(b)).decode().rstrip("=")


def main():
    devs = list(CtapHidDevice.list_devices())
    print("发现 %d 个 CTAPHID 设备" % len(devs))
    if not devs:
        print("未发现设备：请用【管理员权限】运行（Windows 的 FIDO 驱动会独占设备）")
        return 1

    ctap2 = Ctap2(devs[0])
    server = Fido2Server(PublicKeyCredentialRpEntity(id=RP_ID, name="Test RP"))
    user = PublicKeyCredentialUserEntity(id=b"user-1", name="user1", display_name="User 1")

    # ---------------- 注册 ----------------
    print()
    print("=" * 60)
    print("[注册] LED 慢闪时请按 PB4")
    print("=" * 60)

    opts, state = server.register_begin(user)
    cdj = json.dumps({
        "type": "webauthn.create",
        "challenge": b64(opts.public_key.challenge),
        "origin": ORIGIN,
    }, separators=(",", ":")).encode()
    cdh = hashlib.sha256(cdj).digest()

    try:
        result = ctap2.make_credential(
            client_data_hash=cdh,
            rp={"id": RP_ID, "name": "Test RP"},
            user={"id": b"user-1", "name": "user1", "displayName": "User 1"},
            key_params=[{"type": "public-key", "alg": -7}],
            options={"rk": False, "uv": False},
        )
    except Exception as e:
        print("设备侧注册失败:", type(e).__name__, e)
        return 1

    # 兼容不同版本：新版返回 AttestationResponse 对象，旧版返回 (att, auth_data)
    if isinstance(result, tuple) and len(result) >= 2:
        att, auth_data = result[0], result[1]
    elif hasattr(result, "auth_data"):
        att, auth_data = result, result.auth_data
    else:
        print("make_credential 返回了意外的类型: %r" % (result,))
        return 2

    # 组装 attestationObject。
    # 注意：这里要用 WebAuthn(JSON) 的文本键，而不是 CTAP2 响应的整数键 ——
    # 后者是设备与主机之间的编码，主机负责把它转成 WebAuthn 的 attestationObject。
    att_obj = cbor.encode({
        "fmt": att.fmt,
        "authData": bytes(att.auth_data),
        "attStmt": att.att_stmt,
    })

    cred_id = auth_data.credential_data.credential_id
    try:
        cred = server.register_complete(state, {
            "id": b64(cred_id),
            "rawId": b64(cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(cdj),
                "attestationObject": b64(att_obj),
            },
        })
        print("注册(服务端验证): 通过")
        cred_data = cred.credential_data
    except Exception as e:
        print("注册(服务端验证): 失败 ->", type(e).__name__, e)
        traceback.print_exc()
        return 1

    # ---------------- 登录 ----------------
    print()
    print("=" * 60)
    print("[登录] LED 慢闪时请按 PB4")
    print("=" * 60)

    opts2, state2 = server.authenticate_begin([cred_data])
    cdj2 = json.dumps({
        "type": "webauthn.get",
        "challenge": b64(opts2.public_key.challenge),
        "origin": ORIGIN,
    }, separators=(",", ":")).encode()
    cdh2 = hashlib.sha256(cdj2).digest()

    try:
        sel = ctap2.get_assertion(
            rp_id=RP_ID,
            client_data_hash=cdh2,
            allow_list=[{"type": "public-key", "id": cred_data.credential_id}],
        )
    except Exception as e:
        print("设备侧登录失败:", type(e).__name__, e)
        return 1

    if hasattr(sel, "get_response"):
        a = sel.get_response(0)
    elif hasattr(sel, "assertions"):
        a = sel.assertions[0]
    elif isinstance(sel, (list, tuple)):
        a = sel[0]
    else:
        a = sel

    user_handle = None
    try:
        if getattr(a, "user", None):
            user_handle = b64(a.user["id"] if isinstance(a.user, dict) else a.user.id)
    except Exception:
        user_handle = None

    # ---- 调试：把两端用于验证的输入都打出来 ----
    from fido2.webauthn import CollectedClientData
    from cryptography.hazmat.primitives.asymmetric import ec, utils as cu
    from cryptography.hazmat.primitives import hashes as ch
    from cryptography.exceptions import InvalidSignature as ISig

    ccd = CollectedClientData(cdj2)
    print()
    print("---- 验证输入对比 ----")
    print("  我构造的 clientDataHash :", cdh2.hex()[:32], "...")
    print("  fido2 算出的 hash       :", ccd.hash.hex()[:32], "...")
    print("  两者一致                :", ccd.hash == cdh2)
    print("  authData 长度           :", len(bytes(a.auth_data)))
    _siglen = len(bytes(a.signature))
    _sigkind = "raw r||s" if _siglen == 64 else (
        "ASN.1 DER" if bytes(a.signature)[:1] == b"0" else "未知")
    print("  signature 长度          :", _siglen, "(%s)" % _sigkind)
    print("  设备返回的 userHandle   :", user_handle)
    print("  authData[32] (flags)    :", hex(bytes(a.auth_data)[32]))
    print("  authData[33:37] (count) :", bytes(a.auth_data)[33:37].hex())

    try:
        k = cred_data.public_key
        x = k[-2]; y = k[-3]
        pub = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"),
            ec.SECP256R1()).public_key()
        digest = __import__("hashlib").sha256(bytes(a.auth_data) + cdh2).digest()
        sig = bytes(a.signature)
        if len(sig) == 64:
            der = cu.encode_dss_signature(
                int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        elif sig[:1] == b"0":
            der = sig                       # 已是 DER
        else:
            raise ValueError("无法识别的签名格式：长度 %d" % len(sig))
        pub.verify(der, digest, ec.ECDSA(cu.Prehashed(ch.SHA256())))
        print("  手工验证(Prehashed)     : 通过")
    except ISig:
        print("  手工验证(Prehashed)     : 失败 InvalidSignature")
    except Exception as e:
        print("  手工验证(Prehashed)     : 异常 %s: %s" % (type(e).__name__, e))

    try:
        cred_data.public_key.verify(bytes(a.auth_data) + ccd.hash, bytes(a.signature))
        print("  fido2 CoseKey.verify    : 通过")
    except ISig:
        print("  fido2 CoseKey.verify    : 失败 InvalidSignature")
    except Exception as e:
        print("  fido2 CoseKey.verify    : 异常 %s: %s" % (type(e).__name__, e))
    print("---- 对比结束 ----")
    print()

    # 服务端期望 ASN.1 DER。本固件当前用 SK_SIG_DER=1 直接输出 DER，
    # 此时原样传递即可；若切回 SK_SIG_DER=0（规范 raw），则需在这里手工转换。
    # （真实浏览器的表现见《详细软件开发计划》5.2.3：本平台上主机不做转换。）
    from cryptography.hazmat.primitives.asymmetric import utils as _cu
    _sig = bytes(a.signature)
    if len(_sig) == 64:
        _der = _cu.encode_dss_signature(
            int.from_bytes(_sig[:32], "big"), int.from_bytes(_sig[32:], "big"))
    else:
        _der = _sig     # 已经是 DER

    try:
        server.authenticate_complete(state2, [cred_data], {
            "id": b64(cred_data.credential_id),
            "rawId": b64(cred_data.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(cdj2),
                "authenticatorData": b64(bytes(a.auth_data)),
                "signature": b64(_der),
                "userHandle": user_handle,
            },
        })
        print("登录(服务端验证): 通过")
        print()
        print("=> 设备与服务端交互完全正确。")
        print("   若浏览器仍报签名错误，问题在网站侧（challenge/origin 处理），不在设备。")
        return 0
    except Exception as e:
        print("登录(服务端验证): 失败 ->", type(e).__name__, e)
        traceback.print_exc()
        print()
        print("=> 服务端不接受这个响应，失败原因见上。")
        return 1


if __name__ == "__main__":
    sys.exit(main())
