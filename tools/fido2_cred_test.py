#!/usr/bin/env python3
"""
FIDOKey_CH583 真机测试 —— 注册与登录（对应测试清单 T4 / T5 / 超时）

用法:
    pip install fido2
    python tools/fido2_cred_test.py

过程中的关键交互:
    运行到注册/登录时，设备 LED 会**慢闪**表示正在等待用户确认 —— 此时按 PB4。
    若 15 秒内不按，应返回 ACTION_TIMEOUT(0x3A)；脚本最后会专门测这一项。

注意: python-fido2 各版本的参数名/返回类型略有差异（尤其是 rp/user 是否接受 dict、
      get_assertion 的返回形式）。脚本已做兼容处理，若仍报参数错误，
      请按你的版本调整，核心验证点（能否成功注册/登录）不受影响。
"""

import hashlib
import sys

try:
    from fido2.hid import CtapHidDevice
    from fido2.ctap2 import Ctap2
    from fido2.ctap import CtapError
except ImportError:
    print("缺少 python-fido2，请先执行: pip install fido2")
    sys.exit(2)


def first_assertion(sel):
    """从 get_assertion() 的返回值里取出第一条断言。

    python-fido2 各版本差别较大：可能是带 get_response() 的 AssertionSelection、
    带 assertions 列表的对象、普通 list，或在只有一条时直接返回该条。
    """
    if hasattr(sel, "get_response"):
        return sel.get_response(0)
    if hasattr(sel, "assertions"):
        return sel.assertions[0]
    if isinstance(sel, (list, tuple)):
        if not sel:
            raise ValueError("assertion 列表为空")
        return sel[0]
    if hasattr(sel, "auth_data"):
        return sel
    raise TypeError("无法从 %r 取出 assertion（类型 %s）" % (sel, type(sel).__name__))



def verify_assertion_signature(cose_key, auth_data, client_data_hash, signature):
    """用注册时的公钥验证登录签名（离线、独立于设备）。

    返回 (ok, detail)。

    签名格式自动识别：
      - 64 字节       -> CTAP2 规范的 raw r||s，需转成 ASN.1 DER 再验证
      - 0x30 开头     -> 已是 ASN.1 DER（本固件当前用 SK_SIG_DER=1，输出 DER）

    固件的开关见 src/ctap.c 的 SK_SIG_DER：DER 格式下浏览器可用，
    但 fido2 库会再转一次 DER，所以下面必须区分处理。
    """
    try:
        import hashlib
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature
    except ImportError as e:
        return None, "缺少 cryptography 库: %s" % e

    try:
        # COSE_Key -> 公钥坐标。python-fido2 的 CoseKey 支持按编号取值。
        x = cose_key[-2] if -2 in cose_key else cose_key.get(-2)
        y = cose_key[-3] if -3 in cose_key else cose_key.get(-3)
        if x is None or y is None:
            return None, "COSE key 缺少 x/y（键: %r）" % (list(cose_key.keys()),)

        pub = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
        ).public_key()

        msg = bytes(auth_data) + client_data_hash
        digest = hashlib.sha256(msg).digest()

        # 自动识别签名格式
        if len(signature) == 64:
            sig_kind = "raw r||s"
            r = int.from_bytes(signature[:32], "big")
            ss = int.from_bytes(signature[32:], "big")
            der = utils.encode_dss_signature(r, ss)
        elif len(signature) >= 2 and signature[0] == 0x30:
            sig_kind = "ASN.1 DER"
            der = signature
        else:
            return None, "无法识别的签名格式（长度 %d，首字节 0x%02X）" % (
                len(signature), signature[0] if signature else 0)

        try:
            pub.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            return True, "签名验证通过（输入 %s）" % sig_kind
        except InvalidSignature:
            return False, "签名验证失败（InvalidSignature）"
    except Exception as e:
        return None, "验证过程出错: %s: %s" % (type(e).__name__, e)


RP_ID = "test.local"
USER_ID = b"securekey-user-1"
TIMEOUT_CODE = 0x3A


def client_data_hash(tag):
    """真实场景是 SHA-256(clientData JSON)；这里只要 32 字节且每次不同即可。"""
    return hashlib.sha256(("securekey-selftest:" + tag).encode()).digest()


def main():
    devs = list(CtapHidDevice.list_devices())
    if not devs:
        print("未发现设备")
        return 1
    ctap2 = Ctap2(devs[0])

    # ---------------- T4 注册 ----------------
    print("=" * 60)
    print("[T4] MakeCredential —— LED 慢闪时请按 PB4")
    print("=" * 60)
    cred_id = None
    try:
        # python-fido2 各版本返回值个数不同（2 个或多个），统一取前两个
        result = ctap2.make_credential(
            client_data_hash=client_data_hash("reg"),
            rp={"id": RP_ID, "name": "SecureKey Test"},
            user={"id": USER_ID, "name": "user1", "displayName": "Test User"},
            key_params=[{"type": "public-key", "alg": -7}],
            options={"rk": False, "uv": False},
        )
        # 新版 python-fido2 返回 AttestationResponse 对象；旧版返回 (att, auth_data)
        if isinstance(result, tuple) and len(result) >= 2:
            att, auth_data = result[0], result[1]
        elif hasattr(result, "auth_data"):
            att, auth_data = result, result.auth_data
        else:
            print("  [WARN] make_credential 返回了意外的类型: %r" % (result,))
            return 2
    except CtapError as e:
        code = getattr(e, "code", None)
        print("  [FAIL] 注册失败: %s" % e)
        if code == 0x2B:
            print("         -> 0x2B 表示请求了可驻留凭证(rk=True)，本实现不支持，属预期行为")
        elif code == TIMEOUT_CODE:
            print("         -> 0x3A 表示没在 15 秒内按 PB4")
        return 1
    except TypeError as e:
        print("  [SKIP] 调用参数与当前 python-fido2 版本不匹配: %s" % e)
        print("         请按你安装的版本调整 rp/user 的写法后重跑")
        return 2

    cred_id = auth_data.credential_data.credential_id
    reg_pubkey = auth_data.credential_data.public_key
    reg_authdata = bytes(auth_data)
    print("  [PASS] 注册成功")
    print("         fmt        : %s" % att.fmt)
    print("         credId 长度: %d" % len(cred_id))
    print("         signCount  : %d" % auth_data.counter)
    print("         UP 标志    : %s  (应为 True，说明确实按了键)" % bool(auth_data.flags & 0x01))
    print("         AT 标志    : %s  (应为 True，说明带 attested 数据)" % bool(auth_data.flags & 0x40))
    if not (auth_data.flags & 0x01):
        print("  [WARN] UP 位没置位 —— 说明没有真正取得用户确认")
    print()

    # ---------------- T5 登录 ----------------
    print("=" * 60)
    print("[T5] GetAssertion —— 再次请在 LED 慢闪时按 PB4")
    print("=" * 60)
    try:
        sel = ctap2.get_assertion(
            rp_id=RP_ID,
            client_data_hash=client_data_hash("auth"),
            allow_list=[{"type": "public-key", "id": cred_id}],
        )
    except CtapError as e:
        print("  [FAIL] 登录失败: %s" % e)
        return 1
    except TypeError as e:
        print("  [SKIP] 参数与当前版本不匹配: %s" % e)
        return 2

    auth_client_data_hash = client_data_hash("auth")
    try:
        a = first_assertion(sel)
    except Exception as ex:
        print("  [SKIP] 无法解析 assertion 返回值: %s" % ex)
        print("         sel 类型 = %s" % type(sel).__name__)
        return 2
    print("  [PASS] 登录成功")
    print("         signCount  : %d" % a.auth_data.counter)
    print("         UP 标志    : %s" % bool(a.auth_data.flags & 0x01))

    # 离线验证签名：用注册时的公钥验证登录签名
    ok, detail = verify_assertion_signature(
        reg_pubkey, a.auth_data, auth_client_data_hash, bytes(a.signature))
    print("         签名验证    : %s  (%s)" % (
        "通过" if ok is True else ("失败" if ok is False else "无法验证"), detail))
    print("         与注册时的差值应为 1（每成功登录一次 +1）")
    print()

    # ---------------- 超时路径 ----------------
    print("=" * 60)
    print("[T4-超时] 再注册一次但故意不按键，期望 ACTION_TIMEOUT(0x3A)")
    print("=" * 60)
    print("  现在开始等待，请不要按按键……")
    try:
        ctap2.make_credential(
            client_data_hash=client_data_hash("timeout"),
            rp={"id": RP_ID, "name": "SecureKey Test"},
            user={"id": b"timeout-user", "name": "u", "displayName": "u"},
            key_params=[{"type": "public-key", "alg": -7}],
            options={"rk": False, "uv": False},
        )
        print("  [FAIL] 居然成功了 —— 说明设备没有等待用户按键")
        return 1
    except CtapError as e:
        code = getattr(e, "code", None)
        if code == TIMEOUT_CODE:
            print("  [PASS] 按预期超时 (0x3A)，说明 UP 等待生效")
        else:
            print("  [WARN] 确实失败了，但错误码是 %s（期望 0x3A）" % (hex(code) if code else e))
    except TypeError as e:
        print("  [SKIP] 参数与当前版本不匹配: %s" % e)

    print()
    print("全部检查完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
