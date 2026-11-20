"""
NTAG 424 DNA SUN(Secure Unique NFC) 암호화 코어
- AES-128 CMAC, 키 파생, PICC 데이터 복호화, SDM MAC 계산/검증
- 칩 발급(provision.py), 검증 서버(server.py), 시뮬레이터(simulate.py)가 공통으로 사용
참고: NXP AN12196 (NTAG 424 DNA features and hints)
"""
import os
import struct
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ZERO_KEY = bytes(16)
PICC_TAG = 0xC7  # UID 미러링 + 카운터 미러링 + UID 길이 7


# ---------- 기본 AES 연산 ----------
def aes_cmac(key: bytes, data: bytes) -> bytes:
    c = CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(data) + e.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return d.update(data) + d.finalize()


def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(data) + e.finalize()


def truncate_mac(mac16: bytes) -> bytes:
    """NXP 방식 MAC 축약: 16바이트 중 홀수 번째(1,3,5..15) 바이트 8개"""
    return mac16[1::2]


# ---------- 키 파생 ----------
# K1(메타 읽기 키)은 모든 태그 공통: 서버가 UID를 알기 전에 복호화해야 하므로
# K0(관리 키), K2(MAC 키)는 태그 UID별로 파생 → 태그 하나가 털려도 다른 태그는 안전
def derive_keys(master_key: bytes, uid: bytes) -> dict:
    assert len(master_key) == 16 and len(uid) == 7
    return {
        0: aes_cmac(master_key, b"\x01" + b"GYEOL-K0" + uid),
        1: aes_cmac(master_key, b"\x02" + b"GYEOL-K1-SHARED"),
        2: aes_cmac(master_key, b"\x03" + b"GYEOL-K2" + uid),
    }


def shared_meta_key(master_key: bytes) -> bytes:
    return aes_cmac(master_key, b"\x02" + b"GYEOL-K1-SHARED")


# ---------- SUN 검증 ----------
def decrypt_picc(meta_key: bytes, picc_enc: bytes):
    """암호화된 PICC 데이터(16B) → (UID 7B, 읽기 카운터 int)"""
    plain = aes_cbc_decrypt(meta_key, bytes(16), picc_enc)
    if plain[0] != PICC_TAG:
        raise ValueError("PICC 태그 바이트 불일치 (키가 틀렸거나 위조된 값)")
    uid = plain[1:8]
    ctr = int.from_bytes(plain[8:11], "little")
    return uid, ctr


def sdm_session_mac_key(file_read_key: bytes, uid: bytes, ctr: int) -> bytes:
    sv2 = bytes.fromhex("3CC300010080") + uid + ctr.to_bytes(3, "little")
    return aes_cmac(file_read_key, sv2)


def calc_sdm_mac(file_read_key: bytes, uid: bytes, ctr: int, mac_input: bytes = b"") -> bytes:
    ks = sdm_session_mac_key(file_read_key, uid, ctr)
    return truncate_mac(aes_cmac(ks, mac_input))


def encrypt_picc(meta_key: bytes, uid: bytes, ctr: int, rand: bytes | None = None) -> bytes:
    """칩이 하는 일을 소프트웨어로 재현 (시뮬레이터용)"""
    rand = rand if rand is not None else os.urandom(5)
    plain = bytes([PICC_TAG]) + uid + ctr.to_bytes(3, "little") + rand
    return aes_cbc_encrypt(meta_key, bytes(16), plain)


def verify_sun(master_key: bytes, picc_hex: str, cmac_hex: str) -> dict:
    """서버에서 호출: URL 파라미터 → 검증 결과"""
    try:
        picc = bytes.fromhex(picc_hex)
        mac = bytes.fromhex(cmac_hex)
        if len(picc) != 16 or len(mac) != 8:
            raise ValueError("파라미터 길이 오류")
        uid, ctr = decrypt_picc(shared_meta_key(master_key), picc)
    except ValueError as e:
        return {"ok": False, "reason": str(e)}
    k2 = derive_keys(master_key, uid)[2]
    expected = calc_sdm_mac(k2, uid, ctr)
    if expected != mac:
        return {"ok": False, "reason": "서명(CMAC) 불일치 — 위조된 태그", "uid": uid.hex().upper(), "ctr": ctr}
    return {"ok": True, "uid": uid.hex().upper(), "ctr": ctr}
