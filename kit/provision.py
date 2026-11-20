"""
NTAG 424 DNA 칩 발급 프로그램
- 리더기(ACR122U 등)에 새 칩을 올리고 실행하면:
  1) UID 읽기 → 2) 인증 URL(NDEF) 기록 → 3) 키 0으로 EV2 인증
  4) SUN(SDM) 설정 → 5) K1, K2 변경 → 6) K0 변경(마지막) → 7) 태그 DB 등록

사용법:
  python provision.py genkey                       # 마스터 키 생성 (최초 1회)
  python provision.py write --name "나전 손거울" --artist "김선애"
  python provision.py write --sim ...              # 칩 없이 에뮬레이터로 테스트
"""
import argparse
import os
import sqlite3
import sys
import zlib

from crypto_core import (ZERO_KEY, aes_cmac, aes_cbc_encrypt, aes_cbc_decrypt,
                         aes_ecb_encrypt, truncate_mac, derive_keys)

AID = bytes.fromhex("D2760000850101")
DB_PATH = os.environ.get("NTAG_DB", "tags.db")
BASE_URL = os.environ.get("NTAG_BASE_URL", "https://bohemiansalt82.github.io/ntag424-dna/v/")
PICC_PH, MAC_PH = "0" * 32, "0" * 16


class CardError(Exception):
    pass


# ---------- 리더기 연결 ----------
class PCSCTransport:
    def __init__(self):
        try:
            from smartcard.System import readers
        except ImportError:
            sys.exit("pyscard가 필요합니다:  pip install pyscard")
        rs = readers()
        if not rs:
            sys.exit("리더기를 찾을 수 없습니다. USB 연결과 드라이버를 확인하세요.")
        print(f"리더기: {rs[0]}")
        self.conn = rs[0].createConnection()
        self.conn.connect()

    def transmit(self, apdu: bytes) -> bytes:
        data, sw1, sw2 = self.conn.transmit(list(apdu))
        return bytes(data) + bytes([sw1, sw2])


# ---------- NTAG 424 DNA 명령 ----------
class Ntag424:
    def __init__(self, t):
        self.t = t
        self.sess = None

    def _x(self, apdu, ok=(b"\x90\x00", b"\x91\x00")):
        r = self.t.transmit(apdu)
        if r[-2:] not in ok:
            raise CardError(f"명령 실패 SW={r[-2:].hex().upper()} (APDU {apdu[:2].hex().upper()})")
        return r[:-2], r[-2:]

    def get_uid(self) -> bytes:
        uid, _ = self._x(b"\xFF\xCA\x00\x00\x00")
        if len(uid) != 7:
            raise CardError(f"UID 길이가 7이 아님({len(uid)}) — NTAG 424 DNA가 맞는지 확인")
        return uid

    def select_app(self):
        self._x(b"\x00\xA4\x04\x00\x07" + AID + b"\x00")
        self.sess = None

    def write_ndef(self, ndef_file: bytes):
        self._x(b"\x00\xA4\x00\x0C\x02\xE1\x04")
        for off in range(0, len(ndef_file), 48):
            chunk = ndef_file[off:off + 48]
            self._x(bytes([0x00, 0xD6, off >> 8, off & 0xFF, len(chunk)]) + chunk)

    def auth_ev2_first(self, kno: int, key: bytes):
        r, _ = self._x(bytes([0x90, 0x71, 0, 0, 2, kno, 0, 0]), ok=(b"\x91\xAF",))
        rndb = aes_cbc_decrypt(key, bytes(16), r)
        rnda = os.urandom(16)
        msg = aes_cbc_encrypt(key, bytes(16), rnda + rndb[1:] + rndb[:1])
        r, _ = self._x(b"\x90\xAF\x00\x00\x20" + msg + b"\x00", ok=(b"\x91\x00",))
        p = aes_cbc_decrypt(key, bytes(16), r)
        ti, rnda_rot = p[:4], p[4:20]
        if rnda_rot != rnda[1:] + rnda[:1]:
            raise CardError("인증 실패: 칩 응답 불일치 (키가 틀림)")
        x = bytes(a ^ b for a, b in zip(rnda[2:8], rndb[0:6]))
        tail = rnda[0:2] + x + rndb[6:16] + rnda[8:16]
        self.sess = {"kno": kno, "ti": ti, "ctr": 0,
                     "enc": aes_cmac(key, bytes.fromhex("A55A00010080") + tail),
                     "mac": aes_cmac(key, bytes.fromhex("5AA500010080") + tail)}

    def _full(self, ins: int, hdr: bytes, plain: bytes, expect_mac=True):
        s = self.sess
        if not s:
            raise CardError("인증되지 않은 상태")
        ctr = s["ctr"].to_bytes(2, "little")
        iv = aes_ecb_encrypt(s["enc"], b"\xA5\x5A" + s["ti"] + ctr + bytes(8))
        padded = plain + b"\x80" + bytes((15 - len(plain)) % 16)
        enc = aes_cbc_encrypt(s["enc"], iv, padded)
        mac = truncate_mac(aes_cmac(s["mac"], bytes([ins]) + ctr + s["ti"] + hdr + enc))
        body = hdr + enc + mac
        r, _ = self._x(bytes([0x90, ins, 0, 0, len(body)]) + body + b"\x00", ok=(b"\x91\x00",))
        s["ctr"] += 1
        if expect_mac:
            exp = truncate_mac(aes_cmac(s["mac"], b"\x00" + s["ctr"].to_bytes(2, "little") + s["ti"]))
            if r != exp:
                raise CardError("응답 MAC 불일치")

    def change_file_settings_sdm(self, picc_off, mac_off, meta_key=1, file_key=2):
        o3 = lambda v: v.to_bytes(3, "little")
        data = (b"\x40"                      # FileOption: SDM 사용, 평문 통신
                + b"\x00\xE0"                # 접근권한: 읽기=누구나, 쓰기/변경=K0
                + b"\xC1"                    # SDM 옵션: UID+카운터 미러, ASCII
                + bytes([0xFF, (meta_key << 4) | file_key])
                + o3(picc_off) + o3(mac_off) + o3(mac_off))   # MAC 입력 = 빈 값
        self._full(0x5F, b"\x02", data)

    def change_key(self, kno: int, new: bytes, old: bytes = ZERO_KEY, ver: int = 1):
        if kno == self.sess["kno"]:
            self._full(0xC4, bytes([kno]), new + bytes([ver]), expect_mac=False)
            self.sess = None
        else:
            crc = (zlib.crc32(new) ^ 0xFFFFFFFF).to_bytes(4, "little")
            xored = bytes(a ^ b for a, b in zip(new, old))
            self._full(0xC4, bytes([kno]), xored + bytes([ver]) + crc)


# ---------- NDEF URL ----------
def build_ndef(base_url: str):
    if not base_url.startswith("https://"):
        raise ValueError("BASE_URL은 https:// 로 시작해야 합니다")
    rest = base_url[len("https://"):] + f"?p={PICC_PH}&m={MAC_PH}"
    payload = b"\x04" + rest.encode()
    if len(payload) > 250:
        raise ValueError("URL이 너무 깁니다")
    msg = bytes([0xD1, 0x01, len(payload), 0x55]) + payload
    f = len(msg).to_bytes(2, "big") + msg
    start = 2 + 4 + 1
    picc_off = start + rest.index(PICC_PH)
    mac_off = start + rest.index("&m=") + 3
    return f, picc_off, mac_off


# ---------- DB ----------
def db():
    c = sqlite3.connect(DB_PATH)
    c.execute("""CREATE TABLE IF NOT EXISTS tags(
        uid TEXT PRIMARY KEY, name TEXT, artist TEXT, category TEXT, made TEXT,
        serial TEXT, last_ctr INTEGER DEFAULT 0, scans INTEGER DEFAULT 0,
        created TEXT DEFAULT CURRENT_TIMESTAMP)""")
    return c


def load_master() -> bytes:
    h = os.environ.get("NTAG_MASTER_KEY")
    if not h and os.path.exists("master.key"):
        h = open("master.key").read().strip()
    if not h:
        sys.exit("마스터 키가 없습니다. 먼저 `python provision.py genkey` 를 실행하세요.")
    return bytes.fromhex(h)


# ---------- 발급 ----------
def provision(transport, args, master):
    tag = Ntag424(transport)
    uid = tag.get_uid()
    print(f"[1/7] UID 읽기: {uid.hex().upper()}")
    k = derive_keys(master, uid)

    ndef, picc_off, mac_off = build_ndef(args.base_url)
    tag.select_app()
    tag.write_ndef(ndef)
    print(f"[2/7] URL 기록 완료 (PICC 오프셋 {picc_off}, MAC 오프셋 {mac_off})")

    tag.select_app()
    tag.auth_ev2_first(0, ZERO_KEY)
    print("[3/7] 기본 키로 EV2 인증 성공")

    tag.change_file_settings_sdm(picc_off, mac_off)
    print("[4/7] SUN(SDM) 설정 완료")

    tag.change_key(1, k[1]); tag.change_key(2, k[2])
    print("[5/7] K1, K2 변경 완료")

    tag.change_key(0, k[0])
    print("[6/7] K0 변경 완료 (태그 잠금)")

    c = db()
    c.execute("INSERT OR REPLACE INTO tags(uid,name,artist,category,made,serial) VALUES(?,?,?,?,?,?)",
              (uid.hex().upper(), args.name, args.artist, args.category, args.made, args.serial))
    c.commit()
    print(f"[7/7] DB 등록: {args.name} / {args.artist}")
    return uid


def main():
    ap = argparse.ArgumentParser(description="NTAG 424 DNA 정품인증 태그 발급")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("genkey", help="마스터 키 생성")
    w = sub.add_parser("write", help="리더기 위 칩 발급")
    w.add_argument("--name", required=True, help="제품명")
    w.add_argument("--artist", default="", help="작가명")
    w.add_argument("--category", default="", help="카테고리")
    w.add_argument("--made", default="", help="제작 정보 (예: 2026, 통영)")
    w.add_argument("--serial", default="", help="일련번호")
    w.add_argument("--base-url", default=BASE_URL, help="검증 서버 주소")
    w.add_argument("--sim", action="store_true", help="실제 칩 대신 에뮬레이터 사용")
    a = ap.parse_args()

    if a.cmd == "genkey":
        if os.path.exists("master.key"):
            sys.exit("master.key가 이미 있습니다. 덮어쓰면 기존 태그를 검증할 수 없게 됩니다.")
        open("master.key", "w").write(os.urandom(16).hex().upper())
        os.chmod("master.key", 0o600)
        print("master.key 생성 완료 — 비밀번호 관리자에 백업하고 절대 공유하지 마세요.")
        return

    master = load_master()
    if a.sim:
        from sim_chip import SimChip
        chip = SimChip()
        provision(chip, a, master)
        print("\n[시뮬레이션] 폰 탭 3회:")
        for _ in range(3):
            print("  ", chip.tap())
    else:
        try:
            provision(PCSCTransport(), a, master)
        except CardError as e:
            sys.exit(f"발급 실패: {e}")
        print("\n완료! 폰으로 태그를 탭해 보세요.")


if __name__ == "__main__":
    main()
