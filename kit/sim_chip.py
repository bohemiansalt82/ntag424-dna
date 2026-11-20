"""
소프트웨어 NTAG 424 DNA 에뮬레이터
- 실제 칩이 없어도 provision.py 전체 흐름(인증·키 변경·SDM 설정)과
  폰 탭(SUN URL 생성)을 테스트할 수 있게 칩 쪽 동작을 재현
- 실제 칩 구매 후에는 사용하지 않아도 됨
"""
import os
import zlib
from crypto_core import (aes_cmac, aes_cbc_encrypt, aes_cbc_decrypt, aes_ecb_encrypt,
                         truncate_mac, encrypt_picc, calc_sdm_mac)

AID = bytes.fromhex("D2760000850101")


class SimChip:
    def __init__(self, uid: bytes | None = None):
        self.uid = uid or bytes([0x04]) + os.urandom(6)
        self.keys = {i: bytes(16) for i in range(5)}
        self.ndef = bytearray(256)
        self.ndef_write_free = True
        self.sdm = None          # SDM 설정 dict
        self.read_ctr = 0
        self.app_selected = False
        self.sess = None
        self._pending = None

    # --- APDU 진입점 ---
    def transmit(self, apdu: bytes) -> bytes:
        cla, ins = apdu[0], apdu[1]
        if cla == 0xFF and ins == 0xCA:                 # 리더기: UID 읽기
            return self.uid + b"\x90\x00"
        if cla == 0x00 and ins == 0xA4:                 # ISO SELECT
            data = apdu[5:5 + apdu[4]]
            if apdu[2] == 0x04 and data == AID:
                self.app_selected, self.sess = True, None
                return b"\x90\x00"
            if apdu[2] == 0x00 and data == b"\xE1\x04":
                return b"\x90\x00"
            return b"\x6A\x82"
        if cla == 0x00 and ins == 0xD6:                 # ISO UPDATE BINARY (NDEF)
            if not self.ndef_write_free:
                return b"\x69\x82"
            off = (apdu[2] << 8) | apdu[3]
            data = apdu[5:5 + apdu[4]]
            self.ndef[off:off + len(data)] = data
            return b"\x90\x00"
        if cla == 0x90:
            data = apdu[5:5 + apdu[4]] if len(apdu) > 5 else b""
            return self._native(ins, data)
        return b"\x6D\x00"

    # --- 폰이 태그를 읽을 때: SUN 값 치환 후 NDEF 반환 ---
    def tap(self) -> str:
        buf = bytearray(self.ndef)
        if self.sdm:
            self.read_ctr += 1
            s = self.sdm
            picc = encrypt_picc(self.keys[s["meta_key"]], self.uid, self.read_ctr)
            buf[s["picc_off"]:s["picc_off"] + 32] = picc.hex().upper().encode()
            mac = calc_sdm_mac(self.keys[s["file_key"]], self.uid, self.read_ctr,
                               bytes(buf[s["mac_in_off"]:s["mac_off"]]))
            buf[s["mac_off"]:s["mac_off"] + 16] = mac.hex().upper().encode()
        nlen = (buf[0] << 8) | buf[1]
        msg = bytes(buf[2:2 + nlen])
        payload = msg[4:4 + msg[2]]
        assert payload[0] == 0x04
        return "https://" + payload[1:].decode()

    # --- 네이티브 명령 ---
    def _native(self, ins, data):
        if ins == 0x71:                                 # AuthenticateEV2First
            kno = data[0]
            self.sess = None
            rndb = os.urandom(16)
            self._pending = (kno, rndb)
            return aes_cbc_encrypt(self.keys[kno], bytes(16), rndb) + b"\x91\xAF"
        if ins == 0xAF and self._pending:
            kno, rndb = self._pending
            self._pending = None
            k = self.keys[kno]
            p = aes_cbc_decrypt(k, bytes(16), data)
            rnda, rndb_rot = p[:16], p[16:]
            if rndb_rot != rndb[1:] + rndb[:1]:
                return b"\x91\xAE"
            ti = os.urandom(4)
            resp = ti + rnda[1:] + rnda[:1] + bytes(12)
            x = bytes(a ^ b for a, b in zip(rnda[2:8], rndb[0:6]))
            tail = rnda[0:2] + x + rndb[6:16] + rnda[8:16]
            self.sess = {"kno": kno, "ti": ti, "ctr": 0,
                         "enc": aes_cmac(k, bytes.fromhex("A55A00010080") + tail),
                         "mac": aes_cmac(k, bytes.fromhex("5AA500010080") + tail)}
            return aes_cbc_encrypt(k, bytes(16), resp) + b"\x91\x00"
        if ins in (0x5F, 0xC4):
            return self._full_cmd(ins, data)
        return b"\x91\x1C"

    def _full_cmd(self, ins, data):
        s = self.sess
        if not s:
            return b"\x91\xAE"
        hdr, enc, mac = data[:1], data[1:-8], data[-8:]
        ctr = s["ctr"].to_bytes(2, "little")
        exp = truncate_mac(aes_cmac(s["mac"], bytes([ins]) + ctr + s["ti"] + hdr + enc))
        if exp != mac:
            self.sess = None
            return b"\x91\x1E"
        iv = aes_ecb_encrypt(s["enc"], b"\xA5\x5A" + s["ti"] + ctr + bytes(8))
        plain = aes_cbc_decrypt(s["enc"], iv, enc)
        plain = plain[:plain.rindex(b"\x80")]          # ISO 9797-1 M2 패딩 제거
        s["ctr"] += 1
        no_mac = False
        if ins == 0x5F:
            if s["kno"] != 0:
                return b"\x91\x9D"
            self._apply_file_settings(hdr[0], plain)
        else:
            kno = hdr[0]
            if kno == s["kno"]:
                self.keys[kno] = plain[:16]
                self.sess, no_mac = None, True
            else:
                new = bytes(a ^ b for a, b in zip(plain[:16], self.keys[kno]))
                crc = (zlib.crc32(new) ^ 0xFFFFFFFF).to_bytes(4, "little")
                if crc != plain[17:21]:
                    return b"\x91\x1E"
                self.keys[kno] = new
        if no_mac:
            return b"\x91\x00"
        rmac = truncate_mac(aes_cmac(s["mac"], b"\x00" + s["ctr"].to_bytes(2, "little") + s["ti"]))
        return rmac + b"\x91\x00"

    def _apply_file_settings(self, fno, d):
        assert fno == 0x02
        opt, ar, sdm_opt, sdm_ar = d[0], d[1:3], d[3], d[4:6]
        self.ndef_write_free = (ar[1] & 0x0F) == 0x0E
        if opt & 0x40:
            meta, fread = sdm_ar[1] >> 4, sdm_ar[1] & 0x0F
            assert sdm_opt == 0xC1 and meta < 5 and fread < 5
            o = lambda i: int.from_bytes(d[i:i + 3], "little")
            self.sdm = {"meta_key": meta, "file_key": fread,
                        "picc_off": o(6), "mac_in_off": o(9), "mac_off": o(12)}
