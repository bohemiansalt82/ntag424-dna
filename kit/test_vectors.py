"""NXP AN12196 공식 예제값으로 암호화 코어 검증"""
from crypto_core import *

# AN12196 예제: 모든 키 0, URL ?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086
uid, ctr = decrypt_picc(ZERO_KEY, bytes.fromhex("EF963FF7828658A599F3041510671E88"))
assert uid.hex().upper() == "04DE5F1EACC040", uid.hex()
assert ctr == 0x3D, ctr
mac = calc_sdm_mac(ZERO_KEY, uid, ctr)
assert mac.hex().upper() == "94EED9EE65337086", mac.hex()
print("AN12196 SUN 테스트 벡터 통과: UID", uid.hex().upper(), "카운터", ctr, "MAC", mac.hex().upper())

# 왕복 테스트 (시뮬레이터 ↔ 서버)
import os
master = os.urandom(16)
uid = bytes.fromhex("04A1B2C3D4E5F6")
k = derive_keys(master, uid)
picc = encrypt_picc(k[1], uid, 7)
m = calc_sdm_mac(k[2], uid, 7)
r = verify_sun(master, picc.hex(), m.hex())
assert r["ok"] and r["ctr"] == 7, r
bad = bytearray(m); bad[0] ^= 1
assert not verify_sun(master, picc.hex(), bytes(bad).hex())["ok"]
print("왕복/위조 탐지 테스트 통과")
