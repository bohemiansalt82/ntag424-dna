"""
칩 없이 전체 흐름 테스트: 에뮬레이터 칩 발급 → 폰 탭 → 서버 검증
  python simulate.py
"""
import argparse
from urllib.parse import urlparse
from sim_chip import SimChip
from provision import provision, load_master
import server

a = argparse.Namespace(name="나전 손거울", artist="김선애", category="나전칠기",
                       made="2026 · 통영", serial="GY-0001",
                       base_url="https://bohemiansalt82.github.io/ntag424-dna/v/")
chip = SimChip()
provision(chip, a, load_master())
client = server.app.test_client()

def visit(url, label):
    u = urlparse(url)
    resp = client.get("/t?" + u.query)
    body = resp.get_data(as_text=True)
    status = ("정품" if "완료되었습니다" in body else "재사용" if "이미 사용된" in body
              else "미등록" if "등록되지 않은" in body else "위조")
    print(f"  {label:<18} HTTP {resp.status_code}  → {status}")
    return status

print("\n검증 테스트:")
u1 = chip.tap(); s1 = visit(u1, "1번째 탭")
u2 = chip.tap(); s2 = visit(u2, "2번째 탭")
s3 = visit(u1, "1번째 URL 재접속")
bad = u2[:-1] + ("0" if u2[-1] != "0" else "1")
s4 = visit(bad, "MAC 1글자 변조")
other = SimChip()                        # 발급 안 된 칩(기본 키) — 다른 키로 서명됨
other.keys = {i: bytes(16) for i in range(5)}
other.sdm = chip.sdm; other.ndef = chip.ndef[:]
s5 = visit(other.tap(), "가짜 칩")
assert (s1, s2, s3, s4, s5) == ("정품", "정품", "재사용", "위조", "위조")
print("\n모든 시나리오 통과")
