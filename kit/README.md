# GYEOL NFC 정품 인증 키트 (NTAG 424 DNA)

칩 발급 → 폰 탭 → 서버 검증까지 한 세트입니다.
암호화 코어는 NXP 공식 문서(AN12196)의 예제값으로 검증했습니다.

## 파일 구성

| 파일 | 역할 |
|---|---|
| `crypto_core.py` | AES-CMAC, 키 파생, SUN 복호화와 서명 검증 (공통) |
| `provision.py` | 리더기로 칩 발급: URL 기록, SUN 설정, 키 교체, DB 등록 |
| `server.py` + `templates/result.html` | 폰이 여는 검증 서버와 결과 페이지 |
| `sim_chip.py` | 소프트웨어 칩 에뮬레이터 (칩 없이 테스트) |
| `simulate.py` | 전체 흐름 자동 테스트 (정품, 재사용, 변조, 복제 칩) |
| `test_vectors.py` | NXP 공식 예제값 검증 |

## 1. 설치

```bash
pip install cryptography flask pyscard
```
- Mac: 기본 PC/SC 드라이버로 동작합니다. ACR122U는 ACS 드라이버를 설치하는 게 안정적입니다.
- Windows: ACS 홈페이지에서 리더기 드라이버를 설치하세요.

## 2. 칩 없이 먼저 테스트

```bash
python test_vectors.py        # 암호 코어 검증
python provision.py genkey    # master.key 생성 (최초 1회)
python simulate.py            # 발급 → 탭 → 검증 시나리오 5개
```

## 3. 실제 칩 발급

1. 검증 서버 주소를 정합니다. 반드시 **HTTPS**여야 합니다.
   ```bash
   export NTAG_BASE_URL="https://verify.내도메인.kr/t"
   ```
2. 리더기에 **새 칩**(공장 기본 키 상태)을 올리고 실행합니다.
   ```bash
   python provision.py write --name "나전 손거울" --artist "김선애" \
       --category "나전칠기" --made "2026 · 통영" --serial "GY-0001"
   ```
3. `[7/7] DB 등록`까지 출력되면 완료입니다.

> ⚠ 처음에는 2~3장으로만 연습하세요. 발급이 끝난 칩은 K0가 바뀌어서
> 같은 명령으로 다시 발급할 수 없습니다(재발급 기능은 아직 없음).
> 중간에 실패하면 칩을 리더기에서 떼지 말고 오류 메시지를 확인하세요.

## 4. 검증 서버 실행

```bash
python server.py              # http://localhost:8000/t?p=...&m=...
```
폰으로 테스트하려면 HTTPS 주소가 필요합니다.
- 빠른 테스트: `ngrok http 8000`이나 Cloudflare Tunnel로 HTTPS 주소를 받아서 그 주소로 칩을 발급
- 실제 운영: Render, Fly.io, 자체 서버(+nginx) 등에 배포

`master.key`와 `tags.db`는 서버와 발급 PC가 같은 것을 써야 합니다.

## 키 구조

| 슬롯 | 용도 | 값 |
|---|---|---|
| K0 | 관리 키 (설정 변경) | 마스터 키 + UID로 파생 (칩마다 다름) |
| K1 | UID·카운터 암호화 | 마스터 키로 파생 (전체 공통, 서버가 UID를 알기 전에 복호화해야 하므로) |
| K2 | CMAC 서명 | 마스터 키 + UID로 파생 (칩마다 다름) |

## 보안 체크리스트

- `master.key`는 **절대 깃에 올리지 마세요**. 운영 환경에서는 환경변수 `NTAG_MASTER_KEY`나 KMS로 관리하세요.
- 마스터 키를 잃어버리면 이미 발급한 모든 칩을 검증할 수 없습니다. 비밀번호 관리자에 백업하세요.
- 태그를 떼어 가짜 제품에 붙이는 공격은 암호로 막을 수 없습니다. 떼면 찢어지는 파손형 스티커를 쓰거나 제품 안에 매립하세요.
