# NTAG 424 DNA 정품 인증 (GYEOL)

NXP NTAG 424 DNA 칩의 SUN(Secure Unique NFC) 기능으로 정품을 인증하는 테스트 프로젝트입니다.
칩 발급 → 폰 탭 → 암호 검증 → 결과까지 각 단계의 값을 개발자가 직접 볼 수 있습니다.

- **시뮬레이터**: https://bohemiansalt82.github.io/ntag424-dna/
- **개발자 검증 페이지**: https://bohemiansalt82.github.io/ntag424-dna/v/
- **NXP 공식 예제로 바로 체험**: [예제 URL 검증](https://bohemiansalt82.github.io/ntag424-dna/v/?p=EF963FF7828658A599F3041510671E88&m=94EED9EE65337086&demo=an12196)

## 동작 흐름

```
[칩]  탭할 때마다 카운터 +1
      p = AES-CBC(K1, C7 ‖ UID ‖ 카운터 ‖ 랜덤)
      m = CMAC(CMAC(K2, 3CC300010080 ‖ UID ‖ 카운터), 빈 값)의 홀수 바이트 8개
        ↓ 폰이 URL 열기
https://bohemiansalt82.github.io/ntag424-dna/v/?p=…&m=…
        ↓ 검증 페이지 (브라우저에서 계산)
 01 URL 분해 → 03 K1 파생 → 04 PICC 복호화(UID·카운터)
 → 05 K2 파생 → 06 세션 키 → 07 CMAC 비교 → 08 카운터 재사용 검사 → 결과
```

## 폴더 구성

| 경로 | 내용 |
|---|---|
| `docs/index.html` | 폰 인증 시뮬레이터 (칩 없이 정품, 재사용, 복제 칩 시나리오) |
| `docs/v/index.html` | 개발자 검증 페이지: 실제 칩이 여는 주소 |
| `docs/js/ntag424.js` | 브라우저용 암호 모듈 (AES-CMAC, 복호화, 단계별 trace) |
| `kit/provision.py` | 리더기로 실제 칩 발급 |
| `kit/server.py` | 운영용 검증 서버 (Flask, 키는 서버에만 보관) |
| `kit/sim_chip.py`, `kit/simulate.py` | 소프트웨어 칩 에뮬레이터와 자동 테스트 |
| `kit/test_vectors.py` | NXP AN12196 공식 예제값 검증 |

## 실제 칩으로 테스트하기

준비물: NTAG 424 DNA 스티커, ACR122U 리더기

```bash
cd kit
pip install cryptography flask pyscard
python test_vectors.py          # 암호 코어 검증
python provision.py genkey      # master.key 생성 (최초 1회, 깃에 올리지 않음)
python simulate.py              # 칩 없이 전체 흐름 테스트

# 리더기에 새 칩을 올리고 발급 (기본 주소가 이 저장소의 검증 페이지)
python provision.py write --name "나전 손거울" --artist "김선애" --serial "GY-0001"
```

폰에서는 다음 순서로 진행합니다.
1. 검증 페이지(`/v/`)를 열고 **키 설정**에 `master.key` 내용(32자리)을 붙여넣어 저장합니다. 키는 이 폰의 브라우저에만 저장됩니다.
2. 칩을 탭하면 결과와 단계별 로그가 나옵니다.
3. 같은 URL을 새로고침하면 "이미 사용된 링크"가 뜨는지 확인합니다.

TagXplorer로 직접 설정한 칩(예: 기본 키 0 그대로)은 키 설정에서 **K1·K2 직접 입력**을 선택하세요.

## 보안 주의

- `/v/` 페이지는 **테스트 전용**입니다. 브라우저에서 검증하려고 키를 폰에 저장하기 때문입니다. 실제 판매용은 `kit/server.py`처럼 서버에서 검증하세요.
- 카운터 재사용 검사도 `/v/`에서는 그 기기 기준입니다. 운영 서버는 DB 기준입니다.
- `master.key`는 절대 커밋하지 마세요. `.gitignore`에 포함되어 있습니다.
