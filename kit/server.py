"""
정품 인증 검증 서버
- 폰이 태그를 탭하면 열리는 URL:  /t?p=<암호화 PICC>&m=<CMAC>
- 복호화 → 서명 검증 → 카운터 재사용 검사 → 결과 페이지

실행:  python server.py         (기본 http://localhost:8000)
배포:  HTTPS 도메인 필수 (예: Render, Fly.io, 자체 서버 + nginx)
"""
import os
import sqlite3
from flask import Flask, request, render_template

from crypto_core import verify_sun
from provision import load_master, DB_PATH

app = Flask(__name__)
MASTER = load_master()


def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def check(p: str, m: str) -> dict:
    """검증 결과: status = genuine | replay | forged | unknown"""
    r = verify_sun(MASTER, p, m)
    if not r["ok"]:
        return {"status": "forged", "reason": r["reason"]}
    c = db()
    tag = c.execute("SELECT * FROM tags WHERE uid=?", (r["uid"],)).fetchone()
    if not tag:
        return {"status": "unknown", "uid": r["uid"]}
    # 카운터는 탭할 때마다 1씩 증가 → 이미 본 값 이하면 복사된 URL
    if r["ctr"] <= tag["last_ctr"]:
        return {"status": "replay", "tag": dict(tag), "ctr": r["ctr"]}
    # 동시 요청에도 안전하게: 조건부 UPDATE
    cur = c.execute("UPDATE tags SET last_ctr=?, scans=scans+1 WHERE uid=? AND last_ctr<?",
                    (r["ctr"], r["uid"], r["ctr"]))
    c.commit()
    if cur.rowcount == 0:
        return {"status": "replay", "tag": dict(tag), "ctr": r["ctr"]}
    tag = c.execute("SELECT * FROM tags WHERE uid=?", (r["uid"],)).fetchone()
    return {"status": "genuine", "tag": dict(tag), "ctr": r["ctr"]}


@app.get("/t")
def tap():
    res = check(request.args.get("p", ""), request.args.get("m", ""))
    code = 200 if res["status"] == "genuine" else 403
    return render_template("result.html", r=res), code


@app.get("/")
def home():
    return "GYEOL 정품 인증 서버 동작 중"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
