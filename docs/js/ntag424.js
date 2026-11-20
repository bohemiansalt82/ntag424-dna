const S = globalThis.crypto.subtle;
const hex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("").toUpperCase();
const unhex = h => new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)));
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
const xor = (a, b) => a.map((v, i) => v ^ b[i]);
const txt = s => new TextEncoder().encode(s);
const le3 = n => new Uint8Array([n & 255, (n >> 8) & 255, (n >> 16) & 255]);
const keyCache = new Map();
async function imp(k) { const h = hex(k); if (!keyCache.has(h)) keyCache.set(h, await S.importKey("raw", k, { name: "AES-CBC" }, false, ["encrypt", "decrypt"])); return keyCache.get(h); }
async function ecb(k, b) { return new Uint8Array(await S.encrypt({ name: "AES-CBC", iv: new Uint8Array(16) }, await imp(k), b)).slice(0, 16); }
async function cbcEnc(k, data) { let prev = new Uint8Array(16), out = []; for (let i = 0; i < data.length; i += 16) { prev = await ecb(k, xor(data.slice(i, i + 16), prev)); out.push(prev); } return cat(...out); }
async function decBlock(k, c) { // AES-CBC(IV=0) 한 블록 복호화 (WebCrypto 패딩 우회)
  const c2 = await ecb(k, xor(c, new Uint8Array(16).fill(16)));
  return new Uint8Array(await S.decrypt({ name: "AES-CBC", iv: new Uint8Array(16) }, await imp(k), cat(c, c2)));
}
const dbl = b => { const o = new Uint8Array(16); for (let i = 0; i < 16; i++) o[i] = ((b[i] << 1) | (i < 15 ? b[i + 1] >> 7 : 0)) & 255; if (b[0] & 128) o[15] ^= 0x87; return o; };
async function cmac(k, m) {
  const k1 = dbl(await ecb(k, new Uint8Array(16))), k2 = dbl(k1);
  const n = Math.max(1, Math.ceil(m.length / 16)), full = m.length > 0 && m.length % 16 === 0;
  let last = m.slice((n - 1) * 16);
  if (full) last = xor(last, k1); else { const p = new Uint8Array(16); p.set(last); p[last.length] = 0x80; last = xor(p, k2); }
  let x = new Uint8Array(16);
  for (let i = 0; i < n - 1; i++) x = await ecb(k, xor(x, m.slice(i * 16, i * 16 + 16)));
  return ecb(k, xor(x, last));
}
const trunc = m => m.filter((_, i) => i % 2 === 1);
// provision.py / crypto_core.py 와 동일한 키 파생
async function deriveKeys(master, uid) {
  return { k0: await cmac(master, cat([1], txt("GYEOL-K0"), uid)),
           k1: await cmac(master, cat([2], txt("GYEOL-K1-SHARED"))),
           k2: await cmac(master, cat([3], txt("GYEOL-K2"), uid)) };
}
async function sdmMac(k2, uid, ctr) { const ks = await cmac(k2, cat(unhex("3CC300010080"), uid, le3(ctr))); return trunc(await cmac(ks, new Uint8Array(0))); }
async function encPicc(k1, uid, ctr) { return cbcEnc(k1, cat([0xC7], uid, le3(ctr), crypto.getRandomValues(new Uint8Array(5)))); }
async function decPicc(k1, c) { const p = await decBlock(k1, c); if (p[0] !== 0xC7) return null; return { uid: p.slice(1, 8), ctr: p[8] | (p[9] << 8) | (p[10] << 16) }; }
async function selfTest() {
  const z = new Uint8Array(16), r = await decPicc(z, unhex("EF963FF7828658A599F3041510671E88"));
  return r && hex(r.uid) === "04DE5F1EACC040" && r.ctr === 61 && hex(await sdmMac(z, r.uid, r.ctr)) === "94EED9EE65337086";
}

// ---------- 개발자용 단계별 검증 (verify 페이지) ----------
// keys: {mode:"master", master} | {mode:"raw", k1, k2}
async function verifyTrace(url, p, m, keys) {
  const steps = [], step = (title, ok, rows, note) => steps.push({ title, ok, rows, note });
  step("태그가 연 URL", true, [["URL", url], ["p (암호화 PICC, 16B)", p], ["m (CMAC 서명, 8B)", m]],
    "칩이 탭될 때마다 p와 m을 새로 만들어 URL에 끼워 넣습니다.");
  if (!/^[0-9A-Fa-f]{32}$/.test(p) || !/^[0-9A-Fa-f]{16}$/.test(m)) {
    step("파라미터 형식 검사", false, [["p 길이", String(p.length)], ["m 길이", String(m.length)]], "p는 32자, m은 16자 HEX여야 합니다.");
    return { status: "forged", steps };
  }
  let k1;
  if (keys.mode === "master") {
    k1 = await cmac(keys.master, cat([2], txt("GYEOL-K1-SHARED")));
    step("K1 파생 (전체 공통 키)", true, [["입력", "02 ‖ \"GYEOL-K1-SHARED\""], ["K1 = CMAC(마스터, 입력)", hex(k1)]],
      "UID를 알기 전에 복호화해야 하므로 모든 칩이 같은 K1을 씁니다.");
  } else {
    k1 = keys.k1;
    step("K1 (직접 입력)", true, [["K1", hex(k1)]]);
  }
  const plain = await decBlock(k1, unhex(p));
  const ph = hex(plain), uid = plain.slice(1, 8), ctr = plain[8] | (plain[9] << 8) | (plain[10] << 16);
  const tagOk = plain[0] === 0xC7;
  step("PICC 복호화  AES-128-CBC(K1, IV=0)", tagOk, [
    ["복호화 결과 16B", ph],
    ["[0] 태그 바이트", ph.slice(0, 2) + (tagOk ? "  (C7 = UID·카운터 미러, UID 7B)" : "  ≠ C7 → 키 불일치 또는 위조")],
    ["[1-7] UID", hex(uid)],
    ["[8-10] 카운터 (LE)", ph.slice(16, 22) + "  → " + ctr],
    ["[11-15] 랜덤 패딩", ph.slice(22)]
  ], tagOk ? "" : "K1로 정상 복호화되지 않았습니다. 다른 키로 만든 칩이거나 값이 변조됐습니다.");
  if (!tagOk) return { status: "forged", steps };
  let k2;
  if (keys.mode === "master") {
    k2 = await cmac(keys.master, cat([3], txt("GYEOL-K2"), uid));
    step("K2 파생 (칩 전용 키)", true, [["입력", "03 ‖ \"GYEOL-K2\" ‖ " + hex(uid)], ["K2 = CMAC(마스터, 입력)", hex(k2)]],
      "UID마다 다른 키라서 칩 하나가 털려도 다른 칩은 안전합니다.");
  } else { k2 = keys.k2; step("K2 (직접 입력)", true, [["K2", hex(k2)]]); }
  const sv2 = cat(unhex("3CC300010080"), uid, le3(ctr)), ks = await cmac(k2, sv2);
  step("세션 MAC 키 생성", true, [["SV2 = 3CC300010080 ‖ UID ‖ CTR", hex(sv2)], ["KSes = CMAC(K2, SV2)", hex(ks)]],
    "카운터가 들어가므로 탭할 때마다 세션 키가 달라집니다.");
  const full = await cmac(ks, new Uint8Array(0)), exp = hex(trunc(full)), got = m.toUpperCase();
  const macOk = exp === got;
  step("CMAC 서명 비교", macOk, [["CMAC(KSes, 빈 입력) 16B", hex(full)], ["홀수 바이트 8B (기대값)", exp], ["URL의 m (받은 값)", got],
    ["결과", macOk ? "일치 ✓" : "불일치 ✕"]], macOk ? "" : "서명이 다릅니다. 복제 칩이거나 URL이 조작됐습니다.");
  return { status: macOk ? "genuine" : "forged", steps, uid: hex(uid), ctr };
}
if (typeof module !== "undefined") module.exports = { hex, unhex, cmac, deriveKeys, sdmMac, encPicc, decPicc, selfTest, verifyTrace };
