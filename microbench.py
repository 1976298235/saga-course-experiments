
"""SAGA 关键密码/协议操作微基准（纯 Python 标准库 + C 实现的原语）。
说明：X25519 不在标准库中，用 RFC 3526 2048-bit MODP 群的 pow() 近似 ECDH 的
标量乘开销量级；对称封装用 HMAC-SHA256 的 encrypt-then-MAC 近似 AEAD。
"""
import hmac, hashlib, json, os, statistics, time, re
from pathlib import Path

MODP = int(
 "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
 "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
 "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
 "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
 "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
 "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
 "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
 "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
G = 2
Q = (MODP - 1) // 2

def dh_keypair():
    x = int.from_bytes(os.urandom(32), 'big') % Q
    return x, pow(G, x, MODP)

def dh(x, gy):
    return pow(gy, x, MODP).to_bytes(256, 'big')

def hkdf(ikm, info=b'saga-token', n=32):
    prk = hmac.new(b'\x00'*32, ikm, hashlib.sha256).digest()
    okm, t, i = b'', b'', 1
    while len(okm) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t; i += 1
    return okm[:n]

def token_seal(key, payload: bytes):
    iv = os.urandom(16)
    ct = bytes(a ^ b for a, b in zip(payload, hashlib.shake_256(key+iv).digest(len(payload))))
    tag = hmac.new(key, iv + ct, hashlib.sha256).digest()
    return iv + ct + tag

def token_open(key, blob):
    iv, ct, tag = blob[:16], blob[16:-32], blob[-32:]
    if not hmac.compare_digest(tag, hmac.new(key, iv+ct, hashlib.sha256).digest()):
        raise ValueError('bad tag')
    return bytes(a ^ b for a, b in zip(ct, hashlib.shake_256(key+iv).digest(len(ct))))

CP = [{"agents": "alice@company.com:calendar_agent", "budget": 15},
      {"agents": "*@company.com:calendar_agent", "budget": 10},
      {"agents": "bob@mail.com:*", "budget": 100}]

def to_regex(p):
    return re.compile('^' + re.escape(p).replace(r'\*', '.*') + '$')

def policy_check(aid):
    best = None
    for r in CP:
        if to_regex(r["agents"]).match(aid):
            if best is None or len(r["agents"].replace('*','')) > len(best["agents"].replace('*','')):
                best = r
    return -1 if best is None else best["budget"]

def bench(fn, n=2000, warmup=50):
    for _ in range(warmup): fn()
    ts = []
    for _ in range(n):
        t0 = time.perf_counter(); fn(); ts.append((time.perf_counter()-t0)*1000)
    return {'mean_ms': round(statistics.mean(ts), 4),
            'median_ms': round(statistics.median(ts), 4),
            'p95_ms': round(sorted(ts)[int(0.95*len(ts))], 4)}

xa, gA = dh_keypair(); xb, gB = dh_keypair()
sA = hkdf(dh(xa, gB)); sB = hkdf(dh(xb, gA))
assert sA == sB
payload = json.dumps({"n": os.urandom(16).hex(), "t_issue": 1762000000,
                      "t_expire": 1762086400, "qmax": 100,
                      "pac_b": gB.to_bytes(256,"big").hex()}).encode()
blob = token_seal(sA, payload)

res = {
  'dh_keypair': bench(dh_keypair),
  'dh_shared_secret': bench(lambda: dh(xa, gB)),
  'hkdf_derive': bench(lambda: hkdf(sA)),
  'token_seal': bench(lambda: token_seal(sA, payload)),
  'token_open': bench(lambda: token_open(sA, blob)),
  'policy_match': bench(lambda: policy_check('alice@company.com:calendar_agent')),
  'json_encode_meta': bench(lambda: json.dumps({"aid":"alice@company.com:calendar_agent","edb":["mac","10.0.0.2",8443],"pac":gA.to_bytes(256,"big").hex()})),
}
# 端到端: 发起方建立令牌所需 (DH + HKDF + 校验 + 封装)
def setup_initiator():
    k = hkdf(dh(xa, gB)); token_open(k, token_seal(k, payload))
res['setup_initiator_total'] = bench(setup_initiator, n=500)
res['setup_receiver_total'] = bench(lambda: hkdf(dh(xb, gA)), n=500)
print(json.dumps(res, ensure_ascii=False, indent=2))
out = Path(__file__).resolve().parent / 'microbench.json'
json.dump(res, open(out,'w'), ensure_ascii=False, indent=2)

