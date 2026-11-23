
"""SAGA-R 撤销时效性仿真 + 论文数据复核。
输出: results.json / results.md
"""
import json, math, os
import numpy as np
from pathlib import Path

rng = np.random.default_rng(20261101)
OUT = Path(__file__).resolve().parent
os.makedirs(OUT, exist_ok=True)

LAM = 6.0            # 恶意发起方请求速率 (req/min)
N_TRIAL = 20000      # 蒙特卡洛次数
QMAX = 100           # 每令牌允许请求数
SYNC = {'SAGA-R(Δ=10s)': 10/60, 'SAGA-R(Δ=60s)': 1.0, 'SAGA-R(Δ=600s)': 10.0}  # 分钟

def simulate(L_min, qmax=QMAX, lam=LAM, n=N_TRIAL):
    """基线 SAGA: 封禁后已签发令牌不可撤回, 直到配额耗尽或过期。"""
    tb = rng.uniform(0, L_min, n)              # 封禁发生在令牌有效期内的随机相位
    used = rng.integers(0, qmax+1, n)          # 封禁时刻已消耗的请求数(均匀近似)
    remain_quota = qmax - used
    remain_time = L_min - tb
    # 到达为泊松过程: 在剩余时间内的到达数; 可接受请求数 = min(剩余配额, 剩余窗口内到达数)
    arrivals = rng.poisson(lam * remain_time)
    R = np.minimum(remain_quota, arrivals)
    # 暴露时长 = 第 R 个到达的时刻 - tb (若配额先耗尽) 否则 = 剩余时间
    W = np.where(R < arrivals, R/lam, remain_time)
    return R, W

def simulate_epoch(L_min, delta_min, qmax=QMAX, lam=LAM, n=N_TRIAL):
    """SAGA-R: 令牌携带代数号, 接收方每 Δ 同步一次吊销摘要; 同步完成前的请求仍被接受。"""
    tb = rng.uniform(0, L_min, n)
    used = rng.integers(0, qmax+1, n)
    remain_quota = qmax - used
    # 接收方感知封禁的时延: 同步周期内均匀分布
    delay = rng.uniform(0, min(delta_min, L_min), n)
    arrivals = rng.poisson(lam * delay)
    R = np.minimum(remain_quota, arrivals)
    W = np.where(R < arrivals, R/lam, delay)
    return R, W

def summarize(R, W):
    return {
        'mean_residual_requests': round(float(R.mean()), 3),
        'p95_residual_requests': int(np.percentile(R, 95)),
        'max_residual_requests': int(R.max()),
        'mean_exposure_seconds': round(float(W.mean()*60), 2),
        'p95_exposure_seconds': round(float(np.percentile(W, 95)*60), 2),
        'p_zero_residual': round(float((R == 0).mean()), 4),
    }

results = {'params': {'lambda_req_per_min': LAM, 'qmax': QMAX, 'trials': N_TRIAL},
           'tables': {}}

# ---------- 表 1: 不同令牌寿命下的残余暴露 ----------
t1 = []
for L_h in [1, 3, 6, 12, 24]:
    L = L_h * 60
    R0, W0 = simulate(L)
    row = {'L_hours': L_h, 'baseline': summarize(R0, W0)}
    for name, dm in SYNC.items():
        R1, W1 = simulate_epoch(L, dm)
        row[name] = summarize(R1, W1)
    # 短寿命令牌方案: L=1min, 无吊销机制
    R2, W2 = simulate(1.0)
    row['short_token(L=1min)'] = summarize(R2, W2)
    t1.append(row)
results['tables']['residual_exposure'] = t1

# ---------- 表 2: 控制面负载 (每智能体每日 Provider 交互次数) ----------
t2 = []
for L_h in [1, 6, 24]:
    L = L_h * 60
    daily_otk = 1440 / L                       # 每 L 分钟取一次 OTK
    row = {'L_hours': L_h, 'otk_requests_per_agent_day': round(daily_otk, 2)}
    for name, dm in SYNC.items():
        row[name + '_sync_per_day'] = round(1440/dm, 1)
        row[name + '_total_per_day'] = round(daily_otk + 1440/dm, 1)
    row['short_token(L=1min)_otk_per_day'] = 1440.0
    t2.append(row)
results['tables']['control_plane_load'] = t2

# ---------- 表 3: 百万智能体规模下的 Provider 负载 ----------
t3 = []
N_AG = 1_000_000
for L_h in [1, 6, 24]:
    for name, dm in [('SAGA-R(Δ=60s)', 1.0)]:
        tot_day = 1440/(L_h*60) + 1440/dm
        t3.append({'agents': N_AG, 'L_hours': L_h, 'scheme': name,
                   'provider_qps': round(tot_day * N_AG / 86400, 1),
                   'provider_req_per_min': round(tot_day * N_AG / 1440, 0)})
results['tables']['scale_1m_agents'] = t3

# ---------- 论文数据复核 ----------
# 表 III / 表 II / 图 6c 的复算
recheck = {
    'token_setup_crypto_ms_paper': 7.0,
    'task_overhead_ratio': {
        'Calendar': round(0.165/(50.001+0.791)*100, 3),
        'Email': round(0.165/(26.862+1.319)*100, 3),
        'Writing': round(0.165/(363.563+1.319)*100, 3),
    },
    'capacity': [],
}
# C = T * L, T 取论文图 6a 中 10 分片 RAFT(3) 的 OTK 请求吞吐
for T_per_min, label in [(178_000, '10 sharders, RAFT(3)'), (204_000, '5-node no-shard')]:
    for L_h in [1, 6, 12, 24]:
        recheck['capacity'].append({'throughput_req_per_min': T_per_min, 'label': label,
                                    'L_hours': L_h, 'agents': int(T_per_min * L_h * 60)})
# 模型: 平均摊销开销 = (RTT + t_crypto) / Qmax (m=100 请求时)
rtts = {'US-West': 30, 'US-East': 60, 'EU': 140, 'Asia': 200}
amort = []
for q in [1, 10, 20, 30]:
    amort.append({'Qmax': q,
                  **{k: round((v + 7.0)/q, 2) for k, v in rtts.items()}})
recheck['amortized_overhead_ms'] = amort
results['recheck'] = recheck

with open(os.path.join(OUT, 'results.json'), 'w') as f:
    json.dump(results, f, ensure_ascii=False, indent=2)

# ---------- markdown 表格 ----------
def md_table(rows, cols):
    out = ['| ' + ' | '.join(cols) + ' |', '|' + '|'.join(['---']*len(cols)) + '|']
    for r in rows:
        out.append('| ' + ' | '.join(str(r[c]) for c in cols) + ' |')
    return '\n'.join(out)

lines = []
lines.append('# 仿真与复算结果\n')
lines.append('## 表 A 残余暴露（封禁后仍被接受的请求数 / 暴露时长）\n')
rows = []
for r in t1:
    for scheme in ['baseline'] + list(SYNC.keys()) + ['short_token(L=1min)']:
        s = r[scheme]
        rows.append({'令牌寿命 L(h)': r['L_hours'], '方案': scheme,
                     '平均残余请求数': s['mean_residual_requests'],
                     'P95 残余请求数': s['p95_residual_requests'],
                     '最大残余请求数': s['max_residual_requests'],
                     '平均暴露时长(s)': s['mean_exposure_seconds'],
                     'P95 暴露时长(s)': s['p95_exposure_seconds']})
lines.append(md_table(rows, ['令牌寿命 L(h)', '方案', '平均残余请求数', 'P95 残余请求数', '最大残余请求数', '平均暴露时长(s)', 'P95 暴露时长(s)']))
lines.append('\n## 表 B 控制面负载（每智能体每日 Provider 交互次数）\n')
lines.append(md_table(t2, list(t2[0].keys())))
lines.append('\n## 表 C 百万智能体规模下的 Provider 负载\n')
lines.append(md_table(t3, list(t3[0].keys())))
lines.append('\n## 表 D 摊销开销复算 (ms)\n')
lines.append(md_table(amort, list(amort[0].keys())))
lines.append('\n## 表 E 任务开销占比复算 (%)\n')
lines.append(md_table([{'任务': k, 'SAGA 开销占比(%)': v} for k, v in recheck['task_overhead_ratio'].items()], ['任务', 'SAGA 开销占比(%)']))
lines.append('\n## 表 F 容量复算 C=T·L\n')
lines.append(md_table(recheck['capacity'], ['throughput_req_per_min', 'label', 'L_hours', 'agents']))
open(os.path.join(OUT, 'results.md'), 'w').write('\n'.join(lines))
print('\n'.join(lines))

