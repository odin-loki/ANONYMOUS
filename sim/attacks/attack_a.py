import numpy as np
from math import lgamma
from scipy.optimize import linear_sum_assignment

rng = np.random.default_rng(7)

def gamma_pdf(x, L, scale):
    # integer/real shape L, scale; x can be array. 0 for x<=0.
    out = np.zeros_like(x)
    m = x > 0
    xv = x[m]
    logp = (L - 1) * np.log(xv) - xv / scale - L * np.log(scale) - lgamma(L)
    out[m] = np.exp(logp)
    return out

def simulate(M=25, L=3, mu=1.0, lam_real=0.5, cover_ratio=0.0, T=60.0, n_trials=8):
    scale = 1.0 / mu
    accs = []
    for _ in range(n_trials):
        perm = rng.permutation(M)
        sender_times = []
        recv = [[] for _ in range(M)]
        for i in range(M):
            n = rng.poisson(lam_real * T)
            ts = np.sort(rng.uniform(0, T, size=n))
            sender_times.append(ts)
            recv[perm[i]].extend((ts + rng.gamma(L, scale, n)).tolist())
        for j in range(M):
            nr = len(recv[j])
            nc = rng.poisson(cover_ratio * max(nr, 1))
            recv[j].extend(rng.uniform(0, T + 6*scale*L, nc).tolist())
        recv = [np.sort(np.array(r)) for r in recv]

        S = np.zeros((M, M))
        for i in range(M):
            ts = sender_times[i]
            if len(ts) == 0:
                continue
            for j in range(M):
                ra = recv[j]
                if len(ra) == 0:
                    continue
                d = ra[:, None] - ts[None, :]
                per_arr = gamma_pdf(d, L, scale).sum(axis=1) / len(ts)
                S[i, j] = np.log(per_arr + 1e-12).sum()
        row, col = linear_sum_assignment(-S)
        accs.append(np.mean(col == perm[row]))
    return float(np.mean(accs))

if __name__ == "__main__":
    import sys, json
    M = 25
    base = 1.0 / M
    out = {"baseline": base, "delay": [], "cover": [], "volume": []}
    for mu in [50.0, 5.0, 1.0, 0.5, 0.2]:
        out["delay"].append((round(1/mu,3), round(simulate(M=M, mu=mu, cover_ratio=0.0),3)))
    for cr in [0.0, 1.0, 2.0, 4.0, 8.0]:
        out["cover"].append((cr, round(simulate(M=M, mu=1.0, cover_ratio=cr),3)))
    for lr in [0.25, 0.5, 1.0, 2.0]:
        out["volume"].append((int(lr*60), round(simulate(M=M, mu=1.0, lam_real=lr, cover_ratio=2.0),3)))
    print(json.dumps(out))
