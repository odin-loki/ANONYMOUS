"""
Designing around Attack A. Lesson: the leak is the SENDER'S EMISSION PROCESS.
Poisson cover still leaves a Poisson-rate signature. Test the fix:

  v2   : real Poisson + dummy Poisson cover (variance in emission -> leaks rate)
  v2.1 : CONSTANT-RATE sending. Every client emits exactly one cell per slot tau,
         real if queued else dummy. All clients' emission processes are IDENTICAL
         -> zero timing information at the entry.

We test TWO adversaries at EQUAL bandwidth:
  (1) timing adversary  : matches sender injection times to receiver arrivals
  (2) volume adversary  : matches per-sender real COUNT to receiver arrival count
                          (worst case: assumes adversary can meter sender volume)
and a volume-padded variant where every receiver is filled to a fixed quota.
"""
import numpy as np
from math import lgamma
from scipy.optimize import linear_sum_assignment
rng = np.random.default_rng(3)

def gpdf(x, L, s):
    out = np.zeros_like(x); m = x > 0; xv = x[m]
    out[m] = np.exp((L-1)*np.log(xv) - xv/s - L*np.log(s) - lgamma(L))
    return out

def timing_match(sender_times, recv, L, scale, M):
    S = np.zeros((M, M))
    for i in range(M):
        ts = sender_times[i]
        if len(ts) == 0: continue
        for j in range(M):
            ra = recv[j]
            if len(ra) == 0: continue
            d = ra[:, None] - ts[None, :]
            per = gpdf(d, L, scale).sum(axis=1) / len(ts)
            S[i, j] = np.log(per + 1e-12).sum()
    r, c = linear_sum_assignment(-S)
    return S, r, c

def run(mode, M=25, L=3, mu=1.0, R=2.0, real_frac=0.5, T=60.0, n_trials=10,
        pad_quota=None):
    """R = total emission rate (cells/s). real_frac = fraction of capacity that is real."""
    scale = 1/mu
    lam_real = R * real_frac
    accs_t, accs_v = [], []
    for _ in range(n_trials):
        perm = rng.permutation(M)
        sender_times, real_counts = [], []
        recv = [[] for _ in range(M)]
        for i in range(M):
            if mode == "poisson":
                # real Poisson + dummy Poisson cover, random times
                nr = rng.poisson(lam_real * T)
                tr = np.sort(rng.uniform(0, T, nr))
                nc = rng.poisson((R - lam_real) * T)
                tc = np.sort(rng.uniform(0, T, nc))
                sender_times.append(np.sort(np.concatenate([tr, tc])))
                real_counts.append(nr)
                recv[perm[i]].extend((tr + rng.gamma(L, scale, nr)).tolist())
            else:  # constant-rate grid
                slots = np.arange(0, T, 1.0/R)
                is_real = rng.random(len(slots)) < real_frac
                tr = slots[is_real]
                sender_times.append(slots)          # identical grid for everyone
                real_counts.append(len(tr))
                recv[perm[i]].extend((tr + rng.gamma(L, scale, len(tr))).tolist())
        # optional receiver-side volume padding to a fixed quota
        if pad_quota is not None:
            for j in range(M):
                deficit = pad_quota - len(recv[j])
                if deficit > 0:
                    recv[j].extend(rng.uniform(0, T + 6*scale*L, deficit).tolist())
        recv = [np.sort(np.array(r)) for r in recv]

        # (1) timing adversary
        _, r, c = timing_match(sender_times, recv, L, scale, M)
        accs_t.append(np.mean(c == perm[r]))
        # (2) volume adversary: match real_counts[i] to len(recv[j])
        rc = np.array(real_counts, float)
        rv = np.array([len(recv[j]) for j in range(M)], float)
        Sv = -np.abs(rc[:, None] - rv[None, :])     # closer counts = higher score
        r2, c2 = linear_sum_assignment(-Sv)
        accs_v.append(np.mean(c2 == perm[r2]))
    return float(np.mean(accs_t)), float(np.mean(accs_v))

if __name__ == "__main__":
    M = 25; base = 1/M
    print(f"random baseline = {base:.3f}  (M={M})\n")
    print(f"{'design':<34}{'timing adv':>12}{'volume adv':>12}")
    t,v = run("poisson", M=M);            print(f"{'v2  Poisson cover (2x bw)':<34}{t:>12.3f}{v:>12.3f}")
    t,v = run("const",   M=M);            print(f"{'v2.1 constant-rate (2x bw)':<34}{t:>12.3f}{v:>12.3f}")
    t,v = run("const",   M=M, pad_quota=None); 
    t,v = run("const",   M=M, pad_quota=45); print(f"{'v2.1 const-rate + vol padding':<34}{t:>12.3f}{v:>12.3f}")
    print()
    print("timing adv = matches injection times; volume adv = matches real msg counts")
    print("(volume adv is worst-case: assumes adversary can meter per-sender real volume)")
