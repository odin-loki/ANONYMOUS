"""
Traffic shapeability: a Gaussian AND non-Gaussian capable model, run through the
hard-cap shaper, to price the cost of realistic (heavy-tailed, self-similar)
traffic vs benign (Gaussian) traffic.

Two axes of "non-Gaussianness", both tested:
  (1) MARGINAL tail  : per-slot count ~ Normal (thin) ... Pareto (heavy).
  (2) TEMPORAL corr. : ON/OFF source aggregate. Exponential ON/OFF -> Gaussian/
      short-range-dependent aggregate. Pareto ON/OFF (alpha in (1,2)) -> self-
      similar, long-range-dependent aggregate (Willinger/Taqqu; Hurst H=(3-a)/2).
      This is THE canonical realistic network-traffic model.

Shaper = hard-cap at C = c * mean cells/slot, excess DEFERRED (FIFO). Security is
invariant by construction (observable output = C every slot). We therefore measure
only the COST: deferral-latency distribution (mean, p99, p99.9) and stability.
"""
import numpy as np
rng = np.random.default_rng(42)

# ---------- unified marginal generator, all normalized to the same mean m ----------
def marginal_counts(kind, n, m=10.0):
    if kind == "gaussian":
        x = rng.normal(m, m*0.35, n)                 # CV=0.35, thin
    elif kind == "lognormal":
        s = 0.75                                      # moderate tail
        x = rng.lognormal(np.log(m) - s*s/2, s, n)    # mean = m
    elif kind.startswith("pareto"):
        a = float(kind.split("_")[1])                 # tail index a
        xm = m*(a-1)/a                                # so mean = m (a>1)
        x = (rng.pareto(a, n) + 1)*xm
    x = np.clip(np.round(x), 0, None)
    return x

# ---------- ON/OFF aggregate: exponential (Gaussian-ish) vs Pareto (self-similar) --
def onoff_aggregate(kind, n_slots, n_sources=200, m_target=10.0):
    """Aggregate active-source count per slot. Pareto ON/OFF -> self-similar."""
    peak = np.zeros(n_slots)
    for _ in range(n_sources):
        t = 0
        on = rng.random() < 0.5
        while t < n_slots:
            if kind == "exp":
                dur = int(np.ceil(rng.exponential(5)))
            else:  # pareto ON/OFF, tail index a
                a = float(kind.split("_")[1])
                dur = int(np.ceil((rng.pareto(a)+1)*3*(a-1)/a))
            dur = max(dur, 1)
            if on:
                peak[t:min(t+dur, n_slots)] += 1
            on = not on
            t += dur
    # scale aggregate to target mean
    peak = peak * (m_target / max(peak.mean(), 1e-9))
    return np.round(peak)

# ---------- hard-cap shaper: cap at C, defer excess FIFO, track backlog latency ----
def shape_cost(counts, c):
    m = counts.mean()
    C = c * m
    backlog = 0.0
    lat = np.empty(len(counts))          # backlog/C = slots-of-work waiting
    for i, x in enumerate(counts):
        backlog += x
        served = min(backlog, C)
        backlog -= served
        lat[i] = backlog / C             # deferral in slot units
    return dict(mean=float(lat.mean()),
                p99=float(np.percentile(lat, 99)),
                p999=float(np.percentile(lat, 99.9)),
                stable=bool(m < C))       # rho<1 stability

def hurst_est(x):
    # rough R/S-free variance-of-aggregated-series Hurst estimate
    x = x - x.mean(); N = len(x)
    ms = [1,2,4,8,16,32,64]
    var = []
    for mm in ms:
        k = N//mm
        agg = x[:k*mm].reshape(k, mm).mean(axis=1)
        var.append(agg.var())
    var = np.array(var); ms = np.array(ms)
    # var(aggregated) ~ m^(2H-2)
    b = np.polyfit(np.log(ms), np.log(var+1e-12), 1)[0]
    return (b + 2) / 2

if __name__ == "__main__":
    N = 60000
    print("=== EXPERIMENT 1: MARGINAL tail -> shaping-latency cost ===")
    print("(hard-cap at c*mean; latency in slot-units; security invariant)\n")
    print(f"{'distribution':<14} {'CV':>6} | " + "  ".join(f"c={c}:p99/p999" for c in [1.2,1.5,2.0]))
    for kind in ["gaussian","lognormal","pareto_2.5","pareto_1.5"]:
        x = marginal_counts(kind, N)
        cv = x.std()/x.mean()
        cells = []
        for c in [1.2,1.5,2.0]:
            r = shape_cost(x, c)
            cells.append(f"{r['p99']:.1f}/{r['p999']:.1f}")
        print(f"{kind:<14} {cv:>6.2f} | " + "     ".join(cells))

    print("\n=== EXPERIMENT 2: TEMPORAL self-similarity -> shaping-latency cost ===")
    print("(ON/OFF aggregate; Hurst ~0.5 = Gaussian/SRD, ->1 = self-similar/LRD)\n")
    print(f"{'ON/OFF model':<14} {'Hurst':>6} {'CV':>6} | " + "  ".join(f"c={c}:p99/p999" for c in [1.2,1.5,2.0,3.0]))
    for kind in ["exp","pareto_1.8","pareto_1.4","pareto_1.2"]:
        x = onoff_aggregate(kind, N, n_sources=150)
        H = hurst_est(x); cv = x.std()/x.mean()
        cells = []
        for c in [1.2,1.5,2.0,3.0]:
            r = shape_cost(x, c)
            cells.append(f"{r['p99']:.1f}/{r['p999']:.1f}")
        print(f"{kind:<14} {H:>6.2f} {cv:>6.2f} | " + "   ".join(cells))
    print("\n(security is identical across ALL rows: observable output = C every slot.")
    print(" the entire cost of non-Gaussian traffic is the latency tail above.)")
