import numpy as np
from shapeability import shape_cost, hurst_est
rng = np.random.default_rng(7)

def onoff(kind, n_slots, n_sources=25):
    """Aggregate of n_sources ON/OFF sources, each contributing 1/slot when ON.
    Burstiness PRESERVED (no over-averaging). Pareto ON -> self-similar/LRD."""
    agg = np.zeros(n_slots)
    for _ in range(n_sources):
        t = 0; on = rng.random() < 0.5
        while t < n_slots:
            if kind == "exp":
                dur = max(1, int(rng.exponential(6)))
            else:
                a = float(kind.split("_")[1])
                dur = max(1, int((rng.pareto(a)+1)*2))   # heavy-tailed ON/OFF
            if on: agg[t:min(t+dur,n_slots)] += 1
            on = not on; t += dur
    return agg

N = 120000
print("=== EXPERIMENT 2 (fixed): temporal self-similarity, burstiness preserved ===")
print("ON/OFF aggregate of 25 heavy sources; hard-cap at c*mean, defer excess\n")
print(f"{'model':<12} {'Hurst':>6} {'CV':>6} | " + "  ".join(f"c={c}:p99/p999/stable" for c in [1.5,2.0,3.0]))
for kind in ["exp","pareto_1.9","pareto_1.5","pareto_1.2"]:
    x = onoff(kind, N)
    H = hurst_est(x); cv = x.std()/x.mean()
    cells = []
    for c in [1.5,2.0,3.0]:
        r = shape_cost(x, c)
        cells.append(f"{r['p99']:.1f}/{r['p999']:.1f}/{'Y' if r['stable'] else 'N'}")
    print(f"{kind:<12} {H:>6.2f} {cv:>6.2f} | " + "  ".join(cells))
print("\nlatency in slot-units; stable=Y means mean<cap (queue does not run away)")
print("compare to Poisson/M-D-1 (earlier): p99~7 slots at rho=0.7 i.e. c~1.43")
