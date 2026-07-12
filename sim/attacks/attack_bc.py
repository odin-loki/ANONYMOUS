"""
Attack B (tests my own C5 claim): predecessor / guard-exposure attack.
Attack C: full-path compromise vs honest-mix fraction.
Plus: latency + bandwidth profiling and the anonymity/latency/bandwidth triangle.
"""
import numpy as np
rng = np.random.default_rng(11)

# ---------------------------------------------------------------------------
# ATTACK B: guard exposure over time. Adversary controls fraction c of relays.
# A client builds one circuit per epoch. "Entry exposure" = the client's entry
# node is adversary-controlled on that circuit (predecessor attack foothold).
# Compare: fresh-random entry each epoch vs a STABLE guard set of size g.
# Metric: P(entry exposed at least once) after k epochs.
# ---------------------------------------------------------------------------
def guard_exposure(c=0.1, g=3, k_max=2000, trials=4000):
    ks = np.array([1, 5, 10, 50, 100, 500, 1000, 2000])
    rot = []   # rotating (fresh random entry each epoch)
    sta = []   # stable guard set
    for k in ks:
        # rotating: exposed at least once if any of k independent draws is malicious
        rot.append(1 - (1 - c) ** k)
        # stable: client fixes g guards once; exposed at least once over k epochs
        # iff at least one chosen guard is malicious AND it gets used within k.
        # With g guards used uniformly, prob a malicious guard is used within k
        # epochs is ~1 for k>>g, so exposure prob -> P(any guard malicious).
        exposed = 0
        for _ in range(trials):
            guards_mal = rng.random(g) < c
            if not guards_mal.any():
                continue                      # never exposed, any k
            # simulate usage: exposed once a malicious guard is picked
            picks = rng.integers(0, g, size=k)
            if guards_mal[picks].any():
                exposed += 1
        sta.append(exposed / trials)
    return ks, np.array(rot), np.array(sta)

# ---------------------------------------------------------------------------
# ATTACK C: probability the ENTIRE path is adversary-controlled (full e2e
# deanonymization) as a function of honest fraction. Random selection => f^L.
# Compare path lengths L=2,3,4. Also show guard effect on entry.
# ---------------------------------------------------------------------------
def path_compromise():
    cs = np.linspace(0.0, 0.5, 11)   # adversary fraction
    res = {}
    for L in [2, 3, 4]:
        res[L] = (cs ** L)           # all L hops malicious
    return cs, res

# ---------------------------------------------------------------------------
# PROFILING: latency ~ Gamma(L, 1/mu); bandwidth overhead from cover.
# Goodput fraction = real / (real + cover). Tie it to Attack A anonymity.
# ---------------------------------------------------------------------------
def profile_latency(L=3, mu=1.0, n=200000):
    d = rng.gamma(L, 1/mu, n)
    return dict(mean=float(d.mean()), p50=float(np.percentile(d,50)),
                p95=float(np.percentile(d,95)), p99=float(np.percentile(d,99)))

if __name__ == "__main__":
    import json
    out = {}

    print("=== ATTACK B: guard exposure, adversary controls c=10% of relays ===")
    ks, rot, sta = guard_exposure(c=0.10, g=3)
    out["guard_c10"] = {"k": ks.tolist(), "rotating": rot.round(3).tolist(),
                        "stable_g3": sta.round(3).tolist()}
    print(f"{'epochs':>8} | {'rotating':>9} | {'stable(g=3)':>11}")
    for i,k in enumerate(ks):
        print(f"{k:>8} | {rot[i]:>9.3f} | {sta[i]:>11.3f}")
    print("plateau for stable = 1-(1-c)^g =", round(1-(0.9**3),3))

    print("\n=== ATTACK C: full-path compromise = f^L ===")
    cs, res = path_compromise()
    out["path"] = {"c": cs.round(2).tolist(),
                   **{f"L{L}": res[L].round(4).tolist() for L in res}}
    print(f"{'adv frac':>9} | {'L=2':>7} | {'L=3':>7} | {'L=4':>7}")
    for i,c in enumerate(cs):
        print(f"{c:>9.2f} | {res[2][i]:>7.4f} | {res[3][i]:>7.4f} | {res[4][i]:>7.4f}")

    print("\n=== PROFILING: end-to-end latency (L=3) ===")
    out["latency"] = {}
    print(f"{'mean hop':>9} | {'e2e mean':>9} | {'p95':>7} | {'p99':>7}")
    for mu in [10.0, 2.0, 1.0, 0.5]:
        p = profile_latency(L=3, mu=mu)
        out["latency"][1/mu] = p
        print(f"{1/mu:>7.2f}s | {p['mean']:>7.2f}s | {p['p95']:>5.2f}s | {p['p99']:>5.2f}s")

    print("\n=== THE TRADEOFF (pairing Attack A anonymity w/ cost) ===")
    print("cover=8x gave match acc 0.12 (best tested) but costs 8x bandwidth +")
    print("mixing 1s/hop => 3s mean e2e latency. cover=0 is free+fast but acc=1.0.")

    with open("results_bc.json","w") as f: json.dump(out, f)
    print("\nsaved results_bc.json")
