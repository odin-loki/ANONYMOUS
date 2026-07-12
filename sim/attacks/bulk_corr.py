"""
Testing the dual-mode claim on the BULK data plane.

Scenario: k concurrent bulk transfers meet at a rendezvous RP in a window.
Adversary (GPA) sees the A-side flows entering RP (size, start-time) and the
B-side flows leaving RP (size, start-time+delay), and matches them to recover
who-sent-to-whom. This tests whether "negotiate a short hop and go P2P/rendezvous"
actually hides the bulk RELATIONSHIP, or just the setup.

Configs (increasing defense):
  raw            : real file sizes (heavy-tailed), random start times.
  size_quantized : sizes rounded up to B coarse buckets (pad to bucket).
  quant+rounds   : sizes bucketed AND starts aligned to synchronized rounds.
  uniform        : every flow padded to the SAME size and started in the SAME
                   round (full traffic-flow security for bulk).

Metric: P(adversary correctly matches a given A-flow to its B-flow), baseline 1/k.
"""
import numpy as np
from scipy.optimize import linear_sum_assignment
rng = np.random.default_rng(9)

def bulk_match(config, k=20, W=100.0, n_buckets=4, n_rounds=5, trials=200):
    accs = []
    for _ in range(trials):
        # real file sizes: heavy-tailed (Pareto) -> highly distinctive
        sizes = (rng.pareto(1.5, k) + 1) * 100
        starts = rng.uniform(0, W, k)

        a_size, a_time = sizes.copy(), starts.copy()
        if config in ("size_quantized", "quant+rounds", "uniform"):
            # pad each size UP to its bucket's ceiling (log-spaced buckets)
            edges = np.geomspace(sizes.min(), sizes.max()+1, n_buckets+1)
            idx = np.clip(np.digitize(sizes, edges)-1, 0, n_buckets-1)
            a_size = edges[idx+1]                      # padded size (bucket ceiling)
        if config in ("quant+rounds", "uniform"):
            # align starts to nearest of n_rounds synchronized round times
            round_times = np.linspace(0, W, n_rounds)
            a_time = round_times[np.argmin(np.abs(starts[:,None]-round_times[None,:]),axis=1)]
        if config == "uniform":
            a_size = np.full(k, a_size.max())          # pad ALL to the max size
            a_time = np.full(k, 0.0)                    # all in one round

        # B-side = same flows after RP (tiny relay delay + jitter)
        b_size = a_size.copy()
        b_time = a_time + rng.normal(0.5, 0.2, k)
        perm = rng.permutation(k)
        b_size, b_time = b_size[perm], b_time[perm]

        # adversary cost: normalized (size,time) distance; Hungarian assignment
        sN = (a_size[:,None]-b_size[None,:]) / (a_size.std()+1e-9)
        tN = (a_time[:,None]-b_time[None,:]) / (a_time.std()+1e-9)
        cost = sN**2 + tN**2
        r,c = linear_sum_assignment(cost)
        # did A-flow r[i] get matched to its true B position (where perm sent it)?
        true_bpos = np.argsort(perm)                   # a-flow i -> b index
        accs.append(np.mean(c[r]==true_bpos[r]))
    return float(np.mean(accs))

if __name__ == "__main__":
    for k in [10, 20, 40]:
        print(f"\n=== {k} concurrent bulk transfers (random baseline = {1/k:.3f}) ===")
        for cfg in ["raw","size_quantized","quant+rounds","uniform"]:
            acc = bulk_match(cfg, k=k)
            print(f"  {cfg:<16} P(relationship recovered) = {acc:.3f}")
    print("\nraw/rendezvous bulk -> relationship trivially recovered (no anonymity set).")
    print("only UNIFORM (pad all to max size + single round) approaches baseline -")
    print("i.e. bulk hiding costs the SAME padding the mixnet does. no free lunch.")
