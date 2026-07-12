"""
Bulk-plane confirmation attack. Adversary suppresses A in chosen bulk rounds and
correlates the suppression schedule with each candidate receiver's observed bulk
inflow, to confirm A<->B.

Three regimes:
  L0/L1 opt-in     : endpoints send bulk ONLY when they have real data. B's inflow
                     drops when A is suppressed -> confirmation.
  L2 const-partic  : every endpoint sends a uniform flow every round (dummy if
                     idle) BUT the adversary can still block A entirely -> the
                     round shows one fewer flow unless a relay fills it.
  L2 const-count   : rendezvous relays keep the observed flow COUNT constant every
                     round via bulk loop-cover (fill A's slot when suppressed).
                     Observable is constant -> confirmation defeated (like hard-cap).

Metric: P(adversary ranks B #1 among M receivers), baseline 1/M.
Then: the confirmation-resistant FILE-SIZE CEILING set by the cover budget.
"""
import numpy as np
rng = np.random.default_rng(77)

def bulk_confirm(regime, M=30, s_rate=0.6, bg=2.0, R=400, probe=0.5, trials=300):
    hits = 0
    for _ in range(trials):
        B = rng.integers(M)
        probe_r = rng.random(R) < probe
        a_real = (rng.random(R) < s_rate).astype(float)   # A has real bulk this round
        a_real[probe_r] = 0                                # suppression zeroes it
        bg_flows = rng.poisson(bg, size=(R, M)).astype(float)
        obs = bg_flows.copy()
        obs[:, B] += a_real                                # B receives A's bulk

        if regime == "const_partic":
            # A sends a dummy when idle, so real vs dummy indistinguishable...
            # but suppression BLOCKS A entirely -> B still loses the flow.
            # (A's dummy would have gone to a random decoy, not B, so B still drops)
            pass                                           # same observable drop at B
        elif regime == "const_count":
            # relays keep every receiver's observed count constant each round
            obs[:] = float(round(bg + 1))                  # constant, no signal

        # adversary: correlate suppression with observed inflow drop
        p = probe_r.astype(float) - probe_r.mean()
        score = np.abs((obs * p[:, None]).sum(axis=0))
        if np.argmax(score) == B:
            hits += 1
    return hits / trials

if __name__ == "__main__":
    M = 30
    print(f"random baseline = {1/M:.3f}\n")
    print("=== Bulk-plane confirmation: P(confirm A<->B) ===")
    for regime in ["opt_in", "const_partic", "const_count"]:
        print(f"  {regime:<14} {bulk_confirm(regime, M=M):.3f}")
    print("\nopt-in & const-partic leak (suppression removes B's flow);")
    print("only const-count (relay bulk loop-cover) reaches baseline -- but that")
    print("cover is a FULL UNIFORM BULK FLOW per filled slot => expensive.\n")

    print("=== Confirmation-resistant FILE-SIZE CEILING ===")
    print("F_max = cover_budget * T_round / (C_flows - avg_real_flows)")
    print("(largest file that can be hidden per round given a cover bandwidth)\n")
    C_flows = 8            # uniform flows kept constant per round
    avg_real = 3           # avg real flows per round
    print(f"{'cover budget':>14} | {'T_round':>8} | {'F_max per flow':>16}")
    for cover_MBs in [10, 50, 200]:          # MB/s of cover the relays can spend
        for T in [60, 300, 900]:             # round period seconds
            F = cover_MBs * T / (C_flows - avg_real)   # MB
            print(f"{cover_MBs:>11} MB/s | {T:>6}s | {F:>13.0f} MB")
    print("\nAbove F_max: FRAGMENT the file across many rounds (-> pays mixnet-class")
    print("cost) or accept confirmation exposure. Confirmation-resistant bulk has a")
    print("hard size ceiling = cover_budget x round_period. No way around it.")
