"""
Phase 1 open question: can an ACTIVE adversary defeat receiver padding?

Attack (confirmation via sender suppression): adversary suspects S<->R and can
suppress S's real traffic in chosen "probe" epochs (compromised guard/link near S).
It then correlates the suppression schedule with R's OBSERVABLE volume.

Two padding schemes:
  PAD_UP  : observable = max(real, Q).  Overflow (real>Q) is VISIBLE. When the
            adversary suppresses S, R's overflow shrinks -> correlation -> leak.
  HARD_CAP: observable = exactly Q ALWAYS. Excess real (>Q) is queued/delayed to
            later epochs, never shown. Degrades LATENCY, never emission shape.
            Prediction: zero correlation -> active attack defeated at any Q>=mean.

Metric: P(adversary ranks R #1 among M receivers by |corr(suppress, drop)|).
Also: HARD_CAP receiver-side backlog (latency cost) vs Q/mean.
"""
import numpy as np
rng = np.random.default_rng(31)

def confirm_attack(scheme, M=30, s_rate=3.0, bg=8.0, Q=25, probe_frac=0.5,
                   E=400, trials=300):
    hits = 0
    for _ in range(trials):
        R = rng.integers(M)
        probe = rng.random(E) < probe_frac         # epochs where S is suppressed
        s_real = rng.poisson(s_rate, E)
        s_real[probe] = 0                          # suppression zeroes S->R
        bg_counts = rng.poisson(bg, size=(E, M)).astype(float)
        real = bg_counts.copy()
        real[:, R] += s_real

        if scheme == "pad_up":
            obs = np.maximum(real, Q)
        else:  # hard_cap: observable is exactly Q every epoch (excess queued away)
            obs = np.full_like(real, float(Q))

        # adversary statistic: correlation between suppression and observed drop.
        # (Q - obs) is the "how far below cap" signal; suppression should raise it
        # for the true R under pad_up (overflow vanishes), zero for hard_cap.
        drop = Q - obs                              # >=0 under pad_up only when no overflow
        p = probe.astype(float) - probe.mean()
        scores = np.abs((drop * p[:, None]).sum(axis=0))   # |covariance| per receiver
        if np.argmax(scores) == R:
            hits += 1
    return hits / trials

def hardcap_backlog(Q, s_rate=3.0, bg=8.0, E=100000):
    """Receiver-side queue if we cap observable at Q and defer excess. Backlog
    grows when real arrivals exceed Q. Returns mean & p99 deferred-latency (epochs)."""
    real = rng.poisson(bg + s_rate, E)             # total real at the busy receiver
    backlog = 0
    waits = []
    for r in real:
        backlog += r
        served = min(backlog, Q)                    # only Q leave (as real) per epoch
        backlog -= served
        # crude latency proxy: current backlog / throughput Q = epochs to drain
        waits.append(backlog / Q)
    w = np.array(waits)
    return real.mean(), float(w.mean()), float(np.percentile(w, 99))

if __name__ == "__main__":
    M = 30; base = 1/M
    print(f"random baseline = {base:.3f}\n")
    print("=== ACTIVE confirmation attack: P(confirm S<->R) vs quota Q ===")
    print(f"(bg mean=8, S adds 3; suppression on 50% of {400} epochs)\n")
    print(f"{'Q':>4} | {'Q/mean_bg':>9} | {'PAD_UP':>8} | {'HARD_CAP':>9}")
    for Q in [12, 15, 18, 22, 25, 30]:
        pu = confirm_attack("pad_up", M=M, Q=Q)
        hc = confirm_attack("hard_cap", M=M, Q=Q)
        print(f"{Q:>4} | {Q/8:>9.2f} | {pu:>8.3f} | {hc:>9.3f}")

    print("\n=== HARD_CAP cost: receiver-side deferral latency vs Q ===")
    print("(busy receiver, real mean = bg+s = 11 msgs/epoch)\n")
    print(f"{'Q':>4} | {'Q/real_mean':>11} | {'mean defer':>11} | {'p99 defer':>10}")
    for Q in [11, 12, 13, 15, 18, 25]:
        rm, mw, p99 = hardcap_backlog(Q)
        print(f"{Q:>4} | {Q/rm:>11.2f} | {mw:>9.2f}ep | {p99:>8.2f}ep")
