"""
Long-term intersection (statistical disclosure) attack.

A persistent sender S talks to a FIXED receiver R across many epochs. Adversary
accumulates observations and tries to identify R among M candidate receivers.
This is the attack that historically erodes mixnets: any per-epoch leak > 0,
integrated over enough epochs, compounds to certainty.

We compare what the ADVERSARY CAN OBSERVE under each design (same underlying
real traffic in all cases):

  A. Poisson cover      : adversary sees S's real per-epoch send COUNT (emission
                          bursts are visible) -> weights receiver counts by it.
  B. constant-rate only : S emits an identical constant stream -> adversary CANNOT
                          see S's per-epoch signal. Falls back to receiver-side
                          cumulative volume (mean-shift attack): R carries S's
                          extra traffic, so R's mean count is higher than decoys.
  C. const-rate + pad(HIGH) : every receiver padded UP to quota Q above peak
                          volume -> observed counts identical -> no signal.
  D. const-rate + pad(LOW)  : Q set too low -> R (higher mean) OVERFLOWS the quota
                          in busy epochs; those epochs leak (padding can only pad
                          UP, never hide real > Q).

Metric: P(adversary ranks R #1 among M receivers) vs number of epochs.
"""
import numpy as np
rng = np.random.default_rng(20)

def run_intersection(mode, M=30, s_rate=3.0, bg=8.0, Q=None,
                     epoch_grid=(5,10,25,50,100,200,400,800), trials=300):
    """
    M       : candidate receivers
    s_rate  : mean real msgs/epoch S sends to R (the hidden signal)
    bg      : mean background real arrivals/epoch at EACH receiver
    Q       : padding quota (None = no padding)
    """
    Emax = max(epoch_grid)
    hits = {E: 0 for E in epoch_grid}
    for _ in range(trials):
        R = rng.integers(M)                       # hidden true partner
        # per-epoch real arrivals at each receiver from background
        bg_counts = rng.poisson(bg, size=(Emax, M)).astype(float)
        # S's real contribution to R each epoch
        s_counts = rng.poisson(s_rate, size=Emax).astype(float)
        obs = bg_counts.copy()
        obs[:, R] += s_counts                      # R gets S's real traffic

        # adversary's per-epoch observable + statistic
        if mode == "poisson":
            # adversary sees S's real count per epoch; weight receiver counts by it
            w = s_counts - s_counts.mean()
            stat_per_epoch = obs * w[:, None]      # covariance contribution
        else:
            # constant-rate: no S signal. optionally apply padding to observation.
            observed = obs.copy()
            if Q is not None:
                observed = np.maximum(observed, Q)  # pad UP to Q (can't go below real)
            # mean-shift statistic: cumulative volume per receiver
            stat_per_epoch = observed

        cum = np.zeros(M)
        gi = 0
        for e in range(Emax):
            cum += stat_per_epoch[e]
            if e + 1 == epoch_grid[gi]:
                if np.argmax(cum) == R:
                    hits[epoch_grid[gi]] += 1
                gi += 1
                if gi >= len(epoch_grid):
                    break
    return {E: hits[E] / trials for E in epoch_grid}

if __name__ == "__main__":
    import json
    M = 30; base = 1/M
    print(f"random baseline P(rank R #1) = {base:.3f}   (M={M})\n")

    configs = {
        "A_poisson":        dict(mode="poisson"),
        "B_constrate_only": dict(mode="const", Q=None),
        "C_pad_HIGH_Q30":   dict(mode="const", Q=30),   # above peak (bg~8 + s~3, peak<30)
        "D_pad_LOW_Q12":    dict(mode="const", Q=12),    # R often overflows -> leaks
    }
    out = {"baseline": base, "epochs": [5,10,25,50,100,200,400,800], "series": {}}
    for name, kw in configs.items():
        r = run_intersection(M=M, **kw)
        out["series"][name] = [round(r[E],3) for E in out["epochs"]]
        print(f"{name:<20} " + "  ".join(f"{r[E]:.2f}" for E in out["epochs"]))
    print("\ncolumns = epochs:", out["epochs"])
    json.dump(out, open("intersection.json","w"))
