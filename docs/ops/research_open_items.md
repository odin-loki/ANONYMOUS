# AEGIS — Spec §13 Research Open Items (in-repo simulation)

This document records **in-repo** characterization work for spec §13 open items
that can be advanced without hardware, fake crypto proofs, or operational traces.
Status tags: **[O]** open / not mitigated; **[O → QUANTIFIED]** simulated limits
documented honestly.

See also `docs/AEGIS_phase8_hardening_notes.md` for Phase 8 context.

---

## A) Adaptive compromised-mix set [O → QUANTIFIED]

**Spec:** "Adaptive adversary varying the compromised-mix set across epochs."

**Simulator:** `sim/aegis_sim/adversaries.py`
- `adaptive_guard_exposure(c, g, epochs, mode)` — single horizon
- `adaptive_guard_exposure_curve(...)` — static plateau vs adaptive growth

**Parameters (committed artifact):**
| Param | Value | Notes |
|-------|-------|-------|
| `c` | 0.015 | per-relay compromise probability (free parameter) |
| `g` | 3 | stable guard set size |
| `epoch_grid` | 5…2000 | adaptive redraw each epoch |
| `trials` | 20000 | Monte Carlo |

**Findings (characterizes, does not close):**
- `mode='static'`: exposure plateaus at `1-(1-c)^g` (control; matches §12).
- `mode='adaptive'`: exposure **grows with horizon** even for a stable guard set.
- `mode='mitigated_first'`: v1 baseline — sticky cap + demotion on signal.
- `mode='mitigated'`: v2 — tighter cap, stronger demotion, linger after dirty; **~13 pp lower than v1 at E=200**.
- `mode='mitigated_aggressive'`: v2 second tier — extra demotion on dirty epoch.
- `mode='mitigated_v3'`: v3 — hard epoch-age cap 4, decaying stickiness, reputation soft rotate; **~32 pp lower than v2 at E=200**; still saturates toward 1.0 at E=2000.
- See [`adaptive_guard_mitigation.md`](adaptive_guard_mitigation.md).

**Artifact:** `sim/data/adaptive_guard_exposure.analysis.json` (includes `mitigated_v3_by_epochs`, `mitigated_by_epochs`, `mitigation_at_200`)
**Sweeps:** `sim/data/adaptive_mitigation_sweep.json`, `adaptive_mitigation_offline.json` via `sim/scripts/sweep_adaptive_mitigation.py`

**Pytest:** `sim/tests/test_hardening.py` (`test_adaptive_*`, `test_mitigated_v3_*`)

**Honest limit:** Real adversary recompromise *rate* is unknown; this models
independent per-epoch redraw, not detected/slow recompromise.

---

## B) Combined active(n-1) + intersection long horizon [O → QUANTIFIED]

**Spec:** "Combined active(n-1)+intersection over long horizons on Mode 1."

**Simulator:** `sim/aegis_sim/combined_active_intersection.py` (re-exported from `adversaries.py`)
- `combined_active_intersection(scheme, E, ...)` — single horizon
- `combined_active_intersection_curve(...)` — P(deanonymize) vs epochs
- `combined_attack_defense_report(...)` — ranking + sensitivity + offline horizons
- `sensitivity_to_anonymity_set` / `sensitivity_to_padding_budget` — M and Q sweeps

**Mode-1 schemes (ranked in artifact):**
| Scheme | Observable | Expected |
|--------|------------|----------|
| `constant_only` | raw counts | both components leak; → ~1.0 by long E |
| `pad_up` | max(real, Q) | fails; high Q helps but stays above baseline |
| `truncate_only` | min(real, Q) | leaks (no dummy fill) |
| `noisy_hard_cap` | Q + 0.4·(real−Q) | partial transparency; saturates |
| `deferred_hard_cap` | exactly Q (FIFO defer model) | ties `hard_cap`; maps to `HardCapPadder` |
| `hard_cap` | exactly Q | fused attack stays at baseline 1/M |

**Parameters (committed artifact):**
| Param | Value | Notes |
|-------|-------|-------|
| `M` | 30 | candidate receivers (sensitivity also sweeps M) |
| `s_rate` / `bg` | 3.0 / 8.0 | sender signal / background |
| `Q` | 25 | padding quota (sensitivity also sweeps Q) |
| `probe_frac` | 0.5 | active suppression duty cycle |
| `epoch_grid` | 50…1600 | CI long-horizon checkpoints |
| `offline_long_horizon` | 3200…6400 | offline-only extension in artifact |
| `trials` | 200 (CI curves) / 80 (sensitivity) / 100 (offline) | Monte Carlo |

**Findings (characterizes, does not close):**
- Without hard-cap, combined attack reaches high P(confirm) by E≈1600.
- Hard-cap / deferred_hard_cap hold at random baseline through CI and offline horizons.
- Pad-up, truncate-only, and noisy_hard_cap remain vulnerable; no scheme beats hard-cap honestly.
- Sensitivity: hard_cap tracks ~1/M; larger pad budgets do not make pad_up equivalent to hard-cap.

**Artifact:** `sim/data/combined_active_intersection.analysis.json`

**Sim → product mapping:** [`combined_attack_mode1_hardcap.md`](combined_attack_mode1_hardcap.md)

**Pytest:** `sim/tests/test_combined_active_intersection.py` + `test_hardening.py` (`test_combined_*`)

**Operator note (Mode-1):** Production receivers **must keep hard-cap padding
enabled** (`HardCapPadder`; `Q` exactly caps observable counts; set
`Q >= ~1.2×` sustained mean). Pad-up / truncate / noisy / constant-rate
observables remain vulnerable — do not disable hard-cap for "efficiency."
**Exit / non-AEGIS receivers are excluded** from this residual claim.

**Honest limits:** Synthetic Poisson traffic; global passive + partial active
(n-1) model; no multi-hop mix delay, guard rotation, or Sphinx crypto proofs.

---

## Regenerating artifacts

```bash
cd sim && PYTHONPATH=. python scripts/generate_research_artifacts.py --only combined
cd sim && PYTHONPATH=. pytest -q tests/test_combined_active_intersection.py tests/test_hardening.py -k combined
```
