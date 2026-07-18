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
- `mode='mitigated'`: first mitigation — sticky cap + demotion on signal; **lower** than adaptive at E=200/800; may still saturate at E=2000. See [`adaptive_guard_mitigation.md`](adaptive_guard_mitigation.md).

**Artifact:** `sim/data/adaptive_guard_exposure.analysis.json` (includes `mitigated_by_epochs`, `mitigation_at_200`)

**Pytest:** `sim/tests/test_hardening.py` (`test_adaptive_*`)

**Honest limit:** Real adversary recompromise *rate* is unknown; this models
independent per-epoch redraw, not detected/slow recompromise.

---

## B) Combined active(n-1) + intersection long horizon [O → QUANTIFIED]

**Spec:** "Combined active(n-1)+intersection over long horizons on Mode 1."

**Simulator:** `sim/aegis_sim/adversaries.py`
- `combined_active_intersection(scheme, E, ...)` — single horizon
- `combined_active_intersection_curve(...)` — P(deanonymize) vs epochs
- `combined_attack_report(...)` — JSON export

**Mode-1 schemes:**
| Scheme | Observable | Expected |
|--------|------------|----------|
| `constant_only` | raw counts | both components leak; degrades over epochs |
| `pad_up` | max(real, Q) | fails active + intersection at low Q |
| `hard_cap` | exactly Q | fused attack stays at baseline 1/M |

**Parameters (committed artifact):**
| Param | Value | Notes |
|-------|-------|-------|
| `M` | 30 | candidate receivers |
| `s_rate` / `bg` | 3.0 / 8.0 | sender signal / background |
| `Q` | 25 | padding quota (pad_up / hard_cap) |
| `probe_frac` | 0.5 | active suppression duty cycle |
| `epoch_grid` | 50…1600 | long-horizon checkpoints |
| `trials` | 200 | Monte Carlo |

**Findings (characterizes, does not close):**
- Without hard-cap, combined attack reaches high P(confirm) by E≈1600.
- Hard-cap holds fused attack at random baseline through E=800+.
- Pad-up at low Q remains vulnerable; combined ≥ intersection-only.

**Artifact:** `sim/data/combined_active_intersection.analysis.json`

**Pytest:** `sim/tests/test_hardening.py` (`test_combined_*`)

**Honest limits:** Synthetic Poisson traffic; global passive + partial active
(n-1) model; no multi-hop mix delay, guard rotation, or Sphinx crypto proofs.

---

## Regenerating artifacts

```bash
cd sim && PYTHONPATH=. python scripts/generate_research_artifacts.py
cd sim && PYTHONPATH=. pytest -q tests/test_hardening.py
```
