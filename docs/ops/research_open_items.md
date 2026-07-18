# AEGIS — Spec §13 Research Open Items (in-repo simulation)

**Tip:** `c7c2f0d`  
**Hub:** [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md)  
**Agenda:** [`RESEARCH_AGENDA.md`](RESEARCH_AGENDA.md)

This document records **in-repo** characterization work for spec §13 open items
that can be advanced without hardware, fake crypto proofs, or operational traces.
Status tags: **[O]** open / not mitigated; **[O → QUANTIFIED]** simulated limits
documented honestly; **Partial** = useful mitigation that does **not** close §13.

See also [`AEGIS_phase8_hardening_notes.md`](../AEGIS_phase8_hardening_notes.md) and
[`adaptive_guard_mitigation.md`](adaptive_guard_mitigation.md).

**Research is not closed.**

---

## A) Adaptive compromised-mix set [O → QUANTIFIED + Partial v1–v4]

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
- `mode='mitigated_first'`: v1 — sticky cap + demotion on signal (~0.90 @ E=200).
- `mode='mitigated'`: v2 — tighter cap, stronger demotion, linger (~0.77 @ E=200).
- `mode='mitigated_aggressive'`: v2 second tier — extra demotion on dirty epoch.
- `mode='mitigated_v3'`: v3 — hard age cap 4, decaying stickiness, rep soft rotate (~0.45 @ E=200; ~0.99 @ E=2000).
- **`mode='mitigated_v4'`: v4 — best Partial** — hard age cap 2, stronger demotion (~0.24 @ E=200; ~0.85 @ E=2000, ~14 pp better than v3); still saturates long-horizon.
- Rust: prefer `GuardMitigationPolicy::adaptive_v4()` / TOML `preset = "adaptive_v4"` (default **off**).
- See [`adaptive_guard_mitigation.md`](adaptive_guard_mitigation.md).

**Artifacts:**
- `sim/data/adaptive_guard_exposure.analysis.json` (`mitigated_v4_by_epochs`, `mitigated_v3_by_epochs`, …)
- `sim/data/adaptive_v4_saturation.analysis.json`
- Sweeps: `adaptive_mitigation_sweep.json`, `adaptive_mitigation_offline.json` via `sim/scripts/sweep_adaptive_mitigation.py`

**Pytest:** `sim/tests/test_hardening.py` (`test_adaptive_*`, `test_mitigated_v3_*`, `test_mitigated_v4_*`)

**Honest limit:** Real adversary recompromise *rate* is unknown; this models
independent per-epoch redraw, not detected/slow recompromise. **§13 remains [O].**

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

## C) Exit-tier anonymity-set / intersection [O → QUANTIFIED] (coverage C2)

**Spec / wave:** Exit weaker tier (spec §8) + RESEARCH_COVERAGE_WAVE C2.

**Simulator:** `sim/aegis_sim/exit_tier_intersection.py`
- `exit_tier_intersection(...)` — single-horizon mean anonymity set, ∩ singleton, volume rank
- `exit_tier_intersection_curve(...)` — metrics vs epochs
- `exit_tier_report(...)` — sensitivity + offline horizons

**Defenses (S4 → product A2):** `exit_tier_defense.py` ranks `presence_pad` / `pool_hard_cap` (sim);
product opt-in `[exit].presence_pad` (default **off**). See [`exit_tier_defense.md`](exit_tier_defense.md).

**Model:** N clients share one exit; co-active windows form the sender anonymity set; GPA at exit↔clearnet sees **unshaped** residual (no receiver hard-cap). Tip-sparse ∩ uses partial activity knowledge (`tip_rate`); naive full-window ∩ collapses faster.

**Findings (characterizes, does not close):**
- Mean co-active anonymity set grows with `p_active` and client pool N.
- Tip-sparse intersection shrinks with E; unshaped volume ranking beats 1/N quickly.
- Naive full-window ∩ collapses near-singleton early (honest residual).
- **Not WAN closed** — synthetic Poisson clearnet residual only.

**Artifact:** `sim/data/exit_tier_intersection.analysis.json`  
**Script:** `sim/scripts/run_exit_tier_intersection.py` (`--offline` for E≤3200)  
**Pytest:** `sim/tests/test_exit_tier_intersection.py`

---

## D) Fused adaptive ∩ active/intersection [O → QUANTIFIED] (coverage C2 → S5)

**Spec / wave:** Compose adaptive compromised-mix redraw with Mode-1 active+intersection.

**Simulator:** `sim/aegis_sim/fused_adversary.py` (calls public APIs; does not rewrite adaptive_v4 / CAI guts)
- `fused_long_horizon(...)` — coupled curves (`p_adaptive_exposed`, `p_mode1_confirm`, union/joint)
- `baseline_adaptive_only` / `baseline_combined_only` — live public-API baselines
- `load_committed_baselines` — reuse `adaptive_guard_exposure.analysis.json` + `combined_active_intersection.analysis.json`

**Defenses (S5):** `fused_defense.py` — **`fused_v4`** (+ optional `hard_cap_forced`) lowers dirty-epoch frac so Mode-1 stays hard_cap longer. Artifact `sim/data/fused_defense.analysis.json`.

**Coupling:** Per epoch redraw guards with prob `c`. Dirty → leaky Mode-1 obs (`constant_only` / `pad_up`); clean → `hard_cap` (no fused signal).

**Findings (characterizes, does not close):**
- With `c=0`, Mode-1 confirm stays near 1/M (hard_cap epochs only).
- With realistic/high `c`, adaptive exposure unlocks Mode-1 confirm; union ≥ either component.
- Committed adaptive/combined artifacts remain the pinned separate baselines.
- Prefer adaptive_v4 in product for fewer leaky epochs; **does not close §13**.

**Artifact:** `sim/data/fused_adversary.analysis.json`  
**Script:** `sim/scripts/run_fused_adversary.py` (`--offline` for longer E)  
**Pytest:** `sim/tests/test_fused_adversary.py` · `test_fused_defense.py`

**Honest limits:** Synthetic; not WAN closed; exit clearnet residual is a separate weaker tier (section C).

---

## E) Joint adaptive-guard × gossip-eclipse [O → QUANTIFIED] (leftovers B3)

**Spec / wave:** Compose adaptive compromised-mix redraw with gossip eclipse / `majority_k` over shared epochs. Landed at tip **c7c2f0d**.

**Theory / playbook:** [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md) · [`ATTACK_PLAYBOOK.md`](ATTACK_PLAYBOOK.md) §3.1 / §10 · [`PRODUCTIZE_LEFTOVERS_WAVE.md`](PRODUCTIZE_LEFTOVERS_WAVE.md).

**Simulator:** `sim/aegis_sim/joint_guard_gossip.py` (imports public APIs; does not rewrite adaptive / gossip cores)
- `joint_long_horizon(...)` — coupled curves (`p_adaptive_exposed`, `p_gossip_fp`, `p_eclipse_any`, union/joint)
- `baseline_adaptive_only` / `baseline_gossip_only` — live public-API baselines
- `joint_defense_curve` — optional **`mitigated_v4` + stacked gossip** vs undefended
- `load_committed_baselines` — reuse adaptive + gossip committed artifacts

**Coupling:** Per epoch redraw guards with prob `c`. Concurrent coordinated eclipse at `(N,f,K)` with default **`f=0.125`, `K=2`, `N=8`** (1 adv — below solo quorum). **Boosted:** dirty epochs raise effective `f` by seating compromised guards as eclipse reporters so `adv≥K`. Clean epochs keep baseline `f`. Gossip success = eclipse_any ∨ false_probation.

**Product knobs (compose, do not close):**
- Client: `[guard_mitigation] preset = "adaptive_v4"`
- Relay: stacked `[health_gossip]` (`majority_k=4`, `min_orgs=2`, `eclipse_detect=true`) + peer `org_id` / `jurisdiction`
- Optional: `[path] require_diverse_jurisdictions` (B2 soft filter)

**Findings (characterizes, does not close):**
- Union ≥ either component; joint ≤ min(components).
- Independent gossip at default `f` rarely eclipses; boosted unlocks eclipse as adaptive exposure grows.
- **`joint_v4_stacked`** lowers mid-horizon union at partial `f`; long-E / `f→1` still saturate.
- **§13 not closed**; field recompromise and eclipse rates unmeasured; multi-org BFT External.

**Artifact:** `sim/data/joint_guard_gossip.analysis.json`  
**Script:** `sim/scripts/run_joint_guard_gossip.py` (`--offline` for longer E)  
**Pytest:** `sim/tests/test_joint_guard_gossip.py`

**Honest limits:** Synthetic; no WAN adversary. Does not claim adaptive_v4 or stacked gossip closed.

---

## Related product / verify pointers (not §13 closure)

| Track | Status | Pointer |
|-------|--------|---------|
| Peelable cover onions (B1) | Partial product | [`cover_multihop_defense.md`](cover_multihop_defense.md) |
| Jurisdiction path-select (B2) | Soft filter | [`faction_sybil_skew.md`](faction_sybil_skew.md) |
| Metrics export gate (A4/A5) | Partial | [`metrics_scrape_defense.md`](metrics_scrape_defense.md) |
| ProVerif Sphinx (S3) | Symbolic L1–L3 proved | [`sphinx_symbolic_model.md`](sphinx_symbolic_model.md) |
| SoftHSM ceremony (S6) | Software token Succeeded | [`softhsm_ceremony.md`](softhsm_ceremony.md) |

---

## Regenerating artifacts

```bash
cd sim && PYTHONPATH=. python scripts/generate_research_artifacts.py --only adaptive
cd sim && PYTHONPATH=. python scripts/run_adaptive_v4_saturation.py
cd sim && PYTHONPATH=. python scripts/generate_research_artifacts.py --only combined
cd sim && PYTHONPATH=. python scripts/generate_research_artifacts.py --only c2
# or: python scripts/run_exit_tier_intersection.py --offline
#     python scripts/run_fused_adversary.py --offline
#     python scripts/run_fused_defense.py
#     python scripts/run_joint_guard_gossip.py --offline
cd sim && PYTHONPATH=. pytest -q tests/test_combined_active_intersection.py tests/test_hardening.py -k "combined or mitigated_v4 or adaptive"
cd sim && PYTHONPATH=. pytest -q tests/test_exit_tier_intersection.py tests/test_fused_adversary.py tests/test_fused_defense.py
cd sim && PYTHONPATH=. pytest -q tests/test_joint_guard_gossip.py
```
