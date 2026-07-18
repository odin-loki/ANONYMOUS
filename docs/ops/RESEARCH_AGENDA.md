# AEGIS research agenda (honest backlog)

**Date:** 2026-07-18  
**Tip:** `c7c2f0d` — leftovers B1–B3 landed (peelable `cover_onions`, jurisdiction paths, joint guard×gossip)  
**Theory hub:** [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md) — single map of science status, product knobs, and residuals  
**Wave status:** Coverage C1–C6, PC-verify S1–S6, productize A1–A6 + leftovers B1–B3 are **in-repo**. **Research is not closed.**

This is the single backlog for what remains **open**, **partial**, or **External-only**.
It complements (does not replace) the spec's §13 list in
[`docs/AEGIS_SPEC_v3_consolidated.md`](../AEGIS_SPEC_v3_consolidated.md).

**Legend:** [T] tested (in-repo evidence) · [R] reasoned · [O] open · **External** = platform/operator integration, not unfinished wiring.

**Related:** [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md) (hub) · [`ATTACK_PLAYBOOK.md`](ATTACK_PLAYBOOK.md) · [`RESEARCH_OPS_STATUS.md`](RESEARCH_OPS_STATUS.md) · [`research_open_items.md`](research_open_items.md) · [`adaptive_guard_mitigation.md`](adaptive_guard_mitigation.md) · [`PRODUCTIZE_DEFENSES_WAVE.md`](PRODUCTIZE_DEFENSES_WAVE.md) · [`PRODUCTIZE_LEFTOVERS_WAVE.md`](PRODUCTIZE_LEFTOVERS_WAVE.md) · [`PC_VERIFY_RESEARCH_WAVE.md`](PC_VERIFY_RESEARCH_WAVE.md) · [`RESEARCH_COVERAGE_WAVE.md`](RESEARCH_COVERAGE_WAVE.md) · [`RESEARCH_UPGRADE_PLAN.md`](RESEARCH_UPGRADE_PLAN.md) (historical) · [`CONSORTIUM_CHARTER.md`](CONSORTIUM_CHARTER.md) · [`PILOT.md`](PILOT.md).

---

## 0. Product knobs that exist now (opt-in unless noted)

| Knob | TOML / API | Default | Residual |
|------|------------|---------|----------|
| **Adaptive guard v4** (preferred Partial) | `[guard_mitigation] preset = "adaptive_v4"` | **off** | Long-horizon saturation; field rates unmeasured |
| Adaptive v1–v3 (legacy) | `adaptive_first` / `adaptive_v2` / `adaptive_v3` | off | Weaker than v4 at E=2000 |
| **Jurisdiction path diversity** (B2) | `[path] require_diverse_jurisdictions` / `max_per_jurisdiction` | **off** | Soft filter; charter legal enforcement External |
| **Stacked health gossip** (A1) | `[health_gossip]` `majority_k=4`, `min_orgs=2`, `eclipse_detect=true` | stacked when enabled | Multi-org BFT External; `f=1` saturates |
| Peer org / jurisdiction labels | `[[peers]] org_id` / `jurisdiction` | unlabeled fail-open | Diversity gate needs labels |
| **Exit presence_pad** (A2) | `[exit].presence_pad` | **off** | Clearnet GPA; bandwidth cost |
| **Cover multi-hop** (A3/B1) | `[cover] multihop_defense = "cover_onions"` (or `matched_local_discard` / scaffold) | off / discard | Peel-to-sink ≠ client exit; not info-theoretic |
| **Metrics export gate** (A4) | `[metrics]` cadence 30s / quantize 16 / suppress drops | production-hard when used | Privileged raw scrape residual |
| Mode-1 hard-cap (receivers) | `HardCapPadder` / Q | ops-required for Mode 1 | Exit/clearnet excluded |
| SoftHSM ceremony pilot | `scripts/softhsm_*` + PKCS#11 ops | lab | Software token ≠ hardware HSM |
| ProVerif Sphinx model (S3) | `tools/proverif/` | CI/lab | Symbolic ≠ EasyCrypt / computational |

Pilot comments prefer `preset = "adaptive_v4"`. Detail: [`adaptive_guard_mitigation.md`](adaptive_guard_mitigation.md), [`health_gossip.md`](health_gossip.md), [`cover_multihop_defense.md`](cover_multihop_defense.md), [`metrics_scrape_defense.md`](metrics_scrape_defense.md), [`exit_tier_defense.md`](exit_tier_defense.md).

---

## 1. Platform External — scaffolding done; research = integration

In-tree contracts, fail-closed hooks, ops runbooks, and CI smokes exist. Remaining work is **operator/platform integration**, not more Rust/Python wiring.

| Area | In-tree scaffolding | Research / integration left | Ops doc |
|------|---------------------|----------------------------|---------|
| **TEE attestation** | Software quotes; `HardwareTeeProvider` fail-closed; DCAP/SEV request types; `tee-hardware` hook | **External:** Intel DCAP / AMD SEV-SNP SDK + platform device | [`tee_attestation.md`](tee_attestation.md) |
| **HSM / key ceremony** | Shamir + `Pkcs11CustodyOps`; lab `SimulatedHsmProvider`; **SoftHSM2 user-local Succeeded** (software token) | **External:** vendor HSM SDK + interactive MPC; SoftHSM ≠ tamper-resistant custody | [`consortium_key_ceremony.md`](consortium_key_ceremony.md) · [`softhsm_ceremony.md`](softhsm_ceremony.md) |
| **Multi-org BFT / health gossip** | Authority-set quorum; **stacked** merge productized (A1); C1 + S5 eclipse defense sims; **B3 joint** adaptive×gossip | **External:** multi-org BFT reputation consensus | [`health_gossip.md`](health_gossip.md) · playbook §10 |
| **Anonymous credentials (AC)** | Issuer + blinded issue; epoch rotate; nullifier merge; C4 unlinkability sim | **External:** interactive AC / real ZK show at scale | [`anonymous_reputation.md`](anonymous_reputation.md) |
| **dudect / CT evidence** | Smokes; `tools/dudect/`; WSL deepen (not isolated) | **External:** ≥10⁵ traces/primitive on isolated CPU | [`constant_time_ci.md`](constant_time_ci.md) |

**Status summary:** scaffolding **done** · SoftHSM pilot **Succeeded** (software) · research phase = **integration** with real hardware, multi-org ops, and lab-grade timing.

See [`RESEARCH_OPS_STATUS.md`](RESEARCH_OPS_STATUS.md) for the one-page matrix.

---

## 2. Spec §13 science [O] — quantified + Partial mitigations (not closed)

From [`AEGIS_SPEC_v3_consolidated.md`](../AEGIS_SPEC_v3_consolidated.md) §13. None claimed **closed**. Hub narrative: [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md).

| §13 / science item | Status | In-repo progress / pointers |
|--------------------|--------|----------------------------|
| Adaptive adversary varying compromised-mix set | **[O] QUANTIFIED + Partial (v1–v4)** | Best Partial: **`adaptive_v4`** / `mode='mitigated_v4'` (~0.24 @ E=200; ~0.85 @ E=2000, ~14 pp better than v3). Rust `GuardMitigationPolicy::adaptive_v4()`. Artifacts: `adaptive_guard_exposure.analysis.json`, `adaptive_v4_saturation.analysis.json`. [`adaptive_guard_mitigation.md`](adaptive_guard_mitigation.md). **Does not close §13.** |
| Combined active(n−1) + intersection (Mode 1) | **[O] QUANTIFIED** | Hard-cap / deferred_hard_cap best; pad/truncate/noisy fail. `combined_active_intersection.analysis.json`. **Not mitigated** beyond hard-cap ops requirement. |
| Exit-tier + fused adaptive∩active | **[O] QUANTIFIED + product Partial** | Exit window ∩ / volume; fused coupling; S5 `fused_v4`; A2 `[exit].presence_pad`. Clearnet residual remains. |
| Cover-burst / GPA + multi-hop cover | **[O] QUANTIFIED + product Partial** | Cover CV/KS; C5/S4 multi-hop; **B1 peelable `cover_onions`** opt-in. Not info-theoretic. |
| Gossip eclipse / `majority_k` | **[O] QUANTIFIED Partial** | C1 baseline + S5 **stacked** defense; **A1** product defaults; **B3 joint** with adaptive. Multi-org BFT still External. |
| Joint adaptive-guard × gossip-eclipse (B3) | **[O] QUANTIFIED** | `joint_guard_gossip.py` + `joint_guard_gossip.analysis.json`; `joint_v4_stacked` Partial at mid-horizon. [`research_open_items.md`](research_open_items.md) §E. |
| Real-trace shapeability (ops C2) | **[O] partial [T]** | Loopback testnet only; WAN/operational still [O]. |
| Sphinx crypto correctness | **[O] partial** | Peel KATs; Python oracle (S1); **ProVerif L1–L3 proved** (S3 symbolic); A6 fuzz evidence (crashes=0). **No** EasyCrypt / computational proof. |
| Consortium governance | **[O] policy draft + QUANTIFIED skew + soft path (B2)** | Charter draft; faction skew sim; `[path]` jurisdiction diversity opt-in. Legal vetting External. |

Detail: [`research_open_items.md`](research_open_items.md) · [`AEGIS_phase8_hardening_notes.md`](../AEGIS_phase8_hardening_notes.md).

### Adaptive tiers (prefer v4)

| Tier | Sim mode / Rust preset | Honest sim note |
|------|------------------------|-----------------|
| v1 | `mitigated_first` / `adaptive_first` | ~0.90 @ E=200 |
| v2 | `mitigated` / `adaptive_v2` | ~0.77 @ E=200 |
| v3 | `mitigated_v3` / `adaptive_v3` | ~0.45 @ E=200; ~0.99 @ E=2000 |
| **v4 (best Partial)** | **`mitigated_v4` / `adaptive_v4`** | **~0.24 @ E=200; ~0.85 @ E=2000** |

Defaults remain **disabled**; pilot comments prefer v4.

---

## 3. Productize waves (landed — residuals remain)

| Wave | IDs | Status | Leftover |
|------|-----|--------|----------|
| Coverage | C1–C6 | Landed [O] QUANTIFIED / Partial | WAN, BFT, isolated dudect, legal gov |
| PC-verify | S1–S6 | Landed (oracle, ProVerif, SoftHSM Succeeded, v4, stacked gossip) | EasyCrypt; hardware HSM; field rates |
| Productize | A1–A6 | Landed | See knobs table §0 |
| Leftovers | B1–B3 | Landed at tip **c7c2f0d** | Forwardable cover; charter legal; field joint rates |

Docs: [`PRODUCTIZE_DEFENSES_WAVE.md`](PRODUCTIZE_DEFENSES_WAVE.md) · [`PRODUCTIZE_LEFTOVERS_WAVE.md`](PRODUCTIZE_LEFTOVERS_WAVE.md) · [`PC_VERIFY_RESEARCH_WAVE.md`](PC_VERIFY_RESEARCH_WAVE.md).

---

## 4. Real C2 shapeability — loopback [T]; operational C2 still [O]

| Vantage | Status | Notes |
|---------|--------|-------|
| Benign client-send on loopback testnet | **[T]** | Phase 8 notes §4 |
| Relay post-forward (paced multi-process loopback) | **[T]** | Loopback/bin-width artifacts possible |
| **Operational C2 / telemetry** | **[O]** | No genuine operational trace in repo |

Drop-in: `sim/scripts/run_c2_shapeability_pipeline.py --trace … --operational`. Only `"is_operational": true` counts as ops evidence. Do **not** cite loopback or synthetic stress as §13 closure.

---

## 5. Governance [O] — policy draft + soft path filter

- **Charter:** [`CONSORTIUM_CHARTER.md`](CONSORTIUM_CHARTER.md) — draft; counsel External.
- **Sybil / faction skew (C3):** [`faction_sybil_skew.md`](faction_sybil_skew.md) — quantified; not legal governance.
- **Jurisdiction path-select (B2):** opt-in `[path] require_diverse_jurisdictions` — soft software filter; composes with `adaptive_v4`; does **not** enforce charter quotas legally.
- **Code enforces:** M-of-N signed roster, reputation + stacked gossip verify paths.

---

## 6. What is NOT claimed closed

| Claim | Honest status |
|-------|---------------|
| "Research complete" / "all §13 closed" | **False** |
| Platform TEE / vendor HSM / BFT / AC / dudect "done" | **False** — scaffolding + SoftHSM software pilot; integration **External** |
| SoftHSM = hardware custody | **False** — software token only |
| ProVerif = Sphinx formally verified | **False** — symbolic L1–L3 only; not EasyCrypt / computational |
| Adaptive guard exposure neutralized | **False** — **v4 best Partial**; still saturates long-horizon |
| Combined active + intersection closed | **False** — quantified; hard-cap ops only |
| Cover / metrics / exit pads close anonymity | **False** — Partial product knobs |
| Joint guard×gossip closed | **False** — [O] QUANTIFIED; stacked+v4 Partial |
| Real-trace shapeability validated | **False** — loopback only |
| Consortium governance solved | **False** — charter + soft path; legal External |

---

## 7. Suggested next sessions (priority-neutral)

1. **Operational trace ingest** — redacted WAN/C2 CSV + `--operational` pipeline.
2. **Field-rate measurement** — recompromise / eclipse rates under `adaptive_v4` + stacked gossip (closes nothing alone; grounds sims).
3. **Platform integration pilots** — one External row at a time (TEE SDK, vendor HSM, multi-org gossip, AC issuer, isolated dudect).
4. **Forwardable cover onions** — beyond B1 peel-to-sink; directory PK distro.
5. **Formal Sphinx** — EasyCrypt / computational (beyond ProVerif + fuzz).
6. **Governance** — counsel review of charter; bind jurisdiction labels to audit cadence.

Historical upgrade waves (W1–W6): [`RESEARCH_UPGRADE_PLAN.md`](RESEARCH_UPGRADE_PLAN.md) — **landed**; use this agenda + the theory hub going forward.
