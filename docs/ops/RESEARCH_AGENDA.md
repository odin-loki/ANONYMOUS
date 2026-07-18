# AEGIS research agenda (honest backlog)

**Date:** 2026-07-18  
**Tip:** d304354  
**Wave status:** In-repo scaffolding and sim quantification advanced; **research is not closed.**

This is the single backlog for what remains **open**, **partial**, or **External-only**.
It complements (does not replace) the spec's §13 list in
[`docs/AEGIS_SPEC_v3_consolidated.md`](../AEGIS_SPEC_v3_consolidated.md).

**Legend:** [T] tested (in-repo evidence) · [R] reasoned · [O] open · **External** = platform/operator integration, not unfinished wiring.

**Related:** [`RESEARCH_OPS_STATUS.md`](RESEARCH_OPS_STATUS.md) (one-page residual table) · [`AEGIS_research_ops_hardening_plan.md`](../AEGIS_research_ops_hardening_plan.md) (closed wave plan) · [`AEGIS_phase8_hardening_notes.md`](../AEGIS_phase8_hardening_notes.md) (§13 sim progress detail).

---

## 1. Platform External — scaffolding done; research = integration

In-tree contracts, fail-closed hooks, ops runbooks, and CI smokes exist. Remaining work is **operator/platform integration**, not more Rust/Python wiring.

| Area | In-tree scaffolding | Research / integration left | Ops doc |
|------|---------------------|----------------------------|---------|
| **TEE attestation** | Software quotes; `HardwareTeeProvider` fail-closed; DCAP/SEV request types; `tee-hardware` hook | **External:** Intel DCAP / AMD SEV-SNP SDK + platform device | [`tee_attestation.md`](tee_attestation.md) |
| **HSM / key ceremony** | Shamir + `Pkcs11CustodyOps`; lab `SimulatedHsmProvider`; fail-closed | **External:** PKCS#11 / vendor HSM SDK + interactive MPC ceremony | [`consortium_key_ceremony.md`](consortium_key_ceremony.md) |
| **Multi-org BFT / health gossip** | Authority-set quorum log; `majority_k`; optional `HealthEpochCheckpoint` | **External:** multi-org BFT reputation consensus across operators | [`health_gossip.md`](health_gossip.md) |
| **Anonymous credentials (AC)** | Issuer + blinded issue types; epoch rotate; nullifier merge | **External:** interactive AC / real ZK show at scale | [`anonymous_reputation.md`](anonymous_reputation.md) |
| **dudect / CT evidence** | Smokes; `tools/dudect/` lab Makefile; WSL scripts → `sim/dudect_lab_attempt.txt`; CI sim-pytest | **External:** ≥10⁵ traces/primitive on isolated CPU | [`constant_time_ci.md`](constant_time_ci.md) |

**Status summary:** scaffolding **done** · research phase = **integration** with real hardware, multi-org ops, and lab-grade timing measurement.

See [`RESEARCH_OPS_STATUS.md`](RESEARCH_OPS_STATUS.md) rows #1–2, #6–7, #10 for the one-page matrix.

---

## 2. Spec §13 science [O] — in-repo sim progress (not closed)

From [`AEGIS_SPEC_v3_consolidated.md`](../AEGIS_SPEC_v3_consolidated.md) §13. None of these are claimed **closed**; some have **quantification** in `sim/`.

| §13 open item | Status | In-repo progress / pointers |
|---------------|--------|----------------------------|
| Adaptive adversary varying compromised-mix set across epochs | **[O] QUANTIFIED** | `sim/aegis_sim/adversaries.py` → `adaptive_guard_exposure(..., mode='adaptive')`; regression in `sim/tests/test_hardening.py` (`test_adaptive_adversary_increases_exposure_over_horizon`). Long-horizon exposure grows; **not mitigated**. |
| Combined active(n−1) + intersection over long horizons (Mode 1) | **[O] NOT ADDRESSED** | Separate gates in `sim/aegis_sim/adversaries.py` (`active_confirm`, `intersection`); no combined attack sim yet. Future: compose on shared epoch timeline. |
| Real-trace shapeability (actual C2/telemetry, not synthetic) | **[O] partial [T]** | Loopback testnet captures only — see §3 below. Pipeline: `sim/aegis_sim/traffic.py` (`load_trace_counts`, `synthetic_c2_like_counts`), `sim/aegis_sim/metrics.py` (`shapeability_report`), `sim/tests/test_hardening.py`. Traces: `sim/data/real_testnet_trace.csv`, `sim/data/real_multiprocess_trace.csv`, `sim/data/real_multiprocess_relay_forward_trace.csv` + `sim/scripts/analyze_*_trace.py`. |
| Sphinx crypto correctness — proof / test vectors, not simulation | **[O] partial** | Phase 2 test vectors pass (`docs/AEGIS_phase2_implementation_notes.md`); formal proof does **not** exist. |
| Consortium governance (who runs/vets relays across nations) | **[O] policy only** | See §4 below. |

Detail and honest limits: [`AEGIS_phase8_hardening_notes.md`](../AEGIS_phase8_hardening_notes.md) §2 and §4–§5.

Sibling agents may extend sim coverage; expected touchpoints:

- `sim/aegis_sim/adversaries.py` — adaptive exposure, attack primitives
- `sim/tests/test_hardening.py` — §13 exploratory regressions (bounds looser than core ledger)
- `sim/aegis_sim/traffic.py`, `sim/aegis_sim/metrics.py` — trace ingest + shapeability tiering
- `sim/scripts/capture_multiprocess_*.py`, `sim/scripts/analyze_*_trace.py` — real testnet trace capture/analysis

---

## 3. Real C2 shapeability — loopback [T]; operational C2 still [O]

| Vantage | Status | Notes |
|---------|--------|-------|
| Benign client-send on loopback testnet (in-process + multi-process) | **[T]** | `shapeability_report` on committed CSVs; CV/tier documented in Phase 8 notes §4. |
| Relay post-forward (paced multi-process loopback) | **[T]** | `sim/data/real_multiprocess_relay_forward_trace.csv`; 1 s slot tier may read **unshapeable** as a loopback/bin-width artifact (Phase 8 §5). |
| **Operational C2 / telemetry** (production traffic shapes, WAN, real endpoints) | **[O]** | No genuine operational trace in repo. `synthetic_c2_like_counts` is pipeline-test only — **not** evidence about real C2. |

Do **not** cite loopback captures as closure of spec §13 "actual C2/telemetry".

---

## 4. Governance [O] — policy only, no code

Spec §13: *Consortium governance: who runs/vets relays across nations (business/political).*

- **Status:** **[O]** — out of scope for this codebase.
- **In-repo:** threat-model and ops docs describe **technical** admission/reputation/roster mechanics; they do **not** resolve cross-national operator policy, legal vetting, or consortium charter.
- **Research type:** governance / policy / business — not a software deliverable in `crates/` or `sim/`.

---

## 5. What is NOT claimed closed

Use this checklist when writing release notes, README claims, or sales material.

| Claim | Honest status |
|-------|---------------|
| "Research complete" / "all §13 closed" | **False** — adaptive adversary mitigated, combined attacks, operational C2 shapeability, formal Sphinx proof, and governance remain open or External. |
| Platform TEE / HSM / BFT / AC / dudect "done" | **False** — scaffolding done; integration is **External**. |
| Real-trace shapeability fully validated | **False** — loopback testnet only **[T]**; operational C2 **[O]**. |
| Adaptive guard exposure neutralized | **False** — quantified and **not mitigated** (`test_hardening.py`). |
| Combined active + intersection bounded | **False** — not simulated. |
| Sphinx formally verified | **False** — test vectors only. |
| Consortium governance solved | **False** — policy/business **[O]**. |
| Call-site profiling / ops wave | **Closed** (2026-07-17/18) except B-class **External** — see [`RESEARCH_OPS_STATUS.md`](RESEARCH_OPS_STATUS.md). |

**Wave closure (software):** In-repo work for listed residuals is advanced as far as software allows. Remaining blockers are operator/platform **External** integration and **science [O]** items above — not missing wiring in the default datapath.

---

## 6. Suggested next sessions (priority-neutral backlog)

1. **Combined attack sim** — compose `active_confirm` + `intersection` on shared Mode 1 population (`sim/aegis_sim/adversaries.py`).
2. **Operational trace ingest** — point `load_trace_counts` / `shapeability_report` at a redacted real C2 or telemetry capture (operator-supplied; not in repo).
3. **Adaptive mitigation design** — rate-limit / detect relay recompromise (candidate tie-in: Phase 7 anomaly detection); sim before code.
4. **Platform integration pilots** — one External row at a time (TEE SDK, PKCS#11 HSM, multi-org gossip, AC issuer, isolated dudect lab) per ops runbooks.
5. **Governance artifact** — consortium charter / vetting policy (external to repo; link from ops docs when it exists).
