# AEGIS research agenda (honest backlog)

**Date:** 2026-07-18  
**Tip:** 29e89f5+ (research upgrade in flight)  
**Wave status:** In-repo scaffolding and sim quantification advanced; **research is not closed.**

This is the single backlog for what remains **open**, **partial**, or **External-only**.
It complements (does not replace) the spec's §13 list in
[`docs/AEGIS_SPEC_v3_consolidated.md`](../AEGIS_SPEC_v3_consolidated.md).

**Legend:** [T] tested (in-repo evidence) · [R] reasoned · [O] open · **External** = platform/operator integration, not unfinished wiring.

**Related:** [`ATTACK_PLAYBOOK.md`](ATTACK_PLAYBOOK.md) (attack primitives, mitigation status, residuals) · [`RESEARCH_UPGRADE_PLAN.md`](RESEARCH_UPGRADE_PLAN.md) (active anonymity/attack upgrade) · [`RESEARCH_OPS_STATUS.md`](RESEARCH_OPS_STATUS.md) · [`AEGIS_research_ops_hardening_plan.md`](../AEGIS_research_ops_hardening_plan.md) · [`AEGIS_phase8_hardening_notes.md`](../AEGIS_phase8_hardening_notes.md) · [`CONSORTIUM_CHARTER.md`](CONSORTIUM_CHARTER.md) · [`PILOT.md`](PILOT.md).

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
| Adaptive adversary varying compromised-mix set across epochs | **[O] QUANTIFIED + Partial mitigation (v1–v3)** | `adaptive_guard_exposure` + `mode='mitigated_v3'` (best), `mitigated` (v2), `mitigated_first` (v1); artifact `mitigated_v3_by_epochs`; Rust `GuardMitigationPolicy::adaptive_v3()`; [`adaptive_guard_mitigation.md`](adaptive_guard_mitigation.md). v3 ~32 pp lower than v2 at E=200 in sim; long-horizon saturation residual remains — **does not close §13.** |
| Combined active(n−1) + intersection over long horizons (Mode 1) | **[O] QUANTIFIED** | Extended ranking (`hard_cap`/`deferred_hard_cap` + pad/truncate/noisy), M/Q sensitivity, offline E≤6400; artifact `sim/data/combined_active_intersection.analysis.json`; mapping [`combined_attack_mode1_hardcap.md`](combined_attack_mode1_hardcap.md); gates in `test_combined_active_intersection.py` + `test_hardening.py`. Characterized, **not closed**. |
| Cover-burst / GPA timing (related Partial) | **[O] QUANTIFIED** | `cover_timing.py` CV + KS + gap histograms + burst_heavy bundle; artifact `sim/data/cover_burst_gpa_characterization.json`; CI in `test_cover_burst_gpa.py`. Not info-theoretic indistinguishability. |
| Real-trace shapeability (actual C2/telemetry, not synthetic) | **[O] partial [T]** | Loopback testnet captures only — see §3 below. Ingest pipeline: `traffic.load_timestamp_csv` / `metrics.characterize_trace_file`; synthetic stress labeled `NOT_OPERATIONAL_C2` via `scripts/run_c2_shapeability_pipeline.py`. |
| Sphinx crypto correctness — proof / test vectors, not simulation | **[O] partial** | Peel-order KATs (2/3/max + all lengths), wrong-hop reject, seeded structural KAT in `vectors.rs`; formal proof does **not** exist (`docs/AEGIS_phase2_implementation_notes.md`). |
| Consortium governance (who runs/vets relays across nations) | **[O] policy draft** | Practical charter: [`CONSORTIUM_CHARTER.md`](CONSORTIUM_CHARTER.md). Code enforces signed roster + reputation; jurisdiction quotas and legal vetting remain policy. |

Detail and honest limits: [`AEGIS_phase8_hardening_notes.md`](../AEGIS_phase8_hardening_notes.md) §2 and §4–§5.

Sibling agents may extend sim coverage; expected touchpoints:

- `sim/aegis_sim/adversaries.py` — adaptive exposure, attack primitives
- `sim/tests/test_hardening.py` — §13 exploratory regressions (bounds looser than core ledger)
- `sim/aegis_sim/traffic.py`, `sim/aegis_sim/metrics.py` — trace ingest + shapeability tiering
- `sim/scripts/run_c2_shapeability_pipeline.py` — WAN drop-in / synthetic stress (labeled NOT_OPERATIONAL_C2)
- `sim/scripts/run_cover_burst_gpa_characterization.py` — cover CV/KS/histogram artifact
- `sim/scripts/capture_multiprocess_*.py`, `sim/scripts/analyze_*_trace.py` — real testnet trace capture/analysis

---

## 3. Real C2 shapeability — loopback [T]; operational C2 still [O]

| Vantage | Status | Notes |
|---------|--------|-------|
| Benign client-send on loopback testnet (in-process + multi-process) | **[T]** | `shapeability_report` on committed CSVs; CV/tier documented in Phase 8 notes §4. |
| Relay post-forward (paced multi-process loopback) | **[T]** | `sim/data/real_multiprocess_relay_forward_trace.csv`; 1 s slot tier may read **unshapeable** as a loopback/bin-width artifact (Phase 8 §5). |
| **Operational C2 / telemetry** (production traffic shapes, WAN, real endpoints) | **[O]** | No genuine operational trace in repo. `synthetic_c2_like_counts` / `synthetic_c2_stress_suite` are pipeline-test only — **not** evidence about real C2. |

### Dropping in a real WAN / operational trace

1. Export redacted event timestamps (seconds) **or** pre-binned `slot,count` CSV.
2. Place under `sim/data/` (example: `sim/data/wan_ops_trace.csv`) — do not commit secrets.
3. Characterize:
   ```bash
   cd sim && PYTHONPATH=. python scripts/run_c2_shapeability_pipeline.py \
     --trace data/wan_ops_trace.csv --operational --slot-seconds 1.0 \
     -o data/wan_ops_trace.analysis.json
   ```
4. Only artifacts with `"is_operational": true` may be cited as operational evidence.
5. For pipeline CI without real data: `--synthetic-stress` writes `synthetic_c2_stress_shapeability.json` labeled `NOT_OPERATIONAL_C2`.

Do **not** cite loopback captures or synthetic stress as closure of spec §13 "actual C2/telemetry".

---

## 4. Governance [O] — policy draft + code boundaries

Spec §13: *Consortium governance: who runs/vets relays across nations (business/political).*

- **Status:** **[O]** — not closed; a **practical draft charter** now exists for operators.
- **In-repo:** [`CONSORTIUM_CHARTER.md`](CONSORTIUM_CHARTER.md) (membership, vetting, M-of-N roles, jurisdiction diversity goals, compromise response, reputation disputes, code vs policy). Technical admission/reputation/roster mechanics in threat-model and ops runbooks.
- **Code enforces:** M-of-N signed roster load, fail-closed lab flags (`aegis-node validate`), reputation + gossip verify paths.
- **Policy / External:** legal vetting, sanctions screening, diversity quota compliance audits, multi-org BFT reputation — not software deliverables alone.

---

## 5. What is NOT claimed closed

Use this checklist when writing release notes, README claims, or sales material.

| Claim | Honest status |
|-------|---------------|
| "Research complete" / "all §13 closed" | **False** — science items are quantified or partial; not closed. |
| Platform TEE / HSM / BFT / AC / dudect "done" | **False** — scaffolding done; integration is **External**. |
| Real-trace shapeability fully validated | **False** — loopback testnet only **[T]**; operational C2 **[O]**. |
| Adaptive guard exposure neutralized | **False** — v3 lowers sim exposure vs v2/v1/unmitigated (~0.45 vs ~0.77 vs ~0.90 vs ~1.0 at E=200) but still saturates long-horizon; **§13 still [O]**. |
| Combined active + intersection bounded | **False** — quantified (`combined_active_intersection.analysis.json`); **not mitigated**. |
| Sphinx formally verified | **False** — KATs/edge tests only. |
| Consortium governance solved | **False** — charter draft **[O]**; binding governance still external to code. |
| Call-site profiling / ops wave | **Closed** (2026-07-17/18) except B-class **External** — see [`RESEARCH_OPS_STATUS.md`](RESEARCH_OPS_STATUS.md). |

**Wave closure (software):** In-repo characterization of listed science items is as far as software allows. Remaining blockers are operator/platform **External** integration, formal proofs, operational C2 data, mitigation design, and governance — not missing wiring in the default datapath.

---

## 6. Suggested next sessions (priority-neutral backlog)

1. **Pilot productization** — **Closed** (2026-07-18) — staged rollout per [`PILOT.md`](PILOT.md): `deploy/templates/` production snippets, Docker compose pilot, `aegis-node validate`, client CLI roster-path + `[guard_mitigation]` wiring. Remaining: operator-supplied WAN/C2 traces, counsel-reviewed charter, External platform rows.
2. **Operational trace ingest** — drop a redacted WAN/C2 CSV and run `scripts/run_c2_shapeability_pipeline.py --trace … --operational` (pipeline ready; data still operator-supplied).
3. **Adaptive / composed-attack mitigation** — v1–v3: sim `mode='mitigated_v3'` + `GuardMitigationPolicy::adaptive_v3()` ([`adaptive_guard_mitigation.md`](adaptive_guard_mitigation.md)); saturation residual + detection fidelity still open; combined attack still [O].
4. **Platform integration pilots** — one External row at a time (TEE SDK, PKCS#11 HSM, multi-org gossip, AC issuer, isolated dudect lab) per ops runbooks.
5. **Formal Sphinx proof** — external crypto review / mechanized proof (not more unit tests).
6. **Governance hardening** — counsel review of [`CONSORTIUM_CHARTER.md`](CONSORTIUM_CHARTER.md); bind to operator agreements and audit cadence.
