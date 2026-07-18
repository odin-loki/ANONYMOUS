# Faction / Sybil jurisdiction-skew profiling (wave C3)

**Date:** 2026-07-18  
**Status:** **[O] QUANTIFIED** — characterization only; governance **not closed**  
**Legal vetting:** **External** (counsel / sanctions / binding quotas — not software)

## Purpose

Profile how a **correlated consortium faction** (authorities sharing jurisdiction and
signing keys) interacts with **jurisdiction-skewed Sybil relay candidates** under
M-of-N roster admission. Complements the Rust integration test
`crates/aegis-topology/tests/sybil_admission.rs` (single-key flood + reputation)
with a pure-Python policy mirror of threshold + charter diversity goals.

## Policy params mirrored

| Param | Value | Source |
|-------|-------|--------|
| M-of-N threshold verify | ≥M distinct authority sigs | `ThresholdConsortium` / `verify_threshold` |
| Admission rate limit | 5 / 24h (default) | `RosterAdmissionPolicy` |
| Guard set size `g` | 3 | `GUARD_SET_SIZE` |
| Layers `L` | 4 | `TopologyConfig::high_threat` |
| Min distinct guard jurisdictions | ≥3 | [`CONSORTIUM_CHARTER.md`](CONSORTIUM_CHARTER.md) §5 |
| Max single-jurisdiction path slots | ≤40% of L | Charter §5 |
| Exit concentration | ≤1 exit / jurisdiction | Charter §5 |
| Authority trustee diversity | ≥2 jurisdictions among N | Charter §5 |

Jurisdiction fields remain **declarative** in code; quota compliance is policy.

## Sim

- Module: `sim/aegis_sim/faction_sybil_skew.py`
- Artifact: `sim/data/faction_sybil_skew.json`
- CI: `sim/tests/test_faction_sybil_skew.py`
- Regen: `cd sim && PYTHONPATH=. python scripts/run_faction_sybil_skew.py`

### Threat model (sim)

1. Fraction `f` of `N` authority keys are faction-controlled; optionally **all** share
   one jurisdiction label (`SY`) — correlated compulsion / capture.
2. Honest authorities **refuse** Sybil admissions; faction keys **sign** them.
3. Admission succeeds iff signatures ≥ `M` (crypto). Optional rate-limit ablation
   caps admits at 5/window even when `f·N ≥ M`.
4. Admitted relays are epoch-shuffled into L layers (mirror `build_topology`);
   measure guard/exit concentration and path jurisdiction fraction.

## Metrics (artifact)

| Metric | Meaning |
|--------|---------|
| `sybil_admission_success_rate` | P(Sybil gets ≥M sigs) — ≈0 if faction keys `< M`, ≈1 if `≥ M` |
| `faction_can_unilateral_admit` | `faction_keys ≥ M` |
| `layer1_sybil_fraction` / `primary_guard_sybil_rate` / `guard_set_any_sybil_rate` | Guard-surface capture (primary tracks layer-1; set ≈ `1-(1-c)^g`) |
| `path_max_jurisdiction_fraction_mean` / `path_charter_40pct_pass_rate` | Charter path-slot diversity under skewed pool |
| `exit_max_per_jurisdiction` / `exit_charter_pass` | Exit concentration vs charter ≤1/jur |
| `authorities_meet_charter_diversity` | Trustee jurisdiction count ≥2 |
| `rate_limited_rejects` | Slow-pipeline residual when rate limit on |

## Client path-select (wave B2)

Opt-in soft enforcement on roster-driven client paths (default **off**):

```toml
[path]
require_diverse_jurisdictions = true
max_per_jurisdiction = 1   # default when diversity enabled; ignored when off
```

Wires to `build_bound_path_diverse_pruned` / mitigated compose when
`[guard_mitigation] preset = "adaptive_v4"` (or other presets) is also set.
This is **software path resampling**, not charter/legal quota enforcement.

## Honest leftovers

- **Legal vetting / sanctions screening:** External — not modeled as crypto.
- **Binding diversity quotas / charter enforcement:** Still **External** (counsel /
  auditor process). Client knobs only reject concentrated hops at path-build time;
  they do not admit, revoke, or legally certify jurisdiction labels.
- **Multi-org BFT reputation / global revocation:** External.
- This sim does **not** claim consortium governance closed.

## Related

- [`CONSORTIUM_CHARTER.md`](CONSORTIUM_CHARTER.md) §5–§8
- [`ATTACK_PLAYBOOK.md`](ATTACK_PLAYBOOK.md) §6 (consortium faction)
- [`RESEARCH_AGENDA.md`](RESEARCH_AGENDA.md) §1 / §4 governance
- [`RESEARCH_COVERAGE_WAVE.md`](RESEARCH_COVERAGE_WAVE.md) track C3
- [`adaptive_guard_mitigation.md`](adaptive_guard_mitigation.md) — compose with adaptive_v4
- [`PILOT.md`](PILOT.md) — client `[path]` knobs
