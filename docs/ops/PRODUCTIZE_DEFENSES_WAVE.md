# Productize defenses wave (no Docker)

**Date:** 2026-07-18  
**Tip baseline:** ddaad73  
**Goal:** Land sim-recommended defenses into product + deepen fuzz/metrics research on this PC.  
**Out of scope:** Docker, false §13/formal-proof closure, inventing WAN C2.

| ID | Track | Deliverable | Honest leftover |
|----|-------|-------------|-----------------|
| A1 | Gossip stacked | **Done** — `GossipMergePolicy` stacked defaults (K=4, min_orgs=2, eclipse-detect); TOML + PeerInfo org/jurisdiction | Multi-org BFT; `f=1` still saturates |
| A2 | Exit presence_pad | **Done** — `[exit].presence_pad` matched-Q decoy/idle pad (default off) | Clearnet GPA |
| A3 | Cover multi-hop | **Shipped:** opt-in `matched_local_discard` + `cover_onions_scaffold` (still discard) | Info-theoretic / Sphinx continuity |
| A4 | Metrics scrape harden | **Done** — `MetricsExportGate` + `[metrics]` (cadence 30s / quantize 16 / suppress drops); `operator_check` warns on high-res | Privileged raw `coarse_stats` / high-res opt-in |
| A5 | Metrics scrape defense sim | **Done** — `metrics_scrape_defense.py` ranks `stacked` vs C5 Pearson; artifact + pytest | Not closed; fail/queue residual |
| A6 | Sphinx fuzz evidence | **Done** — timed libFuzzer + [`sim/sphinx_fuzz_evidence.txt`](../../sim/sphinx_fuzz_evidence.txt) | Mechanized proof |

**Execution:** Grok 4.5 agents in parallel; parent integrates.

---

## A6 status (2026-07-18) — **done**

**Status:** WSL nightly + cargo-fuzz evidence pack for `fuzz_sphinx_process`.  
**Captured:** `max_total_time=720s` (agent short mode); wall ~762s; **~171492 execs**; cov 708; **crashes=0**.  
**Not claimed:** Mechanized / EasyCrypt proof; exhaustive Sphinx validity.

| Artifact | Path |
|----------|------|
| Evidence | [`sim/sphinx_fuzz_evidence.txt`](../../sim/sphinx_fuzz_evidence.txt) |
| Seeder | `scripts/seed_sphinx_fuzz_corpus.py` (22 layout/boundary seeds) |
| Runner | `scripts/run_sphinx_fuzz_evidence.sh` · `.ps1` |
| Harness | `crates/aegis-crypto/fuzz/` |

```bash
SPHINX_FUZZ_MODE=short bash scripts/run_sphinx_fuzz_evidence.sh       # ~12 min
SPHINX_FUZZ_MODE=overnight bash scripts/run_sphinx_fuzz_evidence.sh   # 8h
powershell -File scripts/run_sphinx_fuzz_evidence.ps1 -Mode overnight
```

**Honest residual:** Crash/panic search only; fixed harness key → most inputs hit early KEM/MAC reject (libFuzzer corp stayed tiny in short run).
