# Productize leftovers wave (no Docker)

**Date:** 2026-07-18  
**Tip baseline:** 7cada32 → **landed at `c7c2f0d`**  
**Status:** **Landed** (B1–B3 Done/Shipped). Hub: [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md).  
**Goal:** Close remaining productize/research gaps on this PC.  
**Out of scope:** Docker, false §13/EasyCrypt closure, External TEE/HSM/BFT/WAN-C2.

| ID | Track | Deliverable | Honest leftover |
|----|-------|-------------|-----------------|
| B1 | cover_onions peelable | **Shipped:** opt-in `multihop_defense=cover_onions` — valid Sphinx to terminal → peel-then-discard at `COVER_SINK_HOP_ID` (not client exit). Scaffold remains distinct. | Full multi-hop forwardable cover; directory PK distro; info-theoretic |
| B2 | Jurisdiction path-select | **Done** — `[path] require_diverse_jurisdictions` / `max_per_jurisdiction` → diverse pruned (+ adaptive_v4 compose) | Charter legal enforcement still **External** |
| B3 | Joint guard×gossip adversary | **Done** — sim + artifact + CI | Field rates unmeasured |

**B3 deliverables:** `sim/aegis_sim/joint_guard_gossip.py`, `sim/data/joint_guard_gossip.analysis.json`, `sim/scripts/run_joint_guard_gossip.py`, `sim/tests/test_joint_guard_gossip.py`. Tag **[O] QUANTIFIED**; **§13 not closed**. Cross-ref [`ATTACK_PLAYBOOK.md`](ATTACK_PLAYBOOK.md) §3 + §10.

**Execution:** Grok 4.5 agents in parallel; parent integrates.  
**Operator entry:** [`PILOT.md`](PILOT.md) · [`DEPLOYMENT.md`](DEPLOYMENT.md) · [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md).
