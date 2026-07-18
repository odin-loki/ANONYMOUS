# AEGIS research & anonymity upgrade plan (historical)

**Date:** 2026-07-18  
**Status:** **Historical — waves landed.** Do not treat this file as the live backlog.  
**Tip at close of leftovers:** `c7c2f0d`  
**Live hub:** [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md)  
**Live backlog:** [`RESEARCH_AGENDA.md`](RESEARCH_AGENDA.md) · matrix [`RESEARCH_OPS_STATUS.md`](RESEARCH_OPS_STATUS.md)

**Honest limit (unchanged):** Real Docker daemon (ops-dependent), TEE/vendor HSM hardware, formal computational Sphinx proofs, operational C2, and multi-org BFT remain External or operator-gated. SoftHSM software-token pilot **Succeeded**. Science items remain **[O]** — **research is not closed.**

---

## Landed workstreams (W1–W6)

Originally scoped from tip `ae536f1` → SoftHSM/science v3 (`649c4a7`) and onward. All rows below are **complete as in-repo deliverables**; leftovers are honest External / [O], not missing wiring.

| ID | Workstream | Landed deliverable | Honest leftover |
|----|------------|--------------------|-----------------|
| W1 | Adaptive compromise defense | **v1–v4**; prefer **`adaptive_v4`** (~14 pp vs v3 @ E=2000) | Field validation; long-horizon saturation |
| W2 | Combined active+intersection | Expanded ranking; hard_cap best; Mode-1 ops doc; fused_v4 | WAN adversary |
| W3 | GPA / cover anonymity | Cover CV/KS; ingress KEM fail-closed; **B1 peelable `cover_onions`** | Info-theoretic cover; forwardable multi-hop |
| W4 | Attack playbook + Sphinx properties | Playbook; KATs; S1 oracle; **ProVerif**; A6 fuzz | EasyCrypt / computational proof |
| W5 | Reputation/gossip anonymity | Stacked gossip **A1**; AC scaffolding; C4 sim | Real AC / multi-org BFT |
| W6 | CT / ceremony ops | SoftHSM **Succeeded** (user-local); Docker offline pack; dudect deepen | Docker Desktop; isolated dudect; vendor HSM |

---

## Follow-on waves (also landed)

| Wave | Tip / note | Doc |
|------|------------|-----|
| Coverage C1–C6 | Gossip, exit/fused, faction, AC, cover/metrics, dudect | [`RESEARCH_COVERAGE_WAVE.md`](RESEARCH_COVERAGE_WAVE.md) |
| PC-verify S1–S6 | Oracle, ProVerif, SoftHSM, adaptive_v4, stacked gossip | [`PC_VERIFY_RESEARCH_WAVE.md`](PC_VERIFY_RESEARCH_WAVE.md) |
| Productize A1–A6 | Stacked gossip, presence_pad, cover match, metrics gate, fuzz | [`PRODUCTIZE_DEFENSES_WAVE.md`](PRODUCTIZE_DEFENSES_WAVE.md) |
| Leftovers B1–B3 | Peelable `cover_onions`, jurisdiction paths, joint guard×gossip | [`PRODUCTIZE_LEFTOVERS_WAVE.md`](PRODUCTIZE_LEFTOVERS_WAVE.md) · tip **c7c2f0d** |

---

## Original acceptance (met for in-repo scope)

1. SoftHSM evidence `RESULT_CODE=SUCCEEDED` (software token) — **met**.
2. Docker offline validate green when daemon absent — **met** (daemon itself External/ops).
3. adaptive_v4 + combined + cover/Sphinx tests green; no “research closed” claims — **standing rule**.
4. Pilot templates document `preset = "adaptive_v4"` — **met** (comments; default remains off).

---

## Where to go next

Use [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md) for status narrative and [`RESEARCH_AGENDA.md`](RESEARCH_AGENDA.md) §7 for the open session backlog. This upgrade plan is retained only as a wave history pointer.
