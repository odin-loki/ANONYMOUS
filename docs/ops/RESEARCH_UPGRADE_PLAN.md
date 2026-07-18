# AEGIS research & anonymity upgrade plan

**Date:** 2026-07-18  
**Tip baseline:** ae536f1 → operator+science wave (buckets 1+3)  
**Goal:** Advance anonymity, attack resistance, and research evidence as far as software allows.  
**Honest limit:** Real Docker daemon, TEE/HSM hardware (beyond SoftHSM software token), formal Sphinx proofs, operational C2, and multi-org BFT remain External or operator-gated.  
**Status:** W1–W4 landed earlier; **bucket-1 SoftHSM succeeded (user-local)**; Docker offline-hardened (daemon absent); **adaptive_v3 + combined ranking + cover/Sphinx/C2 pipeline** advanced. Science items remain **[O]** — not closed.

## Workstreams

| ID | Workstream | In-repo deliverable | External leftover |
|----|------------|---------------------|-------------------|
| W1 | Adaptive compromise defense | **v3** sim + Rust `adaptive_v3` (~32 pp vs v2 at E=200) | Field validation; long-horizon saturation |
| W2 | Combined active+intersection defense | Expanded ranking; hard_cap still best; Mode-1 ops doc | WAN adversary |
| W3 | GPA / cover anonymity | Cover CV/KS/histograms v2; ingress KEM fail-closed | Info-theoretic cover |
| W4 | Attack playbook + Sphinx properties | Playbook + expanded Sphinx KATs | Formal proof |
| W5 | Reputation/gossip anonymity | Prior Partial notes | Real AC / multi-org BFT |
| W6 | CT / ceremony ops | SoftHSM **Succeeded** (user-local); Docker offline pack | Docker Desktop; isolated dudect |

## Acceptance (this wave)

1. SoftHSM evidence `RESULT_CODE=SUCCEEDED` or honest blocked codes.
2. Docker: offline validate green; no false “containers running” if daemon absent.
3. adaptive_v3 + combined + cover/Sphinx tests green; no “research closed” claims.
4. Pilot templates document `preset = "adaptive_v3"`.

## Execution

Grok 4.5 agents: SoftHSM ∥ Docker ∥ adaptive ∥ combined ∥ cover/Sphinx/C2; parent integrates, tests, pushes.
