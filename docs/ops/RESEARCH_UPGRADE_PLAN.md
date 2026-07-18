# AEGIS research & anonymity upgrade plan

**Date:** 2026-07-18  
**Tip baseline:** 29e89f5 → research-upgrade wave (this commit)  
**Goal:** Advance anonymity, attack resistance, and research evidence as far as software allows.  
**Honest limit:** Real C2 captures, SoftHSM/Docker without sudo, TEE/HSM hardware, formal Sphinx proofs, and multi-org BFT remain External or operator-gated.  
**Status:** W1–W4 **landed in-repo** (Partial/quantified). Science items remain **[O]** — not closed.

## Workstreams

| ID | Workstream | In-repo deliverable | External leftover |
|----|------------|---------------------|-------------------|
| W1 | Adaptive compromise defense v2 | Stronger sim mitigation + Rust policy + client signal hooks | Field validation |
| W2 | Combined active+intersection defense | Sim defenses ranking + Mode-1 hard-cap enforcement notes/tests | WAN adversary |
| W3 | GPA / cover anonymity | Cover timing metrics v2; ingress client-binding Partial | Info-theoretic cover |
| W4 | Attack playbook + Sphinx properties | [`ATTACK_PLAYBOOK.md`](ATTACK_PLAYBOOK.md) + extra Sphinx/property gates | Formal proof |
| W5 | Reputation/gossip anonymity | Stronger nullifier/AC docs + gossip eclipse notes | Real AC / multi-org BFT |
| W6 | CT / ceremony ops | Evidence refresh; SoftHSM/Docker unblock checklist | Isolated dudect; sudo |

## Acceptance (this wave)

1. Plan committed; RESEARCH_AGENDA points here and to [`ATTACK_PLAYBOOK.md`](ATTACK_PLAYBOOK.md).
2. W1–W4 land with tests green.
3. No false “research closed” claims.
4. Operator unblock steps listed for SoftHSM/Docker/C2.

## Execution

Composer 2.5 agents run W1–W4 in parallel; parent integrates, tests, pushes.
