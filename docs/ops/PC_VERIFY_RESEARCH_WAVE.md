# PC verify + research wave (no Docker)

**Date:** 2026-07-18  
**Tip baseline:** 3819c1b → **landed at `c7c2f0d`**  
**Status:** **Landed** (S1–S6 Done). Hub: [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md).  
**Goal:** Max security verify + research on this PC.  
**Out of scope:** Docker, false formal-proof claims, inventing WAN C2.

| ID | Track | Deliverable | Status | Not claimed |
|----|-------|-------------|--------|-------------|
| S1 | Sphinx P1 | Python bit-oracle + KATs + fuzz deepen | **Done** — see § S1 how-to | Mechanized proof |
| S2 | Threat-model crypto gaps | Gaps → tests/docs | **Done** — see § S2 | Hardware TEE |
| S3 | Symbolic Sphinx | ProVerif model (best effort) | **Done** — see § S3 | Full EasyCrypt |
| S4 | Exit + cover multi-hop | Defense sims from C2/C5 | **Done** — see § S4 | Info-theoretic |
| S5 | Gossip K + adaptive/fused | `adaptive_v4` + stacked gossip | **Done** — see § S5 | Field rates |
| S6 | CT / SoftHSM / Noise | Evidence + Noise note | **Done** — see § S6 | Isolated dudect bar |

**Execution:** Grok 4.5 agents in parallel; parent integrates.  
**Operator entry:** [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md).

---

## S3 status (2026-07-18) — **done**

**Status:** Best-effort ProVerif symbolic model (idealized hop peel + MAC + replay).  
**Owned:** `tools/proverif/`, [`sphinx_symbolic_model.md`](sphinx_symbolic_model.md)

| Check | Result |
|-------|--------|
| Tool | WSL2 yes; ProVerif **2.05** via `~/tools/proverif_linux_amd64_static` (no Docker; no sudo apt) |
| L1 Secrecy | **Proved** — `not attacker(secret_payload)` (`sphinx_hop.pv`) |
| L2 Integrity | **Proved** — `ExitDeliver(sid, secret_payload) ⇒ ClientBuilt(sid)` |
| L3 Replay | **Proved** — `inj-event(HopAccept(t)) ⇒ inj-event(ClientBuilt(t))` (`sphinx_replay.pv`) |

```bash
# WSL / Linux
tools/proverif/run_proverif.sh
# Windows host → WSL
powershell -File tools/proverif/run_proverif.ps1
```

**Not claimed:** EasyCrypt; computational ML-KEM proof; anonymity sims; bit-exact Rust Sphinx.

---

## S5 status (2026-07-18) — **done**

**Status:** **[O] QUANTIFIED Partial** — gossip + adaptive/fused defenses ranked in-sim; **§13 not closed**; field rates unmeasured.

| Track | Deliverable | Best defense | Metrics vs prior | Honest residual |
|-------|-------------|--------------|------------------|-----------------|
| Gossip (C1→S5) | `gossip_eclipse_defense.py` + `gossip_eclipse_defense.analysis.json` | **`stacked`** (K=4 + min_orgs=2 + eclipse-detect) | Lower FP / eclipse frac vs C1 baseline at partial `f` | `f=1` saturates; multi-org BFT External |
| Adaptive (C2→S5) | `mitigated_v4` + Rust `adaptive_v4` + `adaptive_v4_saturation.analysis.json` | **`adaptive_v4`** | ~14 pp better than v3 at E=2000 (sim); also better at E=200 | Still → high at long E; §13 [O] |
| Fused (C2→S5) | `fused_defense.py` + `fused_defense.analysis.json` | **`fused_v4`** (+ `hard_cap_forced` for Mode-1) | Lower dirty-epoch frac → Mode-1 stays hard_cap longer | Not WAN closed; adaptive exposure remains |

**Pilot:** `sim/data/pilot_configs/client.toml` comments `preset = "adaptive_v4"`.  
**Docs:** playbook §3 / §7.1 / §10 · [`adaptive_guard_mitigation.md`](adaptive_guard_mitigation.md).

```bash
cd sim && PYTHONPATH=. python scripts/run_gossip_eclipse_defense.py
cd sim && PYTHONPATH=. python scripts/run_fused_defense.py
cd sim && PYTHONPATH=. python scripts/run_adaptive_v4_saturation.py
cd sim && PYTHONPATH=. pytest -q tests/test_gossip_eclipse_defense.py tests/test_fused_defense.py \
  tests/test_hardening.py::test_mitigated_v4_improves_e2000_vs_v3
cargo test -p aegis-topology guard_mitigation
```

**Not claimed:** §13 closed, field recompromise rates, multi-org BFT gossip, WAN fused C2.

### S1 how to run

```bash
# Python oracle + adversarial unit tests
cd sim && PYTHONPATH=. pytest -q tests/test_sphinx_oracle.py

# Rust gate + additive KATs
cargo test -p aegis-crypto --test vectors
cargo test -p aegis-crypto python_oracle_shared_primitive_kats

# Fuzz evidence pack (WSL/Linux; prefer this over bare cargo-fuzz)
# Evidence pointer: sim/sphinx_fuzz_evidence.txt (wave A6 deepen)
python scripts/seed_sphinx_fuzz_corpus.py
SPHINX_FUZZ_MODE=short bash scripts/run_sphinx_fuzz_evidence.sh          # ~12 min
# SPHINX_FUZZ_MODE=overnight bash scripts/run_sphinx_fuzz_evidence.sh    # 8h
# Windows host → WSL:
#   powershell -File scripts/run_sphinx_fuzz_evidence.ps1 -Mode short
```

**S1 fuzz evidence:** [`sim/sphinx_fuzz_evidence.txt`](../../sim/sphinx_fuzz_evidence.txt) · harness notes in `crates/aegis-crypto/fuzz/README.md`.  
**Not claimed:** Mechanized Sphinx proof (crash/panic search only).

---

## S4 status (2026-07-18) — **done**

**Status:** **[O] QUANTIFIED Partial** — defenses ranked in-sim; **not** info-theoretic / WAN closed.

| Track | Deliverable | Recommended (sim) | Metrics | Honest residual |
|-------|-------------|-------------------|---------|-----------------|
| Exit-tier (C2→S4) | `exit_tier_defense.py` + `sim/data/exit_tier_defense*.json` + tests | `presence_pad` @E=100 (strongest: `pool_hard_cap`) | `composite_risk`, `p_intersection_singleton`, `p_volume_rank_top` | Clearnet cannot hard-cap; long-E tip-∩ residual; decoy cost |
| Cover multi-hop (C5→S4) | `cover_multihop_defense.py` + `sim/data/cover_multihop_defense*.json` + tests | `cover_onions` (ops lever: `matched_local_discard`) | `implied_packet_continuity`→1.0, `semantic_gap_score`, hop L1 | Product still `COVER_FRAGMENT_RESERVED` local discard |

**Docs:** [`exit_tier_defense.md`](exit_tier_defense.md) · [`cover_multihop_defense.md`](cover_multihop_defense.md) · playbook §7 / §9 rows.  
**Rust (at S4 land):** policy comment only in `crates/aegis-relay/src/cover_flow.rs`.  
**Later product (A2/A3/B1 → tip `c7c2f0d`):** `[exit].presence_pad`; `[cover] multihop_defense` = `matched_local_discard` / `cover_onions` / scaffold — see [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md).

```bash
cd sim && PYTHONPATH=. python scripts/run_exit_tier_defense.py
cd sim && PYTHONPATH=. python scripts/run_cover_multihop_defense.py
cd sim && PYTHONPATH=. pytest -q tests/test_exit_tier_defense.py tests/test_cover_multihop_defense.py
```

**Not claimed (S4-era residual; still true for science):** Info-theoretic cover indistinguishability, WAN exit C2 close. Peelable cover onions later shipped as product opt-in (B1) — not info-theoretic.

---

## S2 status (2026-07-18) — **done**

**Owner deliverables**

| Artifact | Path |
|----------|------|
| Gap ledger | [`CRYPTO_THREAT_GAP_LEDGER.md`](CRYPTO_THREAT_GAP_LEDGER.md) |
| Property tests | `crates/aegis-crypto/tests/threat_model_gaps.rs` |
| Threat model updates | `docs/AEGIS_implementation_threat_model.md` §1 + client send crypto rows |
| Small fix | `SPHINX_PACKET_LEN` docs 8504 → **8512** (`sphinx.rs`) |

**Gaps closed / tested**

- Link identity + KEM commitment binding fail-closed (wrong peer / wrong commitment)
- AEAD frame width quantified (no peer-id field)
- Tampered gamma → `IntegrityFailure` (functional MAC gate)
- Fixed 8512 B / 18-fragment surface + reassembly round-trip
- Replay duplicate reject + capacity bound under flood
- Opaque hop-id round-trip on peel (documents out-of-crate PKI trust)

**Residuals accepted (honest)**

- MAC / replay post-`ct_eq` branch timing → S6 / `dudect` (Low)
- Replay O(capacity) CPU (Low)
- Config-held link PSK / shared ingress static; AEAD frames anonymous (Low–medium)
- No rate limit inside `aegis-crypto` — relay ingress owns it (Low)
- Malicious client path pick / raw `--raw` unpaced (Low / Low–medium)

**Verify:** `cd crates && cargo test -p aegis-crypto --test threat_model_gaps` (10 passed, 2026-07-18)

**Not claimed:** Hardware TEE, Tamarin, anonymity sims. (Sphinx Python oracle is S1.)

---

## S6 status (2026-07-18) — **done**

**Track:** CT / SoftHSM / Noise research deepen (no Docker).

### (a) Noise_IK vs LegacyPsk + KEM binding

| Artifact | Path |
|----------|------|
| Research note | [`noise_vs_legacy_kem_binding.md`](noise_vs_legacy_kem_binding.md) |
| Operator Noise | [`noise_link_auth.md`](noise_link_auth.md) |

- Noise_IK: mutual static X25519; **no** roster KEM commitment in transcript.
- LegacyPsk: PSK-MAC + optional relay-id / KEM commitment binding.
- Fail-closed: `require_ingress_kem_commitment` + Noise → Malformed (no silent bind loss).
- Residual: KEM bind ≠ PQ HS; Auto mode asymmetry; AEGIS `LinkKey` domain mix ≠ raw Noise transport.

### (b) SoftHSM

| Check | Result |
|-------|--------|
| Probe | `SOFTHSM_USABLE=1` (user-local 2.6.1; `SUDO_NOPASSWD=no`) |
| Ceremony regress | [`scripts/softhsm_ceremony_regress.sh`](../../scripts/softhsm_ceremony_regress.sh) → `RESULT_CODE=SUCCEEDED` |
| Evidence | [`sim/softhsm_ceremony_regress.txt`](../../sim/softhsm_ceremony_regress.txt); init append `ALREADY_INITIALIZED` |
| Custody tests | 8 passed (`SimulatedHsm` / Hardware fail-closed) |

```powershell
powershell -File scripts/softhsm_wsl.ps1 -Action regress -Evidence
```

**Not claimed:** Hardware custody (software token only; PKCS#11 Rust link still External).

### (c) Constant-time / dudect

| Check | Result |
|-------|--------|
| `timing_smoke` + `dudect_smoke` (WSL) | **green** |
| Short lab (`DUDECT_LAB_MODE=short`) | ≈0.09 M / 0.08 M traces; `BUDGET_EXHAUSTED`; `external_bar_met=NO` |
| Prior deepen (same host; not re-run) | ≈81.95 M replay / 1.05 M MAC; WSL, not isolated |
| External bar | **unmet** |

Docs: [`constant_time_ci.md`](constant_time_ci.md).

### Honest limits

- SoftHSM ≠ tamper-resistant HSM.
- WSL dudect ≠ External isolated ≥1e5/primitive.
- Noise note = code reading + existing tests; not Tamarin/EasyCrypt.
- Out of scope this wave: Sphinx oracle rewrite, Tamarin, anonymity defense sims.
