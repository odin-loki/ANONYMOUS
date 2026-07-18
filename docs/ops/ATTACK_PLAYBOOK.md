# AEGIS attack playbook (operator / research)

**Date:** 2026-07-18  
**Tip baseline:** 29e89f5  
**Adversary baseline:** nation-state global passive adversary (GPA) + active fraction `f` of compromised mixes on a **permissioned consortium** mixnet.

This document maps named attack primitives to **current mitigation status**, **residual risk**, and **in-repo evidence**. It does **not** claim spec §13 closed, formal Sphinx proofs, or operational C2 validation.

**Cross-references:** [`AEGIS_implementation_threat_model.md`](../AEGIS_implementation_threat_model.md) · [`AEGIS_phase8_hardening_notes.md`](../AEGIS_phase8_hardening_notes.md) · [`RESEARCH_AGENDA.md`](RESEARCH_AGENDA.md) · [`RESEARCH_UPGRADE_PLAN.md`](RESEARCH_UPGRADE_PLAN.md) · [`adaptive_guard_mitigation.md`](adaptive_guard_mitigation.md) · [`anonymous_reputation.md`](anonymous_reputation.md) · [`health_gossip.md`](health_gossip.md) · [`CONSORTIUM_CHARTER.md`](CONSORTIUM_CHARTER.md)

**Legend:** **Mitigated** · **Partial** · **Open [O]** · **By design** · **External**

---

## How to read mitigation vs residual

| Column | Meaning |
|--------|---------|
| **Mitigation status** | What the codebase + ops defaults do today |
| **Residual** | What a capable adversary can still do |
| **Evidence** | Sim artifact, test, or threat-model citation |

---

## 1. Global passive adversary (GPA)

**Threat:** Observer on all links and ingress/egress sees timing, volume, and (where unshaped) cadence.

| Surface | Mitigation status | Residual | Evidence |
|---------|-------------------|----------|----------|
| Client TCP ingress (default paced CLI) | **Partial** — `PacedSession` + continuous dummy cover; τ-aligned cells | Raw/`--raw`/`send_payload` bypass emitter; handshake per session; adversarial custom client | Threat model §6 `aegis-client`; Phase 8 §4 benign vs malicious traces |
| Per-hop mixing delay Exp(μ) | **By design** — delay visible on link | GPA learns delay samples; not the primary hiding primitive | Threat model §2 `aegis-relay` |
| Relay cover bursts (τ-paced) | **Partial (2026-07-18)** — cover cells AEAD-sealed, same width; τ dispatcher; multi-hop semantic gap quantified | Cover discarded / invalid onion ≠ Sphinx forward continuity; shape GPA on long horizons | `cover_flow.rs`, `cover_burst_gpa_characterization.json`, `cover_multihop_characterization.json` |
| Exit → clearnet server | **By design (weaker tier)** — sender-side shaping to exit; receiver not in AEGIS | GPA at exit server link sees ordinary TLS/volume; no receiver hard-cap | Phase 8 §3 exit-tier; spec §8 |
| Sticky guard entry pin | **By design** — GPA learns one guard id per client epoch | Bounded by plateau math if `c` small; adaptive adversary worsens (§4) | Threat model §3 guards; `adaptive_guard_exposure.analysis.json` |

**GPA summary:** Default product path is **Partial** against link timing correlation. Deliberate raw APIs and exit-tier traffic remain the largest honest residuals.

---

## 2. Fraction `f` compromised mixes

**Threat:** Adversary controls fraction `f` of relays; learns plaintext at owned hops; biases routing if guards/path selection fail.

| Control | Mitigation status | Residual | Evidence |
|---------|-------------------|----------|----------|
| Path inner hops (CSPRNG per packet) | **Mitigated** | Compromised hop still sees peel plaintext | Threat model §3 `path::select_path_indexed_impl` |
| Guard set g=3 + reputation filter | **Mitigated (2026-07-17)** | Sticky **primary** is g=1 entry pin; honest-pool failure at extreme `c` | `sybil_admission.rs`; threat model §3 |
| Probationary admission (0.1) + rate limit | **Mitigated** | Slow Sybil flood, not impossible with compromised consortium keys | `RosterAdmissionPolicy` default 5/24h |
| M-of-N threshold roster admission | **Mitigated** | ≥M authority compromise or correlated keys | `ThresholdConsortium`, `CONSORTIUM_CHARTER.md` |
| Compromised relay forward path | **Mitigated** — onion peel only | Standard mixnet assumption: owner sees one layer | Threat model §2 |

**f-compromised summary:** Production APIs combine multi-guard + rep filter + signed roster. Residual is **standard mixnet layer compromise** plus **guard-entry observability** and **adaptive recompromise** (§4).

---

## 3. Adaptive compromise (varying compromised set)

**Threat:** Adversary recompromises relays across epochs; guard stickiness lets exposure grow toward 1.0.

| Layer | Mitigation status | Residual | Evidence |
|-------|-------------------|----------|----------|
| Sim quantification | **Open [O] QUANTIFIED** | Unmitigated adaptive → ~1.0 by E=200 (`c=0.015`, `g=3`) | `sim/data/adaptive_guard_exposure.analysis.json`; `test_hardening.py` |
| v1 mitigation (`mode='mitigated_first'`) | **Partial** — lower curve, not closed | ~0.90 at E=200; → 1.0 at E=2000 | Artifact `mitigated_first_by_epochs` |
| v2 mitigation (`mode='mitigated'`) | **Partial** — ~13 pp better than v1 at E=200 | ~0.77 at E=200; → 1.0 at E=2000 | Artifact `mitigated_by_epochs` |
| v3 mitigation (`mode='mitigated_v3'`) | **Partial** — ~32 pp better than v2 at E=200 | ~0.45 at E=200; still → ~0.99 at E=2000 (saturation residual) | Artifact `mitigated_v3_by_epochs`; [`adaptive_guard_mitigation.md`](adaptive_guard_mitigation.md) |
| v4 mitigation (`mode='mitigated_v4'`) | **Partial (S5)** — tighter sticky + stronger demotion; best long-horizon sim | ~0.23 at E=200; ~0.85 at E=2000 (~14 pp better than v3; still saturates) | `sim/data/adaptive_v4_saturation.analysis.json`; `test_hardening.py` |
| Rust client preset | **Partial** — hard/soft sticky + resample hooks | Defaults **disabled**; prefer `preset = "adaptive_v4"` (or `adaptive_v3` / `adaptive_v2` / legacy `adaptive_first`) | `aegis-topology/src/guard_mitigation.rs`; client `[guard_mitigation]` + `[path].epoch_age` |

**Adaptive summary:** **Partial v1–v4** lowers sim exposure (v4 best at E=2000; v3 still strong mid-horizon); **does not close §13**. Operators enable `preset = "adaptive_v4"` on clients for pilot; field recompromise rates unmeasured.

---

## 4. Combined active (n−1) + intersection (Mode 1)

**Threat:** Active sender suppression + long-horizon intersection on constant-rate Mode 1 traffic.

| Defense | Mitigation status | Residual | Evidence |
|---------|-------------------|----------|----------|
| Hard-cap receiver padding (`HardCapPadder`) | **Mitigated** (internal tier only) | Exit / non-AEGIS receivers **excluded** | Rust `padding.rs`; [`combined_attack_mode1_hardcap.md`](combined_attack_mode1_hardcap.md) |
| Sim `hard_cap` / `deferred_hard_cap` | **Mitigated in model** | Synthetic; no WAN adversary | `combined_active_intersection.analysis.json` ranking |
| Constant-rate without receiver hard-cap | **Partial** | `constant_only` → ~1.0 by E=1600 | Same artifact `curves.constant_only` |
| `pad_up` / `truncate_only` / `noisy_hard_cap` | **Partial** | pad_up ~0.085@E=1600 / ~0.27@E=6400 (Q=25); truncate/noisy → ~1.0; high Q collapses pad_up toward hard_cap | Artifact curves + sensitivity_Q + offline |
| Larger anonymity set M | **Does not close** | hard_cap ~1/M; pad_up stays high | Artifact `sensitivity.anonymity_set_M` |

**Operators must enable:** Mode-1 paced sessions + receiver hard-cap with `Q ≥ ~1.2×` sustained mean on internal-tier peers. Do not swap in pad-up for “efficiency.”

**Combined attack summary:** **Open [O] QUANTIFIED**, **not mitigated** in production-science sense (exit-tier exclusion + synthetic model). Recommended defense remains **hard-cap**; no ranked scheme beats it without lying about production observables. Offline curves extend to E=6400 in the artifact.

---

## 5. Malicious client

**Threat:** Custom or `--raw` client floods ingress, picks paths, or skips paced/cover policy.

| Vector | Mitigation status | Residual | Evidence |
|--------|-------------------|----------|----------|
| Unpaced flood at ingress | **Partial** — ingress token bucket + global budget; silent drop | TCP accept + handshake before limit; many connections | `IngressRateLimitConfig`; threat model §2, §6 |
| Malicious burst trace | **Partial** — shapeability **cheap** tier when unpaced | `events_per_slot_max` 12 vs 4 benign; CV 0.34 | `sim/data/real_testnet_malicious_trace.csv`, `.analysis.json`; `trace_capture.rs` |
| Path picking | **Open** if client ignores topology | Low severity — hurts sender anonymity, not relay integrity | Threat model §6 |
| Default CLI paced session | **Mitigated** | Residual only if operator uses `--raw` or deprecated APIs | `aegis-client` session default |

**Malicious client summary:** Relays **rate-limit** floods; product default **paces**. Raw integration paths remain **Partial** side channels for GPA.

---

## 6. Consortium faction / authority compromise

**Threat:** Coalition of consortium authorities or operators signs bad relays, blocks good ones, or concentrates exit/guard roles.

| Control | Mitigation status | Residual | Evidence |
|---------|-------------------|----------|----------|
| M-of-N threshold admission | **Mitigated** | Compromise ≥M distinct keys; correlated jurisdictions | `ThresholdConsortium`; [`consortium_key_ceremony.md`](consortium_key_ceremony.md) |
| Admission rate limit | **Mitigated** | Slow Sybil pipeline | `sybil_admission.rs` |
| Jurisdiction diversity | **External / policy** | Charter goals not enforced in code | [`CONSORTIUM_CHARTER.md`](CONSORTIUM_CHARTER.md) § diversity |
| Exit concentration policy | **External / policy** | Code does not cap exits per jurisdiction | Charter § exit approval |
| Compromised faction + honest rep | **Partial** — probation + gossip median | Colluding `majority_k` neighbors bias health merge | §10 below; threat model §4 |
| Faction key-fraction × jurisdiction-skew (sim) | **[O] QUANTIFIED** | Sybil admit ≈0 if faction keys `< M`, ≈1 if `≥ M`; skewed pool raises guard/exit/path concentration; rate limit slows flood only | `sim/aegis_sim/faction_sybil_skew.py`; artifact `sim/data/faction_sybil_skew.json`; [`faction_sybil_skew.md`](faction_sybil_skew.md) |

**Consortium faction summary:** Cryptographic admission is **Mitigated** with M-of-N; **governance and geographic diversity** remain **External**. Legal vetting is **External**. Jurisdiction-skew profiling characterizes capture under correlated keys — it does **not** close governance.

---

## 7. Exit observation

**Threat:** Observer at exit relay or clearnet next hop learns payload timing, volume, or correlates flows.

| Surface | Mitigation status | Residual | Evidence |
|---------|-------------------|----------|----------|
| Terminal peel delivery | **Partial** — optional `[exit]` sink on exit hops only | Mix relays must not enable exit sink | Phase 8 §5 `[exit]`; `exit_sink.rs` |
| Payload extraction | **By design at exit** — exit operator sees delta | Trust exit operator; separate exit approval in charter | `sphinx::process` peel |
| Sender anonymity set at exit | **Partial [O] QUANTIFIED** — multi-client exit window | No receiver hard-cap on clearnet; long-horizon ∩ / volume ranking above 1/N | `sim/data/exit_tier_intersection.analysis.json`; `exit_tier_intersection.py` |
| Clearnet residual volume | **By design (weaker)** — unshaped exit↔server link | GPA sees ordinary encrypted volume; Mode-1 hard-cap does not transfer | Phase 8 §3; artifact `honest_limits` / `wan_closed: false` |
| Exit-tier defenses (S4) | **Partial [O] QUANTIFIED** — ranked sim pads/decoys | Clearnet still cannot hard-cap; decoys burn bandwidth; tip knowledge residual | `exit_tier_defense.py`; `sim/data/exit_tier_defense.analysis.json`; [`exit_tier_defense.md`](exit_tier_defense.md) |
| Trace `[trace].path` on mix hops | **Mitigated** — off by default in production template | Misconfig leaks forward timing | [`DEPLOYMENT.md`](DEPLOYMENT.md) |

**Exit observation summary:** **Weaker tier by design.** Position as sender-anonymity-set to exit, not internal Mode 1 receiver guarantees. Sim C2 quantifies co-active window sizes and long-horizon intersection/volume ranking on unshaped clearnet residual — **not WAN closed**. Wave S4 recommends `presence_pad` at E=100 (practical); `pool_hard_cap` is strongest composite; product egress pad hooks are **not shipped**.

### 7.1 Fused long-horizon adversary (adaptive ∩ active/intersection)

**Threat:** Adaptive recompromise of the client's guard set **plus** Mode-1 active suppression / intersection on the same horizon (coverage wave C2).

| Surface | Status | Residual | Evidence |
|---------|--------|----------|----------|
| Adaptive-only baseline | **[O] QUANTIFIED** | Exposure → ~1 at long E (`c=0.015`, `g=3`) | `adaptive_guard_exposure.analysis.json` (reused) |
| Combined-only baseline | **[O] QUANTIFIED** | `constant_only` saturates; `hard_cap` ~1/M | `combined_active_intersection.analysis.json` (reused) |
| Fused coupling | **[O] QUANTIFIED** | Dirty epochs unlock leaky Mode-1 obs; clean epochs stay hard_cap | `sim/data/fused_adversary.analysis.json`; `fused_adversary.py` |
| Fused defenses (S5) | **Partial [O] QUANTIFIED** — `fused_v4` / `hard_cap_forced` | v4 lowers dirty-epoch frac so Mode-1 stays hard_cap longer; forced hard_cap keeps confirm ~1/M but not adaptive exposure | `fused_defense.py`; `sim/data/fused_defense.analysis.json` |

**Fused note:** Coupling gates Mode-1 leakage on adaptive exposure — union success tracks the worse surface; hard_cap on clean epochs does not erase adaptive risk. S5 `fused_v4` reduces leaky epochs via adaptive_v4; **does not close §13**. **Not WAN closed**; exit clearnet residual remains a separate weaker tier (§7).

---

## 8. Metrics scrape (coarse relay stats)

**Threat:** GPA or operator scrapes relay load/error counters at high frequency to infer traffic.

| Surface | Mitigation status | Residual | Evidence |
|---------|-------------------|----------|----------|
| External export | **Mitigated** — `RelayCoarseStats` only (`processed_ok/fail`, `cover_emitted`, queue drops) | High-frequency scrape under flood may still correlate load | Threat model exec summary #4; §2 `RelayCoarseStats` |
| Fine-grained counters | **Mitigated** — `debug_stats` in-process / tests only | Leak if exported to Prometheus by mistake | `RelayHandle::debug_stats` docs |
| Ingress drop counters | **Partial** — coarse `IngressRateLimitStats` | Confirms attack volume to observer with metrics access | `aegis-relay` net |
| Flood volume via scrape deltas | **Partial (2026-07-18)** — lab model: `dropped_frames` recovers most excess attack volume; KS(flood, baseline) > 0 | Not an info-theoretic leakage bound; depends on scrape cadence | `sim/data/metrics_sidechannel_characterization.json` |
| Flood timing via scrape envelope | **Partial** — Pearson(scrape Δ dropped/load_proxy, attack windows) high at 1s scrapes | Coarser scrapes blur timing but volume residual remains | `metrics_sidechannel.py`; interval sweep in artifact |
| Cover-round `cover_emitted` | **Partial** — scrape Δ tracks cover-flow ground truth in model | Intended coarse ops signal; still confirms cover schedule to metrics observer | artifact `cover_bulk_round` |

**Metrics scrape summary:** **Do not export `debug_stats`.** Coarse buckets are **Mitigated** for intended ops; scraping under attack is **Open [O] QUANTIFIED** (volume + coarse timing) — **Low–medium** residual, not closed.

---

## 9. Cover distinguishability (GPA timing)

**Threat:** GPA distinguishes paced bulk Sphinx fragments from cover bursts or unpaced gaps.

| Measurement | Mitigation status | Residual | Evidence |
|-------------|-------------------|----------|----------|
| Inter-cell gap τ alignment | **Partial** — paced bulk / cover+τ `fraction_near_tau` high under active emission | Not info-theoretic indistinguishability | `sim/data/cover_burst_gpa_characterization.json` |
| Gap CV (bulk vs cover+bulk) | **Partial** — cover lowers CV (`gap_cv_ratio_cover_over_bulk` < 1 in model) | Multi-hop semantic difference remains | `cover_timing.py`; `test_cover_burst_gpa.py` |
| Gap KS + histogram L1 | **Partial** — two-sample KS D + τ-multiple gap histograms in artifact | Distributional comparison only; not a proof | artifact `delta.gap_ks_distance_*`, `gap_histogram` |
| Burst-heavy scenario | **Partial** — baseline + `burst_heavy` bundle in same artifact | Lab model; not WAN GPA | `compare_cover_modes_under_burst` |
| Multi-hop semantic gap | **Partial (2026-07-18)** — cover/invalid lower `implied_packet_continuity` vs Sphinx-only; raise `semantic_gap_score` | Single-hop gap CV can still look τ-like while hop semantics diverge | `cover_multihop.py`; `sim/data/cover_multihop_characterization.json` |
| Cover discard vs Sphinx forward | **Partial** — next hop discards `COVER_FRAGMENT_RESERVED`; forwards do not continue | GPA with ≥2 hop vantage sees wire≠forward yield | `cover_flow.rs`; multihop artifact `delta.continuity_ratio_*` |
| Cover multi-hop defenses (S4) | **Partial [O] QUANTIFIED** — cover onions restore continuity≈1 in-sim; matched discard lowers hop L1 | Product still local-discard only; peelable cover onions not shipped | `cover_multihop_defense.py`; `sim/data/cover_multihop_defense.analysis.json`; [`cover_multihop_defense.md`](cover_multihop_defense.md) |
| Invalid onion (fail peel) | **Partial** — modeled as non-forwarding wire inflation (like discard, different counter path) | Contributes `processed_fail` if it reaches peel; semantic gap score rises | multihop `sphinx_plus_invalid` |
| Reserved-byte cover marker | **Mitigated** — cover never reassembled as Sphinx | Volume/count correlation still possible | Phase 8 cover marker notes |
| Ingress KEM client-binding | **Partial** — `require_ingress_kem_commitment` fail-closed on LegacyPsk; matching binding required | Noise_IK does not bind KEM commitment (fails closed if require+Noise); holders of ingress PSK + correct commitment still admitted | `aegis-relay` `net.rs`; node `[link].require_ingress_kem_commitment` |

**Cover distinguishability summary:** **Open [O] QUANTIFIED** — single-hop CV/KS/histogram + multi-hop semantic-gap gates in CI; **formal indistinguishability not claimed**.

---

## 10. Reputation / gossip anonymity (eclipse, `majority_k`)

**Threat:** Adversary eclipses a victim's gossip view, forges health adverts, or colludes `K` neighbors to demote honest relays; anonymous reputation replay or issuer linkage.

See also [`anonymous_reputation.md`](anonymous_reputation.md) § anonymity bounds and [`health_gossip.md`](health_gossip.md).

| Vector | Mitigation status | Residual | Evidence |
|--------|-------------------|----------|----------|
| **Gossip eclipse** | **Partial** — **[O] QUANTIFIED** neighbor-only adverts; peer table from config | Victim with `adv ≥ K` under coordinated report-first gets pure-adv medians; full eclipse (`f=1`) → bias≈0.9 / FP≈1 in sim; no global view | `sim/aegis_sim/gossip_eclipse.py`; `sim/data/gossip_eclipse*.json`; [`health_gossip.md`](health_gossip.md); threat model §4 |
| **Gossip defenses (S5)** | **Partial [O] QUANTIFIED** — raised K + org diversity + eclipse-detect (`stacked`) | Cuts FP vs C1 baseline at partial `f`; `f=1` still saturates / needs quarantine | `gossip_eclipse_defense.py`; `sim/data/gossip_eclipse_defense.analysis.json` |
| **`majority_k` collusion** | **Partial** — **[O] QUANTIFIED** K distinct authority reporters before median merge (default K=2) | Solo quorum needs `adv ≥ K`; mixed sets where adv hold median majority (e.g. 2-of-3) still attack-rate; half-weight preserves ratio | `PeerHealthTracker::apply_gossip_outcomes`; C1 gates `test_gossip_eclipse.py` |
| Equivocation | **Mitigated** — quorum log rejects conflicting `(epoch, reporter, subject)` | Local log only; not multi-org BFT | `health_quorum_log.rs` |
| Anonymous presentation | **Partial** — no RelayId in proof blob | Issuer learns id at issue; local nullifier only | `anonymous_reputation.md` |
| Cross-node nullifier | **Partial** — file export/merge | No wire gossip consensus; eclipse of merge path | `NullifierRegistry::merge_from_file` |
| Issuer correlation / blinded nullifier link | **Partial [O] QUANTIFIED** — wave C4 lab | Residual 1.0 at issue; blinded path still links via nullifier log; **interactive ZK External / not done** | `sim/data/ac_nullifier_unlinkability.json`; `ac_nullifier_unlinkability.py` |
| Nullifier merge eclipse / delayed merge | **Partial [O] QUANTIFIED** — partition + delay + suppress scenarios | Double-accept until merge; exposure ≈ delay/window; suppress export ⇒ residual 1.0 | C4 artifact; Rust `partition_allows_double_accept_until_merge` |
| Multi-org BFT reputation | **External** | Not in scope — C1 sim does **not** close this | `RESEARCH_AGENDA.md` §1 |

**Eclipse / majority_k guidance for operators:**

- Set `majority_k ≥ 2` in production; prefer **K≥3–4** where peer-table size allows (S5 `raised_k`); **`majority_k = 1` is lab-only**.
- Diversify gossip neighbors across operators/jurisdictions (S5 `diverse_org` / `min_orgs≥2`); monitor for partition.
- Prefer eclipse-detect quarantine when merge median diverges sharply from local health (S5 heuristic; sim-proposed).
- Do not treat gossip median as ground truth without independent health checks.
- Treat C1/S5 sim numbers as characterization only: raising `K` blocks solo eclipse but not colluding median majorities inside a `K`-set; multi-org BFT remains External.
- Anonymous credentials: treat issuer as trusted at issue time; use epoch rotation + nullifier merge only with authenticated operator channels.
- Nullifier sync: authenticate `export_to_file` / `merge_from_file` channels; minimize merge delay; do not treat file merge as consensus. See C4 residual scores in `sim/data/ac_nullifier_unlinkability.json`.

---

## 11. Sphinx crypto properties (non-proof)

**Threat:** Implementation bugs in peel order, path bounds, MAC, replay.

| Property | Mitigation status | Residual | Evidence |
|----------|-------------------|----------|----------|
| Fixed packet size | **Mitigated** | Doc historically said 8504; wire size is **8512** | `vectors.rs` `constant_size_*`; `SPHINX_PACKET_LEN` |
| MAC before peel | **Mitigated** | Timing branch after verify (low) | Phase 2 gate; CT review |
| Replay cache | **Mitigated** | O(capacity) CPU under flood | `replay.rs` |
| Hop peel ordering / next-hop ids | **Partial [T]** — 2/3/max-hop KATs + all-length property | Per-hop DH blinding documented as best-effort in `kem.rs` | `vectors.rs` `hop_peel_ordering_*`, `peel_order_property_all_path_lengths` |
| Wrong-hop / later-secret / skip-hop peel | **Partial [T]** — integrity fail | Not a formal unlinkability proof | `wrong_hop_secret_rejected_*`, `later_hop_secret_cannot_peel_*`, `skip_hop_secret_rejected` |
| Seeded relay-key structural KAT | **Partial [T]** — size + peel-order stability | Encapsulation RNG still live (`OsRng`); no official cross-impl vector | `seeded_relay_keys_build_size_and_peel_kat` |
| Alpha/gamma/beta tagging bit-flips | **Mitigated [T]** — hop-0 integrity fail | Delta not under gamma (by design) | `tamper_alpha_or_gamma_rejected`, `tagging_bit_flip_map_beta_rejects`, `delta_bit_flip_does_not_fail_hop0_mac` |
| Python bit-oracle (build/peel/MAC/replay) | **Partial [T] (S1)** — secrets+headers oracle; KEM Rust-only | No hybrid encap in Python; not a proof | `sim/aegis_sim/sphinx_oracle.py`, `test_sphinx_oracle.py`, `python_oracle_shared_primitive_kats` |
| Max-path forward count | **Partial [T]** | Terminal hop still Forward to exit id | `vectors.rs` `max_hops_forward_count_is_layers_minus_one` |
| LibFuzzer `fuzz_sphinx_process` | **Partial [T]** — harness + overnight recipe | Empty corpus was easy gap; seeder added | `fuzz/README.md`, `scripts/seed_sphinx_fuzz_corpus.py` |
| Formal verification | **Open [O] External** | Mechanized proof not in repo | `RESEARCH_AGENDA.md` §5 |

**Sphinx summary (surgical S1):** Phase-2 KATs + Python oracle + tagging/path/wrong-hop gates; **formal proof explicitly not claimed**.

---

## 12. Regenerate evidence

```bash
# Sim §13 artifacts
cd sim && PYTHONPATH=. python scripts/generate_research_artifacts.py
cd sim && PYTHONPATH=. python scripts/run_cover_burst_gpa_characterization.py
cd sim && PYTHONPATH=. python scripts/run_cover_multihop_characterization.py
cd sim && PYTHONPATH=. python scripts/run_exit_tier_defense.py
cd sim && PYTHONPATH=. python scripts/run_cover_multihop_defense.py
cd sim && PYTHONPATH=. python scripts/run_metrics_sidechannel_characterization.py
cd sim && PYTHONPATH=. python scripts/run_c2_shapeability_pipeline.py --synthetic-stress
cd sim && PYTHONPATH=. python -m aegis_sim.ac_nullifier_unlinkability
cd sim && PYTHONPATH=. pytest -q tests/test_hardening.py tests/test_cover_burst_gpa.py tests/test_cover_multihop.py tests/test_exit_tier_defense.py tests/test_cover_multihop_defense.py tests/test_metrics_sidechannel.py tests/test_c2_shapeability_pipeline.py tests/test_ac_nullifier_unlinkability.py

# Sphinx property gates + S1 oracle
cargo test -p aegis-crypto --test vectors
cargo test -p aegis-crypto python_oracle_shared_primitive_kats
cd sim && PYTHONPATH=. pytest -q tests/test_sphinx_oracle.py
# Overnight fuzz (WSL): see crates/aegis-crypto/fuzz/README.md

# Ingress KEM commitment (Partial)
cargo test -p aegis-relay require_ingress_kem_commitment

# Malicious trace (ignored integration)
cargo test -p aegis-node --test trace_capture -- --ignored
```

---

## 13. Honest limits (this wave)

| Claim | Status |
|-------|--------|
| Attack playbook closes §13 | **False** — maps status + residuals |
| All attacks mitigated | **False** — see §4, §9, adaptive §3 |
| Gossip eclipse solved | **False** — **[O] QUANTIFIED Partial** (C1 sim); multi-org BFT still External |
| Sphinx formally verified | **False** — KATs/property tests only |

**Upgrade plan:** W4 (this doc + Sphinx gates) and W5 (§10) tracked in [`RESEARCH_UPGRADE_PLAN.md`](RESEARCH_UPGRADE_PLAN.md).
