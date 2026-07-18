# AEGIS attack playbook (operator / research)

**Date:** 2026-07-18  
**Tip baseline:** c7c2f0d  
**Adversary baseline:** nation-state global passive adversary (GPA) + active fraction `f` of compromised mixes on a **permissioned consortium** mixnet.

This document maps named attack primitives to **current mitigation status**, **residual risk**, and **in-repo evidence**. It does **not** claim spec §13 closed, formal Sphinx computational proofs, or operational C2 validation.

**Cross-references:** [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md) (adversary models + science status) · [`AEGIS_implementation_threat_model.md`](../AEGIS_implementation_threat_model.md) · [`AEGIS_phase8_hardening_notes.md`](../AEGIS_phase8_hardening_notes.md) · [`RESEARCH_AGENDA.md`](RESEARCH_AGENDA.md) · [`RESEARCH_UPGRADE_PLAN.md`](RESEARCH_UPGRADE_PLAN.md) · [`adaptive_guard_mitigation.md`](adaptive_guard_mitigation.md) · [`anonymous_reputation.md`](anonymous_reputation.md) · [`health_gossip.md`](health_gossip.md) · [`CONSORTIUM_CHARTER.md`](CONSORTIUM_CHARTER.md) · [`PC_VERIFY_RESEARCH_WAVE.md`](PC_VERIFY_RESEARCH_WAVE.md) · [`PRODUCTIZE_DEFENSES_WAVE.md`](PRODUCTIZE_DEFENSES_WAVE.md) · [`PRODUCTIZE_LEFTOVERS_WAVE.md`](PRODUCTIZE_LEFTOVERS_WAVE.md)

**Legend:** **Mitigated** · **Partial** · **Open [O]** · **By design** · **External**

---

## How to read mitigation vs residual

| Column | Meaning |
|--------|---------|
| **Mitigation status** | What the codebase + ops defaults do today |
| **Residual** | What a capable adversary can still do |
| **Evidence** | Sim artifact, test, or threat-model citation |

---

## 0. Theory — adversary models (why mitigations work / fail)

Operators need the *model*, not only the knob. Full narrative lives in [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md); this section is the playbook digest.

| Surface | Adversary model (short) | Why mitigations help | Why they still fail / residual |
|---------|-------------------------|----------------------|--------------------------------|
| **GPA** | Sees all links: timing, volume, cadence; no key break required | τ-aligned paced cells + cover raise cost of emission-process distinguishability | Raw/`--raw` bypass; exit clearnet unshaped; cover discard ≠ Sphinx continuity; not info-theoretic |
| **Adaptive** | Recompromises relays across epochs; sticky guard → exposure → 1 | `adaptive_v4` caps sticky tenure + demotes dirty guards → slows curve | Long-E saturation (~0.85@E=2000); field `c` unmeasured; §13 **[O]** |
| **Combined (n−1 ∩)** | Active sender suppression + long-horizon intersection on Mode-1 | Receiver `HardCapPadder` flattens observables → confirm ~1/M | Exit / non-AEGIS receivers excluded; pad_up / truncate lose; synthetic model |
| **Exit** | Observer at exit↔clearnet sees residual volume / presence | `presence_pad` matched-Q idle/active decoys raise tip-∩ cost | Clearnet cannot hard-cap; WAN C2 **not** closed; default **off** |
| **Gossip** | Eclipse peer table / collude `K` reporters → bias health median | Stacked `K=4` + `min_orgs=2` + eclipse-detect raises solo-eclipse bar | `f=1` saturates; multi-org collusion meeting `min_orgs` still biases; BFT **External** |
| **Cover** | GPA compares wire yield vs forward continuity across hops | `matched_local_discard` aligns volume; `cover_onions` peel-to-sink restore continuity≈1 in-sim | Sink ≠ client exit; lab KEM seeds ≠ directory PK; not info-theoretic |
| **Sphinx** | Crypto adversary: peel order, MAC, replay, tagging (not traffic analysis) | KATs + Python oracle + ProVerif L1–L3 (symbolic) catch class bugs | Idealized Dolev–Yao ≠ ML-KEM reduction; EasyCrypt **External**; anonymity out of scope |

**Product snapshot at tip `c7c2f0d`:** prefer client `preset = "adaptive_v4"`; gossip **stacked** defaults; opt-in `[exit].presence_pad`; opt-in `[cover] multihop_defense = cover_onions | matched_local_discard`; `[metrics]` via `MetricsExportGate`; `[path] require_diverse_jurisdictions` / `max_per_jurisdiction`; SoftHSM ceremony **Succeeded** (software token only).

---

## 1. Global passive adversary (GPA)

### Theory

A GPA does not need to break Sphinx. It correlates **emission processes**: when a client sends, when cover fires, and how volume appears at exit. Mixing delay Exp(μ) is **visible noise**, not the hiding primitive — sender-side pacing + cover + (internal) hard-cap are. Mitigations fail when the product path is bypassed (`--raw`), when cover is local-discard only (wire≠forward), or when the observer sits on clearnet past the exit.

| Surface | Mitigation status | Residual | Evidence |
|---------|-------------------|----------|----------|
| Client TCP ingress (default paced CLI) | **Partial** — `PacedSession` + continuous dummy cover; τ-aligned cells | Raw/`--raw`/`send_payload` bypass emitter; handshake per session; adversarial custom client | Threat model §6 `aegis-client`; Phase 8 §4 benign vs malicious traces |
| Per-hop mixing delay Exp(μ) | **By design** — delay visible on link | GPA learns delay samples; not the primary hiding primitive | Threat model §2 `aegis-relay` |
| Relay cover bursts (τ-paced) | **Partial** — cover cells AEAD-sealed, same width; τ dispatcher; multi-hop gap quantified; A3 `matched_local_discard`; B1 peelable `cover_onions` opt-in | Local-discard cover ≠ Sphinx continuity; peelable onions are **sink-discard** (not client exit); not info-theoretic | `cover_flow.rs`; `sim/data/cover_burst_gpa_characterization.json`; `sim/data/cover_multihop_characterization.json`; `sim/data/cover_multihop_defense.analysis.json` |
| Exit → clearnet server | **By design (weaker tier)** — sender-side shaping to exit; receiver not in AEGIS | GPA at exit server link sees ordinary TLS/volume; no receiver hard-cap | Phase 8 §3 exit-tier; spec §8; §7 |
| Sticky guard entry pin | **By design** — GPA learns one guard id per client epoch | Bounded by plateau math if `c` small; adaptive adversary worsens (§3) | Threat model §3 guards; `sim/data/adaptive_guard_exposure.analysis.json` |

**GPA summary:** Default product path is **Partial** against link timing correlation. Deliberate raw APIs and exit-tier traffic remain the largest honest residuals.

---

## 2. Fraction `f` compromised mixes

**Threat:** Adversary controls fraction `f` of relays; learns plaintext at owned hops; biases routing if guards/path selection fail.

| Control | Mitigation status | Residual | Evidence |
|---------|-------------------|----------|----------|
| Path inner hops (CSPRNG per packet) | **Mitigated** | Compromised hop still sees peel plaintext | Threat model §3 `path::select_path_indexed_impl` |
| Guard set g=3 + reputation filter | **Mitigated** | Sticky **primary** is g=1 entry pin; honest-pool failure at extreme `c` | `sybil_admission.rs`; threat model §3 |
| Probationary admission (0.1) + rate limit | **Mitigated** | Slow Sybil flood, not impossible with compromised consortium keys | `RosterAdmissionPolicy` default 5/24h |
| M-of-N threshold roster admission | **Mitigated** | ≥M authority compromise or correlated keys | `ThresholdConsortium`; `CONSORTIUM_CHARTER.md` |
| Jurisdiction path knobs (B2) | **Partial** — opt-in `[path] require_diverse_jurisdictions` / `max_per_jurisdiction` (composes with `adaptive_v4`) | Soft software filter only; charter/legal enforcement **External** | `faction_sybil_skew.md`; `PILOT.md`; tip leftovers B2 |
| Compromised relay forward path | **Mitigated** — onion peel only | Standard mixnet assumption: owner sees one layer | Threat model §2 |

**f-compromised summary:** Production APIs combine multi-guard + rep filter + signed roster + optional jurisdiction prune. Residual is **standard mixnet layer compromise** plus **guard-entry observability** and **adaptive recompromise** (§3).

---

## 3. Adaptive compromise (varying compromised set)

### Theory

Sticky guards create a **sampling bias**: once a compromised relay is pinned as primary entry, the adversary’s observation window grows with epoch stickiness. Unmitigated exposure → ~1.0 by long E. Mitigations (`adaptive_v4` best) shorten sticky tenure and demote dirty guards so the client resamples — they **slow** the curve; they do **not** erase long-horizon saturation when recompromise rate `c` stays positive. Field `c` is unmeasured → §13 stays **[O]**.

| Layer | Mitigation status | Residual | Evidence |
|-------|-------------------|----------|----------|
| Sim quantification | **Open [O] QUANTIFIED** | Unmitigated adaptive → ~1.0 by E=200 (`c=0.015`, `g=3`) | `sim/data/adaptive_guard_exposure.analysis.json`; `test_hardening.py` |
| v1 mitigation (`mode='mitigated_first'`) | **Partial** — lower curve, not closed | ~0.90 at E=200; → 1.0 at E=2000 | Artifact `mitigated_first_by_epochs` |
| v2 mitigation (`mode='mitigated'`) | **Partial** — ~13 pp better than v1 at E=200 | ~0.77 at E=200; → 1.0 at E=2000 | Artifact `mitigated_by_epochs` |
| v3 mitigation (`mode='mitigated_v3'`) | **Partial** — ~32 pp better than v2 at E=200 | ~0.45 at E=200; still → ~0.99 at E=2000 (saturation residual) | Artifact `mitigated_v3_by_epochs`; [`adaptive_guard_mitigation.md`](adaptive_guard_mitigation.md) |
| v4 mitigation (`mode='mitigated_v4'`) | **Partial (S5)** — tighter sticky + stronger demotion; **best long-horizon sim** | ~0.23 at E=200; ~0.85 at E=2000 (~14 pp better than v3; still saturates) | `sim/data/adaptive_v4_saturation.analysis.json`; `test_hardening.py` |
| Rust client preset | **Partial** — hard/soft sticky + resample hooks | Defaults **disabled**; prefer `preset = "adaptive_v4"` (or `adaptive_v3` / `adaptive_v2` / legacy `adaptive_first`) | `aegis-topology/src/guard_mitigation.rs`; client `[guard_mitigation]` + `[path].epoch_age` |

**Adaptive summary:** **Partial v1–v4** lowers sim exposure (v4 best at E=2000; v3 still strong mid-horizon); **does not close §13**. Operators enable `preset = "adaptive_v4"` on clients for pilot; field recompromise rates unmeasured.

### 3.1 Joint adaptive-guard × gossip-eclipse (leftovers B3)

**Threat:** Same-horizon adaptive recompromise of the client's guard set **plus** coordinated gossip eclipse / `majority_k` collusion on the victim peer table (boosted: dirty epochs seat compromised guards as eclipse reporters).

| Surface | Status | Residual | Evidence |
|---------|--------|----------|----------|
| Adaptive-only baseline | **[O] QUANTIFIED** | Exposure → ~1 at long E | `adaptive_guard_exposure.analysis.json` (reused) |
| Gossip-only baseline | **[O] QUANTIFIED Partial** | FP / eclipse vs `(f,K,N)` | `gossip_eclipse*.json` (reused); §10 |
| Joint boosted coupling | **[O] QUANTIFIED** | At `f=0.125`/`K=2` independent rarely eclipses; dirty epochs unlock `adv≥K` → eclipse rises with exposure | `sim/data/joint_guard_gossip.analysis.json`; `joint_guard_gossip.py` |
| Joint defense (`mitigated_v4` + stacked gossip) | **Partial [O] QUANTIFIED** | Lowers union/joint at partial `f`; **`f=1` / long-E still saturate** | Artifact `joint_defense`; §10 stacked |

**Joint note:** Characterization only — **does not close §13**. Field recompromise and peer-table eclipse rates are **unmeasured** free parameters (`c`, `f`). Multi-org BFT remains **External**. See also §10.

---

## 4. Combined active (n−1) + intersection (Mode 1)

### Theory

The n−1 (active) adversary suppresses all but one sender while an intersection adversary accumulates who was online across epochs. On **constant-rate Mode 1**, presence itself is the signal. Receiver hard-cap forces every epoch to look identical (confirm ~1/M). Schemes that only pad-up, truncate, or add noise leak presence/volume and re-saturate. Exit-tier receivers are **out of model** — hard-cap does not transfer to clearnet (§7).

| Defense | Mitigation status | Residual | Evidence |
|---------|-------------------|----------|----------|
| Hard-cap receiver padding (`HardCapPadder`) | **Mitigated** (internal tier only) | Exit / non-AEGIS receivers **excluded** | Rust `padding.rs`; [`combined_attack_mode1_hardcap.md`](combined_attack_mode1_hardcap.md) |
| Sim `hard_cap` / `deferred_hard_cap` | **Mitigated in model** | Synthetic; no WAN adversary | `sim/data/combined_active_intersection.analysis.json` ranking |
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
| SoftHSM ceremony pilot (S6) | **Partial** — **Succeeded** user-local SoftHSM2 2.6.1 software token + PKCS#11 probe | **Not** tamper-resistant HSM; vendor HSM / Rust PKCS#11 link still **External** | [`softhsm_ceremony.md`](softhsm_ceremony.md); `sim/softhsm_ceremony_regress.txt` (`RESULT_CODE=SUCCEEDED`) |
| Admission rate limit | **Mitigated** | Slow Sybil pipeline | `sybil_admission.rs` |
| Jurisdiction diversity (charter) | **External / policy** | Charter goals not legally enforced | [`CONSORTIUM_CHARTER.md`](CONSORTIUM_CHARTER.md) § diversity |
| Jurisdiction path knobs (product B2) | **Partial** — soft path prune opt-in | Labels spoofable without admission policy; legal vetting **External** | `[path] require_diverse_jurisdictions`; `faction_sybil_skew.md` |
| Exit concentration policy | **External / policy** | Code does not cap exits per jurisdiction | Charter § exit approval |
| Compromised faction + honest rep | **Partial** — probation + stacked gossip median | Colluding `majority_k` + `min_orgs` neighbors bias health merge | §10 below; threat model §4 |
| Faction key-fraction × jurisdiction-skew (sim) | **[O] QUANTIFIED** | Sybil admit ≈0 if faction keys `< M`, ≈1 if `≥ M`; skewed pool raises guard/exit/path concentration; rate limit slows flood only | `sim/aegis_sim/faction_sybil_skew.py`; `sim/data/faction_sybil_skew.json`; [`faction_sybil_skew.md`](faction_sybil_skew.md) |

**Consortium faction summary:** Cryptographic admission is **Mitigated** with M-of-N; SoftHSM pilot is a **software-token** success path for ceremony ops. **Governance and geographic diversity** remain **External**. Jurisdiction path knobs are soft Partial only.

---

## 7. Exit observation

### Theory

Past the last mix hop, AEGIS ends. The exit↔clearnet link is ordinary encrypted volume: Mode-1 receiver hard-cap **does not apply**. Intersection and volume-ranking attacks exploit tip-sparse co-active windows. `presence_pad` activates idle clients at matched Q so tip-∩ and volume rank degrade — at bandwidth cost — but a GPA on the server link still sees padded clearnet traffic. Position as **sender-anonymity-set to exit**, not internal Mode 1 guarantees.

| Surface | Mitigation status | Residual | Evidence |
|---------|-------------------|----------|----------|
| Terminal peel delivery | **Partial** — optional `[exit]` sink on exit hops only | Mix relays must not enable exit sink | Phase 8 §5 `[exit]`; `exit_sink.rs` |
| Payload extraction | **By design at exit** — exit operator sees delta | Trust exit operator; separate exit approval in charter | `sphinx::process` peel |
| Sender anonymity set at exit | **Partial [O] QUANTIFIED** — multi-client exit window | No receiver hard-cap on clearnet; long-horizon ∩ / volume ranking above 1/N | `sim/data/exit_tier_intersection.analysis.json`; `exit_tier_intersection.py` |
| Clearnet residual volume | **By design (weaker)** — exit↔server link | GPA sees ordinary encrypted volume (optionally matched-Q padded); Mode-1 hard-cap does not transfer | Phase 8 §3; artifact `honest_limits` / `wan_closed: false` |
| Exit-tier defenses (S4→A2) | **Partial [O] QUANTIFIED** + **product opt-in** — `[exit].presence_pad` matched-Q decoy/idle pad (default **off**) | Clearnet still cannot hard-cap; pad burns bandwidth; tip knowledge + long-E residual; `pool_hard_cap` sim-only | `sim/data/exit_tier_defense.analysis.json`; [`exit_tier_defense.md`](exit_tier_defense.md); `exit_sink.rs` |
| Trace `[trace].path` on mix hops | **Mitigated** — off by default in production template | Misconfig leaks forward timing | [`DEPLOYMENT.md`](DEPLOYMENT.md) |

**Exit observation summary:** **Weaker tier by design.** Sim C2 quantifies co-active window sizes and long-horizon intersection/volume ranking on clearnet residual — **not WAN closed**. Wave S4 recommends `presence_pad` at E=100 (practical); `pool_hard_cap` is strongest composite. Wave A2 ships opt-in exit-sink `[exit].presence_pad` (default off, exit hops only); clearnet GPA residual remains.

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
| Ingress drop counters | **Partial** — coarse `IngressRateLimitStats`; production export **suppresses** drop detail via `MetricsExportGate` | Raw `dropped_frames()` still confirms volume to privileged observers | `aegis-relay` `metrics_export` / `net` |
| Export cadence / quantize | **Mitigated** — default min scrape 30s + quantize bucket 16; high-res opt-in only | Callers that bypass the gate (raw `coarse_stats`) keep high-res deltas | `[metrics]` TOML; `MetricsExportConfig::production()` |
| Flood volume via scrape deltas | **Partial** — lab model: `dropped_frames` recovers most excess attack volume; KS(flood, baseline) > 0 | Not an info-theoretic leakage bound; depends on scrape cadence | `sim/data/metrics_sidechannel_characterization.json` |
| Flood timing via scrape envelope | **Partial** — Pearson(scrape Δ dropped/load_proxy, attack windows) high at 1s scrapes | Coarser scrapes blur timing but volume residual remains | `metrics_sidechannel.py`; interval sweep in artifact |
| Scrape defenses (A5) | **Partial [O] QUANTIFIED** — stacked cadence+quantize+suppress ranked best vs C5 Pearson≈0.97 | Privileged / high-res observer residual; fail/queue buckets can still correlate | `metrics_scrape_defense.py`; `sim/data/metrics_scrape_defense.analysis.json`; [`metrics_scrape_defense.md`](metrics_scrape_defense.md) |
| Cover-round `cover_emitted` | **Partial** — scrape Δ tracks cover-flow ground truth in model | Intended coarse ops signal; still confirms cover schedule to metrics observer | artifact `cover_bulk_round` |

**Metrics scrape summary:** **Do not export `debug_stats`.** Use **`MetricsExportGate`** / `[metrics]` defaults for external scrapes. Coarse buckets are **Mitigated** for intended ops; scraping under attack remains **Open [O] QUANTIFIED** (volume + coarse timing) — **Low–medium** residual for privileged observers, not closed.

---

## 9. Cover distinguishability (GPA timing)

### Theory

Single-hop τ alignment can make cover *look* like bulk while multi-hop semantics diverge: `COVER_FRAGMENT_RESERVED` is discarded, so wire volume ≠ forward yield. A GPA with ≥2 hop vantage exploits that gap. `matched_local_discard` aligns schedules across hops (volume). `cover_onions` emit valid Sphinx to a terminal peer, peel, then sink at `COVER_SINK_HOP_ID` — restoring continuity≈1 in-sim without delivering client exit traffic. Neither is info-theoretic indistinguishability; lab peer KEM seeds are not directory PK distribution.

| Measurement | Mitigation status | Residual | Evidence |
|-------------|-------------------|----------|----------|
| Inter-cell gap τ alignment | **Partial** — paced bulk / cover+τ `fraction_near_tau` high under active emission | Not info-theoretic indistinguishability | `sim/data/cover_burst_gpa_characterization.json` |
| Gap CV (bulk vs cover+bulk) | **Partial** — cover lowers CV (`gap_cv_ratio_cover_over_bulk` < 1 in model) | Multi-hop semantic difference remains | `cover_timing.py`; `test_cover_burst_gpa.py` |
| Gap KS + histogram L1 | **Partial** — two-sample KS D + τ-multiple gap histograms in artifact | Distributional comparison only; not a proof | artifact `delta.gap_ks_distance_*`, `gap_histogram` |
| Burst-heavy scenario | **Partial** — baseline + `burst_heavy` bundle in same artifact | Lab model; not WAN GPA | `compare_cover_modes_under_burst` |
| Multi-hop semantic gap | **Partial** — cover/invalid lower `implied_packet_continuity` vs Sphinx-only; raise `semantic_gap_score` | Single-hop gap CV can still look τ-like while hop semantics diverge | `cover_multihop.py`; `sim/data/cover_multihop_characterization.json` |
| Cover discard vs Sphinx forward | **Partial** — next hop discards `COVER_FRAGMENT_RESERVED`; forwards do not continue | GPA with ≥2 hop vantage sees wire≠forward yield | `cover_flow.rs`; multihop artifact `delta.continuity_ratio_*` |
| Cover multi-hop defenses (S4→A3/B1) | **Partial** — in-sim cover onions → continuity≈1; product opt-in `matched_local_discard`; **`cover_onions`** peel-to-sink (valid Sphinx → terminal → `COVER_SINK_HOP_ID`); scaffold remains discard-only | Full multi-hop forwardable cover deferred; lab peer KEM seeds ≠ directory PK distro; not client exit traffic; not info-theoretic | `cover_flow.rs` `CoverMultihopDefense`; TOML `[cover] multihop_defense=cover_onions`; `sim/data/cover_multihop_defense.analysis.json`; [`cover_multihop_defense.md`](cover_multihop_defense.md) |
| Invalid onion (fail peel) | **Partial** — modeled as non-forwarding wire inflation (like discard, different counter path) | Contributes `processed_fail` if it reaches peel; semantic gap score rises | multihop `sphinx_plus_invalid` |
| Reserved-byte cover marker | **Mitigated** — cover never reassembled as Sphinx | Volume/count correlation still possible | Phase 8 cover marker notes |
| Ingress KEM client-binding | **Partial** — `require_ingress_kem_commitment` fail-closed on LegacyPsk; matching binding required | Noise_IK does not bind KEM commitment (fails closed if require+Noise); holders of ingress PSK + correct commitment still admitted | `aegis-relay` `net.rs`; node `[link].require_ingress_kem_commitment` |

**Cover distinguishability summary:** **Open [O] QUANTIFIED** — single-hop CV/KS/histogram + multi-hop semantic-gap gates in CI; product peel-to-sink / matched discard are **Partial** opt-ins; **formal indistinguishability not claimed**.

---

## 10. Reputation / gossip anonymity (eclipse, `majority_k`)

### Theory

Gossip is neighbor-only: the victim’s peer table *is* the universe. If `adv ≥ majority_k` reporters (and they meet `min_orgs`), the median can be pure-adversary. Raising K and requiring cross-org labels blocks **solo** eclipse; eclipse-detect quarantines high-gap medians vs local/honest baseline. None of this invents honest signal under `f=1`, and colluding multi-org sets that satisfy `min_orgs` still win. Multi-org BFT reputation is **External**.

See also [`anonymous_reputation.md`](anonymous_reputation.md) § anonymity bounds and [`health_gossip.md`](health_gossip.md).

| Vector | Mitigation status | Residual | Evidence |
|--------|-------------------|----------|----------|
| **Gossip eclipse** | **Partial** — **[O] QUANTIFIED** neighbor-only adverts; peer table from config | Victim with `adv ≥ K` under coordinated report-first gets pure-adv medians; full eclipse (`f=1`) → bias≈0.9 / FP≈1 in sim; no global view | `sim/aegis_sim/gossip_eclipse.py`; `sim/data/gossip_eclipse.analysis.json`; `sim/data/gossip_eclipse_offline.json`; [`health_gossip.md`](health_gossip.md); threat model §4 |
| **Joint adaptive × gossip (B3)** | **[O] QUANTIFIED** — shared-epoch coupling; see §3.1 | Boosted dirty epochs raise effective `f`; union ≥ either surface; field rates unmeasured | `joint_guard_gossip.py`; `sim/data/joint_guard_gossip.analysis.json` |
| **Gossip defenses (S5 → product)** | **Partial [O] QUANTIFIED** — Rust **`stacked`** (`majority_k=4` + `min_orgs=2` + eclipse-detect) | Cuts FP vs C1 at partial `f`; **`f=1` still saturates**; multi-org collusion meeting `min_orgs` still biases median | Product: `GossipMergePolicy` / `PeerHealthTracker`; `sim/data/gossip_eclipse_defense.analysis.json`; [`health_gossip.md`](health_gossip.md) |
| **`majority_k` collusion** | **Partial** — **[O] QUANTIFIED** K distinct authority reporters before median merge (default **K=4**) | Solo quorum needs `adv ≥ K`; mixed sets where adv hold median majority still attack-rate; half-weight preserves ratio | `PeerHealthTracker`; C1/S5 gates; TOML `majority_k` |
| Equivocation | **Mitigated** — quorum log rejects conflicting `(epoch, reporter, subject)` | Local log only; not multi-org BFT | `health_quorum_log.rs` |
| Anonymous presentation | **Partial** — no RelayId in proof blob | Issuer learns id at issue; local nullifier only | `anonymous_reputation.md` |
| Cross-node nullifier | **Partial** — file export/merge | No wire gossip consensus; eclipse of merge path | `NullifierRegistry::merge_from_file` |
| Issuer correlation / blinded nullifier link | **Partial [O] QUANTIFIED** — wave C4 lab | Residual 1.0 at issue; blinded path still links via nullifier log; **interactive ZK External / not done** | `sim/data/ac_nullifier_unlinkability.json`; `ac_nullifier_unlinkability.py` |
| Nullifier merge eclipse / delayed merge | **Partial [O] QUANTIFIED** — partition + delay + suppress scenarios | Double-accept until merge; exposure ≈ delay/window; suppress export ⇒ residual 1.0 | C4 artifact; Rust `partition_allows_double_accept_until_merge` |
| Multi-org BFT reputation | **External** | Not in scope — C1/S5 sim does **not** close this | `RESEARCH_AGENDA.md` §1 |

**Eclipse / majority_k guidance for operators:**

- Production defaults are **stacked**: `majority_k = 4`, `min_orgs = 2`, `eclipse_detect = true`. **`majority_k = 1` is lab-only**.
- Set peer `org_id` (or `jurisdiction`) so `min_orgs` bites; unlabeled peers fail-open as distinct `rid:…` keys.
- Eclipse-detect quarantines high-gap medians vs local/honest baseline; it does **not** invent honest signal under `f=1`.
- Do not treat gossip median as ground truth without independent health checks.
- Treat C1/S5 sim numbers as characterization only: raising `K` blocks solo eclipse but not colluding median majorities inside a `K`-set; multi-org BFT remains **External**.
- Anonymous credentials: treat issuer as trusted at issue time; use epoch rotation + nullifier merge only with authenticated operator channels.
- Nullifier sync: authenticate `export_to_file` / `merge_from_file` channels; minimize merge delay; do not treat file merge as consensus. See C4 residual scores in `sim/data/ac_nullifier_unlinkability.json`.

---

## 11. Sphinx crypto properties (non-proof)

### Theory

Traffic analysis (GPA / adaptive / exit) is orthogonal to **packet crypto**: fixed size, MAC-before-peel, replay, peel order, tagging. In-repo KATs + Python bit-oracle catch implementation regressions. ProVerif L1–L3 prove **symbolic** secrecy / integrity / replay under idealized Dolev–Yao — not a computational reduction to ML-KEM-768/X25519, not EasyCrypt, and not anonymity. SoftHSM is custody ceremony (software token), not Sphinx math.

| Property | Mitigation status | Residual | Evidence |
|----------|-------------------|----------|----------|
| Fixed packet size | **Mitigated** — wire size **8512** (`SPHINX_PACKET_LEN`) | Doc historically said 8504; do not reintroduce that figure | `vectors.rs` `constant_size_*`; [`AEGIS_phase2_implementation_notes.md`](../AEGIS_phase2_implementation_notes.md) |
| MAC before peel | **Mitigated** | Timing branch after verify (low) | Phase 2 gate; CT review; `dudect` smokes |
| Replay cache | **Mitigated** | O(capacity) CPU under flood | `replay.rs` |
| Hop peel ordering / next-hop ids | **Partial [T]** — 2/3/max-hop KATs + all-length property | Per-hop DH blinding documented as best-effort in `kem.rs` | `vectors.rs` `hop_peel_ordering_*`, `peel_order_property_all_path_lengths` |
| Wrong-hop / later-secret / skip-hop peel | **Partial [T]** — integrity fail | Not a formal unlinkability proof | `wrong_hop_secret_rejected_*`, `later_hop_secret_cannot_peel_*`, `skip_hop_secret_rejected` |
| Seeded relay-key structural KAT | **Partial [T]** — size + peel-order stability | Encapsulation RNG still live (`OsRng`); no official cross-impl vector | `seeded_relay_keys_build_size_and_peel_kat` |
| Alpha/gamma/beta tagging bit-flips | **Mitigated [T]** — hop-0 integrity fail | Delta not under gamma (by design) | `tamper_alpha_or_gamma_rejected`, `tagging_bit_flip_map_beta_rejects`, `delta_bit_flip_does_not_fail_hop0_mac` |
| Python bit-oracle (build/peel/MAC/replay) | **Partial [T] (S1)** — secrets+headers oracle; KEM Rust-only | No hybrid encap in Python; not a proof | `sim/aegis_sim/sphinx_oracle.py`, `test_sphinx_oracle.py`, `python_oracle_shared_primitive_kats` |
| ProVerif symbolic L1–L3 (S3) | **Partial [T]** — L1 secrecy, L2 integrity, L3 replay **proved** this PC (idealized model) | ≠ computational ML-KEM proof; ≠ EasyCrypt; no anonymity lemmas | `tools/proverif/`; [`sphinx_symbolic_model.md`](sphinx_symbolic_model.md); `PC_VERIFY_RESEARCH_WAVE.md` § S3 |
| Max-path forward count | **Partial [T]** | Terminal hop still Forward to exit id | `vectors.rs` `max_hops_forward_count_is_layers_minus_one` |
| LibFuzzer `fuzz_sphinx_process` | **Partial [T]** — harness + short/overnight evidence pack | Crash/panic search only; not a proof | `sim/sphinx_fuzz_evidence.txt`; `fuzz/README.md`; `scripts/seed_sphinx_fuzz_corpus.py` |
| Formal computational verification | **Open [O] External** | Mechanized EasyCrypt / reduction not in repo | `RESEARCH_AGENDA.md` §5 |

**Sphinx summary:** Phase-2 KATs + Python oracle + ProVerif L1–L3 (symbolic) + fuzz evidence; **computational / EasyCrypt proof explicitly not claimed**. Wire size is **8512**.

---

## 12. Evidence index (latest artifacts at tip)

| Topic | Primary artifact(s) |
|-------|---------------------|
| Adaptive v4 saturation | `sim/data/adaptive_v4_saturation.analysis.json` |
| Adaptive baselines | `sim/data/adaptive_guard_exposure.analysis.json`, `adaptive_mitigation_*.json` |
| Combined Mode-1 ranking | `sim/data/combined_active_intersection.analysis.json` |
| Exit ∩ / volume | `sim/data/exit_tier_intersection.analysis.json` |
| Exit defenses / presence_pad | `sim/data/exit_tier_defense.analysis.json` |
| Fused adaptive∩Mode-1 | `sim/data/fused_adversary.analysis.json`, `fused_defense.analysis.json` |
| Gossip eclipse + stacked defense | `sim/data/gossip_eclipse.analysis.json`, `gossip_eclipse_defense.analysis.json`, `gossip_eclipse_offline.json` |
| Joint guard × gossip (B3) | `sim/data/joint_guard_gossip.analysis.json` |
| Cover GPA / multi-hop / defense | `sim/data/cover_burst_gpa_characterization.json`, `cover_multihop_characterization.json`, `cover_multihop_defense.analysis.json` |
| Metrics scrape | `sim/data/metrics_sidechannel_characterization.json`, `metrics_scrape_defense.analysis.json` |
| Faction / jurisdiction skew | `sim/data/faction_sybil_skew.json` |
| AC nullifier unlinkability | `sim/data/ac_nullifier_unlinkability.json` |
| SoftHSM ceremony | `sim/softhsm_ceremony_regress.txt`, `sim/softhsm_init_evidence.txt` |
| Sphinx fuzz | `sim/sphinx_fuzz_evidence.txt` |
| Loopback traces | `sim/data/real_*_trace*.analysis.json` |

Theory + science status narrative: [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md).

---

## 13. Regenerate evidence

```bash
# Sim §13 / defense artifacts
cd sim && PYTHONPATH=. python scripts/generate_research_artifacts.py
cd sim && PYTHONPATH=. python scripts/run_cover_burst_gpa_characterization.py
cd sim && PYTHONPATH=. python scripts/run_cover_multihop_characterization.py
cd sim && PYTHONPATH=. python scripts/run_cover_multihop_defense.py
cd sim && PYTHONPATH=. python scripts/run_exit_tier_defense.py
cd sim && PYTHONPATH=. python scripts/run_adaptive_v4_saturation.py
cd sim && PYTHONPATH=. python scripts/run_gossip_eclipse_defense.py
cd sim && PYTHONPATH=. python scripts/run_fused_defense.py
cd sim && PYTHONPATH=. python scripts/run_joint_guard_gossip.py
cd sim && PYTHONPATH=. python scripts/run_metrics_sidechannel_characterization.py
cd sim && PYTHONPATH=. python scripts/run_c2_shapeability_pipeline.py --synthetic-stress
cd sim && PYTHONPATH=. python -m aegis_sim.ac_nullifier_unlinkability
cd sim && PYTHONPATH=. pytest -q tests/test_hardening.py tests/test_cover_burst_gpa.py \
  tests/test_cover_multihop.py tests/test_exit_tier_defense.py tests/test_cover_multihop_defense.py \
  tests/test_metrics_sidechannel.py tests/test_c2_shapeability_pipeline.py \
  tests/test_ac_nullifier_unlinkability.py tests/test_gossip_eclipse_defense.py \
  tests/test_fused_defense.py tests/test_joint_guard_gossip.py

# Sphinx property gates + S1 oracle
cargo test -p aegis-crypto --test vectors
cargo test -p aegis-crypto python_oracle_shared_primitive_kats
cd sim && PYTHONPATH=. pytest -q tests/test_sphinx_oracle.py

# ProVerif L1–L3 (WSL / Linux)
tools/proverif/run_proverif.sh
# Windows host → WSL:
#   powershell -File tools/proverif/run_proverif.ps1

# SoftHSM ceremony regress (software token; optional)
#   powershell -File scripts/softhsm_wsl.ps1 -Action regress -Evidence

# Overnight fuzz (WSL): see crates/aegis-crypto/fuzz/README.md
#   SPHINX_FUZZ_MODE=short bash scripts/run_sphinx_fuzz_evidence.sh

# Ingress KEM commitment (Partial)
cargo test -p aegis-relay require_ingress_kem_commitment

# Malicious trace (ignored integration)
cargo test -p aegis-node --test trace_capture -- --ignored
```

---

## 14. Honest limits (this tip)

| Claim | Status |
|-------|--------|
| Attack playbook closes §13 | **False** — maps status + residuals |
| All attacks mitigated | **False** — see §4, §9, adaptive §3, exit §7 |
| Gossip eclipse solved | **False** — **[O] QUANTIFIED Partial** (stacked product); multi-org BFT still External |
| Cover onions = info-theoretic | **False** — peel-to-sink / matched discard are Partial opt-ins |
| Sphinx formally verified (computational) | **False** — KATs + oracle + ProVerif symbolic L1–L3 only |
| SoftHSM = hardware custody | **False** — software token succeeded; vendor HSM External |
| Operational WAN C2 closed | **False** — loopback / synthetic only |

**Upgrade / productize trackers:** [`RESEARCH_UPGRADE_PLAN.md`](RESEARCH_UPGRADE_PLAN.md) · [`PRODUCTIZE_DEFENSES_WAVE.md`](PRODUCTIZE_DEFENSES_WAVE.md) · [`PRODUCTIZE_LEFTOVERS_WAVE.md`](PRODUCTIZE_LEFTOVERS_WAVE.md) · theory status [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md).
