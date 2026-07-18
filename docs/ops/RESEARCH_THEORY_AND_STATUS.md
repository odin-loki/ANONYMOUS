# AEGIS research: theory & status hub

**Date:** 2026-07-18  
**Tip:** `c7c2f0d` — *Land leftovers B1-B3: peelable cover onions, jurisdiction paths, joint sim.*  
**Audience:** operators, researchers, and agents who need one place for *why* the defenses exist and *what is honestly done*.

> **Research is not closed.** Spec §13 science items are quantified or partially mitigated; platform rows remain External where hardware/multi-org work is required. This hub does **not** claim Docker runs, WAN C2 validation, EasyCrypt proofs, or info-theoretic anonymity.

**Sibling indexes:** [`ATTACK_PLAYBOOK.md`](ATTACK_PLAYBOOK.md) · [`RESEARCH_AGENDA.md`](RESEARCH_AGENDA.md) · [`RESEARCH_OPS_STATUS.md`](RESEARCH_OPS_STATUS.md) · [`research_open_items.md`](research_open_items.md)

---

## 1. How to use this document

| Need | Go to |
|------|--------|
| Intuition for an attack / defense | §2 Theory |
| What waves landed (C/S/A/B) | §3 Status matrix |
| Knobs to set today | §4 Operator defaults |
| What is still open / External | §5 Remaining backlog |
| Deep dive / evidence | §6 Document & artifact index |

**Legend:** **[T]** tested in-repo · **[O] QUANTIFIED** simulated limits documented · **Partial** useful mitigation with honest leftover · **External** platform/operator integration (not unfinished wiring).

---

## 2. Theory (accessible, precise)

### 2.1 Mixnet / Sphinx hop peel + hybrid PQ (8512 B)

A **mixnet** hides who talks to whom by routing fixed-size packets through several relays. Each relay learns only *its* layer: previous hop → next hop. That property comes from **Sphinx-style onion encryption**.

**Peel order (product):** at every hop,

1. **Decap** the hybrid KEM header (`alpha`) → per-hop shared secret  
2. **Verify** the MAC (`gamma`) over the routing onion (`beta`)  
3. **Replay-tag** check (reject duplicates)  
4. **Peel:** reveal `next_hop`, shift `beta`, refresh `alpha`/`gamma`, XOR one layer of payload (`delta`)

Wrong-hop secrets, skipped hops, and tagging bit-flips fail integrity — see KATs in `crates/aegis-crypto/tests/vectors.rs`.

**Why hybrid PQ Sphinx is 8512 bytes:** classical Sphinx used a compact DH header. AEGIS needs **post-quantum confidentiality** on the hop key exchange, so `alpha` carries **X25519 (32 B) + ML-KEM-768 ciphertext (1088 B)** = 1120 B hybrid header, plus a fixed six-slot routing onion (`beta`), 32 B MAC, and 256 B payload onion:

```text
alpha 1120 │ beta 7104 │ gamma 32 │ delta 256  →  SPHINX_PACKET_LEN = 8512
```

Every path length ≤ `MAX_HOPS=6` pads to the **same** wire size so GPA cannot fingerprint path length from packet length. (Stale docs saying 8504 are wrong; ledger/tests assert 8512.)

**What Sphinx does *not* buy you alone:** timing/volume correlation, adaptive guard compromise, exit clearnet observation, or gossip eclipse. Those need cover pacing, padding policy, guard rotation, and gossip merge rules — below.

---

### 2.2 GPA timing / cover / τ pacing

A **global passive adversary (GPA)** sees every link. Even with perfect onion crypto, *when* and *how many* cells move can link sender and receiver.

AEGIS’s primary shaping lever is a discrete slot length **τ**:

- Clients use a **paced session** that emits real or dummy cells on τ boundaries.  
- Relays emit **cover** cells that are AEAD-sealed and width-matched, scheduled by a τ dispatcher.  
- Characterization uses gap **CV**, two-sample **KS**, and τ-multiple histograms (`cover_burst_gpa_characterization.json`). Cover lowers gap CV vs bulk-only in the lab model; it is **not** info-theoretic indistinguishability.

**Semantic gap (multi-hop):** local-discard cover (`COVER_FRAGMENT_RESERVED`) never peels/forwards. A GPA with ≥2 hop vantage sees wire ≠ forward yield even when single-hop gaps look τ-like. Opt-in **`cover_onions`** emit valid Sphinx that peel to a sink hop so continuity ≈ Sphinx-only in sim — still not client exit traffic, still not a proof.

---

### 2.3 Adaptive guard compromise (stickiness → exposure→1; v1–v4)

Clients pin a small **guard set** (`g=3`) for entry stability. Against a *static* compromised fraction `c`, exposure plateaus at `1-(1-c)^g`. Against an **adaptive** adversary that redraws which relays are compromised each epoch, stickiness is deadly: over enough epochs the chance that *some* dirty epoch hit your guards grows toward **1.0**.

Intuition: sticky guards turn “small per-epoch risk” into “almost-sure long-horizon hit.”

| Tier | Idea | Sim E=200 (`c=0.015`, `g=3`) | E=2000 |
|------|------|------------------------------|--------|
| Unmitigated | sticky forever | ~1.0 | ~1.0 |
| **v1** | soft demotion + sticky cap ~10 | ~0.90 | →1 |
| **v2** | tighter cap + linger | ~0.77 | →1 |
| **v3** | hard age 4 + decaying stickiness + rep soft-rotate | ~0.45 | ~0.99 |
| **v4** | hard age 2 + stronger demotion (best long-E) | ~0.24 | ~0.85 |

Product preset: `GuardMitigationPolicy::adaptive_v4()` / TOML `preset = "adaptive_v4"`. **§13 remains [O]** — curves still saturate; field recompromise rate is unmeasured.

---

### 2.4 Combined active(n−1) + intersection + hard_cap

**Mode-1** receivers try to look constant-rate. An adversary can (a) **actively suppress** a fraction of senders and (b) **intersect** who was active across epochs. Without a true hard observable cap, confirm probability climbs toward 1 over long horizons.

Ranking in sim (`combined_active_intersection.analysis.json`):

| Observable | Long-horizon behavior |
|------------|------------------------|
| `constant_only` / truncate / noisy | Saturates toward deanonymize |
| `pad_up` | Helps but stays above baseline; high Q only *approaches* hard-cap |
| **`hard_cap` / `deferred_hard_cap`** | Holds near random baseline **1/M** |

**Operator rule:** internal-tier Mode-1 peers must keep **`HardCapPadder`** with `Q ≥ ~1.2×` sustained mean. Pad-up for “efficiency” reopens the attack. **Exit / clearnet receivers are excluded** from this claim (weaker tier).

---

### 2.5 Exit-tier clearnet residual + presence_pad

At the exit hop, payload leaves the mix toward ordinary clearnet. Mode-1 hard-cap does **not** transfer: the exit↔server link is an unshaped (or only sender-shaped) residual. GPA can:

- form co-active **windows** and run tip-sparse intersection toward a singleton, and/or  
- **rank volumes** so the true client beats `1/N` quickly.

**`presence_pad`** (sim-recommended at E=100; product opt-in): when idle, sometimes emit matched-Q decoys so presence frequency is less distinctive; when active, pad up toward Q. Strongest sim scheme is always-on `pool_hard_cap` (costly; sim-only). Clearnet still cannot hard-cap safely — residual remains.

---

### 2.6 Gossip eclipse / majority_k / stacked

Relays exchange signed **peer-health** adverts. Merge uses the **median** failure rate once enough reporters agree. Risks:

- **Eclipse:** victim’s peer table is flooded with adversary neighbors → adversarial medians.  
- **`majority_k`:** need `K` distinct authority reporters before merge; solo eclipse needs `adv ≥ K`, but a colluding median majority *inside* a K-set still biases.  
- **`f=1`:** saturates regardless of quarantine — you cannot invent honest signal.

**Stacked** (sim S5 → product A1): raise `K`, require **`min_orgs`** diversity labels, and **eclipse-detect** quarantine of high-gap medians. Cuts FP at partial `f`; multi-org BFT remains External.

---

### 2.7 Faction / Sybil M-of-N + jurisdiction diversity

Roster admission requires **≥M distinct consortium signatures**. If a faction holds `< M` keys, Sybil admit ≈ 0; if `≥ M`, admit ≈ 1. Jurisdiction *skew* then concentrates guards/exits even when crypto admission “works.”

Code enforces M-of-N + rate limits + reputation; **legal vetting, sanctions, and binding diversity quotas are External**. Soft client path filter: `[path] require_diverse_jurisdictions` (opt-in).

---

### 2.8 AC / nullifier unlinkability residuals

Anonymous reputation proves `score ≥ threshold` without putting `RelayId` in the proof blob. Honest residuals (C4):

- Issuer still learns identity **at issue** (software binding, not full AC).  
- Blinded request path still links via the **nullifier log**.  
- File merge of nullifiers: partition/delay/suppress → double-accept until merge; suppress export ⇒ residual 1.0.  
- Interactive ZK show / consensus nullifier ledger: **External**.

---

### 2.9 Metrics scrape side-channel

Coarse ops counters (`processed_ok/fail`, `cover_emitted`, queue drops) are necessary — and leaky under flood. Lab model (C5): 1s scrapes of drop/load deltas recover attack volume and show Pearson≈0.97 vs attack windows.

**Stacked export gate (A4):** min scrape interval 30s + quantize bucket 16 + suppress ingress drop detail. Raw `coarse_stats` / `debug_stats` / high-res opt-in bypass the gate (privileged residual). Fail/queue buckets can still correlate after drop suppression.

---

### 2.10 ProVerif idealized vs EasyCrypt / formal

| Layer | What it is | Status |
|-------|------------|--------|
| **KATs / property tests / Python oracle / fuzz** | Concrete bit-level gates | **[T] Partial** — crash/panic + peel/MAC/replay; not a proof |
| **ProVerif (S3)** | Dolev–Yao symbolic model: secrecy, integrity correspondence, injective replay | **Lemmas proved** under *ideal* MAC/enc |
| **EasyCrypt / computational** | Reduction to ML-KEM-768 / X25519 IND-CCA, machine-checked | **Not in repo — External / open** |

Cite ProVerif as “idealized hop properties hold symbolically,” **not** as “Sphinx is formally verified in the computational model,” and never as an anonymity proof.

---

## 3. Status matrix (waves → product → evidence)

### 3.1 Coverage wave C (quantify Partial / [O] surfaces)

| ID | Track | Status | Evidence under `sim/data/` |
|----|-------|--------|----------------------------|
| **C1** | Gossip eclipse / `majority_k` | **[O] QUANTIFIED Partial** | `gossip_eclipse.analysis.json`, `gossip_eclipse_offline.json` |
| **C2** | Exit-tier ∩ + fused adaptive∩Mode-1 | **[O] QUANTIFIED** | `exit_tier_intersection.analysis.json`, `fused_adversary.analysis.json` |
| **C3** | Faction / Sybil jurisdiction skew | **[O] QUANTIFIED** | `faction_sybil_skew.json` |
| **C4** | AC / nullifier unlinkability | **[O] QUANTIFIED Partial** | `ac_nullifier_unlinkability.json` |
| **C5** | Cover multi-hop + metrics scrape | **[O] QUANTIFIED Partial** | `cover_multihop_characterization.json`, `metrics_sidechannel_characterization.json` |
| **C6** | dudect WSL deepen | **Partial** (not isolated bar) | `sim/dudect_lab_summary.txt` (lab; External ≥10⁵ isolated) |

Also foundational §13 sims: `adaptive_guard_exposure.analysis.json`, `combined_active_intersection.analysis.json`, `cover_burst_gpa_characterization.json`.

### 3.2 PC verify + research wave S (defenses + crypto evidence)

| ID | Track | Status | Key artifacts / pointers |
|----|-------|--------|--------------------------|
| **S1** | Sphinx oracle + fuzz deepen | **Done** as research pack | `sim/aegis_sim/sphinx_oracle.py`; `sim/sphinx_fuzz_evidence.txt` |
| **S2** | Crypto threat-model gaps | **Done** (tested / accepted) | [`CRYPTO_THREAT_GAP_LEDGER.md`](CRYPTO_THREAT_GAP_LEDGER.md) |
| **S3** | ProVerif symbolic Sphinx | **Done** (idealized) | [`sphinx_symbolic_model.md`](sphinx_symbolic_model.md); `tools/proverif/` |
| **S4** | Exit + cover multi-hop defenses | **[O] QUANTIFIED Partial** | `exit_tier_defense.analysis.json`, `cover_multihop_defense.analysis.json` |
| **S5** | `adaptive_v4` + stacked gossip + fused_v4 | **[O] QUANTIFIED Partial** | `adaptive_v4_saturation.analysis.json`, `gossip_eclipse_defense.analysis.json`, `fused_defense.analysis.json` |
| **S6** | CT / SoftHSM / Noise note | **Partial** + External dudect | [`constant_time_ci.md`](constant_time_ci.md), [`noise_link_auth.md`](noise_link_auth.md) |

### 3.3 Productize wave A (sim → knobs)

| ID | Product landing | Default today | Honest leftover |
|----|-----------------|---------------|-----------------|
| **A1** | Stacked gossip merge | **On** (`K=4`, `min_orgs=2`, `eclipse_detect=true`) | `f=1` saturate; multi-org BFT External |
| **A2** | `[exit].presence_pad` | **Off** (opt-in, exit hops only) | Clearnet GPA |
| **A3** | Cover multihop defense | Scaffold / local discard; opt-in match / onions | Full forwardable cover; info-theoretic |
| **A4** | `MetricsExportGate` | **Production stacked** (30s / q16 / suppress drops) | Privileged raw / high-res |
| **A5** | Metrics scrape defense sim | Characterization | Not closed |
| **A6** | Sphinx fuzz evidence pack | Evidence file in `sim/` | Mechanized proof |

### 3.4 Leftovers wave B (tip `c7c2f0d`)

| ID | Landing | Status | Evidence |
|----|---------|--------|----------|
| **B1** | Peelable `cover_onions` → sink | **Shipped opt-in** | [`cover_multihop_defense.md`](cover_multihop_defense.md) |
| **B2** | Jurisdiction-diverse path select | **Shipped opt-in** | `[path] require_diverse_jurisdictions`; [`faction_sybil_skew.md`](faction_sybil_skew.md) |
| **B3** | Joint adaptive-guard × gossip-eclipse | **[O] QUANTIFIED** | `joint_guard_gossip.analysis.json` |

### 3.5 Product knobs (quick map)

| Surface | TOML / API | Research-backed setting |
|---------|------------|-------------------------|
| Guard mitigation | `[guard_mitigation] preset` | `"adaptive_v4"` (client-enforced) |
| Path age / signals | `[path] epoch_age`, anomaly flags | Pilot: low `epoch_age` with v4 hard cap 2 |
| Jurisdiction soft filter | `[path] require_diverse_jurisdictions` | Opt-in `true`; `max_per_jurisdiction = 1` |
| Health gossip | `[health_gossip]` + peer `org_id` | Stacked defaults; label peers |
| Cover base | `[cover] enabled/require` | On + fail-closed for pilot |
| Cover multihop | `[cover] multihop_defense` | Opt-in `cover_onions` or `matched_local_discard` |
| Exit pad | `[exit].presence_pad` | Opt-in on **exit hops only** |
| Mode-1 pad | receiver `HardCapPadder` | **Must stay on** internal tier |
| Metrics | `[metrics]` | Production gate; no `debug_stats` export |

---

## 4. Recommended operator defaults (today)

These are the **best research-aligned** settings as of tip `c7c2f0d`. Defaults in code may still be conservative (e.g. guard mitigation **disabled** until you set the preset) — enable explicitly for pilot/WAN soak.

### Prefer on / set explicitly

1. **`[guard_mitigation] preset = "adaptive_v4"`** on clients (nodes may mirror for symmetry; clients enforce).  
2. **Stacked gossip:** `majority_k = 4`, `min_orgs = 2`, `eclipse_detect = true`; set peer `org_id` / `jurisdiction`.  
3. **`[metrics]` production gate:** 30s min scrape, quantize 16, suppress ingress drop detail; `allow_high_resolution = false`.  
4. **Mode-1 hard-cap** on internal receivers (`Q ≥ ~1.2×` mean).  
5. Cover **enabled + require** on relays; paced clients (no `--raw` in ops).

### Opt-in (bandwidth / ops cost — enable when ready)

| Knob | When |
|------|------|
| `[cover] multihop_defense = "cover_onions"` | Terminal peer KEM available; want peel continuity |
| `multihop_defense = "matched_local_discard"` | Align cover volume without onion KEM |
| `[exit].presence_pad = true` | Designated exit hops only |
| `[path] require_diverse_jurisdictions = true` | Soft diversity; charter still External |

### Do not claim from defaults alone

- Research closed / §13 closed  
- Docker compose pilot “ran” without a local Docker engine check  
- Operational C2 / WAN GPA validated  
- Sphinx computationally verified  
- Multi-org BFT gossip or full AC unlinkability  

Loopback / offline compose lint is fine; see [`PILOT.md`](PILOT.md) for honest Docker rules.

---

## 5. Honest remaining External / open list

### 5.1 Spec §13 science — quantified, not closed

| Item | Honest status |
|------|---------------|
| Adaptive compromised-mix set | **[O] QUANTIFIED + Partial v1–v4**; long-E saturation |
| Combined active(n−1)+intersection | **[O] QUANTIFIED**; hard_cap recommended, not “solved forever” |
| Exit-tier + fused / joint adversaries | **[O] QUANTIFIED**; not WAN closed |
| Cover / GPA timing indistinguishability | **[O] QUANTIFIED Partial**; not info-theoretic |
| Gossip eclipse | **[O] QUANTIFIED Partial**; `f=1` saturates |
| Real operational C2 / telemetry shapeability | **[O]** — loopback **[T]** only |
| Sphinx formal (computational) proof | **[O] External** |
| Consortium governance / legal diversity | **[O]** charter draft + sim skew; binding policy External |

### 5.2 Platform External (scaffolding done)

| Area | Leftover |
|------|----------|
| TEE attestation | Intel DCAP / AMD SEV-SNP SDK + device |
| HSM / key ceremony | PKCS#11 vendor SDK + interactive MPC |
| Multi-org BFT reputation | Cross-operator consensus (beyond stacked median) |
| Interactive AC / real ZK show | Scale issuer + unlinkable multi-show |
| Isolated dudect ≥10⁵ / primitive | Lab-grade CT evidence (WSL deepen ≠ bar) |

One-page matrix: [`RESEARCH_OPS_STATUS.md`](RESEARCH_OPS_STATUS.md). Full backlog: [`RESEARCH_AGENDA.md`](RESEARCH_AGENDA.md).

---

## 6. Document & artifact index

### 6.1 Core ops / research docs

| Doc | Role |
|-----|------|
| [`ATTACK_PLAYBOOK.md`](ATTACK_PLAYBOOK.md) | Attack primitives → mitigation → residual → evidence |
| [`RESEARCH_AGENDA.md`](RESEARCH_AGENDA.md) | Honest open / External backlog |
| [`RESEARCH_OPS_STATUS.md`](RESEARCH_OPS_STATUS.md) | One-page residual status |
| [`research_open_items.md`](research_open_items.md) | §13 sim parameter tables + regen commands |
| [`adaptive_guard_mitigation.md`](adaptive_guard_mitigation.md) | v1–v4 theory → TOML / Rust presets |
| [`cover_multihop_defense.md`](cover_multihop_defense.md) | Cover semantic-gap defenses + `cover_onions` |
| [`exit_tier_defense.md`](exit_tier_defense.md) | Clearnet residual + `presence_pad` |
| [`combined_attack_mode1_hardcap.md`](combined_attack_mode1_hardcap.md) | Mode-1 scheme ranking → `HardCapPadder` |
| [`health_gossip.md`](health_gossip.md) | Stacked gossip knobs |
| [`metrics_scrape_defense.md`](metrics_scrape_defense.md) | Scrape side-channel + export gate |
| [`faction_sybil_skew.md`](faction_sybil_skew.md) | M-of-N × jurisdiction skew |
| [`anonymous_reputation.md`](anonymous_reputation.md) | AC / nullifier honesty bounds |
| [`sphinx_symbolic_model.md`](sphinx_symbolic_model.md) | ProVerif L1–L3 + limits |
| [`CRYPTO_THREAT_GAP_LEDGER.md`](CRYPTO_THREAT_GAP_LEDGER.md) | Phase-2 crypto gap dispositions |
| [`PILOT.md`](PILOT.md) | Loopback pilot + honest Docker rules |
| [`CONSORTIUM_CHARTER.md`](CONSORTIUM_CHARTER.md) | Governance draft (not closed) |

### 6.2 Wave plans

| Wave | Plan doc |
|------|----------|
| Coverage C1–C6 | [`RESEARCH_COVERAGE_WAVE.md`](RESEARCH_COVERAGE_WAVE.md) |
| PC verify S1–S6 | [`PC_VERIFY_RESEARCH_WAVE.md`](PC_VERIFY_RESEARCH_WAVE.md) |
| Productize A1–A6 | [`PRODUCTIZE_DEFENSES_WAVE.md`](PRODUCTIZE_DEFENSES_WAVE.md) |
| Leftovers B1–B3 | [`PRODUCTIZE_LEFTOVERS_WAVE.md`](PRODUCTIZE_LEFTOVERS_WAVE.md) |
| Earlier upgrade / ops hardening | [`RESEARCH_UPGRADE_PLAN.md`](RESEARCH_UPGRADE_PLAN.md) · [`../AEGIS_research_ops_hardening_plan.md`](../AEGIS_research_ops_hardening_plan.md) |

### 6.3 Evidence paths (`sim/data/` — primary)

```text
adaptive_guard_exposure.analysis.json
adaptive_v4_saturation.analysis.json
adaptive_mitigation_sweep.json / adaptive_mitigation_offline.json
combined_active_intersection.analysis.json
cover_burst_gpa_characterization.json
cover_multihop_characterization.json
cover_multihop_defense.analysis.json
exit_tier_intersection.analysis.json
exit_tier_defense.analysis.json
fused_adversary.analysis.json
fused_defense.analysis.json
gossip_eclipse.analysis.json / gossip_eclipse_offline.json
gossip_eclipse_defense.analysis.json
joint_guard_gossip.analysis.json
faction_sybil_skew.json
ac_nullifier_unlinkability.json
metrics_sidechannel_characterization.json
metrics_scrape_defense.analysis.json
real_*_trace.csv (+ .analysis.json)          # loopback [T], not operational C2
synthetic_c2_stress_shapeability.json        # NOT_OPERATIONAL_C2
```

Related non-`data/` pointers: `sim/sphinx_fuzz_evidence.txt`, `sim/dudect_lab_summary.txt`, `tools/proverif/`.

### 6.4 Regenerate (high level)

```bash
cd sim && PYTHONPATH=. python scripts/generate_research_artifacts.py
cd sim && PYTHONPATH=. pytest -q tests/test_hardening.py \
  tests/test_gossip_eclipse.py tests/test_gossip_eclipse_defense.py \
  tests/test_exit_tier_intersection.py tests/test_exit_tier_defense.py \
  tests/test_fused_adversary.py tests/test_fused_defense.py \
  tests/test_joint_guard_gossip.py tests/test_cover_burst_gpa.py \
  tests/test_cover_multihop.py tests/test_cover_multihop_defense.py \
  tests/test_metrics_sidechannel.py tests/test_metrics_scrape_defense.py \
  tests/test_faction_sybil_skew.py tests/test_ac_nullifier_unlinkability.py \
  tests/test_sphinx_oracle.py
cargo test -p aegis-crypto --test vectors
# ProVerif (WSL/Linux): tools/proverif/run_proverif.sh
```

---

## 7. One-paragraph verdict

As of **`c7c2f0d` (2026-07-18)**, AEGIS has a coherent research stack: hybrid PQ Sphinx (8512 B) with peel/MAC/replay gates and idealized ProVerif lemmas; τ-paced cover with quantified GPA/multi-hop residuals; adaptive_v4 + stacked gossip + Mode-1 hard_cap as the strongest in-tree anonymity knobs; opt-in presence_pad / cover_onions / jurisdiction diversity; and a full sim evidence tree under `sim/data/`. **None of that closes research.** Treat every Partial as “measured enough to operate carefully,” not “solved,” and keep External platform work off the critical-path claims.
