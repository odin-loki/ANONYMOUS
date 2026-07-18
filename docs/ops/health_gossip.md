# Cross-relay health gossip (`PeerHealthAdvert`)

**Status:** Partial (2026-07-18) — **stacked** eclipse defense productized  
**Scope:** Signed, neighbor-only failure-rate gossip over hop links with
**BFT-lite quorum append log** + **stacked** merge (`raised_k` + `min_orgs` +
eclipse-detect quarantine). **Not** multi-org BFT consensus.

## Goal

Relays share local peer-health observations so pruning / ledger updates can incorporate
second-hand signals from admitted neighbors, without a global reputation consensus.
A single malicious neighbor must not unilaterally demote a subject: receivers wait for
`K` distinct authority reporters **and** `min_orgs` diversity keys, apply the **median**
failure rate at half weight, and optionally **quarantine** medians that look eclipsed
vs local/honest baseline.

## Wire format

Link-control cell command `0x07` (`Command::PeerHealthAdvert`). These cells are handled
on the link bridge and **never** enter Sphinx reassembly.

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | `Command::PeerHealthAdvert` (`0x07`) |
| 1 | 32 | `reporter` RelayId |
| 33 | 32 | `subject` RelayId |
| 65 | 8 | `successes` (u64 LE) |
| 73 | 8 | `failures` (u64 LE) |
| 81 | 8 | `timestamp_secs` (u64 LE Unix) |
| 89 | 64 | Ed25519 signature |
| 153…511 | — | zero padding |

Signed body (canonical): `reporter || subject || successes || failures || timestamp_secs`.

## Trust rules (minimal)

1. Authenticated hop peer must equal `reporter` (PSK / link identity).
2. `reporter` must be in the local peer table (admitted neighbor only).
3. Signature verifies under that peer’s configured `gossip_verifying_key`.
4. Timestamp within ~1 hour (allow 2 minutes future skew).
5. **BFT-lite quorum log:** verified adverts append to an in-tree log scoped by gossip
   **epoch** (`timestamp_secs / interval_secs`). Conflicting payloads for the same
   `(epoch, reporter, subject)` are rejected (**equivocation**). When `majority_k`
   distinct **authority** reporters (peers with `gossip_verifying_key`) have appended
   for the same `(epoch, subject)` **and** `min_orgs` distinct diversity keys are
   present, the **median** failure rate is applied at **half weight**
   (`GOSSIP_WEIGHT = 1/2`) unless eclipse-detect quarantines it.
6. Set `majority_k = 1` and `min_orgs = 1` with `eclipse_detect = false` to restore
   legacy immediate merge (lab / single-neighbor).

This is **not** Byzantine agreement across organizations: colluding `K` admitted
neighbors that also meet `min_orgs` (multi-org collusion) can still bias the median;
there is no cross-relay global quorum or multi-org BFT. Full eclipse (`f=1`) still
saturates — quarantine discards bad merges but cannot invent honest signal.

## Stacked merge policy (sim S5 → product)

| Knob | Default | Role |
|------|---------|------|
| `majority_k` | **4** | Raised K (sim `raised_k` / `CI_DEFENSE_K`) |
| `min_orgs` | **2** | Distinct `org_id` (else `jurisdiction`) labels in the quorum |
| `eclipse_detect` | **true** | Quarantine when median ≥ baseline + `eclipse_median_gap` |
| `eclipse_median_gap` | 0.45 | Sim `ECLIPSE_MEDIAN_GAP` |
| `eclipse_local_min_samples` | 8 | Prefer local subject fail-rate as baseline when enough samples |
| `eclipse_honest_baseline` | 0.10 | Fallback baseline (sim `HONEST_FAIL_RATE`) |

Diversity key resolution: `org:{org_id}` → else `jur:{jurisdiction}` → else
`rid:{reporter_hex}` (unlabeled peers count as distinct — **availability fail-open**;
set `org_id` / `jurisdiction` on peers for the diversity gate to bite against same-org
collusion).

## Node TOML

```toml
[health_gossip]
enabled = true
signing_seed = "<64 hex chars of Ed25519 seed>"
# or: signing_key_file = "gossip.seed"
interval_secs = 60
majority_k = 4          # stacked default (was 2)
min_orgs = 2            # require cross-org/jurisdiction quorum
eclipse_detect = true   # quarantine high-gap medians
# eclipse_median_gap = 0.45
# eclipse_local_min_samples = 8
# eclipse_honest_baseline = 0.10
quorum_log_path = "data/health_quorum.log"   # optional; omit for in-memory only

[[peers]]
id = "..."
addr = "..."
link_key = "..."
gossip_verifying_key = "<64 hex chars of peer Ed25519 VK>"
org_id = "acme"           # preferred diversity label
jurisdiction = "US"       # used if org_id omitted
```

When enabled with a signing seed, `aegis-node` periodically snapshots local health windows
(with enough samples) and sends a signed advert about each subject to every peer-table
neighbor via the link-bridge gossip channel. Inbound accept uses
`accept_advert_quorum` → `HealthQuorumLog` when gossip is enabled; merge policy comes
from `HealthGossipConfig::merge_policy()` → `PeerHealthTracker::with_policy`.

## Code map

| Piece | Location |
|-------|----------|
| Advert encode/sign/verify | `crates/aegis-relay/src/health_gossip.rs` |
| BFT-lite quorum append log | `crates/aegis-relay/src/health_quorum_log.rs` |
| Stacked buffer + median + quarantine | `PeerHealthTracker` / `GossipMergePolicy` in `peer_health.rs` |
| Inbound accept + outbound dispatcher | `crates/aegis-relay/src/net.rs` |
| Config + emit loop | `crates/aegis-node/src/{config,main}.rs` |

## Quorum log on-disk record (152 bytes)

| Field | Size |
|-------|------|
| `epoch` (u64 LE) | 8 |
| `reporter` | 32 |
| `subject` | 32 |
| `successes` (u64 LE) | 8 |
| `failures` (u64 LE) | 8 |
| Ed25519 signature | 64 |

Append-only; replay on startup rebuilds pending quorum state. Org labels are **not**
persisted in the log record — replay uses per-reporter diversity keys.

### Optional epoch checkpoint

After quorum merges for a gossip epoch, operators may call
`HealthQuorumLog::sign_epoch_checkpoint(epoch, signing_key)` to produce a signed
[`HealthEpochCheckpoint`] summarizing all accepted median `(successes, failures)` pairs
for that epoch. Verification uses Ed25519 over a canonical domain-separated blob.
This is a **local audit artifact**, not multi-org BFT agreement.

## Residual

- **External:** multi-org BFT reputation consensus — not in scope for this gossip path.
- Colluding multi-org adversaries that meet `min_orgs` can still shift the median.
- Full eclipse (`f=1`): no honest reporters → FP still saturates; quarantine helps only
  when a local/honest baseline exists to compare against.
- Eclipse heuristic false-positives possible under genuine correlated outages.
- Unidentified ingress (shared ingress key) cannot source gossip.
- Clock skew / replay of fresh-enough adverts is accepted within the age window.

## Sim profiling (wave C1 / S5) — [O] QUANTIFIED Partial

Pure-Python twin of the merge math (not a close claim):

| Piece | Location |
|-------|----------|
| Baseline model | `sim/aegis_sim/gossip_eclipse.py` |
| Defenses (`stacked`) | `sim/aegis_sim/gossip_eclipse_defense.py` |
| CI artifacts | `sim/data/gossip_eclipse*.json`, `gossip_eclipse_defense.analysis.json` |
| Gates | `sim/tests/test_gossip_eclipse.py` (+ defense tests) |

**What it measures** (victim with `N` neighbors, adversarial fraction `f`, `majority_k=K`):

- **Median health bias** — window fail-rate − true honest fail-rate after half-weight merges
- **False probation** — P(window fail-rate ≥ 0.40) for an honest subject
- **Eclipse** — fraction of epochs where adversaries form a pure-adv `K`-quorum (coordinated report-first)

Raising `K` above `adv_count` blocks *solo* eclipse; `min_orgs` + eclipse-detect cut
FP under partial `f`. Neither makes the path BFT — multi-org BFT remains **External**.
`f=1` still saturates.
