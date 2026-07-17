# Cross-relay health gossip (`PeerHealthAdvert`)

**Status:** Partial (2026-07-17)  
**Scope:** Signed, neighbor-only failure-rate gossip over hop links with
**BFT-lite quorum append log** + **lightweight majority / median merge**.
**Not** multi-org BFT consensus.

## Goal

Relays share local peer-health observations so pruning / ledger updates can incorporate
second-hand signals from admitted neighbors, without a global reputation consensus.
A single malicious neighbor must not unilaterally demote a subject: receivers wait for
`K` distinct authority reporters and apply the **median** failure rate.

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
   for the same `(epoch, subject)`, the **median** failure rate is applied at **half
   weight** (`GOSSIP_WEIGHT = 1/2`).
6. Set `majority_k = 1` to restore legacy immediate merge (lab / single-neighbor).

This is **not** Byzantine agreement across organizations: colluding `K` admitted
neighbors can still bias the median; there is no cross-relay global quorum or
multi-org BFT.

## Node TOML

```toml
[health_gossip]
enabled = true
signing_seed = "<64 hex chars of Ed25519 seed>"
# or: signing_key_file = "gossip.seed"
interval_secs = 60
majority_k = 2   # distinct authority reporters before median merge (default 2)
quorum_log_path = "data/health_quorum.log"   # optional; omit for in-memory only

[[peers]]
id = "..."
addr = "..."
link_key = "..."
gossip_verifying_key = "<64 hex chars of peer Ed25519 VK>"
```

When enabled with a signing seed, `aegis-node` periodically snapshots local health windows
(with enough samples) and sends a signed advert about each subject to every peer-table
neighbor via the link-bridge gossip channel. Inbound accept uses
`accept_advert_quorum` → `HealthQuorumLog` when gossip is enabled.

## Code map

| Piece | Location |
|-------|----------|
| Advert encode/sign/verify | `crates/aegis-relay/src/health_gossip.rs` |
| BFT-lite quorum append log | `crates/aegis-relay/src/health_quorum_log.rs` |
| Majority buffer + median merge | `PeerHealthTracker::apply_gossip_outcomes` in `peer_health.rs` |
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

Append-only; replay on startup rebuilds pending quorum state.

## Residual

- **External:** multi-org BFT reputation consensus — not in scope for this gossip path.
- `K` colluding admitted neighbors can still shift the median within one org.
- Unidentified ingress (shared ingress key) cannot source gossip.
- Clock skew / replay of fresh-enough adverts is accepted within the age window.
