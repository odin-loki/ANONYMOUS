# Cross-relay health gossip (`PeerHealthAdvert`)

**Status:** Partial (2026-07-17)  
**Scope:** Signed, neighbor-only failure-rate gossip over hop links. **Not** BFT consensus.

## Goal

Relays share local peer-health observations so pruning / ledger updates can incorporate
second-hand signals from admitted neighbors, without a global reputation consensus.

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
5. Applied into `PeerHealthTracker` at **half weight** (`GOSSIP_WEIGHT = 1/2`).

There is **no** multi-reporter quorum, no conflict resolution beyond local EWMA/anomaly
drain, and no guarantee of global agreement.

## Node TOML

```toml
[health_gossip]
enabled = true
signing_seed = "<64 hex chars of Ed25519 seed>"
# or: signing_key_file = "gossip.seed"
interval_secs = 60

[[peers]]
id = "..."
addr = "..."
link_key = "..."
gossip_verifying_key = "<64 hex chars of peer Ed25519 VK>"
```

When enabled with a signing seed, `aegis-node` periodically snapshots local health windows
(with enough samples) and sends a signed advert about each subject to every peer-table
neighbor via the link-bridge gossip channel.

## Code map

| Piece | Location |
|-------|----------|
| Advert encode/sign/verify | `crates/aegis-relay/src/health_gossip.rs` |
| Inbound accept + outbound dispatcher | `crates/aegis-relay/src/net.rs` |
| Local merge / snapshot | `crates/aegis-relay/src/peer_health.rs` |
| Config + emit loop | `crates/aegis-node/src/{config,main}.rs` |

## Residual

- No global consensus / BFT.
- Malicious admitted neighbors can still bias local views (half-weight dampens, does not eliminate).
- Unidentified ingress (shared ingress key) cannot source gossip.
- Clock skew / replay of fresh-enough adverts is accepted within the age window.
