# AEGIS production deployment checklist

**Date:** 2026-07-18  
**Audience:** operators deploying `aegis-node` / `aegis-client` relays and clients.

This is a concise go-live gate. It does **not** replace threat-model review or consortium ceremony docs.

## Pre-flight

| Check | Production setting | Why |
|-------|-------------------|-----|
| Roster verify | Consortium keys configured; **`allow_unverified_roster = false`** | Unsigned roster load is lab-only ([`consortium_key_ceremony.md`](consortium_key_ceremony.md)) |
| Hop handshake | **`handshake = "auto"`** with **`noise_static_secret`** (+ peer **`noise_static_public`**) on every link | Auto selects Noise_IK when keys present ([`noise_link_auth.md`](noise_link_auth.md)) |
| Cover egress | Cover pacing **on** (default τ-paced emitter; do not disable for “performance”) | Sender-side unobservability depends on constant-rate cover |
| Ingress limits | Token bucket enabled; tune **`max_cells_per_sec`** / peer budgets for your τ | Prevents adversarial flood ([`RESEARCH_OPS_STATUS.md`](RESEARCH_OPS_STATUS.md) #8) |
| Health gossip | **`[health_gossip] enabled = true`**, **`signing_seed`** or **`signing_key_file`**, peer **`gossip_verifying_key`** set | Signed neighbor health with BFT-lite quorum ([`health_gossip.md`](health_gossip.md)) |
| Reputation | Issuer pubkey loaded; **`verify_and_spend`** / nullifier registry; presentations **signed** by issuer | Anonymous reputation path is Partial — do not skip verifier steps ([`anonymous_reputation.md`](anonymous_reputation.md)) |
| Lab flags off | **`allow_unverified_roster = false`**; no `load_from_file_unverified` in production wiring | Explicit unverified roster is test/lab only |
| Trace / debug | **`[trace].path` unset** on mix relays; exit sink only on designated exit hops | Relay forward trace is capture instrumentation, not production default ([`AEGIS_phase8_hardening_notes.md`](../AEGIS_phase8_hardening_notes.md) §5) |

## KEM / secrets (Unix)

- Prefer platform keychain when available; file fallback must be **`0600`** with no group/world read.
- On Unix, **`kem.seeds`** with group/world-readable mode is **refused at load** — fix permissions before restart.
- Windows CI does not exercise Unix mode checks; run kem-mode integration tests on Linux agents ([`constant_time_ci.md`](constant_time_ci.md) CI note).

## Constant-time evidence

- In-tree smokes: `cargo test -p aegis-crypto --test timing_smoke --test dudect_smoke`
- Release CT claims require External oreparaz/dudect on isolated CPU (≥10⁵ traces) — see [`constant_time_ci.md`](constant_time_ci.md).

## Smoke after deploy

1. Roster loads with signature verify (no “unverified roster” log lines).
2. Hop links complete handshake (Noise when keys configured).
3. Health gossip adverts verify from configured neighbor keys.
4. Ingress drop metrics stable under expected load; cover cells egress at τ.
5. No `[trace]` CSV growth on production mix nodes.

## Related ops docs

- [`noise_link_auth.md`](noise_link_auth.md) — handshake modes and static keys  
- [`health_gossip.md`](health_gossip.md) — gossip signing and quorum  
- [`anonymous_reputation.md`](anonymous_reputation.md) — issuer + nullifier checklist  
- [`consortium_key_ceremony.md`](consortium_key_ceremony.md) — roster authority keys  
- [`constant_time_ci.md`](constant_time_ci.md) — timing smokes and dudect lab boundary  
- [`RESEARCH_OPS_STATUS.md`](RESEARCH_OPS_STATUS.md) — honest Partial vs External gaps
