# AEGIS production deployment checklist

**Date:** 2026-07-18  
**Tip:** `c7c2f0d`  
**Audience:** operators deploying `aegis-node` / `aegis-client` relays and clients.

This is a concise go-live gate. It does **not** replace threat-model review or consortium ceremony docs. Theory hub: [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md).

## Config templates and validation

Production-oriented TOML starters live under [`deploy/templates/`](../../deploy/templates/) (`node.production.toml`, `client.production.toml`, `roster.toml.snippet`). Copy per relay/client, replace placeholders, then:

```bash
cargo run -p aegis-node -- validate --config /path/to/node.toml
```

Fails closed on lab flags (`allow_unverified_roster`, inline KEM, `[trace].path`, disabled ingress caps). See [`PILOT.md`](PILOT.md) for the full pilot sequence.

### Docker compose pilot (optional)

Multi-container bridge pilot lives under [`deploy/compose/`](../../deploy/compose/) (healthchecked relays, `.env.example`, bridge `pilot_configs/`). Full steps, Windows Docker Desktop + WSL2 install, and honest “containers ran” rules: [`PILOT.md`](PILOT.md) § Docker pilot.

**Without a Docker daemon** (common on fresh Windows hosts):

```powershell
.\deploy\scripts\check_pilot_prereqs.ps1
python deploy\scripts\validate_compose_offline.py
```

That path validates compose YAML + pilot TOML shape only — it does **not** start containers. Pilot node TOMLs intentionally fail `aegis-node validate` on lab KEM flags; production templates must pass validate after placeholders are replaced.

**Adaptive / roster-path (client):** production client template documents `[guard_mitigation] preset = "adaptive_v4"` (preferred; v3/v2/legacy `adaptive_first` still parse) and `[path]` / `--roster-path` wiring — see [`adaptive_guard_mitigation.md`](adaptive_guard_mitigation.md). Defaults remain off.

## Pre-flight

| Check | Production setting | Why |
|-------|-------------------|-----|
| Roster verify | Consortium keys configured; **`allow_unverified_roster = false`** | Unsigned roster load is lab-only ([`consortium_key_ceremony.md`](consortium_key_ceremony.md)) |
| Hop handshake | **`handshake = "auto"`** with **`noise_static_secret`** (+ peer **`noise_static_public`**) on every link | Auto selects Noise_IK when keys present ([`noise_link_auth.md`](noise_link_auth.md)) |
| Cover egress | Cover pacing **on** (default τ-paced emitter; do not disable for “performance”) | Sender-side unobservability depends on constant-rate cover |
| Cover multi-hop (opt-in) | `[cover] multihop_defense = "cover_onions"` when terminal peer KEM public available; else `"matched_local_discard"` | Raises wire↔forward continuity vs baseline local discard ([`cover_multihop_defense.md`](cover_multihop_defense.md)) |
| Ingress limits | Token bucket enabled; tune **`max_cells_per_sec`** / peer budgets for your τ | Prevents adversarial flood ([`RESEARCH_OPS_STATUS.md`](RESEARCH_OPS_STATUS.md) #8) |
| Ingress KEM binding | Optional **`kem_commitment`** + **`link.require_ingress_kem_commitment = true`** | Binds ingress handshake MAC to roster KEM; fails closed without commitment ([`AEGIS_implementation_threat_model.md`](../AEGIS_implementation_threat_model.md)) |
| Coarse metrics scrape | Use **`MetricsExportGate`** / `[metrics]` defaults (min **30s**, quantize **16**, suppress ingress drops); do not poll raw `coarse_stats` for dashboards | High-res / privileged observers retain GPA residual under flood ([`metrics_scrape_defense.md`](metrics_scrape_defense.md)) |
| Health gossip | **`[health_gossip] enabled = true`**, signing key, peer **`gossip_verifying_key`**; prefer **stacked** `majority_k = 4`, `min_orgs = 2`, `eclipse_detect = true` + peer `org_id`/`jurisdiction` | Signed neighbor health with BFT-lite quorum ([`health_gossip.md`](health_gossip.md)) |
| Adaptive guard (client) | Opt-in **`[guard_mitigation] preset = "adaptive_v4"`** + optional `[path]` signals / `--roster-path` | Best long-horizon sim mitigation; does not close §13 ([`adaptive_guard_mitigation.md`](adaptive_guard_mitigation.md)) |
| Jurisdiction path (client) | Opt-in **`[path] require_diverse_jurisdictions = true`** | Soft software filter; charter/legal External ([`faction_sybil_skew.md`](faction_sybil_skew.md)) |
| Reputation | Issuer pubkey loaded; **`verify_and_spend`** / nullifier registry; presentations **signed** by issuer | Anonymous reputation path is Partial — do not skip verifier steps ([`anonymous_reputation.md`](anonymous_reputation.md)) |
| Lab flags off | **`allow_unverified_roster = false`**; no `load_from_file_unverified` in production wiring | Explicit unverified roster is test/lab only |
| Trace / debug | **`[trace].path` unset** on mix relays; exit sink only on designated exit hops | Relay forward trace is capture instrumentation, not production default ([`AEGIS_phase8_hardening_notes.md`](../AEGIS_phase8_hardening_notes.md) §5) |
| Exit presence pad | **`[exit].presence_pad = false`** (default) on all relays; enable only on exit hops if accepting bandwidth cost | Matched-Q decoy/idle pad; clearnet GPA residual remains ([`exit_tier_defense.md`](exit_tier_defense.md)) |

### Knobs summary (metrics / gossip / cover / exit)

| Section | Knobs | Production intent |
|---------|-------|-------------------|
| `[metrics]` | `min_scrape_interval_secs=30`, `quantize_bucket=16`, `suppress_ingress_drop_detail=true`, `allow_high_resolution=false` | Stacked scrape harden via `MetricsExportGate` |
| `[health_gossip]` | `enabled=true`, `majority_k=4`, `min_orgs=2`, `eclipse_detect=true` | Stacked eclipse defense (not multi-org BFT) |
| `[cover]` | `enabled`/`require=true`; opt-in `multihop_defense` = `cover_onions` \| `matched_local_discard` | τ cover required; multi-hop defenses opt-in |
| `[exit]` | `presence_pad` (default false), `pad_q`, `epoch_ms`, `presence_rate_pct` | Exit hops only when accepting pad cost |

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

- [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md) — theory hub (recommended opt-ins + wave status)  
- [`PILOT.md`](PILOT.md) — pilot packaging, templates, staged rollout  
- [`CONSORTIUM_CHARTER.md`](CONSORTIUM_CHARTER.md) — governance draft (membership, vetting, compromise response)  
- [`noise_link_auth.md`](noise_link_auth.md) — handshake modes and static keys  
- [`health_gossip.md`](health_gossip.md) — gossip signing and quorum  
- [`anonymous_reputation.md`](anonymous_reputation.md) — issuer + nullifier checklist  
- [`consortium_key_ceremony.md`](consortium_key_ceremony.md) — roster authority keys  
- [`softhsm_ceremony.md`](softhsm_ceremony.md) — SoftHSM2 PKCS#11 stand-in  
- [`constant_time_ci.md`](constant_time_ci.md) — timing smokes and dudect lab boundary  
- [`RESEARCH_OPS_STATUS.md`](RESEARCH_OPS_STATUS.md) — honest Partial vs External gaps
