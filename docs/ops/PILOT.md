# AEGIS operator pilot (4-node loopback)

**Date:** 2026-07-18  
**Audience:** operators validating a production-checklist stack before WAN deployment  
**Related:** [`DEPLOYMENT.md`](DEPLOYMENT.md), [`consortium_key_ceremony.md`](consortium_key_ceremony.md), [`noise_link_auth.md`](noise_link_auth.md), [`health_gossip.md`](health_gossip.md)

This pilot runs four `aegis-node` relays and a paced `aegis-client` on **127.0.0.1** with settings aligned to the production deployment checklist — not the lab-loose `sim/data/testnet_configs/` flags (unverified roster, trace on, ingress limits disabled).

## What this is / is not

| In scope | Out of scope |
|----------|--------------|
| Verified roster (`allow_unverified_roster = false`) | Multi-host WAN latency, packet loss, NAT |
| Noise `handshake = "auto"` with static keys | Real consortium ceremony / HSM custody |
| Cover on + fail-closed (`[cover] require = true`) | Info-theoretic traffic-analysis guarantees |
| Health gossip enabled with signed adverts | Multi-org BFT gossip quorum across operators |
| Production ingress token-bucket defaults | Constant-time dudect evidence (see [`constant_time_ci.md`](constant_time_ci.md)) |
| No relay forward `[trace]` paths | TEE attestation, anonymous reputation issuer wiring |

**Honest limit:** a loopback pilot proves binaries, config, roster verify, Noise handshakes, cover startup, and end-to-end Sphinx delivery on one machine. It does **not** substitute for staged WAN soak, adversarial network sim, or ops ceremony on distinct hosts.

## Layout

| Path | Purpose |
|------|---------|
| `sim/data/pilot_configs/` | Generated templates: `node0.toml`…`node3.toml`, `client.toml`, `roster.json`, `authority.pub.hex` |
| `sim/scripts/generate_pilot_configs.py` | Regenerates configs (fixed ports **17419–17422** or `--ephemeral-ports`) |
| `scripts/run_pilot.ps1` | Windows smoke: build → start 4 nodes → paced sends → coarse health |
| `scripts/run_pilot.sh` | Unix equivalent |
| `crates/aegis-topology/src/bin/aegis_pilot_gen.rs` | Deterministic key/roster/TOML generator |

## Step-by-step (manual)

### 1. Build binaries

From the repo root:

```powershell
cd crates
cargo build -p aegis-node -p aegis-client -p aegis-topology --bin aegis-pilot-gen
```

### 2. Generate Noise / KEM / gossip keys + verified roster

Pilot keys are **deterministic** (reproducible smoke material — not production secrets):

```powershell
# from repo root
python sim/scripts/generate_pilot_configs.py
```

This invokes `aegis-pilot-gen`, which:

- Builds four KEM-derived relay IDs and a **1-of-1 consortium-signed** `roster.json`
- Writes per-node Noise static secrets + peer `noise_static_public` (Auto → Noise_IK)
- Writes per-node health-gossip `signing_seed` + peer `gossip_verifying_key`
- Sets `allow_unverified_roster = false` with `authority.pub.hex` referenced in every node/client config

To regenerate with ephemeral OS ports (e.g. CI):

```powershell
python sim/scripts/generate_pilot_configs.py --ephemeral-ports
```

### 3. Inspect production-checklist defaults

Each `node*.toml` includes:

```toml
[roster]
allow_unverified_roster = false

[cover]
enabled = true
require = true

[health_gossip]
enabled = true
# signing_seed + peer gossip_verifying_key configured

[link]
handshake = "auto"
noise_static_secret = "..."
# production ingress limits: defaults (≈ 1/τ cells/sec); not zeroed like testnet

# NO [trace] section
```

Inline `[kem]` seeds use `allow_plaintext_kem = true` for pilot convenience only. Production WAN nodes should use external `kem.seeds` with `0600` per [`DEPLOYMENT.md`](DEPLOYMENT.md).

### 4. Start the 4-node path

Fixed-port example (after generate):

```powershell
cd crates
$cfg = "..\sim\data\pilot_configs"
Start-Process target\debug\aegis-node.exe -ArgumentList "--config","$cfg\node0.toml" -NoNewWindow
# ... node1..node3 similarly
```

Or use the orchestrator (starts nodes with **`sim/data/pilot_configs/` as working directory** so relative `roster.json` paths resolve):

```powershell
.\scripts\run_pilot.ps1
```

```bash
chmod +x scripts/run_pilot.sh
./scripts/run_pilot.sh
```

### 5. Paced client send (cover on, trace off)

The run scripts invoke:

```text
aegis-client --config client.toml --payload pilot-N --cover-secs 2 --tau-secs 0.35
```

This uses **paced Mode-1** sessions (not `--raw`). Relay `[trace]` remains unset.

### 6. Coarse health checks

After sends, verify:

1. All four node processes still running (no “unverified roster” stderr).
2. `sim/data/pilot_configs/data/exit_deliveries.log` grows on exit node (node3).
3. Optional: `data/health_quorum.log` on nodes — gossip uses `majority_k = 2`; a short pilot may not reach quorum; that is expected.

## One-command smoke (Windows)

```powershell
.\scripts\run_pilot.ps1
```

Options: `-EphemeralPorts`, `-Sends 5`, `-CoverSecs 2`, `-TauSecs 0.35`, `-SkipBuild`.

## One-command smoke (Unix)

```bash
./scripts/run_pilot.sh --sends 3
```

## Regenerating committed templates

After changing `aegis-pilot-gen`:

```powershell
python sim/scripts/generate_pilot_configs.py --out sim/data/pilot_configs
git add sim/data/pilot_configs/
```

Do **not** commit real ceremony seeds; pilot authority material is labeled test-only in `authority.pub.hex`.

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| `UnverifiedRosterNotAllowed` | `[roster]` missing `authority_pubkeys` or `allow_unverified_roster = true` |
| Handshake / Noise failure | Mismatched `noise_static_public` vs peer secret; re-run `generate_pilot_configs.py` |
| Node refuses start (cover) | `[cover] require = true` and cover channel failed — check stderr |
| Client KEM binding error | Hop `kem_commitment` does not match signed roster — regenerate configs |
| Port already in use | Use `--ephemeral-ports` or free **17419–17422** |

## See also

- [`DEPLOYMENT.md`](DEPLOYMENT.md) — production go-live gate  
- [`RESEARCH_OPS_STATUS.md`](RESEARCH_OPS_STATUS.md) — Partial vs External gaps  
- `sim/scripts/capture_multiprocess_trace.py` — lab trace capture (trace on, lab flags); pilot intentionally diverges
