# AEGIS operator pilot (4-node loopback)

**Date:** 2026-07-18  
**Tip:** `c7c2f0d`  
**Audience:** operators validating a production-checklist stack before WAN deployment  
**Related:** [`DEPLOYMENT.md`](DEPLOYMENT.md), [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md) (theory hub), [`consortium_key_ceremony.md`](consortium_key_ceremony.md), [`noise_link_auth.md`](noise_link_auth.md), [`health_gossip.md`](health_gossip.md), [`softhsm_ceremony.md`](softhsm_ceremony.md)

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
| `deploy/compose/` | Docker multi-node pilot (4 relays + optional client profile) |
| `deploy/scripts/check_pilot_prereqs.*` | Probe docker/cargo/python; print unblock steps (no installs) |
| `deploy/scripts/validate_compose_offline.py` | Compose YAML + pilot TOML lint without a Docker daemon |
| `deploy/evidence/` | Probe / offline-validate artifacts (not proof of running containers) |

## Docker pilot (multi-container)

When Docker is available, a bridge-network variant exercises the same production-checklist defaults as loopback (`verified roster`, Noise `auto`, cover on, gossip on) across **separate containers** instead of one host process tree.

| Path | Purpose |
|------|---------|
| `deploy/compose/Dockerfile` | Builds `aegis-node` + `aegis-client` (release); bash for TCP healthchecks |
| `deploy/compose/docker-compose.yml` | 4 relays (healthchecks, restart, host ports) + optional `client` profile |
| `deploy/compose/.env.example` | `AEGIS_RUST_LOG`, host ports, client payload/τ knobs |
| `deploy/compose/generate_configs.ps1` / `generate_configs.sh` | Writes `deploy/compose/pilot_configs/` with `--network bridge` |

**Honest status rule:** if `docker version` / engine is missing, do **not** claim the compose pilot ran. Use the offline pack checks below, then loopback `run_pilot.*`.

### Offline pack validation (no Docker daemon)

From repo root (Python 3.11+; PyYAML recommended):

```powershell
.\deploy\scripts\check_pilot_prereqs.ps1
python deploy\scripts\validate_compose_offline.py
```

```bash
chmod +x deploy/scripts/check_pilot_prereqs.sh
./deploy/scripts/check_pilot_prereqs.sh
python3 deploy/scripts/validate_compose_offline.py
```

This lints `docker-compose.yml`, checks pilot TOML shape (`[roster].path`, cover, gossip, Noise `auto`, Docker DNS peers), documents `adaptive_v4` / roster-path wiring in comments, and — if `aegis-node` is on PATH or under `crates/target/` — runs `aegis-node validate`. Pilot configs are **expected to FAIL** validate on lab KEM flags (`allow_plaintext_kem` + inline seeds) while roster verify succeeds when cwd is `pilot_configs/`. Evidence: `deploy/evidence/offline_validate.json`, `deploy/evidence/host_probe.txt`.

### Windows Docker Desktop + WSL2 (operator install — interactive)

These steps are **not** automated by repo scripts (Docker Desktop requires an installer UI). Run as administrator where noted; reboot when prompted.

1. **BIOS/UEFI:** enable hardware virtualization (VT-x/AMD-V) if disabled.
2. **Admin PowerShell** — enable WSL + Virtual Machine Platform (no Docker install yet):

```powershell
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```

3. **Reboot**, then install/update WSL2 Ubuntu:

```powershell
wsl --install -d Ubuntu
# if WSL already present:
wsl --update
wsl --set-default-version 2
wsl -l -v
```

4. **Docker Desktop for Windows:** download from [Docker’s Windows install docs](https://docs.docker.com/desktop/setup/install/windows-install/). Run the installer UI → enable **Use WSL 2 based engine** → finish wizard → **Start Docker Desktop** and wait until the engine reports running.
5. **New terminal** verify:

```powershell
docker version
docker compose version
```

6. **Pilot up** (from repo root):

```powershell
.\deploy\compose\generate_configs.ps1
# optional: copy deploy\compose\.env.example → deploy\compose\.env
docker compose -f deploy/compose/docker-compose.yml up --build
docker compose -f deploy/compose/docker-compose.yml --profile client run --rm client
```

Capture logs under `deploy/evidence/` if you need a run record (operator-authored). Until step 5 succeeds, treat the host as **Docker absent**.

### Generate bridge configs + run (when Docker is present)

```powershell
.\deploy\compose\generate_configs.ps1
docker compose -f deploy/compose/docker-compose.yml up --build
docker compose -f deploy/compose/docker-compose.yml --profile client run --rm client
```

```bash
chmod +x deploy/compose/generate_configs.sh
./deploy/compose/generate_configs.sh
docker compose -f deploy/compose/docker-compose.yml up --build
docker compose -f deploy/compose/docker-compose.yml --profile client run --rm client
```

Configs mount at `/config`; nodes listen on `0.0.0.0:17419–17422`, publish optional host ports, and peer via Docker DNS (`node0`…`node3`). Healthchecks probe local TCP listen; `restart: unless-stopped` on relays. Runtime logs land in `deploy/compose/pilot_configs/data/` on the bind mount. Inline `[kem]` seeds remain pilot-only (`allow_plaintext_kem = true`).

**If Docker is unavailable**, keep using offline validate + loopback (`run_pilot.ps1` / `run_pilot.sh`). Compose files stay in-tree for CI or another machine.

### Loopback vs bridge — honest limits

| Aspect | Loopback (`run_pilot.*`) | Docker bridge (`deploy/compose/`) |
|--------|--------------------------|-----------------------------------|
| Process isolation | Single OS; hidden windows / same user | Separate containers |
| Network path | `127.0.0.1` TCP — no NIC, no ARP | Bridge veth; synthetic L2/L3 between containers |
| Latency / loss | Near-zero LAN loopback | Slightly higher; still not WAN |
| NAT / firewall | N/A | Not modeled (same bridge) |
| Multi-host | No | No — all containers on one Docker host |
| Gossip quorum | Short runs may miss 60s interval | Same — not a multi-org deployment |

Neither path replaces staged **WAN soak** on distinct operator hosts, adversarial netem, or consortium ceremony. Docker bridge only proves that cross-container DNS + Noise + roster verify + cover + gossip wiring works beyond a single loopback namespace.

## Recommended opt-ins (default off unless noted)

These are the current researched/productized levers. Loopback pilot templates keep most **commented out** so the smoke stays minimal; enable for staging / production checklist runs. Theory + residuals: [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md).

| Opt-in | Where | Recommended setting | Notes |
|--------|-------|---------------------|-------|
| Adaptive guard | **Client** `[guard_mitigation]` | `preset = "adaptive_v4"` | Prefer v4 over v3/v2/`adaptive_first`. Node parses for symmetry only — see [`adaptive_guard_mitigation.md`](adaptive_guard_mitigation.md). |
| Jurisdiction path | **Client** `[path]` | `require_diverse_jurisdictions = true`, `max_per_jurisdiction = 1` | Soft filter; composes with adaptive_v4. Legal charter remains **External** ([`faction_sybil_skew.md`](faction_sybil_skew.md)). |
| Health gossip stacked | **Node** `[health_gossip]` | `majority_k = 4`, `min_orgs = 2`, `eclipse_detect = true` + peer `org_id`/`jurisdiction` | Code defaults are stacked when knobs omitted; committed pilot TOMLs still pin `majority_k = 2` for short smoke — raise to stacked for staging ([`health_gossip.md`](health_gossip.md)). |
| Exit presence pad | **Exit node** `[exit]` | `presence_pad = true` (+ `pad_q` / `epoch_ms` / `presence_rate_pct`) | Exit hops only; bandwidth cost; clearnet GPA residual ([`exit_tier_defense.md`](exit_tier_defense.md)). |
| Cover multi-hop | **Node** `[cover]` | `multihop_defense = "cover_onions"` (or `"matched_local_discard"`) | Onions need terminal peer KEM public; matched discard when PK unavailable ([`cover_multihop_defense.md`](cover_multihop_defense.md)). |
| Metrics export gate | **Node** `[metrics]` | Keep production defaults (min **30s**, quantize **16**, suppress ingress drops) | Use `MetricsExportGate`; do not scrape raw `coarse_stats` ([`metrics_scrape_defense.md`](metrics_scrape_defense.md)). |

**Client path wiring:** omit ordered `[[hops]]` or pass `--roster-path` for roster-driven paths (KEM registry by relay `id` still required).

### SoftHSM ceremony path (optional, not required for loopback)

For PKCS#11 stand-in before vendor HSM: user-local SoftHSM2 under WSL/Linux — probe → user-build → init token `aegis-ceremony` → ceremony regress. Does **not** claim hardware custody. Full steps: [`softhsm_ceremony.md`](softhsm_ceremony.md).

```powershell
powershell -File scripts/softhsm_wsl.ps1 -Action probe
powershell -File scripts/softhsm_wsl.ps1 -Action user-build
powershell -File scripts/softhsm_wsl.ps1 -Action init -Evidence
powershell -File scripts/softhsm_wsl.ps1 -Action regress -Evidence
```

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
# Pilot templates pin majority_k = 2; staging: stacked majority_k=4, min_orgs=2, eclipse_detect=true

[link]
handshake = "auto"
noise_static_secret = "..."
# production ingress limits: defaults (≈ 1/τ cells/sec); not zeroed like testnet

# [metrics]  — omit to use MetricsExportGate production defaults (30s / quantize 16 / suppress drops)
# NO [trace] section
```

Optional researched opt-ins (**default off** unless noted) — see table above:

```toml
# Client (or node for symmetry):
# [guard_mitigation]
# preset = "adaptive_v4"   # preferred; or "adaptive_v3" / "adaptive_v2" / "adaptive_first"
# [path]
# epoch_age = 7
# require_diverse_jurisdictions = true
# max_per_jurisdiction = 1

# Node cover multi-hop (opt-in):
# [cover]
# multihop_defense = "cover_onions"          # or "matched_local_discard"
# cover_onion_flows = 1
# # matched_cover_flows = 2

# Exit hop only:
# [exit]
# deliver_to = "file:data/exit_deliveries.log"
# presence_pad = true
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
3. Optional: `data/health_quorum.log` on nodes — committed pilot TOMLs use `majority_k = 2` (short smoke); stacked staging uses `majority_k = 4` and may not reach quorum in a short run — expected.

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

- [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md) — theory hub (quantified / productized / External)  
- [`DEPLOYMENT.md`](DEPLOYMENT.md) — production go-live gate  
- [`RESEARCH_OPS_STATUS.md`](RESEARCH_OPS_STATUS.md) — Partial vs External gaps  
- [`softhsm_ceremony.md`](softhsm_ceremony.md) — SoftHSM2 PKCS#11 stand-in (not hardware custody)  
- `sim/scripts/capture_multiprocess_trace.py` — lab trace capture (trace on, lab flags); pilot intentionally diverges
