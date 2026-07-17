//! TOML node configuration: identity, KEM secret, listen address, peers.
//!
//! ## KEM seed storage (threat model: `docs/AEGIS_implementation_threat_model.md` §7)
//!
//! Production default: first-run generation writes seeds to a **separate file**
//! (default `kem.seeds` beside the node config); the TOML holds only
//! `[kem] file = "..."`. Inline seeds in the main config require explicit
//! `[kem] allow_plaintext_kem = true` (lab/test).
//!
//! - **Unix** (feature `kem-keyring`, default): OS keychain via `keyring`
//!   (service `aegis-node`; account = relay id or config-path hash). Pointer file
//!   uses magic [`crate::kem_seed_protect::KEM_SEED_KEYRING_MAGIC`]. Falls back to
//!   plaintext TOML + mode `0600` if the keychain is unavailable.
//! - **Windows** (feature `kem-dpapi`, default): DPAPI **same-user** wrap
//!   (`CryptProtectData`, user scope) with magic
//!   [`crate::kem_seed_protect::KEM_SEED_DPAPI_MAGIC`]; decryptable only by the
//!   creating Windows profile. Legacy owner-readable plaintext still loads.
//! - **Unix load hardening:** [`crate::kem_seed_protect::assert_kem_seed_file_mode_safe`]
//!   refuses group/world-readable `kem.seeds` (stricter than write-time `0600` alone).

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use aegis_crypto::kem::RelayKemSecret;
use aegis_negotiator::SecurityDial;
use aegis_relay::{
    BulkCoverConfig, IngressRateLimitConfig, LinkBridgeConfig, LinkHandshakeMode, PeerInfo,
    RelayConfig, RelayId, DEFAULT_COVER_ROUND_SECS, DEFAULT_COVER_TARGET_FLOW_COUNT,
    DEFAULT_GLOBAL_MAX_CELLS_PER_SEC, DEFAULT_INGRESS_BURST, DEFAULT_INGRESS_MAX_CELLS_PER_SEC,
};
use aegis_topology::{RelayRoster, RosterError, ThresholdConsortium};
use aegis_trust::{
    signing_key_from_hex_seed, verifying_key_from_hex, NullifierError, NullifierRegistry,
    RelayPruningPolicy, ReputationError, ReputationLedger,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::{CryptoRngCore, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("serialize: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("hex: {0}")]
    Hex(&'static str),
    #[error("missing kem seeds — run `aegis-node --config <path>` once to generate them, or set [kem] file / inline seeds")]
    MissingKem,
    #[error("incomplete [kem] inline seeds — need x25519_seed, mlkem_d, and mlkem_z together")]
    IncompleteKem,
    #[error("roster: {0}")]
    Roster(#[from] RosterError),
    #[error("reputation: {0}")]
    Reputation(#[from] ReputationError),
    #[error("nullifier registry: {0}")]
    Nullifier(#[from] NullifierError),
    #[error("kem seed protect: {0}")]
    KemProtect(String),
}

/// Default KEM seed filename when `[kem] file` is omitted (beside the node config).
pub const DEFAULT_KEM_SEED_FILENAME: &str = "kem.seeds";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfigFile {
    pub relay_id: String,
    pub listen: String,
    #[serde(default = "default_mu")]
    pub mu: f64,
    #[serde(default)]
    pub kem: Option<KemFileConfig>,
    /// Optional local roster KEM commitment (64 hex chars) bound into inbound handshake MACs.
    #[serde(default)]
    pub kem_commitment: Option<String>,
    #[serde(default)]
    pub ingress: Option<IngressConfig>,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub link: LinkNetConfig,
    /// Optional exit sink for terminal Sphinx peels (off by default; enable on exit relays only).
    #[serde(default)]
    pub exit: ExitConfig,
    /// Optional post-forward timestamp trace (relay vantage, off by default).
    #[serde(default)]
    pub trace: TraceConfig,
    /// Optional permissioned relay roster loaded from JSON (spec §4.9).
    #[serde(default)]
    pub roster: Option<RosterFileConfig>,
    /// Bulk cover-flow policy (spec §5.2 L2). Defaults to production fail-closed.
    #[serde(default)]
    pub cover: CoverFileConfig,
    /// Optional local reputation ledger persistence (spec §4.8).
    #[serde(default)]
    pub reputation: ReputationConfig,
    /// Optional signed cross-relay peer-health gossip (see `docs/ops/health_gossip.md`).
    #[serde(default)]
    pub health_gossip: HealthGossipConfig,
}

/// TOML `[reputation]` — EWMA ledger persistence for this relay process.
///
/// ## Optional operator attestation
///
/// In-memory `record_success` / `record_failure` stay unsigned. When keys are
/// configured, snapshots on disk are Ed25519-signed over a canonical encoding of
/// decay + scores (anti-repudiation of persisted state only; no cross-node consensus).
///
/// - `operator_signing_seed` — 64 hex chars; used to sign on save (also derives VK).
/// - `operator_signing_key_file` — file containing 64 hex chars of seed (alternative).
/// - `operator_verifying_key` — 64 hex chars; when set, load verifies signatures and
///   rejects unsigned/tampered ledgers. If omitted but a signing seed is present,
///   the derived verifying key is used for load verification.
///
/// With no signing/verifying material, behavior matches the legacy unsigned JSON path.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReputationConfig {
    /// JSON ledger file; loaded on startup when present, saved on drain/shutdown.
    #[serde(default)]
    pub ledger_path: Option<String>,
    /// Optional JSON nullifier registry for local anonymous-presentation replay
    /// prevention (`aegis_trust::NullifierRegistry`). Local/file-backed only —
    /// not a multi-node AC issuer. See `docs/ops/anonymous_reputation.md`.
    #[serde(default)]
    pub nullifier_registry_path: Option<String>,
    /// Optional hex Ed25519 seed (32 bytes) for signing ledger snapshots on save.
    #[serde(default)]
    pub operator_signing_seed: Option<String>,
    /// Optional path to a file containing the hex signing seed (alternative to inline).
    #[serde(default)]
    pub operator_signing_key_file: Option<String>,
    /// Optional hex Ed25519 verifying key; when set (or derived from signing seed),
    /// ledger load requires a valid operator signature.
    #[serde(default)]
    pub operator_verifying_key: Option<String>,
}

const DEFAULT_REPUTATION_DECAY: f64 = 0.9;
const DEFAULT_ANOMALY_ALPHA: f64 = 0.2;
const DEFAULT_ANOMALY_Z: f64 = 3.0;

impl ReputationConfig {
    /// Resolve optional operator signing / verifying keys from TOML fields.
    pub fn resolve_operator_keys(&self) -> Result<(Option<SigningKey>, Option<VerifyingKey>), ReputationError> {
        let signing = if let Some(ref hex) = self.operator_signing_seed {
            Some(signing_key_from_hex_seed(hex)?)
        } else if let Some(ref path_str) = self.operator_signing_key_file {
            let text = fs::read_to_string(path_str)?;
            Some(signing_key_from_hex_seed(text.trim())?)
        } else {
            None
        };

        let verifying = if let Some(ref hex) = self.operator_verifying_key {
            Some(verifying_key_from_hex(hex)?)
        } else {
            signing.as_ref().map(|sk| sk.verifying_key())
        };

        Ok((signing, verifying))
    }

    /// Build the relay pruning policy, optionally hydrating the ledger from disk.
    pub fn load_pruning_policy(&self) -> Result<RelayPruningPolicy, ReputationError> {
        let (_signing, verifying) = self.resolve_operator_keys()?;
        if let Some(ref path_str) = self.ledger_path {
            let path = PathBuf::from(path_str);
            if path.exists() {
                let load_result = match verifying.as_ref() {
                    Some(vk) => {
                        ReputationLedger::load_from_file_verified(
                            &path,
                            DEFAULT_REPUTATION_DECAY,
                            vk,
                        )
                    }
                    None => ReputationLedger::load_from_file(&path, DEFAULT_REPUTATION_DECAY),
                };
                match load_result {
                    Ok(ledger) => {
                        eprintln!("loaded reputation ledger from {}", path.display());
                        return Ok(RelayPruningPolicy::with_ledger(
                            ledger,
                            DEFAULT_ANOMALY_ALPHA,
                            DEFAULT_ANOMALY_Z,
                        ));
                    }
                    Err(e) => {
                        eprintln!(
                            "warning: reputation ledger load failed ({e}); starting fresh"
                        );
                    }
                }
            }
        }
        RelayPruningPolicy::new(
            DEFAULT_REPUTATION_DECAY,
            DEFAULT_ANOMALY_ALPHA,
            DEFAULT_ANOMALY_Z,
        )
    }

    /// Persist the shared ledger when `ledger_path` is configured.
    ///
    /// Signs the snapshot when `operator_signing_seed` or `operator_signing_key_file`
    /// is set; otherwise writes unsigned JSON (legacy path).
    pub fn save_ledger(&self, policy: &RelayPruningPolicy) {
        let Some(ref path_str) = self.ledger_path else {
            return;
        };
        let path = PathBuf::from(path_str);
        let signing = match self.resolve_operator_keys() {
            Ok((sk, _)) => sk,
            Err(e) => {
                eprintln!("warning: reputation operator key resolve failed ({e})");
                return;
            }
        };
        let result = match signing.as_ref() {
            Some(sk) => policy.ledger().save_to_file_signed(&path, sk),
            None => policy.ledger().save_to_file(&path),
        };
        if let Err(e) = result {
            eprintln!("warning: reputation ledger save failed ({e})");
        }
    }

    /// Load the optional nullifier registry (empty if path unset or missing).
    pub fn load_nullifier_registry(&self) -> Result<NullifierRegistry, NullifierError> {
        let Some(ref path_str) = self.nullifier_registry_path else {
            return Ok(NullifierRegistry::new());
        };
        let path = PathBuf::from(path_str);
        let reg = NullifierRegistry::open_or_empty(&path)?;
        if path.exists() {
            eprintln!(
                "loaded nullifier registry from {} ({} spent)",
                path.display(),
                reg.len()
            );
        }
        Ok(reg)
    }

    /// Persist the nullifier registry when `nullifier_registry_path` is set.
    pub fn save_nullifier_registry(&self, registry: &NullifierRegistry) {
        let Some(ref path_str) = self.nullifier_registry_path else {
            return;
        };
        let path = PathBuf::from(path_str);
        if let Err(e) = registry.save_to_file(&path) {
            eprintln!("warning: nullifier registry save failed ({e})");
        }
    }

    /// Merge a peer-exported nullifier registry file into `registry` and optionally persist.
    pub fn merge_nullifier_registry_from(
        &self,
        registry: &mut NullifierRegistry,
        import_path: &str,
    ) -> Result<aegis_trust::NullifierMergeReport, NullifierError> {
        let report = registry.merge_from_file(Path::new(import_path))?;
        self.save_nullifier_registry(registry);
        Ok(report)
    }
}

/// TOML `[cover]` — bulk cover round auto-start / fail-closed policy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverFileConfig {
    /// Open L2 bulk rounds and emit cover on the cover channel (default true).
    #[serde(default = "default_cover_enabled")]
    pub enabled: bool,
    /// Refuse to run if cover cannot be started (default true).
    #[serde(default = "default_cover_require")]
    pub require: bool,
    /// Target observed flow count per round (default [`DEFAULT_COVER_TARGET_FLOW_COUNT`]).
    #[serde(default = "default_cover_target")]
    pub target_flow_count: u32,
    /// Seconds between end/begin rotation so cover can emit (default 30; 0 = begin once).
    #[serde(default = "default_cover_round_secs")]
    pub round_secs: u64,
}

impl Default for CoverFileConfig {
    fn default() -> Self {
        Self {
            enabled: default_cover_enabled(),
            require: default_cover_require(),
            target_flow_count: default_cover_target(),
            round_secs: default_cover_round_secs(),
        }
    }
}

impl CoverFileConfig {
    pub fn into_bulk_cover(self) -> BulkCoverConfig {
        BulkCoverConfig {
            enabled: self.enabled,
            require: self.require,
            dial: SecurityDial::L2UniformBatched,
            target_flow_count: self.target_flow_count,
            round_secs: self.round_secs,
        }
    }
}

fn default_cover_enabled() -> bool {
    true
}

fn default_cover_require() -> bool {
    true
}

fn default_cover_target() -> u32 {
    DEFAULT_COVER_TARGET_FLOW_COUNT
}

fn default_cover_round_secs() -> u64 {
    DEFAULT_COVER_ROUND_SECS
}

/// Disk roster + consortium authority keys for signature re-verify on load.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RosterFileConfig {
    /// Path to persisted roster JSON.
    pub path: String,
    /// Hex-encoded Ed25519 consortium verifying keys (32 bytes each).
    #[serde(default)]
    pub authority_pubkeys: Vec<String>,
    /// M-of-N threshold over `authority_pubkeys` (default 1).
    #[serde(default = "default_roster_threshold")]
    pub threshold: usize,
    /// Lab/test only: allow loading without re-verifying signatures when no keys
    /// are configured. Ignored when `authority_pubkeys` is non-empty (keys always
    /// force verification).
    #[serde(default)]
    pub allow_unverified_roster: bool,
}

fn default_roster_threshold() -> usize {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LinkNetConfig {
    /// Per-read timeout on link-layer TCP I/O (seconds).
    #[serde(default = "default_link_read_timeout_secs")]
    pub read_timeout_secs: u64,
    /// Maximum concurrent inbound TCP connections.
    #[serde(default = "default_max_inbound_connections")]
    pub max_inbound_connections: usize,
    /// Bind handshake MACs to the peer roster relay id (recommended).
    #[serde(default = "default_identity_binding")]
    pub identity_binding: bool,
    /// Sustained inbound cell/frame accept rate (cells/sec). Default ≈ 1/τ (Mode-1).
    /// Set to `0.0` to disable per-connection ingress rate limiting.
    #[serde(default = "default_max_cells_per_sec")]
    pub max_cells_per_sec: f64,
    /// Token-bucket burst (cells) above the sustained rate.
    #[serde(default = "default_ingress_burst")]
    pub burst: u32,
    /// Aggregate cap across all inbound connections (cells/sec).
    /// Default: Mode-1 × 8 expected clients (`DEFAULT_GLOBAL_MAX_CELLS_PER_SEC` ≈ 22.86).
    /// Set to `0.0` to disable the shared budget.
    #[serde(default = "default_global_max_cells_per_sec")]
    pub global_max_cells_per_sec: Option<f64>,
    /// `"auto"` (default), `"legacy_psk"`, or `"noise"`.
    ///
    /// `auto` selects Noise when local (+ peer) static keys are present; otherwise
    /// LegacyPsk. Explicit `"legacy_psk"` never uses Noise.
    #[serde(default = "default_link_handshake")]
    pub handshake: String,
    /// Local Noise static secret (64 hex). Required when `handshake = "noise"`;
    /// enables Noise under `handshake = "auto"` when peer statics are also set.
    #[serde(default)]
    pub noise_static_secret: Option<String>,
    /// Expected ingress initiator Noise static public (64 hex), optional.
    #[serde(default)]
    pub ingress_noise_static_public: Option<String>,
}

fn default_link_handshake() -> String {
    #[cfg(feature = "noise-link")]
    {
        "auto".to_string()
    }
    #[cfg(not(feature = "noise-link"))]
    {
        "legacy_psk".to_string()
    }
}

impl Default for LinkNetConfig {
    fn default() -> Self {
        Self {
            read_timeout_secs: default_link_read_timeout_secs(),
            max_inbound_connections: default_max_inbound_connections(),
            identity_binding: default_identity_binding(),
            max_cells_per_sec: default_max_cells_per_sec(),
            burst: default_ingress_burst(),
            global_max_cells_per_sec: default_global_max_cells_per_sec(),
            handshake: default_link_handshake(),
            noise_static_secret: None,
            ingress_noise_static_public: None,
        }
    }
}

fn default_identity_binding() -> bool {
    true
}

fn default_link_read_timeout_secs() -> u64 {
    aegis_relay::DEFAULT_LINK_READ_TIMEOUT.as_secs()
}

fn default_max_inbound_connections() -> usize {
    aegis_relay::DEFAULT_MAX_INBOUND_CONNECTIONS
}

fn default_max_cells_per_sec() -> f64 {
    DEFAULT_INGRESS_MAX_CELLS_PER_SEC
}

fn default_ingress_burst() -> u32 {
    DEFAULT_INGRESS_BURST
}

fn default_global_max_cells_per_sec() -> Option<f64> {
    Some(DEFAULT_GLOBAL_MAX_CELLS_PER_SEC)
}

fn default_mu() -> f64 {
    aegis_relay::DEFAULT_MU
}

/// On-disk KEM seed material (external file or inline in node TOML).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KemSeeds {
    pub x25519_seed: String,
    pub mlkem_d: String,
    pub mlkem_z: String,
}

/// `[kem]` — seed location policy and optional inline material.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct KemFileConfig {
    /// External seed file path (relative to the config directory, or absolute).
    /// Default on first run: [`DEFAULT_KEM_SEED_FILENAME`] beside the node config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Lab/test only: persist generated seeds inline in the node TOML on first run.
    /// Production default is `false` (separate file + restrictive permissions).
    #[serde(default)]
    pub allow_plaintext_kem: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x25519_seed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mlkem_d: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mlkem_z: Option<String>,
}

impl KemFileConfig {
    fn has_any_inline(&self) -> bool {
        self.x25519_seed.is_some() || self.mlkem_d.is_some() || self.mlkem_z.is_some()
    }

    fn has_complete_inline(&self) -> bool {
        self.x25519_seed.is_some() && self.mlkem_d.is_some() && self.mlkem_z.is_some()
    }

    fn inline_seeds(&self) -> Option<KemSeeds> {
        if self.has_complete_inline() {
            Some(KemSeeds {
                x25519_seed: self.x25519_seed.clone().unwrap(),
                mlkem_d: self.mlkem_d.clone().unwrap(),
                mlkem_z: self.mlkem_z.clone().unwrap(),
            })
        } else {
            None
        }
    }
}

/// Resolve the path to the external KEM seed file for a node config.
pub fn kem_seed_file_path(config_path: &Path, kem: &KemFileConfig) -> PathBuf {
    kem_seed_file_path_from_option(config_path, kem.file.as_deref())
}

fn kem_seed_file_path_from_option(config_path: &Path, file: Option<&str>) -> PathBuf {
    if let Some(f) = file {
        let p = PathBuf::from(f);
        if p.is_absolute() {
            return p;
        }
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(p)
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(DEFAULT_KEM_SEED_FILENAME)
    }
}

/// Load KEM seeds from inline `[kem]` fields or the configured external file.
pub fn resolve_kem_seeds(config_path: &Path, kem: &KemFileConfig) -> Result<KemSeeds, ConfigError> {
    if kem.has_any_inline() {
        if let Some(seeds) = kem.inline_seeds() {
            return Ok(seeds);
        }
        return Err(ConfigError::IncompleteKem);
    }
    let seed_path = kem_seed_file_path(config_path, kem);
    if !seed_path.is_file() {
        return Err(ConfigError::MissingKem);
    }
    crate::kem_seed_protect::assert_kem_seed_file_mode_safe(&seed_path)
        .map_err(ConfigError::KemProtect)?;
    let raw = fs::read(&seed_path)?;
    let plain = crate::kem_seed_protect::unprotect_seed_bytes(&raw)
        .map_err(ConfigError::KemProtect)?;
    let text = std::str::from_utf8(&plain)
        .map_err(|_| ConfigError::KemProtect("kem seed plaintext is not UTF-8".into()))?;
    Ok(toml::from_str(text)?)
}

fn generate_kem_seeds(rng: &mut (impl RngCore + CryptoRngCore)) -> KemSeeds {
    let mut x25519_seed = [0u8; 32];
    let mut mlkem_d = [0u8; 32];
    let mut mlkem_z = [0u8; 32];
    rng.fill_bytes(&mut x25519_seed);
    rng.fill_bytes(&mut mlkem_d);
    rng.fill_bytes(&mut mlkem_z);
    KemSeeds {
        x25519_seed: hex_encode(&x25519_seed),
        mlkem_d: hex_encode(&mlkem_d),
        mlkem_z: hex_encode(&mlkem_z),
    }
}

/// Write KEM seeds to `path`.
///
/// On Windows with `kem-dpapi` (default), stores DPAPI-protected bytes with a
/// clear magic header. On Unix with `kem-keyring` (default), stores a keyring
/// pointer file and the secret in the OS keychain (falls back to plaintext
/// `0600` if the keychain is unavailable). Account defaults to a hash of `path`.
pub fn persist_kem_seeds_file(path: &Path, seeds: &KemSeeds) -> Result<(), ConfigError> {
    let account = crate::kem_seed_protect::kem_keyring_account(path, None);
    persist_kem_seeds_file_with_account(path, seeds, &account)
}

/// Like [`persist_kem_seeds_file`], but with an explicit keyring account
/// (typically `kem_keyring_account(config_path, Some(relay_id_hex))`).
pub fn persist_kem_seeds_file_with_account(
    path: &Path,
    seeds: &KemSeeds,
    account: &str,
) -> Result<(), ConfigError> {
    let text = toml::to_string(seeds)?;
    let stored = crate::kem_seed_protect::protect_seed_bytes(text.as_bytes(), account)
        .map_err(ConfigError::KemProtect)?;
    write_restricted_file(path, &stored)
}

fn write_restricted_file(path: &Path, contents: &[u8]) -> Result<(), ConfigError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        fs::write(path, contents)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngressConfig {
    pub link_key: String,
    /// Optional override of `[link].max_cells_per_sec` for this node's ingress policy.
    #[serde(default)]
    pub max_cells_per_sec: Option<f64>,
    /// Optional override of `[link].burst`.
    #[serde(default)]
    pub burst: Option<u32>,
    /// Optional override of `[link].global_max_cells_per_sec`.
    #[serde(default)]
    pub global_max_cells_per_sec: Option<f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerConfig {
    pub id: String,
    pub addr: String,
    pub link_key: String,
    /// Optional roster KEM public-key commitment (64 hex chars) for outbound handshake MAC binding.
    #[serde(default)]
    pub kem_commitment: Option<String>,
    /// Optional Ed25519 verifying key (64 hex) for this peer's health-gossip adverts.
    #[serde(default)]
    pub gossip_verifying_key: Option<String>,
    /// Optional peer Noise static public key (64 hex) for `handshake = "noise"`.
    #[serde(default)]
    pub noise_static_public: Option<String>,
}

/// TOML `[health_gossip]` — signed `PeerHealthAdvert` exchange over hop links.
///
/// When `enabled` and a signing seed is configured, the node periodically signs
/// local peer-health windows and sends them as link-control cells. Receivers
/// verify under each peer's `gossip_verifying_key`, buffer until `majority_k`
/// distinct reporters, then merge the median failure rate at half weight.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthGossipConfig {
    /// Emit and accept health-gossip cells (default false).
    #[serde(default)]
    pub enabled: bool,
    /// Hex Ed25519 seed (32 bytes) for signing outbound adverts.
    #[serde(default)]
    pub signing_seed: Option<String>,
    /// Alternative path to a file containing the hex signing seed.
    #[serde(default)]
    pub signing_key_file: Option<String>,
    /// Seconds between gossip emission rounds (default 60).
    #[serde(default = "default_gossip_interval_secs")]
    pub interval_secs: u64,
    /// Distinct neighbor adverts required before merging (default 2). Set `1`
    /// for legacy immediate apply. Lightweight majority — not BFT.
    #[serde(default = "default_gossip_majority_k")]
    pub majority_k: usize,
    /// Optional path for the BFT-lite quorum append log (see `docs/ops/health_gossip.md`).
    #[serde(default)]
    pub quorum_log_path: Option<String>,
}

fn default_gossip_interval_secs() -> u64 {
    60
}

fn default_gossip_majority_k() -> usize {
    aegis_relay::DEFAULT_GOSSIP_MAJORITY_K
}

impl Default for HealthGossipConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            signing_seed: None,
            signing_key_file: None,
            interval_secs: default_gossip_interval_secs(),
            majority_k: default_gossip_majority_k(),
            quorum_log_path: None,
        }
    }
}

impl HealthGossipConfig {
    /// Resolve the optional gossip signing key.
    pub fn resolve_signing_key(&self) -> Result<Option<SigningKey>, ReputationError> {
        if let Some(ref hex) = self.signing_seed {
            Ok(Some(signing_key_from_hex_seed(hex)?))
        } else if let Some(ref path_str) = self.signing_key_file {
            let text = fs::read_to_string(path_str)?;
            Ok(Some(signing_key_from_hex_seed(text.trim())?))
        } else {
            Ok(None)
        }
    }
}

/// Exit delivery for terminal Sphinx peels (`deliver_to` and/or `log_payloads`).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitConfig {
    /// Log peeled payload size + hex preview to stderr when true.
    #[serde(default)]
    pub log_payloads: bool,
    /// `"stdout"` or `"file:path"` — off when omitted.
    #[serde(default)]
    pub deliver_to: Option<String>,
}

impl ExitConfig {
    pub fn into_settings(self) -> Result<crate::exit_sink::ExitSinkSettings, ConfigError> {
        Ok(crate::exit_sink::ExitSinkSettings {
            log_payloads: self.log_payloads,
            deliver_to: self
                .deliver_to
                .map(|s| parse_exit_deliver_to(&s))
                .transpose()?,
        })
    }
}

/// Relay-side post-shaping forward trace file.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceConfig {
    /// Append `(timestamp, cell_count, event_type)` rows here when set.
    #[serde(default)]
    pub path: Option<String>,
}

fn parse_exit_deliver_to(s: &str) -> Result<crate::exit_sink::ExitDeliverTarget, ConfigError> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("stdout") {
        return Ok(crate::exit_sink::ExitDeliverTarget::Stdout);
    }
    if let Some(path) = s.strip_prefix("file:") {
        let path = path.trim();
        if path.is_empty() {
            return Err(ConfigError::Hex("exit.deliver_to file: requires a path"));
        }
        return Ok(crate::exit_sink::ExitDeliverTarget::File(path.into()));
    }
    Err(ConfigError::Hex(
        "exit.deliver_to must be \"stdout\" or \"file:path\"",
    ))
}

/// Parsed runtime configuration for one relay process.
pub struct NodeRuntimeConfig {
    pub relay_id: RelayId,
    pub listen: SocketAddr,
    pub relay_config: RelayConfig,
    pub kem_secret: RelayKemSecret,
    /// Local roster KEM commitment for inbound handshake MAC binding (when configured).
    pub local_kem_commitment: Option<[u8; 32]>,
    pub ingress_link_key: Option<[u8; 32]>,
    pub peer_table: HashMap<RelayId, PeerInfo>,
    pub link_bridge_config: LinkBridgeConfig,
    pub exit: ExitConfig,
    pub trace: TraceConfig,
    /// Verified (or explicitly lab-unverified) roster when `[roster]` is configured.
    pub roster: Option<RelayRoster>,
    pub reputation: ReputationConfig,
    pub health_gossip: HealthGossipConfig,
}

impl NodeConfigFile {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }

    /// Load or create KEM seeds on disk when absent.
    ///
    /// Default (production): writes seeds to a separate file beside the config and
    /// stores only `[kem] file = "..."` in the TOML. Set `[kem] allow_plaintext_kem = true`
    /// to persist inline hex seeds in the main config (lab/test).
    pub fn load_or_init_kem(
        path: &Path,
        file: &mut Self,
        rng: &mut (impl RngCore + CryptoRngCore),
    ) -> Result<(), ConfigError> {
        if file.kem.is_none() {
            file.kem = Some(KemFileConfig::default());
        }
        let relay_id_hex = file.relay_id.clone();
        let kem_cfg = file.kem.as_mut().expect("kem section just initialized");
        if resolve_kem_seeds(path, kem_cfg).is_ok() {
            return Ok(());
        }

        let seeds = generate_kem_seeds(rng);
        if kem_cfg.allow_plaintext_kem {
            kem_cfg.x25519_seed = Some(seeds.x25519_seed.clone());
            kem_cfg.mlkem_d = Some(seeds.mlkem_d.clone());
            kem_cfg.mlkem_z = Some(seeds.mlkem_z.clone());
            let text = toml::to_string_pretty(file)?;
            fs::write(path, text)?;
            eprintln!(
                "generated and persisted KEM seeds inline in {} (allow_plaintext_kem=true)",
                path.display()
            );
        } else {
            let seed_path = kem_seed_file_path(path, kem_cfg);
            let account =
                crate::kem_seed_protect::kem_keyring_account(path, Some(relay_id_hex.as_str()));
            persist_kem_seeds_file_with_account(&seed_path, &seeds, &account)?;
            if kem_cfg.file.is_none() {
                kem_cfg.file = Some(DEFAULT_KEM_SEED_FILENAME.to_string());
            }
            kem_cfg.x25519_seed = None;
            kem_cfg.mlkem_d = None;
            kem_cfg.mlkem_z = None;
            let text = toml::to_string_pretty(file)?;
            fs::write(path, text)?;
            eprintln!(
                "generated and persisted KEM seeds to {} (referenced from {})",
                seed_path.display(),
                path.display()
            );
        }
        Ok(())
    }

    pub fn into_runtime(self, config_path: &Path) -> Result<NodeRuntimeConfig, ConfigError> {
        let relay_id = RelayId(parse_hex32(&self.relay_id)?);
        let listen: SocketAddr = self
            .listen
            .parse()
            .map_err(|_| ConfigError::Hex("listen address"))?;
        let kem_cfg = self.kem.as_ref().ok_or(ConfigError::MissingKem)?;
        let kem = resolve_kem_seeds(config_path, kem_cfg)?;
        let kem_secret = {
            let x = parse_hex32(&kem.x25519_seed)?;
            let d = parse_hex32(&kem.mlkem_d)?;
            let z = parse_hex32(&kem.mlkem_z)?;
            RelayKemSecret::generate_deterministic(x, d, z).0
        };
        let mut ingress_rate_limit = IngressRateLimitConfig {
            max_cells_per_sec: self.link.max_cells_per_sec,
            burst: self.link.burst,
            global_max_cells_per_sec: self.link.global_max_cells_per_sec,
        };
        let ingress_link_key = match self.ingress {
            Some(i) => {
                if let Some(rate) = i.max_cells_per_sec {
                    ingress_rate_limit.max_cells_per_sec = rate;
                }
                if let Some(burst) = i.burst {
                    ingress_rate_limit.burst = burst;
                }
                if i.global_max_cells_per_sec.is_some() {
                    ingress_rate_limit.global_max_cells_per_sec = i.global_max_cells_per_sec;
                }
                Some(parse_hex32(&i.link_key)?)
            }
            None => None,
        };
        let local_kem_commitment = self
            .kem_commitment
            .as_deref()
            .map(parse_hex32)
            .transpose()?;
        let mut peer_table = HashMap::new();
        for peer in self.peers {
            let id = RelayId(parse_hex32(&peer.id)?);
            let addr: SocketAddr = peer
                .addr
                .parse()
                .map_err(|_| ConfigError::Hex("peer addr"))?;
            let link_key_bytes = parse_hex32(&peer.link_key)?;
            let mut info = PeerInfo::new(addr, link_key_bytes);
            if let Some(ref hex) = peer.kem_commitment {
                info = info.with_kem_commitment(parse_hex32(hex)?);
            }
            if let Some(ref hex) = peer.gossip_verifying_key {
                info = info.with_gossip_verifying_key(parse_hex32(hex)?);
            }
            if let Some(ref hex) = peer.noise_static_public {
                info = info.with_noise_static_public(parse_hex32(hex)?);
            }
            peer_table.insert(id, info);
        }
        let roster = self
            .roster
            .as_ref()
            .map(load_roster_from_config)
            .transpose()?;
        let handshake = parse_link_handshake_mode(&self.link.handshake)?;
        let noise_static_secret = self
            .link
            .noise_static_secret
            .as_deref()
            .map(parse_hex32)
            .transpose()?;
        let ingress_noise_static_public = self
            .link
            .ingress_noise_static_public
            .as_deref()
            .map(parse_hex32)
            .transpose()?;
        #[cfg(feature = "noise-link")]
        if matches!(handshake, LinkHandshakeMode::Noise) && noise_static_secret.is_none() {
            return Err(ConfigError::Hex(
                "link.noise_static_secret required when handshake = \"noise\"",
            ));
        }
        Ok(NodeRuntimeConfig {
            relay_id,
            listen,
            relay_config: RelayConfig::new(self.mu).with_bulk_cover(self.cover.into_bulk_cover()),
            kem_secret,
            local_kem_commitment,
            ingress_link_key,
            peer_table,
            link_bridge_config: LinkBridgeConfig {
                read_timeout: std::time::Duration::from_secs(self.link.read_timeout_secs),
                max_inbound_connections: self.link.max_inbound_connections,
                identity_binding: self.link.identity_binding,
                handshake,
                noise_static_secret,
                ingress_noise_static_public,
                ingress_rate_limit,
                ..LinkBridgeConfig::default()
            },
            exit: self.exit,
            trace: self.trace,
            roster,
            reputation: self.reputation,
            health_gossip: self.health_gossip,
        })
    }
}

/// Load a roster JSON file using production verification policy.
pub fn load_roster_from_config(cfg: &RosterFileConfig) -> Result<RelayRoster, ConfigError> {
    let path = PathBuf::from(&cfg.path);
    let consortium = if cfg.authority_pubkeys.is_empty() {
        None
    } else {
        let mut keys = Vec::with_capacity(cfg.authority_pubkeys.len());
        for hex in &cfg.authority_pubkeys {
            keys.push(parse_hex32(hex)?);
        }
        Some(ThresholdConsortium::from_raw_pubkeys(cfg.threshold, &keys)?)
    };
    Ok(RelayRoster::load_from_file_with_policy(
        &path,
        consortium.as_ref(),
        cfg.allow_unverified_roster,
    )?)
}

fn parse_link_handshake_mode(s: &str) -> Result<LinkHandshakeMode, ConfigError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "legacy_psk" | "legacy" | "psk" => Ok(LinkHandshakeMode::LegacyPsk),
        #[cfg(feature = "noise-link")]
        "auto" => Ok(LinkHandshakeMode::Auto),
        #[cfg(feature = "noise-link")]
        "noise" | "noise_ik" => Ok(LinkHandshakeMode::Noise),
        #[cfg(not(feature = "noise-link"))]
        "auto" | "noise" | "noise_ik" => Err(ConfigError::Hex(
            "handshake = \"auto\"/\"noise\" requires the noise-link feature",
        )),
        _ => Err(ConfigError::Hex(
            "link.handshake must be \"auto\", \"legacy_psk\", or \"noise\"",
        )),
    }
}

pub fn parse_hex32(s: &str) -> Result<[u8; 32], ConfigError> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() != 64 {
        return Err(ConfigError::Hex("expected 64 hex chars for 32 bytes"));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        if chunk.len() != 2 {
            return Err(ConfigError::Hex("odd hex length"));
        }
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, ConfigError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(ConfigError::Hex("invalid hex digit")),
    }
}

pub fn hex_encode(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_topology::{
        test_relay_record, ConsortiumKey, RelayRoster, RosterAdmissionPolicy, RosterError,
    };
    use aegis_trust::reputation::ReputationLedger;
    use rand_core::OsRng;

    #[test]
    fn cover_defaults_are_production_fail_closed() {
        let cfg = CoverFileConfig::default();
        assert!(cfg.enabled);
        assert!(cfg.require);
        assert_eq!(cfg.target_flow_count, DEFAULT_COVER_TARGET_FLOW_COUNT);
        let bulk = cfg.into_bulk_cover();
        assert!(bulk.validate_spawn(true).is_ok());
        assert!(bulk.validate_spawn(false).is_err());
    }

    #[test]
    fn link_handshake_defaults_to_auto_and_parses_modes() {
        assert_eq!(default_link_handshake(), "auto");
        assert_eq!(
            parse_link_handshake_mode("auto").unwrap(),
            LinkHandshakeMode::Auto
        );
        assert_eq!(
            parse_link_handshake_mode("legacy_psk").unwrap(),
            LinkHandshakeMode::LegacyPsk
        );
        assert_eq!(
            parse_link_handshake_mode("noise").unwrap(),
            LinkHandshakeMode::Noise
        );
        let file: NodeConfigFile = toml::from_str(
            r#"
relay_id = "0100000000000000000000000000000000000000000000000000000000000000"
listen = "127.0.0.1:9000"
"#,
        )
        .unwrap();
        assert_eq!(file.link.handshake, "auto");
    }

    #[test]
    fn link_handshake_noise_requires_static_secret() {
        let dir = test_config_dir("noise-requires-secret");
        let _ = std::fs::create_dir_all(&dir);
        let config_path = dir.join("node.toml");
        let seeds = fixed_seeds();
        std::fs::write(
            &config_path,
            format!(
                r#"
relay_id = "0100000000000000000000000000000000000000000000000000000000000000"
listen = "127.0.0.1:9000"

[kem]
allow_plaintext_kem = true
x25519_seed = "{}"
mlkem_d = "{}"
mlkem_z = "{}"

[link]
handshake = "noise"
"#,
                seeds.x25519_seed, seeds.mlkem_d, seeds.mlkem_z
            ),
        )
        .unwrap();
        let file = NodeConfigFile::load(&config_path).unwrap();
        match file.into_runtime(&config_path) {
            Err(ConfigError::Hex(msg)) if msg.contains("noise_static_secret") => {}
            Ok(_) => panic!("expected noise_static_secret ConfigError::Hex, got Ok"),
            Err(e) => panic!("expected noise_static_secret ConfigError::Hex, got {e}"),
        }
        let _ = std::fs::remove_file(&config_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn reputation_config_parses_ledger_path() {
        let toml = r#"
relay_id = "0100000000000000000000000000000000000000000000000000000000000000"
listen = "127.0.0.1:9000"

[reputation]
ledger_path = "data/reputation.json"
nullifier_registry_path = "data/nullifiers.json"
"#;
        let file: NodeConfigFile = toml::from_str(toml).unwrap();
        assert_eq!(
            file.reputation.ledger_path.as_deref(),
            Some("data/reputation.json")
        );
        assert_eq!(
            file.reputation.nullifier_registry_path.as_deref(),
            Some("data/nullifiers.json")
        );
        assert!(file.reputation.operator_signing_seed.is_none());
        assert!(file.reputation.operator_verifying_key.is_none());
    }

    #[test]
    fn reputation_nullifier_registry_load_save_roundtrip() {
        use aegis_trust::derive_reputation_nullifier;

        let dir = std::env::temp_dir().join(format!(
            "aegis-node-nullifier-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("nullifiers.json");

        let cfg = ReputationConfig {
            nullifier_registry_path: Some(path.to_string_lossy().into()),
            ..Default::default()
        };
        let mut reg = cfg.load_nullifier_registry().unwrap();
        let n = derive_reputation_nullifier(&[5u8; 32], 3, &[6u8; 32]);
        reg.try_register(3, n).unwrap();
        cfg.save_nullifier_registry(&reg);

        let reloaded = cfg.load_nullifier_registry().unwrap();
        assert!(reloaded.is_spent(3, &n));
        assert!(matches!(
            {
                let mut r = reloaded;
                r.try_register(3, n)
            },
            Err(_)
        ));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn health_gossip_config_parses() {
        let seed = "cc".repeat(32);
        let vk = "dd".repeat(32);
        let toml = format!(
            r#"
relay_id = "0100000000000000000000000000000000000000000000000000000000000000"
listen = "127.0.0.1:9000"

[health_gossip]
enabled = true
signing_seed = "{seed}"
interval_secs = 45
majority_k = 3

[[peers]]
id = "0200000000000000000000000000000000000000000000000000000000000000"
addr = "127.0.0.1:9001"
link_key = "ee00000000000000000000000000000000000000000000000000000000000000"
gossip_verifying_key = "{vk}"
"#
        );
        let file: NodeConfigFile = toml::from_str(&toml).unwrap();
        assert!(file.health_gossip.enabled);
        assert_eq!(file.health_gossip.interval_secs, 45);
        assert_eq!(file.health_gossip.majority_k, 3);
        assert!(file.health_gossip.resolve_signing_key().unwrap().is_some());
        assert_eq!(
            file.peers[0].gossip_verifying_key.as_deref(),
            Some(vk.as_str())
        );
    }

    #[test]
    fn reputation_config_parses_operator_keys() {
        let seed = "aa".repeat(32);
        let toml = format!(
            r#"
relay_id = "0100000000000000000000000000000000000000000000000000000000000000"
listen = "127.0.0.1:9000"

[reputation]
ledger_path = "data/reputation.json"
operator_signing_seed = "{seed}"
"#
        );
        let file: NodeConfigFile = toml::from_str(&toml).unwrap();
        let (sk, vk) = file.reputation.resolve_operator_keys().unwrap();
        assert!(sk.is_some());
        assert!(vk.is_some());
        assert_eq!(
            sk.unwrap().verifying_key().to_bytes(),
            vk.unwrap().to_bytes()
        );
    }

    #[test]
    fn reputation_config_load_and_save_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "aegis-node-rep-ledger-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ledger.json");

        let cfg = ReputationConfig {
            ledger_path: Some(path.to_string_lossy().into()),
            ..Default::default()
        };
        let mut policy = cfg.load_pruning_policy().unwrap();
        policy.ledger_mut().admit_new_relay([7u8; 32]);
        for _ in 0..20 {
            policy.ledger_mut().record_success([7u8; 32]);
        }
        cfg.save_ledger(&policy);

        let reloaded = cfg.load_pruning_policy().unwrap();
        assert!(reloaded.ledger().score([7u8; 32]).0 > 0.3);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn reputation_config_signed_roundtrip_and_rejects_tamper() {
        let dir = std::env::temp_dir().join(format!(
            "aegis-node-rep-signed-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ledger.json");
        let seed = "bb".repeat(32);

        let cfg = ReputationConfig {
            ledger_path: Some(path.to_string_lossy().into()),
            operator_signing_seed: Some(seed),
            ..Default::default()
        };
        let mut policy = cfg.load_pruning_policy().unwrap();
        policy.ledger_mut().admit_new_relay([9u8; 32]);
        for _ in 0..15 {
            policy.ledger_mut().record_success([9u8; 32]);
        }
        cfg.save_ledger(&policy);

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("signature"));

        let reloaded = cfg.load_pruning_policy().unwrap();
        assert!(reloaded.ledger().score([9u8; 32]).0 > 0.3);

        // Tamper scores while keeping the old signature → verified load fails, fresh policy.
        let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
        if let Some(scores) = value.get_mut("scores").and_then(|s| s.as_object_mut()) {
            for (_k, v) in scores.iter_mut() {
                *v = serde_json::json!(0.01);
            }
        }
        std::fs::write(&path, serde_json::to_string_pretty(&value).unwrap()).unwrap();
        let after_tamper = cfg.load_pruning_policy().unwrap();
        // Fresh ledger: unseen relay is NEUTRAL 0.5, not the tampered 0.01 and not the prior score.
        assert!((after_tamper.ledger().score([9u8; 32]).0 - 0.5).abs() < 1e-9);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn roster_config_requires_keys_or_lab_flag() {
        let dir = std::env::temp_dir().join(format!(
            "aegis-node-roster-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("roster.json");
        RelayRoster::new().save_to_file(&path).unwrap();

        let cfg = RosterFileConfig {
            path: path.to_string_lossy().into(),
            authority_pubkeys: vec![],
            threshold: 1,
            allow_unverified_roster: false,
        };
        let err = load_roster_from_config(&cfg).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Roster(RosterError::UnverifiedRosterNotAllowed)
        ));

        let lab = RosterFileConfig {
            allow_unverified_roster: true,
            ..cfg
        };
        assert!(load_roster_from_config(&lab).is_ok());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn roster_config_verifies_with_authority_key() {
        let mut rng = OsRng;
        let authority = ConsortiumKey::generate(&mut rng);
        let pk = authority.verifying_key();

        let mut roster =
            RelayRoster::with_admission_policy(RosterAdmissionPolicy::permissive_for_tests());
        let mut ledger = ReputationLedger::new(0.9).unwrap();
        roster
            .admit_signed(
                authority.sign_record(&test_relay_record(3, "DE")),
                &pk,
                &mut ledger,
            )
            .unwrap();

        let dir = std::env::temp_dir().join(format!(
            "aegis-node-roster-ok-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("roster.json");
        roster.save_to_file(&path).unwrap();

        let cfg = RosterFileConfig {
            path: path.to_string_lossy().into(),
            authority_pubkeys: vec![hex_encode(&pk.to_bytes())],
            threshold: 1,
            allow_unverified_roster: false,
        };
        let loaded = load_roster_from_config(&cfg).expect("verified");
        assert_eq!(loaded.len(), 1);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    fn test_config_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("aegis-node-kem-{tag}-{}", std::process::id()))
    }

    fn minimal_node_toml(kem_section: &str) -> String {
        format!(
            r#"relay_id = "0100000000000000000000000000000000000000000000000000000000000000"
listen = "127.0.0.1:9000"
{kem_section}"#
        )
    }

    fn fixed_seeds() -> KemSeeds {
        KemSeeds {
            x25519_seed: hex_encode(&[0x11; 32]),
            mlkem_d: hex_encode(&[0x22; 32]),
            mlkem_z: hex_encode(&[0x33; 32]),
        }
    }

    #[test]
    fn kem_first_run_writes_external_file_by_default() {
        let dir = test_config_dir("external-default");
        let _ = std::fs::create_dir_all(&dir);
        let config_path = dir.join("node.toml");
        std::fs::write(&config_path, minimal_node_toml("")).unwrap();

        let mut file = NodeConfigFile::load(&config_path).unwrap();
        NodeConfigFile::load_or_init_kem(&config_path, &mut file, &mut OsRng).unwrap();

        let seed_path = dir.join(DEFAULT_KEM_SEED_FILENAME);
        assert!(seed_path.is_file(), "expected external kem.seeds");
        let reloaded = NodeConfigFile::load(&config_path).unwrap();
        let kem = reloaded.kem.as_ref().unwrap();
        assert_eq!(kem.file.as_deref(), Some(DEFAULT_KEM_SEED_FILENAME));
        assert!(!kem.allow_plaintext_kem);
        assert!(kem.x25519_seed.is_none());
        assert!(kem.mlkem_d.is_none());
        assert!(kem.mlkem_z.is_none());
        assert!(resolve_kem_seeds(&config_path, kem).is_ok());
        reloaded.into_runtime(&config_path).unwrap();

        let _ = std::fs::remove_file(&seed_path);
        let _ = std::fs::remove_file(&config_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn kem_inline_when_allow_plaintext_kem() {
        let dir = test_config_dir("inline-opt-in");
        let _ = std::fs::create_dir_all(&dir);
        let config_path = dir.join("node.toml");
        std::fs::write(
            &config_path,
            minimal_node_toml("[kem]\nallow_plaintext_kem = true\n"),
        )
        .unwrap();

        let mut file = NodeConfigFile::load(&config_path).unwrap();
        NodeConfigFile::load_or_init_kem(&config_path, &mut file, &mut OsRng).unwrap();

        let reloaded = NodeConfigFile::load(&config_path).unwrap();
        let kem = reloaded.kem.as_ref().unwrap();
        assert!(kem.allow_plaintext_kem);
        assert!(kem.has_complete_inline());
        assert!(!dir.join(DEFAULT_KEM_SEED_FILENAME).exists());
        reloaded.into_runtime(&config_path).unwrap();

        let _ = std::fs::remove_file(&config_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn kem_load_from_external_file_with_custom_path() {
        let dir = test_config_dir("custom-file");
        let _ = std::fs::create_dir_all(&dir);
        let config_path = dir.join("node.toml");
        let seed_path = dir.join("secrets").join("relay.kem");
        persist_kem_seeds_file(&seed_path, &fixed_seeds()).unwrap();

        std::fs::write(
            &config_path,
            minimal_node_toml(r#"[kem]
file = "secrets/relay.kem"
"#),
        )
        .unwrap();

        let file = NodeConfigFile::load(&config_path).unwrap();
        let kem = file.kem.as_ref().unwrap();
        let loaded = resolve_kem_seeds(&config_path, kem).unwrap();
        assert_eq!(loaded, fixed_seeds());
        file.into_runtime(&config_path).unwrap();

        let _ = std::fs::remove_file(&seed_path);
        let _ = std::fs::remove_dir(dir.join("secrets"));
        let _ = std::fs::remove_file(&config_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn kem_legacy_inline_still_loads() {
        let dir = test_config_dir("legacy-inline");
        let _ = std::fs::create_dir_all(&dir);
        let config_path = dir.join("node.toml");
        let seeds = fixed_seeds();
        std::fs::write(
            &config_path,
            minimal_node_toml(&format!(
                r#"[kem]
x25519_seed = "{}"
mlkem_d = "{}"
mlkem_z = "{}"
"#,
                seeds.x25519_seed, seeds.mlkem_d, seeds.mlkem_z
            )),
        )
        .unwrap();

        let file = NodeConfigFile::load(&config_path).unwrap();
        let kem = file.kem.as_ref().unwrap();
        assert_eq!(resolve_kem_seeds(&config_path, kem).unwrap(), seeds);
        file.into_runtime(&config_path).unwrap();

        let _ = std::fs::remove_file(&config_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn kem_incomplete_inline_is_rejected() {
        let kem = KemFileConfig {
            x25519_seed: Some(hex_encode(&[1; 32])),
            mlkem_d: None,
            mlkem_z: None,
            ..KemFileConfig::default()
        };
        let err = resolve_kem_seeds(Path::new("/tmp/unused.toml"), &kem).unwrap_err();
        assert!(matches!(err, ConfigError::IncompleteKem));
    }

    #[test]
    fn kem_load_or_init_is_idempotent() {
        let dir = test_config_dir("idempotent");
        let _ = std::fs::create_dir_all(&dir);
        let config_path = dir.join("node.toml");
        std::fs::write(&config_path, minimal_node_toml("")).unwrap();

        let mut file = NodeConfigFile::load(&config_path).unwrap();
        NodeConfigFile::load_or_init_kem(&config_path, &mut file, &mut OsRng).unwrap();
        let first = resolve_kem_seeds(
            &config_path,
            file.kem.as_ref().unwrap(),
        )
        .unwrap();

        NodeConfigFile::load_or_init_kem(&config_path, &mut file, &mut OsRng).unwrap();
        let second = resolve_kem_seeds(
            &config_path,
            file.kem.as_ref().unwrap(),
        )
        .unwrap();
        assert_eq!(first, second);

        let _ = std::fs::remove_file(dir.join(DEFAULT_KEM_SEED_FILENAME));
        let _ = std::fs::remove_file(&config_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn kem_external_file_has_restrictive_mode_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_config_dir("unix-mode");
        let _ = std::fs::create_dir_all(&dir);
        let seed_path = dir.join("kem.seeds");
        persist_kem_seeds_file(&seed_path, &fixed_seeds()).unwrap();
        let mode = std::fs::metadata(&seed_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let _ = std::fs::remove_file(&seed_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn kem_resolve_rejects_group_world_readable_seed_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_config_dir("unix-loose-mode");
        let _ = std::fs::create_dir_all(&dir);
        let config_path = dir.join("node.toml");
        let seed_path = dir.join(DEFAULT_KEM_SEED_FILENAME);
        let seeds = fixed_seeds();
        std::fs::write(&seed_path, toml::to_string(&seeds).unwrap()).unwrap();
        let mut perms = std::fs::metadata(&seed_path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&seed_path, perms).unwrap();
        std::fs::write(
            &config_path,
            minimal_node_toml(&format!(
                "[kem]\nfile = \"{DEFAULT_KEM_SEED_FILENAME}\"\n"
            )),
        )
        .unwrap();

        let file = NodeConfigFile::load(&config_path).unwrap();
        let err = resolve_kem_seeds(&config_path, file.kem.as_ref().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::KemProtect(_)));
        assert!(err.to_string().contains("insecure mode"));

        let _ = std::fs::remove_file(&seed_path);
        let _ = std::fs::remove_file(&config_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn kem_legacy_plaintext_seed_file_still_loads() {
        let dir = test_config_dir("legacy-plain-file");
        let _ = std::fs::create_dir_all(&dir);
        let config_path = dir.join("node.toml");
        let seed_path = dir.join(DEFAULT_KEM_SEED_FILENAME);
        let seeds = fixed_seeds();
        // Intentionally write raw TOML (no DPAPI magic) — pre-DPAPI format.
        std::fs::write(&seed_path, toml::to_string(&seeds).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&seed_path).unwrap().permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&seed_path, perms).unwrap();
        }
        std::fs::write(
            &config_path,
            minimal_node_toml(&format!(
                "[kem]\nfile = \"{DEFAULT_KEM_SEED_FILENAME}\"\n"
            )),
        )
        .unwrap();

        let file = NodeConfigFile::load(&config_path).unwrap();
        let loaded = resolve_kem_seeds(&config_path, file.kem.as_ref().unwrap()).unwrap();
        assert_eq!(loaded, seeds);
        assert!(!crate::kem_seed_protect::is_dpapi_protected(
            &std::fs::read(&seed_path).unwrap()
        ));
        file.into_runtime(&config_path).unwrap();

        let _ = std::fs::remove_file(&seed_path);
        let _ = std::fs::remove_file(&config_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn kem_persist_roundtrip_via_protect_layer() {
        let dir = test_config_dir("persist-roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let seed_path = dir.join("kem.seeds");
        let seeds = fixed_seeds();
        persist_kem_seeds_file(&seed_path, &seeds).unwrap();
        let raw = std::fs::read(&seed_path).unwrap();
        #[cfg(all(windows, feature = "kem-dpapi"))]
        {
            assert!(crate::kem_seed_protect::is_dpapi_protected(&raw));
        }
        #[cfg(not(all(windows, feature = "kem-dpapi")))]
        {
            assert!(!crate::kem_seed_protect::is_dpapi_protected(&raw));
        }
        let kem = KemFileConfig {
            file: Some("kem.seeds".into()),
            ..KemFileConfig::default()
        };
        let config_path = dir.join("node.toml");
        assert_eq!(resolve_kem_seeds(&config_path, &kem).unwrap(), seeds);

        let _ = std::fs::remove_file(&seed_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[cfg(all(windows, feature = "kem-dpapi"))]
    #[test]
    fn kem_first_run_writes_dpapi_protected_file_on_windows() {
        let dir = test_config_dir("win-dpapi-default");
        let _ = std::fs::create_dir_all(&dir);
        let config_path = dir.join("node.toml");
        std::fs::write(&config_path, minimal_node_toml("")).unwrap();

        let mut file = NodeConfigFile::load(&config_path).unwrap();
        NodeConfigFile::load_or_init_kem(&config_path, &mut file, &mut OsRng).unwrap();

        let seed_path = dir.join(DEFAULT_KEM_SEED_FILENAME);
        let raw = std::fs::read(&seed_path).unwrap();
        assert!(
            crate::kem_seed_protect::is_dpapi_protected(&raw),
            "first-run should write DPAPI-protected kem.seeds"
        );
        assert!(resolve_kem_seeds(&config_path, file.kem.as_ref().unwrap()).is_ok());

        let _ = std::fs::remove_file(&seed_path);
        let _ = std::fs::remove_file(&config_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn link_and_ingress_toml_wire_ingress_rate_limit() {
        let dir = test_config_dir("ingress-rate");
        let _ = std::fs::create_dir_all(&dir);
        let config_path = dir.join("node.toml");
        let seeds = fixed_seeds();
        let seed_path = dir.join(DEFAULT_KEM_SEED_FILENAME);
        persist_kem_seeds_file(&seed_path, &seeds).unwrap();
        let toml = format!(
            r#"relay_id = "0100000000000000000000000000000000000000000000000000000000000000"
listen = "127.0.0.1:9000"

[kem]
file = "{}"

[link]
max_cells_per_sec = 5.0
burst = 8
global_max_cells_per_sec = 20.0

[ingress]
link_key = "c000000000000000000000000000000000000000000000000000000000000000"
max_cells_per_sec = 3.0
burst = 2
"#,
            DEFAULT_KEM_SEED_FILENAME
        );
        std::fs::write(&config_path, toml).unwrap();
        let file = NodeConfigFile::load(&config_path).unwrap();
        let runtime = file.into_runtime(&config_path).unwrap();
        let rl = &runtime.link_bridge_config.ingress_rate_limit;
        assert!((rl.max_cells_per_sec - 3.0).abs() < 1e-9, "ingress overrides link");
        assert_eq!(rl.burst, 2);
        assert_eq!(rl.global_max_cells_per_sec, Some(20.0));

        let _ = std::fs::remove_file(&seed_path);
        let _ = std::fs::remove_file(&config_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn link_rate_limit_defaults_match_mode1_tau() {
        let cfg = LinkNetConfig::default();
        assert!((cfg.max_cells_per_sec - DEFAULT_INGRESS_MAX_CELLS_PER_SEC).abs() < 1e-9);
        assert_eq!(cfg.burst, DEFAULT_INGRESS_BURST);
        assert_eq!(
            cfg.global_max_cells_per_sec,
            Some(DEFAULT_GLOBAL_MAX_CELLS_PER_SEC)
        );
    }
}
