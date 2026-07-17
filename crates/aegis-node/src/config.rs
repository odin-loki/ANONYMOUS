//! TOML node configuration: identity, KEM secret, listen address, peers.

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use aegis_crypto::kem::RelayKemSecret;
use aegis_negotiator::SecurityDial;
use aegis_relay::{
    BulkCoverConfig, LinkBridgeConfig, PeerInfo, RelayConfig, RelayId, DEFAULT_COVER_ROUND_SECS,
    DEFAULT_COVER_TARGET_FLOW_COUNT,
};
use aegis_topology::{RelayRoster, RosterError, ThresholdConsortium};
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
    #[error("missing kem seeds — generate with `aegis-node --config <path>` after first run persists them")]
    MissingKem,
    #[error("roster: {0}")]
    Roster(#[from] RosterError),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfigFile {
    pub relay_id: String,
    pub listen: String,
    #[serde(default = "default_mu")]
    pub mu: f64,
    #[serde(default)]
    pub kem: Option<KemSeeds>,
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
}

impl Default for LinkNetConfig {
    fn default() -> Self {
        Self {
            read_timeout_secs: default_link_read_timeout_secs(),
            max_inbound_connections: default_max_inbound_connections(),
            identity_binding: default_identity_binding(),
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

fn default_mu() -> f64 {
    aegis_relay::DEFAULT_MU
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KemSeeds {
    pub x25519_seed: String,
    pub mlkem_d: String,
    pub mlkem_z: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngressConfig {
    pub link_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerConfig {
    pub id: String,
    pub addr: String,
    pub link_key: String,
    /// Optional roster KEM public-key commitment (64 hex chars) for outbound handshake MAC binding.
    #[serde(default)]
    pub kem_commitment: Option<String>,
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
}

impl NodeConfigFile {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }

    /// Load or create KEM seeds on disk when absent.
    pub fn load_or_init_kem(
        path: &Path,
        file: &mut Self,
        rng: &mut (impl RngCore + CryptoRngCore),
    ) -> Result<(), ConfigError> {
        if file.kem.is_some() {
            return Ok(());
        }
        let mut x25519_seed = [0u8; 32];
        let mut mlkem_d = [0u8; 32];
        let mut mlkem_z = [0u8; 32];
        rng.fill_bytes(&mut x25519_seed);
        rng.fill_bytes(&mut mlkem_d);
        rng.fill_bytes(&mut mlkem_z);
        file.kem = Some(KemSeeds {
            x25519_seed: hex_encode(&x25519_seed),
            mlkem_d: hex_encode(&mlkem_d),
            mlkem_z: hex_encode(&mlkem_z),
        });
        let text = toml::to_string_pretty(file)?;
        fs::write(path, text)?;
        eprintln!("generated and persisted KEM seeds to {}", path.display());
        Ok(())
    }

    pub fn into_runtime(self) -> Result<NodeRuntimeConfig, ConfigError> {
        let relay_id = RelayId(parse_hex32(&self.relay_id)?);
        let listen: SocketAddr = self
            .listen
            .parse()
            .map_err(|_| ConfigError::Hex("listen address"))?;
        let kem = self.kem.ok_or(ConfigError::MissingKem)?;
        let kem_secret = {
            let x = parse_hex32(&kem.x25519_seed)?;
            let d = parse_hex32(&kem.mlkem_d)?;
            let z = parse_hex32(&kem.mlkem_z)?;
            RelayKemSecret::generate_deterministic(x, d, z).0
        };
        let ingress_link_key = self
            .ingress
            .map(|i| parse_hex32(&i.link_key))
            .transpose()?;
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
            peer_table.insert(id, info);
        }
        let roster = self
            .roster
            .as_ref()
            .map(load_roster_from_config)
            .transpose()?;
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
            },
            exit: self.exit,
            trace: self.trace,
            roster,
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
}
