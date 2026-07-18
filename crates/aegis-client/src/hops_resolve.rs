//! Resolve client hops: explicit `[[hops]]` (pilot/lab) or roster-driven bound path.

use std::collections::HashMap;

use aegis_crypto::kem::RelayKemPublic;
use aegis_topology::layers::build_topology;
use aegis_topology::types::{KemPublicCommitment, TopologyConfig};
use aegis_topology::{
    GuardConfig, GuardMitigationSignals, RelayRoster, TopologyError,
};
use aegis_trust::policy::{RelayPruningPolicy, DEFAULT_PATH_REPUTATION_FLOOR};

use crate::config::{ClientConfigFile, HopConfig, PathFileConfig};
use crate::path::{build_client_bound_path, ClientPathBuildParams};
use crate::roster_load::{load_roster_from_config, RosterLoadError};
use crate::send::{hops_from_bound_path, ClientHop, SendError};

#[derive(Debug, thiserror::Error)]
pub enum HopsResolveError {
    #[error("hex: {0}")]
    Hex(String),
    #[error("roster: {0}")]
    Roster(#[from] RosterLoadError),
    #[error("topology: {0}")]
    Topology(#[from] TopologyError),
    #[error("send: {0}")]
    Send(#[from] SendError),
    #[error("config must include at least one hop")]
    NoHops,
    #[error("roster path requires [roster] in config")]
    RosterRequired,
    #[error("roster path requires [[hops]] kem registry entries keyed by relay id (or use explicit [[hops]] path)")]
    KemRegistryRequired,
    #[error("no [[hops]] kem registry entry for relay {relay_id}")]
    MissingKemRegistryEntry { relay_id: String },
    #[error("kem_commitment: {0}")]
    KemCommitment(String),
}

/// When true, build a reputation-weighted bound path from roster + guard mitigation.
pub fn use_roster_path(file: &ClientConfigFile, force_roster_path: bool) -> bool {
    if !file.hops.is_empty() && !force_roster_path {
        return false;
    }
    file.roster.is_some() || file.hops.is_empty() || force_roster_path
}

/// Resolve hops for send: explicit ordered `[[hops]]` or roster-driven mitigated path.
pub fn resolve_client_hops(
    file: &ClientConfigFile,
    force_roster_path: bool,
) -> Result<Vec<ClientHop>, HopsResolveError> {
    if use_roster_path(file, force_roster_path) {
        resolve_roster_hops(file)
    } else {
        explicit_hops_from_config(&file.hops)
    }
}

fn resolve_roster_hops(file: &ClientConfigFile) -> Result<Vec<ClientHop>, HopsResolveError> {
    let roster_cfg = file.roster.as_ref().ok_or(HopsResolveError::RosterRequired)?;
    if file.hops.is_empty() {
        return Err(HopsResolveError::KemRegistryRequired);
    }
    let roster = load_roster_from_config(roster_cfg)?;

    let kem_registry = kem_registry_from_hops(&file.hops)?;
    let path_cfg = file.path.as_ref().cloned().unwrap_or_default();
    let records = build_roster_path_records(&roster, &path_cfg, file)?;
    let publics: Vec<RelayKemPublic> = records
        .iter()
        .map(|record| {
            kem_registry
                .get(record.id.as_bytes())
                .map(|hop| hop.kem_public.clone())
                .ok_or_else(|| HopsResolveError::MissingKemRegistryEntry {
                    relay_id: hex_encode(record.id.as_bytes()),
                })
        })
        .collect::<Result<_, _>>()?;

    hops_from_bound_path(&records, &publics, &HashMap::new()).map_err(HopsResolveError::Send)
}

fn build_roster_path_records(
    roster: &RelayRoster,
    path_cfg: &PathFileConfig,
    file: &ClientConfigFile,
) -> Result<Vec<aegis_topology::types::RelayRecord>, HopsResolveError> {
    let topo = build_topology(
        roster,
        path_cfg.epoch,
        &TopologyConfig::high_threat(),
        path_cfg.topology_seed,
    )?;
    let pruning = RelayPruningPolicy::new(0.9, 0.2, 3.0).map_err(|e| {
        HopsResolveError::Hex(format!("pruning policy: {e}"))
    })?;
    let params = ClientPathBuildParams {
        client_seed: path_cfg.client_seed,
        guard_config: GuardConfig::default(),
        mitigation: file.guard_mitigation.resolve_policy(),
        signals: GuardMitigationSignals {
            epoch_age: path_cfg.epoch_age,
            anomaly_demotion_flag: path_cfg.anomaly_demotion_flag,
            peer_anomaly_count: path_cfg.peer_anomaly_count,
        },
        min_reputation: DEFAULT_PATH_REPUTATION_FLOOR,
        max_attempts: 50,
    };
    let (_guards, records) = build_client_bound_path(&topo, roster, &pruning, &params)?;
    Ok(records)
}

fn kem_registry_from_hops(
    hops: &[HopConfig],
) -> Result<HashMap<[u8; 32], ClientHop>, HopsResolveError> {
    let mut registry = HashMap::new();
    for hop in hops {
        let client_hop = hop_config_to_client_hop(hop)?;
        if registry
            .insert(client_hop.id, client_hop)
            .is_some()
        {
            return Err(HopsResolveError::Hex(format!(
                "duplicate kem registry entry for relay {}",
                hop.id
            )));
        }
    }
    Ok(registry)
}

pub fn explicit_hops_from_config(hops: &[HopConfig]) -> Result<Vec<ClientHop>, HopsResolveError> {
    if hops.is_empty() {
        return Err(HopsResolveError::NoHops);
    }
    hops.iter().map(hop_config_to_client_hop).collect()
}

fn hop_config_to_client_hop(hop: &HopConfig) -> Result<ClientHop, HopsResolveError> {
    use aegis_crypto::kem::RelayKemSecret;

    let id = parse_hex32(&hop.id).map_err(HopsResolveError::Hex)?;
    let x = parse_hex32(&hop.kem_x25519_seed).map_err(HopsResolveError::Hex)?;
    let d = parse_hex32(&hop.kem_mlkem_d).map_err(HopsResolveError::Hex)?;
    let z = parse_hex32(&hop.kem_mlkem_z).map_err(HopsResolveError::Hex)?;
    let (_sec, pk) = RelayKemSecret::generate_deterministic(x, d, z);
    let kem_commitment = hop
        .kem_commitment
        .as_deref()
        .map(parse_hex32)
        .transpose()
        .map_err(|e| HopsResolveError::KemCommitment(e))?
        .map(KemPublicCommitment);
    Ok(ClientHop {
        id,
        kem_public: pk,
        kem_commitment,
        addr: None,
    })
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() != 64 {
        return Err("expected 64 hex chars".into());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("invalid hex".into()),
    }
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use aegis_topology::types::{test_relay_id, test_relay_record};
    use aegis_topology::{GuardMitigationPolicy, GuardPinMode, GUARD_SET_SIZE};

    use super::*;

    fn test_hop_for_fixture(id: u64) -> HopConfig {
        let relay_id = test_relay_id(id);
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&id.to_le_bytes());
        let hex32 = |b: [u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        HopConfig {
            id: hex32(*relay_id.as_bytes()),
            kem_x25519_seed: hex32(seed),
            kem_mlkem_d: hex32(seed),
            kem_mlkem_z: hex32(seed),
            kem_commitment: None,
        }
    }

    fn pilot_hop(id_byte: u8) -> HopConfig {
        test_hop_for_fixture(id_byte as u64)
    }

    #[test]
    fn explicit_hops_override_roster_config() {
        let file = ClientConfigFile {
            first_hop_addr: "127.0.0.1:9000".into(),
            ingress_link_key: "0000000000000000000000000000000000000000000000000000000000000001".into(),
            payload: None,
            hops: vec![pilot_hop(1), pilot_hop(2)],
            roster: Some(crate::roster_load::RosterFileConfig {
                path: "roster.json".into(),
                authority_pubkeys: vec![],
                threshold: 1,
                allow_unverified_roster: true,
            }),
            link: None,
            guard_mitigation: Default::default(),
            path: None,
        };
        assert!(!use_roster_path(&file, false));
        let hops = resolve_client_hops(&file, false).unwrap();
        assert_eq!(hops.len(), 2);
    }

    #[test]
    fn roster_path_requires_kem_registry_when_hops_empty() {
        let file = ClientConfigFile {
            first_hop_addr: "127.0.0.1:9000".into(),
            ingress_link_key: "0000000000000000000000000000000000000000000000000000000000000001".into(),
            payload: None,
            hops: vec![],
            roster: Some(crate::roster_load::RosterFileConfig {
                path: "roster.json".into(),
                authority_pubkeys: vec![],
                threshold: 1,
                allow_unverified_roster: true,
            }),
            link: None,
            guard_mitigation: Default::default(),
            path: None,
        };
        assert!(use_roster_path(&file, false));
        assert!(matches!(
            resolve_client_hops(&file, false),
            Err(HopsResolveError::KemRegistryRequired)
        ));
    }

    #[test]
    fn roster_path_applies_guard_mitigation() {
        let mut roster = RelayRoster::new();
        for i in 0..24 {
            roster.admit_for_tests(test_relay_record(i + 1, "US"));
        }
        let dir = std::env::temp_dir().join(format!(
            "aegis-client-roster-path-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let roster_path = dir.join("roster.json");
        roster.save_to_file(&roster_path).unwrap();

        let mut kem_hops = Vec::new();
        for i in 1..=24u64 {
            kem_hops.push(test_hop_for_fixture(i));
        }

        let file = ClientConfigFile {
            first_hop_addr: "127.0.0.1:9000".into(),
            ingress_link_key: "0000000000000000000000000000000000000000000000000000000000000001".into(),
            payload: None,
            hops: kem_hops,
            roster: Some(crate::roster_load::RosterFileConfig {
                path: roster_path.to_string_lossy().into(),
                authority_pubkeys: vec![],
                threshold: 1,
                allow_unverified_roster: true,
            }),
            link: None,
            guard_mitigation: aegis_topology::GuardMitigationFileConfig {
                adaptive_first: true,
            },
            path: Some(PathFileConfig {
                client_seed: 99,
                anomaly_demotion_flag: true,
                ..PathFileConfig::default()
            }),
        };

        assert!(use_roster_path(&file, true));
        let hops = resolve_client_hops(&file, true).unwrap();
        assert_eq!(hops.len(), TopologyConfig::high_threat().layer_count);
        assert_eq!(
            file.guard_mitigation.resolve_policy(),
            GuardMitigationPolicy::adaptive_first()
        );

        let topo = build_topology(
            &roster,
            0,
            &TopologyConfig::high_threat(),
            0,
        )
        .unwrap();
        let pruning = RelayPruningPolicy::new(0.9, 0.2, 3.0).unwrap();
        let params = ClientPathBuildParams {
            client_seed: 99,
            mitigation: GuardMitigationPolicy::adaptive_first(),
            signals: GuardMitigationSignals {
                anomaly_demotion_flag: true,
                ..GuardMitigationSignals::default()
            },
            ..ClientPathBuildParams::default()
        };
        let (guards, _) =
            build_client_bound_path(&topo, &roster, &pruning, &params).unwrap();
        assert_eq!(guards.pin_mode, GuardPinMode::Rotate);
        assert_eq!(guards.guard_set().len(), GUARD_SET_SIZE as usize);

        let _ = std::fs::remove_file(&roster_path);
        let _ = std::fs::remove_dir(&dir);
    }
}
