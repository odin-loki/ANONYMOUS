//! Client TOML configuration types.

use aegis_topology::GuardMitigationFileConfig;
use serde::Deserialize;

use crate::roster_load::RosterFileConfig;

/// Parsed client config file (subset used by the CLI and path builders).
#[derive(Debug, Deserialize)]
pub struct ClientConfigFile {
    pub first_hop_addr: String,
    pub ingress_link_key: String,
    #[serde(default)]
    pub payload: Option<String>,
    #[serde(default)]
    pub hops: Vec<HopConfig>,
    /// Optional permissioned roster; when set, loaded with consortium re-verify.
    #[serde(default)]
    pub roster: Option<RosterFileConfig>,
    /// Optional first-hop Noise link settings (production ingress).
    #[serde(default)]
    pub link: Option<ClientLinkFileConfig>,
    /// Optional adaptive guard mitigation (spec §13 first pass — default off).
    #[serde(default)]
    pub guard_mitigation: GuardMitigationFileConfig,
    /// Optional roster-path build parameters (ignored when explicit `[[hops]]` override).
    #[serde(default)]
    pub path: Option<PathFileConfig>,
}

/// Parameters for roster-driven bound-path construction.
#[derive(Clone, Debug, Deserialize, Default, PartialEq, Eq)]
pub struct PathFileConfig {
    /// Client seed for guard-set sampling (re-mixed when mitigation re-samples).
    #[serde(default)]
    pub client_seed: u64,
    /// Epoch id passed to topology builder.
    #[serde(default)]
    pub epoch: u64,
    /// Topology assignment seed for the epoch.
    #[serde(default)]
    pub topology_seed: u64,
    /// Mitigation signal: epochs since last guard re-sample.
    #[serde(default)]
    pub epoch_age: u64,
    /// Mitigation signal: operator/anomaly demotion flag.
    #[serde(default)]
    pub anomaly_demotion_flag: bool,
    /// Mitigation signal: peer health spike count.
    #[serde(default)]
    pub peer_anomaly_count: u32,
}

#[derive(Debug, Deserialize, Default)]
pub struct ClientLinkFileConfig {
    #[serde(default)]
    pub handshake: Option<String>,
    #[serde(default)]
    pub noise_static_secret: Option<String>,
    #[serde(default)]
    pub first_hop_noise_static_public: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HopConfig {
    pub id: String,
    pub kem_x25519_seed: String,
    pub kem_mlkem_d: String,
    pub kem_mlkem_z: String,
    /// Optional SHA3-256 hex commitment from the signed roster (64 hex chars).
    #[serde(default)]
    pub kem_commitment: Option<String>,
}

/// Load and parse a client TOML config file.
pub fn load_client_config(text: &str) -> Result<ClientConfigFile, toml::de::Error> {
    toml::from_str(text)
}

#[cfg(test)]
mod tests {
    use aegis_topology::{GuardMitigationFileConfig, GuardMitigationPolicy};

    use super::*;

    #[test]
    fn guard_mitigation_defaults_disabled() {
        let file: ClientConfigFile = toml::from_str(
            r#"
first_hop_addr = "127.0.0.1:9000"
ingress_link_key = "0000000000000000000000000000000000000000000000000000000000000001"
"#,
        )
        .unwrap();
        assert_eq!(file.guard_mitigation, GuardMitigationFileConfig::default());
        assert!(!file.guard_mitigation.adaptive_first);
        assert_eq!(
            file.guard_mitigation.resolve_policy(),
            GuardMitigationPolicy::disabled()
        );
    }

    #[test]
    fn guard_mitigation_adaptive_first_parses_and_resolves() {
        let file: ClientConfigFile = toml::from_str(
            r#"
first_hop_addr = "127.0.0.1:9000"
ingress_link_key = "0000000000000000000000000000000000000000000000000000000000000001"

[guard_mitigation]
adaptive_first = true
"#,
        )
        .unwrap();
        assert!(file.guard_mitigation.adaptive_first);
        assert_eq!(
            file.guard_mitigation.resolve_policy(),
            GuardMitigationPolicy::adaptive_first()
        );
    }

    #[test]
    fn guard_mitigation_preset_adaptive_v2_parses_and_resolves() {
        let file: ClientConfigFile = toml::from_str(
            r#"
first_hop_addr = "127.0.0.1:9000"
ingress_link_key = "0000000000000000000000000000000000000000000000000000000000000001"

[guard_mitigation]
preset = "adaptive_v2"
"#,
        )
        .unwrap();
        assert_eq!(file.guard_mitigation.preset.as_deref(), Some("adaptive_v2"));
        assert_eq!(
            file.guard_mitigation.resolve_policy(),
            GuardMitigationPolicy::adaptive_v2()
        );
    }

    #[test]
    fn guard_mitigation_preset_adaptive_v3_parses_and_resolves() {
        let file: ClientConfigFile = toml::from_str(
            r#"
first_hop_addr = "127.0.0.1:9000"
ingress_link_key = "0000000000000000000000000000000000000000000000000000000000000001"

[guard_mitigation]
preset = "adaptive_v3"
"#,
        )
        .unwrap();
        assert_eq!(file.guard_mitigation.preset.as_deref(), Some("adaptive_v3"));
        let policy = file.guard_mitigation.resolve_policy();
        assert_eq!(policy, GuardMitigationPolicy::adaptive_v3());
        assert!(policy.should_resample_guards(4, false, 0));
    }

    #[test]
    fn guard_mitigation_preset_adaptive_v4_parses_and_resolves() {
        let file: ClientConfigFile = toml::from_str(
            r#"
first_hop_addr = "127.0.0.1:9000"
ingress_link_key = "0000000000000000000000000000000000000000000000000000000000000001"

[guard_mitigation]
preset = "adaptive_v4"
"#,
        )
        .unwrap();
        assert_eq!(file.guard_mitigation.preset.as_deref(), Some("adaptive_v4"));
        let policy = file.guard_mitigation.resolve_policy();
        assert_eq!(policy, GuardMitigationPolicy::adaptive_v4());
        assert!(policy.should_resample_guards(2, false, 0));
        assert_eq!(policy.soft_sticky_epochs, 1);
    }

    #[test]
    fn path_epoch_age_parses_for_mitigation_signals() {
        let file: ClientConfigFile = toml::from_str(
            r#"
first_hop_addr = "127.0.0.1:9000"
ingress_link_key = "0000000000000000000000000000000000000000000000000000000000000001"

[path]
epoch_age = 7
"#,
        )
        .unwrap();
        let path = file.path.expect("path section");
        assert_eq!(path.epoch_age, 7);
    }
}
