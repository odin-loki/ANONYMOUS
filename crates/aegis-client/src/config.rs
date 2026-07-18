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
}
