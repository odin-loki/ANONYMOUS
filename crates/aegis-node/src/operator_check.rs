//! Production config validation for operators (`aegis-node validate`).

use std::fmt;
use std::path::Path;

use crate::config::{load_roster_from_config, NodeConfigFile};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckSeverity {
    Error,
    Warning,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigCheck {
    pub severity: CheckSeverity,
    pub field: &'static str,
    pub message: String,
}

#[derive(Clone, Debug, Default)]
pub struct ValidationReport {
    pub relay_id: Option<String>,
    pub listen: Option<String>,
    pub checks: Vec<ConfigCheck>,
}

impl ValidationReport {
    pub fn errors(&self) -> impl Iterator<Item = &ConfigCheck> {
        self.checks
            .iter()
            .filter(|c| c.severity == CheckSeverity::Error)
    }

    pub fn warnings(&self) -> impl Iterator<Item = &ConfigCheck> {
        self.checks
            .iter()
            .filter(|c| c.severity == CheckSeverity::Warning)
    }

    pub fn ok(&self) -> bool {
        self.errors().next().is_none()
    }
}

impl fmt::Display for ValidationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "aegis-node config validation")?;
        if let Some(ref id) = self.relay_id {
            writeln!(f, "  relay_id: {id}")?;
        }
        if let Some(ref listen) = self.listen {
            writeln!(f, "  listen: {listen}")?;
        }
        let err_count = self.checks.iter().filter(|c| c.severity == CheckSeverity::Error).count();
        let warn_count = self.checks.iter().filter(|c| c.severity == CheckSeverity::Warning).count();
        writeln!(
            f,
            "  summary: {} error(s), {} warning(s) — {}",
            err_count,
            warn_count,
            if self.ok() { "PASS" } else { "FAIL" }
        )?;
        for check in &self.checks {
            let tag = match check.severity {
                CheckSeverity::Error => "ERROR",
                CheckSeverity::Warning => "WARN",
            };
            writeln!(f, "  [{tag}] {} — {}", check.field, check.message)?;
        }
        writeln!(f)?;
        writeln!(
            f,
            "live coarse_stats (at relay run): processed_ok, processed_fail, cover_emitted, queue_dropped"
        )?;
        writeln!(
            f,
            "  failure_rate = processed_fail / (processed_ok + processed_fail)"
        )?;
        writeln!(
            f,
            "  scrape: poll coarse_stats at most once per 30s (GPA residual if scraped faster under flood)"
        )?;
        Ok(())
    }
}

fn error(field: &'static str, message: impl Into<String>) -> ConfigCheck {
    ConfigCheck {
        severity: CheckSeverity::Error,
        field,
        message: message.into(),
    }
}

fn warn(field: &'static str, message: impl Into<String>) -> ConfigCheck {
    ConfigCheck {
        severity: CheckSeverity::Warning,
        field,
        message: message.into(),
    }
}

/// Validate a node TOML for production deployment (fail closed on lab flags).
pub fn validate_production_config(config_path: &Path) -> Result<ValidationReport, Box<dyn std::error::Error>> {
    let file = NodeConfigFile::load(config_path)?;
    let mut report = ValidationReport {
        relay_id: Some(file.relay_id.clone()),
        listen: Some(file.listen.clone()),
        checks: Vec::new(),
    };

    if let Some(ref kem) = file.kem {
        if kem.allow_plaintext_kem {
            report.checks.push(error(
                "kem.allow_plaintext_kem",
                "lab flag true — production must use external kem.seeds (false or omitted)",
            ));
        }
        if kem.x25519_seed.is_some() || kem.mlkem_d.is_some() || kem.mlkem_z.is_some() {
            report.checks.push(error(
                "kem inline seeds",
                "inline KEM seeds in main config are lab-only; use [kem] file = \"...\"",
            ));
        }
    }

    if let Some(ref roster) = file.roster {
        if roster.allow_unverified_roster {
            report.checks.push(error(
                "roster.allow_unverified_roster",
                "lab flag true — production requires signed roster verify",
            ));
        }
        if roster.authority_pubkeys.is_empty() {
            report.checks.push(error(
                "roster.authority_pubkeys",
                "empty — production requires consortium authority keys",
            ));
        }
        if roster.threshold == 0 {
            report.checks.push(error(
                "roster.threshold",
                "must be >= 1",
            ));
        }
        match load_roster_from_config(roster) {
            Ok(loaded) => {
                if loaded.is_empty() {
                    report.checks.push(warn(
                        "roster.path",
                        "roster loaded but contains zero relays",
                    ));
                }
            }
            Err(e) => report.checks.push(error(
                "roster.path",
                format!("roster load/verify failed: {e}"),
            )),
        }
    } else {
        report.checks.push(warn(
            "roster",
            "no [roster] section — permissioned deployment expects signed roster",
        ));
    }

    if file.trace.path.is_some() {
        report.checks.push(error(
            "trace.path",
            "lab/capture instrumentation set — unset on production mix relays",
        ));
    }

    if file.exit.log_payloads {
        report.checks.push(warn(
            "exit.log_payloads",
            "payload logging enabled — disable except on designated debug exit hops",
        ));
    }

    if !file.cover.enabled || !file.cover.require {
        report.checks.push(error(
            "cover",
            "production requires [cover] enabled = true and require = true (fail-closed)",
        ));
    }

    if file.link.max_cells_per_sec <= 0.0 {
        report.checks.push(error(
            "link.max_cells_per_sec",
            "ingress rate limit disabled (0) — lab/test only",
        ));
    }

    if file.link.global_max_cells_per_sec == Some(0.0) {
        report.checks.push(error(
            "link.global_max_cells_per_sec",
            "global ingress cap disabled (0) — lab/test only",
        ));
    }

    if !file.link.identity_binding {
        report.checks.push(warn(
            "link.identity_binding",
            "false — production should bind handshake MACs to roster relay id",
        ));
    }

    if file.link.require_ingress_kem_commitment && file.kem_commitment.is_none() {
        report.checks.push(error(
            "link.require_ingress_kem_commitment",
            "true but kem_commitment unset — ingress KEM binding fails closed",
        ));
    } else if file.link.require_ingress_kem_commitment {
        report.checks.push(warn(
            "link.require_ingress_kem_commitment",
            "ingress peers must present matching KEM commitment in link handshake (client hop config)",
        ));
    }

    if file.link.handshake.eq_ignore_ascii_case("legacy_psk") {
        report.checks.push(warn(
            "link.handshake",
            "legacy_psk — production should use handshake = \"auto\" with Noise static keys",
        ));
    }

    #[cfg(feature = "noise-link")]
    if matches!(
        file.link.handshake.to_ascii_lowercase().as_str(),
        "auto" | "noise"
    ) && file.link.noise_static_secret.is_none()
    {
        report.checks.push(warn(
            "link.noise_static_secret",
            "missing — Noise handshake selected but no local static secret configured",
        ));
    }

    if file.health_gossip.enabled {
        if file.health_gossip.signing_seed.is_none()
            && file.health_gossip.signing_key_file.is_none()
        {
            report.checks.push(error(
                "health_gossip",
                "enabled but no signing_seed or signing_key_file",
            ));
        }
        let peers_with_gossip = file
            .peers
            .iter()
            .filter(|p| p.gossip_verifying_key.is_some())
            .count();
        if peers_with_gossip == 0 && !file.peers.is_empty() {
            report.checks.push(warn(
                "peers.gossip_verifying_key",
                "health gossip enabled but no peer gossip_verifying_key configured",
            ));
        }
    } else {
        report.checks.push(warn(
            "health_gossip.enabled",
            "false — production checklist recommends signed neighbor health gossip",
        ));
    }

    if file.peers.is_empty() {
        report.checks.push(warn(
            "peers",
            "empty peer table — mix relay needs neighbor links for routing",
        ));
    }

    for peer in &file.peers {
        if file.health_gossip.enabled && peer.gossip_verifying_key.is_none() {
            report.checks.push(warn(
                "peers.gossip_verifying_key",
                format!("peer {} missing gossip_verifying_key", peer.id),
            ));
        }
        #[cfg(feature = "noise-link")]
        if matches!(
            file.link.handshake.to_ascii_lowercase().as_str(),
            "auto" | "noise"
        ) && peer.noise_static_public.is_none()
        {
            report.checks.push(warn(
                "peers.noise_static_public",
                format!("peer {} missing noise_static_public for Noise handshake", peer.id),
            ));
        }
    }

    // Structural parse check (does not require KEM seeds on disk).
    if file.relay_id.len() != 64 {
        report.checks.push(error(
            "relay_id",
            "expected 64 hex chars",
        ));
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{hex_encode, persist_kem_seeds_file, KemSeeds, DEFAULT_KEM_SEED_FILENAME};
    use aegis_topology::{
        test_relay_record, ConsortiumKey, RelayRoster, RosterAdmissionPolicy,
    };
    use aegis_trust::ReputationLedger;
    use rand_core::OsRng;
    use std::fs;

    fn test_dir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("aegis-node-validate-{tag}-{}", std::process::id()))
    }

    fn fixed_seeds() -> KemSeeds {
        KemSeeds {
            x25519_seed: hex_encode(&[0x11; 32]),
            mlkem_d: hex_encode(&[0x22; 32]),
            mlkem_z: hex_encode(&[0x33; 32]),
        }
    }

    fn write_verified_roster(dir: &Path, authority: &ConsortiumKey) -> (String, String) {
        let mut roster =
            RelayRoster::with_admission_policy(RosterAdmissionPolicy::permissive_for_tests());
        let mut ledger = ReputationLedger::new(0.9).unwrap();
        roster
            .admit_signed(
                authority.sign_record(&test_relay_record(1, "US")),
                &authority.verifying_key(),
                &mut ledger,
            )
            .unwrap();
        let path = dir.join("roster.json");
        roster.save_to_file(&path).unwrap();
        // Forward slashes so Windows paths are valid TOML (backslash+\U is a unicode escape).
        let toml_path = path.to_string_lossy().replace('\\', "/");
        (
            toml_path,
            hex_encode(&authority.verifying_key().to_bytes()),
        )
    }

    #[test]
    fn validate_fails_on_lab_flags() {
        let dir = test_dir("lab-flags");
        fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("node.toml");
        fs::write(
            &config_path,
            r#"
relay_id = "0100000000000000000000000000000000000000000000000000000000000000"
listen = "127.0.0.1:9000"

[kem]
allow_plaintext_kem = true
x25519_seed = "1122334455667788990011223344556677889900112233445566778899001122"
mlkem_d = "2233445566778899001122334455667788990011223344556677889900112233"
mlkem_z = "3344556678990011223344556677889900112233445566778899001122334455"

[trace]
path = "trace.csv"

[link]
max_cells_per_sec = 0.0
global_max_cells_per_sec = 0.0

[roster]
path = "roster.json"
allow_unverified_roster = true
"#,
        )
        .unwrap();

        let report = validate_production_config(&config_path).unwrap();
        assert!(!report.ok());
        assert!(report
            .checks
            .iter()
            .any(|c| c.field == "kem.allow_plaintext_kem"));
        assert!(report.checks.iter().any(|c| c.field == "trace.path"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_passes_production_shape() {
        let dir = test_dir("prod-shape");
        fs::create_dir_all(&dir).unwrap();
        let mut rng = OsRng;
        let authority = ConsortiumKey::generate(&mut rng);
        let (roster_path, pk) = write_verified_roster(&dir, &authority);
        let seed_path = dir.join(DEFAULT_KEM_SEED_FILENAME);
        persist_kem_seeds_file(&seed_path, &fixed_seeds()).unwrap();

        let config_path = dir.join("node.toml");
        fs::write(
            &config_path,
            format!(
                r#"
relay_id = "0100000000000000000000000000000000000000000000000000000000000000"
listen = "127.0.0.1:9000"

[kem]
file = "{DEFAULT_KEM_SEED_FILENAME}"

[link]
handshake = "auto"
max_cells_per_sec = 2.86
noise_static_secret = "aa00000000000000000000000000000000000000000000000000000000000000"

[cover]
enabled = true
require = true

[roster]
path = "{roster_path}"
threshold = 1
allow_unverified_roster = false
authority_pubkeys = ["{pk}"]

[health_gossip]
enabled = true
signing_seed = "bb00000000000000000000000000000000000000000000000000000000000000"

[[peers]]
id = "0200000000000000000000000000000000000000000000000000000000000000"
addr = "127.0.0.1:9001"
link_key = "cc00000000000000000000000000000000000000000000000000000000000000"
gossip_verifying_key = "dd00000000000000000000000000000000000000000000000000000000000000"
noise_static_public = "ee00000000000000000000000000000000000000000000000000000000000000"
"#
            ),
        )
        .unwrap();

        let report = validate_production_config(&config_path).unwrap();
        assert!(report.ok(), "report: {report}");

        let _ = fs::remove_dir_all(&dir);
    }
}
