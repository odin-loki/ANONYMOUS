//! CLI client: build a Sphinx packet and send it to the first hop over TCP.

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use aegis_client::driver::config_with_tau_and_peak;
use aegis_client::emitter::env_allows_high_rho;
use aegis_client::roster_load::{load_roster_from_config, RosterFileConfig};
use aegis_client::send::{BuildPacketOptions, ClientHop, ClientLink};
use aegis_client::session::{PacedSession, PacedSessionConfig};
use aegis_crypto::kem::RelayKemSecret;
use aegis_topology::types::KemPublicCommitment;
use aegis_relay::LinkBridgeConfig;
use clap::Parser;
use rand_core::OsRng;
use serde::Deserialize;

#[derive(Parser, Debug)]
#[command(name = "aegis-client", about = "AEGIS Sphinx packet injector")]
struct Cli {
    /// TOML file with path hops and link settings.
    #[arg(long)]
    config: PathBuf,

    /// Payload bytes (overrides config payload).
    #[arg(long)]
    payload: Option<String>,

    /// Read payload from stdin when set.
    #[arg(long)]
    stdin: bool,

    /// Burst-send without constant-rate pacing (debug / trace capture only).
    #[arg(long)]
    raw: bool,

    /// Seconds of dummy cover after the last fragment (Mode 1 default).
    #[arg(long, default_value_t = 2.0)]
    cover_secs: f64,

    /// Slot period τ in seconds (spec worked example 0.35).
    #[arg(long, default_value_t = 0.35)]
    tau_secs: f64,

    /// Peak message enqueue rate (msg/s) for ρ validation (spec default 2.0).
    #[arg(long, default_value_t = 2.0)]
    peak_rate: f64,

    /// Allow offered load ρ > 0.7 (lab / adversarial trace only).
    #[arg(long)]
    allow_high_rho: bool,

    /// Require roster KEM commitment on every hop (default: on when any hop config includes `kem_commitment`).
    #[arg(long)]
    require_kem_binding: Option<bool>,

    /// Allow hops without roster KEM commitments (dev/legacy only).
    #[arg(long, conflicts_with = "require_kem_binding")]
    no_require_kem_binding: bool,
}

#[derive(Debug, Deserialize)]
struct ClientConfigFile {
    first_hop_addr: String,
    ingress_link_key: String,
    payload: Option<String>,
    hops: Vec<HopConfig>,
    /// Optional permissioned roster; when set, loaded with consortium re-verify.
    #[serde(default)]
    roster: Option<RosterFileConfig>,
}

#[derive(Debug, Deserialize)]
struct HopConfig {
    id: String,
    kem_x25519_seed: String,
    kem_mlkem_d: String,
    kem_mlkem_z: String,
    /// Optional SHA3-256 hex commitment from the signed roster (64 hex chars).
    kem_commitment: Option<String>,
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let text = fs::read_to_string(&cli.config)?;
    let file: ClientConfigFile = toml::from_str(&text)?;

    if let Some(ref roster_cfg) = file.roster {
        let roster = load_roster_from_config(roster_cfg)?;
        eprintln!(
            "loaded roster from {} ({} relays)",
            roster_cfg.path,
            roster.len()
        );
    }

    let payload = if cli.stdin {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)?;
        buf
    } else if let Some(p) = cli.payload {
        p.into_bytes()
    } else {
        file.payload.unwrap_or_default().into_bytes()
    };

    let mut hops = Vec::new();
    for hop in &file.hops {
        let id = parse_hex32(&hop.id)?;
        let x = parse_hex32(&hop.kem_x25519_seed)?;
        let d = parse_hex32(&hop.kem_mlkem_d)?;
        let z = parse_hex32(&hop.kem_mlkem_z)?;
        let (_sec, pk) = RelayKemSecret::generate_deterministic(x, d, z);
        let kem_commitment = hop
            .kem_commitment
            .as_deref()
            .map(parse_hex32)
            .transpose()
            .map_err(|e| format!("kem_commitment: {e}"))?
            .map(KemPublicCommitment);
        hops.push(ClientHop {
            id,
            kem_public: pk,
            kem_commitment,
            addr: None,
        });
    }

    let first_hop_addr: SocketAddr = file.first_hop_addr.parse()?;
    let first_hop_relay_id = hops
        .first()
        .map(|hop| hop.id)
        .ok_or("config must include at least one hop")?;
    let link = ClientLink {
        first_hop_addr,
        first_hop_relay_id,
        link_key_bytes: parse_hex32(&file.ingress_link_key)?,
        kem_commitment: hops
            .first()
            .and_then(|h| h.kem_commitment.map(|c| c.0)),
    };

    let require_kem_binding = if cli.no_require_kem_binding {
        false
    } else {
        cli.require_kem_binding.unwrap_or_else(|| {
            file.hops.iter().any(|hop| hop.kem_commitment.is_some())
        })
    };
    let packet_options = BuildPacketOptions {
        require_kem_binding,
    };

    let mut rng = OsRng;
    if cli.raw {
        let packet =
            aegis_client::send::send_payload_with_options(&hops, &link, &payload, &mut rng, packet_options)
                .await?;
        eprintln!(
            "sent sphinx packet (raw/unpaced, {} B payload) to {}",
            payload.len(),
            first_hop_addr
        );
        let _ = packet;
    } else {
        let mut session = PacedSession::connect(
            &link,
            &LinkBridgeConfig::default(),
            PacedSessionConfig {
                emitter_config: config_with_tau_and_peak(cli.tau_secs, cli.peak_rate),
                cover_after_send: Duration::from_secs_f64(cli.cover_secs),
                allow_high_rho: cli.allow_high_rho || env_allows_high_rho(),
            },
            &mut rng,
        )
        .await?;
        let packet = session.send_payload_via_session_with_options(
            &hops,
            &payload,
            &mut rng,
            packet_options,
        )?;
        session.wait_idle_cover().await?;
        session.shutdown().await?;
        eprintln!(
            "sent sphinx packet (paced session, {} B payload, cover {}s) to {}",
            payload.len(),
            cli.cover_secs,
            first_hop_addr
        );
        let _ = packet;
    }
    Ok(())
}
