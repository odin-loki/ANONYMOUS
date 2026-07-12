//! CLI client: build a Sphinx packet and send it to the first hop over TCP.

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

use aegis_client::send::{send_payload, ClientHop, ClientLink};
use aegis_crypto::kem::RelayKemSecret;
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
}

#[derive(Debug, Deserialize)]
struct ClientConfigFile {
    first_hop_addr: String,
    ingress_link_key: String,
    payload: Option<String>,
    hops: Vec<HopConfig>,
}

#[derive(Debug, Deserialize)]
struct HopConfig {
    id: String,
    kem_x25519_seed: String,
    kem_mlkem_d: String,
    kem_mlkem_z: String,
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
        hops.push(ClientHop {
            id,
            kem_public: pk,
            addr: None,
        });
    }

    let first_hop_addr: SocketAddr = file.first_hop_addr.parse()?;
    let link = ClientLink {
        first_hop_addr,
        link_key_bytes: parse_hex32(&file.ingress_link_key)?,
    };

    let mut rng = OsRng;
    let packet = send_payload(&hops, &link, &payload, &mut rng).await?;
    eprintln!(
        "sent sphinx packet ({} B payload) to {}",
        payload.len(),
        first_hop_addr
    );
    let _ = packet;
    Ok(())
}
