//! Deterministic operator-pilot material: verified roster, production-default flags.
//!
//! ```text
//! cargo run -p aegis-topology --bin aegis-pilot-gen -- \
//!   --out ../../sim/data/pilot_configs \
//!   --ports 17419,17420,17421,17422
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use aegis_crypto::kem::RelayKemSecret;
use aegis_crypto::noise_link::{derive_noise_static_secret, noise_static_public};
use aegis_topology::roster::{ConsortiumKey, RelayRoster, ThresholdConsortium, ThresholdSignedRelayRecord};
use aegis_topology::types::{JurisdictionId, KemPublicCommitment, RelayRecord};
use aegis_trust::{signing_key_from_seed, ReputationLedger};
use clap::Parser;
use ed25519_dalek::SigningKey;
use serde::Serialize;

const PATH_LEN: usize = 4;
const PILOT_BASE_PORT: u16 = 17419;

#[derive(Parser, Debug)]
#[command(
    name = "aegis-pilot-gen",
    about = "Generate deterministic 4-node loopback pilot configs (production checklist defaults)"
)]
struct Args {
    /// Output directory for roster + node/client TOML templates.
    #[arg(long, default_value = "pilot_configs")]
    out: PathBuf,

    /// Comma-separated loopback listen ports (4 values) or empty for defaults.
    #[arg(long, default_value = "17419,17420,17421,17422")]
    ports: String,

    /// Emit JSON manifest to stdout instead of writing TOML files.
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct PilotManifest {
    authority_pubkey_hex: String,
    ingress_link_key: String,
    ingress_noise_static_public: String,
    ingress_noise_static_secret: String,
    nodes: Vec<PilotNodeManifest>,
}

#[derive(Serialize)]
struct PilotNodeManifest {
    index: usize,
    relay_id: String,
    kem_x25519_seed: String,
    kem_mlkem_d: String,
    kem_mlkem_z: String,
    kem_commitment: String,
    noise_static_secret: String,
    noise_static_public: String,
    gossip_signing_seed: String,
    gossip_verifying_key: String,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn pilot_domain_seed(label: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"aegis-pilot-v1");
    h.update(label);
    h.finalize().into()
}

fn pilot_signing_key(label: &[u8]) -> SigningKey {
    signing_key_from_seed(&pilot_domain_seed(label))
}

fn link_key(tag: u8) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[0] = tag;
    buf[1] = 0xA5;
    buf
}

fn kem_seeds(index: usize) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let i = index as u8;
    let mut x = [0u8; 32];
    x[0] = 0xA0 + i;
    x[1] = 0xB0 + i;
    let mut d = [0u8; 32];
    d[0] = 0xC0 + i;
    d[1] = 0xD0 + i;
    let mut z = [0u8; 32];
    z[0] = 0xE0 + i;
    z[1] = 0xF0 + i;
    (x, d, z)
}

fn parse_ports(raw: &str) -> Result<Vec<u16>, String> {
    let ports: Result<Vec<_>, _> = raw
        .split(',')
        .map(|s| s.trim().parse::<u16>())
        .collect();
    let ports = ports.map_err(|_| "invalid --ports".to_string())?;
    if ports.len() != PATH_LEN {
        return Err(format!("expected {PATH_LEN} ports, got {}", ports.len()));
    }
    Ok(ports)
}

fn build_manifest() -> (PilotManifest, RelayRoster, ThresholdConsortium) {
    let authority = ConsortiumKey::from_signing_key(pilot_signing_key(b"consortium"));
    let authority_pk = authority.verifying_key();
    let consortium = ThresholdConsortium::single(authority_pk);

    let ingress_material = link_key(0xD0);
    let ingress_link_key = hex_encode(&ingress_material);
    let ingress_noise_sk = derive_noise_static_secret(&ingress_material);
    let ingress_noise_static_public = hex_encode(&noise_static_public(&ingress_noise_sk));
    let ingress_noise_static_secret = hex_encode(&ingress_noise_sk);

    let mut roster =
        RelayRoster::with_admission_policy(aegis_topology::RosterAdmissionPolicy::permissive_for_tests());
    let mut ledger = ReputationLedger::new(0.9).expect("ledger");

    let mut nodes = Vec::with_capacity(PATH_LEN);
    for i in 0..PATH_LEN {
        let (x, d, z) = kem_seeds(i);
        let (_sec, kem_public) = RelayKemSecret::generate_deterministic(x, d, z);
        let record =
            RelayRecord::from_kem_public(JurisdictionId::new("US"), &kem_public);
        let mut signed = ThresholdSignedRelayRecord::new(record.clone());
        signed = signed.with_signature(authority.sign_authority(&record));
        roster
            .admit_threshold_signed(signed, &consortium, &mut ledger)
            .expect("admit pilot relay");

        let noise_material = link_key(0x10 + i as u8);
        let noise_sk = derive_noise_static_secret(&noise_material);
        let gossip_key = pilot_signing_key(format!("gossip-{i}").as_bytes());

        nodes.push(PilotNodeManifest {
            index: i,
            relay_id: hex_encode(record.id.as_bytes()),
            kem_x25519_seed: hex_encode(&x),
            kem_mlkem_d: hex_encode(&d),
            kem_mlkem_z: hex_encode(&z),
            kem_commitment: hex_encode(&KemPublicCommitment::from_public(&kem_public).0),
            noise_static_secret: hex_encode(&noise_sk),
            noise_static_public: hex_encode(&noise_static_public(&noise_sk)),
            gossip_signing_seed: hex_encode(&gossip_key.to_bytes()),
            gossip_verifying_key: hex_encode(gossip_key.verifying_key().as_bytes()),
        });
    }

    let manifest = PilotManifest {
        authority_pubkey_hex: hex_encode(authority_pk.as_bytes()),
        ingress_link_key,
        ingress_noise_static_public,
        ingress_noise_static_secret,
        nodes,
    };
    (manifest, roster, consortium)
}

fn peer_noise_public(manifest: &PilotManifest, peer_index: usize) -> String {
    manifest.nodes[peer_index].noise_static_public.clone()
}

fn edge_link_tag(a: usize, b: usize) -> u8 {
    a.max(b) as u8
}

fn write_all(out: &Path, ports: &[u16], manifest: &PilotManifest, roster: &RelayRoster) -> Result<(), String> {
    fs::create_dir_all(out).map_err(|e| e.to_string())?;
    fs::create_dir_all(out.join("data")).map_err(|e| e.to_string())?;

    roster
        .save_to_file(&out.join("roster.json"))
        .map_err(|e| e.to_string())?;

    fs::write(
        out.join("authority.pub.hex"),
        format!("{}\n", manifest.authority_pubkey_hex),
    )
    .map_err(|e| e.to_string())?;

    for (i, port) in ports.iter().enumerate() {
        let node = &manifest.nodes[i];
        let roster_path = "roster.json";
        let mut peers = String::new();
        if i > 0 {
            let p = i - 1;
            peers.push_str(&format!(
                r#"
[[peers]]
id = "{id}"
addr = "127.0.0.1:{port}"
link_key = "{link_key}"
noise_static_public = "{noise_pk}"
gossip_verifying_key = "{gossip_vk}"
"#,
                id = manifest.nodes[p].relay_id,
                port = ports[p],
                link_key = hex_encode(&link_key(edge_link_tag(i, p))),
                noise_pk = peer_noise_public(manifest, p),
                gossip_vk = manifest.nodes[p].gossip_verifying_key,
            ));
        }
        if i + 1 < PATH_LEN {
            let p = i + 1;
            peers.push_str(&format!(
                r#"
[[peers]]
id = "{id}"
addr = "127.0.0.1:{port}"
link_key = "{link_key}"
noise_static_public = "{noise_pk}"
gossip_verifying_key = "{gossip_vk}"
"#,
                id = manifest.nodes[p].relay_id,
                port = ports[p],
                link_key = hex_encode(&link_key(edge_link_tag(i, p))),
                noise_pk = peer_noise_public(manifest, p),
                gossip_vk = manifest.nodes[p].gossip_verifying_key,
            ));
        }

        let ingress = if i == 0 {
            format!(
                r#"
[ingress]
link_key = "{ingress_key}"
"#,
                ingress_key = manifest.ingress_link_key,
            )
        } else {
            String::new()
        };

        let ingress_noise = if i == 0 {
            format!(
                "ingress_noise_static_public = \"{}\"\n",
                manifest.ingress_noise_static_public
            )
        } else {
            String::new()
        };

        let exit = if i == PATH_LEN - 1 {
            r#"
[exit]
deliver_to = "file:data/exit_deliveries.log"
"#
            .to_string()
        } else {
            String::new()
        };

        let toml = format!(
            r#"relay_id = "{relay_id}"
listen = "127.0.0.1:{port}"
mu = 80.0

[kem]
allow_plaintext_kem = true
x25519_seed = "{x25519}"
mlkem_d = "{mlkem_d}"
mlkem_z = "{mlkem_z}"

kem_commitment = "{kem_commitment}"

[roster]
path = "{roster_path}"
threshold = 1
authority_pubkeys = ["{authority_pk}"]
allow_unverified_roster = false

[cover]
enabled = true
require = true

[health_gossip]
enabled = true
signing_seed = "{gossip_seed}"
interval_secs = 60
majority_k = 2
quorum_log_path = "data/health_quorum.log"

[link]
handshake = "auto"
noise_static_secret = "{noise_sk}"
{ingress_noise}{ingress}{exit}{peers}
"#,
            relay_id = node.relay_id,
            port = port,
            x25519 = node.kem_x25519_seed,
            mlkem_d = node.kem_mlkem_d,
            mlkem_z = node.kem_mlkem_z,
            kem_commitment = node.kem_commitment,
            roster_path = roster_path,
            authority_pk = manifest.authority_pubkey_hex,
            gossip_seed = node.gossip_signing_seed,
            noise_sk = node.noise_static_secret,
            ingress_noise = ingress_noise,
        );

        fs::write(out.join(format!("node{i}.toml")), toml).map_err(|e| e.to_string())?;
    }

    let mut hops = String::new();
    for node in &manifest.nodes {
        hops.push_str(&format!(
            r#"
[[hops]]
id = "{id}"
kem_x25519_seed = "{x25519}"
kem_mlkem_d = "{mlkem_d}"
kem_mlkem_z = "{mlkem_z}"
kem_commitment = "{kem_commitment}"
"#,
            id = node.relay_id,
            x25519 = node.kem_x25519_seed,
            mlkem_d = node.kem_mlkem_d,
            mlkem_z = node.kem_mlkem_z,
            kem_commitment = node.kem_commitment,
        ));
    }

    let client = format!(
        r#"first_hop_addr = "127.0.0.1:{port0}"
ingress_link_key = "{ingress_key}"
payload = "pilot-smoke"

[roster]
path = "roster.json"
threshold = 1
authority_pubkeys = ["{authority_pk}"]
allow_unverified_roster = false

[link]
handshake = "auto"
noise_static_secret = "{ingress_noise_sk}"
first_hop_noise_static_public = "{first_hop_noise_pk}"
{hops}
"#,
        port0 = ports[0],
        ingress_key = manifest.ingress_link_key,
        authority_pk = manifest.authority_pubkey_hex,
        ingress_noise_sk = manifest.ingress_noise_static_secret,
        first_hop_noise_pk = manifest.nodes[0].noise_static_public,
    );
    fs::write(out.join("client.toml"), client).map_err(|e| e.to_string())?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let ports = parse_ports(&args.ports)?;
    let (manifest, roster, _consortium) = build_manifest();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&manifest)?);
        return Ok(());
    }

    write_all(&args.out, &ports, &manifest, &roster)?;
    eprintln!(
        "pilot configs -> {} (ports={ports:?}, base default {PILOT_BASE_PORT})",
        args.out.display()
    );
    Ok(())
}
