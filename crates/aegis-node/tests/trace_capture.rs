//! Capture a real client-send timestamp trace over the in-process TCP testnet.
//!
//! Uses the same real loopback sockets and Sphinx/link code path as
//! `tcp_testnet.rs`, but drives a bursty multi-packet emission schedule and
//! writes wall-clock send events to `sim/data/real_testnet_trace.csv`.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aegis_client::send::{send_payload, ClientHop, ClientLink};
use aegis_crypto::fragment::SPHINX_FRAGMENT_COUNT;
use aegis_crypto::kem::RelayKemSecret;
use aegis_relay::{spawn_link_bridge, LinkBridgeConfig, PeerInfo, RelayConfig, RelayId, RelayNode};
use rand_core::{OsRng, RngCore};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const PATH_LEN: usize = 4;
/// High μ => short per-hop delays for a reliable capture gate.
const FAST_MU: f64 = 80.0;
const N_SENDS: usize = 48;

fn workspace_trace_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("sim")
        .join("data")
        .join("real_testnet_trace.csv")
}

fn make_id(index: usize) -> RelayId {
    let mut id_bytes = [0u8; 32];
    id_bytes[0] = (index + 1) as u8;
    RelayId(id_bytes)
}

fn link_key_byte(tag: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = tag;
    k
}

fn wall_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs_f64()
}

/// Bursty gaps: rapid clusters (50–180 ms) separated by longer idle (0.8–3.5 s).
fn bursty_gaps_ms(rng: &mut impl RngCore, n: usize) -> Vec<u64> {
    let mut gaps = Vec::with_capacity(n);
    while gaps.len() < n {
        if gaps.len() + 1 < n && (gaps.len() % 11 < 4) {
            let cluster = (4usize).min(n - gaps.len());
            for _ in 0..cluster {
                gaps.push(50 + (rng.next_u32() % 131) as u64);
            }
        } else {
            gaps.push(800 + (rng.next_u32() % 2700) as u64);
        }
    }
    gaps.truncate(n);
    gaps
}

struct TcpRelaySlot {
    handle: aegis_relay::RelayHandle,
    _relay_task: tokio::task::JoinHandle<()>,
    _net_tasks: (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>),
}

struct TcpTestnet {
    relays: Vec<TcpRelaySlot>,
    hops: Vec<ClientHop>,
    client_link: ClientLink,
}

impl TcpTestnet {
    async fn build(path_len: usize) -> Self {
        let mut rng = OsRng;
        let mut secrets = Vec::with_capacity(path_len);
        let mut publics = Vec::with_capacity(path_len);
        let mut ids = Vec::with_capacity(path_len);

        for i in 0..path_len {
            let (sec, pk) = RelayKemSecret::generate(&mut rng);
            secrets.push(sec);
            publics.push(pk);
            ids.push(make_id(i));
        }

        let mut listen_addrs = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind loopback");
            listen_addrs.push(listener.local_addr().expect("local_addr"));
        }

        let client_ingress_key = link_key_byte(0xC0);
        let mut relays = Vec::with_capacity(path_len);

        for i in 0..path_len {
            let id = ids[i];
            let mut peer_table = HashMap::new();

            if i > 0 {
                peer_table.insert(
                    ids[i - 1],
                    PeerInfo::new(listen_addrs[i - 1], link_key_byte(i as u8)),
                );
            }
            if i + 1 < path_len {
                peer_table.insert(
                    ids[i + 1],
                    PeerInfo::new(listen_addrs[i + 1], link_key_byte((i + 1) as u8)),
                );
            }

            let ingress = if i == 0 {
                Some(client_ingress_key)
            } else {
                None
            };

            let (inbound_tx, inbound_rx) = mpsc::channel(64);
            let (outbound_tx, outbound_rx) = mpsc::channel(64);
            let (cover_tx, cover_rx) = mpsc::channel(64);

            let node = RelayNode::new(id, secrets.remove(0), RelayConfig::new(FAST_MU));
            let (handle, relay_task) = node.spawn(inbound_rx, outbound_tx, Some(cover_tx), OsRng);

            let net_tasks = spawn_link_bridge(
                listen_addrs[i],
                peer_table,
                ingress,
                inbound_tx,
                outbound_rx,
                Some(cover_rx),
                None,
                OsRng,
                LinkBridgeConfig::default(),
                None,
            );

            relays.push(TcpRelaySlot {
                handle,
                _relay_task: relay_task,
                _net_tasks: net_tasks,
            });
        }

        let hops: Vec<ClientHop> = ids
            .iter()
            .zip(publics.iter())
            .enumerate()
            .map(|(i, (id, pk))| ClientHop {
                id: id.0,
                kem_public: pk.clone(),
                kem_commitment: None,
                addr: if i == 0 {
                    Some(listen_addrs[0])
                } else {
                    None
                },
            })
            .collect();

        let client_link = ClientLink {
            first_hop_addr: listen_addrs[0],
            link_key_bytes: client_ingress_key,
        };

        Self {
            relays,
            hops,
            client_link,
        }
    }

    fn relay_handle(&self, index: usize) -> &aegis_relay::RelayHandle {
        &self.relays[index].handle
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "regenerates sim/data/real_testnet_trace.csv; run with --ignored to re-capture"]
async fn capture_burst_trace_to_csv() {
    let testnet = TcpTestnet::build(PATH_LEN).await;
    let mut rng = OsRng;
    let gaps = bursty_gaps_ms(&mut rng, N_SENDS.saturating_sub(1));

    let mut rows: Vec<(f64, usize, usize)> = Vec::with_capacity(N_SENDS);

    for i in 0..N_SENDS {
        let payload_len = 32 + (rng.next_u32() as usize % 225);
        let mut payload = vec![0u8; payload_len];
        payload[0] = (i as u8).wrapping_add(0xA5);
        payload[payload_len - 1] = (i as u8).wrapping_add(0x5A);

        let ts = wall_secs();
        send_payload(
            &testnet.hops,
            &testnet.client_link,
            &payload,
            &mut rng,
        )
        .await
        .expect("client send over TcpStream");

        rows.push((ts, payload_len, SPHINX_FRAGMENT_COUNT));

        if i + 1 < N_SENDS {
            tokio::time::sleep(Duration::from_millis(gaps[i])).await;
        }
    }

    // Allow mixing delays to drain through the path.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    assert!(
        testnet.relay_handle(0).debug_stats().forwarded_count >= N_SENDS as u64,
        "ingress relay should have forwarded all sends"
    );

    let out_path = workspace_trace_path();
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("create sim/data");
    }
    let mut f = File::create(&out_path).expect("create trace csv");
    writeln!(f, "timestamp,payload_bytes,cell_count").expect("header");
    writeln!(f, "# vantage=client_send_wall_clock").expect("meta");
    writeln!(
        f,
        "# capture=in_process_tcp_testnet path_len={PATH_LEN} n_sends={N_SENDS}"
    )
    .expect("meta");
    for (ts, payload_bytes, cell_count) in &rows {
        writeln!(f, "{ts:.6},{payload_bytes},{cell_count}").expect("row");
    }

    let duration = rows.last().unwrap().0 - rows.first().unwrap().0;
    eprintln!(
        "wrote {} events ({duration:.1}s span) to {}",
        rows.len(),
        out_path.display()
    );
    assert!(duration >= 5.0, "trace should span multiple seconds");
    assert_eq!(rows.len(), N_SENDS);
}

fn workspace_malicious_trace_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("sim")
        .join("data")
        .join("real_testnet_malicious_trace.csv")
}

const MALICIOUS_SENDS: usize = 80;
/// Minimal inter-send gap (ms) — tight flood well above any negotiated round rate.
const MALICIOUS_GAP_MS: u64 = 2;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "regenerates sim/data/real_testnet_malicious_trace.csv; run with --ignored"]
async fn capture_malicious_burst_trace_to_csv() {
    let testnet = TcpTestnet::build(PATH_LEN).await;
    let mut rng = OsRng;

    let mut rows: Vec<(f64, usize, usize, bool)> = Vec::with_capacity(MALICIOUS_SENDS);
    let mut send_errors = 0u32;

    for i in 0..MALICIOUS_SENDS {
        let payload_len = 32 + (rng.next_u32() as usize % 225);
        let mut payload = vec![0u8; payload_len];
        payload[0] = (i as u8).wrapping_add(0xF0);
        payload[payload_len - 1] = (i as u8).wrapping_add(0x0F);

        let ts = wall_secs();
        let ok = send_payload(
            &testnet.hops,
            &testnet.client_link,
            &payload,
            &mut rng,
        )
        .await
        .is_ok();
        if !ok {
            send_errors += 1;
        }
        rows.push((ts, payload_len, SPHINX_FRAGMENT_COUNT, ok));

        if i + 1 < MALICIOUS_SENDS {
            tokio::time::sleep(Duration::from_millis(MALICIOUS_GAP_MS)).await;
        }
    }

    // Allow mixing queue to drain (or saturate).
    tokio::time::sleep(Duration::from_millis(3000)).await;

    let ingress = testnet.relay_handle(0);
    let ingress_debug = ingress.debug_stats();
    let forwarded = ingress_debug.forwarded_count;
    let integrity_err = ingress_debug.integrity_error_count;
    let dropped = ingress_debug.dropped_count;

    let out_path = workspace_malicious_trace_path();
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("create sim/data");
    }
    let mut f = File::create(&out_path).expect("create malicious trace csv");
    writeln!(f, "timestamp,payload_bytes,cell_count,send_ok").expect("header");
    writeln!(f, "# vantage=client_send_wall_clock").expect("meta");
    writeln!(
        f,
        "# capture=malicious_flood path_len={PATH_LEN} n_sends={MALICIOUS_SENDS} gap_ms={MALICIOUS_GAP_MS}"
    )
    .expect("meta");
    writeln!(
        f,
        "# relay_stats forwarded={forwarded} integrity_err={integrity_err} dropped={dropped} send_errors={send_errors}"
    )
    .expect("meta");
    for (ts, payload_bytes, cell_count, ok) in &rows {
        writeln!(
            f,
            "{ts:.6},{payload_bytes},{cell_count},{}",
            if *ok { 1 } else { 0 }
        )
        .expect("row");
    }

    let duration = rows.last().unwrap().0 - rows.first().unwrap().0;
    let ok_count = rows.iter().filter(|(_, _, _, ok)| *ok).count();
    eprintln!(
        "wrote {} events ({duration:.2}s span, {ok_count}/{} client sends ok, ingress forwarded={forwarded}) to {}",
        rows.len(),
        rows.len(),
        out_path.display()
    );

    // Flood completes far faster than the benign ~72 s capture despite per-send crypto cost.
    assert!(duration < 30.0, "malicious flood should be tight vs benign: {duration:.2}s");
    assert!(ok_count > 0, "at least some sends should succeed");
}
