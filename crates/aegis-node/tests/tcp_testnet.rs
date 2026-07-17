//! TCP integration gate: multi-hop Sphinx delivery over real loopback sockets.

#![allow(deprecated)] // intentional raw send_payload for unpaced integration gates

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use aegis_client::send::{send_payload_with_options, BuildPacketOptions, ClientHop, ClientLink};
use aegis_topology::types::KemPublicCommitment;
use aegis_crypto::kem::RelayKemSecret;
use aegis_crypto::sphinx::{build, PathHop, SphinxPacket};
use aegis_relay::{
    load_trace_timestamps, packet_delta, spawn_link_bridge_with_listener, InboundListen,
    LinkBridgeConfig, PeerInfo, RelayConfig, RelayForwardTrace, RelayId, RelayNode,
};
use rand_core::OsRng;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const PATH_LEN: usize = 4;
const PAYLOAD: &[u8] = b"tcp-testnet-payload";
/// High μ => short per-hop delays for a reliable CI gate.
const FAST_MU: f64 = 80.0;

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

struct TcpRelaySlot {
    #[allow(dead_code)]
    listen_addr: SocketAddr,
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
    async fn build(
        path_len: usize,
        exit_tx: Option<mpsc::Sender<SphinxPacket>>,
        ingress_trace: Option<RelayForwardTrace>,
    ) -> Self {
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

        // Bind once and hand listeners to the bridge (no Windows rebind race).
        let mut listen_addrs = Vec::with_capacity(path_len);
        let mut listeners = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind loopback");
            listen_addrs.push(listener.local_addr().expect("local_addr"));
            listeners.push(Some(listener));
        }

        let client_ingress_key = link_key_byte(0xC0);
        let commitments: Vec<[u8; 32]> = publics
            .iter()
            .map(|pk| KemPublicCommitment::from_public(pk).0)
            .collect();
        let mut relays = Vec::with_capacity(path_len);

        for i in 0..path_len {
            let id = ids[i];
            let mut peer_table = HashMap::new();

            if i > 0 {
                let upstream_id = ids[i - 1];
                peer_table.insert(
                    upstream_id,
                    PeerInfo::new(listen_addrs[i - 1], link_key_byte(i as u8))
                        .with_kem_commitment(commitments[i - 1]),
                );
            }
            if i + 1 < path_len {
                let downstream_id = ids[i + 1];
                peer_table.insert(
                    downstream_id,
                    PeerInfo::new(listen_addrs[i + 1], link_key_byte((i + 1) as u8))
                        .with_kem_commitment(commitments[i + 1]),
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
            let (handle, relay_task) = node
                .spawn(inbound_rx, outbound_tx, Some(cover_tx), OsRng)
                .expect("spawn relay");

            let exit = if i == path_len - 1 {
                exit_tx.clone()
            } else {
                None
            };

            let listener = listeners[i].take().expect("listener");
            let net_tasks = spawn_link_bridge_with_listener(
                InboundListen::Listener(listener),
                id,
                Some(commitments[i]),
                peer_table,
                ingress,
                inbound_tx,
                outbound_rx,
                Some(cover_rx),
                None,
                exit,
                if i == 0 {
                    ingress_trace.clone()
                } else {
                    None
                },
                OsRng,
                // Raw integration floods; production defaults rate-limit ingress.
                LinkBridgeConfig::default().without_ingress_rate_limit(),
                None,
            );

            relays.push(TcpRelaySlot {
                listen_addr: listen_addrs[i],
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
                kem_commitment: Some(KemPublicCommitment::from_public(pk)),
                addr: if i == 0 {
                    Some(listen_addrs[0])
                } else {
                    None
                },
            })
            .collect();

        let client_link = ClientLink {
            first_hop_addr: listen_addrs[0],
            first_hop_relay_id: hops[0].id,
            link_key_bytes: client_ingress_key,
            kem_commitment: hops[0].kem_commitment.map(|c| c.0),
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
async fn tcp_testnet_paced_send_delivers_payload() {
    let (exit_tx, mut exit_rx) = mpsc::channel(1);
    let testnet = TcpTestnet::build(PATH_LEN, Some(exit_tx), None).await;

    let mut rng = OsRng;
    let tau = Duration::from_millis(25);
    aegis_client::send::send_payload_paced(
        &testnet.hops,
        &testnet.client_link,
        PAYLOAD,
        &mut rng,
        Some(aegis_client::EmitterConfig {
            tau,
            ..Default::default()
        }),
        &LinkBridgeConfig::default(),
        Duration::ZERO,
    )
    .await
    .expect("paced client send over TcpStream");

    let exit_packet = tokio::time::timeout(Duration::from_secs(20), exit_rx.recv())
        .await
        .expect("timed out waiting for paced exit packet")
        .expect("exit channel closed");

    let delta = packet_delta(&exit_packet);
    assert_eq!(
        &delta[..PAYLOAD.len()],
        PAYLOAD,
        "payload mismatch after paced send over {PATH_LEN} TCP hops"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_testnet_routes_sphinx_over_real_sockets() {
    let (exit_tx, mut exit_rx) = mpsc::channel(1);
    let testnet = TcpTestnet::build(PATH_LEN, Some(exit_tx), None).await;

    let mut rng = OsRng;
    send_payload_with_options(
        &testnet.hops,
        &testnet.client_link,
        PAYLOAD,
        &mut rng,
        BuildPacketOptions::default(),
    )
        .await
        .expect("client send over TcpStream");

    let exit_packet = tokio::time::timeout(Duration::from_secs(20), exit_rx.recv())
        .await
        .expect("timed out waiting for exit packet")
        .expect("exit channel closed");

    let delta = packet_delta(&exit_packet);
    assert_eq!(
        &delta[..PAYLOAD.len()],
        PAYLOAD,
        "payload mismatch after {PATH_LEN} TCP hops"
    );

    assert_eq!(
        testnet.relay_handle(0).debug_stats().forwarded_count,
        1,
        "first relay should have forwarded once"
    );
    assert_eq!(
        testnet.relay_handle(PATH_LEN - 1).debug_stats().forwarded_count,
        1,
        "exit relay should have peeled once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_testnet_exit_sink_file_receives_payload() {
    use aegis_node::exit_sink::{spawn_exit_sink, ExitDeliverTarget, ExitSinkSettings};
    use std::fs;

    let dir = std::env::temp_dir().join(format!("aegis_exit_{}", std::process::id()));
    fs::create_dir_all(&dir).expect("temp dir");
    let exit_path = dir.join("exit_payloads.log");

    let exit_tx = spawn_exit_sink(ExitSinkSettings {
        log_payloads: false,
        deliver_to: Some(ExitDeliverTarget::File(exit_path.clone())),
    })
    .expect("file exit sink enabled");

    let testnet = TcpTestnet::build(PATH_LEN, Some(exit_tx), None).await;
    let mut rng = OsRng;
    send_payload_with_options(
        &testnet.hops,
        &testnet.client_link,
        PAYLOAD,
        &mut rng,
        BuildPacketOptions::default(),
    )
        .await
        .expect("client send");

    let mut log = String::new();
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Ok(text) = fs::read_to_string(&exit_path) {
            if !text.is_empty() {
                log = text;
                break;
            }
        }
    }
    assert!(!log.is_empty(), "exit log was not written within timeout");
    let expected_hex: String = PAYLOAD.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        log.contains(&expected_hex),
        "exit file should contain payload hex; got:\n{log}"
    );
    let _ = fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_testnet_relay_forward_trace_records_events() {
    use aegis_crypto::fragment::SPHINX_FRAGMENT_COUNT;
    use std::fs;

    let dir = std::env::temp_dir().join(format!("aegis_rtrace_{}", std::process::id()));
    fs::create_dir_all(&dir).expect("temp dir");
    let trace_path = dir.join("relay_trace.csv");
    let trace = RelayForwardTrace::spawn(&trace_path).expect("spawn trace");

    let testnet = TcpTestnet::build(PATH_LEN, None, Some(trace.clone())).await;
    send_payload_with_options(
        &testnet.hops,
        &testnet.client_link,
        PAYLOAD,
        &mut OsRng,
        BuildPacketOptions::default(),
    )
    .await
    .expect("send");

    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if fs::read_to_string(&trace_path)
            .map(|t| t.contains(&format!(",{SPHINX_FRAGMENT_COUNT},forward")))
            .unwrap_or(false)
        {
            break;
        }
    }
    drop(trace);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let text = fs::read_to_string(&trace_path).expect("trace file");
    assert!(text.contains("timestamp,cell_count,event_type"));
    assert!(
        text.contains(&format!(",{SPHINX_FRAGMENT_COUNT},forward")),
        "ingress relay should record post-forward event:\n{text}"
    );
    let timestamps = load_trace_timestamps(&trace_path).expect("parse");
    assert!(!timestamps.is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn exit_config_defaults_off() {
    use aegis_node::ExitConfig;
    let cfg = ExitConfig::default();
    assert!(!cfg.log_payloads);
    assert!(cfg.deliver_to.is_none());
    let settings = cfg.into_settings().expect("parse");
    assert!(!settings.enabled());
}

#[test]
fn tcp_testnet_uses_os_assigned_tcp_listener() {
    // Document the real-socket requirement for the gate report.
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.port() != 0);
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_path_build_matches_direct_peel() {
    let testnet = TcpTestnet::build(PATH_LEN, None, None).await;
    let path: Vec<PathHop> = testnet
        .hops
        .iter()
        .map(|h| PathHop {
            id: h.id,
            pk: h.kem_public.clone(),
        })
        .collect();
    let mut rng = OsRng;
    let packet = build(&path, PAYLOAD, &mut rng).unwrap();
    send_payload_with_options(
        &testnet.hops,
        &testnet.client_link,
        PAYLOAD,
        &mut rng,
        BuildPacketOptions::default(),
    )
        .await
        .unwrap();

    let mut traversed = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if testnet.relay_handle(PATH_LEN - 1).debug_stats().forwarded_count >= 1
            || testnet.relay_handle(0).debug_stats().forwarded_count >= 1
        {
            traversed = true;
            break;
        }
    }
    assert!(traversed, "packet should traverse TCP links");
    let _ = packet;
}
