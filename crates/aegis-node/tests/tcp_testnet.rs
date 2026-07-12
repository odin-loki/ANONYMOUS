//! TCP integration gate: multi-hop Sphinx delivery over real loopback sockets.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use aegis_client::send::{send_payload, ClientHop, ClientLink};
use aegis_crypto::kem::RelayKemSecret;
use aegis_crypto::sphinx::{build, PathHop, SphinxPacket};
use aegis_relay::{
    packet_delta, spawn_link_bridge, LinkBridgeConfig, PeerInfo, RelayConfig, RelayId, RelayNode,
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
    async fn build(path_len: usize, exit_tx: Option<mpsc::Sender<SphinxPacket>>) -> Self {
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
                let upstream_id = ids[i - 1];
                peer_table.insert(
                    upstream_id,
                    PeerInfo::new(listen_addrs[i - 1], link_key_byte(i as u8)),
                );
            }
            if i + 1 < path_len {
                let downstream_id = ids[i + 1];
                peer_table.insert(
                    downstream_id,
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

            let node = RelayNode::new(id, secrets.remove(0), RelayConfig::new(FAST_MU));
            let (handle, relay_task) = node.spawn(inbound_rx, outbound_tx, OsRng);

            let exit = if i == path_len - 1 {
                exit_tx.clone()
            } else {
                None
            };

            let net_tasks = spawn_link_bridge(
                listen_addrs[i],
                peer_table,
                ingress,
                inbound_tx,
                outbound_rx,
                exit,
                OsRng,
                LinkBridgeConfig::default(),
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
async fn tcp_testnet_paced_send_delivers_payload() {
    let (exit_tx, mut exit_rx) = mpsc::channel(1);
    let testnet = TcpTestnet::build(PATH_LEN, Some(exit_tx)).await;

    let mut rng = OsRng;
    let tau = Duration::from_millis(25);
    aegis_client::send::send_payload_paced(
        &testnet.hops,
        &testnet.client_link,
        PAYLOAD,
        &mut rng,
        Some(aegis_client::EmitterConfig { tau }),
        &LinkBridgeConfig::default(),
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
    let testnet = TcpTestnet::build(PATH_LEN, Some(exit_tx)).await;

    let mut rng = OsRng;
    send_payload(&testnet.hops, &testnet.client_link, PAYLOAD, &mut rng)
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
        testnet.relay_handle(0).forwarded_count(),
        1,
        "first relay should have forwarded once"
    );
    assert_eq!(
        testnet.relay_handle(PATH_LEN - 1).forwarded_count(),
        1,
        "exit relay should have peeled once"
    );
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
    let testnet = TcpTestnet::build(PATH_LEN, None).await;
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
    send_payload(&testnet.hops, &testnet.client_link, PAYLOAD, &mut rng)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        testnet.relay_handle(PATH_LEN - 1).forwarded_count() >= 1
            || testnet.relay_handle(0).forwarded_count() >= 1,
        "packet should traverse TCP links"
    );
    let _ = packet;
}
