//! Phase-3 gate: in-process testnet routes Sphinx e2e; latency sanity vs §7 budget.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use aegis_crypto::kem::{RelayKemPublic, RelayKemSecret};
use aegis_crypto::sphinx::{build, tamper_beta_byte, PathHop, SphinxPacket};
use aegis_relay::{
    packet_delta, ForwardedPacket, RelayConfig, RelayId, RelayNode, DEFAULT_MU,
};
use rand_core::OsRng;
use tokio::sync::mpsc;

const PATH_LEN: usize = 4;
const PAYLOAD: &[u8] = b"phase3-gate-payload";

/// One mix in the in-process testnet.
struct RelaySlot {
    handle: aegis_relay::RelayHandle,
    inbound_tx: mpsc::Sender<SphinxPacket>,
    _task: tokio::task::JoinHandle<()>,
}

/// In-process testnet: one `RelayNode` per hop, wired by `next_hop` via a shared route table.
struct Testnet {
    relays: Vec<RelaySlot>,
}

impl Testnet {
    fn make_id(index: usize) -> RelayId {
        let mut id_bytes = [0u8; 32];
        id_bytes[0] = (index + 1) as u8;
        RelayId(id_bytes)
    }

    /// Build a linear testnet whose relay keys match `secrets`.
    async fn build(
        secrets: Vec<RelayKemSecret>,
        mu: f64,
        exit_tx: Option<mpsc::Sender<ForwardedPacket>>,
    ) -> Self {
        let path_len = secrets.len();
        let mut routes = HashMap::new();
        let mut inbound_rxs = Vec::with_capacity(path_len);

        for i in 0..path_len {
            let id = Self::make_id(i);
            let (inbound_tx, inbound_rx) = mpsc::channel(64);
            routes.insert(id, inbound_tx);
            inbound_rxs.push(inbound_rx);
        }

        let mut relays = Vec::with_capacity(path_len);

        for (i, secret) in secrets.into_iter().enumerate() {
            let id = Self::make_id(i);
            let inbound_tx = routes.get(&id).unwrap().clone();
            let inbound_rx = inbound_rxs.remove(0);

            let (outbound_tx, outbound_rx) = mpsc::channel(64);
            let node = RelayNode::new(id, secret, RelayConfig::new(mu));
            let (handle, task) = node.spawn(inbound_rx, outbound_tx, None, OsRng);

            relays.push(RelaySlot {
                handle,
                inbound_tx,
                _task: task,
            });

            let routes_clone = routes.clone();
            let is_exit = i == path_len - 1;
            let exit_tx = exit_tx.clone();
            tokio::spawn(async move {
                let mut outbound_rx = outbound_rx;
                while let Some(fwd) = outbound_rx.recv().await {
                    if is_exit {
                        if let Some(ref tx) = exit_tx {
                            let _ = tx.send(fwd.clone()).await;
                        }
                    }
                    if let Some(tx) = routes_clone.get(&fwd.next_hop) {
                        let _ = tx.send(fwd.packet).await;
                    }
                }
            });
        }

        Self { relays }
    }

    fn entry_inbound(&self) -> &mpsc::Sender<SphinxPacket> {
        &self.relays[0].inbound_tx
    }

    fn relay_handle(&self, index: usize) -> &aegis_relay::RelayHandle {
        &self.relays[index].handle
    }
}

fn make_path_keys(path_len: usize) -> (Vec<PathHop>, Vec<RelayKemSecret>, Vec<RelayKemPublic>) {
    let mut rng = OsRng;
    let mut hops = Vec::with_capacity(path_len);
    let mut secrets = Vec::with_capacity(path_len);
    let mut publics = Vec::with_capacity(path_len);

    for i in 0..path_len {
        let (sec, pk) = RelayKemSecret::generate(&mut rng);
        let mut id = [0u8; 32];
        id[0] = (i + 1) as u8;
        hops.push(PathHop { id, pk: pk.clone() });
        secrets.push(sec);
        publics.push(pk);
    }

    (hops, secrets, publics)
}

#[test]
fn four_hop_sync_peel_delivers_payload() {
    let (path, secrets, _) = make_path_keys(PATH_LEN);
    let mut rng = OsRng;
    let packet = build(&path, PAYLOAD, &mut rng).unwrap();
    let mut current = packet;
    for (i, secret) in secrets.iter().enumerate() {
        let mut replay = aegis_crypto::replay::ReplayCache::new();
        current = match aegis_crypto::sphinx::process(&current, secret, &mut replay)
            .unwrap_or_else(|e| panic!("hop {i}: {e:?}"))
        {
            aegis_crypto::sphinx::Processed::Forward { packet, .. } => packet,
            other => panic!("hop {i}: {other:?}"),
        };
    }
    assert_eq!(&packet_delta(&current)[..PAYLOAD.len()], PAYLOAD);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn testnet_routes_sphinx_e2e_payload_and_latency() {
    let (path, secrets, _publics) = make_path_keys(PATH_LEN);
    let (exit_tx, mut exit_rx) = mpsc::channel(1);
    let testnet = Testnet::build(secrets, DEFAULT_MU, Some(exit_tx)).await;

    let mut rng = OsRng;
    let packet = build(&path, PAYLOAD, &mut rng).expect("build sphinx packet");

    let t0 = Instant::now();
    testnet
        .entry_inbound()
        .send(packet)
        .await
        .expect("inject at guard");

    let exit = tokio::time::timeout(Duration::from_secs(15), exit_rx.recv())
        .await
        .expect("timed out waiting for exit forward")
        .expect("exit channel closed");

    let e2e = t0.elapsed();
    let delta = packet_delta(&exit.packet);

    assert_eq!(
        &delta[..PAYLOAD.len()],
        PAYLOAD,
        "payload mismatch after {PATH_LEN} hops"
    );

    // Per-hop delays are Exp(μ); single-trial e2e is variable — loose bounds only.
    assert!(e2e > Duration::from_millis(1), "e2e latency should be positive");
    assert!(
        e2e < Duration::from_secs(12),
        "e2e latency {e2e:?} exceeded generous upper bound"
    );

    // §7 ballpark: L=4, μ=2 => mean mixing ~2s. Print for the gate log.
    eprintln!(
        "testnet e2e latency: {e2e:?} (per-hop delay this exit: {:?}; §7 target mean ~2s for L=4)",
        exit.delay_applied
    );

    assert_eq!(
        testnet.relay_handle(0).debug_stats().forwarded_count,
        1,
        "first relay should have forwarded once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn testnet_mean_latency_over_trials_near_budget() {
    let trials = 8;
    let mut samples = Vec::with_capacity(trials);

    for _ in 0..trials {
        let (path, secrets, _) = make_path_keys(PATH_LEN);
        let (exit_tx, mut exit_rx) = mpsc::channel(1);
        let testnet = Testnet::build(secrets, DEFAULT_MU, Some(exit_tx)).await;

        let mut rng = OsRng;
        let packet = build(&path, PAYLOAD, &mut rng).unwrap();

        let t0 = Instant::now();
        testnet.entry_inbound().send(packet).await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(15), exit_rx.recv())
            .await
            .unwrap()
            .unwrap();
        samples.push(t0.elapsed().as_secs_f64());
    }

    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    eprintln!("testnet mean e2e latency over {trials} trials: {mean:.3}s (§7 mixing mean ~2s)");

    // Soft check: mean within a wide band around 2s (queue + scheduling slack).
    assert!(
        mean > 0.5 && mean < 6.0,
        "mean latency {mean}s outside generous §7 band"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampered_packet_rejected_without_forward() {
    let (path, secrets, _) = make_path_keys(PATH_LEN);
    let (exit_tx, mut exit_rx) = mpsc::channel(1);
    let testnet = Testnet::build(secrets, DEFAULT_MU, Some(exit_tx)).await;

    let mut rng = OsRng;
    let mut packet = build(&path, PAYLOAD, &mut rng).unwrap();
    tamper_beta_byte(&mut packet, 8);

    testnet.entry_inbound().send(packet).await.unwrap();

    // Relay 0 should reject; nothing reaches exit or downstream relays.
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        testnet.relay_handle(0).debug_stats().integrity_error_count,
        1,
        "tampered packet should increment integrity error count"
    );
    assert_eq!(
        testnet.relay_handle(0).debug_stats().forwarded_count,
        0,
        "tampered packet must not be forwarded"
    );
    assert_eq!(
        testnet.relay_handle(1).debug_stats().forwarded_count,
        0,
        "downstream relay must not see traffic"
    );
    assert!(exit_rx.try_recv().is_err(), "exit channel must be empty");
}
