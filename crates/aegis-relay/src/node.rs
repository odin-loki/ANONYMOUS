//! Async mix relay node: Sphinx peel, Exp(μ) delay, forward, bulk cover padding.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aegis_crypto::cell::Cell;
use aegis_crypto::kem::RelayKemSecret;
use aegis_crypto::replay::ReplayCache;
use aegis_crypto::sphinx::{self, Processed, SphinxPacket};
use aegis_crypto::CryptoError;
use aegis_negotiator::cover::CoverRequirement;
use aegis_negotiator::SecurityDial;
use rand_core::{CryptoRngCore, RngCore};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use crate::config::RelayConfig;
use crate::cover_flow::{BulkRoundCommand, BulkRoundTracker, CoverFlowConfig};
use crate::delay::sample_mixing_delay;
use crate::relay_id::RelayId;

/// A peeled packet ready for routing after the per-hop mixing delay.
#[derive(Debug, Clone)]
pub struct ForwardedPacket {
    pub next_hop: RelayId,
    pub packet: SphinxPacket,
    /// Mixing delay applied at this hop before forwarding.
    pub delay_applied: Duration,
}

/// GPA-safe aggregate counters for external-facing surfaces (metrics, health checks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayCoarseStats {
    /// Successfully processed ingress packets (forwarded, loop-returned, or dropped cover).
    pub processed_ok: u64,
    /// Failed peel/decrypt (integrity, replay, and other errors aggregated).
    pub processed_fail: u64,
    /// Synthetic cover flows emitted on the wire during bulk rounds.
    pub cover_emitted: u64,
}

impl RelayCoarseStats {
    /// Self-ingress failure rate: `processed_fail / (processed_ok + processed_fail)`.
    pub fn failure_rate(&self) -> Option<f64> {
        let total = self.processed_ok.saturating_add(self.processed_fail);
        if total == 0 {
            None
        } else {
            Some(self.processed_fail as f64 / total as f64)
        }
    }
}

/// Fine-grained relay counters — **internal / test only**.
///
/// Do not export to untrusted observers (metrics scrapers, external APIs). Per-error-type
/// breakdown enables GPA load inference under flood (see threat model §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayDebugStats {
    pub loop_return_count: u64,
    pub dropped_count: u64,
    pub cover_flow_count: u64,
    pub cover_cell_count: u64,
    pub integrity_error_count: u64,
    pub replay_error_count: u64,
    pub other_error_count: u64,
    pub forwarded_count: u64,
}

/// Lightweight observability counters (internal only — not a wire signal).
#[derive(Debug)]
struct RelayStats {
    loop_return_count: AtomicU64,
    dropped_count: AtomicU64,
    cover_flow_count: AtomicU64,
    cover_cell_count: AtomicU64,
    integrity_error_count: AtomicU64,
    replay_error_count: AtomicU64,
    other_error_count: AtomicU64,
    forwarded_count: AtomicU64,
}

impl RelayStats {
    fn new() -> Self {
        Self {
            loop_return_count: AtomicU64::new(0),
            dropped_count: AtomicU64::new(0),
            cover_flow_count: AtomicU64::new(0),
            cover_cell_count: AtomicU64::new(0),
            integrity_error_count: AtomicU64::new(0),
            replay_error_count: AtomicU64::new(0),
            other_error_count: AtomicU64::new(0),
            forwarded_count: AtomicU64::new(0),
        }
    }

    fn coarse(&self) -> RelayCoarseStats {
        let loop_return = self.loop_return_count.load(Ordering::Relaxed);
        let dropped = self.dropped_count.load(Ordering::Relaxed);
        let forwarded = self.forwarded_count.load(Ordering::Relaxed);
        let integrity = self.integrity_error_count.load(Ordering::Relaxed);
        let replay = self.replay_error_count.load(Ordering::Relaxed);
        let other = self.other_error_count.load(Ordering::Relaxed);
        RelayCoarseStats {
            processed_ok: forwarded + loop_return + dropped,
            processed_fail: integrity + replay + other,
            cover_emitted: self.cover_flow_count.load(Ordering::Relaxed),
        }
    }

    fn debug(&self) -> RelayDebugStats {
        RelayDebugStats {
            loop_return_count: self.loop_return_count.load(Ordering::Relaxed),
            dropped_count: self.dropped_count.load(Ordering::Relaxed),
            cover_flow_count: self.cover_flow_count.load(Ordering::Relaxed),
            cover_cell_count: self.cover_cell_count.load(Ordering::Relaxed),
            integrity_error_count: self.integrity_error_count.load(Ordering::Relaxed),
            replay_error_count: self.replay_error_count.load(Ordering::Relaxed),
            other_error_count: self.other_error_count.load(Ordering::Relaxed),
            forwarded_count: self.forwarded_count.load(Ordering::Relaxed),
        }
    }
}

/// A round-control command paired with an ack channel.
///
/// [`BulkRoundCommand::Begin`]/[`BulkRoundCommand::EndRound`] travel on their own
/// `mpsc` channel, separate from `inbound`'s packet channel. Without an explicit
/// ack, `begin_bulk_round().await` returning only means the command was *enqueued*
/// — `tokio::select!` gives no ordering guarantee between the two channels, so a
/// packet sent immediately after `begin_bulk_round().await` could race ahead of
/// the relay loop actually processing `Begin` and be counted while the round is
/// still inactive (silently dropped by [`BulkRoundTracker::observe_real_flow`]).
/// The ack closes that race: `begin_bulk_round`/`end_bulk_round` don't return
/// until the relay loop has actually applied the command.
type RoundControlMsg = (BulkRoundCommand, tokio::sync::oneshot::Sender<()>);

/// Error returned when the relay's processing task has already stopped.
#[derive(Debug, thiserror::Error)]
#[error("relay task is no longer running")]
pub struct RelayStoppedError;

/// Handle to a running relay task; exposes accounting counters and bulk-round control.
#[derive(Clone, Debug)]
pub struct RelayHandle {
    pub id: RelayId,
    stats: Arc<RelayStats>,
    round_tx: mpsc::Sender<RoundControlMsg>,
}

impl RelayHandle {
    /// Aggregate counters safe for external export (no per-error-type breakdown).
    pub fn coarse_stats(&self) -> RelayCoarseStats {
        self.stats.coarse()
    }

    /// Fine-grained counters for tests and in-process diagnostics only.
    ///
    /// **Do not export to untrusted observers** — per-error-type fields enable GPA
    /// load inference under flood.
    pub fn debug_stats(&self) -> RelayDebugStats {
        self.stats.debug()
    }

    /// Declare an L2 (or other dial) bulk round with target observed flow count.
    ///
    /// Does not return until the relay loop has actually applied `Begin` — safe to
    /// send inbound packets immediately after this resolves without racing the
    /// round's activation (see [`RoundControlMsg`]).
    pub async fn begin_bulk_round(
        &self,
        dial: SecurityDial,
        requirement: CoverRequirement,
    ) -> Result<(), RelayStoppedError> {
        self.send_round_cmd(BulkRoundCommand::Begin { dial, requirement })
            .await
    }

    /// Close the active bulk round and emit synthetic cover flows if required.
    ///
    /// Does not return until the relay loop has applied the close, emitted cover on
    /// the optional outbound channel, and updated cover counters.
    pub async fn end_bulk_round(&self) -> Result<(), RelayStoppedError> {
        self.send_round_cmd(BulkRoundCommand::EndRound).await
    }

    async fn send_round_cmd(&self, cmd: BulkRoundCommand) -> Result<(), RelayStoppedError> {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        self.round_tx
            .send((cmd, ack_tx))
            .await
            .map_err(|_| RelayStoppedError)?;
        ack_rx.await.map_err(|_| RelayStoppedError)
    }
}

/// In-process mix relay: decrypt one Sphinx layer, mix, forward.
pub struct RelayNode {
    id: RelayId,
    secret: RelayKemSecret,
    config: RelayConfig,
}

impl RelayNode {
    pub fn new(id: RelayId, secret: RelayKemSecret, config: RelayConfig) -> Self {
        Self { id, secret, config }
    }

    /// Spawn the async relay loop on the current tokio runtime.
    ///
    /// `inbound` receives raw Sphinx packets; `outbound` emits peeled packets after
    /// the per-hop Exp(μ) mixing delay. When `cover_tx` is set, synthetic cover cell
    /// bursts from [`RelayHandle::end_bulk_round`] are sent there for link-layer sealing
    /// (see [`crate::net::spawn_link_bridge`]). Bulk cover padding is driven via
    /// [`RelayHandle::begin_bulk_round`] / [`RelayHandle::end_bulk_round`].
    pub fn spawn<R: RngCore + CryptoRngCore + Send + 'static>(
        self,
        inbound: mpsc::Receiver<SphinxPacket>,
        outbound: mpsc::Sender<ForwardedPacket>,
        cover_tx: Option<mpsc::Sender<Vec<Cell>>>,
        mut rng: R,
    ) -> (RelayHandle, JoinHandle<()>) {
        let stats = Arc::new(RelayStats::new());
        let (round_tx, mut round_rx) = mpsc::channel(16);
        let handle = RelayHandle {
            id: self.id,
            stats: Arc::clone(&stats),
            round_tx,
        };
        let replay = Arc::new(Mutex::new(ReplayCache::new()));
        let cover_config = CoverFlowConfig::default();

        let join = tokio::spawn(async move {
            let mut inbound = inbound;
            let mut round = BulkRoundTracker::new();

            loop {
                tokio::select! {
                    cmd = round_rx.recv() => {
                        match cmd {
                            Some((BulkRoundCommand::Begin { dial, requirement }, ack)) => {
                                round.begin(dial, requirement);
                                let _ = ack.send(());
                            }
                            Some((BulkRoundCommand::EndRound, ack)) => {
                                if let Some(result) = round.close_and_emit(&mut rng, &cover_config) {
                                    stats
                                        .cover_flow_count
                                        .fetch_add(result.cover_flow_count as u64, Ordering::Relaxed);
                                    stats
                                        .cover_cell_count
                                        .fetch_add(result.cover_cell_count, Ordering::Relaxed);
                                    if let Some(ref tx) = cover_tx {
                                        for flow in result.cover_flows {
                                            if tx.send(flow.cells).await.is_err() {
                                                break;
                                            }
                                        }
                                    }
                                }
                                let _ = ack.send(());
                            }
                            None => break,
                        }
                    }
                    packet = inbound.recv() => {
                        match packet {
                            Some(packet) => {
                                if process_one_packet(
                                    &packet,
                                    &self,
                                    &replay,
                                    &outbound,
                                    &stats,
                                    &mut round,
                                    &mut rng,
                                )
                                .await
                                .is_err()
                                {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        (handle, join)
    }
}

async fn process_one_packet<R: RngCore + CryptoRngCore>(
    packet: &SphinxPacket,
    node: &RelayNode,
    replay: &Arc<Mutex<ReplayCache>>,
    outbound: &mpsc::Sender<ForwardedPacket>,
    stats: &Arc<RelayStats>,
    round: &mut BulkRoundTracker,
    rng: &mut R,
) -> Result<(), ()> {
    let result = {
        let mut cache = replay.lock().await;
        sphinx::process(packet, &node.secret, &mut cache)
    };

    match result {
        Ok(Processed::Forward { next_hop, packet }) => {
            round.observe_real_flow();
            let delay = sample_mixing_delay(node.config.mu, rng);
            tokio::time::sleep(delay).await;
            stats.forwarded_count.fetch_add(1, Ordering::Relaxed);
            outbound
                .send(ForwardedPacket {
                    next_hop: RelayId(next_hop),
                    packet,
                    delay_applied: delay,
                })
                .await
                .map_err(|_| ())
        }
        Ok(Processed::LoopReturned) => {
            stats.loop_return_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        Ok(Processed::Drop) => {
            stats.dropped_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        Err(CryptoError::IntegrityFailure) => {
            stats.integrity_error_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        Err(CryptoError::Replay) => {
            stats.replay_error_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        Err(_) => {
            stats.other_error_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }
}

/// Extract the `delta` region from a Sphinx packet (for post-path payload checks).
pub fn packet_delta(packet: &SphinxPacket) -> &[u8] {
    let bytes = packet.as_bytes();
    let off = aegis_crypto::sphinx::ALPHA_LEN
        + aegis_crypto::sphinx::BETA_LEN
        + aegis_crypto::sphinx::GAMMA_LEN;
    &bytes[off..off + aegis_crypto::sphinx::DELTA_LEN]
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_crypto::cell::Command;
    use aegis_crypto::fragment::SPHINX_FRAGMENT_COUNT;
    use aegis_crypto::kem::RelayKemSecret;
    use aegis_crypto::sphinx::{build, PathHop};
    use aegis_negotiator::cover::CoverRequirement;
    use rand_core::OsRng;
    use tokio::sync::mpsc;

    fn relay_test_path(
        rng: &mut OsRng,
    ) -> (
        RelayKemSecret,
        RelayId,
        Vec<PathHop>,
        mpsc::Sender<SphinxPacket>,
        mpsc::Receiver<SphinxPacket>,
        mpsc::Sender<ForwardedPacket>,
        mpsc::Receiver<ForwardedPacket>,
    ) {
        let (guard_sec, guard_pk) = RelayKemSecret::generate(rng);
        let (_exit_sec, exit_pk) = RelayKemSecret::generate(rng);
        let mut guard_id = [0u8; 32];
        guard_id[0] = 1;
        let mut exit_id = [0u8; 32];
        exit_id[0] = 2;
        let path = vec![
            PathHop {
                id: guard_id,
                pk: guard_pk,
            },
            PathHop {
                id: exit_id,
                pk: exit_pk,
            },
        ];
        let (inbound_tx, inbound_rx) = mpsc::channel(8);
        let (outbound_tx, outbound_rx) = mpsc::channel(8);
        (
            guard_sec,
            RelayId(guard_id),
            path,
            inbound_tx,
            inbound_rx,
            outbound_tx,
            outbound_rx,
        )
    }

    #[tokio::test]
    async fn cover_flow_count_accumulates_across_rounds() {
        let mut rng = OsRng;
        let (guard_sec, guard_id, path, inbound_tx, inbound_rx, outbound_tx, mut outbound_rx) =
            relay_test_path(&mut rng);

        let node = RelayNode::new(guard_id, guard_sec, RelayConfig::default());
        let (handle, _task) = node.spawn(inbound_rx, outbound_tx, None, OsRng);

        // Round 1: L2, target 3, one real flow -> 2 cover flows.
        handle
            .begin_bulk_round(SecurityDial::L2UniformBatched, CoverRequirement::new(3))
            .await
            .unwrap();
        let packet = build(&path, b"r1", &mut rng).unwrap();
        inbound_tx.send(packet).await.unwrap();
        let _ = outbound_rx.recv().await;
        handle.end_bulk_round().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(handle.debug_stats().cover_flow_count, 2);
        assert_eq!(handle.coarse_stats().cover_emitted, 2);
        assert_eq!(handle.debug_stats().forwarded_count, 1);

        // Round 2: L0 — no cover even when under target.
        handle
            .begin_bulk_round(SecurityDial::L0Raw, CoverRequirement::new(3))
            .await
            .unwrap();
        let packet = build(&path, b"r2", &mut rng).unwrap();
        inbound_tx.send(packet).await.unwrap();
        let _ = outbound_rx.recv().await;
        handle.end_bulk_round().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            handle.debug_stats().cover_flow_count,
            2,
            "L0 must not add cover flows"
        );

        // Round 3: L2, target 2, two real flows -> 0 cover.
        handle
            .begin_bulk_round(SecurityDial::L2UniformBatched, CoverRequirement::new(2))
            .await
            .unwrap();
        for payload in [b"r3a".as_slice(), b"r3b"] {
            let packet = build(&path, payload, &mut rng).unwrap();
            inbound_tx.send(packet).await.unwrap();
            let _ = outbound_rx.recv().await;
        }
        handle.end_bulk_round().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(handle.debug_stats().cover_flow_count, 2);
        assert_eq!(handle.debug_stats().forwarded_count, 4);
    }

    #[tokio::test]
    async fn end_bulk_round_emits_cover_cells_on_outbound_channel() {
        let mut rng = OsRng;
        let (guard_sec, guard_id, path, inbound_tx, inbound_rx, outbound_tx, mut outbound_rx) =
            relay_test_path(&mut rng);

        let (cover_tx, mut cover_rx) = mpsc::channel(8);
        let node = RelayNode::new(guard_id, guard_sec, RelayConfig::default());
        let (handle, _task) = node.spawn(inbound_rx, outbound_tx, Some(cover_tx), OsRng);

        handle
            .begin_bulk_round(SecurityDial::L2UniformBatched, CoverRequirement::new(4))
            .await
            .unwrap();
        let packet = build(&path, b"cover-wire", &mut rng).unwrap();
        inbound_tx.send(packet).await.unwrap();
        let _ = outbound_rx.recv().await;

        handle.end_bulk_round().await.unwrap();

        let mut cover_bursts = 0usize;
        let mut cover_cells = 0usize;
        while let Ok(cells) = cover_rx.try_recv() {
            cover_bursts += 1;
            assert_eq!(cells.len(), SPHINX_FRAGMENT_COUNT);
            assert!(
                cells
                    .iter()
                    .all(|c| c.as_bytes()[0] == Command::SphinxFragment as u8)
            );
            cover_cells += cells.len();
        }
        assert_eq!(cover_bursts, 3, "target 4 with 1 real flow => 3 cover bursts");
        assert_eq!(
            cover_cells,
            3 * SPHINX_FRAGMENT_COUNT,
            "every cover flow must hit the outbound channel"
        );
        assert_eq!(handle.debug_stats().cover_cell_count, cover_cells as u64);
    }

    #[tokio::test]
    async fn coarse_stats_aggregate_without_error_breakdown() {
        let mut rng = OsRng;
        let (guard_sec, guard_id, path, inbound_tx, inbound_rx, outbound_tx, mut outbound_rx) =
            relay_test_path(&mut rng);

        let node = RelayNode::new(guard_id, guard_sec, RelayConfig::default());
        let (handle, _task) = node.spawn(inbound_rx, outbound_tx, None, OsRng);

        let packet = build(&path, b"ok", &mut rng).unwrap();
        inbound_tx.send(packet).await.unwrap();
        let _ = outbound_rx.recv().await;

        let coarse = handle.coarse_stats();
        assert_eq!(coarse.processed_ok, 1);
        assert_eq!(coarse.processed_fail, 0);
        assert_eq!(coarse.cover_emitted, 0);
        // Fine-grained fields remain available via debug_stats only.
        assert_eq!(handle.debug_stats().forwarded_count, 1);
    }

    #[test]
    fn coarse_stats_failure_rate() {
        let stats = RelayCoarseStats {
            processed_ok: 7,
            processed_fail: 3,
            cover_emitted: 0,
        };
        assert!((stats.failure_rate().unwrap() - 0.3).abs() < f64::EPSILON);
        assert!(RelayCoarseStats {
            processed_ok: 0,
            processed_fail: 0,
            cover_emitted: 0,
        }
        .failure_rate()
        .is_none());
    }
}
