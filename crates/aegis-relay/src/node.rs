//! Async mix relay node: Sphinx peel, Exp(μ) delay, forward, bulk cover padding.
//!
//! ## Bounded queue / backpressure policy
//!
//! Production inbound, outbound, and cover paths use bounded `mpsc` channels of
//! capacity [`RELAY_CHANNEL_CAPACITY`] (64). When a queue is full, senders use
//! [`try_send_drop_newest`]: the **newest** item is dropped and a coarse counter
//! is incremented — the sender never blocks forever under flood.
//!
//! This complements (does not replace) link-bridge ingress rate limiting and
//! per-peer fair drain in [`crate::net`]: rate-limit drops frames before
//! reassembly; each connection enqueues into its own bounded peer queue; a
//! weighted fair drain feeds the shared mix inbound. Queue drops apply on peer
//! queues or the shared inbound (drop-newest) so one peer cannot monopolize.

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

use crate::config::{BulkCoverConfig, CoverPolicyError, RelayConfig};
use crate::cover_flow::{BulkRoundCommand, BulkRoundTracker, CoverFlowConfig};
use crate::delay::sample_mixing_delay;
use crate::relay_id::RelayId;

/// Production capacity for relay inbound / outbound / cover `mpsc` channels.
pub const RELAY_CHANNEL_CAPACITY: usize = 64;

/// Enqueue with drop-newest backpressure: never blocks the sender on a full queue.
///
/// On [`mpsc::error::TrySendError::Full`], drops `item` (newest arrival) and
/// increments `dropped`. Returns `Err(())` only when the channel is closed.
pub fn try_send_drop_newest<T>(
    tx: &mpsc::Sender<T>,
    item: T,
    dropped: &AtomicU64,
) -> Result<(), ()> {
    match tx.try_send(item) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => {
            dropped.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        Err(mpsc::error::TrySendError::Closed(_)) => Err(()),
    }
}

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
    /// Outbound queue drops under [`try_send_drop_newest`] (full bounded channel).
    pub queue_dropped: u64,
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
    queue_dropped: AtomicU64,
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
            queue_dropped: AtomicU64::new(0),
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
            queue_dropped: self.queue_dropped.load(Ordering::Relaxed),
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
    ///
    /// When [`RelayConfig::bulk_cover`] has [`BulkCoverConfig::require`], this fails
    /// closed if `cover_tx` is `None` or cover is disabled. Callers that enable cover
    /// should then invoke [`start_bulk_cover`] so a misconfigured node cannot accept
    /// bulk while silently skipping cover rounds.
    pub fn spawn<R: RngCore + CryptoRngCore + Send + 'static>(
        self,
        inbound: mpsc::Receiver<SphinxPacket>,
        outbound: mpsc::Sender<ForwardedPacket>,
        cover_tx: Option<mpsc::Sender<Vec<Cell>>>,
        mut rng: R,
    ) -> Result<(RelayHandle, JoinHandle<()>), CoverPolicyError> {
        self.config
            .bulk_cover
            .validate_spawn(cover_tx.is_some())?;

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

        Ok((handle, join))
    }
}

/// Begin (and optionally rotate) bulk cover rounds for a running relay.
///
/// When `policy.enabled` is false, this is a no-op. When enabled, opens an L2 bulk
/// round immediately and, if `policy.round_secs > 0`, spawns a task that periodically
/// closes and re-opens the round so cover padding can emit on the cover channel.
///
/// Returns the optional rotation task handle (abort on shutdown).
pub async fn start_bulk_cover(
    handle: &RelayHandle,
    policy: &BulkCoverConfig,
) -> Result<Option<JoinHandle<()>>, RelayStoppedError> {
    if !policy.enabled {
        return Ok(None);
    }

    handle
        .begin_bulk_round(policy.dial, policy.requirement())
        .await?;

    if policy.round_secs == 0 {
        return Ok(None);
    }

    let handle = handle.clone();
    let dial = policy.dial;
    let requirement = policy.requirement();
    let period = Duration::from_secs(policy.round_secs);
    let task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // First tick completes immediately; skip so we don't end the just-started round.
        interval.tick().await;
        loop {
            interval.tick().await;
            if handle.end_bulk_round().await.is_err() {
                break;
            }
            if handle.begin_bulk_round(dial, requirement).await.is_err() {
                break;
            }
        }
    });
    Ok(Some(task))
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
            try_send_drop_newest(
                outbound,
                ForwardedPacket {
                    next_hop: RelayId(next_hop),
                    packet,
                    delay_applied: delay,
                },
                &stats.queue_dropped,
            )
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
    use crate::config::{BulkCoverConfig, CoverPolicyError, DEFAULT_MU};
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
        let (handle, _task) = node.spawn(inbound_rx, outbound_tx, None, OsRng).unwrap();

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
        let (handle, _task) = node
            .spawn(inbound_rx, outbound_tx, Some(cover_tx), OsRng)
            .unwrap();

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
        let (handle, _task) = node.spawn(inbound_rx, outbound_tx, None, OsRng).unwrap();

        let packet = build(&path, b"ok", &mut rng).unwrap();
        inbound_tx.send(packet).await.unwrap();
        let _ = outbound_rx.recv().await;

        let coarse = handle.coarse_stats();
        assert_eq!(coarse.processed_ok, 1);
        assert_eq!(coarse.processed_fail, 0);
        assert_eq!(coarse.cover_emitted, 0);
        assert_eq!(coarse.queue_dropped, 0);
        // Fine-grained fields remain available via debug_stats only.
        assert_eq!(handle.debug_stats().forwarded_count, 1);
    }

    #[test]
    fn coarse_stats_failure_rate() {
        let stats = RelayCoarseStats {
            processed_ok: 7,
            processed_fail: 3,
            cover_emitted: 0,
            queue_dropped: 0,
        };
        assert!((stats.failure_rate().unwrap() - 0.3).abs() < f64::EPSILON);
        assert!(RelayCoarseStats {
            processed_ok: 0,
            processed_fail: 0,
            cover_emitted: 0,
            queue_dropped: 0,
        }
        .failure_rate()
        .is_none());
    }

    #[tokio::test]
    async fn outbound_full_drops_newest_without_panic() {
        use aegis_crypto::sphinx::SPHINX_PACKET_LEN;

        let mut rng = OsRng;
        let (guard_sec, guard_pk) = RelayKemSecret::generate(&mut rng);
        let (_exit_sec, exit_pk) = RelayKemSecret::generate(&mut rng);
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
        let (outbound_tx, mut outbound_rx) = mpsc::channel(1);
        // Occupy the single slot before spawn so the first real forward is drop-newest.
        outbound_tx
            .try_send(ForwardedPacket {
                next_hop: RelayId([0u8; 32]),
                packet: SphinxPacket::from_bytes([0u8; SPHINX_PACKET_LEN]),
                delay_applied: Duration::ZERO,
            })
            .unwrap();

        // Huge μ → near-zero mixing delay so this does not flake under suite load.
        let node = RelayNode::new(
            RelayId(guard_id),
            guard_sec,
            RelayConfig::new(1_000_000.0),
        );
        let (handle, _task) = node.spawn(inbound_rx, outbound_tx, None, OsRng).unwrap();

        inbound_tx
            .send(build(&path, b"ok", &mut rng).unwrap())
            .await
            .unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while handle.coarse_stats().queue_dropped < 1 {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            handle.coarse_stats().queue_dropped >= 1,
            "full outbound must count drop-newest (processed_ok={}, fail={})",
            handle.coarse_stats().processed_ok,
            handle.coarse_stats().processed_fail,
        );
        // Placeholder still present; real forward was dropped.
        let kept = outbound_rx.try_recv().expect("bounded slot still holds prior item");
        assert_eq!(kept.next_hop, RelayId([0u8; 32]));
        assert!(outbound_rx.try_recv().is_err());
    }

    #[test]
    fn try_send_drop_newest_counts_and_delivers() {
        let (tx, mut rx) = mpsc::channel::<u32>(1);
        let dropped = AtomicU64::new(0);
        assert!(try_send_drop_newest(&tx, 1, &dropped).is_ok());
        assert!(try_send_drop_newest(&tx, 2, &dropped).is_ok());
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        assert_eq!(rx.try_recv().unwrap(), 1);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn require_cover_fails_closed_without_channel() {
        let mut rng = OsRng;
        let (guard_sec, guard_id, _path, _tx, inbound_rx, outbound_tx, _outbound_rx) =
            relay_test_path(&mut rng);
        let cfg = RelayConfig::new(DEFAULT_MU).with_bulk_cover(BulkCoverConfig::production());
        let node = RelayNode::new(guard_id, guard_sec, cfg);
        let err = node
            .spawn(inbound_rx, outbound_tx, None, OsRng)
            .expect_err("must refuse bulk without cover channel");
        assert_eq!(err, CoverPolicyError::CoverChannelRequired);
    }

    #[tokio::test]
    async fn start_bulk_cover_begins_round_when_enabled() {
        let mut rng = OsRng;
        let (guard_sec, guard_id, path, inbound_tx, inbound_rx, outbound_tx, mut outbound_rx) =
            relay_test_path(&mut rng);
        let (cover_tx, mut cover_rx) = mpsc::channel(8);
        let policy = BulkCoverConfig {
            enabled: true,
            require: true,
            dial: SecurityDial::L2UniformBatched,
            target_flow_count: 3,
            round_secs: 0,
        };
        let node = RelayNode::new(
            guard_id,
            guard_sec,
            RelayConfig::new(DEFAULT_MU).with_bulk_cover(policy.clone()),
        );
        let (handle, _task) = node
            .spawn(inbound_rx, outbound_tx, Some(cover_tx), OsRng)
            .unwrap();
        start_bulk_cover(&handle, &policy).await.unwrap();

        let packet = build(&path, b"auto", &mut rng).unwrap();
        inbound_tx.send(packet).await.unwrap();
        let _ = outbound_rx.recv().await;
        handle.end_bulk_round().await.unwrap();

        let burst = cover_rx.try_recv().expect("cover emitted after started round");
        assert_eq!(burst.len(), SPHINX_FRAGMENT_COUNT);
        assert_eq!(handle.debug_stats().cover_flow_count, 2);
    }
}
