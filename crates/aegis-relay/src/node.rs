//! Async mix relay node: Sphinx peel, Exp(μ) delay, forward.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aegis_crypto::kem::RelayKemSecret;
use aegis_crypto::replay::ReplayCache;
use aegis_crypto::sphinx::{self, Processed, SphinxPacket};
use aegis_crypto::CryptoError;
use rand_core::{CryptoRngCore, RngCore};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use crate::config::RelayConfig;
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

/// Lightweight observability counters (internal only — not a wire signal).
#[derive(Debug)]
pub struct RelayStats {
    loop_return_count: AtomicU64,
    dropped_count: AtomicU64,
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
            integrity_error_count: AtomicU64::new(0),
            replay_error_count: AtomicU64::new(0),
            other_error_count: AtomicU64::new(0),
            forwarded_count: AtomicU64::new(0),
        }
    }

    /// Loop-cover cells that returned to this relay (§4.6 hook; full detection is future work).
    pub fn loop_return_count(&self) -> u64 {
        self.loop_return_count.load(Ordering::Relaxed)
    }

    /// Cover/dummy cells silently discarded at this relay.
    pub fn dropped_count(&self) -> u64 {
        self.dropped_count.load(Ordering::Relaxed)
    }

    pub fn integrity_error_count(&self) -> u64 {
        self.integrity_error_count.load(Ordering::Relaxed)
    }

    pub fn replay_error_count(&self) -> u64 {
        self.replay_error_count.load(Ordering::Relaxed)
    }

    pub fn forwarded_count(&self) -> u64 {
        self.forwarded_count.load(Ordering::Relaxed)
    }
}

/// Handle to a running relay task; exposes accounting counters.
#[derive(Clone, Debug)]
pub struct RelayHandle {
    pub id: RelayId,
    stats: Arc<RelayStats>,
}

impl RelayHandle {
    pub fn loop_return_count(&self) -> u64 {
        self.stats.loop_return_count()
    }

    pub fn dropped_count(&self) -> u64 {
        self.stats.dropped_count()
    }

    pub fn integrity_error_count(&self) -> u64 {
        self.stats.integrity_error_count()
    }

    pub fn forwarded_count(&self) -> u64 {
        self.stats.forwarded_count()
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
    /// the per-hop Exp(μ) mixing delay.
    pub fn spawn<R: RngCore + CryptoRngCore + Send + 'static>(
        self,
        inbound: mpsc::Receiver<SphinxPacket>,
        outbound: mpsc::Sender<ForwardedPacket>,
        mut rng: R,
    ) -> (RelayHandle, JoinHandle<()>) {
        let stats = Arc::new(RelayStats::new());
        let handle = RelayHandle {
            id: self.id,
            stats: Arc::clone(&stats),
        };
        let replay = Arc::new(Mutex::new(ReplayCache::new()));

        let join = tokio::spawn(async move {
            let mut inbound = inbound;
            while let Some(packet) = inbound.recv().await {
                let result = {
                    let mut cache = replay.lock().await;
                    sphinx::process(&packet, &self.secret, &mut cache)
                };

                match result {
                    Ok(Processed::Forward { next_hop, packet }) => {
                        let delay = sample_mixing_delay(self.config.mu, &mut rng);
                        tokio::time::sleep(delay).await;
                        stats.forwarded_count.fetch_add(1, Ordering::Relaxed);
                        if outbound
                            .send(ForwardedPacket {
                                next_hop: RelayId(next_hop),
                                packet,
                                delay_applied: delay,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(Processed::LoopReturned) => {
                        stats.loop_return_count.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(Processed::Drop) => {
                        stats.dropped_count.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(CryptoError::IntegrityFailure) => {
                        stats.integrity_error_count.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(CryptoError::Replay) => {
                        stats.replay_error_count.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        stats.other_error_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });

        (handle, join)
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
