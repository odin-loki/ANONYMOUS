//! TCP hop-link bridge: fixed-width AEAD frames + Sphinx fragmentation.
//!
//! Bridges real `tokio::net::TcpStream` sockets to a local [`crate::RelayNode`]'s
//! `mpsc` channels without modifying the relay core. Each ordered link carries
//! [`aegis_crypto::link::LINK_FRAME_LEN`] byte frames (ChaCha20-Poly1305 over one
//! 512-byte [`aegis_crypto::cell::Cell`]); Sphinx packets are split into exactly
//! [`aegis_crypto::fragment::SPHINX_FRAGMENT_COUNT`] fragments before sealing.
//!
//! ## Link-key provisioning
//!
//! Relays configure a **static pre-shared key** per peer pair (hex in the peer table /
//! ingress config). On each new TCP connection either:
//! - **LegacyPsk** (default): ephemeral X25519 + PSK MAC handshake, or
//! - **Noise** (`noise-link` feature): Noise_IK-compatible mutual auth with roster
//!   static X25519 keys (`LinkBridgeConfig::handshake`).
//! Both derive a fresh ChaCha20-Poly1305 session key with forward secrecy before
//! any Sphinx frames are sent.
//!
//! ## Inbound peer identification
//!
//! The responder learns which PSK matched during the handshake confirm MAC (tries
//! ingress key then each peer-table key). The resulting session key is cached for
//! the lifetime of the connection.
//!
//! ## Ingress rate limiting
//!
//! After handshake, each inbound connection applies a token-bucket cell/frame rate
//! limit (default â‰ˆ Mode-1 `1/Ï„` cells/s with a small burst). Excess frames are
//! **dropped silently** (connection stays open); see [`IngressRateLimitStats`].
//! A shared aggregate cap ([`IngressRateLimitConfig::global_max_cells_per_sec`]) is
//! **on by default** (Mode-1 Ã— [`DEFAULT_EXPECTED_INGRESS_CLIENTS`]); set `None` or
//! `0.0` to disable.
//!
//! ## Bounded inbound queue (drop-newest) + per-peer weighted fair drain
//!
//! Each inbound TCP connection gets its own bounded per-peer `mpsc` (capacity
//! [`PER_PEER_INBOUND_CAPACITY`]). Reassembled Sphinx packets are enqueued with
//! [`crate::node::try_send_drop_newest`] into that peer queue. A fair-drain task
//! uses **weighted deficit round-robin** (WFQ-style) into the relay's shared
//! inbound channel (capacity [`crate::node::RELAY_CHANNEL_CAPACITY`]), so one
//! busy peer cannot monopolize the mix queue. Weights default to
//! [`DEFAULT_PEER_QUEUE_WEIGHT`] (`1`); after handshake, weights are derived from
//! peer-health success rate (unhealthy peers get lower weight). When a peer
//! queue or the shared inbound is full, the **newest** packet is dropped and
//! [`QueueDropStats::dropped`] increments. Rate-limit drops happen first
//! (pre-reassembly); queue drops are a second shed for post-reassembly backlog.
//!
//! ## Bounded outbound queue (drop-newest) + per-peer weighted fair drain
//!
//! Packets from the relay's shared outbound channel are routed into per-next-hop
//! bounded queues (capacity [`PER_PEER_OUTBOUND_CAPACITY`]) with drop-newest.
//! A fair-drain task uses **weighted deficit round-robin** (WFQ-style) to choose
//! which peer to serve next, so one busy next-hop cannot monopolize egress TCP
//! writes. Weights use the same peer-health success-rate mapping as inbound.
//! Exit/terminal peels with no peer-table route bypass the fair hub when
//! `exit_tx` is wired. Residual: discrete weight quanta (not continuous GPS);
//! per-peer queues are keyed by roster `RelayId`, not TCP connection count.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_crypto::cell::{Cell, Command};
use aegis_crypto::fragment::{fragment_with_random_id, SphinxReassembler, SPHINX_FRAGMENT_COUNT};
use aegis_crypto::link::{
    link_handshake_confirm_mac, link_handshake_finish_mac, link_handshake_init_write,
    link_handshake_resp_write, link_handshake_responder_finish, parse_link_handshake_init,
    parse_link_handshake_mac, parse_link_handshake_resp, verify_link_handshake_confirm_mac,
    verify_link_handshake_finish_mac, LinkHandshakeBinding, LinkHandshakeTranscript, LinkKey,
    LINK_FRAME_LEN, LINK_HANDSHAKE_CONFIRM_LEN, LINK_HANDSHAKE_FINISH_LEN, LINK_HANDSHAKE_INIT_LEN,
    LINK_HANDSHAKE_RESP_LEN,
};
use aegis_crypto::sphinx::SphinxPacket;
use aegis_crypto::CryptoError;
use rand_core::{CryptoRngCore, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, Notify, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use thiserror::Error;

use crate::cover_flow::is_relay_cover_fragment;
use crate::health_gossip::{
    accept_advert, unix_timestamp_secs, PeerHealthAdvert, DEFAULT_MAX_ADVERT_AGE_SECS,
};
use crate::node::{try_send_drop_newest, ForwardedPacket};
use crate::peer_health::PeerHealthTracker;
use crate::relay_id::RelayId;
use crate::trace::RelayForwardTrace;

/// Default per-read timeout: slow-loris peers cannot hold a task indefinitely.
pub const DEFAULT_LINK_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Default cap on concurrent inbound TCP connections per listener.
pub const DEFAULT_MAX_INBOUND_CONNECTIONS: usize = 256;

/// Per-connection inbound queue capacity before weighted fair drain into the
/// shared relay inbound channel.
pub const PER_PEER_INBOUND_CAPACITY: usize = 16;

/// Per-next-hop outbound queue capacity before weighted fair drain to TCP.
pub const PER_PEER_OUTBOUND_CAPACITY: usize = 16;

/// Default per-peer inbound drain weight when no health samples exist.
pub const DEFAULT_PEER_QUEUE_WEIGHT: u32 = 1;

/// Maximum per-peer inbound drain weight (healthy peers with ~100% success).
pub const MAX_PEER_QUEUE_WEIGHT: u32 = 8;

/// Mode-1 spec worked-example slot period Ï„ (seconds).
pub const MODE1_TAU_SECS: f64 = 0.35;

/// Default sustained ingress accept rate: ~1/Ï„ cells/s (Mode-1 pacing).
pub const DEFAULT_INGRESS_MAX_CELLS_PER_SEC: f64 = 1.0 / MODE1_TAU_SECS;

/// Small burst above sustained rate so Ï„-paced clients tolerate minor jitter.
pub const DEFAULT_INGRESS_BURST: u32 = 4;

/// Conservative expected concurrent Mode-1 paced clients for the default global budget.
///
/// Operators with larger honest concurrency should raise
/// [`IngressRateLimitConfig::global_max_cells_per_sec`] (TOML `[link]` /
/// `[ingress]`).
pub const DEFAULT_EXPECTED_INGRESS_CLIENTS: f64 = 8.0;

/// Default aggregate ingress cap across connections: Mode-1 Ã— expected clients
/// (`8 / Ï„` â‰ˆ 22.86 cells/s). Sheds multi-connection floods that individually stay
/// under the per-conn limit.
pub const DEFAULT_GLOBAL_MAX_CELLS_PER_SEC: f64 =
    DEFAULT_EXPECTED_INGRESS_CLIENTS / MODE1_TAU_SECS;

/// Default inter-cell spacing for cover egress (Mode-1 Ï„).
pub const DEFAULT_COVER_CELL_TAU: Duration = Duration::from_millis(350);

/// Per-connection and global ingress frame rate limit for the link bridge.
///
/// Excess frames after AEAD framing are **dropped silently** (TCP stays open); see
/// [`IngressRateLimitStats::dropped_frames`]. Set `max_cells_per_sec` to `0.0` to disable
/// per-connection limiting; set `global_max_cells_per_sec` to `None` or `Some(0.0)` to
/// disable the aggregate cap (default is [`DEFAULT_GLOBAL_MAX_CELLS_PER_SEC`]).
#[derive(Clone, Debug)]
pub struct IngressRateLimitConfig {
    /// Sustained accept rate (cells/sec). `0.0` disables per-connection limiting.
    pub max_cells_per_sec: f64,
    /// Token-bucket burst (cells).
    pub burst: u32,
    /// Aggregate cap across all inbound connections (cells/sec). `None` / `Some(0.0)` disables.
    pub global_max_cells_per_sec: Option<f64>,
}

impl Default for IngressRateLimitConfig {
    fn default() -> Self {
        Self {
            max_cells_per_sec: DEFAULT_INGRESS_MAX_CELLS_PER_SEC,
            burst: DEFAULT_INGRESS_BURST,
            global_max_cells_per_sec: Some(DEFAULT_GLOBAL_MAX_CELLS_PER_SEC),
        }
    }
}

impl IngressRateLimitConfig {
    /// Disable ingress rate limiting (integration tests / lab floods).
    pub const fn disabled() -> Self {
        Self {
            max_cells_per_sec: 0.0,
            burst: 0,
            global_max_cells_per_sec: None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.max_cells_per_sec > 0.0 || self.global_max_cells_per_sec.is_some_and(|r| r > 0.0)
    }
}

/// Coarse counter for silently dropped ingress frames (link bridge only).
#[derive(Debug, Default)]
pub struct IngressRateLimitStats {
    dropped_frames: AtomicU64,
}

impl IngressRateLimitStats {
    pub fn dropped_frames(&self) -> u64 {
        self.dropped_frames.load(Ordering::Relaxed)
    }

    fn record_drop(&self) {
        self.dropped_frames.fetch_add(1, Ordering::Relaxed);
    }
}

/// Coarse counter for inbound Sphinx packets dropped when the relay `mpsc` is full
/// (drop-newest; see module docs).
#[derive(Debug, Default)]
pub struct QueueDropStats {
    dropped: AtomicU64,
}

impl QueueDropStats {
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn counter(&self) -> &AtomicU64 {
        &self.dropped
    }
}

/// Map peer-health success rate to a drain weight in `[1, MAX_PEER_QUEUE_WEIGHT]`.
///
/// No samples → [`DEFAULT_PEER_QUEUE_WEIGHT`]. Low success (unhealthy) → lower weight.
pub fn peer_queue_weight_from_success_rate(success_rate: Option<f64>) -> u32 {
    match success_rate {
        None => DEFAULT_PEER_QUEUE_WEIGHT,
        Some(rate) => {
            let clamped = rate.clamp(0.0, 1.0);
            let w = (clamped * MAX_PEER_QUEUE_WEIGHT as f64).round() as u32;
            w.clamp(DEFAULT_PEER_QUEUE_WEIGHT, MAX_PEER_QUEUE_WEIGHT)
        }
    }
}

fn peer_queue_weight_for(
    matched_peer: Option<RelayId>,
    peer_health: Option<&PeerHealthTracker>,
) -> u32 {
    let Some(id) = matched_peer else {
        return DEFAULT_PEER_QUEUE_WEIGHT;
    };
    let Some(health) = peer_health else {
        return DEFAULT_PEER_QUEUE_WEIGHT;
    };
    peer_queue_weight_from_success_rate(health.success_rate(*id.as_bytes()))
}

/// Per-connection sender into the fair-inbound hub (drop-newest on the peer queue).
struct FairPeerSender {
    tx: mpsc::Sender<SphinxPacket>,
    notify: Arc<Notify>,
    drop_stats: Arc<QueueDropStats>,
    hub: Arc<FairInboundHub>,
    slot_id: usize,
}

impl FairPeerSender {
    fn try_enqueue(&self, packet: SphinxPacket) -> Result<(), ()> {
        let result = try_send_drop_newest(&self.tx, packet, self.drop_stats.counter());
        self.notify.notify_one();
        result
    }

    async fn set_weight(&self, weight: u32) {
        self.hub.set_weight(self.slot_id, weight).await;
    }
}

/// Live peer slot: receiver + WFQ weight + remaining service credits.
struct FairPeerSlot<T> {
    rx: mpsc::Receiver<T>,
    weight: u32,
    /// Remaining packets this peer may send before the cursor advances.
    credits: u32,
}

/// Weighted fair hub: per-connection receivers drained by deficit round-robin.
struct FairInboundHub {
    slots: Mutex<Vec<Option<FairPeerSlot<SphinxPacket>>>>,
    notify: Arc<Notify>,
}

impl FairInboundHub {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            slots: Mutex::new(Vec::new()),
            notify: Arc::new(Notify::new()),
        })
    }

    async fn register(
        self: &Arc<Self>,
        drop_stats: Arc<QueueDropStats>,
    ) -> (usize, FairPeerSender) {
        self.register_with_weight(drop_stats, DEFAULT_PEER_QUEUE_WEIGHT)
            .await
    }

    async fn register_with_weight(
        self: &Arc<Self>,
        drop_stats: Arc<QueueDropStats>,
        weight: u32,
    ) -> (usize, FairPeerSender) {
        let weight = weight.max(DEFAULT_PEER_QUEUE_WEIGHT);
        let (tx, rx) = mpsc::channel(PER_PEER_INBOUND_CAPACITY);
        let mut slots = self.slots.lock().await;
        let slot = FairPeerSlot::<SphinxPacket> {
            rx,
            weight,
            credits: 0,
        };
        let slot_id = if let Some(i) = slots.iter().position(|s| s.is_none()) {
            slots[i] = Some(slot);
            i
        } else {
            slots.push(Some(slot));
            slots.len() - 1
        };
        let sender = FairPeerSender {
            tx,
            notify: Arc::clone(&self.notify),
            drop_stats,
            hub: Arc::clone(self),
            slot_id,
        };
        // Wake the drain task if it is blocked on an empty slot table (avoids
        // lost wakeup between empty-check and `notified().await`).
        self.notify.notify_one();
        (slot_id, sender)
    }

    async fn set_weight(&self, slot_id: usize, weight: u32) {
        let weight = weight.max(DEFAULT_PEER_QUEUE_WEIGHT);
        let mut slots = self.slots.lock().await;
        if let Some(Some(slot)) = slots.get_mut(slot_id) {
            slot.weight = weight;
        }
    }
}

/// Weighted fair take: each peer may emit up to `weight` packets per visit
/// (credit refill). Equal weights (`1`) reduce to classic round-robin.
fn fair_wfq_take_one<T>(
    slots: &mut [Option<FairPeerSlot<T>>],
    cursor: &mut usize,
) -> Option<T> {
    let n = slots.len();
    if n == 0 {
        return None;
    }
    for step in 0..n {
        let i = (*cursor + step) % n;
        let outcome = match slots.get_mut(i).and_then(|s| s.as_mut()) {
            Some(slot) => {
                if slot.credits == 0 {
                    slot.credits = slot.weight.max(DEFAULT_PEER_QUEUE_WEIGHT);
                }
                match slot.rx.try_recv() {
                    Ok(pkt) => {
                        slot.credits = slot.credits.saturating_sub(1);
                        let advance = slot.credits == 0;
                        Some(Ok((pkt, advance)))
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {
                        // Empty peer forfeits remaining credits so a silent peer
                        // cannot bank weight across rounds.
                        slot.credits = 0;
                        None
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => Some(Err(())),
                }
            }
            None => None,
        };
        match outcome {
            Some(Ok((pkt, advance))) => {
                if advance {
                    *cursor = i.wrapping_add(1);
                } else {
                    *cursor = i;
                }
                return Some(pkt);
            }
            Some(Err(())) => {
                slots[i] = None;
            }
            None => {}
        }
    }
    None
}

fn spawn_fair_inbound_drain(
    hub: Arc<FairInboundHub>,
    inbound_tx: mpsc::Sender<SphinxPacket>,
    queue_drop_stats: Arc<QueueDropStats>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut cursor = 0usize;
        loop {
            // Subscribe before scanning so a concurrent enqueue cannot lose its wakeup.
            let notified = hub.notify.notified();
            tokio::pin!(notified);

            let packet = {
                let mut slots = hub.slots.lock().await;
                if slots.is_empty() {
                    drop(slots);
                    notified.await;
                    continue;
                }
                fair_wfq_take_one(&mut slots, &mut cursor)
            };

            match packet {
                Some(pkt) => {
                    if try_send_drop_newest(&inbound_tx, pkt, queue_drop_stats.counter()).is_err()
                    {
                        return;
                    }
                }
                None => {
                    let _ = timeout(Duration::from_millis(5), notified).await;
                }
            }
        }
    })
}

/// Drain one weighted-fair packet for tests (exposes WFQ scheduling without TCP).
#[cfg(test)]
async fn fair_inbound_drain_once_for_test(
    hub: &FairInboundHub,
    cursor: &mut usize,
) -> Option<SphinxPacket> {
    let mut slots = hub.slots.lock().await;
    fair_wfq_take_one(&mut slots, cursor)
}

/// Per-next-hop sender into the fair-outbound hub (drop-newest on the peer queue).
struct FairOutboundPeerSender {
    tx: mpsc::Sender<ForwardedPacket>,
    notify: Arc<Notify>,
    drop_stats: Arc<QueueDropStats>,
    hub: Arc<FairOutboundHub>,
    slot_id: usize,
}

impl FairOutboundPeerSender {
    fn try_enqueue(&self, packet: ForwardedPacket) -> Result<(), ()> {
        let result = try_send_drop_newest(&self.tx, packet, self.drop_stats.counter());
        self.notify.notify_one();
        result
    }

    async fn set_weight(&self, weight: u32) {
        self.hub.set_weight(self.slot_id, weight).await;
    }
}

/// Weighted fair hub for egress: per-next-hop queues drained by deficit round-robin.
struct FairOutboundHub {
    slots: Mutex<Vec<Option<FairPeerSlot<ForwardedPacket>>>>,
    notify: Arc<Notify>,
}

impl FairOutboundHub {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            slots: Mutex::new(Vec::new()),
            notify: Arc::new(Notify::new()),
        })
    }

    async fn register_peer(
        self: &Arc<Self>,
        drop_stats: Arc<QueueDropStats>,
        weight: u32,
    ) -> FairOutboundPeerSender {
        let weight = weight.max(DEFAULT_PEER_QUEUE_WEIGHT);
        let (tx, rx) = mpsc::channel(PER_PEER_OUTBOUND_CAPACITY);
        let mut slots = self.slots.lock().await;
        let slot = FairPeerSlot::<ForwardedPacket> {
            rx,
            weight,
            credits: 0,
        };
        let slot_id = if let Some(i) = slots.iter().position(|s| s.is_none()) {
            slots[i] = Some(slot);
            i
        } else {
            slots.push(Some(slot));
            slots.len() - 1
        };
        let sender = FairOutboundPeerSender {
            tx,
            notify: Arc::clone(&self.notify),
            drop_stats,
            hub: Arc::clone(self),
            slot_id,
        };
        self.notify.notify_one();
        sender
    }

    async fn set_weight(&self, slot_id: usize, weight: u32) {
        let weight = weight.max(DEFAULT_PEER_QUEUE_WEIGHT);
        let mut slots = self.slots.lock().await;
        if let Some(Some(slot)) = slots.get_mut(slot_id) {
            slot.weight = weight;
        }
    }
}

fn all_outbound_slots_empty(slots: &[Option<FairPeerSlot<ForwardedPacket>>]) -> bool {
    slots
        .iter()
        .all(|slot| slot.as_ref().map_or(true, |s| s.rx.is_empty()))
}

fn spawn_fair_outbound_drain<R: RngCore + CryptoRngCore + Send + 'static>(
    hub: Arc<FairOutboundHub>,
    router_done: Arc<AtomicBool>,
    pool: Arc<Mutex<ConnectionPool>>,
    peer_table: HashMap<RelayId, PeerInfo>,
    forward_trace: Option<RelayForwardTrace>,
    rng: Arc<Mutex<R>>,
    bridge_config: LinkBridgeConfig,
    peer_health: Option<Arc<PeerHealthTracker>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut cursor = 0usize;
        loop {
            let notified = hub.notify.notified();
            tokio::pin!(notified);

            let fwd = {
                let mut slots = hub.slots.lock().await;
                if slots.is_empty() {
                    drop(slots);
                    if router_done.load(Ordering::Relaxed) {
                        return;
                    }
                    notified.await;
                    continue;
                }
                if router_done.load(Ordering::Relaxed) && all_outbound_slots_empty(&slots) {
                    return;
                }
                fair_wfq_take_one(&mut slots, &mut cursor)
            };

            match fwd {
                Some(fwd) => {
                    let Some(peer) = peer_table.get(&fwd.next_hop).cloned() else {
                        continue;
                    };
                    let mut guard = rng.lock().await;
                    match forward_to_peer(
                        &pool,
                        fwd.next_hop,
                        &peer,
                        &fwd.packet,
                        &mut *guard,
                        &bridge_config,
                        &peer_health,
                    )
                    .await
                    {
                        Ok(()) => {
                            if let Some(ref trace) = forward_trace {
                                trace.record_forward(SPHINX_FRAGMENT_COUNT as u32);
                            }
                        }
                        Err(e) => {
                            eprintln!("aegis-relay net: forward to {:?}: {e}", fwd.next_hop);
                        }
                    }
                }
                None => {
                    if router_done.load(Ordering::Relaxed) {
                        let slots = hub.slots.lock().await;
                        if all_outbound_slots_empty(&slots) {
                            return;
                        }
                    }
                    let _ = timeout(Duration::from_millis(5), notified).await;
                }
            }
        }
    })
}

/// Drain one weighted-fair outbound packet for tests (WFQ without TCP).
#[cfg(test)]
async fn fair_outbound_drain_once_for_test(
    hub: &FairOutboundHub,
    cursor: &mut usize,
) -> Option<ForwardedPacket> {
    let mut slots = hub.slots.lock().await;
    fair_wfq_take_one(&mut slots, cursor)
}

/// Which hop-link handshake to run after TCP connect/accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum LinkHandshakeMode {
    /// Ephemeral X25519 + PSK MAC.
    ///
    /// Default when the `noise-link` feature is disabled.
    #[cfg_attr(not(feature = "noise-link"), default)]
    LegacyPsk,
    /// Select Noise when local (+ peer) static keys are present; else LegacyPsk.
    ///
    /// Default when `noise-link` is enabled. Keeps LegacyPsk behavior when keys
    /// are absent.
    #[cfg(feature = "noise-link")]
    #[default]
    Auto,
    /// Noise_IK-compatible mutual auth with roster static keys (`noise-link` feature).
    #[cfg(feature = "noise-link")]
    Noise,
}

/// Tunables for the TCP link bridge (read timeout, connection cap, ingress rate limit).
#[derive(Clone, Debug)]
pub struct LinkBridgeConfig {
    pub read_timeout: Duration,
    pub max_inbound_connections: usize,
    /// When true, bind the peer roster relay id into handshake MAC inputs.
    pub identity_binding: bool,
    /// Handshake protocol selection (`Auto` / `LegacyPsk` / `Noise`).
    pub handshake: LinkHandshakeMode,
    /// Local Noise static secret (32 bytes). Required when `handshake == Noise`;
    /// when `handshake == Auto`, enables Noise if the peer static is also known.
    pub noise_static_secret: Option<[u8; 32]>,
    /// Expected initiator static public for shared ingress Noise auth (optional).
    pub ingress_noise_static_public: Option<[u8; 32]>,
    pub ingress_rate_limit: IngressRateLimitConfig,
    /// Optional shared counter for rate-limited frame drops (tests / ops).
    pub ingress_rate_limit_stats: Option<Arc<IngressRateLimitStats>>,
    /// Optional shared counter for inbound queue-full drops (tests / ops).
    pub queue_drop_stats: Option<Arc<QueueDropStats>>,
    /// Inter-cell spacing for cover egress on the wire (Mode-1 τ by default).
    ///
    /// Cover dispatcher emits **one** sealed cell per tick when non-zero, matching
    /// client Mode-1 cadence. Set to [`Duration::ZERO`] in lab tests that only
    /// check frame shape. Residual: multi-hop Sphinx semantics still differ from
    /// real bulk (cover is discarded at the next hop).
    pub cover_cell_tau: Duration,
}

impl Default for LinkBridgeConfig {
    fn default() -> Self {
        Self {
            read_timeout: DEFAULT_LINK_READ_TIMEOUT,
            max_inbound_connections: DEFAULT_MAX_INBOUND_CONNECTIONS,
            identity_binding: true,
            handshake: LinkHandshakeMode::default(),
            noise_static_secret: None,
            ingress_noise_static_public: None,
            ingress_rate_limit: IngressRateLimitConfig::default(),
            ingress_rate_limit_stats: None,
            queue_drop_stats: None,
            cover_cell_tau: DEFAULT_COVER_CELL_TAU,
        }
    }
}

impl LinkBridgeConfig {
    /// Disable ingress rate limiting while keeping other defaults.
    pub fn without_ingress_rate_limit(mut self) -> Self {
        self.ingress_rate_limit = IngressRateLimitConfig::disabled();
        self
    }

    /// Disable cover τ-pacing (burst cover cells; lab / unit tests).
    pub fn without_cover_cell_pacing(mut self) -> Self {
        self.cover_cell_tau = Duration::ZERO;
        self
    }

    /// Whether the initiator should run Noise for this peer.
    ///
    /// `Auto` selects Noise only when both local `noise_static_secret` and
    /// `peer_noise_static` are present; otherwise LegacyPsk.
    #[cfg(feature = "noise-link")]
    pub fn initiator_selects_noise(&self, peer_noise_static: Option<[u8; 32]>) -> bool {
        match self.handshake {
            LinkHandshakeMode::Noise => true,
            LinkHandshakeMode::LegacyPsk => false,
            LinkHandshakeMode::Auto => {
                self.noise_static_secret.is_some() && peer_noise_static.is_some()
            }
        }
    }

    /// Whether the responder should run Noise for inbound connections.
    ///
    /// `Auto` selects Noise when local `noise_static_secret` is configured.
    #[cfg(feature = "noise-link")]
    pub fn responder_selects_noise(&self) -> bool {
        match self.handshake {
            LinkHandshakeMode::Noise => true,
            LinkHandshakeMode::LegacyPsk => false,
            LinkHandshakeMode::Auto => self.noise_static_secret.is_some(),
        }
    }
}

#[derive(Debug)]
struct TokenBucket {
    rate: f64,
    capacity: f64,
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rate: f64, burst: u32) -> Self {
        let capacity = burst.max(1) as f64;
        Self {
            rate,
            capacity,
            tokens: capacity,
            last_refill: Instant::now(),
        }
    }

    fn is_enabled(&self) -> bool {
        self.rate > 0.0
    }

    fn try_consume(&mut self, n: u32) -> bool {
        if !self.is_enabled() {
            return true;
        }
        self.refill();
        let need = n as f64;
        if self.tokens >= need {
            self.tokens -= need;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
            self.last_refill = now;
        }
    }
}

struct InboundRateLimitState {
    local: TokenBucket,
    global: Option<Arc<Mutex<TokenBucket>>>,
    stats: Arc<IngressRateLimitStats>,
    config: IngressRateLimitConfig,
}

impl InboundRateLimitState {
    fn new(
        config: &IngressRateLimitConfig,
        stats: Arc<IngressRateLimitStats>,
        global: Option<Arc<Mutex<TokenBucket>>>,
    ) -> Self {
        let local = if config.max_cells_per_sec > 0.0 {
            TokenBucket::new(config.max_cells_per_sec, config.burst)
        } else {
            TokenBucket::new(0.0, 0)
        };
        Self {
            local,
            global,
            stats,
            config: config.clone(),
        }
    }

    async fn allow_frame(&mut self) -> bool {
        if !self.config.is_active() {
            return true;
        }
        if self.config.max_cells_per_sec > 0.0 && !self.local.try_consume(1) {
            self.stats.record_drop();
            return false;
        }
        if let Some(global) = &self.global {
            let mut bucket = global.lock().await;
            if !bucket.try_consume(1) {
                self.stats.record_drop();
                return false;
            }
        }
        true
    }
}

fn link_handshake_binding(
    config: &LinkBridgeConfig,
    peer_relay_id: RelayId,
    kem_public_commitment: Option<[u8; 32]>,
) -> Option<LinkHandshakeBinding> {
    if !config.identity_binding {
        return None;
    }
    let mut binding = LinkHandshakeBinding::peer_id(*peer_relay_id.as_bytes());
    if let Some(commitment) = kem_public_commitment {
        binding = binding.with_kem_commitment(commitment);
    }
    Some(binding)
}

/// A remote peer reachable over TCP with a pre-shared hop link key.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    /// 32-byte pre-shared key for handshake authentication (not used directly for AEAD).
    pub link_key_bytes: [u8; 32],
    /// Optional roster KEM public-key commitment bound into outbound handshake MACs.
    pub kem_public_commitment: Option<[u8; 32]>,
    /// Optional Ed25519 verifying key for signed [`crate::health_gossip::PeerHealthAdvert`].
    pub gossip_verifying_key: Option<[u8; 32]>,
    /// Expected peer Noise static public key (32 bytes). Required for `LinkHandshakeMode::Noise`.
    pub noise_static_public: Option<[u8; 32]>,
}

impl PeerInfo {
    pub fn new(addr: SocketAddr, link_key_bytes: [u8; 32]) -> Self {
        Self {
            addr,
            link_key_bytes,
            kem_public_commitment: None,
            gossip_verifying_key: None,
            noise_static_public: None,
        }
    }

    pub fn with_kem_commitment(mut self, kem_public_commitment: [u8; 32]) -> Self {
        self.kem_public_commitment = Some(kem_public_commitment);
        self
    }

    pub fn with_gossip_verifying_key(mut self, gossip_verifying_key: [u8; 32]) -> Self {
        self.gossip_verifying_key = Some(gossip_verifying_key);
        self
    }

    /// Set the roster-expected Noise static public key for this peer.
    pub fn with_noise_static_public(mut self, noise_static_public: [u8; 32]) -> Self {
        self.noise_static_public = Some(noise_static_public);
        self
    }
}

/// Optional sink for exit traffic (last hop peeled packet, no downstream peer).
pub type ExitSink = mpsc::Sender<SphinxPacket>;

#[derive(Debug, Error)]
pub enum NetError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("peer not found: {0:?}")]
    PeerNotFound(RelayId),
    #[error("fragment: {0}")]
    Fragment(#[from] aegis_crypto::fragment::FragmentError),
    #[error("could not authenticate link handshake with any configured key")]
    UnidentifiedInbound,
    #[error("noise handshake misconfigured: {0}")]
    NoiseConfig(&'static str),
    #[error("link read timed out after {0:?}")]
    ReadTimeout(Duration),
    #[error("inbound connection limit reached ({0})")]
    ConnectionLimit(usize),
}

/// Outbound signed health-gossip cell destined for one hop peer.
pub type GossipOutbound = (RelayId, Cell);

/// Spawn inbound listener + outbound dispatcher bridging TCP and `RelayNode` channels.
///
/// When `cover_rx` is set, a cover dispatcher seals synthetic cover cell bursts from
/// [`crate::RelayNode::spawn`] and writes them on a hop link (same AEAD framing as
/// real traffic).
///
/// When `gossip_rx` is set, sealed [`Command::PeerHealthAdvert`] cells are written
/// on hop links without entering Sphinx reassembly.
///
/// When `peer_health` is set, outbound send/handshake outcomes and inbound
/// responder handshakes (once a peer-table PSK matches) are recorded per peer
/// for periodic feeding into [`RelayPruningPolicy`](aegis_trust::RelayPruningPolicy)
/// via [`PeerHealthTracker::drain_into_policy`]. Inbound health-gossip cells are
/// verified and merged into the same tracker.
///
/// Returns join handles for the listener and dispatcher tasks.
pub fn spawn_link_bridge<R: RngCore + CryptoRngCore + Send + Sync + 'static>(
    listen_addr: SocketAddr,
    local_relay_id: RelayId,
    local_kem_commitment: Option<[u8; 32]>,
    peer_table: HashMap<RelayId, PeerInfo>,
    ingress_link_key: Option<[u8; 32]>,
    inbound_tx: mpsc::Sender<SphinxPacket>,
    outbound_rx: mpsc::Receiver<ForwardedPacket>,
    cover_rx: Option<mpsc::Receiver<Vec<Cell>>>,
    gossip_rx: Option<mpsc::Receiver<GossipOutbound>>,
    exit_tx: Option<ExitSink>,
    forward_trace: Option<RelayForwardTrace>,
    rng: R,
    bridge_config: LinkBridgeConfig,
    peer_health: Option<Arc<PeerHealthTracker>>,
) -> (JoinHandle<()>, JoinHandle<()>) {
    spawn_link_bridge_with_listener(
        InboundListen::Bind(listen_addr),
        local_relay_id,
        local_kem_commitment,
        peer_table,
        ingress_link_key,
        inbound_tx,
        outbound_rx,
        cover_rx,
        gossip_rx,
        exit_tx,
        forward_trace,
        rng,
        bridge_config,
        peer_health,
    )
}

/// Like [`spawn_link_bridge`] but accepts an already-bound [`TcpListener`]
/// (avoids Windows probe-bind / rebind races in integration tests).
pub fn spawn_link_bridge_with_listener<R: RngCore + CryptoRngCore + Send + Sync + 'static>(
    listen: InboundListen,
    local_relay_id: RelayId,
    local_kem_commitment: Option<[u8; 32]>,
    peer_table: HashMap<RelayId, PeerInfo>,
    ingress_link_key: Option<[u8; 32]>,
    inbound_tx: mpsc::Sender<SphinxPacket>,
    outbound_rx: mpsc::Receiver<ForwardedPacket>,
    cover_rx: Option<mpsc::Receiver<Vec<Cell>>>,
    gossip_rx: Option<mpsc::Receiver<GossipOutbound>>,
    exit_tx: Option<ExitSink>,
    forward_trace: Option<RelayForwardTrace>,
    rng: R,
    bridge_config: LinkBridgeConfig,
    peer_health: Option<Arc<PeerHealthTracker>>,
) -> (JoinHandle<()>, JoinHandle<()>) {
    let rng = Arc::new(Mutex::new(rng));
    let listener = spawn_inbound_listener(
        listen,
        local_relay_id,
        local_kem_commitment,
        peer_table.clone(),
        ingress_link_key,
        inbound_tx,
        bridge_config.clone(),
        peer_health.clone(),
    );
    if let Some(cover_rx) = cover_rx {
        spawn_cover_dispatcher(
            cover_rx,
            peer_table.clone(),
            forward_trace.clone(),
            Arc::clone(&rng),
            bridge_config.clone(),
            peer_health.clone(),
        );
    }
    if let Some(gossip_rx) = gossip_rx {
        spawn_gossip_dispatcher(
            gossip_rx,
            peer_table.clone(),
            Arc::clone(&rng),
            bridge_config.clone(),
            peer_health.clone(),
        );
    }
    let dispatcher = spawn_outbound_dispatcher(
        outbound_rx,
        peer_table,
        exit_tx,
        forward_trace,
        Arc::clone(&rng),
        bridge_config,
        peer_health,
    );
    (listener, dispatcher)
}

/// How the inbound link-bridge listener is obtained.
pub enum InboundListen {
    /// Bind a fresh `TcpListener` on this address.
    Bind(SocketAddr),
    /// Use an already-bound listener (tests / supervised sockets).
    Listener(TcpListener),
}

fn record_peer_outcome(
    health: &Option<Arc<PeerHealthTracker>>,
    peer_id: RelayId,
    success: bool,
) {
    if let Some(tracker) = health {
        if success {
            tracker.record_success(*peer_id.as_bytes());
        } else {
            tracker.record_failure(*peer_id.as_bytes());
        }
    }
}

fn record_inbound_handshake_outcome(
    health: Option<&PeerHealthTracker>,
    matched_peer: Option<RelayId>,
    success: bool,
) {
    if let (Some(tracker), Some(peer_id)) = (health, matched_peer) {
        if success {
            tracker.record_success(*peer_id.as_bytes());
        } else {
            tracker.record_failure(*peer_id.as_bytes());
        }
    }
}

/// Established TCP hop link: one handshake, many sealed cell frames on the same session key.
pub struct LinkSession {
    stream: TcpStream,
    session_key: LinkKey,
    read_timeout: Duration,
}

impl LinkSession {
    /// Connect to `addr`, run the initiator link handshake once, and return a reusable session.
    ///
    /// When `kem_public_commitment` is `Some`, it is bound into confirm/finish MACs (must match
    /// the responder's configured local commitment).
    pub async fn connect<R: RngCore + CryptoRngCore>(
        addr: SocketAddr,
        psk: &[u8; 32],
        peer_relay_id: RelayId,
        kem_public_commitment: Option<[u8; 32]>,
        peer_noise_static: Option<[u8; 32]>,
        rng: &mut R,
        bridge_config: &LinkBridgeConfig,
    ) -> Result<Self, NetError> {
        let mut stream = TcpStream::connect(addr).await?;
        let session_key = run_initiator_handshake(
            &mut stream,
            psk,
            peer_relay_id,
            kem_public_commitment,
            peer_noise_static,
            rng,
            bridge_config,
        )
        .await?;
        Ok(Self {
            stream,
            session_key,
            read_timeout: bridge_config.read_timeout,
        })
    }

    /// Seal and write one 512-byte cell as a single AEAD link frame (no re-handshake).
    pub async fn send_cell<R: RngCore + CryptoRngCore>(
        &mut self,
        cell: &Cell,
        rng: &mut R,
    ) -> Result<(), NetError> {
        let frame = self.session_key.seal(cell, rng)?;
        write_all_timeout(&mut self.stream, &frame, self.read_timeout).await
    }

    /// Flush buffered TCP writes (call after a paced burst if needed).
    pub async fn flush(&mut self) -> Result<(), NetError> {
        self.stream.flush().await.map_err(NetError::Io)
    }
}

/// Connect, run the link handshake, seal/fragment, and send one Sphinx packet.
pub async fn send_sphinx_packet<R: RngCore + CryptoRngCore>(
    addr: SocketAddr,
    psk: &[u8; 32],
    peer_relay_id: RelayId,
    kem_public_commitment: Option<[u8; 32]>,
    peer_noise_static: Option<[u8; 32]>,
    packet: &SphinxPacket,
    rng: &mut R,
    bridge_config: &LinkBridgeConfig,
) -> Result<(), NetError> {
    let mut session = LinkSession::connect(
        addr,
        psk,
        peer_relay_id,
        kem_public_commitment,
        peer_noise_static,
        rng,
        bridge_config,
    )
    .await?;
    write_packet_on_session(&mut session, packet, rng).await
}

async fn write_packet_on_session<R: RngCore + CryptoRngCore>(
    session: &mut LinkSession,
    packet: &SphinxPacket,
    rng: &mut R,
) -> Result<(), NetError> {
    let (cells, _) = fragment_with_random_id(packet, rng);
    for cell in &cells {
        session.send_cell(cell, rng).await?;
    }
    session.flush().await
}

/// Seal, fragment, and send one Sphinx packet on an existing handshaken stream.
pub async fn write_packet<R: RngCore + CryptoRngCore>(
    stream: &mut TcpStream,
    link_key: &LinkKey,
    packet: &SphinxPacket,
    rng: &mut R,
) -> Result<(), NetError> {
    write_packet_with_key(stream, link_key, packet, rng, DEFAULT_LINK_READ_TIMEOUT).await
}

async fn write_packet_with_key<R: RngCore + CryptoRngCore>(
    stream: &mut TcpStream,
    link_key: &LinkKey,
    packet: &SphinxPacket,
    rng: &mut R,
    read_timeout: Duration,
) -> Result<(), NetError> {
    let (cells, _) = fragment_with_random_id(packet, rng);
    for cell in &cells {
        let frame = link_key.seal(cell, rng)?;
        write_all_timeout(stream, &frame, read_timeout).await?;
    }
    stream.flush().await?;
    Ok(())
}

/// Seal and write one cell on an existing handshaken stream (legacy helper).
pub async fn send_link_cell<R: RngCore + CryptoRngCore>(
    stream: &mut TcpStream,
    link_key: &LinkKey,
    cell: &Cell,
    rng: &mut R,
    read_timeout: Duration,
) -> Result<(), NetError> {
    let frame = link_key.seal(cell, rng)?;
    write_all_timeout(stream, &frame, read_timeout).await
}

async fn read_exact_timeout(
    stream: &mut TcpStream,
    buf: &mut [u8],
    read_timeout: Duration,
) -> Result<(), NetError> {
    match timeout(read_timeout, stream.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(NetError::Io(e)),
        Err(_) => Err(NetError::ReadTimeout(read_timeout)),
    }
}

async fn write_all_timeout(
    stream: &mut TcpStream,
    buf: &[u8],
    write_timeout: Duration,
) -> Result<(), NetError> {
    match timeout(write_timeout, stream.write_all(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(NetError::Io(e)),
        Err(_) => Err(NetError::ReadTimeout(write_timeout)),
    }
}

/// Initiator-side link handshake on an established TCP stream.
///
/// `peer_noise_static` is the roster-expected responder static public key when
/// Noise is selected (`Noise` mode, or `Auto` with both local and peer statics);
/// ignored for LegacyPsk.
pub async fn run_initiator_handshake<R: RngCore + CryptoRngCore>(
    stream: &mut TcpStream,
    psk: &[u8; 32],
    peer_relay_id: RelayId,
    kem_public_commitment: Option<[u8; 32]>,
    peer_noise_static: Option<[u8; 32]>,
    rng: &mut R,
    bridge_config: &LinkBridgeConfig,
) -> Result<LinkKey, NetError> {
    #[cfg(feature = "noise-link")]
    if bridge_config.initiator_selects_noise(peer_noise_static) {
        return run_initiator_noise_handshake(stream, peer_noise_static, rng, bridge_config).await;
    }
    let _ = peer_noise_static;

    let binding = link_handshake_binding(bridge_config, peer_relay_id, kem_public_commitment);
    let binding_ref = binding.as_ref();
    let read_timeout = bridge_config.read_timeout;

    let (init_sk, init_msg) = link_handshake_init_write(rng);
    let init = parse_link_handshake_init(&init_msg)?;
    write_all_timeout(stream, &init_msg, read_timeout).await?;

    let mut resp_msg = [0u8; LINK_HANDSHAKE_RESP_LEN];
    read_exact_timeout(stream, &mut resp_msg, read_timeout).await?;
    let resp = parse_link_handshake_resp(&resp_msg)?;
    let transcript = LinkHandshakeTranscript::from_messages(&init, &resp);
    let confirm = link_handshake_confirm_mac(psk, &transcript, binding_ref);
    write_all_timeout(stream, &confirm, read_timeout).await?;

    let mut finish_msg = [0u8; LINK_HANDSHAKE_FINISH_LEN];
    read_exact_timeout(stream, &mut finish_msg, read_timeout).await?;
    let finish = parse_link_handshake_mac(&finish_msg)?;
    if !verify_link_handshake_finish_mac(psk, &transcript, binding_ref, &finish) {
        return Err(NetError::Crypto(CryptoError::IntegrityFailure));
    }
    let _ = psk;
    Ok(aegis_crypto::link::derive_link_session_key(
        init_sk,
        &resp.eph_pk,
        &transcript,
    ))
}

#[cfg(feature = "noise-link")]
async fn run_initiator_noise_handshake<R: RngCore + CryptoRngCore>(
    stream: &mut TcpStream,
    peer_noise_static: Option<[u8; 32]>,
    rng: &mut R,
    bridge_config: &LinkBridgeConfig,
) -> Result<LinkKey, NetError> {
    use aegis_crypto::noise_link::{
        noise_ik_initiator_read_msg2, noise_ik_initiator_write_msg1, NOISE_IK_MSG2_LEN,
    };

    let local_sk = bridge_config
        .noise_static_secret
        .ok_or(NetError::NoiseConfig("missing local noise_static_secret"))?;
    let remote_pk = peer_noise_static
        .ok_or(NetError::NoiseConfig("missing peer noise_static_public"))?;
    let read_timeout = bridge_config.read_timeout;

    let (state, msg1) = noise_ik_initiator_write_msg1(&local_sk, &remote_pk, rng)?;
    write_all_timeout(stream, &msg1, read_timeout).await?;

    let mut msg2 = [0u8; NOISE_IK_MSG2_LEN];
    read_exact_timeout(stream, &mut msg2, read_timeout).await?;
    Ok(noise_ik_initiator_read_msg2(state, &msg2)?)
}

/// Responder-side link handshake; identifies which configured PSK matched.
///
/// Returns `(session_key, matched_peer_table_id)`. The peer id is `Some` only when
/// authentication succeeded via a peer-table PSK (not the shared ingress key).
///
/// When local_kem_commitment is Some, it is bound into confirm/finish MACs (must match
/// the initiator's peer-table / hop commitment for this relay).
///
/// When `peer_health` is set and authentication succeeds via a peer-table PSK, records
/// success for that peer; records failure if finish steps fail after the PSK matched.
/// Ingress-key and unidentified inbound outcomes are not attributed to a peer id.
pub async fn run_responder_handshake<R: RngCore + CryptoRngCore>(
    stream: &mut TcpStream,
    local_relay_id: RelayId,
    local_kem_commitment: Option<[u8; 32]>,
    ingress_link_key: Option<[u8; 32]>,
    peer_table: &HashMap<RelayId, PeerInfo>,
    rng: &mut R,
    bridge_config: &LinkBridgeConfig,
    peer_health: Option<&PeerHealthTracker>,
) -> Result<(LinkKey, Option<RelayId>), NetError> {
    #[cfg(feature = "noise-link")]
    if bridge_config.responder_selects_noise() {
        return run_responder_noise_handshake(
            stream,
            ingress_link_key,
            peer_table,
            rng,
            bridge_config,
            peer_health,
        )
        .await;
    }

    let read_timeout = bridge_config.read_timeout;

    let mut init_msg = [0u8; LINK_HANDSHAKE_INIT_LEN];
    read_exact_timeout(stream, &mut init_msg, read_timeout).await?;
    let init = parse_link_handshake_init(&init_msg)?;

    let (resp_sk, resp_msg) = link_handshake_resp_write(rng);
    let resp = parse_link_handshake_resp(&resp_msg)?;
    write_all_timeout(stream, &resp_msg, read_timeout).await?;

    let mut confirm_msg = [0u8; LINK_HANDSHAKE_CONFIRM_LEN];
    read_exact_timeout(stream, &mut confirm_msg, read_timeout).await?;
    let confirm = parse_link_handshake_mac(&confirm_msg)?;

    let transcript = LinkHandshakeTranscript::from_messages(&init, &resp);
    let binding = link_handshake_binding(bridge_config, local_relay_id, local_kem_commitment);
    let binding_ref = binding.as_ref();

    if let Some(psk) = ingress_link_key {
        if verify_link_handshake_confirm_mac(&psk, &transcript, binding_ref, &confirm) {
            let session = link_handshake_responder_finish(
                &psk,
                resp_sk,
                &init,
                &resp,
                &confirm_msg,
                binding_ref,
            )?;
            let finish = link_handshake_finish_mac(&psk, &transcript, binding_ref);
            write_all_timeout(stream, &finish, read_timeout).await?;
            return Ok((session, None));
        }
    }

    for (id, peer) in peer_table {
        let psk = peer.link_key_bytes;
        if verify_link_handshake_confirm_mac(&psk, &transcript, binding_ref, &confirm) {
            let matched = *id;
            match link_handshake_responder_finish(
                &psk,
                resp_sk,
                &init,
                &resp,
                &confirm_msg,
                binding_ref,
            ) {
                Ok(session) => {
                    let finish = link_handshake_finish_mac(&psk, &transcript, binding_ref);
                    if let Err(e) = write_all_timeout(stream, &finish, read_timeout).await {
                        record_inbound_handshake_outcome(peer_health, Some(matched), false);
                        return Err(e.into());
                    }
                    record_inbound_handshake_outcome(peer_health, Some(matched), true);
                    return Ok((session, Some(matched)));
                }
                Err(e) => {
                    record_inbound_handshake_outcome(peer_health, Some(matched), false);
                    return Err(e.into());
                }
            }
        }
    }

    Err(NetError::UnidentifiedInbound)
}

#[cfg(feature = "noise-link")]
async fn run_responder_noise_handshake<R: RngCore + CryptoRngCore>(
    stream: &mut TcpStream,
    ingress_link_key: Option<[u8; 32]>,
    peer_table: &HashMap<RelayId, PeerInfo>,
    rng: &mut R,
    bridge_config: &LinkBridgeConfig,
    peer_health: Option<&PeerHealthTracker>,
) -> Result<(LinkKey, Option<RelayId>), NetError> {
    use aegis_crypto::noise_link::{
        derive_noise_static_secret, noise_ik_responder_read_msg1, noise_static_public,
        verify_noise_static_public, NOISE_IK_MSG1_LEN,
    };

    let local_sk = bridge_config
        .noise_static_secret
        .ok_or(NetError::NoiseConfig("missing local noise_static_secret"))?;
    let read_timeout = bridge_config.read_timeout;

    let mut msg1 = [0u8; NOISE_IK_MSG1_LEN];
    read_exact_timeout(stream, &mut msg1, read_timeout).await?;
    let resp_state = noise_ik_responder_read_msg1(&local_sk, &msg1, rng)?;
    let initiator_pk = resp_state.initiator_static_pk;
    let msg2 = *resp_state.msg2();

    let mut candidates: Vec<([u8; 32], Option<RelayId>)> = Vec::new();
    if let Some(expected) = bridge_config.ingress_noise_static_public {
        candidates.push((expected, None));
    } else if let Some(ingress_psk) = ingress_link_key {
        candidates.push((
            noise_static_public(&derive_noise_static_secret(&ingress_psk)),
            None,
        ));
    }
    for (id, peer) in peer_table {
        let expected = match peer.noise_static_public {
            Some(pk) => pk,
            None => noise_static_public(&derive_noise_static_secret(&peer.link_key_bytes)),
        };
        candidates.push((expected, Some(*id)));
    }

    let mut matched_expected: Option<([u8; 32], Option<RelayId>)> = None;
    for (expected, matched) in candidates {
        if verify_noise_static_public(&initiator_pk, &expected) {
            matched_expected = Some((expected, matched));
            break;
        }
    }

    let Some((expected, matched)) = matched_expected else {
        return Err(NetError::UnidentifiedInbound);
    };

    match resp_state.into_session_if_peer_matches(&expected) {
        Ok(session) => {
            if let Err(e) = write_all_timeout(stream, &msg2, read_timeout).await {
                record_inbound_handshake_outcome(peer_health, matched, false);
                return Err(e);
            }
            record_inbound_handshake_outcome(peer_health, matched, true);
            Ok((session, matched))
        }
        Err(e) => {
            record_inbound_handshake_outcome(peer_health, matched, false);
            Err(e.into())
        }
    }
}


fn spawn_inbound_listener(
    listen: InboundListen,
    local_relay_id: RelayId,
    local_kem_commitment: Option<[u8; 32]>,
    peer_table: HashMap<RelayId, PeerInfo>,
    ingress_link_key: Option<[u8; 32]>,
    inbound_tx: mpsc::Sender<SphinxPacket>,
    bridge_config: LinkBridgeConfig,
    peer_health: Option<Arc<PeerHealthTracker>>,
) -> JoinHandle<()> {
    let connection_slots = Arc::new(Semaphore::new(bridge_config.max_inbound_connections));
    let rate_stats = bridge_config
        .ingress_rate_limit_stats
        .clone()
        .unwrap_or_else(|| Arc::new(IngressRateLimitStats::default()));
    let queue_drop_stats = bridge_config
        .queue_drop_stats
        .clone()
        .unwrap_or_else(|| Arc::new(QueueDropStats::default()));
    let rate_limit_config = bridge_config.ingress_rate_limit.clone();
    let global_rate_bucket = rate_limit_config
        .global_max_cells_per_sec
        .filter(|&rate| rate > 0.0)
        .map(|rate| {
            Arc::new(Mutex::new(TokenBucket::new(
                rate,
                rate_limit_config.burst,
            )))
        });
    let fair_hub = FairInboundHub::new();
    tokio::spawn(async move {
        // Keep the drain JoinHandle alive for the listener lifetime; dropping it
        // would abort the task and starve the mix inbound channel.
        let _fair_drain = spawn_fair_inbound_drain(
            Arc::clone(&fair_hub),
            inbound_tx,
            Arc::clone(&queue_drop_stats),
        );
        let listener = match listen {
            InboundListen::Listener(l) => l,
            InboundListen::Bind(listen_addr) => match TcpListener::bind(listen_addr).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("aegis-relay net: bind {listen_addr}: {e}");
                    return;
                }
            },
        };
        loop {
            let Ok((stream, _remote)) = listener.accept().await else {
                continue;
            };
            let permit = match connection_slots.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    eprintln!(
                        "aegis-relay net: rejecting inbound connection (limit {})",
                        bridge_config.max_inbound_connections
                    );
                    drop(stream);
                    continue;
                }
            };
            let peer_table = peer_table.clone();
            let ingress = ingress_link_key;
            let kem = local_kem_commitment;
            let cfg = bridge_config.clone();
            let local_id = local_relay_id;
            let health = peer_health.clone();
            let rate_stats = Arc::clone(&rate_stats);
            let queue_drop_stats = Arc::clone(&queue_drop_stats);
            let rate_limit_config = rate_limit_config.clone();
            let global_rate_bucket = global_rate_bucket.clone();
            let fair_hub = Arc::clone(&fair_hub);
            tokio::spawn(async move {
                let _permit = permit;
                // Do not `unregister` here: dropping the peer queue would discard a
                // just-reassembled Sphinx packet when the client closes TCP immediately
                // after the last fragment (common in lab floods). Closing `peer_tx`
                // (end of this task) lets the fair drain empty remaining items, then
                // clear the slot on `TryRecvError::Disconnected`.
                let (_slot_id, peer_tx) = fair_hub.register(Arc::clone(&queue_drop_stats)).await;
                let result = run_inbound_connection(
                    stream,
                    local_id,
                    kem,
                    peer_table,
                    ingress,
                    peer_tx,
                    &cfg,
                    health.as_deref(),
                    rate_limit_config,
                    rate_stats,
                    global_rate_bucket,
                )
                .await;
                if let Err(e) = result {
                    eprintln!("aegis-relay net: inbound connection ended: {e}");
                }
            });
        }
    })
}

async fn run_inbound_connection(
    mut stream: TcpStream,
    local_relay_id: RelayId,
    local_kem_commitment: Option<[u8; 32]>,
    peer_table: HashMap<RelayId, PeerInfo>,
    ingress_link_key: Option<[u8; 32]>,
    peer_tx: FairPeerSender,
    bridge_config: &LinkBridgeConfig,
    peer_health: Option<&PeerHealthTracker>,
    rate_limit_config: IngressRateLimitConfig,
    rate_stats: Arc<IngressRateLimitStats>,
    global_rate_bucket: Option<Arc<Mutex<TokenBucket>>>,
) -> Result<(), NetError> {
    let mut rng = rand_core::OsRng;
    let (session_key, matched_peer) = run_responder_handshake(
        &mut stream,
        local_relay_id,
        local_kem_commitment,
        ingress_link_key,
        &peer_table,
        &mut rng,
        bridge_config,
        peer_health,
    )
    .await?;

    // Weighted fair inbound: unhealthy peers (low success rate) get lower weight.
    peer_tx
        .set_weight(peer_queue_weight_for(matched_peer, peer_health))
        .await;

    let mut frame = [0u8; LINK_FRAME_LEN];
    let mut reassembler = SphinxReassembler::new();
    let mut rate_limit =
        InboundRateLimitState::new(&rate_limit_config, rate_stats, global_rate_bucket);

    loop {
        read_exact_timeout(&mut stream, &mut frame, bridge_config.read_timeout).await?;
        if !rate_limit.allow_frame().await {
            // Excess cells: drop silently (TCP stays open). Coarse counter only.
            continue;
        }
        let cell = session_key.open(&frame)?;
        // Mode-1 cover / loop / health-gossip cells share the link with Sphinx
        // fragments; handle control cells here so they never poison reassembly.
        match Command::from_u8(cell.as_bytes()[0]) {
            Some(Command::Drop) | Some(Command::LoopToSelf) => continue,
            Some(Command::PeerHealthAdvert) => {
                if let (Some(tracker), Some(link_peer)) = (peer_health, matched_peer) {
                    if let Ok(advert) = PeerHealthAdvert::from_cell(&cell) {
                        let _ = accept_advert(
                            &advert,
                            link_peer,
                            &peer_table,
                            unix_timestamp_secs(),
                            DEFAULT_MAX_ADVERT_AGE_SECS,
                            tracker,
                        );
                    }
                }
                continue;
            }
            Some(Command::SphinxFragment) if is_relay_cover_fragment(&cell) => continue,
            Some(Command::SphinxFragment) => {}
            _ => continue,
        }
        if let Some(packet) = reassembler.push(&cell)? {
            // Per-peer drop-newest; fair drain moves packets into the mix inbound.
            if peer_tx.try_enqueue(packet).is_err() {
                break;
            }
        }
    }
    Ok(())
}

fn spawn_gossip_dispatcher<R: RngCore + CryptoRngCore + Send + 'static>(
    gossip_rx: mpsc::Receiver<GossipOutbound>,
    peer_table: HashMap<RelayId, PeerInfo>,
    rng: Arc<Mutex<R>>,
    bridge_config: LinkBridgeConfig,
    peer_health: Option<Arc<PeerHealthTracker>>,
) {
    tokio::spawn(async move {
        let pool = Arc::new(Mutex::new(ConnectionPool::new()));
        let mut gossip_rx = gossip_rx;
        while let Some((peer_id, cell)) = gossip_rx.recv().await {
            let peer = match peer_table.get(&peer_id) {
                Some(p) => p.clone(),
                None => continue,
            };
            let mut guard = rng.lock().await;
            if let Err(e) = write_gossip_cell(
                &pool,
                peer_id,
                &peer,
                &cell,
                &mut *guard,
                &bridge_config,
                &peer_health,
            )
            .await
            {
                eprintln!("aegis-relay net: health gossip to {:?}: {e}", peer.addr);
            }
        }
    });
}

async fn write_gossip_cell<R: RngCore + CryptoRngCore>(
    pool: &Arc<Mutex<ConnectionPool>>,
    peer_id: RelayId,
    peer: &PeerInfo,
    cell: &Cell,
    rng: &mut R,
    bridge_config: &LinkBridgeConfig,
    peer_health: &Option<Arc<PeerHealthTracker>>,
) -> Result<(), NetError> {
    let conn = match {
        let mut pool = pool.lock().await;
        pool.get_or_handshake(peer_id, peer, rng, bridge_config).await
    } {
        Ok(c) => c,
        Err(e) => {
            record_peer_outcome(peer_health, peer_id, false);
            return Err(e);
        }
    };
    let mut guard = conn.lock().await;
    let session_key = LinkKey::new(*guard.session_key.as_bytes());
    // Pace real bulk on the same τ schedule as cover (cover-burst indistinguishability).
    let pace = bridge_config.cover_cell_tau;
    match write_cells_on_stream(
        &mut guard.stream,
        &session_key,
        std::slice::from_ref(cell),
        rng,
        bridge_config.read_timeout,
        pace,
    )
    .await
    {
        Ok(()) => {
            record_peer_outcome(peer_health, peer_id, true);
            Ok(())
        }
        Err(NetError::Io(_)) | Err(NetError::ReadTimeout(_)) => {
            drop(guard);
            let conn = match {
                let mut pool = pool.lock().await;
                pool.reconnect(peer_id, peer, rng, bridge_config).await
            } {
                Ok(c) => c,
                Err(e) => {
                    record_peer_outcome(peer_health, peer_id, false);
                    return Err(e);
                }
            };
            let mut guard = conn.lock().await;
            let session_key = LinkKey::new(*guard.session_key.as_bytes());
            match write_cells_on_stream(
                &mut guard.stream,
                &session_key,
                std::slice::from_ref(cell),
                rng,
                bridge_config.read_timeout,
                pace,
            )
            .await
            {
                Ok(()) => {
                    record_peer_outcome(peer_health, peer_id, true);
                    Ok(())
                }
                Err(e) => {
                    record_peer_outcome(peer_health, peer_id, false);
                    Err(e)
                }
            }
        }
        Err(e) => {
            record_peer_outcome(peer_health, peer_id, false);
            Err(e)
        }
    }
}

fn pick_cover_egress(peer_table: &HashMap<RelayId, PeerInfo>) -> Option<(RelayId, PeerInfo)> {
    let mut peers: Vec<_> = peer_table
        .iter()
        .map(|(id, info)| (*id, info.clone()))
        .collect();
    peers.sort_by_key(|(_, p)| p.addr);
    peers.into_iter().next()
}

fn spawn_cover_dispatcher<R: RngCore + CryptoRngCore + Send + 'static>(
    cover_rx: mpsc::Receiver<Vec<Cell>>,
    peer_table: HashMap<RelayId, PeerInfo>,
    forward_trace: Option<RelayForwardTrace>,
    rng: Arc<Mutex<R>>,
    bridge_config: LinkBridgeConfig,
    peer_health: Option<Arc<PeerHealthTracker>>,
) {
    tokio::spawn(async move {
        let pool = Arc::new(Mutex::new(ConnectionPool::new()));
        let mut cover_rx = cover_rx;
        let mut logged_empty_peer = false;
        while let Some(cells) = cover_rx.recv().await {
            let (peer_id, peer) = match pick_cover_egress(&peer_table) {
                Some(p) => p,
                None => {
                    if !logged_empty_peer {
                        eprintln!("aegis-relay net: cover egress skipped (empty peer table)");
                        logged_empty_peer = true;
                    }
                    continue;
                }
            };
            let mut guard = rng.lock().await;
            match write_cover_cells(
                &pool,
                peer_id,
                &peer,
                &cells,
                &mut *guard,
                &bridge_config,
                &peer_health,
            )
            .await
            {
                Ok(()) => {
                    if let Some(ref trace) = forward_trace {
                        trace.record_cover(cells.len() as u32);
                    }
                }
                Err(e) => {
                    eprintln!("aegis-relay net: cover egress to {:?}: {e}", peer.addr);
                }
            }
        }
    });
}

async fn write_cover_cells<R: RngCore + CryptoRngCore>(
    pool: &Arc<Mutex<ConnectionPool>>,
    peer_id: RelayId,
    peer: &PeerInfo,
    cells: &[Cell],
    rng: &mut R,
    bridge_config: &LinkBridgeConfig,
    peer_health: &Option<Arc<PeerHealthTracker>>,
) -> Result<(), NetError> {
    let conn = match {
        let mut pool = pool.lock().await;
        pool.get_or_handshake(peer_id, peer, rng, bridge_config).await
    } {
        Ok(c) => c,
        Err(e) => {
            record_peer_outcome(peer_health, peer_id, false);
            return Err(e);
        }
    };
    let mut guard = conn.lock().await;
    let session_key = LinkKey::new(*guard.session_key.as_bytes());
    let pace = bridge_config.cover_cell_tau;
    match write_cells_on_stream(
        &mut guard.stream,
        &session_key,
        cells,
        rng,
        bridge_config.read_timeout,
        pace,
    )
    .await
    {
        Ok(()) => {
            record_peer_outcome(peer_health, peer_id, true);
            Ok(())
        }
        Err(NetError::Io(_)) | Err(NetError::ReadTimeout(_)) => {
            drop(guard);
            let conn = match {
                let mut pool = pool.lock().await;
                pool.reconnect(peer_id, peer, rng, bridge_config).await
            } {
                Ok(c) => c,
                Err(e) => {
                    record_peer_outcome(peer_health, peer_id, false);
                    return Err(e);
                }
            };
            let mut guard = conn.lock().await;
            let session_key = LinkKey::new(*guard.session_key.as_bytes());
            match write_cells_on_stream(
                &mut guard.stream,
                &session_key,
                cells,
                rng,
                bridge_config.read_timeout,
                pace,
            )
            .await
            {
                Ok(()) => {
                    record_peer_outcome(peer_health, peer_id, true);
                    Ok(())
                }
                Err(e) => {
                    record_peer_outcome(peer_health, peer_id, false);
                    Err(e)
                }
            }
        }
        Err(e) => {
            record_peer_outcome(peer_health, peer_id, false);
            Err(e)
        }
    }
}

async fn write_cells_on_stream<R: RngCore + CryptoRngCore>(
    stream: &mut TcpStream,
    link_key: &LinkKey,
    cells: &[Cell],
    rng: &mut R,
    read_timeout: Duration,
    cell_pace: Duration,
) -> Result<(), NetError> {
    for (i, cell) in cells.iter().enumerate() {
        if i > 0 && !cell_pace.is_zero() {
            tokio::time::sleep(cell_pace).await;
        }
        let frame = link_key.seal(cell, rng)?;
        write_all_timeout(stream, &frame, read_timeout).await?;
    }
    stream.flush().await?;
    Ok(())
}

struct PooledConnection {
    stream: TcpStream,
    session_key: LinkKey,
}

struct ConnectionPool {
    connections: HashMap<SocketAddr, Arc<Mutex<PooledConnection>>>,
}

impl ConnectionPool {
    fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    async fn get_or_handshake<R: RngCore + CryptoRngCore>(
        &mut self,
        peer_id: RelayId,
        peer: &PeerInfo,
        rng: &mut R,
        bridge_config: &LinkBridgeConfig,
    ) -> Result<Arc<Mutex<PooledConnection>>, NetError> {
        if let Some(s) = self.connections.get(&peer.addr) {
            return Ok(Arc::clone(s));
        }
        let mut stream = TcpStream::connect(peer.addr).await?;
        let session_key = run_initiator_handshake(
            &mut stream,
            &peer.link_key_bytes,
            peer_id,
            peer.kem_public_commitment,
            peer.noise_static_public,
            rng,
            bridge_config,
        )
        .await?;
        let shared = Arc::new(Mutex::new(PooledConnection { stream, session_key }));
        self.connections.insert(peer.addr, Arc::clone(&shared));
        Ok(shared)
    }

    async fn reconnect<R: RngCore + CryptoRngCore>(
        &mut self,
        peer_id: RelayId,
        peer: &PeerInfo,
        rng: &mut R,
        bridge_config: &LinkBridgeConfig,
    ) -> Result<Arc<Mutex<PooledConnection>>, NetError> {
        self.connections.remove(&peer.addr);
        self.get_or_handshake(peer_id, peer, rng, bridge_config).await
    }
}

fn spawn_outbound_dispatcher<R: RngCore + CryptoRngCore + Send + 'static>(
    outbound_rx: mpsc::Receiver<ForwardedPacket>,
    peer_table: HashMap<RelayId, PeerInfo>,
    exit_tx: Option<ExitSink>,
    forward_trace: Option<RelayForwardTrace>,
    rng: Arc<Mutex<R>>,
    bridge_config: LinkBridgeConfig,
    peer_health: Option<Arc<PeerHealthTracker>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let pool = Arc::new(Mutex::new(ConnectionPool::new()));
        let fair_hub = FairOutboundHub::new();
        let outbound_drop_stats = Arc::new(QueueDropStats::default());
        let router_done = Arc::new(AtomicBool::new(false));

        let mut peer_senders: HashMap<RelayId, FairOutboundPeerSender> = HashMap::new();
        for (peer_id, _) in &peer_table {
            let weight = peer_queue_weight_for(Some(*peer_id), peer_health.as_deref());
            let sender = fair_hub
                .register_peer(Arc::clone(&outbound_drop_stats), weight)
                .await;
            peer_senders.insert(*peer_id, sender);
        }

        let drain = spawn_fair_outbound_drain(
            Arc::clone(&fair_hub),
            Arc::clone(&router_done),
            Arc::clone(&pool),
            peer_table.clone(),
            forward_trace.clone(),
            Arc::clone(&rng),
            bridge_config.clone(),
            peer_health.clone(),
        );

        let mut outbound_rx = outbound_rx;
        while let Some(fwd) = outbound_rx.recv().await {
            if let Some(ref tx) = exit_tx {
                if peer_table.get(&fwd.next_hop).is_none() {
                    if let Some(ref trace) = forward_trace {
                        trace.record_exit(SPHINX_FRAGMENT_COUNT as u32);
                    }
                    let _ = tx.send(fwd.packet).await;
                    continue;
                }
            }
            if peer_table.get(&fwd.next_hop).is_none() {
                continue;
            }
            if let Some(sender) = peer_senders.get(&fwd.next_hop) {
                let weight = peer_queue_weight_for(Some(fwd.next_hop), peer_health.as_deref());
                sender.set_weight(weight).await;
                let _ = sender.try_enqueue(fwd);
            }
        }
        router_done.store(true, Ordering::Relaxed);
        fair_hub.notify.notify_one();
        let _ = drain.await;
    })
}

async fn forward_to_peer<R: RngCore + CryptoRngCore>(
    pool: &Arc<Mutex<ConnectionPool>>,
    peer_id: RelayId,
    peer: &PeerInfo,
    packet: &SphinxPacket,
    rng: &mut R,
    bridge_config: &LinkBridgeConfig,
    peer_health: &Option<Arc<PeerHealthTracker>>,
) -> Result<(), NetError> {
    let conn = match {
        let mut pool = pool.lock().await;
        pool.get_or_handshake(peer_id, peer, rng, bridge_config).await
    } {
        Ok(c) => c,
        Err(e) => {
            record_peer_outcome(peer_health, peer_id, false);
            return Err(e);
        }
    };
    let mut guard = conn.lock().await;
    let session_key = LinkKey::new(*guard.session_key.as_bytes());
    match write_packet_with_key(
        &mut guard.stream,
        &session_key,
        packet,
        rng,
        bridge_config.read_timeout,
    )
    .await
    {
        Ok(()) => {
            record_peer_outcome(peer_health, peer_id, true);
            Ok(())
        }
        Err(NetError::Io(_)) | Err(NetError::ReadTimeout(_)) => {
            drop(guard);
            let conn = match {
                let mut pool = pool.lock().await;
                pool.reconnect(peer_id, peer, rng, bridge_config).await
            } {
                Ok(c) => c,
                Err(e) => {
                    record_peer_outcome(peer_health, peer_id, false);
                    return Err(e);
                }
            };
            let mut guard = conn.lock().await;
            let session_key = LinkKey::new(*guard.session_key.as_bytes());
            match write_packet_with_key(
                &mut guard.stream,
                &session_key,
                packet,
                rng,
                bridge_config.read_timeout,
            )
            .await
            {
                Ok(()) => {
                    record_peer_outcome(peer_health, peer_id, true);
                    Ok(())
                }
                Err(e) => {
                    record_peer_outcome(peer_health, peer_id, false);
                    Err(e)
                }
            }
        }
        Err(e) => {
            record_peer_outcome(peer_health, peer_id, false);
            Err(e)
        }
    }
}

/// Read exactly one Sphinx packet (18 frames) from a stream using `link_key`.
pub async fn read_one_packet(
    stream: &mut TcpStream,
    link_key: &LinkKey,
) -> Result<SphinxPacket, NetError> {
    let mut reassembler = SphinxReassembler::new();
    let mut frame = [0u8; LINK_FRAME_LEN];
    for _ in 0..SPHINX_FRAGMENT_COUNT {
        read_exact_timeout(stream, &mut frame, DEFAULT_LINK_READ_TIMEOUT).await?;
        let cell = link_key.open(&frame)?;
        if let Some(packet) = reassembler.push(&cell)? {
            return Ok(packet);
        }
    }
    Err(NetError::Crypto(CryptoError::Malformed("incomplete packet")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use rand_core::OsRng;

    fn test_psk(tag: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = tag;
        k
    }

    fn test_relay_id(tag: u8) -> RelayId {
        let mut id = [0u8; 32];
        id[0] = tag;
        RelayId(id)
    }

    #[tokio::test]
    async fn link_session_sends_cells_one_at_a_time() {
        use aegis_crypto::cell::Cell;

        let psk = test_psk(0xCD);
        let relay_id = test_relay_id(0xCD);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = LinkBridgeConfig::default();
        let cfg_server = cfg.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            let (key, _) = run_responder_handshake(
                &mut stream,
                relay_id,
                None,
                Some(psk),
                &HashMap::new(),
                &mut rng,
                &cfg_server,
                None,
            )
            .await
            .unwrap();

            let mut frame = [0u8; LINK_FRAME_LEN];
            for _ in 0..3 {
                read_exact_timeout(&mut stream, &mut frame, cfg_server.read_timeout)
                    .await
                    .unwrap();
                let cell = key.open(&frame).unwrap();
                assert_eq!(cell.as_bytes().len(), aegis_crypto::cell::CELL_LEN);
            }
        });

        let mut rng = OsRng;
        let mut session = LinkSession::connect(addr, &psk, relay_id, None, None, &mut rng, &cfg)
            .await
            .unwrap();
        for i in 0..3u8 {
            let mut cell = Cell::zeroed();
            cell.0[0] = i;
            session.send_cell(&cell, &mut rng).await.unwrap();
        }
        session.flush().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn initiator_responder_handshake_roundtrip() {
        let psk = test_psk(0xAB);
        let relay_id = test_relay_id(0xAB);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = LinkBridgeConfig::default();
        let cfg_server = cfg.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            run_responder_handshake(
                &mut stream,
                relay_id,
                None,
                Some(psk),
                &HashMap::new(),
                &mut rng,
                &cfg_server,
                None,
            )
            .await
            .unwrap()
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let key_i = run_initiator_handshake(&mut client, &psk, relay_id, None, None, &mut rng, &cfg)
            .await
            .unwrap();
        let (key_r, _) = server.await.unwrap();
        assert_eq!(key_i, key_r);
    }

    #[tokio::test]
    async fn wrong_peer_id_handshake_rejected() {
        let psk = test_psk(0x11);
        let expected = test_relay_id(0x11);
        let wrong = test_relay_id(0x22);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = LinkBridgeConfig::default();
        let cfg_server = cfg.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            run_responder_handshake(
                &mut stream,
                expected,
                None,
                Some(psk),
                &HashMap::new(),
                &mut rng,
                &cfg_server,
                None,
            )
            .await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let err =
            run_initiator_handshake(&mut client, &psk, wrong, None, None, &mut rng, &cfg).await;
        assert!(matches!(
            err,
            Err(NetError::ReadTimeout(_))
                | Err(NetError::Io(_))
                | Err(NetError::Crypto(CryptoError::IntegrityFailure))
        ));
        let server_err = server.await.unwrap();
        assert!(matches!(server_err, Err(NetError::UnidentifiedInbound)));
    }

    #[tokio::test]
    async fn wrong_psk_handshake_rejected() {
        let psk = test_psk(0x01);
        let wrong = test_psk(0x02);
        let relay_id = test_relay_id(0x01);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = LinkBridgeConfig::default();
        let cfg_server = cfg.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            run_responder_handshake(
                &mut stream,
                relay_id,
                None,
                Some(wrong),
                &HashMap::new(),
                &mut rng,
                &cfg_server,
                None,
            )
            .await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let err = run_initiator_handshake(&mut client, &psk, relay_id, None, None, &mut rng, &cfg).await;
        assert!(matches!(
            err,
            Err(NetError::ReadTimeout(_))
                | Err(NetError::Io(_))
                | Err(NetError::Crypto(CryptoError::IntegrityFailure))
        ));
        let server_err = server.await.unwrap();
        assert!(matches!(server_err, Err(NetError::UnidentifiedInbound)));
    }

    #[tokio::test]
    async fn cover_dispatcher_writes_sealed_frames() {
        use aegis_crypto::cell::Command;
        use aegis_crypto::fragment::SPHINX_FRAGMENT_COUNT;
        use crate::cover_flow::CoverFlowGenerator;
        use aegis_negotiator::cover::CoverRequirement;

        let psk = test_psk(0xEE);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = LinkBridgeConfig::default();
        let cfg_server = cfg.clone();
        let peer_id = test_relay_id(9);
        let local_id = test_relay_id(0xEE);
        let peer_table = HashMap::from([(peer_id, PeerInfo::new(addr, psk))]);

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            let (key, _) = run_responder_handshake(
                &mut stream,
                peer_id,
                None,
                Some(psk),
                &HashMap::new(),
                &mut rng,
                &cfg_server,
                None,
            )
            .await
            .unwrap();

            let mut frame = [0u8; LINK_FRAME_LEN];
            let mut frames = 0usize;
            for _ in 0..SPHINX_FRAGMENT_COUNT {
                read_exact_timeout(&mut stream, &mut frame, cfg_server.read_timeout)
                    .await
                    .unwrap();
                let cell = key.open(&frame).unwrap();
                assert_eq!(cell.as_bytes()[0], Command::SphinxFragment as u8);
                frames += 1;
            }
            frames
        });

        let (cover_tx, cover_rx) = mpsc::channel(4);
        let (_listener_task, _dispatcher_task) = spawn_link_bridge(
            "127.0.0.1:0".parse().unwrap(),
            local_id,
            None,
            peer_table,
            None,
            mpsc::channel(1).0,
            mpsc::channel(1).1,
            Some(cover_rx),
            None,
            None,
            None,
            OsRng,
            cfg,
            None,
        );

        let gen = CoverFlowGenerator::new(CoverRequirement::new(4));
        let flow = gen.generate(1, &mut OsRng).into_iter().next().unwrap();
        cover_tx.send(flow.cells).await.unwrap();
        drop(cover_tx);

        let frames = server.await.unwrap();
        assert_eq!(frames, SPHINX_FRAGMENT_COUNT);
    }

    #[tokio::test]
    async fn truncated_handshake_init_graceful_err() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = LinkBridgeConfig {
            read_timeout: Duration::from_millis(200),
            ..Default::default()
        };

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            run_responder_handshake(
                &mut stream,
                test_relay_id(0x01),
                None,
                None,
                &HashMap::new(),
                &mut rng,
                &cfg,
                None,
            )
            .await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0u8; LINK_HANDSHAKE_INIT_LEN - 1]).await.unwrap();
        let err = server.await.unwrap();
        assert!(matches!(err, Err(NetError::ReadTimeout(_))));
    }

    #[tokio::test]
    async fn cover_emit_empty_peer_table_is_quiet() {
        use crate::cover_flow::CoverFlowGenerator;
        use aegis_negotiator::cover::CoverRequirement;

        let (cover_tx, cover_rx) = mpsc::channel(4);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(4);
        let (_listener_task, _dispatcher_task) = spawn_link_bridge(
            "127.0.0.1:0".parse().unwrap(),
            test_relay_id(0x01),
            None,
            HashMap::new(),
            None,
            inbound_tx,
            mpsc::channel(1).1,
            Some(cover_rx),
            None,
            None,
            None,
            OsRng,
            LinkBridgeConfig::default(),
            None,
        );

        let gen = CoverFlowGenerator::new(CoverRequirement::new(1));
        let flow = gen.generate(0, &mut OsRng).into_iter().next().unwrap();
        cover_tx.send(flow.cells).await.unwrap();
        drop(cover_tx);

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            inbound_rx.try_recv().is_err(),
            "cover must not enter Sphinx inbound when peer table is empty"
        );
    }

    #[tokio::test]
    async fn inbound_skips_relay_cover_fragments() {
        use crate::cover_flow::CoverFlowGenerator;
        use aegis_negotiator::cover::CoverRequirement;

        let psk = test_psk(0xCF);
        let relay_id = test_relay_id(0xCF);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = LinkBridgeConfig::default().without_ingress_rate_limit();
        let (inbound_tx, mut inbound_rx) = mpsc::channel(4);

        let server_cfg = cfg.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let hub = FairInboundHub::new();
            let drop_stats = Arc::new(QueueDropStats::default());
            let (_slot, peer_tx) = hub.register(Arc::clone(&drop_stats)).await;
            let _drain = spawn_fair_inbound_drain(Arc::clone(&hub), inbound_tx, drop_stats);
            run_inbound_connection(
                stream,
                relay_id,
                None,
                HashMap::new(),
                Some(psk),
                peer_tx,
                &server_cfg,
                None,
                server_cfg.ingress_rate_limit.clone(),
                Arc::new(IngressRateLimitStats::default()),
                None,
            )
            .await
        });

        let gen = CoverFlowGenerator::new(CoverRequirement::new(1));
        let flow = gen.generate(0, &mut OsRng).into_iter().next().unwrap();

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let mut rng = OsRng;
            let session_key =
                run_initiator_handshake(&mut stream, &psk, relay_id, None, None, &mut rng, &cfg)
                    .await
                    .unwrap();
            write_cells_on_stream(
                &mut stream,
                &session_key,
                &flow.cells,
                &mut rng,
                cfg.read_timeout,
                Duration::ZERO,
            )
            .await
            .unwrap();
        });

        client.await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("inbound should finish after cover burst");
        assert!(
            inbound_rx.try_recv().is_err(),
            "relay-cover fragments must not reassemble into Sphinx inbound"
        );
    }

    #[tokio::test]
    async fn matching_kem_commitment_handshake_succeeds() {
        let psk = test_psk(0xB1);
        let relay_id = test_relay_id(0xB1);
        let commitment = [0xAAu8; 32];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = LinkBridgeConfig::default();
        let cfg_server = cfg.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            run_responder_handshake(
                &mut stream,
                relay_id,
                Some(commitment),
                Some(psk),
                &HashMap::new(),
                &mut rng,
                &cfg_server,
                None,
            )
            .await
            .unwrap()
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let key_i = run_initiator_handshake(
            &mut client,
            &psk,
            relay_id,
            Some(commitment),
            None,
            &mut rng,
            &cfg,
        )
        .await
        .unwrap();
        let (key_r, _) = server.await.unwrap();
        assert_eq!(key_i, key_r);
    }

    #[tokio::test]
    async fn mismatched_kem_commitment_handshake_fails() {
        let psk = test_psk(0xB2);
        let relay_id = test_relay_id(0xB2);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = LinkBridgeConfig::default();
        let cfg_server = cfg.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            run_responder_handshake(
                &mut stream,
                relay_id,
                Some([0x11u8; 32]),
                Some(psk),
                &HashMap::new(),
                &mut rng,
                &cfg_server,
                None,
            )
            .await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let err = run_initiator_handshake(
            &mut client,
            &psk,
            relay_id,
            Some([0x22u8; 32]),
            None,
            &mut rng,
            &cfg,
        )
        .await;
        assert!(matches!(
            err,
            Err(NetError::ReadTimeout(_))
                | Err(NetError::Io(_))
                | Err(NetError::Crypto(CryptoError::IntegrityFailure))
        ));
        let server_err = server.await.unwrap();
        assert!(matches!(server_err, Err(NetError::UnidentifiedInbound)));
    }

    #[tokio::test]
    async fn missing_kem_commitment_both_sides_relay_id_only() {
        let psk = test_psk(0xB3);
        let relay_id = test_relay_id(0xB3);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = LinkBridgeConfig::default();
        let cfg_server = cfg.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            run_responder_handshake(
                &mut stream,
                relay_id,
                None,
                Some(psk),
                &HashMap::new(),
                &mut rng,
                &cfg_server,
                None,
            )
            .await
            .unwrap()
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let key_i = run_initiator_handshake(&mut client, &psk, relay_id, None, None, &mut rng, &cfg)
            .await
            .unwrap();
        let (key_r, _) = server.await.unwrap();
        assert_eq!(key_i, key_r);
    }

    #[tokio::test]
    async fn inbound_peer_table_handshake_records_peer_health() {
        let psk = test_psk(0x55);
        let peer_id = test_relay_id(0x55);
        let local_id = test_relay_id(0xAA);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = LinkBridgeConfig::default();
        let cfg_server = cfg.clone();
        let peer_table = HashMap::from([(peer_id, PeerInfo::new(addr, psk))]);
        let health = Arc::new(PeerHealthTracker::new());
        let health_server = Arc::clone(&health);

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            run_responder_handshake(
                &mut stream,
                local_id,
                None,
                None,
                &peer_table,
                &mut rng,
                &cfg_server,
                Some(health_server.as_ref()),
            )
            .await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        run_initiator_handshake(&mut client, &psk, local_id, None, None, &mut rng, &cfg)
            .await
            .unwrap();
        server.await.unwrap().unwrap();

        assert_eq!(
            health.failure_rate(*peer_id.as_bytes()),
            Some(0.0),
            "inbound peer-table handshake should record success for matched peer"
        );
    }

    #[tokio::test]
    async fn unidentified_inbound_handshake_does_not_record_peer_health() {
        let psk = test_psk(0x66);
        let peer_id = test_relay_id(0x66);
        let local_id = test_relay_id(0xBB);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = LinkBridgeConfig::default();
        let cfg_server = cfg.clone();
        let peer_table = HashMap::from([(peer_id, PeerInfo::new(addr, test_psk(0x99)))]);

        let health = Arc::new(PeerHealthTracker::new());
        let health_server = Arc::clone(&health);

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            run_responder_handshake(
                &mut stream,
                local_id,
                None,
                None,
                &peer_table,
                &mut rng,
                &cfg_server,
                Some(health_server.as_ref()),
            )
            .await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let _ = run_initiator_handshake(&mut client, &psk, local_id, None, None, &mut rng, &cfg).await;
        assert!(matches!(
            server.await.unwrap(),
            Err(NetError::UnidentifiedInbound)
        ));
        assert!(
            health.failure_rate(*peer_id.as_bytes()).is_none(),
            "unidentified inbound must not attribute failure to roster peers"
        );
    }

    #[tokio::test]
    async fn unknown_next_hop_without_exit_sink_is_silent() {
        use aegis_crypto::sphinx::SPHINX_PACKET_LEN;

        let (outbound_tx, outbound_rx) = mpsc::channel(4);
        let (_listener_task, dispatcher_task) = spawn_link_bridge(
            "127.0.0.1:0".parse().unwrap(),
            test_relay_id(0x01),
            None,
            HashMap::new(),
            None,
            mpsc::channel(1).0,
            outbound_rx,
            None,
            None,
            None,
            None,
            OsRng,
            LinkBridgeConfig::default(),
            None,
        );

        let mut random_next = [0u8; 32];
        OsRng.fill_bytes(&mut random_next);
        outbound_tx
            .send(ForwardedPacket {
                next_hop: RelayId(random_next),
                packet: aegis_crypto::sphinx::SphinxPacket::from_bytes([0u8; SPHINX_PACKET_LEN]),
                delay_applied: Duration::ZERO,
            })
            .await
            .unwrap();
        drop(outbound_tx);
        tokio::time::sleep(Duration::from_millis(50)).await;
        dispatcher_task.abort();
    }

    #[tokio::test]
    async fn paced_ingress_cells_accepted_under_default_limit() {
        let psk = test_psk(0xD1);
        let relay_id = test_relay_id(0xD1);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stats = Arc::new(IngressRateLimitStats::default());
        let cfg = LinkBridgeConfig {
            ingress_rate_limit: IngressRateLimitConfig {
                // Comfortably above Mode-1 1/Ï„ â‰ˆ 2.86 cells/s.
                max_cells_per_sec: 10.0,
                burst: 4,
                global_max_cells_per_sec: None,
            },
            ingress_rate_limit_stats: Some(Arc::clone(&stats)),
            ..Default::default()
        };
        let (inbound_tx, _inbound_rx) = mpsc::channel(8);
        let server_cfg = cfg.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let hub = FairInboundHub::new();
            let drop_stats = Arc::new(QueueDropStats::default());
            let (_slot, peer_tx) = hub.register(Arc::clone(&drop_stats)).await;
            let _drain = spawn_fair_inbound_drain(Arc::clone(&hub), inbound_tx, drop_stats);
            let _ = run_inbound_connection(
                stream,
                relay_id,
                None,
                HashMap::new(),
                Some(psk),
                peer_tx,
                &server_cfg,
                None,
                server_cfg.ingress_rate_limit.clone(),
                server_cfg
                    .ingress_rate_limit_stats
                    .clone()
                    .unwrap_or_default(),
                None,
            )
            .await;
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let session_key =
            run_initiator_handshake(&mut stream, &psk, relay_id, None, None, &mut rng, &cfg)
                .await
                .unwrap();
        // One cell every 200ms â‰ˆ 5 cells/s â€” under the 10/s limit.
        for i in 0..6u8 {
            let mut cell = Cell::zeroed();
            cell.0[0] = Command::Drop as u8;
            cell.0[1] = i;
            let frame = session_key.seal(&cell, &mut rng).unwrap();
            write_all_timeout(&mut stream, &frame, cfg.read_timeout)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        drop(stream);
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
        assert_eq!(
            stats.dropped_frames(),
            0,
            "Ï„-paced traffic must pass comfortably"
        );
    }

    #[tokio::test]
    async fn sustained_high_rate_ingress_drops_excess_frames() {
        let psk = test_psk(0xD2);
        let relay_id = test_relay_id(0xD2);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stats = Arc::new(IngressRateLimitStats::default());
        let cfg = LinkBridgeConfig {
            ingress_rate_limit: IngressRateLimitConfig {
                max_cells_per_sec: 5.0,
                burst: 2,
                global_max_cells_per_sec: None,
            },
            ingress_rate_limit_stats: Some(Arc::clone(&stats)),
            ..Default::default()
        };
        let (inbound_tx, _inbound_rx) = mpsc::channel(8);
        let server_cfg = cfg.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let hub = FairInboundHub::new();
            let drop_stats = Arc::new(QueueDropStats::default());
            let (_slot, peer_tx) = hub.register(Arc::clone(&drop_stats)).await;
            let _drain = spawn_fair_inbound_drain(Arc::clone(&hub), inbound_tx, drop_stats);
            let _ = run_inbound_connection(
                stream,
                relay_id,
                None,
                HashMap::new(),
                Some(psk),
                peer_tx,
                &server_cfg,
                None,
                server_cfg.ingress_rate_limit.clone(),
                server_cfg
                    .ingress_rate_limit_stats
                    .clone()
                    .unwrap_or_default(),
                None,
            )
            .await;
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let session_key =
            run_initiator_handshake(&mut stream, &psk, relay_id, None, None, &mut rng, &cfg)
                .await
                .unwrap();
        // Flood 40 cells immediately â€” burst=2 then drop the rest.
        for i in 0..40u8 {
            let mut cell = Cell::zeroed();
            cell.0[0] = Command::Drop as u8;
            cell.0[1] = i;
            let frame = session_key.seal(&cell, &mut rng).unwrap();
            write_all_timeout(&mut stream, &frame, cfg.read_timeout)
                .await
                .unwrap();
        }
        stream.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(stream);
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
        assert!(
            stats.dropped_frames() >= 30,
            "sustained flood should drop most frames, got {}",
            stats.dropped_frames()
        );
    }

    #[test]
    fn default_ingress_rate_aligned_with_mode1_tau() {
        let cfg = IngressRateLimitConfig::default();
        assert!((cfg.max_cells_per_sec - (1.0 / MODE1_TAU_SECS)).abs() < 1e-9);
        assert_eq!(cfg.burst, DEFAULT_INGRESS_BURST);
        assert_eq!(
            cfg.global_max_cells_per_sec,
            Some(DEFAULT_GLOBAL_MAX_CELLS_PER_SEC)
        );
        assert!(
            (DEFAULT_GLOBAL_MAX_CELLS_PER_SEC
                - DEFAULT_EXPECTED_INGRESS_CLIENTS / MODE1_TAU_SECS)
                .abs()
                < 1e-9
        );
        assert_eq!(LinkBridgeConfig::default().cover_cell_tau, DEFAULT_COVER_CELL_TAU);
        assert!(cfg.is_active());
        assert!(!IngressRateLimitConfig::disabled().is_active());
    }

    /// Cover cells on the wire are spaced near Ï„ (Mode-1), not burst at round close.
    ///
    /// Residual (documented): multi-hop Sphinx semantics still differ â€” cover is
    /// discarded at the next hop and never peels/forwards like real bulk.
    #[tokio::test]
    async fn cover_dispatcher_paces_cells_near_tau() {
        use aegis_crypto::cell::Command;
        use crate::cover_flow::CoverFlowGenerator;
        use aegis_negotiator::cover::CoverRequirement;

        let psk = test_psk(0xCF);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tau = Duration::from_millis(40);
        let cfg = LinkBridgeConfig {
            cover_cell_tau: tau,
            ..LinkBridgeConfig::default().without_ingress_rate_limit()
        };
        let cfg_server = cfg.clone();
        let peer_id = test_relay_id(0xCF);
        let local_id = test_relay_id(0xCE);
        let peer_table = HashMap::from([(peer_id, PeerInfo::new(addr, psk))]);
        let cell_count = 5usize;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            let (key, _) = run_responder_handshake(
                &mut stream,
                peer_id,
                None,
                Some(psk),
                &HashMap::new(),
                &mut rng,
                &cfg_server,
                None,
            )
            .await
            .unwrap();

            let mut frame = [0u8; LINK_FRAME_LEN];
            let mut stamps = Vec::with_capacity(cell_count);
            for _ in 0..cell_count {
                read_exact_timeout(&mut stream, &mut frame, cfg_server.read_timeout)
                    .await
                    .unwrap();
                let cell = key.open(&frame).unwrap();
                assert_eq!(cell.as_bytes()[0], Command::SphinxFragment as u8);
                stamps.push(Instant::now());
            }
            stamps
        });

        let (cover_tx, cover_rx) = mpsc::channel(4);
        let (_listener_task, _dispatcher_task) = spawn_link_bridge(
            "127.0.0.1:0".parse().unwrap(),
            local_id,
            None,
            peer_table,
            None,
            mpsc::channel(1).0,
            mpsc::channel(1).1,
            Some(cover_rx),
            None,
            None,
            None,
            OsRng,
            cfg,
            None,
        );

        let gen = CoverFlowGenerator::with_config(
            CoverRequirement::new(1),
            crate::cover_flow::CoverFlowConfig {
                cells_per_flow: cell_count,
            },
        );
        let flow = gen.generate(0, &mut OsRng).into_iter().next().unwrap();
        assert_eq!(flow.cells.len(), cell_count);
        cover_tx.send(flow.cells).await.unwrap();
        drop(cover_tx);

        let stamps = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("cover pacing test timed out")
            .expect("server task");
        assert_eq!(stamps.len(), cell_count);
        for w in stamps.windows(2) {
            let gap = w[1].duration_since(w[0]);
            assert!(
                gap >= tau / 2 && gap < tau * 3,
                "cover cell gap {gap:?} not near τ={tau:?}"
            );
        }
    }


    /// Multi-connection flood is shed by the shared global token bucket even when
    /// each connection stays under a generous per-conn limit.
    #[tokio::test]
    async fn global_ingress_budget_sheds_multi_conn_flood() {
        let psk = test_psk(0xB3);
        let relay_id = test_relay_id(0xB3);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stats = Arc::new(IngressRateLimitStats::default());
        let cfg = LinkBridgeConfig {
            ingress_rate_limit: IngressRateLimitConfig {
                max_cells_per_sec: 200.0,
                burst: 8,
                global_max_cells_per_sec: Some(4.0),
            },
            ingress_rate_limit_stats: Some(Arc::clone(&stats)),
            ..Default::default()
        };

        let (inbound_tx, _inbound_rx) = mpsc::channel(64);
        let _tasks = spawn_link_bridge_with_listener(
            InboundListen::Listener(listener),
            relay_id,
            None,
            HashMap::new(),
            Some(psk),
            inbound_tx,
            mpsc::channel(1).1,
            None,
            None,
            None,
            None,
            OsRng,
            cfg.clone(),
            None,
        );

        async fn flood_conn(
            addr: SocketAddr,
            psk: [u8; 32],
            relay_id: RelayId,
            cfg: LinkBridgeConfig,
            n: u8,
        ) {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let mut rng = OsRng;
            let session_key =
                run_initiator_handshake(&mut stream, &psk, relay_id, None, None, &mut rng, &cfg)
                    .await
                    .unwrap();
            for i in 0..n {
                let mut cell = Cell::zeroed();
                cell.0[0] = Command::Drop as u8;
                cell.0[1] = i;
                let frame = session_key.seal(&cell, &mut rng).unwrap();
                write_all_timeout(&mut stream, &frame, cfg.read_timeout)
                    .await
                    .unwrap();
            }
            stream.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(80)).await;
        }

        let a = tokio::spawn(flood_conn(addr, psk, relay_id, cfg.clone(), 30));
        let b = tokio::spawn(flood_conn(addr, psk, relay_id, cfg.clone(), 30));
        a.await.unwrap();
        b.await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        assert!(
            stats.dropped_frames() >= 40,
            "shared global budget must shed multi-conn flood, dropped={}",
            stats.dropped_frames()
        );
    }

    #[test]
    fn inbound_queue_full_drops_newest_and_counts() {
        use aegis_crypto::sphinx::SPHINX_PACKET_LEN;

        let (tx, mut rx) = mpsc::channel::<SphinxPacket>(1);
        let stats = QueueDropStats::default();
        let mk = || SphinxPacket::from_bytes([0u8; SPHINX_PACKET_LEN]);
        assert!(try_send_drop_newest(&tx, mk(), stats.counter()).is_ok());
        assert!(try_send_drop_newest(&tx, mk(), stats.counter()).is_ok());
        assert_eq!(stats.dropped(), 1, "full inbound must drop newest");
        assert!(rx.try_recv().is_ok(), "first enqueued packet still delivered");
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn spawn_bridge_accepts_ingress_psk_handshake() {
        let psk = test_psk(0xC0);
        let relay_id = test_relay_id(0x01);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (inbound_tx, mut inbound_rx) = mpsc::channel(4);
        let cfg = LinkBridgeConfig::default().without_ingress_rate_limit();

        let _tasks = spawn_link_bridge_with_listener(
            InboundListen::Listener(listener),
            relay_id,
            None,
            HashMap::new(),
            Some(psk),
            inbound_tx,
            mpsc::channel(1).1,
            None,
            None,
            None,
            None,
            OsRng,
            cfg.clone(),
            None,
        );

        let mut rng = OsRng;
        let mut session = LinkSession::connect(addr, &psk, relay_id, None, None, &mut rng, &cfg)
            .await
            .expect("ingress handshake via spawn_link_bridge_with_listener");
        let mut cell = Cell::zeroed();
        cell.0[0] = Command::Drop as u8;
        session.send_cell(&cell, &mut rng).await.unwrap();
        session.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(inbound_rx.try_recv().is_err(), "Drop must not reassemble");
    }

    #[tokio::test]
    async fn fair_inbound_round_robin_interleaves_peers() {
        use aegis_crypto::sphinx::SPHINX_PACKET_LEN;

        let hub = FairInboundHub::new();
        let stats = Arc::new(QueueDropStats::default());
        let (_id_a, tx_a) = hub.register(Arc::clone(&stats)).await;
        let (_id_b, tx_b) = hub.register(Arc::clone(&stats)).await;

        // Tag packets via first payload byte so we can see RR order.
        let mk = |tag: u8| {
            let mut bytes = [0u8; SPHINX_PACKET_LEN];
            bytes[0] = tag;
            SphinxPacket::from_bytes(bytes)
        };
        // Peer A floods 4; peer B sends 2.
        for _ in 0..4 {
            assert!(tx_a.try_enqueue(mk(0xAA)).is_ok());
        }
        for _ in 0..2 {
            assert!(tx_b.try_enqueue(mk(0xBB)).is_ok());
        }

        let mut cursor = 0usize;
        let mut order = Vec::new();
        for _ in 0..6 {
            let pkt = fair_inbound_drain_once_for_test(&hub, &mut cursor)
                .await
                .expect("packet available");
            order.push(pkt.as_bytes()[0]);
        }
        // Equal weights → classic RR: B between A's packets (not AAAA then BB).
        assert_eq!(order, vec![0xAA, 0xBB, 0xAA, 0xBB, 0xAA, 0xAA]);
        assert!(fair_inbound_drain_once_for_test(&hub, &mut cursor).await.is_none());
    }

    #[tokio::test]
    async fn fair_inbound_weighted_prefers_healthy_peer() {
        use aegis_crypto::sphinx::SPHINX_PACKET_LEN;

        let hub = FairInboundHub::new();
        let stats = Arc::new(QueueDropStats::default());
        // Healthy peer weight 3; unhealthy weight 1.
        let (_id_a, tx_a) = hub.register_with_weight(Arc::clone(&stats), 3).await;
        let (_id_b, tx_b) = hub.register_with_weight(Arc::clone(&stats), 1).await;

        let mk = |tag: u8| {
            let mut bytes = [0u8; SPHINX_PACKET_LEN];
            bytes[0] = tag;
            SphinxPacket::from_bytes(bytes)
        };
        for _ in 0..6 {
            assert!(tx_a.try_enqueue(mk(0xAA)).is_ok());
            assert!(tx_b.try_enqueue(mk(0xBB)).is_ok());
        }

        let mut cursor = 0usize;
        let mut order = Vec::new();
        for _ in 0..8 {
            let pkt = fair_inbound_drain_once_for_test(&hub, &mut cursor)
                .await
                .expect("packet available");
            order.push(pkt.as_bytes()[0]);
        }
        // Weight-3 peer gets three packets before weight-1 peer's turn.
        assert_eq!(
            &order[..4],
            &[0xAA, 0xAA, 0xAA, 0xBB],
            "WFQ must serve heavy peer first: {order:?}"
        );
        let a_count = order.iter().filter(|&&b| b == 0xAA).count();
        let b_count = order.iter().filter(|&&b| b == 0xBB).count();
        assert!(a_count > b_count, "healthy peer should win share: {order:?}");
    }

    #[tokio::test]
    async fn fair_outbound_round_robin_interleaves_peers() {
        use aegis_crypto::sphinx::SPHINX_PACKET_LEN;

        let hub = FairOutboundHub::new();
        let stats = Arc::new(QueueDropStats::default());
        let tx_a = hub
            .register_peer(Arc::clone(&stats), DEFAULT_PEER_QUEUE_WEIGHT)
            .await;
        let tx_b = hub
            .register_peer(Arc::clone(&stats), DEFAULT_PEER_QUEUE_WEIGHT)
            .await;

        let mk = |tag: u8| ForwardedPacket {
            next_hop: test_relay_id(tag),
            packet: {
                let mut bytes = [0u8; SPHINX_PACKET_LEN];
                bytes[0] = tag;
                SphinxPacket::from_bytes(bytes)
            },
            delay_applied: Duration::ZERO,
        };
        for _ in 0..4 {
            assert!(tx_a.try_enqueue(mk(0xAA)).is_ok());
        }
        for _ in 0..2 {
            assert!(tx_b.try_enqueue(mk(0xBB)).is_ok());
        }

        let mut cursor = 0usize;
        let mut order = Vec::new();
        for _ in 0..6 {
            let fwd = fair_outbound_drain_once_for_test(&hub, &mut cursor)
                .await
                .expect("packet available");
            order.push(fwd.packet.as_bytes()[0]);
        }
        assert_eq!(order, vec![0xAA, 0xBB, 0xAA, 0xBB, 0xAA, 0xAA]);
        assert!(fair_outbound_drain_once_for_test(&hub, &mut cursor)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn fair_outbound_weighted_prefers_healthy_peer() {
        use aegis_crypto::sphinx::SPHINX_PACKET_LEN;

        let hub = FairOutboundHub::new();
        let stats = Arc::new(QueueDropStats::default());
        let tx_a = hub.register_peer(Arc::clone(&stats), 3).await;
        let tx_b = hub.register_peer(Arc::clone(&stats), 1).await;

        let mk = |tag: u8| ForwardedPacket {
            next_hop: test_relay_id(tag),
            packet: {
                let mut bytes = [0u8; SPHINX_PACKET_LEN];
                bytes[0] = tag;
                SphinxPacket::from_bytes(bytes)
            },
            delay_applied: Duration::ZERO,
        };
        for _ in 0..6 {
            assert!(tx_a.try_enqueue(mk(0xAA)).is_ok());
            assert!(tx_b.try_enqueue(mk(0xBB)).is_ok());
        }

        let mut cursor = 0usize;
        let mut order = Vec::new();
        for _ in 0..8 {
            let fwd = fair_outbound_drain_once_for_test(&hub, &mut cursor)
                .await
                .expect("packet available");
            order.push(fwd.packet.as_bytes()[0]);
        }
        assert_eq!(
            &order[..4],
            &[0xAA, 0xAA, 0xAA, 0xBB],
            "outbound WFQ must serve heavy peer first: {order:?}"
        );
    }

    #[test]
    fn peer_queue_weight_maps_success_rate() {
        assert_eq!(
            peer_queue_weight_from_success_rate(None),
            DEFAULT_PEER_QUEUE_WEIGHT
        );
        assert_eq!(peer_queue_weight_from_success_rate(Some(1.0)), MAX_PEER_QUEUE_WEIGHT);
        assert_eq!(peer_queue_weight_from_success_rate(Some(0.0)), DEFAULT_PEER_QUEUE_WEIGHT);
        assert_eq!(peer_queue_weight_from_success_rate(Some(0.5)), 4);
    }

    #[tokio::test]
    async fn fair_peer_queue_full_drops_newest_not_other_peer() {
        use aegis_crypto::sphinx::SPHINX_PACKET_LEN;

        let hub = FairInboundHub::new();
        let stats = Arc::new(QueueDropStats::default());
        let (_id_a, tx_a) = hub.register(Arc::clone(&stats)).await;
        let (_id_b, tx_b) = hub.register(Arc::clone(&stats)).await;
        let mk = || SphinxPacket::from_bytes([0u8; SPHINX_PACKET_LEN]);

        for _ in 0..PER_PEER_INBOUND_CAPACITY {
            assert!(tx_a.try_enqueue(mk()).is_ok());
        }
        // One more on A drops newest on A's queue only.
        assert!(tx_a.try_enqueue(mk()).is_ok());
        assert_eq!(stats.dropped(), 1);
        // B can still enqueue.
        assert!(tx_b.try_enqueue(mk()).is_ok());
        assert_eq!(stats.dropped(), 1);
    }

    #[tokio::test]
    async fn peer_health_advert_over_link_merges_into_tracker() {
        use ed25519_dalek::SigningKey;

        let reporter_sk = SigningKey::from_bytes(&[0x42; 32]);
        let reporter_id = test_relay_id(0x42);
        let local_id = test_relay_id(0x10);
        let subject = test_relay_id(0x99);
        let psk = test_psk(0x42);

        let mut peer_table = HashMap::new();
        peer_table.insert(
            reporter_id,
            PeerInfo::new("127.0.0.1:1".parse().unwrap(), psk)
                .with_gossip_verifying_key(reporter_sk.verifying_key().to_bytes()),
        );

        // K=1 for this link-level round-trip; production default majority_k=2.
        let health = Arc::new(PeerHealthTracker::with_gossip_majority_k(1));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = LinkBridgeConfig::default().without_ingress_rate_limit();
        let cfg_server = cfg.clone();
        let peer_table_server = peer_table.clone();
        let health_server = Arc::clone(&health);

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            let (key, matched) = run_responder_handshake(
                &mut stream,
                local_id,
                None,
                None,
                &peer_table_server,
                &mut rng,
                &cfg_server,
                Some(health_server.as_ref()),
            )
            .await
            .unwrap();
            assert_eq!(matched, Some(reporter_id));

            let mut frame = [0u8; LINK_FRAME_LEN];
            read_exact_timeout(&mut stream, &mut frame, cfg_server.read_timeout)
                .await
                .unwrap();
            let cell = key.open(&frame).unwrap();
            assert_eq!(cell.as_bytes()[0], Command::PeerHealthAdvert as u8);
            let advert = PeerHealthAdvert::from_cell(&cell).unwrap();
            accept_advert(
                &advert,
                matched.unwrap(),
                &peer_table_server,
                advert.timestamp_secs,
                DEFAULT_MAX_ADVERT_AGE_SECS,
                health_server.as_ref(),
            )
            .unwrap();
        });

        let mut rng = OsRng;
        let mut session =
            LinkSession::connect(addr, &psk, local_id, None, None, &mut rng, &cfg)
                .await
                .unwrap();
        let advert = PeerHealthAdvert::sign(
            &reporter_sk,
            *reporter_id.as_bytes(),
            *subject.as_bytes(),
            8,
            2,
            1_700_000_000,
        );
        session.send_cell(&advert.to_cell(), &mut rng).await.unwrap();
        session.flush().await.unwrap();
        server.await.unwrap();

        // Half-weight: 8/2 → 4/1 → failure rate 0.2
        let rate = health.failure_rate(*subject.as_bytes()).unwrap();
        assert!((rate - 0.2).abs() < 1e-9);
    }

    #[cfg(feature = "noise-link")]
    #[tokio::test]
    async fn noise_ik_honest_roundtrip() {
        use aegis_crypto::noise_link::{derive_noise_static_secret, noise_static_public};

        let init_sk = derive_noise_static_secret(&[0x11u8; 32]);
        let resp_sk = derive_noise_static_secret(&[0x22u8; 32]);
        let init_pk = noise_static_public(&init_sk);
        let resp_pk = noise_static_public(&resp_sk);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer_id = test_relay_id(0xA1);
        let local_id = test_relay_id(0xA2);
        let psk = test_psk(0xAA);

        let peer = PeerInfo::new(addr, psk).with_noise_static_public(init_pk);
        let peer_table = HashMap::from([(peer_id, peer)]);

        let mut cfg = LinkBridgeConfig::default();
        cfg.handshake = LinkHandshakeMode::Noise;
        cfg.noise_static_secret = Some(resp_sk);

        let cfg_server = cfg.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            run_responder_handshake(
                &mut stream,
                local_id,
                None,
                None,
                &peer_table,
                &mut rng,
                &cfg_server,
                None,
            )
            .await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let mut init_cfg = LinkBridgeConfig::default();
        init_cfg.handshake = LinkHandshakeMode::Noise;
        init_cfg.noise_static_secret = Some(init_sk);
        let key_i = run_initiator_handshake(
            &mut client,
            &psk,
            local_id,
            None,
            Some(resp_pk),
            &mut rng,
            &init_cfg,
        )
        .await
        .unwrap();
        let (key_r, matched) = server.await.unwrap().unwrap();
        assert_eq!(matched, Some(peer_id));
        assert_eq!(key_i, key_r);
    }

    #[cfg(feature = "noise-link")]
    #[tokio::test]
    async fn noise_ik_wrong_static_key_fails() {
        use aegis_crypto::noise_link::{derive_noise_static_secret, noise_static_public};

        let init_sk = derive_noise_static_secret(&[0x31u8; 32]);
        let resp_sk = derive_noise_static_secret(&[0x32u8; 32]);
        let wrong_init_pk = noise_static_public(&derive_noise_static_secret(&[0x99u8; 32]));
        let resp_pk = noise_static_public(&resp_sk);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer_id = test_relay_id(0xA3);
        let local_id = test_relay_id(0xA4);
        let psk = test_psk(0xBB);

        // Responder expects a different initiator static than the real client.
        let peer = PeerInfo::new(addr, psk).with_noise_static_public(wrong_init_pk);
        let peer_table = HashMap::from([(peer_id, peer)]);

        let mut cfg = LinkBridgeConfig::default();
        cfg.handshake = LinkHandshakeMode::Noise;
        cfg.noise_static_secret = Some(resp_sk);
        let cfg_server = cfg.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            run_responder_handshake(
                &mut stream,
                local_id,
                None,
                None,
                &peer_table,
                &mut rng,
                &cfg_server,
                None,
            )
            .await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let mut init_cfg = LinkBridgeConfig::default();
        init_cfg.handshake = LinkHandshakeMode::Noise;
        init_cfg.noise_static_secret = Some(init_sk);
        let err = run_initiator_handshake(
            &mut client,
            &psk,
            local_id,
            None,
            Some(resp_pk),
            &mut rng,
            &init_cfg,
        )
        .await;
        assert!(matches!(
            err,
            Err(NetError::ReadTimeout(_))
                | Err(NetError::Io(_))
                | Err(NetError::Crypto(_))
                | Err(NetError::UnidentifiedInbound)
        ));
        let server_err = server.await.unwrap();
        assert!(matches!(server_err, Err(NetError::UnidentifiedInbound)));
    }

    #[tokio::test]
    async fn legacy_psk_still_used_when_keys_absent() {
        let psk = test_psk(0x42);
        let relay_id = test_relay_id(0x01);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = LinkBridgeConfig::default();
        #[cfg(feature = "noise-link")]
        {
            assert_eq!(cfg.handshake, LinkHandshakeMode::Auto);
            assert!(!cfg.initiator_selects_noise(None));
            assert!(!cfg.responder_selects_noise());
        }
        #[cfg(not(feature = "noise-link"))]
        assert_eq!(cfg.handshake, LinkHandshakeMode::LegacyPsk);

        let cfg_server = cfg.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            run_responder_handshake(
                &mut stream,
                relay_id,
                None,
                Some(psk),
                &HashMap::new(),
                &mut rng,
                &cfg_server,
                None,
            )
            .await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let key_i =
            run_initiator_handshake(&mut client, &psk, relay_id, None, None, &mut rng, &cfg)
                .await
                .unwrap();
        let (key_r, _) = server.await.unwrap().unwrap();
        assert_eq!(key_i, key_r);
    }

    #[cfg(feature = "noise-link")]
    #[tokio::test]
    async fn handshake_auto_selects_noise_when_keys_present() {
        use aegis_crypto::noise_link::{derive_noise_static_secret, noise_static_public};

        let init_sk = derive_noise_static_secret(&[0x51u8; 32]);
        let resp_sk = derive_noise_static_secret(&[0x52u8; 32]);
        let init_pk = noise_static_public(&init_sk);
        let resp_pk = noise_static_public(&resp_sk);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer_id = test_relay_id(0xB1);
        let local_id = test_relay_id(0xB2);
        let psk = test_psk(0xCC);

        let peer = PeerInfo::new(addr, psk).with_noise_static_public(init_pk);
        let peer_table = HashMap::from([(peer_id, peer)]);

        let mut cfg = LinkBridgeConfig::default();
        assert_eq!(cfg.handshake, LinkHandshakeMode::Auto);
        cfg.noise_static_secret = Some(resp_sk);
        assert!(cfg.responder_selects_noise());

        let cfg_server = cfg.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            run_responder_handshake(
                &mut stream,
                local_id,
                None,
                None,
                &peer_table,
                &mut rng,
                &cfg_server,
                None,
            )
            .await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let mut init_cfg = LinkBridgeConfig::default();
        init_cfg.noise_static_secret = Some(init_sk);
        assert!(init_cfg.initiator_selects_noise(Some(resp_pk)));
        let key_i = run_initiator_handshake(
            &mut client,
            &psk,
            local_id,
            None,
            Some(resp_pk),
            &mut rng,
            &init_cfg,
        )
        .await
        .unwrap();
        let (key_r, matched) = server.await.unwrap().unwrap();
        assert_eq!(matched, Some(peer_id));
        assert_eq!(key_i, key_r);
    }

    #[cfg(feature = "noise-link")]
    #[test]
    fn handshake_auto_falls_back_without_peer_static() {
        let mut cfg = LinkBridgeConfig::default();
        cfg.noise_static_secret = Some([0x77; 32]);
        // Responder can offer Noise with local secret alone.
        assert!(cfg.responder_selects_noise());
        // Initiator needs peer static too — otherwise LegacyPsk.
        assert!(!cfg.initiator_selects_noise(None));
    }
}
