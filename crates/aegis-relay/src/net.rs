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
//! ingress config). On each new TCP connection an ephemeral X25519 handshake
//! authenticated by that PSK derives a fresh ChaCha20-Poly1305 session key with
//! forward secrecy before any Sphinx frames are sent.
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
//! limit (default ≈ Mode-1 `1/τ` cells/s with a small burst). Excess frames are
//! **dropped silently** (connection stays open); see [`IngressRateLimitStats`].
//! Optional aggregate cap: [`IngressRateLimitConfig::global_max_cells_per_sec`].
//!
//! ## Bounded inbound queue (drop-newest)
//!
//! Reassembled Sphinx packets are enqueued with [`crate::node::try_send_drop_newest`]
//! into the relay's bounded inbound `mpsc` (capacity
//! [`crate::node::RELAY_CHANNEL_CAPACITY`]). When the mix core is slower than
//! admitted ingress, the **newest** packet is dropped and
//! [`QueueDropStats::dropped`] increments — the inbound task does not block
//! forever. Rate-limit drops happen first (pre-reassembly); queue drops are a
//! second shed for post-reassembly backlog. Per-connection tasks share one
//! channel, so load shedding is naturally interleaved across peers.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
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
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use thiserror::Error;

use crate::cover_flow::is_relay_cover_fragment;
use crate::node::{try_send_drop_newest, ForwardedPacket};
use crate::peer_health::PeerHealthTracker;
use crate::relay_id::RelayId;
use crate::trace::RelayForwardTrace;

/// Default per-read timeout: slow-loris peers cannot hold a task indefinitely.
pub const DEFAULT_LINK_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Default cap on concurrent inbound TCP connections per listener.
pub const DEFAULT_MAX_INBOUND_CONNECTIONS: usize = 256;

/// Mode-1 spec worked-example slot period τ (seconds).
pub const MODE1_TAU_SECS: f64 = 0.35;

/// Default sustained ingress accept rate: ~1/τ cells/s (Mode-1 pacing).
pub const DEFAULT_INGRESS_MAX_CELLS_PER_SEC: f64 = 1.0 / MODE1_TAU_SECS;

/// Small burst above sustained rate so τ-paced clients tolerate minor jitter.
pub const DEFAULT_INGRESS_BURST: u32 = 4;

/// Per-connection (and optional global) ingress frame rate limit for the link bridge.
///
/// Excess frames after AEAD framing are **dropped silently** (TCP stays open); see
/// [`IngressRateLimitStats::dropped_frames`]. Set `max_cells_per_sec` to `0.0` to disable
/// per-connection limiting; omit `global_max_cells_per_sec` to disable aggregate cap.
#[derive(Clone, Debug)]
pub struct IngressRateLimitConfig {
    /// Sustained accept rate (cells/sec). `0.0` disables per-connection limiting.
    pub max_cells_per_sec: f64,
    /// Token-bucket burst (cells).
    pub burst: u32,
    /// Optional aggregate cap across all inbound connections (cells/sec).
    pub global_max_cells_per_sec: Option<f64>,
}

impl Default for IngressRateLimitConfig {
    fn default() -> Self {
        Self {
            max_cells_per_sec: DEFAULT_INGRESS_MAX_CELLS_PER_SEC,
            burst: DEFAULT_INGRESS_BURST,
            global_max_cells_per_sec: None,
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

/// Tunables for the TCP link bridge (read timeout, connection cap, ingress rate limit).
#[derive(Clone, Debug)]
pub struct LinkBridgeConfig {
    pub read_timeout: Duration,
    pub max_inbound_connections: usize,
    /// When true, bind the peer roster relay id into handshake MAC inputs.
    pub identity_binding: bool,
    pub ingress_rate_limit: IngressRateLimitConfig,
    /// Optional shared counter for rate-limited frame drops (tests / ops).
    pub ingress_rate_limit_stats: Option<Arc<IngressRateLimitStats>>,
    /// Optional shared counter for inbound queue-full drops (tests / ops).
    pub queue_drop_stats: Option<Arc<QueueDropStats>>,
}

impl Default for LinkBridgeConfig {
    fn default() -> Self {
        Self {
            read_timeout: DEFAULT_LINK_READ_TIMEOUT,
            max_inbound_connections: DEFAULT_MAX_INBOUND_CONNECTIONS,
            identity_binding: true,
            ingress_rate_limit: IngressRateLimitConfig::default(),
            ingress_rate_limit_stats: None,
            queue_drop_stats: None,
        }
    }
}

impl LinkBridgeConfig {
    /// Disable ingress rate limiting while keeping other defaults.
    pub fn without_ingress_rate_limit(mut self) -> Self {
        self.ingress_rate_limit = IngressRateLimitConfig::disabled();
        self
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
}

impl PeerInfo {
    pub fn new(addr: SocketAddr, link_key_bytes: [u8; 32]) -> Self {
        Self {
            addr,
            link_key_bytes,
            kem_public_commitment: None,
        }
    }

    pub fn with_kem_commitment(mut self, kem_public_commitment: [u8; 32]) -> Self {
        self.kem_public_commitment = Some(kem_public_commitment);
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
    #[error("link read timed out after {0:?}")]
    ReadTimeout(Duration),
    #[error("inbound connection limit reached ({0})")]
    ConnectionLimit(usize),
}

/// Spawn inbound listener + outbound dispatcher bridging TCP and `RelayNode` channels.
///
/// When `cover_rx` is set, a cover dispatcher seals synthetic cover cell bursts from
/// [`crate::RelayNode::spawn`] and writes them on a hop link (same AEAD framing as
/// real traffic).
///
/// When `peer_health` is set, outbound send/handshake outcomes and inbound
/// responder handshakes (once a peer-table PSK matches) are recorded per peer
/// for periodic feeding into [`RelayPruningPolicy`](aegis_trust::RelayPruningPolicy)
/// via [`PeerHealthTracker::drain_into_policy`].
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
        rng: &mut R,
        bridge_config: &LinkBridgeConfig,
    ) -> Result<Self, NetError> {
        let mut stream = TcpStream::connect(addr).await?;
        let session_key = run_initiator_handshake(
            &mut stream,
            psk,
            peer_relay_id,
            kem_public_commitment,
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
    packet: &SphinxPacket,
    rng: &mut R,
    bridge_config: &LinkBridgeConfig,
) -> Result<(), NetError> {
    let mut session =
        LinkSession::connect(addr, psk, peer_relay_id, kem_public_commitment, rng, bridge_config)
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
pub async fn run_initiator_handshake<R: RngCore + CryptoRngCore>(
    stream: &mut TcpStream,
    psk: &[u8; 32],
    peer_relay_id: RelayId,
    kem_public_commitment: Option<[u8; 32]>,
    rng: &mut R,
    bridge_config: &LinkBridgeConfig,
) -> Result<LinkKey, NetError> {
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
    Ok(aegis_crypto::link::derive_link_session_key(
        init_sk,
        &resp.eph_pk,
        &transcript,
    ))
}

/// Responder-side link handshake; identifies which configured PSK matched.
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
) -> Result<LinkKey, NetError> {
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
            return Ok(session);
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
                    return Ok(session);
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
    tokio::spawn(async move {
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
            let inbound_tx = inbound_tx.clone();
            let cfg = bridge_config.clone();
            let local_id = local_relay_id;
            let health = peer_health.clone();
            let rate_stats = Arc::clone(&rate_stats);
            let queue_drop_stats = Arc::clone(&queue_drop_stats);
            let rate_limit_config = rate_limit_config.clone();
            let global_rate_bucket = global_rate_bucket.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = run_inbound_connection(
                    stream,
                    local_id,
                    kem,
                    peer_table,
                    ingress,
                    inbound_tx,
                    &cfg,
                    health.as_deref(),
                    rate_limit_config,
                    rate_stats,
                    queue_drop_stats,
                    global_rate_bucket,
                )
                .await
                {
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
    inbound_tx: mpsc::Sender<SphinxPacket>,
    bridge_config: &LinkBridgeConfig,
    peer_health: Option<&PeerHealthTracker>,
    rate_limit_config: IngressRateLimitConfig,
    rate_stats: Arc<IngressRateLimitStats>,
    queue_drop_stats: Arc<QueueDropStats>,
    global_rate_bucket: Option<Arc<Mutex<TokenBucket>>>,
) -> Result<(), NetError> {
    let mut rng = rand_core::OsRng;
    let session_key = run_responder_handshake(
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
        // Mode-1 cover / loop cells share the link with Sphinx fragments; discard
        // them here so continuous dummy cover does not poison reassembly.
        match Command::from_u8(cell.as_bytes()[0]) {
            Some(Command::Drop) | Some(Command::LoopToSelf) => continue,
            Some(Command::SphinxFragment) if is_relay_cover_fragment(&cell) => continue,
            Some(Command::SphinxFragment) => {}
            _ => continue,
        }
        if let Some(packet) = reassembler.push(&cell)? {
            // Drop-newest when the mix inbound queue is full (never block forever).
            if try_send_drop_newest(&inbound_tx, packet, queue_drop_stats.counter()).is_err() {
                break;
            }
        }
    }
    Ok(())
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
    match write_cells_on_stream(
        &mut guard.stream,
        &session_key,
        cells,
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
            match write_cells_on_stream(
                &mut guard.stream,
                &session_key,
                cells,
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

async fn write_cells_on_stream<R: RngCore + CryptoRngCore>(
    stream: &mut TcpStream,
    link_key: &LinkKey,
    cells: &[Cell],
    rng: &mut R,
    read_timeout: Duration,
) -> Result<(), NetError> {
    for cell in cells {
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
            let peer = match peer_table.get(&fwd.next_hop) {
                Some(p) => p.clone(),
                None => {
                    // Terminal peel (exit hop) or misconfiguration — no peer route.
                    // When `exit_tx` is set the packet was already delivered above.
                    continue;
                }
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
            let key = run_responder_handshake(
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
        let mut session = LinkSession::connect(addr, &psk, relay_id, None, &mut rng, &cfg)
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
        let key_i = run_initiator_handshake(&mut client, &psk, relay_id, None, &mut rng, &cfg)
            .await
            .unwrap();
        let key_r = server.await.unwrap();
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
            run_initiator_handshake(&mut client, &psk, wrong, None, &mut rng, &cfg).await;
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
        let err = run_initiator_handshake(&mut client, &psk, relay_id, None, &mut rng, &cfg).await;
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
            let key = run_responder_handshake(
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
            run_inbound_connection(
                stream,
                relay_id,
                None,
                HashMap::new(),
                Some(psk),
                inbound_tx,
                &server_cfg,
                None,
                server_cfg.ingress_rate_limit.clone(),
                Arc::new(IngressRateLimitStats::default()),
                Arc::new(QueueDropStats::default()),
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
                run_initiator_handshake(&mut stream, &psk, relay_id, None, &mut rng, &cfg)
                    .await
                    .unwrap();
            write_cells_on_stream(
                &mut stream,
                &session_key,
                &flow.cells,
                &mut rng,
                cfg.read_timeout,
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
            &mut rng,
            &cfg,
        )
        .await
        .unwrap();
        let key_r = server.await.unwrap();
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
        let key_i = run_initiator_handshake(&mut client, &psk, relay_id, None, &mut rng, &cfg)
            .await
            .unwrap();
        let key_r = server.await.unwrap();
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
        run_initiator_handshake(&mut client, &psk, local_id, None, &mut rng, &cfg)
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
        let _ = run_initiator_handshake(&mut client, &psk, local_id, None, &mut rng, &cfg).await;
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
                // Comfortably above Mode-1 1/τ ≈ 2.86 cells/s.
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
            let _ = run_inbound_connection(
                stream,
                relay_id,
                None,
                HashMap::new(),
                Some(psk),
                inbound_tx,
                &server_cfg,
                None,
                server_cfg.ingress_rate_limit.clone(),
                server_cfg
                    .ingress_rate_limit_stats
                    .clone()
                    .unwrap_or_default(),
                Arc::new(QueueDropStats::default()),
                None,
            )
            .await;
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let session_key =
            run_initiator_handshake(&mut stream, &psk, relay_id, None, &mut rng, &cfg)
                .await
                .unwrap();
        // One cell every 200ms ≈ 5 cells/s — under the 10/s limit.
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
            "τ-paced traffic must pass comfortably"
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
            let _ = run_inbound_connection(
                stream,
                relay_id,
                None,
                HashMap::new(),
                Some(psk),
                inbound_tx,
                &server_cfg,
                None,
                server_cfg.ingress_rate_limit.clone(),
                server_cfg
                    .ingress_rate_limit_stats
                    .clone()
                    .unwrap_or_default(),
                Arc::new(QueueDropStats::default()),
                None,
            )
            .await;
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let session_key =
            run_initiator_handshake(&mut stream, &psk, relay_id, None, &mut rng, &cfg)
                .await
                .unwrap();
        // Flood 40 cells immediately — burst=2 then drop the rest.
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
        assert!(cfg.is_active());
        assert!(!IngressRateLimitConfig::disabled().is_active());
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
            OsRng,
            cfg.clone(),
            None,
        );

        let mut rng = OsRng;
        let mut session = LinkSession::connect(addr, &psk, relay_id, None, &mut rng, &cfg)
            .await
            .expect("ingress handshake via spawn_link_bridge_with_listener");
        let mut cell = Cell::zeroed();
        cell.0[0] = Command::Drop as u8;
        session.send_cell(&cell, &mut rng).await.unwrap();
        session.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(inbound_rx.try_recv().is_err(), "Drop must not reassemble");
    }
}
