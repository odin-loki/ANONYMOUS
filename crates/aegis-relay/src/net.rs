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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use aegis_crypto::cell::{Cell, Command};
use aegis_crypto::fragment::{fragment_with_random_id, SphinxReassembler, SPHINX_FRAGMENT_COUNT};
use aegis_crypto::link::{
    link_handshake_confirm_mac, link_handshake_finish_mac, link_handshake_init_write,
    link_handshake_resp_write, link_handshake_responder_finish, parse_link_handshake_init,
    parse_link_handshake_mac, parse_link_handshake_resp, verify_link_handshake_confirm_mac,
    verify_link_handshake_finish_mac, LinkHandshakeTranscript, LinkKey, LINK_FRAME_LEN,
    LINK_HANDSHAKE_CONFIRM_LEN, LINK_HANDSHAKE_FINISH_LEN, LINK_HANDSHAKE_INIT_LEN,
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

use crate::node::ForwardedPacket;
use crate::relay_id::RelayId;

/// Default per-read timeout: slow-loris peers cannot hold a task indefinitely.
pub const DEFAULT_LINK_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Default cap on concurrent inbound TCP connections per listener.
pub const DEFAULT_MAX_INBOUND_CONNECTIONS: usize = 256;

/// Tunables for the TCP link bridge (read timeout, connection cap).
#[derive(Clone, Debug)]
pub struct LinkBridgeConfig {
    pub read_timeout: Duration,
    pub max_inbound_connections: usize,
}

impl Default for LinkBridgeConfig {
    fn default() -> Self {
        Self {
            read_timeout: DEFAULT_LINK_READ_TIMEOUT,
            max_inbound_connections: DEFAULT_MAX_INBOUND_CONNECTIONS,
        }
    }
}

/// A remote peer reachable over TCP with a pre-shared hop link key.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    /// 32-byte pre-shared key for handshake authentication (not used directly for AEAD).
    pub link_key_bytes: [u8; 32],
}

impl PeerInfo {
    pub fn new(addr: SocketAddr, link_key_bytes: [u8; 32]) -> Self {
        Self { addr, link_key_bytes }
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
/// Returns join handles for the listener and dispatcher tasks.
pub fn spawn_link_bridge<R: RngCore + CryptoRngCore + Send + Sync + 'static>(
    listen_addr: SocketAddr,
    peer_table: HashMap<RelayId, PeerInfo>,
    ingress_link_key: Option<[u8; 32]>,
    inbound_tx: mpsc::Sender<SphinxPacket>,
    outbound_rx: mpsc::Receiver<ForwardedPacket>,
    cover_rx: Option<mpsc::Receiver<Vec<Cell>>>,
    exit_tx: Option<ExitSink>,
    rng: R,
    bridge_config: LinkBridgeConfig,
) -> (JoinHandle<()>, JoinHandle<()>) {
    let rng = Arc::new(Mutex::new(rng));
    let listener = spawn_inbound_listener(
        listen_addr,
        peer_table.clone(),
        ingress_link_key,
        inbound_tx,
        bridge_config.clone(),
    );
    if let Some(cover_rx) = cover_rx {
        spawn_cover_dispatcher(
            cover_rx,
            peer_table.clone(),
            Arc::clone(&rng),
            bridge_config.clone(),
        );
    }
    let dispatcher = spawn_outbound_dispatcher(
        outbound_rx,
        peer_table,
        exit_tx,
        Arc::clone(&rng),
        bridge_config,
    );
    (listener, dispatcher)
}

/// Established TCP hop link: one handshake, many sealed cell frames on the same session key.
pub struct LinkSession {
    stream: TcpStream,
    session_key: LinkKey,
    read_timeout: Duration,
}

impl LinkSession {
    /// Connect to `addr`, run the initiator link handshake once, and return a reusable session.
    pub async fn connect<R: RngCore + CryptoRngCore>(
        addr: SocketAddr,
        psk: &[u8; 32],
        rng: &mut R,
        bridge_config: &LinkBridgeConfig,
    ) -> Result<Self, NetError> {
        let mut stream = TcpStream::connect(addr).await?;
        let session_key =
            run_initiator_handshake(&mut stream, psk, rng, bridge_config.read_timeout).await?;
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
    packet: &SphinxPacket,
    rng: &mut R,
    bridge_config: &LinkBridgeConfig,
) -> Result<(), NetError> {
    let mut session = LinkSession::connect(addr, psk, rng, bridge_config).await?;
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
    rng: &mut R,
    read_timeout: Duration,
) -> Result<LinkKey, NetError> {
    let (init_sk, init_msg) = link_handshake_init_write(rng);
    let init = parse_link_handshake_init(&init_msg)?;
    write_all_timeout(stream, &init_msg, read_timeout).await?;

    let mut resp_msg = [0u8; LINK_HANDSHAKE_RESP_LEN];
    read_exact_timeout(stream, &mut resp_msg, read_timeout).await?;
    let resp = parse_link_handshake_resp(&resp_msg)?;
    let transcript = LinkHandshakeTranscript::from_messages(&init, &resp);
    let confirm = link_handshake_confirm_mac(psk, &transcript);
    write_all_timeout(stream, &confirm, read_timeout).await?;

    let mut finish_msg = [0u8; LINK_HANDSHAKE_FINISH_LEN];
    read_exact_timeout(stream, &mut finish_msg, read_timeout).await?;
    let finish = parse_link_handshake_mac(&finish_msg)?;
    if !verify_link_handshake_finish_mac(psk, &transcript, &finish) {
        return Err(NetError::Crypto(CryptoError::IntegrityFailure));
    }
    Ok(aegis_crypto::link::derive_link_session_key(
        init_sk,
        &resp.eph_pk,
        &transcript,
    ))
}

/// Responder-side link handshake; identifies which configured PSK matched.
pub async fn run_responder_handshake<R: RngCore + CryptoRngCore>(
    stream: &mut TcpStream,
    ingress_link_key: Option<[u8; 32]>,
    peer_table: &HashMap<RelayId, PeerInfo>,
    rng: &mut R,
    read_timeout: Duration,
) -> Result<LinkKey, NetError> {
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

    if let Some(psk) = ingress_link_key {
        if verify_link_handshake_confirm_mac(&psk, &transcript, &confirm) {
            let session =
                link_handshake_responder_finish(&psk, resp_sk, &init, &resp, &confirm_msg)?;
            let finish = link_handshake_finish_mac(&psk, &transcript);
            write_all_timeout(stream, &finish, read_timeout).await?;
            return Ok(session);
        }
    }

    for (id, peer) in peer_table {
        let psk = peer.link_key_bytes;
        if verify_link_handshake_confirm_mac(&psk, &transcript, &confirm) {
            let session =
                link_handshake_responder_finish(&psk, resp_sk, &init, &resp, &confirm_msg)?;
            let finish = link_handshake_finish_mac(&psk, &transcript);
            write_all_timeout(stream, &finish, read_timeout).await?;
            let _ = id;
            return Ok(session);
        }
    }

    Err(NetError::UnidentifiedInbound)
}

fn spawn_inbound_listener(
    listen_addr: SocketAddr,
    peer_table: HashMap<RelayId, PeerInfo>,
    ingress_link_key: Option<[u8; 32]>,
    inbound_tx: mpsc::Sender<SphinxPacket>,
    bridge_config: LinkBridgeConfig,
) -> JoinHandle<()> {
    let connection_slots = Arc::new(Semaphore::new(bridge_config.max_inbound_connections));
    tokio::spawn(async move {
        let listener = match TcpListener::bind(listen_addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("aegis-relay net: bind {listen_addr}: {e}");
                return;
            }
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
            let inbound_tx = inbound_tx.clone();
            let cfg = bridge_config.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) =
                    run_inbound_connection(stream, peer_table, ingress, inbound_tx, &cfg).await
                {
                    eprintln!("aegis-relay net: inbound connection ended: {e}");
                }
            });
        }
    })
}

async fn run_inbound_connection(
    mut stream: TcpStream,
    peer_table: HashMap<RelayId, PeerInfo>,
    ingress_link_key: Option<[u8; 32]>,
    inbound_tx: mpsc::Sender<SphinxPacket>,
    bridge_config: &LinkBridgeConfig,
) -> Result<(), NetError> {
    let mut rng = rand_core::OsRng;
    let session_key = run_responder_handshake(
        &mut stream,
        ingress_link_key,
        &peer_table,
        &mut rng,
        bridge_config.read_timeout,
    )
    .await?;

    let mut frame = [0u8; LINK_FRAME_LEN];
    let mut reassembler = SphinxReassembler::new();

    loop {
        read_exact_timeout(&mut stream, &mut frame, bridge_config.read_timeout).await?;
        let cell = session_key.open(&frame)?;
        // Mode-1 cover / loop cells share the link with Sphinx fragments; discard
        // them here so continuous dummy cover does not poison reassembly.
        match Command::from_u8(cell.as_bytes()[0]) {
            Some(Command::Drop) | Some(Command::LoopToSelf) => continue,
            Some(Command::SphinxFragment) => {}
            _ => continue,
        }
        if let Some(packet) = reassembler.push(&cell)? {
            if inbound_tx.send(packet).await.is_err() {
                break;
            }
        }
    }
    Ok(())
}

fn pick_cover_egress(peer_table: &HashMap<RelayId, PeerInfo>) -> Option<PeerInfo> {
    let mut peers: Vec<_> = peer_table.values().cloned().collect();
    peers.sort_by_key(|p| p.addr);
    peers.into_iter().next()
}

fn spawn_cover_dispatcher<R: RngCore + CryptoRngCore + Send + 'static>(
    cover_rx: mpsc::Receiver<Vec<Cell>>,
    peer_table: HashMap<RelayId, PeerInfo>,
    rng: Arc<Mutex<R>>,
    bridge_config: LinkBridgeConfig,
) {
    tokio::spawn(async move {
        let pool = Arc::new(Mutex::new(ConnectionPool::new()));
        let mut cover_rx = cover_rx;
        while let Some(cells) = cover_rx.recv().await {
            let peer = match pick_cover_egress(&peer_table) {
                Some(p) => p,
                None => continue,
            };
            let mut guard = rng.lock().await;
            if let Err(e) =
                write_cover_cells(&pool, &peer, &cells, &mut *guard, &bridge_config).await
            {
                eprintln!("aegis-relay net: cover egress to {:?}: {e}", peer.addr);
            }
        }
    });
}

async fn write_cover_cells<R: RngCore + CryptoRngCore>(
    pool: &Arc<Mutex<ConnectionPool>>,
    peer: &PeerInfo,
    cells: &[Cell],
    rng: &mut R,
    bridge_config: &LinkBridgeConfig,
) -> Result<(), NetError> {
    let conn = {
        let mut pool = pool.lock().await;
        pool.get_or_handshake(peer, rng, bridge_config).await?
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
        Ok(()) => Ok(()),
        Err(NetError::Io(_)) | Err(NetError::ReadTimeout(_)) => {
            drop(guard);
            let mut pool = pool.lock().await;
            let conn = pool.reconnect(peer, rng, bridge_config).await?;
            let mut guard = conn.lock().await;
            let session_key = LinkKey::new(*guard.session_key.as_bytes());
            write_cells_on_stream(
                &mut guard.stream,
                &session_key,
                cells,
                rng,
                bridge_config.read_timeout,
            )
            .await
        }
        Err(e) => Err(e),
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

fn spawn_outbound_dispatcher<R: RngCore + CryptoRngCore + Send + 'static>(
    outbound_rx: mpsc::Receiver<ForwardedPacket>,
    peer_table: HashMap<RelayId, PeerInfo>,
    exit_tx: Option<ExitSink>,
    rng: Arc<Mutex<R>>,
    bridge_config: LinkBridgeConfig,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let pool = Arc::new(Mutex::new(ConnectionPool::new()));
        let mut outbound_rx = outbound_rx;
        while let Some(fwd) = outbound_rx.recv().await {
            if let Some(ref tx) = exit_tx {
                if peer_table.get(&fwd.next_hop).is_none() {
                    let _ = tx.send(fwd.packet).await;
                    continue;
                }
            }
            let peer = match peer_table.get(&fwd.next_hop) {
                Some(p) => p.clone(),
                None => {
                    eprintln!(
                        "aegis-relay net: no peer for next_hop {:?}",
                        fwd.next_hop
                    );
                    continue;
                }
            };
            let mut guard = rng.lock().await;
            if let Err(e) =
                forward_to_peer(&pool, &peer, &fwd.packet, &mut *guard, &bridge_config).await
            {
                eprintln!("aegis-relay net: forward to {:?}: {e}", fwd.next_hop);
            }
        }
    })
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
            rng,
            bridge_config.read_timeout,
        )
        .await?;
        let shared = Arc::new(Mutex::new(PooledConnection { stream, session_key }));
        self.connections.insert(peer.addr, Arc::clone(&shared));
        Ok(shared)
    }

    async fn reconnect<R: RngCore + CryptoRngCore>(
        &mut self,
        peer: &PeerInfo,
        rng: &mut R,
        bridge_config: &LinkBridgeConfig,
    ) -> Result<Arc<Mutex<PooledConnection>>, NetError> {
        self.connections.remove(&peer.addr);
        self.get_or_handshake(peer, rng, bridge_config).await
    }
}

async fn forward_to_peer<R: RngCore + CryptoRngCore>(
    pool: &Arc<Mutex<ConnectionPool>>,
    peer: &PeerInfo,
    packet: &SphinxPacket,
    rng: &mut R,
    bridge_config: &LinkBridgeConfig,
) -> Result<(), NetError> {
    let conn = {
        let mut pool = pool.lock().await;
        pool.get_or_handshake(peer, rng, bridge_config).await?
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
        Ok(()) => Ok(()),
        Err(NetError::Io(_)) | Err(NetError::ReadTimeout(_)) => {
            drop(guard);
            let mut pool = pool.lock().await;
            let conn = pool.reconnect(peer, rng, bridge_config).await?;
            let mut guard = conn.lock().await;
            let session_key = LinkKey::new(*guard.session_key.as_bytes());
            write_packet_with_key(
                &mut guard.stream,
                &session_key,
                packet,
                rng,
                bridge_config.read_timeout,
            )
            .await
        }
        Err(e) => Err(e),
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

    #[tokio::test]
    async fn link_session_sends_cells_one_at_a_time() {
        use aegis_crypto::cell::Cell;

        let psk = test_psk(0xCD);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = LinkBridgeConfig::default();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            let key = run_responder_handshake(
                &mut stream,
                Some(psk),
                &HashMap::new(),
                &mut rng,
                cfg.read_timeout,
            )
            .await
            .unwrap();

            let mut frame = [0u8; LINK_FRAME_LEN];
            for _ in 0..3 {
                read_exact_timeout(&mut stream, &mut frame, cfg.read_timeout)
                    .await
                    .unwrap();
                let cell = key.open(&frame).unwrap();
                assert_eq!(cell.as_bytes().len(), aegis_crypto::cell::CELL_LEN);
            }
        });

        let mut rng = OsRng;
        let mut session = LinkSession::connect(addr, &psk, &mut rng, &cfg)
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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = LinkBridgeConfig::default();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            run_responder_handshake(&mut stream, Some(psk), &HashMap::new(), &mut rng, cfg.read_timeout)
                .await
                .unwrap()
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let key_i =
            run_initiator_handshake(&mut client, &psk, &mut rng, cfg.read_timeout).await.unwrap();
        let key_r = server.await.unwrap();
        assert_eq!(key_i, key_r);
    }

    #[tokio::test]
    async fn wrong_psk_handshake_rejected() {
        let psk = test_psk(0x01);
        let wrong = test_psk(0x02);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = LinkBridgeConfig::default();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            run_responder_handshake(&mut stream, Some(wrong), &HashMap::new(), &mut rng, cfg.read_timeout)
                .await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut rng = OsRng;
        let err = run_initiator_handshake(&mut client, &psk, &mut rng, cfg.read_timeout).await;
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

        let mut peer_id = [0u8; 32];
        peer_id[0] = 9;
        let peer_table = HashMap::from([(
            RelayId(peer_id),
            PeerInfo::new(addr, psk),
        )]);

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rng = OsRng;
            let key = run_responder_handshake(
                &mut stream,
                Some(psk),
                &HashMap::new(),
                &mut rng,
                cfg.read_timeout,
            )
            .await
            .unwrap();

            let mut frame = [0u8; LINK_FRAME_LEN];
            let mut frames = 0usize;
            for _ in 0..SPHINX_FRAGMENT_COUNT {
                read_exact_timeout(&mut stream, &mut frame, cfg.read_timeout)
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
            peer_table,
            None,
            mpsc::channel(1).0,
            mpsc::channel(1).1,
            Some(cover_rx),
            None,
            OsRng,
            cfg.clone(),
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
            run_responder_handshake(&mut stream, None, &HashMap::new(), &mut rng, cfg.read_timeout)
                .await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0u8; LINK_HANDSHAKE_INIT_LEN - 1]).await.unwrap();
        let err = server.await.unwrap();
        assert!(matches!(err, Err(NetError::ReadTimeout(_))));
    }
}
