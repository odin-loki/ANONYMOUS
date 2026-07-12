//! TCP hop-link bridge: fixed-width AEAD frames + Sphinx fragmentation.
//!
//! Bridges real `tokio::net::TcpStream` sockets to a local [`crate::RelayNode`]'s
//! `mpsc` channels without modifying the relay core. Each ordered link carries
//! [`aegis_crypto::link::LINK_FRAME_LEN`] byte frames (ChaCha20-Poly1305 over one
//! 512-byte [`aegis_crypto::cell::Cell`]); Sphinx packets are split into exactly
//! [`aegis_crypto::fragment::SPHINX_FRAGMENT_COUNT`] fragments before sealing.
//!
//! ## Link-key provisioning (honest scope)
//!
//! This pass uses **static pre-shared symmetric keys** provisioned out-of-band
//! (hex-encoded 32-byte values in each node's peer table / ingress config). The
//! same key must appear on both ends of a link pair. There is **no** authenticated
//! key-exchange handshake (Noise, TLS, or similar) yet — that is deliberate future
//! work once admission and identity binding are wired end-to-end.
//!
//! ## Inbound peer identification
//!
//! Accepted TCP connections do not carry a relay identity on the wire. For the
//! first frame on a new connection the reader tries the optional ingress key, then
//! each distinct peer-table key until one AEAD-open succeeds, and caches the
//! result for the lifetime of that connection. This is acceptable for small
//! peer tables in dev/test; production should add an explicit link handshake.
//!
//! ## Connection management
//!
//! Outbound forwarding uses dial-on-demand with reconnect-on-failure (one
//! persistent stream per [`crate::RelayId`] peer). Connection multiplexing,
//! backpressure tuning, and bidirectional link setup are future work.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use aegis_crypto::fragment::{fragment_with_random_id, SphinxReassembler, SPHINX_FRAGMENT_COUNT};
use aegis_crypto::link::{LinkKey, LINK_FRAME_LEN};
use aegis_crypto::sphinx::SphinxPacket;
use aegis_crypto::CryptoError;
use rand_core::{CryptoRngCore, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use thiserror::Error;

use crate::node::ForwardedPacket;
use crate::relay_id::RelayId;

/// A remote peer reachable over TCP with a pre-shared hop link key.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    /// 32-byte ChaCha20-Poly1305 key (cloned for lookup; wire uses [`LinkKey::new`]).
    pub link_key_bytes: [u8; 32],
}

impl PeerInfo {
    pub fn new(addr: SocketAddr, link_key_bytes: [u8; 32]) -> Self {
        Self { addr, link_key_bytes }
    }

    pub fn link_key(&self) -> LinkKey {
        LinkKey::new(self.link_key_bytes)
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
    #[error("could not decrypt first link frame with any configured key")]
    UnidentifiedInbound,
}

/// Spawn inbound listener + outbound dispatcher bridging TCP and `RelayNode` channels.
///
/// Returns join handles for the listener and dispatcher tasks.
pub fn spawn_link_bridge<R: RngCore + CryptoRngCore + Send + Sync + 'static>(
    listen_addr: SocketAddr,
    peer_table: HashMap<RelayId, PeerInfo>,
    ingress_link_key: Option<[u8; 32]>,
    inbound_tx: mpsc::Sender<SphinxPacket>,
    outbound_rx: mpsc::Receiver<ForwardedPacket>,
    exit_tx: Option<ExitSink>,
    rng: R,
) -> (JoinHandle<()>, JoinHandle<()>) {
    let rng = Arc::new(Mutex::new(rng));
    let listener = spawn_inbound_listener(listen_addr, peer_table.clone(), ingress_link_key, inbound_tx);
    let dispatcher = spawn_outbound_dispatcher(outbound_rx, peer_table, exit_tx, Arc::clone(&rng));
    (listener, dispatcher)
}

/// Seal, fragment, and send one Sphinx packet over a fresh TCP connection.
pub async fn send_sphinx_packet<R: RngCore + CryptoRngCore>(
    addr: SocketAddr,
    link_key: &LinkKey,
    packet: &SphinxPacket,
    rng: &mut R,
) -> Result<(), NetError> {
    let mut stream = TcpStream::connect(addr).await?;
    write_packet(&mut stream, link_key, packet, rng).await?;
    Ok(())
}

/// Seal, fragment, and send one Sphinx packet on an existing stream.
pub async fn write_packet<R: RngCore + CryptoRngCore>(
    stream: &mut TcpStream,
    link_key: &LinkKey,
    packet: &SphinxPacket,
    rng: &mut R,
) -> Result<(), NetError> {
    let (cells, _) = fragment_with_random_id(packet, rng);
    for cell in &cells {
        let frame = link_key.seal(cell, rng)?;
        stream.write_all(&frame).await?;
    }
    stream.flush().await?;
    Ok(())
}

fn spawn_inbound_listener(
    listen_addr: SocketAddr,
    peer_table: HashMap<RelayId, PeerInfo>,
    ingress_link_key: Option<[u8; 32]>,
    inbound_tx: mpsc::Sender<SphinxPacket>,
) -> JoinHandle<()> {
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
            let peer_table = peer_table.clone();
            let ingress = ingress_link_key;
            let inbound_tx = inbound_tx.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    run_inbound_connection(stream, peer_table, ingress, inbound_tx).await
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
) -> Result<(), NetError> {
    let mut frame = [0u8; LINK_FRAME_LEN];
    let mut resolved: Option<InboundKey> = None;
    let mut reassembler = SphinxReassembler::new();

    loop {
        stream.read_exact(&mut frame).await?;
        let cell = if let Some(key) = &resolved {
            open_with_resolved(key, &frame, &ingress_link_key, &peer_table)?
        } else {
            let (key, cell) = resolve_first_frame(&frame, ingress_link_key, &peer_table)?;
            resolved = Some(key);
            cell
        };

        if let Some(packet) = reassembler.push(&cell)? {
            if inbound_tx.send(packet).await.is_err() {
                break;
            }
            // One Sphinx packet per connection for client-style inject; relay streams
            // may carry many packets — reassembler resets after each complete packet.
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum InboundKey {
    Ingress,
    Peer(RelayId),
}

fn open_with_resolved(
    resolved: &InboundKey,
    frame: &[u8],
    ingress: &Option<[u8; 32]>,
    peer_table: &HashMap<RelayId, PeerInfo>,
) -> Result<aegis_crypto::cell::Cell, CryptoError> {
    let key = match resolved {
        InboundKey::Ingress => LinkKey::new(ingress.expect("ingress key")),
        InboundKey::Peer(id) => peer_table.get(id).expect("peer").link_key(),
    };
    key.open(frame)
}

fn resolve_first_frame(
    frame: &[u8],
    ingress: Option<[u8; 32]>,
    peer_table: &HashMap<RelayId, PeerInfo>,
) -> Result<(InboundKey, aegis_crypto::cell::Cell), NetError> {
    if let Some(bytes) = ingress {
        let key = LinkKey::new(bytes);
        if let Ok(cell) = key.open(frame) {
            return Ok((InboundKey::Ingress, cell));
        }
    }
    for (id, peer) in peer_table {
        if let Ok(cell) = peer.link_key().open(frame) {
            return Ok((InboundKey::Peer(*id), cell));
        }
    }
    Err(NetError::UnidentifiedInbound)
}

fn spawn_outbound_dispatcher<R: RngCore + CryptoRngCore + Send + 'static>(
    outbound_rx: mpsc::Receiver<ForwardedPacket>,
    peer_table: HashMap<RelayId, PeerInfo>,
    exit_tx: Option<ExitSink>,
    rng: Arc<Mutex<R>>,
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
            if let Err(e) = forward_to_peer(&pool, &peer, &fwd.packet, &mut *guard).await {
                eprintln!("aegis-relay net: forward to {:?}: {e}", fwd.next_hop);
            }
        }
    })
}

struct ConnectionPool {
    streams: HashMap<SocketAddr, Arc<Mutex<TcpStream>>>,
}

impl ConnectionPool {
    fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    async fn get_or_connect(&mut self, addr: SocketAddr) -> Result<Arc<Mutex<TcpStream>>, NetError> {
        if let Some(s) = self.streams.get(&addr) {
            return Ok(Arc::clone(s));
        }
        let stream = TcpStream::connect(addr).await?;
        let shared = Arc::new(Mutex::new(stream));
        self.streams.insert(addr, Arc::clone(&shared));
        Ok(shared)
    }

    async fn reconnect(&mut self, addr: SocketAddr) -> Result<Arc<Mutex<TcpStream>>, NetError> {
        self.streams.remove(&addr);
        self.get_or_connect(addr).await
    }
}

async fn forward_to_peer<R: RngCore + CryptoRngCore>(
    pool: &Arc<Mutex<ConnectionPool>>,
    peer: &PeerInfo,
    packet: &SphinxPacket,
    rng: &mut R,
) -> Result<(), NetError> {
    let stream = {
        let mut pool = pool.lock().await;
        pool.get_or_connect(peer.addr).await?
    };
    let mut stream = stream.lock().await;
    match write_packet(&mut *stream, &peer.link_key(), packet, rng).await {
        Ok(()) => Ok(()),
        Err(NetError::Io(_)) => {
            drop(stream);
            let mut pool = pool.lock().await;
            let stream = pool.reconnect(peer.addr).await?;
            let mut guard = stream.lock().await;
            write_packet(&mut *guard, &peer.link_key(), packet, rng).await
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
        stream.read_exact(&mut frame).await?;
        let cell = link_key.open(&frame)?;
        if let Some(packet) = reassembler.push(&cell)? {
            return Ok(packet);
        }
    }
    Err(NetError::Crypto(CryptoError::Malformed("incomplete packet")))
}
