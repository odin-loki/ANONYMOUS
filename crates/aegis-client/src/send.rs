//! Build and inject Sphinx packets over a real TCP hop link.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use aegis_crypto::fragment::{fragment_with_random_id, SPHINX_FRAGMENT_COUNT};
use aegis_crypto::kem::RelayKemPublic;
use aegis_crypto::sphinx::{build, PathHop, SphinxPacket};
use aegis_relay::{send_sphinx_packet, LinkBridgeConfig};
use rand_core::{CryptoRngCore, OsRng, RngCore};
use thiserror::Error;

use crate::emitter::{ConstantRateEmitter, EmitterConfig};
use crate::tcp_transport::{run_paced_ticks, TcpCellTransport};
use crate::transport::OutboundCell;

/// One hop in an explicit client path (id + KEM public key + optional TCP addr).
#[derive(Clone)]
pub struct ClientHop {
    pub id: [u8; 32],
    pub kem_public: RelayKemPublic,
    /// Listen address of this hop (required for the first hop only).
    pub addr: Option<SocketAddr>,
}

/// Link key for the client → first-hop connection.
#[derive(Clone, Debug)]
pub struct ClientLink {
    pub first_hop_addr: SocketAddr,
    pub link_key_bytes: [u8; 32],
}

#[derive(Debug, Error)]
pub enum SendError {
    #[error("path must have at least 2 hops")]
    PathTooShort,
    #[error("first hop missing TCP address")]
    MissingFirstHopAddr,
    #[error("crypto: {0}")]
    Crypto(#[from] aegis_crypto::CryptoError),
    #[error("network: {0}")]
    Net(#[from] aegis_relay::NetError),
}

/// Build a Sphinx packet along `hops` carrying `payload`.
pub fn build_packet<R: RngCore + CryptoRngCore>(
    hops: &[ClientHop],
    payload: &[u8],
    rng: &mut R,
) -> Result<SphinxPacket, SendError> {
    if hops.len() < 2 {
        return Err(SendError::PathTooShort);
    }
    let path: Vec<PathHop> = hops
        .iter()
        .map(|h| PathHop {
            id: h.id,
            pk: h.kem_public.clone(),
        })
        .collect();
    Ok(build(&path, payload, rng)?)
}

/// Build, fragment, seal, and burst-send a Sphinx packet (unpaced legacy path).
pub async fn send_payload<R: RngCore + CryptoRngCore>(
    hops: &[ClientHop],
    link: &ClientLink,
    payload: &[u8],
    rng: &mut R,
) -> Result<SphinxPacket, SendError> {
    let packet = build_packet(hops, payload, rng)?;
    send_sphinx_packet(
        link.first_hop_addr,
        &link.link_key_bytes,
        &packet,
        rng,
        &LinkBridgeConfig::default(),
    )
    .await?;
    Ok(packet)
}

/// Build, fragment, and emit a Sphinx packet at constant rate τ over TCP (Mode 1 path).
///
/// Connects and handshakes once, then sends exactly one sealed link frame per emitter
/// tick until all [`SPHINX_FRAGMENT_COUNT`] fragments are on the wire.
pub async fn send_payload_paced<R: RngCore + CryptoRngCore>(
    hops: &[ClientHop],
    link: &ClientLink,
    payload: &[u8],
    rng: &mut R,
    emitter_config: Option<EmitterConfig>,
    bridge_config: &LinkBridgeConfig,
) -> Result<SphinxPacket, SendError> {
    let packet = build_packet(hops, payload, rng)?;
    let (fragments, _) = fragment_with_random_id(&packet, rng);

    let config = emitter_config.unwrap_or_default();
    let mut emitter = ConstantRateEmitter::new(config, OsRng);
    for cell in fragments {
        emitter.enqueue_cell(OutboundCell(cell));
    }

    let transport = TcpCellTransport::connect(link, bridge_config, rng).await?;
    run_paced_ticks(&mut emitter, &transport, SPHINX_FRAGMENT_COUNT).await;

    Ok(packet)
}

/// Convenience: paced send with default bridge config and emitter τ.
pub async fn send_payload_paced_default<R: RngCore + CryptoRngCore>(
    hops: &[ClientHop],
    link: &ClientLink,
    payload: &[u8],
    rng: &mut R,
) -> Result<SphinxPacket, SendError> {
    send_payload_paced(
        hops,
        link,
        payload,
        rng,
        None,
        &LinkBridgeConfig::default(),
    )
    .await
}

/// Convenience: path from relay id bytes and pre-built public keys.
pub fn hops_from_keys(
    ids: &[[u8; 32]],
    publics: &[RelayKemPublic],
    addrs: &HashMap<[u8; 32], SocketAddr>,
) -> Vec<ClientHop> {
    ids.iter()
        .zip(publics.iter())
        .map(|(id, pk)| ClientHop {
            id: *id,
            kem_public: pk.clone(),
            addr: addrs.get(id).copied(),
        })
        .collect()
}

/// Test helper: fragment a packet and return fragment cells plus expected tick count.
pub fn sphinx_fragments_for_pacing<R: RngCore + CryptoRngCore>(
    packet: &SphinxPacket,
    rng: &mut R,
) -> ([aegis_crypto::cell::Cell; SPHINX_FRAGMENT_COUNT], Duration) {
    let (cells, _) = fragment_with_random_id(packet, rng);
    (cells, EmitterConfig::default().tau)
}
