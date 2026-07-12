//! Build and inject Sphinx packets over a real TCP hop link.

use std::collections::HashMap;
use std::net::SocketAddr;

use aegis_crypto::kem::RelayKemPublic;
use aegis_crypto::sphinx::{build, PathHop, SphinxPacket};
use aegis_crypto::link::LinkKey;
use aegis_relay::send_sphinx_packet;
use rand_core::{CryptoRngCore, RngCore};
use thiserror::Error;

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

/// Build, fragment, seal, and send a Sphinx packet to the first hop over TCP.
pub async fn send_payload<R: RngCore + CryptoRngCore>(
    hops: &[ClientHop],
    link: &ClientLink,
    payload: &[u8],
    rng: &mut R,
) -> Result<SphinxPacket, SendError> {
    let packet = build_packet(hops, payload, rng)?;
    let key = LinkKey::new(link.link_key_bytes);
    send_sphinx_packet(link.first_hop_addr, &key, &packet, rng).await?;
    Ok(packet)
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
