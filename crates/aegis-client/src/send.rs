//! Build and inject Sphinx packets over a real TCP hop link.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use aegis_crypto::fragment::{fragment_with_random_id, SPHINX_FRAGMENT_COUNT};
use aegis_crypto::kem::RelayKemPublic;
use aegis_crypto::sphinx::{build, PathHop, SphinxPacket};
use aegis_relay::{send_sphinx_packet, LinkBridgeConfig};
use aegis_topology::types::{KemPublicCommitment, RelayRecord};
use rand_core::{CryptoRngCore, RngCore};
use thiserror::Error;

use crate::emitter::EmitterConfig;
use crate::session::{PacedSession, PacedSessionConfig};

/// One hop in an explicit client path (id + KEM public key + optional TCP addr).
#[derive(Clone)]
pub struct ClientHop {
    pub id: [u8; 32],
    pub kem_public: RelayKemPublic,
    /// Roster KEM commitment; when present, [`build_packet`] verifies it matches `kem_public`.
    pub kem_commitment: Option<KemPublicCommitment>,
    /// Listen address of this hop (required for the first hop only).
    pub addr: Option<SocketAddr>,
}

impl ClientHop {
    /// Hop without roster binding (dev / legacy paths).
    pub fn new(id: [u8; 32], kem_public: RelayKemPublic, addr: Option<SocketAddr>) -> Self {
        Self {
            id,
            kem_public,
            kem_commitment: None,
            addr,
        }
    }

    /// Attach a roster KEM commitment for binding verification at build time.
    pub fn with_commitment(mut self, commitment: KemPublicCommitment) -> Self {
        self.kem_commitment = Some(commitment);
        self
    }

    /// Build from an admitted roster record and the relay's live KEM public key.
    pub fn from_relay_record(
        record: &RelayRecord,
        kem_public: RelayKemPublic,
        addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            id: *record.id.as_bytes(),
            kem_public,
            kem_commitment: Some(record.kem_public_commitment),
            addr,
        }
    }
}

/// Link key for the client → first-hop connection.
#[derive(Clone, Debug)]
pub struct ClientLink {
    pub first_hop_addr: SocketAddr,
    /// Expected first-hop relay id for the link handshake.
    pub first_hop_relay_id: [u8; 32],
    pub link_key_bytes: [u8; 32],
}

#[derive(Debug, Error)]
pub enum SendError {
    #[error("path must have at least 2 hops")]
    PathTooShort,
    #[error("bound path record count ({records}) does not match public key count ({publics})")]
    BoundPathLengthMismatch { records: usize, publics: usize },
    #[error("first hop missing TCP address")]
    MissingFirstHopAddr,
    #[error("crypto: {0}")]
    Crypto(#[from] aegis_crypto::CryptoError),
    #[error("network: {0}")]
    Net(#[from] aegis_relay::NetError),
    #[error("paced session closed")]
    SessionClosed,
    #[error("KEM public key does not match roster commitment for hop {hop_id:02x}{hop_id_tail:02x}…")]
    KemBindingMismatch {
        hop_id: u8,
        hop_id_tail: u8,
    },
    #[error("missing roster KEM commitment for hop {hop_id:02x}{hop_id_tail:02x}… (production mode)")]
    MissingKemCommitment {
        hop_id: u8,
        hop_id_tail: u8,
    },
}

/// Options for [`build_packet_with_options`].
#[derive(Clone, Copy, Debug, Default)]
pub struct BuildPacketOptions {
    /// When true, every hop must carry a roster KEM commitment before encapsulation.
    pub require_kem_binding: bool,
}

/// Build a Sphinx packet along `hops` carrying `payload`.
///
/// When a hop carries a roster commitment, verifies it matches `kem_public`.
/// Use [`build_packet_require_bindings`] for production paths built from roster records.
pub fn build_packet<R: RngCore + CryptoRngCore>(
    hops: &[ClientHop],
    payload: &[u8],
    rng: &mut R,
) -> Result<SphinxPacket, SendError> {
    build_packet_with_options(hops, payload, rng, BuildPacketOptions::default())
}

/// Like [`build_packet`] but requires a roster KEM commitment on every hop.
pub fn build_packet_require_bindings<R: RngCore + CryptoRngCore>(
    hops: &[ClientHop],
    payload: &[u8],
    rng: &mut R,
) -> Result<SphinxPacket, SendError> {
    build_packet_with_options(
        hops,
        payload,
        rng,
        BuildPacketOptions {
            require_kem_binding: true,
        },
    )
}

/// Build a Sphinx packet with explicit binding policy.
pub fn build_packet_with_options<R: RngCore + CryptoRngCore>(
    hops: &[ClientHop],
    payload: &[u8],
    rng: &mut R,
    options: BuildPacketOptions,
) -> Result<SphinxPacket, SendError> {
    if hops.len() < 2 {
        return Err(SendError::PathTooShort);
    }
    for hop in hops {
        verify_kem_binding(hop, options.require_kem_binding)?;
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
    send_payload_with_options(hops, link, payload, rng, BuildPacketOptions::default()).await
}

/// Like [`send_payload`] with explicit roster binding policy.
pub async fn send_payload_with_options<R: RngCore + CryptoRngCore>(
    hops: &[ClientHop],
    link: &ClientLink,
    payload: &[u8],
    rng: &mut R,
    options: BuildPacketOptions,
) -> Result<SphinxPacket, SendError> {
    let packet = build_packet_with_options(hops, payload, rng, options)?;
    send_sphinx_packet(
        link.first_hop_addr,
        &link.link_key_bytes,
        aegis_relay::RelayId::from(link.first_hop_relay_id),
        &packet,
        rng,
        &LinkBridgeConfig::default(),
    )
    .await?;
    Ok(packet)
}

/// Build, fragment, and emit a Sphinx packet at constant rate τ over TCP (Mode 1 path).
///
/// Opens one paced session, enqueues all [`SPHINX_FRAGMENT_COUNT`] fragments, waits for
/// the queue to drain, then shuts down. Pass `cover_after_send` to keep dummy cover
/// after the last fragment (production default via CLI); `Duration::ZERO` preserves the
/// legacy exactly-18-ticks behavior.
pub async fn send_payload_paced<R: RngCore + CryptoRngCore>(
    hops: &[ClientHop],
    link: &ClientLink,
    payload: &[u8],
    rng: &mut R,
    emitter_config: Option<EmitterConfig>,
    bridge_config: &LinkBridgeConfig,
    cover_after_send: Duration,
) -> Result<SphinxPacket, SendError> {
    let mut session = PacedSession::connect(
        link,
        bridge_config,
        PacedSessionConfig {
            emitter_config: emitter_config.unwrap_or_default(),
            cover_after_send,
        },
        rng,
    )
    .await?;
    let packet = session.send_payload_via_session(hops, payload, rng)?;
    session.wait_idle_cover().await?;
    session.shutdown().await?;
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
        Duration::ZERO,
    )
    .await
}

/// Convenience: path from relay id bytes and pre-built public keys.
pub fn hops_from_keys(
    ids: &[[u8; 32]],
    publics: &[RelayKemPublic],
    addrs: &HashMap<[u8; 32], SocketAddr>,
) -> Vec<ClientHop> {
    hops_from_keys_with_commitments(ids, publics, None, addrs)
}

/// Like [`hops_from_keys`], with optional per-hop roster KEM commitments.
pub fn hops_from_keys_with_commitments(
    ids: &[[u8; 32]],
    publics: &[RelayKemPublic],
    commitments: Option<&[KemPublicCommitment]>,
    addrs: &HashMap<[u8; 32], SocketAddr>,
) -> Vec<ClientHop> {
    ids.iter()
        .zip(publics.iter())
        .enumerate()
        .map(|(i, (id, pk))| ClientHop {
            id: *id,
            kem_public: pk.clone(),
            kem_commitment: commitments.and_then(|c| c.get(i).copied()),
            addr: addrs.get(id).copied(),
        })
        .collect()
}

/// Build hops from admitted roster records and live KEM public keys (same order).
pub fn hops_from_records(
    records: &[RelayRecord],
    publics: &[RelayKemPublic],
    addrs: &HashMap<[u8; 32], SocketAddr>,
) -> Vec<ClientHop> {
    records
        .iter()
        .zip(publics.iter())
        .map(|(record, pk)| {
            ClientHop::from_relay_record(record, pk.clone(), addrs.get(record.id.as_bytes()).copied())
        })
        .collect()
}

/// Map a pruned bound path from [`aegis_topology::build_bound_path_pruned`] to client hops.
///
/// Verifies each live KEM public key matches the signed roster commitment before returning hops
/// suitable for [`build_packet_require_bindings`].
pub fn hops_from_bound_path(
    records: &[RelayRecord],
    publics: &[RelayKemPublic],
    addrs: &HashMap<[u8; 32], SocketAddr>,
) -> Result<Vec<ClientHop>, SendError> {
    if records.len() != publics.len() {
        return Err(SendError::BoundPathLengthMismatch {
            records: records.len(),
            publics: publics.len(),
        });
    }
    for (record, pk) in records.iter().zip(publics.iter()) {
        if !record.binds_kem_public(pk) {
            let id = record.id.as_bytes();
            return Err(SendError::KemBindingMismatch {
                hop_id: id[0],
                hop_id_tail: id[1],
            });
        }
    }
    Ok(hops_from_records(records, publics, addrs))
}

fn verify_kem_binding(hop: &ClientHop, require: bool) -> Result<(), SendError> {
    match hop.kem_commitment {
        Some(expected) => {
            if expected != KemPublicCommitment::from_public(&hop.kem_public) {
                return Err(SendError::KemBindingMismatch {
                    hop_id: hop.id[0],
                    hop_id_tail: hop.id[1],
                });
            }
        }
        None if require => {
            return Err(SendError::MissingKemCommitment {
                hop_id: hop.id[0],
                hop_id_tail: hop.id[1],
            });
        }
        None => {}
    }
    Ok(())
}

/// Test helper: fragment a packet and return fragment cells plus expected tick count.
pub fn sphinx_fragments_for_pacing<R: RngCore + CryptoRngCore>(
    packet: &SphinxPacket,
    rng: &mut R,
) -> ([aegis_crypto::cell::Cell; SPHINX_FRAGMENT_COUNT], Duration) {
    let (cells, _) = fragment_with_random_id(packet, rng);
    (cells, EmitterConfig::default().tau)
}
