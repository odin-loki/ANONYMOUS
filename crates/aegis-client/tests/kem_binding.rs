//! KEM roster binding checks at Sphinx path build time.

use aegis_client::send::{build_packet, ClientHop, SendError};
use aegis_crypto::kem::RelayKemSecret;
use aegis_topology::types::{KemPublicCommitment, RelayRecord, RelayId, JurisdictionId};
use rand_core::OsRng;

fn sample_hop(id_byte: u8) -> ClientHop {
    let mut rng = OsRng;
    let (_sec, pk) = RelayKemSecret::generate(&mut rng);
    let mut id = [0u8; 32];
    id[0] = id_byte;
    ClientHop::new(id, pk, None)
}

#[test]
fn build_packet_succeeds_with_matching_commitment() {
    let mut rng = OsRng;
    let (_sec, pk) = RelayKemSecret::generate(&mut rng);
    let record = RelayRecord::new(
        RelayId::from_u64(1),
        JurisdictionId::new("US"),
        &pk,
    );
    let hop0 = ClientHop::from_relay_record(&record, pk.clone(), None);
    let hop1 = sample_hop(2);
    let result = build_packet(&[hop0, hop1], b"bound-path", &mut rng);
    assert!(result.is_ok());
}

#[test]
fn build_packet_rejects_mismatched_commitment() {
    let mut rng = OsRng;
    let (_sec, pk) = RelayKemSecret::generate(&mut rng);
    let (_other_sec, other_pk) = RelayKemSecret::generate(&mut rng);
    let record = RelayRecord::new(
        RelayId::from_u64(1),
        JurisdictionId::new("US"),
        &other_pk,
    );
    let hop0 = ClientHop::from_relay_record(&record, pk, None);
    let hop1 = sample_hop(2);
    let err = build_packet(&[hop0, hop1], b"bad-bind", &mut rng).unwrap_err();
    assert!(matches!(err, SendError::KemBindingMismatch { .. }));
}

#[test]
fn build_packet_allows_missing_commitment() {
    let mut rng = OsRng;
    let hops = vec![sample_hop(1), sample_hop(2)];
    assert!(build_packet(&hops, b"legacy-dev", &mut rng).is_ok());
}

#[test]
fn with_commitment_accepts_matching_key() {
    let mut rng = OsRng;
    let (_sec, pk) = RelayKemSecret::generate(&mut rng);
    let commitment = KemPublicCommitment::from_public(&pk);
    let mut id = [0u8; 32];
    id[0] = 7;
    let hop0 = ClientHop::new(id, pk, None).with_commitment(commitment);
    let hop1 = sample_hop(8);
    assert!(build_packet(&[hop0, hop1], b"explicit-commit", &mut rng).is_ok());
}
