//! KEM roster binding checks at Sphinx path build time.

use aegis_client::send::{
    build_packet_require_bindings, build_packet_with_options, BuildPacketOptions, ClientHop,
    SendError,
};
use aegis_crypto::kem::RelayKemSecret;
use aegis_topology::types::{JurisdictionId, KemPublicCommitment, RelayRecord};
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
    let record = RelayRecord::from_kem_public(JurisdictionId::new("US"), &pk);
    let hop0 = ClientHop::from_relay_record(&record, pk.clone(), None);
    let (_sec1, pk1) = RelayKemSecret::generate(&mut rng);
    let record1 = RelayRecord::from_kem_public(JurisdictionId::new("DE"), &pk1);
    let hop1 = ClientHop::from_relay_record(&record1, pk1, None);
    let result = build_packet_require_bindings(&[hop0, hop1], b"bound-path", &mut rng);
    assert!(result.is_ok());
}

#[test]
fn build_packet_rejects_mismatched_commitment() {
    let mut rng = OsRng;
    let (_sec, pk) = RelayKemSecret::generate(&mut rng);
    let (_other_sec, other_pk) = RelayKemSecret::generate(&mut rng);
    let record = RelayRecord::from_kem_public(JurisdictionId::new("US"), &other_pk);
    let hop0 = ClientHop::from_relay_record(&record, pk, None);
    let hop1 = sample_hop(2);
    let err =
        build_packet_require_bindings(&[hop0, hop1], b"bad-bind", &mut rng).unwrap_err();
    assert!(matches!(
        err,
        SendError::KemBindingMismatch { .. } | SendError::MissingKemCommitment { .. }
    ));
}

#[test]
fn legacy_dev_allows_missing_commitment() {
    let mut rng = OsRng;
    let hops = vec![sample_hop(1), sample_hop(2)];
    assert!(build_packet_with_options(
        &hops,
        b"legacy-dev",
        &mut rng,
        BuildPacketOptions::legacy_dev()
    )
    .is_ok());
}

#[test]
fn build_packet_require_bindings_rejects_missing_commitment() {
    let mut rng = OsRng;
    let hops = vec![sample_hop(1), sample_hop(2)];
    let err =
        build_packet_require_bindings(&hops, b"prod", &mut rng).unwrap_err();
    assert!(matches!(err, SendError::MissingKemCommitment { .. }));
}

#[test]
fn build_packet_require_bindings_accepts_roster_hops() {
    let mut rng = OsRng;
    let (_sec0, pk0) = RelayKemSecret::generate(&mut rng);
    let (_sec1, pk1) = RelayKemSecret::generate(&mut rng);
    let record0 = RelayRecord::from_kem_public(JurisdictionId::new("US"), &pk0);
    let record1 = RelayRecord::from_kem_public(JurisdictionId::new("DE"), &pk1);
    let hop0 = ClientHop::from_relay_record(&record0, pk0, None);
    let hop1 = ClientHop::from_relay_record(&record1, pk1, None);
    assert!(
        build_packet_require_bindings(&[hop0, hop1], b"prod", &mut rng).is_ok()
    );
}

#[test]
fn with_commitment_accepts_matching_key() {
    let mut rng = OsRng;
    let (_sec, pk) = RelayKemSecret::generate(&mut rng);
    let commitment = KemPublicCommitment::from_public(&pk);
    let mut id = [0u8; 32];
    id[0] = 7;
    let hop0 = ClientHop::new(id, pk, None).with_commitment(commitment);
    let (_sec1, pk1) = RelayKemSecret::generate(&mut rng);
    let hop1 = ClientHop::new([8u8; 32], pk1.clone(), None)
        .with_commitment(KemPublicCommitment::from_public(&pk1));
    assert!(build_packet_require_bindings(&[hop0, hop1], b"explicit-commit", &mut rng).is_ok());
}
