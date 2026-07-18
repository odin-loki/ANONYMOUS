//! Minimal anonymous-credential **issuer** (Partial — not full AC).
//!
//! [`AnonymousCredentialIssuer`] signs software-bound tokens that bundle:
//!
//! - an [`crate::zk::AnonymousReputationPresentation`] (threshold ZK, no RelayId in proof bytes),
//! - epoch + score-band floor,
//! - an out-of-band [`crate::zk::ReputationNullifier`].
//!
//! Verification reuses [`crate::zk::verify_anonymous`] and spends via
//! [`crate::nullifier::NullifierRegistry`]. This is **not** a paper-complete
//! anonymous-credential system — the issuer sees `relay_id` at issue time and
//! there is no interactive blinding protocol or ZK show proof. See
//! `docs/ops/anonymous_reputation.md`.

use std::fs;
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::nullifier::{NullifierError, NullifierRegistry};
use crate::reputation::ReputationScore;
use crate::zk::{
    derive_reputation_nullifier, present_anonymous, scale_reputation, verify_anonymous,
    verify_anonymous_and_spend, AnonymousReputationPresentation, ReputationNullifier,
};

const ISSUER_PARAMS_VERSION: u32 = 1;
const ISSUER_PROVIDER_ID: &str = "software-v1";
const ISSUER_SIG_DOMAIN: &[u8] = b"aegis-anon-cred-issuer-v1";

#[derive(Debug, Error)]
pub enum IssuerError {
    #[error("score {score} below band floor {floor}")]
    ScoreBelowBand { score: f64, floor: f64 },
    #[error("issuer signature invalid")]
    InvalidSignature,
    #[error("issuer pubkey mismatch")]
    SignerMismatch,
    #[error("presentation score_commitment mismatch")]
    CommitmentMismatch,
    #[error("anonymous presentation verification failed")]
    PresentationInvalid,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported issuer params version {0}")]
    UnsupportedVersion(u32),
    #[error("malformed issuer verifying key")]
    MalformedKey,
    #[error("nullifier: {0}")]
    Nullifier(#[from] NullifierError),
}

/// Public issuer parameters persisted for verifiers (Ed25519 verifying key only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnonymousCredentialIssuerParams {
    pub version: u32,
    pub provider: String,
    pub verifying_key: [u8; 32],
}

impl AnonymousCredentialIssuerParams {
    pub fn verifying_key(&self) -> Result<VerifyingKey, IssuerError> {
        VerifyingKey::from_bytes(&self.verifying_key).map_err(|_| IssuerError::MalformedKey)
    }

    /// Persist public params to JSON (`path`; creates parent dirs).
    pub fn save_to_file(&self, path: &Path) -> Result<(), IssuerError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let text = serde_json::to_string_pretty(self)?;
        fs::write(path, text)?;
        Ok(())
    }

    /// Load public params from JSON written by [`Self::save_to_file`].
    pub fn load_from_file(path: &Path) -> Result<Self, IssuerError> {
        let text = fs::read_to_string(path)?;
        let params: Self = serde_json::from_str(&text)?;
        if params.version != ISSUER_PARAMS_VERSION {
            return Err(IssuerError::UnsupportedVersion(params.version));
        }
        let _ = params.verifying_key()?;
        Ok(params)
    }
}

/// Software-bound issuer: signs epoch + score-band + presentation + nullifier bindings.
///
/// **Not** a hardware or interactive AC issuer — holds an Ed25519 signing key and
/// attests that a relay met a score band at issue time.
pub struct AnonymousCredentialIssuer {
    signing_key: SigningKey,
}

/// Issued token: anonymous presentation + spend nullifier + issuer signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IssuedAnonymousCredential {
    pub epoch: u64,
    /// Minimum score floor this credential authorizes (same as presentation threshold).
    pub score_band_threshold: f64,
    pub presentation: AnonymousReputationPresentation,
    pub nullifier: ReputationNullifier,
    pub issuer_pubkey: [u8; 32],
    pub issuer_signature: Vec<u8>,
}

/// Client-side blinded issuance request (no `RelayId` in serialized fields).
///
/// **Honest Partial binding:** the issuer verifies `presentation` meets
/// `score_band_threshold` via ZK and signs the binding without learning the
/// exact score. The issuer still learns `nullifier` (unlinkable w.r.t. RelayId
/// if `blinding` stays client-secret) and may learn identity out-of-band.
/// This is **not** a cryptographic blind-signature or interactive AC show.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlindedIssueRequest {
    pub epoch: u64,
    pub score_band_threshold: f64,
    pub presentation: AnonymousReputationPresentation,
    pub nullifier: ReputationNullifier,
}

/// Issuer response to [`BlindedIssueRequest`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlindedIssueResponse {
    pub credential: IssuedAnonymousCredential,
}

impl AnonymousCredentialIssuer {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    pub fn public_params(&self) -> AnonymousCredentialIssuerParams {
        AnonymousCredentialIssuerParams {
            version: ISSUER_PARAMS_VERSION,
            provider: ISSUER_PROVIDER_ID.to_string(),
            verifying_key: self.signing_key.verifying_key().to_bytes(),
        }
    }

    /// Issue a blinded presentation token bound to `epoch` and `score_band_threshold`.
    ///
    /// The issuer learns `relay_id` here (honest Partial scope). The resulting
    /// credential carries no RelayId in the ZK proof bytes; spend binding is via
    /// `nullifier` derived from `(relay_id, epoch, blinding)`.
    pub fn issue(
        &self,
        score: ReputationScore,
        score_band_threshold: f64,
        relay_id: &[u8; 32],
        epoch: u64,
        blinding: &[u8; 32],
    ) -> Result<IssuedAnonymousCredential, IssuerError> {
        if score.0 < score_band_threshold {
            return Err(IssuerError::ScoreBelowBand {
                score: score.0,
                floor: score_band_threshold,
            });
        }

        let presentation = present_anonymous(score, score_band_threshold);
        let nullifier = derive_reputation_nullifier(relay_id, epoch, blinding);
        let issuer_pubkey = self.signing_key.verifying_key().to_bytes();
        let issuer_signature = self.sign_binding(
            epoch,
            score_band_threshold,
            &presentation.score_commitment,
            &nullifier,
        );

        Ok(IssuedAnonymousCredential {
            epoch,
            score_band_threshold,
            presentation,
            nullifier,
            issuer_pubkey,
            issuer_signature,
        })
    }

    /// Build a client-side blinded request (presentation + nullifier only).
    pub fn build_blinded_request(
        score: ReputationScore,
        score_band_threshold: f64,
        relay_id: &[u8; 32],
        epoch: u64,
        blinding: &[u8; 32],
    ) -> Result<BlindedIssueRequest, IssuerError> {
        if score.0 < score_band_threshold {
            return Err(IssuerError::ScoreBelowBand {
                score: score.0,
                floor: score_band_threshold,
            });
        }
        Ok(BlindedIssueRequest {
            epoch,
            score_band_threshold,
            presentation: present_anonymous(score, score_band_threshold),
            nullifier: derive_reputation_nullifier(relay_id, epoch, blinding),
        })
    }

    /// Issue from a blinded request without taking `relay_id`.
    ///
    /// Verifies the ZK threshold proof and signs epoch + commitment + nullifier.
    /// Exact score remains hidden; identity is not in request bytes.
    pub fn issue_from_blinded_request(
        &self,
        request: &BlindedIssueRequest,
    ) -> Result<BlindedIssueResponse, IssuerError> {
        if request.presentation.score_commitment != request.presentation.proof.commitment {
            return Err(IssuerError::CommitmentMismatch);
        }
        if !verify_anonymous(&request.presentation, request.score_band_threshold) {
            return Err(IssuerError::PresentationInvalid);
        }

        let issuer_pubkey = self.signing_key.verifying_key().to_bytes();
        let issuer_signature = self.sign_binding(
            request.epoch,
            request.score_band_threshold,
            &request.presentation.score_commitment,
            &request.nullifier,
        );

        Ok(BlindedIssueResponse {
            credential: IssuedAnonymousCredential {
                epoch: request.epoch,
                score_band_threshold: request.score_band_threshold,
                presentation: request.presentation.clone(),
                nullifier: request.nullifier,
                issuer_pubkey,
                issuer_signature,
            },
        })
    }

    /// Epoch rollover helper: drop spent nullifiers for `old_epoch`.
    ///
    /// Pair with fresh credentials at `new_epoch` (distinct nullifier derivation).
    pub fn rotate_epoch(registry: &mut NullifierRegistry, old_epoch: u64) {
        registry.forget_epoch(old_epoch);
    }

    /// Verify issuer signature + anonymous presentation (no spend).
    pub fn verify_credential(
        params: &AnonymousCredentialIssuerParams,
        credential: &IssuedAnonymousCredential,
    ) -> Result<bool, IssuerError> {
        if !Self::verify_issuer_binding(params, credential)? {
            return Ok(false);
        }
        if credential.presentation.score_commitment != credential.presentation.proof.commitment {
            return Err(IssuerError::CommitmentMismatch);
        }
        Ok(verify_anonymous(
            &credential.presentation,
            credential.score_band_threshold,
        ))
    }

    /// Verify issuer binding + ZK, then spend `nullifier` in `registry` for `epoch`.
    pub fn verify_and_spend(
        params: &AnonymousCredentialIssuerParams,
        registry: &mut NullifierRegistry,
        credential: &IssuedAnonymousCredential,
    ) -> Result<bool, IssuerError> {
        if !Self::verify_issuer_binding(params, credential)? {
            return Ok(false);
        }
        if credential.presentation.score_commitment != credential.presentation.proof.commitment {
            return Err(IssuerError::CommitmentMismatch);
        }
        verify_anonymous_and_spend(
            registry,
            &credential.presentation,
            credential.score_band_threshold,
            credential.epoch,
            credential.nullifier,
        )
        .map_err(IssuerError::Nullifier)
    }

    fn sign_binding(
        &self,
        epoch: u64,
        score_band_threshold: f64,
        score_commitment: &[u8; 32],
        nullifier: &ReputationNullifier,
    ) -> Vec<u8> {
        let msg = canonical_binding(epoch, score_band_threshold, score_commitment, nullifier);
        self.signing_key.sign(&msg).to_bytes().to_vec()
    }

    fn verify_issuer_binding(
        params: &AnonymousCredentialIssuerParams,
        credential: &IssuedAnonymousCredential,
    ) -> Result<bool, IssuerError> {
        if credential.issuer_pubkey != params.verifying_key {
            return Err(IssuerError::SignerMismatch);
        }
        let vk = params.verifying_key()?;
        let msg = canonical_binding(
            credential.epoch,
            credential.score_band_threshold,
            &credential.presentation.score_commitment,
            &credential.nullifier,
        );
        let sig_bytes: [u8; 64] = credential
            .issuer_signature
            .as_slice()
            .try_into()
            .map_err(|_| IssuerError::InvalidSignature)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        Ok(vk.verify(&msg, &sig).is_ok())
    }
}

fn canonical_binding(
    epoch: u64,
    score_band_threshold: f64,
    score_commitment: &[u8; 32],
    nullifier: &ReputationNullifier,
) -> Vec<u8> {
    let threshold_scaled = scale_reputation(score_band_threshold);
    let mut msg = Vec::with_capacity(
        ISSUER_SIG_DOMAIN.len() + 8 + 8 + 32 + 32,
    );
    msg.extend_from_slice(ISSUER_SIG_DOMAIN);
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.extend_from_slice(&threshold_scaled.to_le_bytes());
    msg.extend_from_slice(score_commitment);
    msg.extend_from_slice(nullifier);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nullifier::NullifierRegistry;

    fn test_issuer() -> AnonymousCredentialIssuer {
        AnonymousCredentialIssuer::from_seed([0x11u8; 32])
    }

    #[test]
    fn issue_present_verify_roundtrip() {
        let issuer = test_issuer();
        let params = issuer.public_params();
        let cred = issuer
            .issue(
                ReputationScore(0.82),
                0.5,
                &[0xAAu8; 32],
                100,
                &[0xBBu8; 32],
            )
            .unwrap();

        assert!(AnonymousCredentialIssuer::verify_credential(&params, &cred).unwrap());
        assert!(verify_anonymous(&cred.presentation, cred.score_band_threshold));
    }

    #[test]
    fn issue_present_spend_rejects_double_spend() {
        let issuer = test_issuer();
        let params = issuer.public_params();
        let cred = issuer
            .issue(
                ReputationScore(0.75),
                0.4,
                &[1u8; 32],
                42,
                &[2u8; 32],
            )
            .unwrap();
        let mut registry = NullifierRegistry::new();

        assert!(
            AnonymousCredentialIssuer::verify_and_spend(&params, &mut registry, &cred).unwrap()
        );
        let replay = AnonymousCredentialIssuer::verify_and_spend(&params, &mut registry, &cred);
        assert!(replay.is_err());
        assert!(registry.is_spent(42, &cred.nullifier));
    }

    #[test]
    fn issue_rejects_score_below_band() {
        let issuer = test_issuer();
        assert!(
            issuer
                .issue(
                    ReputationScore(0.3),
                    0.5,
                    &[1u8; 32],
                    1,
                    &[2u8; 32],
                )
                .is_err()
        );
    }

    #[test]
    fn tampered_signature_rejects() {
        let issuer = test_issuer();
        let params = issuer.public_params();
        let mut cred = issuer
            .issue(
                ReputationScore(0.9),
                0.5,
                &[3u8; 32],
                7,
                &[4u8; 32],
            )
            .unwrap();
        if !cred.issuer_signature.is_empty() {
            cred.issuer_signature[0] ^= 0xff;
        }
        assert!(!AnonymousCredentialIssuer::verify_credential(&params, &cred).unwrap());
    }

    #[test]
    fn wrong_epoch_in_binding_rejects_on_spend() {
        let issuer = test_issuer();
        let params = issuer.public_params();
        let mut cred = issuer
            .issue(
                ReputationScore(0.8),
                0.5,
                &[5u8; 32],
                10,
                &[6u8; 32],
            )
            .unwrap();
        cred.epoch = 11;
        let mut registry = NullifierRegistry::new();
        // Signature no longer matches tampered epoch.
        assert!(!AnonymousCredentialIssuer::verify_and_spend(&params, &mut registry, &cred).unwrap());
        assert!(registry.is_empty());
    }

    #[test]
    fn params_save_load_roundtrip() {
        let issuer = test_issuer();
        let params = issuer.public_params();
        let dir = std::env::temp_dir().join(format!(
            "aegis-anon-issuer-{}",
            std::process::id()
        ));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("issuer_params.json");

        params.save_to_file(&path).unwrap();
        let loaded = AnonymousCredentialIssuerParams::load_from_file(&path).unwrap();
        assert_eq!(loaded, params);

        let cred = issuer
            .issue(
                ReputationScore(0.7),
                0.5,
                &[7u8; 32],
                3,
                &[8u8; 32],
            )
            .unwrap();
        assert!(AnonymousCredentialIssuer::verify_credential(&loaded, &cred).unwrap());

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn blinded_issue_request_hides_relay_id_and_score() {
        let relay_id = [0xABu8; 32];
        let issuer = test_issuer();
        let request = AnonymousCredentialIssuer::build_blinded_request(
            ReputationScore(0.91),
            0.5,
            &relay_id,
            5,
            &[0xCCu8; 32],
        )
        .unwrap();
        let blob = serde_json::to_vec(&request).unwrap();
        assert!(
            !blob.windows(32).any(|w| w == relay_id),
            "blinded request JSON must not embed RelayId"
        );

        let response = issuer.issue_from_blinded_request(&request).unwrap();
        let params = issuer.public_params();
        assert!(
            AnonymousCredentialIssuer::verify_credential(&params, &response.credential).unwrap()
        );
    }

    #[test]
    fn blinded_issue_rejects_invalid_presentation() {
        let issuer = test_issuer();
        let mut request = AnonymousCredentialIssuer::build_blinded_request(
            ReputationScore(0.8),
            0.5,
            &[1u8; 32],
            1,
            &[2u8; 32],
        )
        .unwrap();
        request.presentation.proof.commitment[0] ^= 0xff;
        assert!(issuer.issue_from_blinded_request(&request).is_err());
    }

    #[test]
    fn epoch_rotate_forgets_old_spends() {
        let issuer = test_issuer();
        let params = issuer.public_params();
        let relay_id = [0x22u8; 32];
        let blinding = [0x33u8; 32];

        let cred_e1 = issuer
            .issue(ReputationScore(0.8), 0.5, &relay_id, 1, &blinding)
            .unwrap();
        let mut registry = NullifierRegistry::new();
        assert!(
            AnonymousCredentialIssuer::verify_and_spend(&params, &mut registry, &cred_e1).unwrap()
        );
        assert_eq!(registry.epoch_len(1), 1);

        AnonymousCredentialIssuer::rotate_epoch(&mut registry, 1);
        assert_eq!(registry.epoch_len(1), 0);

        let cred_e2 = issuer
            .issue(ReputationScore(0.8), 0.5, &relay_id, 2, &blinding)
            .unwrap();
        assert!(
            AnonymousCredentialIssuer::verify_and_spend(&params, &mut registry, &cred_e2).unwrap()
        );
    }

    #[test]
    fn credential_bytes_contain_no_relay_id() {
        let relay_id = [0xCDu8; 32];
        let issuer = test_issuer();
        let cred = issuer
            .issue(
                ReputationScore(0.85),
                0.5,
                &relay_id,
                1,
                &[0xEEu8; 32],
            )
            .unwrap();
        let blob = serde_json::to_vec(&cred.presentation).unwrap();
        assert!(
            !blob.windows(32).any(|w| w == relay_id),
            "presentation JSON must not embed RelayId"
        );
    }
}
