//! At-rest protection for external KEM seed files (`kem.seeds`).
//!
//! ## On-disk formats
//!
//! - **Legacy plaintext:** UTF-8 TOML (`x25519_seed` / `mlkem_d` / `mlkem_z` hex).
//! - **Windows DPAPI (default when `kem-dpapi` is enabled):** magic header
//!   [`KEM_SEED_DPAPI_MAGIC`] followed by a `CryptProtectData` blob (user scope).
//!
//! Non-Windows builds always store plaintext and rely on Unix mode `0600`
//! (no-op "protect"). Legacy plaintext files continue to load on all platforms.

/// Clear magic so loaders can distinguish DPAPI blobs from legacy TOML.
pub const KEM_SEED_DPAPI_MAGIC: &[u8] = b"AEGIS-KEM-DPAPI-v1\0";

/// True when `data` begins with the DPAPI magic header.
pub fn is_dpapi_protected(data: &[u8]) -> bool {
    data.starts_with(KEM_SEED_DPAPI_MAGIC)
}

/// Protect plaintext seed TOML for storage. On Windows with `kem-dpapi`, returns
/// magic + DPAPI ciphertext; otherwise returns plaintext unchanged (no-op).
pub fn protect_seed_bytes(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(all(windows, feature = "kem-dpapi"))]
    {
        use windows_dpapi::{encrypt_data, Scope};
        let cipher = encrypt_data(plaintext, Scope::User, None)
            .map_err(|e| format!("DPAPI CryptProtectData failed: {e}"))?;
        let mut out = Vec::with_capacity(KEM_SEED_DPAPI_MAGIC.len() + cipher.len());
        out.extend_from_slice(KEM_SEED_DPAPI_MAGIC);
        out.extend_from_slice(&cipher);
        return Ok(out);
    }
    #[cfg(not(all(windows, feature = "kem-dpapi")))]
    {
        Ok(plaintext.to_vec())
    }
}

/// Recover plaintext seed TOML from on-disk bytes.
///
/// DPAPI-magic files are unwrapped; everything else is treated as legacy
/// plaintext (UTF-8 TOML).
pub fn unprotect_seed_bytes(data: &[u8]) -> Result<Vec<u8>, String> {
    if is_dpapi_protected(data) {
        #[cfg(all(windows, feature = "kem-dpapi"))]
        {
            use windows_dpapi::{decrypt_data, Scope};
            let cipher = &data[KEM_SEED_DPAPI_MAGIC.len()..];
            return decrypt_data(cipher, Scope::User, None)
                .map_err(|e| format!("DPAPI CryptUnprotectData failed: {e}"));
        }
        #[cfg(not(all(windows, feature = "kem-dpapi")))]
        {
            return Err(
                "kem.seeds is DPAPI-protected but this build has no kem-dpapi / Windows support"
                    .into(),
            );
        }
    }
    Ok(data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_detection() {
        assert!(is_dpapi_protected(KEM_SEED_DPAPI_MAGIC));
        let mut buf = KEM_SEED_DPAPI_MAGIC.to_vec();
        buf.extend_from_slice(b"blob");
        assert!(is_dpapi_protected(&buf));
        assert!(!is_dpapi_protected(b"x25519_seed = \"aa\""));
        assert!(!is_dpapi_protected(b""));
    }

    #[test]
    fn legacy_plaintext_passthrough() {
        let toml = br#"x25519_seed = "11"
mlkem_d = "22"
mlkem_z = "33"
"#;
        let loaded = unprotect_seed_bytes(toml).unwrap();
        assert_eq!(loaded, toml);
    }

    #[cfg(all(windows, feature = "kem-dpapi"))]
    #[test]
    fn dpapi_protect_unprotect_roundtrip() {
        let toml = br#"x25519_seed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
mlkem_d = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
mlkem_z = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
"#;
        let stored = protect_seed_bytes(toml).expect("protect");
        assert!(is_dpapi_protected(&stored));
        assert_ne!(&stored[KEM_SEED_DPAPI_MAGIC.len()..], toml.as_slice());
        let plain = unprotect_seed_bytes(&stored).expect("unprotect");
        assert_eq!(plain, toml);
    }

    #[cfg(not(all(windows, feature = "kem-dpapi")))]
    #[test]
    fn protect_is_noop_without_dpapi() {
        let toml = b"x25519_seed = \"aa\"\n";
        let stored = protect_seed_bytes(toml).unwrap();
        assert_eq!(stored, toml);
        assert!(!is_dpapi_protected(&stored));
    }
}
