//! At-rest protection for external KEM seed files (`kem.seeds`).
//!
//! ## On-disk formats
//!
//! - **Legacy plaintext:** UTF-8 TOML (`x25519_seed` / `mlkem_d` / `mlkem_z` hex).
//! - **Windows DPAPI (default when `kem-dpapi` is enabled):** magic header
//!   [`KEM_SEED_DPAPI_MAGIC`] followed by a `CryptProtectData` blob (**same-user**
//!   scope via `CryptProtectData` / `Scope::User` — decryptable only by the
//!   Windows user profile that created it; not an HSM or cross-user secret store).
//! - **Unix keyring (default when `kem-keyring` is enabled):** magic header
//!   [`KEM_SEED_KEYRING_MAGIC`] followed by the keyring account UTF-8; the seed
//!   TOML lives in the OS keychain (service [`KEM_KEYRING_SERVICE`]).
//!
//! Fallback when keyring is unavailable or disabled: plaintext TOML + Unix mode
//! `0600` on write. **Load refuses** Unix seed files whose mode grants group or
//! world access (`mode & 0o077 != 0`), including legacy plaintext. Legacy
//! plaintext with owner-only mode still loads on all platforms.

use sha3::{Digest, Sha3_256};
use std::path::Path;

/// Clear magic so loaders can distinguish DPAPI blobs from legacy TOML.
pub const KEM_SEED_DPAPI_MAGIC: &[u8] = b"AEGIS-KEM-DPAPI-v1\0";

/// Pointer-file magic: seed material is in the OS keychain under this account.
pub const KEM_SEED_KEYRING_MAGIC: &[u8] = b"AEGIS-KEM-KEYRING-v1\0";

/// `keyring` service name for relay KEM seeds.
pub const KEM_KEYRING_SERVICE: &str = "aegis-node";

/// True when `data` begins with the DPAPI magic header.
pub fn is_dpapi_protected(data: &[u8]) -> bool {
    data.starts_with(KEM_SEED_DPAPI_MAGIC)
}

/// True when `data` begins with the keyring pointer magic header.
pub fn is_keyring_protected(data: &[u8]) -> bool {
    data.starts_with(KEM_SEED_KEYRING_MAGIC)
}

/// Refuse load when a Unix `kem.seeds` path is group- or world-accessible.
///
/// Applies to all on-disk formats (plaintext, keyring pointer, etc.). No-op on
/// non-Unix targets (Windows relies on DPAPI same-user binding instead).
#[cfg(unix)]
pub fn assert_kem_seed_file_mode_safe(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .map_err(|e| format!("kem.seeds metadata: {e}"))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "kem.seeds at {} has insecure mode {mode:o} (group/world access); \
             expected owner-only (0600 or tighter)",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn assert_kem_seed_file_mode_safe(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Stable keyring account for a node config path (or optional relay id hex).
///
/// Prefer `relay_id_hex` when known; otherwise `SHA3-256("aegis-kem-seed-v1" || path)`.
pub fn kem_keyring_account(config_path: &Path, relay_id_hex: Option<&str>) -> String {
    if let Some(id) = relay_id_hex {
        let id = id.trim().trim_start_matches("0x");
        if !id.is_empty() {
            return format!("kem:relay:{id}");
        }
    }
    let mut h = Sha3_256::new();
    h.update(b"aegis-kem-seed-v1");
    h.update(config_path.to_string_lossy().as_bytes());
    let digest = h.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("kem:cfg:{hex}")
}

/// Protect plaintext seed TOML for storage.
///
/// - Windows + `kem-dpapi`: magic + DPAPI ciphertext.
/// - Unix + `kem-keyring`: store secret in OS keychain; return magic + account pointer.
///   If the keychain set fails, returns plaintext (caller persists with mode `0600`).
/// - Otherwise: plaintext unchanged.
pub fn protect_seed_bytes(plaintext: &[u8], account: &str) -> Result<Vec<u8>, String> {
    #[cfg(all(windows, feature = "kem-dpapi"))]
    {
        let _ = account;
        use windows_dpapi::{encrypt_data, Scope};
        let cipher = encrypt_data(plaintext, Scope::User, None)
            .map_err(|e| format!("DPAPI CryptProtectData failed: {e}"))?;
        let mut out = Vec::with_capacity(KEM_SEED_DPAPI_MAGIC.len() + cipher.len());
        out.extend_from_slice(KEM_SEED_DPAPI_MAGIC);
        out.extend_from_slice(&cipher);
        return Ok(out);
    }

    #[cfg(all(unix, feature = "kem-keyring"))]
    {
        match keyring_store(account, plaintext) {
            Ok(()) => {
                let mut out = Vec::with_capacity(KEM_SEED_KEYRING_MAGIC.len() + account.len());
                out.extend_from_slice(KEM_SEED_KEYRING_MAGIC);
                out.extend_from_slice(account.as_bytes());
                return Ok(out);
            }
            Err(e) => {
                // Fallback: plaintext file (0600 applied by caller).
                eprintln!(
                    "aegis-node: keyring store failed ({e}); falling back to 0600 kem.seeds file"
                );
                return Ok(plaintext.to_vec());
            }
        }
    }

    #[cfg(not(any(
        all(windows, feature = "kem-dpapi"),
        all(unix, feature = "kem-keyring")
    )))]
    {
        let _ = account;
        Ok(plaintext.to_vec())
    }
}

/// Recover plaintext seed TOML from on-disk bytes (and keyring when applicable).
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

    if is_keyring_protected(data) {
        let account = std::str::from_utf8(&data[KEM_SEED_KEYRING_MAGIC.len()..])
            .map_err(|_| "kem.seeds keyring pointer account is not UTF-8".to_string())?;
        #[cfg(all(unix, feature = "kem-keyring"))]
        {
            return keyring_load(account);
        }
        #[cfg(not(all(unix, feature = "kem-keyring")))]
        {
            return Err(format!(
                "kem.seeds is keyring-protected (account={account}) but this build has no kem-keyring / Unix support"
            ));
        }
    }

    Ok(data.to_vec())
}

#[cfg(all(unix, feature = "kem-keyring"))]
fn keyring_store(account: &str, plaintext: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(plaintext)
        .map_err(|_| "kem seed plaintext is not UTF-8".to_string())?;
    let entry = keyring::Entry::new(KEM_KEYRING_SERVICE, account)
        .map_err(|e| format!("keyring Entry::new: {e}"))?;
    entry
        .set_password(text)
        .map_err(|e| format!("keyring set_password: {e}"))
}

#[cfg(all(unix, feature = "kem-keyring"))]
fn keyring_load(account: &str) -> Result<Vec<u8>, String> {
    let entry = keyring::Entry::new(KEM_KEYRING_SERVICE, account)
        .map_err(|e| format!("keyring Entry::new: {e}"))?;
    let text = entry
        .get_password()
        .map_err(|e| format!("keyring get_password: {e}"))?;
    Ok(text.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_detection() {
        assert!(is_dpapi_protected(KEM_SEED_DPAPI_MAGIC));
        assert!(is_keyring_protected(KEM_SEED_KEYRING_MAGIC));
        let mut buf = KEM_SEED_DPAPI_MAGIC.to_vec();
        buf.extend_from_slice(b"blob");
        assert!(is_dpapi_protected(&buf));
        assert!(!is_keyring_protected(&buf));
        let mut kbuf = KEM_SEED_KEYRING_MAGIC.to_vec();
        kbuf.extend_from_slice(b"kem:relay:ab");
        assert!(is_keyring_protected(&kbuf));
        assert!(!is_dpapi_protected(&kbuf));
        assert!(!is_dpapi_protected(b"x25519_seed = \"aa\""));
        assert!(!is_keyring_protected(b"x25519_seed = \"aa\""));
        assert!(!is_dpapi_protected(b""));
    }

    #[test]
    fn keyring_account_prefers_relay_id() {
        let acc = kem_keyring_account(Path::new("/tmp/node.toml"), Some("aabbcc"));
        assert_eq!(acc, "kem:relay:aabbcc");
    }

    #[test]
    fn keyring_account_hashes_config_path() {
        let a = kem_keyring_account(Path::new("/tmp/a.toml"), None);
        let b = kem_keyring_account(Path::new("/tmp/b.toml"), None);
        assert!(a.starts_with("kem:cfg:"));
        assert_ne!(a, b);
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
        let stored = protect_seed_bytes(toml, "unused").expect("protect");
        assert!(is_dpapi_protected(&stored));
        assert_ne!(&stored[KEM_SEED_DPAPI_MAGIC.len()..], toml.as_slice());
        let plain = unprotect_seed_bytes(&stored).expect("unprotect");
        assert_eq!(plain, toml);
    }

    #[cfg(not(any(
        all(windows, feature = "kem-dpapi"),
        all(unix, feature = "kem-keyring")
    )))]
    #[test]
    fn protect_is_noop_without_backends() {
        let toml = b"x25519_seed = \"aa\"\n";
        let stored = protect_seed_bytes(toml, "acc").unwrap();
        assert_eq!(stored, toml);
        assert!(!is_dpapi_protected(&stored));
        assert!(!is_keyring_protected(&stored));
    }

    #[cfg(unix)]
    #[test]
    fn kem_seed_file_rejects_group_world_readable_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "aegis-kem-mode-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("kem.seeds");
        std::fs::write(&path, b"x25519_seed = \"aa\"\n").unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms).unwrap();

        let err = assert_kem_seed_file_mode_safe(&path).unwrap_err();
        assert!(
            err.contains("insecure mode"),
            "unexpected error: {err}"
        );

        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms).unwrap();
        assert!(assert_kem_seed_file_mode_safe(&path).is_ok());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[cfg(not(unix))]
    #[test]
    fn kem_seed_file_mode_check_is_noop_off_unix() {
        let path = Path::new("/nonexistent/kem.seeds");
        assert!(assert_kem_seed_file_mode_safe(path).is_ok());
    }
    /// Skips cleanly when the platform keyring backend is missing (CI/headless).
    #[cfg(all(unix, feature = "kem-keyring"))]
    #[test]
    fn keyring_protect_unprotect_roundtrip_or_fallback() {
        let toml = br#"x25519_seed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
mlkem_d = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
mlkem_z = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
"#;
        let account = format!(
            "kem:test:{}:{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let stored = protect_seed_bytes(toml, &account).expect("protect");
        if is_keyring_protected(&stored) {
            let plain = unprotect_seed_bytes(&stored).expect("unprotect");
            assert_eq!(plain, toml);
            // Best-effort cleanup.
            let _ = keyring::Entry::new(KEM_KEYRING_SERVICE, &account)
                .ok()
                .and_then(|e| e.delete_credential().ok());
        } else {
            // Fallback path when no keyring daemon: plaintext.
            assert_eq!(stored, toml);
        }
    }
}
