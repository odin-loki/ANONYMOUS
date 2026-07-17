//! GF(256) Shamir secret sharing for 32-byte ceremony seeds (lab / ops).
//!
//! Each secret byte is shared independently over AES-field GF(2^8) with the
//! same share x-coordinates. This is a small pure-Rust helper — not an HSM
//! substitute. See `docs/ops/consortium_key_ceremony.md`.

use rand_core::{CryptoRng, RngCore};

/// One Shamir share of a 32-byte secret: `x` in `1..=255` and 32 field elements `y`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedShare {
    pub x: u8,
    pub y: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShamirError {
    BadParams(&'static str),
    TooFewShares,
    DuplicateX,
    InvalidX,
}

impl std::fmt::Display for ShamirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadParams(msg) => write!(f, "shamir params: {msg}"),
            Self::TooFewShares => write!(f, "too few shares to reconstruct"),
            Self::DuplicateX => write!(f, "duplicate share x-coordinate"),
            Self::InvalidX => write!(f, "share x must be in 1..=255"),
        }
    }
}

impl std::error::Error for ShamirError {}

/// AES Rijndael irreducible: x^8 + x^4 + x^3 + x + 1.
const IRRED: u16 = 0x11b;

#[inline]
fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

#[inline]
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= IRRED as u8;
        }
        b >>= 1;
    }
    p
}

#[inline]
fn gf_inv(a: u8) -> u8 {
    // a^{254} = a^{-1} for a != 0 in GF(256).
    debug_assert!(a != 0);
    let mut x = a;
    let mut acc = 1u8;
    let mut e = 254u16;
    while e > 0 {
        if e & 1 != 0 {
            acc = gf_mul(acc, x);
        }
        x = gf_mul(x, x);
        e >>= 1;
    }
    acc
}

fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
    // Horner: (...((c_t * x + c_{t-1}) * x + ...) * x + c_0)
    let mut y = 0u8;
    for &c in coeffs.iter().rev() {
        y = gf_add(gf_mul(y, x), c);
    }
    y
}

/// Split a 32-byte seed into `n` shares with reconstruction threshold `threshold`.
///
/// Requires `1 <= threshold <= n <= 255`. Share indices are `1..=n`.
pub fn split_seed(
    secret: &[u8; 32],
    threshold: usize,
    n: usize,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<Vec<SeedShare>, ShamirError> {
    if threshold == 0 || threshold > n {
        return Err(ShamirError::BadParams("threshold must be in 1..=n"));
    }
    if n == 0 || n > 255 {
        return Err(ShamirError::BadParams("n must be in 1..=255"));
    }

    let mut shares: Vec<SeedShare> = (1..=n as u8)
        .map(|x| SeedShare { x, y: [0u8; 32] })
        .collect();

    for byte_idx in 0..32 {
        let mut coeffs = vec![0u8; threshold];
        coeffs[0] = secret[byte_idx];
        for c in coeffs.iter_mut().skip(1) {
            let mut b = [0u8; 1];
            rng.fill_bytes(&mut b);
            // Non-zero leading coeff preferred but zero high coeffs still OK if deg drops;
            // ensure at least random bytes (including possible zeros).
            *c = b[0];
        }
        // Force highest coeff nonzero when threshold > 1 so degree is exact.
        if threshold > 1 {
            while coeffs[threshold - 1] == 0 {
                let mut b = [0u8; 1];
                rng.fill_bytes(&mut b);
                coeffs[threshold - 1] = b[0];
            }
        }
        for share in &mut shares {
            share.y[byte_idx] = eval_poly(&coeffs, share.x);
        }
    }

    Ok(shares)
}

/// Reconstruct a 32-byte seed from at least `threshold` shares (any distinct x).
pub fn reconstruct_seed(shares: &[SeedShare]) -> Result<[u8; 32], ShamirError> {
    if shares.is_empty() {
        return Err(ShamirError::TooFewShares);
    }
    let mut seen = [false; 256];
    for s in shares {
        if s.x == 0 {
            return Err(ShamirError::InvalidX);
        }
        if seen[s.x as usize] {
            return Err(ShamirError::DuplicateX);
        }
        seen[s.x as usize] = true;
    }

    let mut secret = [0u8; 32];
    for byte_idx in 0..32 {
        secret[byte_idx] = lagrange_at_zero(shares, byte_idx)?;
    }
    Ok(secret)
}

fn lagrange_at_zero(shares: &[SeedShare], byte_idx: usize) -> Result<u8, ShamirError> {
    let mut acc = 0u8;
    for (i, si) in shares.iter().enumerate() {
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, sj) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            // ℓ_i(0) = Π_{j≠i} (0 - x_j) / (x_i - x_j) = Π x_j / (x_i + x_j) in GF(2)
            num = gf_mul(num, sj.x);
            den = gf_mul(den, gf_add(si.x, sj.x));
        }
        if den == 0 {
            return Err(ShamirError::DuplicateX);
        }
        let li = gf_mul(num, gf_inv(den));
        acc = gf_add(acc, gf_mul(si.y[byte_idx], li));
    }
    Ok(acc)
}

/// Encode share as `xx` + 64 hex chars of y (lowercase), optional trailing newline stripped by caller.
pub fn encode_share_hex(share: &SeedShare) -> String {
    let mut s = format!("{:02x}", share.x);
    for b in &share.y {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parse `xx` + 64 hex y bytes (33 bytes total).
pub fn decode_share_hex(hex: &str) -> Result<SeedShare, String> {
    let hex = hex.trim();
    if hex.len() != 66 {
        return Err(format!(
            "share hex must be 66 chars (1-byte x + 32-byte y), got {}",
            hex.len()
        ));
    }
    let bytes = hex_decode(hex)?;
    let x = bytes[0];
    if x == 0 {
        return Err("share x must be in 1..=255".into());
    }
    let mut y = [0u8; 32];
    y.copy_from_slice(&bytes[1..33]);
    Ok(SeedShare { x, y })
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn gf_mul_matches_aes_examples() {
        // 0x57 * 0x83 = 0xc1 (FIPS-197)
        assert_eq!(gf_mul(0x57, 0x83), 0xc1);
        assert_eq!(gf_mul(0x00, 0xff), 0x00);
        assert_eq!(gf_mul(0x01, 0xab), 0xab);
    }

    #[test]
    fn gf_inv_roundtrip() {
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "inv({a})");
        }
    }

    #[test]
    fn split_reconstruct_2_of_3() {
        let mut rng = StdRng::seed_from_u64(42);
        let secret = [0xABu8; 32];
        let shares = split_seed(&secret, 2, 3, &mut rng).unwrap();
        assert_eq!(shares.len(), 3);
        let rec = reconstruct_seed(&shares[0..2]).unwrap();
        assert_eq!(rec, secret);
        let rec2 = reconstruct_seed(&[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(rec2, secret);
    }

    #[test]
    fn split_reconstruct_3_of_5_random_secret() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let shares = split_seed(&secret, 3, 5, &mut rng).unwrap();
        let subset = vec![shares[1].clone(), shares[3].clone(), shares[4].clone()];
        assert_eq!(reconstruct_seed(&subset).unwrap(), secret);
    }

    #[test]
    fn one_of_one() {
        let mut rng = StdRng::seed_from_u64(1);
        let secret = [9u8; 32];
        let shares = split_seed(&secret, 1, 1, &mut rng).unwrap();
        assert_eq!(reconstruct_seed(&shares).unwrap(), secret);
    }

    #[test]
    fn hex_roundtrip() {
        let share = SeedShare {
            x: 3,
            y: [0x11; 32],
        };
        let hex = encode_share_hex(&share);
        assert_eq!(hex.len(), 66);
        assert_eq!(decode_share_hex(&hex).unwrap(), share);
    }

    #[test]
    fn rejects_duplicate_x() {
        let s = SeedShare {
            x: 1,
            y: [0; 32],
        };
        assert_eq!(
            reconstruct_seed(&[s.clone(), s]),
            Err(ShamirError::DuplicateX)
        );
    }
}
