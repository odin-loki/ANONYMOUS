# Noise hop-link authentication (ops)

**Date:** 2026-07-17  
**Crates:** `aegis-crypto` (`noise_link`), `aegis-relay` (`net`), `aegis-node` (TOML)  
**Feature:** `noise-link` (default on)

## Summary

Hop links can use:

| Mode | Config | Auth |
|------|--------|------|
| **Auto** (default) | `handshake = "auto"` | Noise when local (+ peer) static keys are present; otherwise LegacyPsk |
| **LegacyPsk** | `handshake = "legacy_psk"` | Ephemeral X25519 + PSK MAC + optional roster id / KEM binding |
| **Noise** | `handshake = "noise"` | Noise_IK-**compatible** mutual auth with per-node static X25519 keys (requires local secret) |

`Auto` keeps existing deployments on LegacyPsk until operators configure `noise_static_*` keys. Explicit `legacy_psk` never selects Noise.

## Wire format (`snow` / standard Noise)

| Message | Bytes |
|---------|------:|
| Initiator → responder (msg1) | 96 (`e` ‖ enc(`s`) ‖ enc(payload tag)) |
| Responder → initiator (msg2) | 48 (`e` ‖ enc(payload tag)) |

Handshake uses **`Noise_IK_25519_ChaChaPoly_BLAKE2s`** via the [`snow`](https://docs.rs/snow) crate
(BLAKE2s transcript). Session keys are derived from the Noise handshake hash with an AEGIS
domain separator; 580-byte cell AEAD framing is unchanged.

### Legacy SHA3 path

Feature `noise-link-legacy-sha3` exposes the pre-2026-07 in-tree transcript (80-byte msg1,
SHA3-256 mixing). **Not** interoperable with the default `snow` path or other standard Noise
stacks. Use only for migration testing.

## Auto selection rules

| Role | Selects Noise when |
|------|--------------------|
| Initiator | `handshake` is `Noise`, **or** `Auto` with local `noise_static_secret` **and** peer `noise_static_public` |
| Responder | `handshake` is `Noise`, **or** `Auto` with local `noise_static_secret` |

Both sides of a link must agree (both Auto with keys, or both explicit Noise). Mixing Auto-without-keys (LegacyPsk) against Auto-with-secret (Noise) will fail the handshake.

## Static keys

- **Local secret:** `[link] noise_static_secret` — 64 hex chars (32 bytes). Required when `handshake = "noise"`; enables Noise under `auto`.
- **Peer public:** `[[peers]] noise_static_public` — 64 hex chars. Roster expectation verified by the responder after decrypting message 1; required on the initiator for Auto→Noise.
- **Lab convenience:** if `noise_static_public` is omitted, the responder may derive an expected public from `SHA3-256("aegis-noise-static-sk-v1" ‖ link_key)` (same helper as `derive_noise_static_secret`). Prefer explicit hex in production.
- **Ingress:** optional `[link] ingress_noise_static_public`, or derive from the ingress `link_key` when unset.

Generate a keypair:

```text
secret = random 32 bytes (or derive_noise_static_secret(material))
public = X25519(secret)
```

Publish only the **public** hex in peer TOML / roster distribution.

## TOML example (production Noise via Auto)

```toml
[link]
handshake = "auto"   # default; Noise once keys below are set
noise_static_secret = "<64 hex local static secret>"
# optional:
# ingress_noise_static_public = "<64 hex>"

[[peers]]
id = "<64 hex relay id>"
addr = "203.0.113.10:9000"
link_key = "<64 hex legacy PSK; unused for Noise AEAD, may seed lab statics>"
noise_static_public = "<64 hex peer static public>"
```

Force LegacyPsk (never Noise):

```toml
[link]
handshake = "legacy_psk"
```

Force Noise (fails config load without local secret):

```toml
[link]
handshake = "noise"
noise_static_secret = "<64 hex local static secret>"
```

## Wire sizes (Noise)

| Message | Bytes |
|---------|------:|
| Initiator → responder (msg1) | 96 |
| Responder → initiator (msg2) | 48 |

After handshake, both sides share one `LinkKey` and use the existing 580-byte ChaCha20-Poly1305 cell frames. Ingress rate-limit, peer-health, weighted fair inbound queues, and drop-newest policy are unchanged.

## Verification rules

1. Initiator must supply the **responder** static public that matches the peer’s configured secret.
2. Responder decrypts the initiator static from msg1 and accepts only if it matches `noise_static_public` (peer table) or ingress expectation.
3. Wrong static ⇒ AEAD / identity failure (`IntegrityFailure` or `UnidentifiedInbound`); no session key.

## Residual

- Handshake is standard Noise IK on the wire; **AEGIS `LinkKey`** still uses a SHA3-256 domain mix on the handshake hash (cell frames are not raw Noise transport).
- Ingress still admits any holder of the configured ingress static (or derived ingress key).
- Static secrets remain operator-distributed (config / roster); no PKI ceremony in this crate.
- Auto without keys (or explicit `legacy_psk`) remains LegacyPsk for existing deployments.
- Pre-`snow` SHA3 peers (80-byte msg1) require explicit migration; see `noise-link-legacy-sha3`.
