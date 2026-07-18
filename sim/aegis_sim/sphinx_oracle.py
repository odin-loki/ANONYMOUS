"""
Bit-level Sphinx build/peel oracle matching ``aegis-crypto`` ``sphinx.rs``.

Coverage vs Rust (honest matrix — not a formal proof):

| Primitive / step                         | Python oracle | Rust owner        | Cross-check |
|------------------------------------------|---------------|-------------------|-------------|
| Packet layout constants                  | Yes           | ``sphinx.rs``     | Unit tests  |
| SHA3-256 stream XOR (beta / delta)       | Yes           | ``stream_xor_range`` | Shared hex KATs |
| Peel-pad stream                          | Yes           | ``peel_pad``      | Shared hex KATs |
| Gamma MAC / verify                       | Yes           | ``compute_mac``   | Shared hex KATs |
| Replay tag                               | Yes           | ``replay_tag``    | Shared hex KATs + public Rust API |
| Peel (shift + alpha/gamma/delta update)  | Yes           | ``peel``          | Self-roundtrip + Rust process |
| Build from secrets+headers               | Yes           | ``build`` body    | Self-roundtrip |
| Hybrid KEM encap/decap (X25519+ML-KEM)   | **No**        | ``kem.rs``        | Rust ``vectors.rs`` only |
| ReplayCache CT membership / eviction     | Minimal set   | ``replay.rs``     | Rust unit tests |
| ``blind_next`` Montgomery blinding       | **No**        | ``kem.rs``        | Unused on peel path today |

Oracle ``build_packet`` takes per-hop shared secrets and KEM header bytes as
inputs (Rust ``encapsulate`` is out of scope). This is an independent
reimplementation for regression / tagging analysis — **not** a mechanized proof.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

# --- layout (must match crates/aegis-crypto/src/sphinx.rs) -----------------
MAX_HOPS = 6
KEM_HEADER_LEN = 1120  # 32 + 1088
ROUTING_SLOT_LEN = 32 + KEM_HEADER_LEN + 32  # 1184
ALPHA_LEN = KEM_HEADER_LEN
BETA_LEN = MAX_HOPS * ROUTING_SLOT_LEN  # 7104
GAMMA_LEN = 32
DELTA_LEN = 256
SPHINX_PACKET_LEN = ALPHA_LEN + BETA_LEN + GAMMA_LEN + DELTA_LEN  # 8504

OFF_ALPHA = 0
OFF_BETA = ALPHA_LEN
OFF_GAMMA = OFF_BETA + BETA_LEN
OFF_DELTA = OFF_GAMMA + GAMMA_LEN

STREAM_BETA = b"aegis-beta-stream-v1"
STREAM_DELTA = b"aegis-delta-stream-v1"
MAC_DOMAIN = b"aegis-gamma-mac-v1"
REPLAY_DOMAIN = b"aegis-replay-tag-v1"
PEEL_PAD_DOMAIN = b"aegis-beta-peel-pad-v1"


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def stream_xor(buf: bytearray, start: int, end: int, secret: bytes, domain: bytes) -> None:
    """In-place SHA3-256 counter stream XOR — matches Rust ``stream_xor_range``."""
    if len(secret) != 32:
        raise ValueError("secret must be 32 bytes")
    counter = 0
    pos = start
    while pos < end:
        block = sha3_256(domain + secret + counter.to_bytes(8, "little"))
        for byte in block:
            if pos >= end:
                break
            buf[pos] ^= byte
            pos += 1
        counter += 1


def peel_pad(secret: bytes, length: int = ROUTING_SLOT_LEN) -> bytes:
    """Deterministic beta tail pad — matches Rust ``peel_pad``."""
    if len(secret) != 32:
        raise ValueError("secret must be 32 bytes")
    out = bytearray(length)
    counter = 0
    pos = 0
    while pos < length:
        block = sha3_256(PEEL_PAD_DOMAIN + secret + counter.to_bytes(8, "little"))
        for byte in block:
            if pos >= length:
                break
            out[pos] = byte
            pos += 1
        counter += 1
    return bytes(out)


def compute_mac(secret: bytes, beta: bytes) -> bytes:
    if len(secret) != 32:
        raise ValueError("secret must be 32 bytes")
    if len(beta) != BETA_LEN:
        raise ValueError(f"beta must be {BETA_LEN} bytes")
    return sha3_256(MAC_DOMAIN + secret + beta)


def verify_mac(secret: bytes, packet: bytes) -> bool:
    if len(packet) != SPHINX_PACKET_LEN:
        raise ValueError("bad packet length")
    expected = compute_mac(secret, packet[OFF_BETA:OFF_GAMMA])
    actual = packet[OFF_GAMMA:OFF_DELTA]
    # Constant-time-ish compare for tests (not claiming CT).
    acc = 0
    for a, b in zip(expected, actual):
        acc |= a ^ b
    return acc == 0


def replay_tag(secret: bytes) -> bytes:
    if len(secret) != 32:
        raise ValueError("secret must be 32 bytes")
    return sha3_256(REPLAY_DOMAIN + secret)


def _encrypt_slots(beta: bytearray, layers: int, secrets: Sequence[bytes]) -> None:
    for i in range(layers):
        off = i * ROUTING_SLOT_LEN
        stream_xor(beta, off, off + ROUTING_SLOT_LEN, secrets[i], STREAM_BETA)


def _decrypt_slots(beta: bytearray, layers: int, secrets: Sequence[bytes]) -> None:
    # Stream XOR is involutive.
    _encrypt_slots(beta, layers, secrets)


def _mac_after_peels(beta: bytes, secrets: Sequence[bytes], peels: int) -> bytes:
    work = bytearray(beta)
    for h in range(peels):
        stream_xor(work, 0, ROUTING_SLOT_LEN, secrets[h], STREAM_BETA)
        work[: BETA_LEN - ROUTING_SLOT_LEN] = work[ROUTING_SLOT_LEN:BETA_LEN]
        pad = peel_pad(secrets[h], ROUTING_SLOT_LEN)
        work[BETA_LEN - ROUTING_SLOT_LEN : BETA_LEN] = pad
    return compute_mac(secrets[peels], bytes(work))


@dataclass
class PeelResult:
    next_hop: bytes
    packet: bytes


def peel(packet: bytes, secret: bytes) -> PeelResult:
    """One hop peel — matches Rust ``peel`` (no KEM / replay)."""
    if len(packet) != SPHINX_PACKET_LEN:
        raise ValueError("bad packet length")
    if len(secret) != 32:
        raise ValueError("secret must be 32 bytes")

    out = bytearray(packet)
    stream_xor(out, OFF_BETA, OFF_BETA + ROUTING_SLOT_LEN, secret, STREAM_BETA)

    next_hop = bytes(out[OFF_BETA : OFF_BETA + 32])
    next_header = bytes(out[OFF_BETA + 32 : OFF_BETA + 32 + KEM_HEADER_LEN])
    next_gamma = bytes(
        out[
            OFF_BETA + 32 + KEM_HEADER_LEN : OFF_BETA
            + 32
            + KEM_HEADER_LEN
            + GAMMA_LEN
        ]
    )

    # Shift beta left by one routing slot; pad tail.
    tail_start = OFF_BETA + ROUTING_SLOT_LEN
    out[OFF_BETA : OFF_BETA + BETA_LEN - ROUTING_SLOT_LEN] = out[
        tail_start : OFF_BETA + BETA_LEN
    ]
    pad = peel_pad(secret, ROUTING_SLOT_LEN)
    out[OFF_BETA + BETA_LEN - ROUTING_SLOT_LEN : OFF_BETA + BETA_LEN] = pad

    out[OFF_ALPHA : OFF_ALPHA + ALPHA_LEN] = next_header
    out[OFF_GAMMA : OFF_GAMMA + GAMMA_LEN] = next_gamma
    stream_xor(out, OFF_DELTA, OFF_DELTA + DELTA_LEN, secret, STREAM_DELTA)

    return PeelResult(next_hop=next_hop, packet=bytes(out))


def process_oracle(
    packet: bytes,
    secret: bytes,
    seen_tags: Optional[set] = None,
) -> PeelResult:
    """MAC → replay-tag → peel (oracle stand-in for Rust ``process`` minus KEM)."""
    if not verify_mac(secret, packet):
        raise ValueError("IntegrityFailure")
    tag = replay_tag(secret)
    if seen_tags is not None:
        if tag in seen_tags:
            raise ValueError("Replay")
        seen_tags.add(tag)
    return peel(packet, secret)


def build_packet(
    hop_ids: Sequence[bytes],
    headers: Sequence[bytes],
    secrets: Sequence[bytes],
    payload: bytes,
    *,
    beta_fill: bytes,
    delta_pad: bytes,
) -> bytes:
    """
    Build a Sphinx packet from materials (secrets + headers already chosen).

    Matches Rust ``build`` after encapsulation: routing-slot fill, inside-out
    next-gamma embedding, beta stream encryption, delta onion, hop-0 MAC.
    """
    n = len(hop_ids)
    if n < 2 or n > MAX_HOPS:
        raise ValueError("path length")
    if not (len(headers) == len(secrets) == n):
        raise ValueError("headers/secrets/hop_ids length mismatch")
    if any(len(h) != 32 for h in hop_ids):
        raise ValueError("hop id must be 32 bytes")
    if any(len(h) != KEM_HEADER_LEN for h in headers):
        raise ValueError("kem header length")
    if any(len(s) != 32 for s in secrets):
        raise ValueError("secret length")
    if len(payload) > DELTA_LEN:
        raise ValueError("payload too long")
    if len(beta_fill) != BETA_LEN:
        raise ValueError("beta_fill length")
    if len(delta_pad) != DELTA_LEN - len(payload):
        raise ValueError("delta_pad length")

    layers = n - 1
    beta = bytearray(beta_fill)

    # Pass 1: routing slots (next_gamma placeholder = whatever is in fill / zeros).
    for i in range(layers):
        off = i * ROUTING_SLOT_LEN
        beta[off : off + 32] = hop_ids[i + 1]
        beta[off + 32 : off + 32 + KEM_HEADER_LEN] = headers[i + 1]
        # Leave gamma field as in beta_fill (Rust leaves RNG bytes until embed).

    _encrypt_slots(beta, layers, secrets[:layers])
    _decrypt_slots(beta, layers, secrets[:layers])

    next_gammas: List[bytes] = [bytes(GAMMA_LEN) for _ in range(layers)]
    for i in range(layers - 1, -1, -1):
        for j in range(i + 1, layers):
            off = j * ROUTING_SLOT_LEN + 32 + KEM_HEADER_LEN
            beta[off : off + GAMMA_LEN] = next_gammas[j]
        _encrypt_slots(beta, layers, secrets[:layers])
        next_gammas[i] = _mac_after_peels(bytes(beta), secrets, i + 1)
        _decrypt_slots(beta, layers, secrets[:layers])

    for i in range(layers):
        off = i * ROUTING_SLOT_LEN + 32 + KEM_HEADER_LEN
        beta[off : off + GAMMA_LEN] = next_gammas[i]
    _encrypt_slots(beta, layers, secrets[:layers])

    gamma = compute_mac(secrets[0], bytes(beta))

    delta = bytearray(DELTA_LEN)
    delta[: len(payload)] = payload
    delta[len(payload) :] = delta_pad
    for sec in secrets:
        stream_xor(delta, 0, DELTA_LEN, sec, STREAM_DELTA)

    packet = bytearray(SPHINX_PACKET_LEN)
    packet[OFF_ALPHA : OFF_ALPHA + ALPHA_LEN] = headers[0]
    packet[OFF_BETA:OFF_GAMMA] = beta
    packet[OFF_GAMMA:OFF_DELTA] = gamma
    packet[OFF_DELTA:] = delta
    return bytes(packet)


def multi_peel(
    packet: bytes, secrets: Sequence[bytes], hops: int
) -> Tuple[List[bytes], bytes]:
    """Peel ``hops`` times; return list of next_hop ids and final packet."""
    current = packet
    next_hops: List[bytes] = []
    for i in range(hops):
        result = peel(current, secrets[i])
        next_hops.append(result.next_hop)
        current = result.packet
    return next_hops, current


def extract_delta(packet: bytes) -> bytes:
    if len(packet) != SPHINX_PACKET_LEN:
        raise ValueError("bad packet length")
    return packet[OFF_DELTA:]


def coverage_matrix() -> list[dict]:
    """Machine-readable coverage matrix for docs / tests."""
    return [
        {"item": "layout_constants", "python": True, "rust": "sphinx.rs", "kat": True},
        {"item": "stream_xor_beta_delta", "python": True, "rust": "sphinx.rs", "kat": True},
        {"item": "peel_pad", "python": True, "rust": "sphinx.rs", "kat": True},
        {"item": "gamma_mac", "python": True, "rust": "sphinx.rs", "kat": True},
        {"item": "replay_tag", "python": True, "rust": "sphinx.rs", "kat": True},
        {"item": "peel", "python": True, "rust": "sphinx.rs", "kat": "self+rust_process"},
        {"item": "build_from_secrets", "python": True, "rust": "sphinx.rs", "kat": "self"},
        {"item": "hybrid_kem", "python": False, "rust": "kem.rs", "kat": "rust_only"},
        {"item": "replay_cache", "python": "minimal", "rust": "replay.rs", "kat": "rust_only"},
        {"item": "blind_next", "python": False, "rust": "kem.rs", "kat": "unused_on_peel"},
    ]
