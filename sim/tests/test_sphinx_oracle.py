"""
Sphinx P1 Python bit-oracle tests (wave S1).

Cross-checks ``aegis_sim.sphinx_oracle`` against algorithms in
``crates/aegis-crypto/src/sphinx.rs``. Shared hex KATs are also asserted from
Rust ``sphinx`` unit tests. Hybrid KEM is out of scope here (Rust-only).

Not a formal proof — independent reimplementation + property gates only.

Run:  cd sim && PYTHONPATH=. pytest -q tests/test_sphinx_oracle.py
"""

from __future__ import annotations

import pytest

from aegis_sim.sphinx_oracle import (
    ALPHA_LEN,
    BETA_LEN,
    DELTA_LEN,
    GAMMA_LEN,
    KEM_HEADER_LEN,
    MAX_HOPS,
    OFF_ALPHA,
    OFF_BETA,
    OFF_DELTA,
    OFF_GAMMA,
    ROUTING_SLOT_LEN,
    SPHINX_PACKET_LEN,
    STREAM_BETA,
    STREAM_DELTA,
    build_packet,
    compute_mac,
    coverage_matrix,
    extract_delta,
    peel,
    peel_pad,
    process_oracle,
    replay_tag,
    stream_xor,
    verify_mac,
)

# Shared hex KATs with crates/aegis-crypto/src/sphinx.rs cfg(test) module.
_SECRET_KAT = bytes([0x11] * 32)
_STREAM_BETA_64_HEX = (
    "886a1434c58d443366682cfbdd777266c5b9dd2f409cc6b67fe43403bcba5d8a"
    "e3da3a10e08f5e33982f8ed5c555cf6022fc7b92f4a7cc307af48092be68dd56"
)
_PEEL_PAD_PREFIX_HEX = "41834555fdf93e922994c7d9c4404b02530a44cc9eeda1827e378500f4866102"
_MAC_HEX = "1e774cf257309c85b558ef27eac3b412ef792a55bce151e10390e1db22f9f3cc"
_REPLAY_HEX = "261d037ead23e8bc7a092e7f3623ea4c78607f6f9a4409702a1f0eb5a86183ac"


def _beta_kat() -> bytes:
    return bytes((i * 17) % 256 for i in range(BETA_LEN))


def _materials(n: int, *, seed: int = 0):
    ids = [bytes([((seed + i + 1) & 0xFF)]) + bytes(31) for i in range(n)]
    headers = [
        bytes([((0xA0 + seed + i) & 0xFF)]) + bytes(KEM_HEADER_LEN - 1) for i in range(n)
    ]
    secrets = [bytes([((0x20 + seed + i) & 0xFF)]) + bytes(31) for i in range(n)]
    beta_fill = bytes([((i * 3 + seed) % 256) for i in range(BETA_LEN)])
    return ids, headers, secrets, beta_fill


def test_layout_constants_match_rust_formula():
    assert KEM_HEADER_LEN == 1120
    assert ROUTING_SLOT_LEN == 1184
    assert BETA_LEN == MAX_HOPS * ROUTING_SLOT_LEN == 7104
    # Doc comments historically said 8504; formula is 8512.
    assert SPHINX_PACKET_LEN == ALPHA_LEN + BETA_LEN + GAMMA_LEN + DELTA_LEN == 8512


def test_shared_hex_kats_stream_mac_replay_pad():
    buf = bytearray(range(64))
    stream_xor(buf, 0, 64, _SECRET_KAT, STREAM_BETA)
    assert buf.hex() == _STREAM_BETA_64_HEX

    pad = peel_pad(_SECRET_KAT)
    assert len(pad) == ROUTING_SLOT_LEN
    assert pad[:32].hex() == _PEEL_PAD_PREFIX_HEX

    assert compute_mac(_SECRET_KAT, _beta_kat()).hex() == _MAC_HEX
    assert replay_tag(_SECRET_KAT).hex() == _REPLAY_HEX


def test_stream_xor_is_involutive():
    buf = bytearray(b"abcdefghijklmnopqrstuvwxyz0123456789ABCD")
    orig = bytes(buf)
    stream_xor(buf, 0, len(buf), _SECRET_KAT, STREAM_DELTA)
    stream_xor(buf, 0, len(buf), _SECRET_KAT, STREAM_DELTA)
    assert bytes(buf) == orig


@pytest.mark.parametrize("n", list(range(2, MAX_HOPS + 1)))
def test_build_peel_roundtrip_all_path_lengths(n: int):
    ids, headers, secrets, beta_fill = _materials(n)
    payload = bytes([n]) * min(32, DELTA_LEN)
    delta_pad = bytes([0x5A] * (DELTA_LEN - len(payload)))
    pkt = build_packet(
        ids, headers, secrets, payload, beta_fill=beta_fill, delta_pad=delta_pad
    )
    assert len(pkt) == SPHINX_PACKET_LEN
    assert verify_mac(secrets[0], pkt)

    current = pkt
    for hop in range(n - 1):
        assert verify_mac(secrets[hop], current)
        result = peel(current, secrets[hop])
        assert result.next_hop == ids[hop + 1]
        assert len(result.packet) == SPHINX_PACKET_LEN
        current = result.packet

    # Exit hop MAC still verifies; payload recovered after all secrets peeled.
    assert verify_mac(secrets[n - 1], current)
    current = peel(current, secrets[n - 1]).packet
    assert extract_delta(current)[: len(payload)] == payload


def test_process_oracle_replay_rejected():
    ids, headers, secrets, beta_fill = _materials(2)
    payload = b"replay"
    delta_pad = bytes([0] * (DELTA_LEN - len(payload)))
    pkt = build_packet(
        ids, headers, secrets, payload, beta_fill=beta_fill, delta_pad=delta_pad
    )
    seen: set = set()
    process_oracle(pkt, secrets[0], seen)
    with pytest.raises(ValueError, match="Replay"):
        process_oracle(pkt, secrets[0], seen)


def test_tagging_beta_bit_flips_fail_mac():
    ids, headers, secrets, beta_fill = _materials(4, seed=7)
    pkt = build_packet(
        ids,
        headers,
        secrets,
        b"tag",
        beta_fill=beta_fill,
        delta_pad=bytes([1] * (DELTA_LEN - 3)),
    )
    offsets = [
        0,
        31,
        32,
        ROUTING_SLOT_LEN - 1,
        ROUTING_SLOT_LEN,
        ROUTING_SLOT_LEN + 32,
        BETA_LEN // 2,
        BETA_LEN - 1,
    ]
    for off in offsets:
        tampered = bytearray(pkt)
        tampered[OFF_BETA + off] ^= 0x01
        assert not verify_mac(secrets[0], bytes(tampered)), f"beta off={off}"


def test_tagging_gamma_flip_fails_mac():
    ids, headers, secrets, beta_fill = _materials(3)
    pkt = build_packet(
        ids,
        headers,
        secrets,
        b"g",
        beta_fill=beta_fill,
        delta_pad=bytes([2] * (DELTA_LEN - 1)),
    )
    tampered = bytearray(pkt)
    tampered[OFF_GAMMA] ^= 0x01
    assert not verify_mac(secrets[0], bytes(tampered))


def test_delta_flip_does_not_fail_hop0_mac():
    """Gamma covers beta only — delta tamper is a documented integrity gap at hop-0."""
    ids, headers, secrets, beta_fill = _materials(3)
    pkt = build_packet(
        ids,
        headers,
        secrets,
        b"d",
        beta_fill=beta_fill,
        delta_pad=bytes([3] * (DELTA_LEN - 1)),
    )
    tampered = bytearray(pkt)
    tampered[OFF_DELTA] ^= 0x01
    assert verify_mac(secrets[0], bytes(tampered))
    # Peel still succeeds; payload corrupted.
    peeled = peel(bytes(tampered), secrets[0])
    assert peeled.next_hop == ids[1]


def test_wrong_hop_secret_fails_mac():
    ids, headers, secrets, beta_fill = _materials(4)
    pkt = build_packet(
        ids,
        headers,
        secrets,
        b"wrong",
        beta_fill=beta_fill,
        delta_pad=bytes([4] * (DELTA_LEN - 5)),
    )
    assert not verify_mac(secrets[2], pkt)
    with pytest.raises(ValueError, match="IntegrityFailure"):
        process_oracle(pkt, secrets[2])


def test_path_length_rejected():
    ids, headers, secrets, beta_fill = _materials(2)
    with pytest.raises(ValueError, match="path length"):
        build_packet(
            ids[:1],
            headers[:1],
            secrets[:1],
            b"x",
            beta_fill=beta_fill,
            delta_pad=bytes(DELTA_LEN - 1),
        )
    ids7, hdr7, sec7, bf = _materials(MAX_HOPS)
    # Force 7 hops by extending
    ids7 = list(ids7) + [bytes([9]) + bytes(31)]
    hdr7 = list(hdr7) + [bytes([0xFF]) + bytes(KEM_HEADER_LEN - 1)]
    sec7 = list(sec7) + [bytes([0x99]) + bytes(31)]
    with pytest.raises(ValueError, match="path length"):
        build_packet(
            ids7,
            hdr7,
            sec7,
            b"x",
            beta_fill=bf,
            delta_pad=bytes(DELTA_LEN - 1),
        )


def test_bit_flip_map_regions():
    """Adversarial map: which region flips break hop-0 MAC."""
    ids, headers, secrets, beta_fill = _materials(3, seed=3)
    pkt = build_packet(
        ids,
        headers,
        secrets,
        b"map",
        beta_fill=beta_fill,
        delta_pad=bytes([9] * (DELTA_LEN - 3)),
    )
    # Sample one byte per major region.
    regions = {
        "alpha": OFF_ALPHA,
        "beta0": OFF_BETA,
        "beta_mid": OFF_BETA + ROUTING_SLOT_LEN,
        "gamma": OFF_GAMMA,
        "delta": OFF_DELTA,
    }
    expect_fail = {"alpha": False, "beta0": True, "beta_mid": True, "gamma": True, "delta": False}
    # Alpha flip does not change gamma MAC over beta — MAC still verifies.
    # (Rust process may still fail KEM/decap/malformed; oracle MAC-only.)
    for name, off in regions.items():
        t = bytearray(pkt)
        t[off] ^= 0x80
        failed = not verify_mac(secrets[0], bytes(t))
        assert failed is expect_fail[name], f"{name}: fail={failed}"


def test_coverage_matrix_lists_kem_gap():
    rows = {r["item"]: r for r in coverage_matrix()}
    assert rows["hybrid_kem"]["python"] is False
    assert rows["gamma_mac"]["python"] is True
    assert rows["build_from_secrets"]["python"] is True
