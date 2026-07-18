#!/usr/bin/env python3
"""Seed corpus for cargo-fuzz target fuzz_sphinx_process (wave S1 / A6).

Writes fixed-size, truncated, boundary, and region-patterned inputs under
crates/aegis-crypto/fuzz/corpus/fuzz_sphinx_process/.

Layout constants match crates/aegis-crypto/src/sphinx.rs:
  alpha=1120 | beta=7104 | gamma=32 | delta=256 → SPHINX_PACKET_LEN=8512

No Docker. Seeds are not claimed to be valid Sphinx packets for the harness key.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

# Keep in sync with aegis-crypto sphinx.rs
ALPHA_LEN = 1120
BETA_LEN = 7104
GAMMA_LEN = 32
DELTA_LEN = 256
SPHINX_PACKET_LEN = ALPHA_LEN + BETA_LEN + GAMMA_LEN + DELTA_LEN  # 8512
ROUTING_SLOT_LEN = 32 + ALPHA_LEN + 32  # hop id + next KEM header + next gamma

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = (
    ROOT / "crates" / "aegis-crypto" / "fuzz" / "corpus" / "fuzz_sphinx_process"
)


def _full(fill: int = 0) -> bytearray:
    return bytearray([fill & 0xFF] * SPHINX_PACKET_LEN)


def _region(fill_alpha: int, fill_beta: int, fill_gamma: int, fill_delta: int) -> bytes:
    buf = _full(0)
    buf[:ALPHA_LEN] = bytes([fill_alpha & 0xFF] * ALPHA_LEN)
    buf[ALPHA_LEN : ALPHA_LEN + BETA_LEN] = bytes([fill_beta & 0xFF] * BETA_LEN)
    g0 = ALPHA_LEN + BETA_LEN
    buf[g0 : g0 + GAMMA_LEN] = bytes([fill_gamma & 0xFF] * GAMMA_LEN)
    d0 = g0 + GAMMA_LEN
    buf[d0 : d0 + DELTA_LEN] = bytes([fill_delta & 0xFF] * DELTA_LEN)
    return bytes(buf)


def _slot_markers() -> bytes:
    """Non-zero markers at each routing-slot boundary inside beta."""
    buf = _full(0)
    # Plausible-looking X25519-ish prefix in alpha (not a real point).
    buf[0] = 0x09
    for i in range(6):
        off = ALPHA_LEN + i * ROUTING_SLOT_LEN
        if off + 4 > ALPHA_LEN + BETA_LEN:
            break
        struct.pack_into("<I", buf, off, 0xAE615000 + i)
        # tag marker near end of slot (gamma placeholder region)
        g_off = off + ROUTING_SLOT_LEN - GAMMA_LEN
        if g_off + 4 <= ALPHA_LEN + BETA_LEN:
            struct.pack_into("<I", buf, g_off, 0x6A6A0000 + i)
    # Distinct gamma / delta bytes
    g0 = ALPHA_LEN + BETA_LEN
    buf[g0 : g0 + GAMMA_LEN] = bytes(range(GAMMA_LEN))
    buf[g0 + GAMMA_LEN :] = bytes((i * 3) % 256 for i in range(DELTA_LEN))
    return bytes(buf)


def build_seeds() -> dict[str, bytes]:
    seeds: dict[str, bytes] = {
        "empty.bin": b"",
        "zeros_full.bin": bytes(SPHINX_PACKET_LEN),
        "ones_full.bin": bytes([0xFF] * SPHINX_PACKET_LEN),
        "asc_mod256.bin": bytes(i % 256 for i in range(SPHINX_PACKET_LEN)),
        "short_64.bin": bytes(range(64)),
        "oversize_trimmed.bin": bytes(
            [(i * 7) % 256 for i in range(SPHINX_PACKET_LEN + 128)]
        ),
        "alpha_only_noise.bin": bytes([0xA5] * ALPHA_LEN)
        + bytes(SPHINX_PACKET_LEN - ALPHA_LEN),
        # Length / layout boundaries (harness pads/truncates to SPHINX_PACKET_LEN).
        "len_alpha_minus1.bin": bytes([0x11] * (ALPHA_LEN - 1)),
        "len_alpha.bin": bytes([0x22] * ALPHA_LEN),
        "len_alpha_beta.bin": bytes([0x33] * (ALPHA_LEN + BETA_LEN)),
        "len_minus_gamma.bin": bytes(
            [0x44] * (SPHINX_PACKET_LEN - GAMMA_LEN)
        ),
        "len_minus1.bin": bytes([0x55] * (SPHINX_PACKET_LEN - 1)),
        "len_plus1.bin": bytes([0x66] * (SPHINX_PACKET_LEN + 1)),
        # Region fills exercise peel/mac/delta paths with patterned headers.
        "region_alpha_ff.bin": _region(0xFF, 0x00, 0x00, 0x00),
        "region_beta_aa.bin": _region(0x00, 0xAA, 0x00, 0x00),
        "region_gamma_5a.bin": _region(0x00, 0x00, 0x5A, 0x00),
        "region_delta_c3.bin": _region(0x00, 0x00, 0x00, 0xC3),
        "region_all_distinct.bin": _region(0x01, 0x02, 0x03, 0x04),
        "slot_boundary_markers.bin": _slot_markers(),
        # Tiny / odd sizes often stress early parse branches.
        "tiny_1.bin": b"\x01",
        "tiny_32.bin": bytes(range(32)),
        "tiny_1120.bin": bytes((i * 13) % 256 for i in range(ALPHA_LEN)),
    }
    return seeds


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help=f"corpus directory (default: {DEFAULT_OUT})",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="print seed names/sizes without writing",
    )
    args = parser.parse_args()
    seeds = build_seeds()

    if args.list:
        for name, data in sorted(seeds.items()):
            print(f"{name}\t{len(data)}")
        print(f"total {len(seeds)} seeds; SPHINX_PACKET_LEN={SPHINX_PACKET_LEN}")
        return 0

    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    for name, data in seeds.items():
        path = out / name
        path.write_bytes(data)
        print(f"wrote {path} ({len(data)} bytes)")
    print(f"seeded {len(seeds)} files -> {out}")
    print(
        f"layout: alpha={ALPHA_LEN} beta={BETA_LEN} gamma={GAMMA_LEN} "
        f"delta={DELTA_LEN} total={SPHINX_PACKET_LEN}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
