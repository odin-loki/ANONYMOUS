#!/usr/bin/env python3
"""Seed corpus for cargo-fuzz target fuzz_sphinx_process (wave S1).

Writes fixed-size / truncated / patterned inputs under
crates/aegis-crypto/fuzz/corpus/fuzz_sphinx_process/.

No Docker. Does not claim valid Sphinx packets for the harness key.
"""

from __future__ import annotations

from pathlib import Path

SPHINX_PACKET_LEN = 8512  # matches aegis-crypto sphinx.rs
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "crates" / "aegis-crypto" / "fuzz" / "corpus" / "fuzz_sphinx_process"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    seeds = {
        "empty.bin": b"",
        "zeros_full.bin": bytes(SPHINX_PACKET_LEN),
        "ones_full.bin": bytes([0xFF] * SPHINX_PACKET_LEN),
        "asc_mod256.bin": bytes(i % 256 for i in range(SPHINX_PACKET_LEN)),
        "short_64.bin": bytes(range(64)),
        "oversize_trimmed.bin": bytes([(i * 7) % 256 for i in range(SPHINX_PACKET_LEN + 128)]),
        "alpha_only_noise.bin": bytes([0xA5] * 1120) + bytes(SPHINX_PACKET_LEN - 1120),
    }
    for name, data in seeds.items():
        path = OUT / name
        path.write_bytes(data)
        print(f"wrote {path} ({len(data)} bytes)")
    print(f"seeded {len(seeds)} files -> {OUT}")


if __name__ == "__main__":
    main()
