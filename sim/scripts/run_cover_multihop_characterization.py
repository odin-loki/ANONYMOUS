#!/usr/bin/env python3
"""Emit multi-hop cover semantic-gap artifact under sim/data/ (partial; not a proof)."""
from __future__ import annotations

import argparse
from pathlib import Path

from aegis_sim import cover_multihop

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "sim" / "data" / "cover_multihop_characterization.json"


def main() -> None:
    p = argparse.ArgumentParser(
        description=(
            "Partial multi-hop semantic-gap characterization "
            "(cover discard / invalid onion vs Sphinx forwards)."
        )
    )
    p.add_argument("--n-hops", type=int, default=3)
    p.add_argument("--n-sends", type=int, default=4)
    p.add_argument("--tau-secs", type=float, default=0.35)
    p.add_argument("--cover-secs", type=float, default=2.0)
    p.add_argument("--relay-cover-bursts", type=int, default=1)
    p.add_argument("--invalid-packets-per-send", type=int, default=1)
    p.add_argument("--burst-n-sends", type=int, default=6)
    p.add_argument("--burst-relay-cover-bursts", type=int, default=3)
    p.add_argument("-o", "--output", type=Path, default=DEFAULT_OUT)
    args = p.parse_args()

    bundle = cover_multihop.full_multihop_characterization_bundle(
        n_hops=args.n_hops,
        n_sends=args.n_sends,
        tau_secs=args.tau_secs,
        cover_secs=args.cover_secs,
        relay_cover_bursts_per_hop=args.relay_cover_bursts,
        invalid_packets_per_send=args.invalid_packets_per_send,
        burst_n_sends=args.burst_n_sends,
        burst_relay_cover_bursts=args.burst_relay_cover_bursts,
    )
    cover_multihop.write_multihop_artifact(args.output, bundle)
    d = bundle["delta"]
    print(f"wrote {args.output}")
    print(
        f"  semantic_gap_delta={d['cover_minus_sphinx_semantic_gap_score']:.4f} "
        f"continuity_ratio={d['continuity_ratio_cover_over_sphinx']:.4f} "
        f"cover_discard={d['cover_discard_fraction']:.4f}"
    )
    print("  claims_info_theoretic_indistinguishability=false")


if __name__ == "__main__":
    main()
