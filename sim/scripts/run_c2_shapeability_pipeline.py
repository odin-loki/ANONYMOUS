#!/usr/bin/env python3
"""C2 / WAN shapeability ingest pipeline (honest labels).

Modes:
  --synthetic-stress   Run the labeled NOT_OPERATIONAL_C2 stress suite.
  --trace PATH         Ingest a timestamp or slot-count CSV (operator drop-in).

Drop-in guide for real WAN / operational traces:
  1. Redact / export event timestamps (seconds) or pre-binned slot counts.
  2. Save as CSV under sim/data/ (or any path), e.g. sim/data/wan_ops_trace.csv
  3. Run:
       cd sim && PYTHONPATH=. python scripts/run_c2_shapeability_pipeline.py \\
         --trace data/wan_ops_trace.csv --operational --slot-seconds 1.0 -o data/wan_ops_trace.analysis.json
  4. Cite only artifacts with is_operational=true as operational evidence.
     Synthetic stress output must never be cited as real C2.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from aegis_sim import metrics

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SYNTH_OUT = ROOT / "sim" / "data" / "synthetic_c2_stress_shapeability.json"


def main() -> None:
    p = argparse.ArgumentParser(
        description="Shapeability ingest pipeline (synthetic stress or operator trace)."
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument(
        "--synthetic-stress",
        action="store_true",
        help="Run NOT_OPERATIONAL_C2 synthetic stress suite (pipeline test only).",
    )
    g.add_argument(
        "--trace",
        type=Path,
        help="Path to timestamp CSV or slot-count CSV to characterize.",
    )
    p.add_argument("--slot-seconds", type=float, default=1.0)
    p.add_argument("--budget-slots", type=float, default=5.0)
    p.add_argument("--hi", type=float, default=6.0)
    p.add_argument(
        "--operational",
        action="store_true",
        help="Mark ingest as genuine operational/WAN capture (never set for synthetic).",
    )
    p.add_argument(
        "--source-label",
        default="operator_trace",
        help="Label stored in the analysis JSON.",
    )
    p.add_argument("-o", "--output", type=Path, default=None)
    p.add_argument("--n-slots", type=int, default=20000, help="Synthetic suite length.")
    args = p.parse_args()

    if args.synthetic_stress:
        if args.operational:
            raise SystemExit("--operational is invalid with --synthetic-stress")
        result = metrics.characterize_synthetic_stress_suite(
            n_slots=args.n_slots,
            budget_slots=args.budget_slots,
            hi=args.hi,
        )
        out = args.output or DEFAULT_SYNTH_OUT
    else:
        result = metrics.characterize_trace_file(
            args.trace,
            slot_seconds=args.slot_seconds,
            budget_slots=args.budget_slots,
            hi=args.hi,
            source_label=args.source_label,
            is_operational=args.operational,
        )
        out = args.output or Path(str(args.trace) + ".analysis.json")

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    print(f"  is_operational={result.get('is_operational')}")
    print(f"  label/disclaimer: {result.get('label') or result.get('disclaimer')}")
    if "reports" in result:
        for name, r in result["reports"].items():
            print(f"  {name}: tier={r['tier']} cv={r['cv']:.3f}")
    else:
        print(f"  tier={result.get('tier')} cv={result.get('cv')}")


if __name__ == "__main__":
    main()
