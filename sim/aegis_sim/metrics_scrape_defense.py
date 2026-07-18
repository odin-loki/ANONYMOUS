"""
Metrics scrape defenses vs C5 baseline (productize wave A4/A5).

Tag: [O] QUANTIFIED Partial — ranks export-policy defenses that reduce scrape
timing/volume leakage vs the C5 1s Pearson baseline; **not closed**. Privileged
observers with raw ``coarse_stats`` / ``debug_stats`` remain a residual.

Defenses (map to ``aegis_relay::metrics_export``):
  baseline_c5_1s     — C5 flood scrape @ 1s (high Pearson)
  min_cadence        — enforce scrape interval ≥ 30s
  quantize           — floor deltas to bucket (default 16)
  suppress_drops     — omit IngressRateLimitStats.dropped_frames detail
  stacked            — cadence + quantize + suppress (production default)

Imports public APIs from ``metrics_sidechannel`` (does not rewrite that core).
"""
from __future__ import annotations

import copy
import json
import math
from pathlib import Path
from typing import Any, Literal

import numpy as np

from aegis_sim import metrics_sidechannel as ms

DefenseScheme = Literal[
    "baseline_c5_1s",
    "min_cadence",
    "quantize",
    "suppress_drops",
    "stacked",
]

CI_SCHEMES: tuple[DefenseScheme, ...] = (
    "baseline_c5_1s",
    "min_cadence",
    "quantize",
    "suppress_drops",
    "stacked",
)

# Match aegis_relay::metrics_export production defaults.
DEFAULT_MIN_CADENCE_SECS = 30.0
DEFAULT_QUANTIZE_BUCKET = 16
# Long enough for ≥10 scrapes at 30s cadence (Pearson needs ≥2 windows).
DEFAULT_DEFENSE_DURATION_SECS = 300.0
C5_BASELINE_SCRAPE_SECS = 1.0
C5_BASELINE_DURATION_SECS = 30.0

DISCLAIMER = (
    "Partial metrics-scrape *defense* ranking — not an info-theoretic leakage "
    "bound. Privileged observers with raw coarse_stats / debug_stats or "
    "allow_high_resolution bypass export harden. Volume residual can remain "
    "via quantized fail/queue buckets even when drops are suppressed."
)


def _nan_safe(x: float) -> float | None:
    if x is None:
        return None
    if isinstance(x, float) and (math.isnan(x) or math.isinf(x)):
        return None
    return float(x)


def _quantize_deltas(deltas: dict[str, list], bucket: int) -> dict[str, list]:
    out: dict[str, list] = {}
    b = max(0, int(bucket))
    for k, vals in deltas.items():
        arr = np.asarray(vals, dtype=float)
        if b > 1:
            arr = np.floor(arr / b) * b
        out[k] = arr.tolist()
    # Rebuild load proxy from components after transform.
    drop = np.asarray(out.get("dropped_frames", []), dtype=float)
    fail = np.asarray(out.get("processed_fail", []), dtype=float)
    queue = np.asarray(out.get("queue_dropped", []), dtype=float)
    if drop.size and fail.size and queue.size:
        out["load_proxy"] = (drop + fail + queue).tolist()
    return out


def _suppress_drop_deltas(deltas: dict[str, list]) -> dict[str, list]:
    out = {k: list(v) for k, v in deltas.items()}
    n = len(out.get("dropped_frames", []))
    out["dropped_frames"] = [0.0] * n
    fail = np.asarray(out.get("processed_fail", [0.0] * n), dtype=float)
    queue = np.asarray(out.get("queue_dropped", [0.0] * n), dtype=float)
    out["load_proxy"] = (fail + queue).tolist()
    return out


def apply_export_defense(
    series: dict[str, Any],
    scheme: DefenseScheme,
    *,
    quantize_bucket: int = DEFAULT_QUANTIZE_BUCKET,
) -> dict[str, Any]:
    """Transform an observer scrape series under a named export defense."""
    if scheme not in CI_SCHEMES:
        raise ValueError(f"unknown scheme {scheme!r}")
    out = copy.deepcopy(series)
    out["defense"] = scheme
    deltas = out["deltas"]

    if scheme == "baseline_c5_1s":
        return out
    if scheme == "min_cadence":
        # Cadence is applied at simulate time; series already uses long interval.
        return out
    if scheme == "quantize":
        out["deltas"] = _quantize_deltas(deltas, quantize_bucket)
        out["quantize_bucket"] = quantize_bucket
        return out
    if scheme == "suppress_drops":
        out["deltas"] = _suppress_drop_deltas(deltas)
        out["ingress_drop_detail_exported"] = False
        # Volume via drops is intentionally unavailable.
        out["totals"] = dict(out["totals"])
        out["totals"]["dropped_cells"] = 0.0
        out["final_ingress"] = {"dropped_frames": 0}
        return out
    if scheme == "stacked":
        out["deltas"] = _suppress_drop_deltas(
            _quantize_deltas(deltas, quantize_bucket)
        )
        out["quantize_bucket"] = quantize_bucket
        out["ingress_drop_detail_exported"] = False
        out["totals"] = dict(out["totals"])
        out["totals"]["dropped_cells"] = 0.0
        out["final_ingress"] = {"dropped_frames": 0}
        return out
    return out


def _fine_held_pearson(series: dict[str, Any], *, slot_secs: float = 0.05) -> float:
    """
    Hold scrape-window load_proxy onto a fine slot grid and correlate with
    fine-grained attack offer. Captures timing blur from coarser cadence that
    window-total Pearson can miss (coarse windows can still align with attack).
    """
    duration = float(series["duration_secs"])
    scrape_iv = float(series["scrape_interval_secs"])
    load = np.asarray(series["deltas"]["load_proxy"], dtype=float)
    gt = np.asarray(series["ground_truth_windows"]["attack_cells"], dtype=float)
    if load.size < 1:
        return float("nan")

    n_slots = max(1, int(round(duration / slot_secs)))
    held = np.zeros(n_slots, dtype=float)
    atk = np.zeros(n_slots, dtype=float)
    # Rebuild fine attack from window totals uniformly within each scrape window.
    for i in range(load.size):
        t0 = i * scrape_iv
        t1 = min(duration, (i + 1) * scrape_iv)
        i0 = min(n_slots - 1, max(0, int(round(t0 / slot_secs))))
        i1 = min(n_slots, max(i0 + 1, int(round(t1 / slot_secs))))
        held[i0:i1] = load[i]
        # Spread window attack mass uniformly across slots in the window.
        width = max(1, i1 - i0)
        atk[i0:i1] = gt[i] / width
    return ms._pearson(held, atk)  # noqa: SLF001 — shared helper


def defense_leakage(series: dict[str, Any]) -> dict[str, Any]:
    """Leakage scores plus fine-held timing Pearson for ranking."""
    leak = ms.leakage_metrics(series)
    fine_r = _fine_held_pearson(series)
    # Primary timing score: prefer drop Pearson when drops exported; else load.
    drops_exported = not (
        series.get("ingress_drop_detail_exported") is False
        or (
            abs(float(series["totals"].get("dropped_cells", 0.0))) < 1e-12
            and series.get("defense") in ("suppress_drops", "stacked")
        )
    )
    primary = leak["pearson_dropped_vs_attack"] if drops_exported else leak[
        "pearson_load_proxy_vs_attack"
    ]
    return {
        **leak,
        "fine_held_pearson_load_vs_attack": fine_r,
        "primary_pearson": primary,
        "drops_detail_exported": drops_exported,
        "scrape_interval_secs": float(series["scrape_interval_secs"]),
        "n_scrapes": len(series["scrape_times"]),
    }


def simulate_defense_series(
    scheme: DefenseScheme,
    *,
    duration_secs: float | None = None,
    scrape_interval_secs: float | None = None,
    quantize_bucket: int = DEFAULT_QUANTIZE_BUCKET,
    attack_cells_per_sec: float = 40.0,
    seed: int = 11,
) -> dict[str, Any]:
    """Simulate flood scrape under a defense scheme (cadence chosen at sim time)."""
    if scheme == "baseline_c5_1s":
        dur = C5_BASELINE_DURATION_SECS if duration_secs is None else duration_secs
        iv = C5_BASELINE_SCRAPE_SECS if scrape_interval_secs is None else scrape_interval_secs
    elif scheme in ("min_cadence", "stacked"):
        dur = DEFAULT_DEFENSE_DURATION_SECS if duration_secs is None else duration_secs
        iv = DEFAULT_MIN_CADENCE_SECS if scrape_interval_secs is None else scrape_interval_secs
    else:
        # quantize / suppress at C5 1s cadence for apples-to-apples vs baseline.
        dur = C5_BASELINE_DURATION_SECS if duration_secs is None else duration_secs
        iv = C5_BASELINE_SCRAPE_SECS if scrape_interval_secs is None else scrape_interval_secs

    raw = ms.simulate_scrape_series(
        "flood_attack",
        duration_secs=dur,
        scrape_interval_secs=iv,
        attack_cells_per_sec=attack_cells_per_sec,
        seed=seed,
    )
    return apply_export_defense(raw, scheme, quantize_bucket=quantize_bucket)


def characterize_defense(
    scheme: DefenseScheme,
    **kwargs: Any,
) -> dict[str, Any]:
    series = simulate_defense_series(scheme, **kwargs)
    leak = defense_leakage(series)
    return {
        "scheme": scheme,
        "duration_secs": series["duration_secs"],
        "scrape_interval_secs": series["scrape_interval_secs"],
        "final_coarse": series["final_coarse"],
        "final_ingress": series["final_ingress"],
        "totals": series["totals"],
        "leakage": {
            k: _nan_safe(v) if isinstance(v, float) else v for k, v in leak.items()
        },
    }


def _abs_or_inf(x: float | None) -> float:
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return 0.0  # no correlation ⇒ best for defender
    return abs(float(x))


def _rank_schemes(by_scheme: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    base = by_scheme["baseline_c5_1s"]["leakage"]
    rows = []
    for name, rep in by_scheme.items():
        leak = rep["leakage"]
        fine = leak.get("fine_held_pearson_load_vs_attack")
        primary = leak.get("primary_pearson")
        vol = leak.get("attack_volume_recoverable_via_drops") or 0.0
        rows.append(
            {
                "scheme": name,
                "scrape_interval_secs": rep["scrape_interval_secs"],
                "primary_pearson": _nan_safe(primary) if primary is not None else None,
                "fine_held_pearson_load_vs_attack": _nan_safe(fine)
                if fine is not None
                else None,
                "attack_volume_recoverable_via_drops": float(vol),
                "pearson_dropped_vs_attack": leak.get("pearson_dropped_vs_attack"),
                "pearson_load_proxy_vs_attack": leak.get("pearson_load_proxy_vs_attack"),
                "drops_detail_exported": leak.get("drops_detail_exported", True),
                "fine_held_reduction_vs_baseline": round(
                    _abs_or_inf(base.get("fine_held_pearson_load_vs_attack"))
                    - _abs_or_inf(fine),
                    6,
                ),
                "volume_reduction_vs_baseline": round(
                    float(base.get("attack_volume_recoverable_via_drops") or 0.0)
                    - float(vol),
                    6,
                ),
                "is_baseline": name == "baseline_c5_1s",
            }
        )
    # Best defense: lowest fine-held |r|, then lowest volume recoverable, then primary.
    rows.sort(
        key=lambda r: (
            0 if r["is_baseline"] else 1,  # baseline first for readability
            _abs_or_inf(r["fine_held_pearson_load_vs_attack"]),
            r["attack_volume_recoverable_via_drops"],
            _abs_or_inf(r["primary_pearson"]),
            r["scheme"],
        )
    )
    # Re-sort non-baseline by strength for ranking list (baseline pinned index 0).
    baseline_row = [r for r in rows if r["is_baseline"]]
    others = [r for r in rows if not r["is_baseline"]]
    others.sort(
        key=lambda r: (
            _abs_or_inf(r["fine_held_pearson_load_vs_attack"]),
            r["attack_volume_recoverable_via_drops"],
            _abs_or_inf(r["primary_pearson"]),
            r["scheme"],
        )
    )
    ranked = baseline_row + others
    for i, r in enumerate(ranked):
        r["rank"] = i  # 0 = baseline, 1 = best defense, ...
    return ranked


def _recommend(ranking: list[dict[str, Any]]) -> dict[str, Any]:
    by = {r["scheme"]: r for r in ranking}
    stacked = by.get("stacked")
    if stacked and (
        stacked["fine_held_reduction_vs_baseline"] > 0.02
        or stacked["volume_reduction_vs_baseline"] > 0.2
    ):
        return {
            "scheme": "stacked",
            "fine_held_pearson_load_vs_attack": stacked[
                "fine_held_pearson_load_vs_attack"
            ],
            "attack_volume_recoverable_via_drops": stacked[
                "attack_volume_recoverable_via_drops"
            ],
            "note": (
                "Recommend production `MetricsExportConfig` stacked defaults: "
                "min_scrape_interval=30s + quantize_bucket=16 + "
                "suppress_ingress_drop_detail. Maps to aegis-node [metrics]."
            ),
            "product_knobs": {
                "min_scrape_interval_secs": DEFAULT_MIN_CADENCE_SECS,
                "quantize_bucket": DEFAULT_QUANTIZE_BUCKET,
                "suppress_ingress_drop_detail": True,
                "allow_high_resolution": False,
            },
        }
    # Fallback: best non-baseline by fine-held reduction.
    candidates = [r for r in ranking if not r["is_baseline"]]
    if not candidates:
        return {"scheme": "baseline_c5_1s", "note": "no defenses evaluated"}
    best = min(
        candidates,
        key=lambda r: (
            _abs_or_inf(r["fine_held_pearson_load_vs_attack"]),
            r["attack_volume_recoverable_via_drops"],
        ),
    )
    return {
        "scheme": best["scheme"],
        "fine_held_pearson_load_vs_attack": best["fine_held_pearson_load_vs_attack"],
        "note": f"Best fine-held timing reduction in this run: {best['scheme']}",
    }


def metrics_scrape_defense_report(
    *,
    schemes: tuple[DefenseScheme, ...] = CI_SCHEMES,
    quantize_bucket: int = DEFAULT_QUANTIZE_BUCKET,
    attack_cells_per_sec: float = 40.0,
    seed: int = 11,
    include_c5_cross_check: bool = True,
) -> dict[str, Any]:
    """Rank scrape-export defenses; CI-safe deterministic defaults."""
    by_scheme: dict[str, dict[str, Any]] = {}
    for sch in schemes:
        by_scheme[sch] = characterize_defense(
            sch,
            quantize_bucket=quantize_bucket,
            attack_cells_per_sec=attack_cells_per_sec,
            seed=seed,
        )
    ranking = _rank_schemes(by_scheme)
    recommended = _recommend(ranking)
    base_leak = by_scheme["baseline_c5_1s"]["leakage"]
    out: dict[str, Any] = {
        "tag": "wave_A5_metrics_scrape_defense",
        "extends": "coverage_C5_metrics_sidechannel",
        "productizes": "wave_A4_metrics_export_gate",
        "disclaimer": DISCLAIMER,
        "claims_info_theoretic_leakage_bound": False,
        "characterizes_not_closes": True,
        "status": "[O] QUANTIFIED",
        "quantize_bucket": quantize_bucket,
        "schemes_evaluated": list(schemes),
        "by_scheme": by_scheme,
        "defense_ranking": ranking,
        "recommended": recommended,
        "delta_vs_c5_baseline": {
            "baseline_pearson_dropped_vs_attack": base_leak.get(
                "pearson_dropped_vs_attack"
            ),
            "baseline_fine_held_pearson": base_leak.get(
                "fine_held_pearson_load_vs_attack"
            ),
            "baseline_volume_recoverable_via_drops": base_leak.get(
                "attack_volume_recoverable_via_drops"
            ),
            "recommended_scheme": recommended["scheme"],
            "recommended_fine_held_pearson": (
                by_scheme[recommended["scheme"]]["leakage"].get(
                    "fine_held_pearson_load_vs_attack"
                )
                if recommended["scheme"] in by_scheme
                else None
            ),
            "recommended_volume_recoverable": (
                by_scheme[recommended["scheme"]]["leakage"].get(
                    "attack_volume_recoverable_via_drops"
                )
                if recommended["scheme"] in by_scheme
                else None
            ),
        },
        "honest_residuals": [
            "Privileged observers with RelayHandle::coarse_stats / debug_stats "
            "or metrics.allow_high_resolution=true bypass the export gate.",
            "Suppressing dropped_frames removes the strongest volume channel; "
            "processed_fail / queue_dropped buckets can still correlate under flood.",
            "Coarse scrape-window Pearson can stay high under long cadence when "
            "windows align with the attack block — fine-held Pearson is the "
            "timing-blur score used for ranking.",
            "Not an info-theoretic leakage bound; lab flood model only.",
        ],
        "sim_to_product": {
            "baseline_c5_1s": "Raw 1s scrape of coarse + ingress drop counters",
            "min_cadence": (
                "MetricsExportConfig.min_scrape_interval = 30s "
                "([metrics].min_scrape_interval_secs)"
            ),
            "quantize": (
                "MetricsExportConfig.quantize_bucket = 16 "
                "([metrics].quantize_bucket)"
            ),
            "suppress_drops": (
                "MetricsExportConfig.suppress_ingress_drop_detail = true"
            ),
            "stacked": "MetricsExportConfig::production() / [metrics] defaults",
            "mapping_doc": "docs/ops/metrics_scrape_defense.md",
        },
        "c5_public_api_ref": {
            "module": "aegis_sim.metrics_sidechannel",
            "artifact": "sim/data/metrics_sidechannel_characterization.json",
            "simulate": "simulate_scrape_series",
            "leakage": "leakage_metrics",
        },
    }
    if include_c5_cross_check:
        c5 = ms.simulate_scrape_series(
            "flood_attack",
            duration_secs=C5_BASELINE_DURATION_SECS,
            scrape_interval_secs=C5_BASELINE_SCRAPE_SECS,
            attack_cells_per_sec=attack_cells_per_sec,
            seed=seed,
        )
        c5_r = ms.leakage_metrics(c5)["pearson_dropped_vs_attack"]
        base_r = base_leak.get("pearson_dropped_vs_attack")
        out["c5_cross_check"] = {
            "c5_pearson_dropped_vs_attack": _nan_safe(c5_r),
            "a5_baseline_pearson_dropped_vs_attack": base_r,
            "match": (
                base_r is not None
                and c5_r == c5_r
                and abs(float(base_r) - float(c5_r)) < 1e-9
            ),
        }
    return out


def _json_sanitize(obj: Any) -> Any:
    if isinstance(obj, float):
        if obj != obj or obj in (float("inf"), float("-inf")):
            return None
        return obj
    if isinstance(obj, dict):
        return {k: _json_sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_sanitize(v) for v in obj]
    return obj


def write_metrics_scrape_defense_artifact(
    path: Path,
    report: dict[str, Any] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    report = report if report is not None else metrics_scrape_defense_report(**kwargs)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_json_sanitize(report), indent=2) + "\n", encoding="utf-8"
    )
    return report
