"""Anonymity / traffic metrics used across the suite."""
import numpy as np


def hurst(x):
    """Rough Hurst exponent via variance-of-aggregated-series.
    ~0.5 = short-range dependent (Poisson-like); ->1 = self-similar / LRD."""
    x = np.asarray(x, float)
    x = x - x.mean()
    N = len(x)
    ms = np.array([1, 2, 4, 8, 16, 32, 64])
    var = []
    for m in ms:
        k = N // m
        var.append(x[:k * m].reshape(k, m).mean(axis=1).var())
    slope = np.polyfit(np.log(ms), np.log(np.array(var) + 1e-12), 1)[0]
    return (slope + 2) / 2


def bulk_size_ceiling(cover_bytes_per_s, round_period_s, c_flows=8, avg_real=3):
    """Confirmation-resistant file-size ceiling: F_max = cover_budget * T / slack."""
    return cover_bytes_per_s * round_period_s / max(c_flows - avg_real, 1)


# ---------------------------------------------------------------------------
# Phase 8 (hardening): honest shapeability characterization for a given trace.
# ---------------------------------------------------------------------------
def shapeability_report(counts, budget_slots=5.0, hi=6.0):
    """Summarize the cost-to-shape for an arbitrary count series (real or
    synthetic). Ties together traffic.cv, shaper.min_multiple and hurst so a
    single call gives the honest per-trace characterization the spec's
    epsilon-per-tier language (§8, §10 Phase 8 gate) asks for.

    Returns a dict: cv, hurst, min_multiple (None if unshapeable at c<=hi),
    and a coarse `tier` label ('cheap' | 'feasible' | 'unshapeable') per the
    §6 cost-by-CV rule of thumb (CV<=1 cheap; 1<CV<=~2.5 feasible; else costly
    /unshapeable).
    """
    from . import shaper, traffic as _traffic  # local import: avoid cycle at module load

    x = np.asarray(counts, float)
    c = _traffic.cv(x)
    h = hurst(x) if len(x) >= 128 else float("nan")
    m = shaper.min_multiple(x, budget_slots=budget_slots, hi=hi)
    if c <= 1.0:
        tier = "cheap"
    elif c <= 2.5:
        tier = "feasible"
    else:
        tier = "unshapeable"
    return dict(cv=c, hurst=h, min_multiple=m, tier=tier)


def characterize_trace_file(
    path,
    *,
    slot_seconds=1.0,
    budget_slots=5.0,
    hi=6.0,
    source_label="operator_trace",
    is_operational=False,
):
    """Ingest a timestamp or slot-count CSV and return an honest shapeability report.

    Additive helper for future WAN / operational drops. Set `is_operational=True`
    only when the file is a genuine redacted operational capture (never for
    synthetic stress outputs).
    """
    from pathlib import Path

    from . import traffic as _traffic

    p = Path(path)
    # Heuristic: prefer timestamps when values look like an event timeline
    # (epoch-scale, or strictly increasing); else treat as pre-binned counts.
    text = p.read_text(encoding="utf-8")
    sample_lines = [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ][:40]
    use_counts = False
    if sample_lines:
        first_fields: list[float] = []
        headerish = False
        for ln in sample_lines:
            parts = [x.strip() for x in ln.split(",")]
            try:
                first_fields.append(float(parts[0]))
            except ValueError:
                if parts[0].lower().startswith("timestamp") or parts[0].lower() == "time":
                    headerish = True
                continue
        if first_fields:
            epochish = any(v >= 1e6 for v in first_fields)
            strictly_increasing = len(first_fields) >= 3 and all(
                first_fields[i] < first_fields[i + 1] for i in range(len(first_fields) - 1)
            )
            looks_like_timestamps = headerish or epochish or strictly_increasing
            use_counts = not looks_like_timestamps

    if use_counts:
        counts = _traffic.load_slot_count_csv(p)
        ingest = "slot_count_csv"
    else:
        events = _traffic.load_timestamp_csv(p)
        counts = _traffic.load_trace_counts(events, slot_seconds=slot_seconds)
        ingest = "timestamp_csv"

    report = shapeability_report(counts, budget_slots=budget_slots, hi=hi)
    report.update(
        dict(
            path=str(p),
            ingest=ingest,
            n_slots=int(len(counts)),
            source_label=source_label,
            is_operational=bool(is_operational),
            disclaimer=(
                "Operational C2 evidence"
                if is_operational
                else "Non-operational / pipeline characterization — not evidence about real C2."
            ),
        )
    )
    return report


def characterize_synthetic_stress_suite(n_slots=20000, budget_slots=5.0, hi=6.0, rng=None):
    """Run `shapeability_report` on the labeled synthetic stress suite (NOT operational C2)."""
    from . import traffic as _traffic

    suite = _traffic.synthetic_c2_stress_suite(n_slots=n_slots, rng=rng)
    reports = {}
    for name, series in suite["series"].items():
        r = shapeability_report(series, budget_slots=budget_slots, hi=hi)
        r["series_name"] = name
        r["is_operational"] = False
        reports[name] = r
    return {
        "label": suite["label"],
        "disclaimer": suite["disclaimer"],
        "is_operational": False,
        "n_slots": n_slots,
        "reports": reports,
    }
