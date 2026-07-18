# Metrics scrape defenses (wave A4 product + A5 sim)

**Status:** **[O] QUANTIFIED Partial** — ranked in-sim; product export gate shipped; **not closed**.

Extends coverage C5 (`metrics_sidechannel`) with export-policy defenses that reduce scrape timing/volume leakage vs the C5 1s Pearson≈0.97 baseline.

## Threat (short)

GPA or operator scrapes `RelayCoarseStats` / `IngressRateLimitStats` at high frequency. Flood windows correlate with scrape deltas (`dropped_frames`, load proxy). `debug_stats` must stay in-process.

## Product knobs (`[metrics]` / `MetricsExportConfig`)

| TOML field | Default | Effect |
|------------|---------|--------|
| `min_scrape_interval_secs` | `30` | Deny external exports faster than cadence |
| `quantize_bucket` | `16` | Floor counters to coarser buckets |
| `suppress_ingress_drop_detail` | `true` | Omit `dropped_frames` from export |
| `allow_high_resolution` | `false` | Lab opt-in: skip all harden |

Use `MetricsExportGate::export` (or `RelayHandle::export_coarse_stats` / `IngressRateLimitStats::export_dropped_frames`). Raw `coarse_stats()` / `dropped_frames()` bypass the gate (privileged residual).

```toml
[metrics]
min_scrape_interval_secs = 30
quantize_bucket = 16
suppress_ingress_drop_detail = true
allow_high_resolution = false
```

`aegis-node validate` warns on high-res / weak cadence / exported drop detail.

## Schemes ranked (sim)

| Scheme | Idea | Product analogue |
|--------|------|------------------|
| `baseline_c5_1s` | 1s flood scrape (C5) | Raw high-freq scrape |
| `min_cadence` | Enforce ≥30s interval | `min_scrape_interval_secs` |
| `quantize` | Floor deltas to bucket 16 | `quantize_bucket` |
| `suppress_drops` | Hide ingress drop counter | `suppress_ingress_drop_detail` |
| `stacked` | Cadence + quantize + suppress | `MetricsExportConfig::production()` |

**Ranking key:** fine-held Pearson (hold scrape load onto a fine grid vs attack) + volume recoverable via drops. Window-total Pearson alone can stay high under long cadence when windows align with the attack block.

## Recommendation

Prefer **`stacked`** (production defaults). Suppressing drops removes the strongest volume channel; quantize blurs 1s deltas; cadence limits scrape Nyquist. Still **Partial**.

## Honest residuals

- Privileged observers with raw handle / `debug_stats` / `allow_high_resolution=true` bypass harden.
- `processed_fail` / `queue_dropped` can still correlate under flood after drop suppression.
- Lab flood model only — not an info-theoretic bound.

## Evidence

| Piece | Path |
|-------|------|
| Sim | `sim/aegis_sim/metrics_scrape_defense.py` |
| Artifact | `sim/data/metrics_scrape_defense.analysis.json` |
| Tests | `sim/tests/test_metrics_scrape_defense.py` |
| Rust gate | `crates/aegis-relay/src/metrics_export.rs` |
| C5 baseline | `sim/data/metrics_sidechannel_characterization.json` |

```bash
cd sim && PYTHONPATH=. python scripts/run_metrics_scrape_defense.py
cd sim && PYTHONPATH=. pytest -q tests/test_metrics_scrape_defense.py
cargo test -p aegis-relay metrics_export
```
