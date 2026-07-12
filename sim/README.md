# aegis-sim

Traffic-analysis simulation harness for AEGIS. This is the **measuring rig** — per
the project's governing principle, no defense is "done" until an attack simulation
confirms it. The reusable core lives in `aegis_sim/`; the original exploratory
attack scripts (with their console output) are preserved in `attacks/`.

## Layout
- `aegis_sim/traffic.py`      Gaussian & non-Gaussian (heavy-tailed, self-similar) generators
- `aegis_sim/shaper.py`       constant-rate hard-cap shaper (the core Mode-1 defense)
- `aegis_sim/adversaries.py`  timing, intersection, confirmation, bulk attacks
- `aegis_sim/metrics.py`      Hurst estimator, bulk size-ceiling
- `tests/test_evidence_ledger.py`  regression suite pinning every key finding
- `attacks/`                  original scripts (documentation of how we got here)

## Run
```bash
pip install -r requirements.txt
export PYTHONPATH=.
pytest -q                     # regression suite (the evidence ledger)
python attacks/intersection.py   # or run any original attack directly
```

## The evidence ledger (what the tests pin)
See Section 12 of `../docs/AEGIS_SPEC_v3_consolidated.md`. Headlines:
- delay alone is nearly useless; constant-rate emission kills timing correlation
- constant-rate ALONE fails long-term intersection (~25 epochs); hard-cap fixes it
- hard-cap defeats passive intersection AND active confirmation at any Q >= mean
- security is invariant to traffic shape; infinite-variance traffic is unshapeable
- raw bulk leaks the relationship; only uniform+batched+relay-cover hides it
