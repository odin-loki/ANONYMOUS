"""
CI-safe gates for gossip eclipse defenses vs C1 baseline (wave S5).

[O] QUANTIFIED Partial — does not claim multi-org BFT closed.

Run:
  cd sim && PYTHONPATH=. pytest -q tests/test_gossip_eclipse_defense.py
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from aegis_sim import gossip_eclipse_defense as ged

RNG = lambda s=0: np.random.default_rng(s)
DATA = Path(__file__).resolve().parent.parent / "data"
ARTIFACT = DATA / "gossip_eclipse_defense.analysis.json"


def test_diverse_buffer_waits_for_orgs():
    buf = ged.DiverseGossipMergeBuffer(majority_k=2, min_orgs=2)
    st, med, have, _, orgs = buf.ingest(0, 90, 10, org_id=0)
    assert st == "buffered" and med is None and have == 1
    # Same org → waiting_diversity even with K reporters.
    st, med, have, _, orgs = buf.ingest(1, 88, 12, org_id=0)
    assert st == "waiting_diversity" and med is None and orgs == 1
    st, med, have, honest, orgs = buf.ingest(2, 91, 9, org_id=1)
    assert st == "applied" and med is not None and orgs == 2 and honest == 3


def test_eclipse_heuristic_quarantines_pure_adv():
    assert ged.eclipse_heuristic_quarantine(
        median_rate=1.0, local_fail_rate=0.1, pure_adversarial=True,
    )
    assert not ged.eclipse_heuristic_quarantine(
        median_rate=0.12, local_fail_rate=0.10, pure_adversarial=False,
        local_samples=20,
    )


def test_raised_k_blocks_solo_vs_baseline():
    """At f=0.25 (2/8 adv), K=4 blocks solo quorum; baseline K=2 does not."""
    base = ged.profile_named_defense("baseline", 0.25, trials=40, epochs=4, rng=RNG(1))
    raised = ged.profile_named_defense("raised_k", 0.25, trials=40, epochs=4, rng=RNG(2))
    assert base["can_solo_quorum"] is True
    assert raised["can_solo_quorum"] is False
    assert raised["mean_eclipse_epoch_fraction"] < base["mean_eclipse_epoch_fraction"] + 1e-9


def test_stacked_reduces_fp_at_partial_eclipse():
    """Stacked defense should cut false probation vs C1 baseline at f=0.5."""
    cmp_ = ged.compare_defenses_vs_baseline(
        f_grid=(0.5,), trials=50, epochs=4, seed=11,
    )
    base = ged.cell_lookup(cmp_["rows"], "baseline", 0.5)
    stacked = ged.cell_lookup(cmp_["rows"], "stacked", 0.5)
    assert stacked["false_probation_rate"] < base["false_probation_rate"] - 0.15
    assert stacked["delta_fp_vs_baseline"] > 0.15


def test_full_eclipse_residual_honest():
    """f=1: stacked blocks same-org merges (min_orgs) or quarantines; no free pass."""
    cell = ged.profile_named_defense("stacked", 1.0, trials=40, epochs=4, rng=RNG(3))
    # With min_orgs=2 and all-adv same org, merges never apply (diversity wait)
    # → local-only window (low FP) OR quarantine if a merge somehow forms.
    assert cell["can_solo_quorum"] is True  # adv >= K, but diversity still blocks
    assert (
        cell["false_probation_rate"] > 0.5
        or cell["mean_quarantined_merges"] > 0.5
        or cell.get("mean_eclipse_epoch_fraction", 1.0) == 0.0
    )
    # Honest residual: defense depends on org diversity being real; colluding
    # multi-org adversaries can still meet min_orgs (documented in report).


def test_report_structure():
    report = ged.gossip_eclipse_defense_report(
        f_grid=(0.0, 0.5), trials=20, epochs=3, include_offline=False, seed=7,
    )
    assert report["status"] == "[O] QUANTIFIED"
    assert report["claim_closed"] is False
    assert report["wave"] == "S5"
    assert report["best_defense"] == "stacked"
    assert "compare" in report


def test_artifact_committed():
    assert ARTIFACT.is_file(), "run scripts/run_gossip_eclipse_defense.py"
    art = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert art["claim_closed"] is False
    assert art["best_defense"] == "stacked"
    rows = art["compare"]["rows"]
    base = ged.cell_lookup(rows, "baseline", 0.5)
    stacked = ged.cell_lookup(rows, "stacked", 0.5)
    assert stacked["false_probation_rate"] <= base["false_probation_rate"]
    assert stacked["delta_fp_vs_baseline"] >= 0.0
