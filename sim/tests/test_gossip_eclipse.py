"""
CI-safe gates for gossip eclipse + majority_k collusion profiling (wave C1).

[O] QUANTIFIED Partial — does not claim multi-org BFT closed.

Run:
  cd sim && PYTHONPATH=. pytest -q tests/test_gossip_eclipse.py
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from aegis_sim import gossip_eclipse as ge

RNG = lambda s=0: np.random.default_rng(s)
DATA = Path(__file__).resolve().parent.parent / "data"
ARTIFACT = DATA / "gossip_eclipse.analysis.json"
OFFLINE = DATA / "gossip_eclipse_offline.json"


def test_median_outcome_counts_matches_rust_example():
    """median(1.0, 0.1) = 0.55 with equal totals (peer_health majority_k2 test)."""
    med = ge.median_outcome_counts([(0, 100), (90, 10)])
    assert med is not None
    ok, fail = med
    rate = fail / (ok + fail)
    assert abs(rate - 0.55) < 0.02


def test_half_weight_preserves_failure_ratio():
    ok, fail = ge.apply_gossip_half_weight(0, 0, 90, 10)
    assert ok == 45 and fail == 5
    assert abs(ge.failure_rate(ok, fail) - 0.1) < 1e-9


def test_majority_k_buffers_until_quorum():
    buf = ge.GossipMergeBuffer(2)
    st, med, have, _ = buf.ingest(0, 90, 10)
    assert st == "buffered" and med is None and have == 1
    st, med, have, honest = buf.ingest(1, 88, 12)
    assert st == "applied" and med is not None and have == 2 and honest == 2


def test_coordinated_eclipse_pure_adv_when_adv_ge_k():
    """N=8, f=0.5 → 4 adv; K=2 → adversaries alone fire pure-adv merge first."""
    ep = ge.simulate_victim_epoch(8, 0.5, 2, eclipse_order=True, rng=RNG(1))
    assert ep["adv_count"] == 4
    assert ep["pure_adv_merges"] >= 1
    assert ep["eclipse_this_epoch"] is True
    assert ep["merges"][0]["pure_adversarial"] is True
    assert ep["merges"][0]["median_rate"] > 0.9
    # Honest neighbors still merge later in-epoch → final window moderated (~0.55).
    assert ep["honest_included_merges"] >= 1
    assert ep["window_fail_rate"] is not None
    assert 0.45 < ep["window_fail_rate"] < 0.70


def test_k_above_adv_blocks_solo_eclipse():
    """N=8, f=0.25 → 2 adv; K=3 → cannot form pure-adv quorum alone."""
    ep = ge.simulate_victim_epoch(8, 0.25, 3, eclipse_order=True, rng=RNG(2))
    assert ep["adv_count"] == 2
    assert ep["pure_adv_merges"] == 0
    assert ep["eclipse_this_epoch"] is False
    assert ep["n_merges"] >= 1
    # 2-of-3 mixed median is still attack-rate (not BFT); later honest merges dilute.
    assert ep["merges"][0]["median_rate"] > 0.9
    assert ep["merges"][0]["honest_in_merge"] == 1
    assert ep["window_fail_rate"] is not None
    assert 0.45 < ep["window_fail_rate"] < 0.70


def test_honest_majority_quorum_resists_bias():
    """N=8, f=0.125 → 1 adv; K=3 → median of (attack, honest, honest) ≈ honest."""
    ep = ge.simulate_victim_epoch(8, 0.125, 3, eclipse_order=True, rng=RNG(22))
    assert ep["adv_count"] == 1
    assert ep["pure_adv_merges"] == 0
    assert ep["window_fail_rate"] is not None
    assert ep["window_fail_rate"] < 0.25
    assert ep["false_probation"] is False


def test_majority_k1_immediate_bias():
    """Lab K=1: every adv advert merges alone → eclipse every epoch; bias elevated."""
    cell = ge.profile_cell(8, 0.25, 1, trials=40, epochs=4, rng=RNG(3))
    assert cell["mean_eclipse_epoch_fraction"] == 1.0
    assert cell["mean_pure_adv_merge_fraction"] > 0.2
    assert cell["mean_median_bias"] is not None
    assert cell["mean_median_bias"] > 0.15
    # At f=0.25 honest majority still dilutes below FP threshold after catch-up.
    assert cell["false_probation_rate"] < 0.2
    # Higher f crosses the false-probation bar.
    cell_hi = ge.profile_cell(8, 0.5, 1, trials=40, epochs=4, rng=RNG(31))
    assert cell_hi["false_probation_rate"] >= 0.9
    assert cell_hi["mean_median_bias"] > 0.35


def test_honest_baseline_low_bias():
    """f=0: bias near zero; no false probation."""
    cell = ge.profile_cell(8, 0.0, 2, trials=40, epochs=4, rng=RNG(4))
    assert cell["mean_median_bias"] is not None
    assert abs(cell["mean_median_bias"]) < 0.05
    assert cell["false_probation_rate"] == 0.0
    assert cell["mean_eclipse_epoch_fraction"] == 0.0


def test_full_eclipse_high_false_probation():
    """f=1.0, K=2: window tracks attack rate → false probation ~1."""
    cell = ge.profile_cell(8, 1.0, 2, trials=40, epochs=4, rng=RNG(5))
    assert cell["can_solo_quorum"]
    assert cell["mean_eclipse_epoch_fraction"] > 0.9
    assert cell["false_probation_rate"] > 0.9
    assert cell["mean_median_bias"] > 0.7


def test_ci_report_structure_and_status():
    report = ge.gossip_eclipse_report(
        f_grid=(0.0, 0.5, 1.0),
        k_grid=(1, 2),
        n_grid=(8,),
        trials=20,
        epochs=3,
        include_offline=False,
        seed=11,
    )
    assert report["status"] == "[O] QUANTIFIED"
    assert report["claim_closed"] is False
    assert report["multi_org_bft"] == "External"
    assert report["wave"] == "C1"
    assert len(report["cells"]) == 6
    assert "highlights" in report["summary"]


def test_artifact_committed_and_honest():
    assert ARTIFACT.is_file(), "regenerate via scripts/run_gossip_eclipse.py"
    art = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert art["status"] == "[O] QUANTIFIED"
    assert art["claim_closed"] is False
    assert art["multi_org_bft"] == "External"
    cells = art["cells"]
    base = ge.cell_lookup(cells, 8, 0.0, 2)
    full = ge.cell_lookup(cells, 8, 1.0, 2)
    assert abs(base["mean_median_bias"]) < 0.08
    assert base["false_probation_rate"] < 0.05
    assert full["false_probation_rate"] > 0.85
    assert full["mean_median_bias"] > 0.7
    # Solo-quorum blocked at K=3 / f=0.25, but mixed 2-of-3 still biases to FP;
    # honest-majority (f=0.125, K=3) is the resisting slice.
    k3_mid = ge.cell_lookup(cells, 8, 0.25, 3)
    assert k3_mid["can_solo_quorum"] is False
    assert k3_mid["mean_eclipse_epoch_fraction"] == 0.0
    assert k3_mid["false_probation_rate"] > 0.85
    assert k3_mid["mean_median_bias"] > 0.35
    k3_resist = ge.cell_lookup(cells, 8, 0.125, 3)
    assert k3_resist["mean_median_bias"] < 0.15
    assert k3_resist["false_probation_rate"] < 0.15
    k1 = ge.cell_lookup(cells, 8, 0.25, 1)
    assert k1["mean_eclipse_epoch_fraction"] == 1.0
    assert k1["mean_median_bias"] > 0.15
    k1_hi = ge.cell_lookup(cells, 8, 0.5, 1)
    assert k1_hi["false_probation_rate"] > 0.85


def test_offline_artifact_if_present():
    """Offline file optional in minimal checkouts; when present, must stay honest."""
    if not OFFLINE.is_file():
        return
    art = json.loads(OFFLINE.read_text(encoding="utf-8"))
    assert art["status"] == "[O] QUANTIFIED"
    assert art["claim_closed"] is False
    assert "offline" in art or "cells" in art
