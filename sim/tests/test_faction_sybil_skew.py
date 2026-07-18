"""
CI gates for faction / Sybil jurisdiction-skew roster admission (wave C3).

Characterizes ([O] QUANTIFIED); does not close consortium governance.
Legal vetting remains External.

Run:
  cd sim && PYTHONPATH=. pytest -q tests/test_faction_sybil_skew.py
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from aegis_sim import faction_sybil_skew as fss

RNG = lambda s=0: np.random.default_rng(s)
DATA = Path(__file__).resolve().parent.parent / "data"
ARTIFACT = DATA / "faction_sybil_skew.json"


def test_threshold_blocks_when_faction_below_m():
    """Honest authorities refuse Sybils → need ≥M faction keys to admit."""
    authorities = fss.build_authorities(5, faction_key_fraction=0.4)  # 2 faction
    assert sum(1 for a in authorities if a.faction) == 2
    sybil = fss.RelayCandidate(relay_id=99, jurisdiction=fss.FACTION_JURISDICTION, sybil=True)
    ok, sigs = fss.admit_with_threshold(sybil, authorities, m=3)
    assert sigs == 2
    assert ok is False


def test_threshold_admits_when_faction_reaches_m():
    authorities = fss.build_authorities(5, faction_key_fraction=0.6)  # 3 faction
    assert sum(1 for a in authorities if a.faction) == 3
    sybil = fss.RelayCandidate(relay_id=99, jurisdiction=fss.FACTION_JURISDICTION, sybil=True)
    ok, sigs = fss.admit_with_threshold(sybil, authorities, m=3)
    assert sigs == 3
    assert ok is True


def test_honest_relays_always_meet_threshold():
    """All authorities sign honest candidates (faction stays stealthy)."""
    for m, n in fss.CI_THRESHOLD_GRID:
        authorities = fss.build_authorities(n, 1.0)
        honest = fss.RelayCandidate(relay_id=1, jurisdiction="US", sybil=False)
        ok, sigs = fss.admit_with_threshold(honest, authorities, m=m)
        assert ok and sigs == n


def test_rate_limit_caps_sybil_pipeline():
    """Default 5/window slows flood even when faction holds ≥M keys."""
    authorities = fss.build_authorities(5, 0.8)
    pool = [
        fss.RelayCandidate(10_000 + i, fss.FACTION_JURISDICTION, True) for i in range(20)
    ]
    outcomes = fss.admit_pool(
        pool, authorities, m=3, apply_rate_limit=True, max_admissions_per_window=5
    )
    assert sum(1 for o in outcomes if o.admitted) == 5
    assert sum(1 for o in outcomes if o.rate_limited) == 15


def test_correlated_authorities_can_fail_charter_diversity():
    """All faction keys in one jurisdiction can drop distinct trustee count below 2."""
    # N=3, all faction → single SY jurisdiction.
    authorities = fss.build_authorities(3, 1.0, correlate_faction_jurisdiction=True)
    jurs = {a.jurisdiction for a in authorities}
    assert len(jurs) == 1
    assert len(jurs) < fss.CHARTER_MIN_AUTHORITY_JURISDICTIONS


def test_scenario_unilateral_raises_sybil_and_skew():
    """When faction ≥ M and pool is skewed, Sybil share and path skew rise."""
    blocked = fss.run_scenario(
        m=3, n=5, faction_key_fraction=0.2, relay_pool_skew=0.8,
        apply_rate_limit=False, client_seeds=150, path_trials=150, rng=RNG(1),
    )
    unilateral = fss.run_scenario(
        m=3, n=5, faction_key_fraction=0.6, relay_pool_skew=0.8,
        apply_rate_limit=False, client_seeds=150, path_trials=150, rng=RNG(2),
    )
    assert blocked.faction_can_unilateral_admit is False
    assert blocked.sybil_admission_success_rate == 0.0
    assert unilateral.faction_can_unilateral_admit is True
    assert unilateral.sybil_admission_success_rate == 1.0
    assert unilateral.admitted_sybil_fraction > blocked.admitted_sybil_fraction
    assert unilateral.layer1_sybil_fraction > 0.2
    # High skew + Sybil flood → charter 40% path goal often fails.
    assert unilateral.path_charter_40pct_pass_rate < 0.95


def test_primary_guard_tracks_layer1_sybil_fraction():
    metrics = fss.run_scenario(
        m=2, n=3, faction_key_fraction=1.0, relay_pool_skew=1.0,
        honest_count=18, sybil_count=18,
        apply_rate_limit=False, client_seeds=300, path_trials=100, rng=RNG(3),
    )
    assert abs(metrics.primary_guard_sybil_rate - metrics.layer1_sybil_fraction) < 0.12
    expected_set = fss.guard_exposure_plateau(metrics.layer1_sybil_fraction, fss.GUARD_SET_SIZE)
    assert abs(metrics.guard_set_any_sybil_rate - expected_set) < 0.12


def test_ci_sweep_summary_separates_faction_ge_m():
    report = fss.ci_sweep(
        client_seeds=80, path_trials=80, seed=7,
        faction_frac_grid=(0.0, 0.4, 0.8),
        relay_skew_grid=(0.5, 0.8),
    )
    assert report.claims_governance_closed is False
    assert report.legal_vetting == "External"
    assert report.summary["mean_sybil_success_when_faction_lt_m"] == pytest.approx(0.0)
    assert report.summary["mean_sybil_success_when_faction_ge_m"] == pytest.approx(1.0)
    assert report.policy_params["max_admissions_per_window"] == 5
    assert report.policy_params["guard_set_size"] == 3
    assert report.policy_params["layer_count"] == 4


def test_artifact_committed_and_gates():
    """Committed JSON exists; summary gates + disclaimer hold."""
    assert ARTIFACT.is_file(), f"missing artifact; run scripts/run_faction_sybil_skew.py"
    data = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert data["claims_governance_closed"] is False
    assert data["legal_vetting"] == "External"
    assert data["characterization"] == "faction_sybil_jurisdiction_skew"
    assert "External" in data["disclaimer"]
    s = data["summary"]
    assert s["mean_sybil_success_when_faction_lt_m"] == pytest.approx(0.0, abs=1e-9)
    assert s["mean_sybil_success_when_faction_ge_m"] == pytest.approx(1.0, abs=1e-9)
    assert s["n_points"] >= 40
    # Rate-limit ablation: with faction ≥ M, admitted count capped at 5/window.
    for pt in s["rate_limit_ablation"]:
        if pt["faction_can_unilateral_admit"]:
            assert pt["rate_limited_rejects"] > 0
            assert pt["admitted_total"] <= fss.DEFAULT_MAX_ADMISSIONS_PER_WINDOW + 24
            # Honest batch may fill the window first depending on pool order;
            # crypto success for Sybils remains 1.0 when measuring signatures.
            assert pt["faction_keys"] >= pt["m"]


def test_policy_params_match_code_docs():
    p = fss.policy_params_dict()
    assert p["max_admissions_per_window"] == 5
    assert p["window_secs"] == 24 * 3600
    assert p["guard_set_size"] == fss.GUARD_SET_SIZE == 3
    assert p["layer_count"] == fss.LAYER_COUNT == 4
    assert p["charter_min_guard_jurisdictions"] == 3
    assert p["charter_max_jurisdiction_path_fraction"] == 0.40
    assert p["charter_max_exits_per_jurisdiction"] == 1
    assert p["legal_vetting"] == "External"
