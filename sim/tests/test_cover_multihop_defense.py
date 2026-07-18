"""
Multi-hop cover defense ranking gates (wave S4 / C5 extension).

Run:  cd sim && PYTHONPATH=. pytest -q tests/test_cover_multihop_defense.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_sim import cover_multihop
from aegis_sim import cover_multihop_defense as cmd

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "sim" / "data" / "cover_multihop_defense.analysis.json"
TAU = 0.35
N_SENDS = 4
N_HOPS = 3


def test_baseline_matches_c5_public_api():
    base = cmd.characterize_defense(
        "baseline_local_discard",
        n_hops=N_HOPS,
        n_sends=N_SENDS,
        tau_secs=TAU,
        cover_secs=2.0,
        relay_cover_bursts_per_hop=1,
        seed=7,
    )
    c5 = cover_multihop.characterize_multihop(
        "sphinx_plus_cover",
        n_hops=N_HOPS,
        n_sends=N_SENDS,
        tau_secs=TAU,
        cover_secs=2.0,
        relay_cover_bursts_per_hop=1,
        seed=7,
    )
    assert base.mean_implied_packet_continuity == pytest.approx(
        c5.mean_implied_packet_continuity, abs=1e-12
    )
    assert base.semantic_gap_score == pytest.approx(c5.semantic_gap_score, abs=1e-12)


def test_cover_onions_raise_continuity_toward_sphinx():
    base = cmd.characterize_defense(
        "baseline_local_discard",
        n_hops=N_HOPS,
        n_sends=N_SENDS,
        tau_secs=TAU,
        seed=7,
    )
    onions = cmd.characterize_defense(
        "cover_onions",
        n_hops=N_HOPS,
        n_sends=N_SENDS,
        tau_secs=TAU,
        cover_onion_packets_per_send=2,
        seed=7,
    )
    sphinx = cmd.characterize_defense(
        "sphinx_only_reference",
        n_hops=N_HOPS,
        n_sends=N_SENDS,
        tau_secs=TAU,
        seed=7,
    )
    assert onions.mean_implied_packet_continuity > base.mean_implied_packet_continuity + 0.15
    assert onions.mean_implied_packet_continuity == pytest.approx(1.0, abs=1e-9)
    assert sphinx.mean_implied_packet_continuity == pytest.approx(1.0, abs=1e-9)
    assert onions.semantic_gap_score < base.semantic_gap_score


def test_matched_discard_lowers_hop_volume_l1():
    base = cmd.characterize_defense(
        "baseline_local_discard",
        n_hops=N_HOPS,
        n_sends=N_SENDS,
        tau_secs=TAU,
        cover_secs=2.0,
        relay_cover_bursts_per_hop=1,
        seed=3,
    )
    matched = cmd.characterize_defense(
        "matched_local_discard",
        n_hops=N_HOPS,
        n_sends=N_SENDS,
        tau_secs=TAU,
        cover_secs=2.0,
        relay_cover_bursts_per_hop=1,
        seed=3,
    )
    # Matched schedule → near-uniform hop volumes.
    assert matched.hop_volume_l1 <= base.hop_volume_l1 + 1e-12
    assert matched.hop_volume_l1 < 0.05


def test_report_ranking_and_honest_flags():
    report = cmd.cover_multihop_defense_report(
        n_hops=N_HOPS,
        n_sends=N_SENDS,
        tau_secs=TAU,
        cover_secs=2.0,
        relay_cover_bursts_per_hop=1,
        cover_onion_packets_per_send=2,
        seed=7,
    )
    assert report["claims_info_theoretic_indistinguishability"] is False
    assert report["characterizes_not_closes"] is True
    assert report["status"] == "[O] QUANTIFIED"
    assert report["c5_cross_check"]["match"] is True
    rec = report["recommended"]["scheme"]
    assert rec in (
        "cover_onions",
        "cover_onions_plus_matched",
        "matched_local_discard",
    )
    # Ranking places a cover-onion scheme above baseline on continuity.
    by = {r["scheme"]: r for r in report["defense_ranking"]}
    assert (
        by["cover_onions"]["mean_implied_packet_continuity"]
        > by["baseline_local_discard"]["mean_implied_packet_continuity"]
    )


def test_artifact_committed_fields():
    if not ARTIFACT.exists():
        pytest.skip(f"optional artifact not committed: {ARTIFACT}")
    on_disk = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert on_disk["tag"] == "wave_S4_cover_multihop_defense"
    assert on_disk["claims_info_theoretic_indistinguishability"] is False
    assert "defense_ranking" in on_disk
    assert on_disk["recommended"]["scheme"] in on_disk["schemes_evaluated"]
    live = cmd.cover_multihop_defense_report(
        n_hops=N_HOPS,
        n_sends=N_SENDS,
        tau_secs=TAU,
        cover_secs=2.0,
        relay_cover_bursts_per_hop=1,
        cover_onion_packets_per_send=2,
        seed=7,
    )
    assert (
        on_disk["by_scheme"]["cover_onions"]["mean_implied_packet_continuity"]
        == live["by_scheme"]["cover_onions"]["mean_implied_packet_continuity"]
    )
