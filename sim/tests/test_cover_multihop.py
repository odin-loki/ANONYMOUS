"""
Multi-hop cover semantic-gap characterization (partial; not indistinguishability).

Run:  cd sim && PYTHONPATH=. pytest -q tests/test_cover_multihop.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_sim import cover_multihop

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "sim" / "data" / "cover_multihop_characterization.json"
TAU = 0.35
N_SENDS = 4
N_HOPS = 3


def test_sphinx_only_near_full_continuity():
    report = cover_multihop.characterize_multihop(
        "sphinx_only",
        n_hops=N_HOPS,
        n_sends=N_SENDS,
        tau_secs=TAU,
        cover_secs=0.0,
        relay_cover_bursts_per_hop=0,
    )
    assert report.mean_discard_fraction == pytest.approx(0.0, abs=1e-12)
    assert report.mean_implied_packet_continuity == pytest.approx(1.0, abs=1e-9)
    assert report.forward_continuity == pytest.approx(1.0, abs=1e-9)
    assert report.semantic_gap_score < 0.05


def test_cover_raises_semantic_gap_and_lowers_continuity():
    sphinx = cover_multihop.characterize_multihop(
        "sphinx_only",
        n_hops=N_HOPS,
        n_sends=N_SENDS,
        tau_secs=TAU,
    )
    cover = cover_multihop.characterize_multihop(
        "sphinx_plus_cover",
        n_hops=N_HOPS,
        n_sends=N_SENDS,
        tau_secs=TAU,
        cover_secs=2.0,
        relay_cover_bursts_per_hop=1,
    )
    assert cover.mean_discard_fraction > sphinx.mean_discard_fraction
    assert cover.mean_implied_packet_continuity < sphinx.mean_implied_packet_continuity
    assert cover.semantic_gap_score > sphinx.semantic_gap_score
    # Same Sphinx forwards continue; cover is local discard.
    assert cover.forward_continuity == pytest.approx(1.0, abs=1e-9)
    for hop in cover.hops:
        assert hop["n_cover_discarded"] > 0
        assert hop["n_packets_forwarded"] == N_SENDS


def test_invalid_onion_also_opens_semantic_gap():
    sphinx = cover_multihop.characterize_multihop(
        "sphinx_only", n_hops=N_HOPS, n_sends=N_SENDS, tau_secs=TAU
    )
    invalid = cover_multihop.characterize_multihop(
        "sphinx_plus_invalid",
        n_hops=N_HOPS,
        n_sends=N_SENDS,
        tau_secs=TAU,
        invalid_packets_per_send=1,
    )
    assert invalid.mean_discard_fraction > 0.0
    assert invalid.mean_implied_packet_continuity < sphinx.mean_implied_packet_continuity
    assert invalid.semantic_gap_score > sphinx.semantic_gap_score
    for hop in invalid.hops:
        assert hop["n_invalid_onion_cells"] > 0


def test_compare_multihop_scenarios_structure():
    data = cover_multihop.compare_multihop_scenarios(
        n_hops=N_HOPS,
        n_sends=N_SENDS,
        tau_secs=TAU,
        cover_secs=2.0,
        relay_cover_bursts_per_hop=1,
        invalid_packets_per_send=1,
    )
    assert data["claims_info_theoretic_indistinguishability"] is False
    assert data["characterization"] == "partial_multihop_semantic_gap"
    assert data["delta"]["cover_minus_sphinx_semantic_gap_score"] > 0.0
    assert data["delta"]["continuity_ratio_cover_over_sphinx"] < 1.0
    assert data["delta"]["cover_discard_fraction"] > data["delta"]["sphinx_discard_fraction"]
    assert "single_hop_timing_ref" in data


def test_burst_heavy_bundle_keeps_honest_flags():
    bundle = cover_multihop.full_multihop_characterization_bundle(
        n_hops=N_HOPS,
        n_sends=N_SENDS,
        tau_secs=TAU,
        cover_secs=2.0,
        relay_cover_bursts_per_hop=1,
        burst_n_sends=6,
        burst_relay_cover_bursts=3,
    )
    assert bundle["claims_info_theoretic_indistinguishability"] is False
    assert "burst_heavy" in bundle
    assert bundle["burst_heavy"]["scenario"] == "burst_heavy"
    assert (
        bundle["burst_heavy"]["delta"]["cover_minus_sphinx_semantic_gap_score"]
        > bundle["delta"]["cover_minus_sphinx_semantic_gap_score"] - 1e-9
    )


def test_characterization_artifact_matches_bundle():
    data = cover_multihop.full_multihop_characterization_bundle(
        n_hops=N_HOPS,
        n_sends=N_SENDS,
        tau_secs=TAU,
        cover_secs=2.0,
        relay_cover_bursts_per_hop=1,
        invalid_packets_per_send=1,
        burst_n_sends=6,
        burst_relay_cover_bursts=3,
    )
    if not ARTIFACT.exists():
        pytest.skip(f"optional artifact not committed: {ARTIFACT}")
    on_disk = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert on_disk["claims_info_theoretic_indistinguishability"] is False
    assert (
        on_disk["sphinx_plus_cover"]["mean_implied_packet_continuity"]
        == data["sphinx_plus_cover"]["mean_implied_packet_continuity"]
    )
    assert on_disk["delta"]["cover_minus_sphinx_semantic_gap_score"] > 0.0
    assert on_disk["delta"]["continuity_ratio_cover_over_sphinx"] < 1.0
    assert "burst_heavy" in on_disk
