"""
CI gates for AC / nullifier unlinkability lab (research coverage wave C4).

Characterizes ([O] QUANTIFIED); does **not** claim interactive ZK or paper AC.

Run:
  cd sim && PYTHONPATH=. pytest -q tests/test_ac_nullifier_unlinkability.py
"""
from __future__ import annotations

import json
from pathlib import Path

from aegis_sim import ac_nullifier_unlinkability as lab

DATA = Path(__file__).resolve().parent.parent / "data"
ARTIFACT = DATA / "ac_nullifier_unlinkability.json"


def test_nullifier_derivation_deterministic_and_domain_separated():
    rid = bytes([1]) * 32
    blind = bytes([2]) * 32
    a = lab.derive_reputation_nullifier(rid, 7, blind)
    b = lab.derive_reputation_nullifier(rid, 7, blind)
    c = lab.derive_reputation_nullifier(rid, 8, blind)
    d = lab.derive_reputation_nullifier(bytes([3]) * 32, 7, blind)
    assert a == b and len(a) == 32
    assert a != c and a != d


def test_local_double_spend_rejected():
    issuer = lab.LabIssuer()
    cred = issuer.issue(bytes([9]) * 32, 1, bytes([8]) * 32, 0.9, 0.5)
    reg = lab.NullifierRegistry()
    assert lab.verify_and_spend(reg, cred) == "accepted"
    assert lab.verify_and_spend(reg, cred) == "double_spend_rejected"


def test_partition_both_accept_then_merge_idempotent():
    issuer = lab.LabIssuer()
    cred = issuer.issue(bytes([4]) * 32, 2, bytes([5]) * 32, 0.9, 0.5)
    a = lab.NullifierRegistry()
    b = lab.NullifierRegistry()
    assert lab.verify_and_spend(a, cred) == "accepted"
    assert lab.verify_and_spend(b, cred) == "accepted"
    report = a.merge(b)
    assert report["added"] == 0
    assert report["already_present"] == 1
    assert a.epoch_len(2) == 1


def test_blinded_request_omits_relay_id():
    issuer = lab.LabIssuer()
    rid = bytes([0xAB]) * 32
    req = issuer.build_blinded_request(rid, 3, bytes([0xCC]) * 32, 0.9, 0.5)
    blob = json.dumps(req)
    assert rid.hex() not in blob
    assert "relay_id" not in req
    cred = issuer.issue_from_blinded_request(req)
    linked = issuer.correlate_spend(cred.nullifier)
    assert linked is not None
    assert linked.relay_id is None  # no OOB id supplied


def test_merge_eclipse_full_suppress_risk_near_one():
    out = lab.scenario_merge_eclipse_suppressed(n_trials=24, suppress_prob=1.0)
    assert out["double_accept_rate"] == 1.0
    assert out["residual_risk_score"] == 1.0


def test_delayed_merge_zero_vs_positive():
    out = lab.scenario_delayed_merge_window(
        delay_slots=(0, 2, 4), window=4, n_adversaries=40
    )
    by_d = {p["delay_slots"]: p for p in out["points"]}
    assert by_d[0]["expected_rate_uniform_attempt"] == 0.0
    assert by_d[0]["double_accept_rate"] == 0.0
    assert by_d[2]["expected_rate_uniform_attempt"] == 0.5
    assert by_d[4]["expected_rate_uniform_attempt"] == 1.0
    # Empirical rates track analytical exposure within MC noise.
    assert abs(by_d[2]["double_accept_rate"] - 0.5) <= 0.2
    assert by_d[4]["double_accept_rate"] == 1.0


def test_suite_scores_in_expected_bands():
    suite = lab.run_all_scenarios()
    lab.assert_scores_in_bands(suite["residual_risk_scores"])
    assert suite["composite_residual_risk"] >= 0.7
    assert all(not fm["interactive_zk_done"] for fm in suite["failure_modes"])


def test_artifact_committed_and_honest():
    assert ARTIFACT.is_file(), "run: PYTHONPATH=. python -m aegis_sim.ac_nullifier_unlinkability"
    art = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert art["tag"] == lab.ARTIFACT_TAG
    assert art["wave"] == "C4"
    assert art["status"] == "[O] QUANTIFIED"
    assert art["characterizes_not_closes"] is True
    assert art["claims_interactive_zk_done"] is False
    assert art["claims_paper_complete_ac"] is False
    assert art["claims_cross_node_nullifier_consensus"] is False
    lab.assert_scores_in_bands(art["residual_risk_scores"])
    # Live suite must match committed residual keys / band honesty.
    live = lab.build_characterization_artifact()
    assert set(live["residual_risk_scores"]) == set(art["residual_risk_scores"])
    for k, v in live["residual_risk_scores"].items():
        assert abs(v - art["residual_risk_scores"][k]) < 1e-9, k


def test_failure_mode_catalog_covers_merge_and_issuer():
    ids = {fm["id"] for fm in lab.failure_mode_catalog()}
    assert "issuer_sees_relay_id_at_issue" in ids
    assert "merge_path_eclipse" in ids
    assert "partition_or_delayed_merge_double_accept" in ids
