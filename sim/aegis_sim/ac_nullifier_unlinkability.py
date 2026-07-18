"""
AC / nullifier unlinkability lab (research coverage wave C4).

Tag: [O] QUANTIFIED — characterizes Partial anonymous-credential +
NullifierRegistry residuals. Does **not** claim interactive ZK, paper-complete
AC, blind signatures, or cross-node nullifier consensus.

Mirrors product surfaces in:
  - crates/aegis-trust/src/nullifier.rs  (NullifierRegistry / merge_from_file)
  - crates/aegis-trust/src/anon_issuer.rs (issue / BlindedIssueRequest)
  - crates/aegis-trust/src/zk.rs         (derive_reputation_nullifier)

See docs/ops/anonymous_reputation.md and ATTACK_PLAYBOOK §10.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Set, Tuple

# Domain must match Rust NULLIFIER_DOMAIN in aegis-trust zk.rs.
NULLIFIER_DOMAIN = b"aegis-rep-nullifier-v1"

ARTIFACT_TAG = "research_wave_C4_ac_nullifier_unlinkability"
ARTIFACT_STATUS = "[O] QUANTIFIED"

# Residual risk score bands (0 = none, 1 = full break in lab model).
RISK_BANDS = {
    "issuer_correlation_at_issue": (0.95, 1.0),
    "issuer_nullifier_link_to_spend": (0.90, 1.0),
    "local_double_spend": (0.0, 0.05),
    "partition_double_spend_pre_merge": (0.95, 1.0),
    # Mean of {0,1,2,4,8}/8 over default delay grid ≈ 0.375.
    "delayed_merge_window": (0.20, 0.60),
    "merge_eclipse_suppressed": (0.80, 1.0),
    "verifier_presentation_relay_id_leak": (0.0, 0.05),
    "blinding_reuse_same_epoch": (0.95, 1.0),
}


def derive_reputation_nullifier(
    relay_id: bytes, epoch: int, blinding: bytes
) -> bytes:
    """SHA3-256 twin of Rust `derive_reputation_nullifier`."""
    if len(relay_id) != 32 or len(blinding) != 32:
        raise ValueError("relay_id and blinding must be 32 bytes")
    h = hashlib.sha3_256()
    h.update(NULLIFIER_DOMAIN)
    h.update(relay_id)
    h.update(int(epoch).to_bytes(8, "little", signed=False))
    h.update(blinding)
    return h.digest()


@dataclass
class NullifierRegistry:
    """In-memory twin of `aegis_trust::NullifierRegistry` (local spend set)."""

    used: MutableMapping[int, Set[bytes]] = field(default_factory=dict)

    def is_spent(self, epoch: int, nullifier: bytes) -> bool:
        return nullifier in self.used.get(epoch, set())

    def try_register(self, epoch: int, nullifier: bytes) -> bool:
        """Return True if newly spent; False if already used (replay)."""
        bucket = self.used.setdefault(epoch, set())
        if nullifier in bucket:
            return False
        bucket.add(nullifier)
        return True

    def epoch_len(self, epoch: int) -> int:
        return len(self.used.get(epoch, ()))

    def len(self) -> int:
        return sum(len(s) for s in self.used.values())

    def export_dict(self) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {}
        for epoch, bucket in self.used.items():
            out[str(epoch)] = sorted(n.hex() for n in bucket)
        return out

    def merge(self, other: "NullifierRegistry") -> Dict[str, int]:
        """Idempotent union-merge (operator file exchange twin)."""
        added = 0
        already = 0
        for epoch, bucket in other.used.items():
            for n in bucket:
                if self.is_spent(epoch, n):
                    already += 1
                else:
                    self.try_register(epoch, n)
                    added += 1
        return {"added": added, "already_present": already}

    @classmethod
    def from_export(cls, epochs: Mapping[str, Iterable[str]]) -> "NullifierRegistry":
        reg = cls()
        for epoch_s, hexes in epochs.items():
            epoch = int(epoch_s)
            seen: Set[str] = set()
            for hx in hexes:
                if hx in seen:
                    raise ValueError(f"merge conflict epoch={epoch} nullifier={hx}")
                seen.add(hx)
                reg.try_register(epoch, bytes.fromhex(hx))
        return reg


@dataclass
class IssueRecord:
    """What the issuer learns at issue time (lab adversary view)."""

    path: str  # "issue" | "blinded"
    epoch: int
    nullifier: bytes
    relay_id: Optional[bytes]
    score_band_threshold: float
    # Out-of-band metadata the issuer may log (session / network).
    session_id: str


@dataclass
class Credential:
    epoch: int
    score_band_threshold: float
    nullifier: bytes
    # Lab stand-in for AnonymousReputationPresentation: no RelayId field.
    presentation: Dict[str, Any]
    issuer_session: str


class LabIssuer:
    """Partial AC issuer twin — not interactive ZK / blind-sig AC."""

    def __init__(self) -> None:
        self.issue_log: List[IssueRecord] = []
        self._session = 0

    def _next_session(self) -> str:
        self._session += 1
        return f"sess-{self._session:04d}"

    def issue(
        self,
        relay_id: bytes,
        epoch: int,
        blinding: bytes,
        score: float,
        score_band_threshold: float,
    ) -> Credential:
        """Software issue path: issuer learns relay_id (honest Partial)."""
        if score < score_band_threshold:
            raise ValueError("score below band")
        nullifier = derive_reputation_nullifier(relay_id, epoch, blinding)
        session = self._next_session()
        self.issue_log.append(
            IssueRecord(
                path="issue",
                epoch=epoch,
                nullifier=nullifier,
                relay_id=relay_id,
                score_band_threshold=score_band_threshold,
                session_id=session,
            )
        )
        return Credential(
            epoch=epoch,
            score_band_threshold=score_band_threshold,
            nullifier=nullifier,
            presentation={
                "score_commitment": hashlib.sha3_256(
                    b"lab-commit|" + nullifier
                ).hexdigest(),
                "threshold_proof": "bulletproofs-threshold-stub",
                # Explicit: no RelayId in presentation bytes.
            },
            issuer_session=session,
        )

    def build_blinded_request(
        self,
        relay_id: bytes,
        epoch: int,
        blinding: bytes,
        score: float,
        score_band_threshold: float,
    ) -> Dict[str, Any]:
        """Client-side blinded request: no RelayId / exact score on the wire."""
        if score < score_band_threshold:
            raise ValueError("score below band")
        nullifier = derive_reputation_nullifier(relay_id, epoch, blinding)
        return {
            "epoch": epoch,
            "score_band_threshold": score_band_threshold,
            "presentation": {
                "score_commitment": hashlib.sha3_256(
                    b"lab-commit|" + nullifier
                ).hexdigest(),
                "threshold_proof": "bulletproofs-threshold-stub",
            },
            "nullifier": nullifier.hex(),
        }

    def issue_from_blinded_request(
        self, request: Mapping[str, Any], *, oob_relay_id: Optional[bytes] = None
    ) -> Credential:
        """
        Issuer signs presentation+nullifier without RelayId in request JSON.

        Still not interactive AC: issuer sees nullifier and may learn identity
        out-of-band (`oob_relay_id`). Exact score stays hidden.
        """
        nullifier = bytes.fromhex(str(request["nullifier"]))
        session = self._next_session()
        self.issue_log.append(
            IssueRecord(
                path="blinded",
                epoch=int(request["epoch"]),
                nullifier=nullifier,
                relay_id=oob_relay_id,
                score_band_threshold=float(request["score_band_threshold"]),
                session_id=session,
            )
        )
        return Credential(
            epoch=int(request["epoch"]),
            score_band_threshold=float(request["score_band_threshold"]),
            nullifier=nullifier,
            presentation=dict(request["presentation"]),
            issuer_session=session,
        )

    def correlate_spend(
        self, nullifier: bytes
    ) -> Optional[IssueRecord]:
        """Issuer links a later spend to an issue session via nullifier log."""
        for rec in self.issue_log:
            if rec.nullifier == nullifier:
                return rec
        return None


def verify_and_spend(registry: NullifierRegistry, cred: Credential) -> str:
    """
    Twin of verify_anonymous_and_spend (crypto assumed valid in lab).

    Returns: 'accepted' | 'double_spend_rejected'
    """
    if registry.try_register(cred.epoch, cred.nullifier):
        return "accepted"
    return "double_spend_rejected"


# ---------------------------------------------------------------------------
# Scenario labs → residual risk scores
# ---------------------------------------------------------------------------


def scenario_issuer_correlation_at_issue(
    n_relays: int = 32, epoch: int = 7
) -> Dict[str, Any]:
    """Issuer `issue()` learns relay_id → perfect identity correlation at issue."""
    issuer = LabIssuer()
    linked = 0
    for i in range(n_relays):
        rid = bytes([i & 0xFF]) * 32
        blind = bytes([(i * 3) & 0xFF]) * 32
        cred = issuer.issue(rid, epoch, blind, score=0.9, score_band_threshold=0.5)
        rec = issuer.issue_log[-1]
        if rec.relay_id == rid and rec.nullifier == cred.nullifier:
            linked += 1
    rate = linked / n_relays
    return {
        "scenario": "issuer_correlation_at_issue",
        "n_relays": n_relays,
        "issuer_learned_relay_id_rate": rate,
        "residual_risk_score": rate,
        "notes": (
            "Software issue path binds identity at issue; not unlinkable multi-show AC. "
            "Interactive ZK issuance is External — not claimed done."
        ),
    }


def scenario_issuer_nullifier_link_to_spend(
    n_cred: int = 40, epoch: int = 11
) -> Dict[str, Any]:
    """Blinded path hides RelayId in JSON, but issuer nullifier log links spends."""
    issuer = LabIssuer()
    registry = NullifierRegistry()
    linked_via_nullifier = 0
    relay_id_in_request = 0
    for i in range(n_cred):
        rid = bytes([i & 0xFF]) * 32
        blind = bytes([(0xA0 + i) & 0xFF]) * 32
        req = issuer.build_blinded_request(
            rid, epoch, blind, score=0.85, score_band_threshold=0.5
        )
        blob = json.dumps(req, sort_keys=True)
        if rid.hex() in blob:
            relay_id_in_request += 1
        cred = issuer.issue_from_blinded_request(req)  # no oob id
        assert verify_and_spend(registry, cred) == "accepted"
        rec = issuer.correlate_spend(cred.nullifier)
        if rec is not None and rec.session_id == cred.issuer_session:
            linked_via_nullifier += 1
    return {
        "scenario": "issuer_nullifier_link_to_spend",
        "n_credentials": n_cred,
        "relay_id_in_blinded_request_rate": relay_id_in_request / n_cred,
        "issuer_nullifier_to_spend_link_rate": linked_via_nullifier / n_cred,
        "residual_risk_score": linked_via_nullifier / n_cred,
        "notes": (
            "BlindedIssueRequest omits RelayId; issuer still sees nullifier and can "
            "link later spends to the issue session. Not interactive AC."
        ),
    }


def scenario_local_double_spend(n_trials: int = 64, epoch: int = 3) -> Dict[str, Any]:
    """Local registry rejects replay — residual near zero on one node."""
    issuer = LabIssuer()
    rejected = 0
    for i in range(n_trials):
        rid = bytes([i & 0xFF]) * 32
        blind = bytes([(0x10 + i) & 0xFF]) * 32
        cred = issuer.issue(rid, epoch, blind, 0.8, 0.4)
        reg = NullifierRegistry()
        assert verify_and_spend(reg, cred) == "accepted"
        if verify_and_spend(reg, cred) == "double_spend_rejected":
            rejected += 1
    rate = rejected / n_trials
    return {
        "scenario": "local_double_spend",
        "n_trials": n_trials,
        "double_spend_reject_rate": rate,
        "residual_risk_score": 1.0 - rate,
        "notes": "NullifierRegistry.try_register rejects same-epoch replay locally.",
    }


def scenario_partition_double_spend_pre_merge(
    n_trials: int = 48, epoch: int = 9
) -> Dict[str, Any]:
    """
    Two verifiers partitioned (no merge) both accept the same nullifier.

    After merge_from_file twin, the spend is recorded once; prior accepts are
    not rolled back — residual is the pre-merge double-accept window.
    """
    both_accepted = 0
    post_merge_len = []
    for i in range(n_trials):
        issuer = LabIssuer()
        rid = bytes([i & 0xFF]) * 32
        blind = bytes([(0x55 + i) & 0xFF]) * 32
        cred = issuer.issue(rid, epoch, blind, 0.9, 0.5)
        a = NullifierRegistry()
        b = NullifierRegistry()
        ok_a = verify_and_spend(a, cred) == "accepted"
        ok_b = verify_and_spend(b, cred) == "accepted"
        if ok_a and ok_b:
            both_accepted += 1
        report = a.merge(b)
        post_merge_len.append(a.epoch_len(epoch))
        assert report["added"] == 0  # both already have the same nullifier
        assert a.is_spent(epoch, cred.nullifier)
    rate = both_accepted / n_trials
    return {
        "scenario": "partition_double_spend_pre_merge",
        "n_trials": n_trials,
        "both_nodes_accepted_rate": rate,
        "mean_post_merge_epoch_len": sum(post_merge_len) / len(post_merge_len),
        "residual_risk_score": rate,
        "notes": (
            "merge_from_file is operator file exchange, not consensus. Partition "
            "allows double-accept; merge is idempotent and does not undo spends."
        ),
    }


def scenario_delayed_merge_window(
    delay_slots: Tuple[int, ...] = (0, 1, 2, 4, 8),
    window: int = 8,
    n_adversaries: int = 40,
    epoch: int = 13,
) -> Dict[str, Any]:
    """
    Adversary picks one uniform random slot in `window` to re-spend on node B
    while A's export is delayed `d` slots (merge at slot `d`).

    P(double-accept) = d/window for d in [0, window]. Immediate merge (d=0) ⇒ 0.
    """
    if window <= 0:
        raise ValueError("window must be positive")
    points = []
    for d in delay_slots:
        if d < 0 or d > window:
            raise ValueError("delay_slots must be within [0, window]")
        successes = 0
        for i in range(n_adversaries):
            issuer = LabIssuer()
            rid = bytes([i & 0xFF]) * 32
            blind = bytes([(0x70 + i) & 0xFF]) * 32
            cred = issuer.issue(rid, epoch, blind, 0.9, 0.5)
            a = NullifierRegistry()
            b = NullifierRegistry()
            assert verify_and_spend(a, cred) == "accepted"
            # Deterministic "random" attempt slot in [0, window).
            attempt_slot = (i * 7 + d * 3) % window
            if attempt_slot < d:
                # Still partitioned — B has not merged yet.
                ok = verify_and_spend(b, cred) == "accepted"
            else:
                # Merge arrives at slot d; attempt at/after merge is rejected.
                b.merge(a)
                ok = verify_and_spend(b, cred) == "accepted"
            if ok:
                successes += 1
        rate = successes / n_adversaries
        expected = d / window
        points.append(
            {
                "delay_slots": d,
                "window": window,
                "double_accept_rate": rate,
                "expected_rate_uniform_attempt": expected,
                "residual_risk_score": expected,
            }
        )
    # Aggregate residual: mean analytical exposure over the delay grid.
    agg = sum(p["residual_risk_score"] for p in points) / len(points)
    return {
        "scenario": "delayed_merge_window",
        "points": points,
        "residual_risk_score": round(agg, 4),
        "notes": (
            "Uniform re-spend timing ⇒ exposure ≈ delay/window. Immediate merge "
            "closes the window; long delay approaches partition double-accept."
        ),
    }


def scenario_merge_eclipse_suppressed(
    n_trials: int = 40,
    suppress_prob: float = 1.0,
    epoch: int = 17,
    seed: int = 0,
) -> Dict[str, Any]:
    """
    Adversary eclipses the operator merge path (export dropped / never imported).

    With suppress_prob=1, peer spends never reach the victim → double-accept
    residual equals 1 for the eclipsed credential set.
    """
    # Deterministic pseudo-random suppress decisions from seed.
    suppressed = 0
    double_accept = 0
    for i in range(n_trials):
        # Integer hash → [0,1)
        u = ((seed * 1_000_003 + i * 97) % 10_000) / 10_000.0
        do_suppress = u < suppress_prob
        issuer = LabIssuer()
        rid = bytes([i & 0xFF]) * 32
        blind = bytes([(0x90 + i) & 0xFF]) * 32
        cred = issuer.issue(rid, epoch, blind, 0.88, 0.5)
        honest = NullifierRegistry()
        victim = NullifierRegistry()
        assert verify_and_spend(honest, cred) == "accepted"
        if do_suppress:
            suppressed += 1
            # Victim never merges honest export.
        else:
            victim.merge(honest)
        if verify_and_spend(victim, cred) == "accepted":
            double_accept += 1
    rate = double_accept / n_trials
    return {
        "scenario": "merge_eclipse_suppressed",
        "n_trials": n_trials,
        "suppress_prob": suppress_prob,
        "suppressed_merges": suppressed,
        "double_accept_rate": rate,
        "residual_risk_score": rate,
        "notes": (
            "File merge is not wire gossip. Suppressing export/import eclipses "
            "the victim's spent set — Partial residual, not BFT consensus."
        ),
    }


def scenario_verifier_presentation_unlinkability(
    n_cred: int = 36, epoch: int = 21
) -> Dict[str, Any]:
    """Verifier seeing only presentation+nullifier cannot recover RelayId."""
    issuer = LabIssuer()
    leaks = 0
    for i in range(n_cred):
        rid = bytes([i & 0xFF]) * 32
        blind = bytes([(0xC0 + i) & 0xFF]) * 32
        cred = issuer.issue(rid, epoch, blind, 0.9, 0.5)
        blob = json.dumps(
            {"presentation": cred.presentation, "nullifier": cred.nullifier.hex()},
            sort_keys=True,
        )
        if rid.hex() in blob or rid.decode("latin-1", errors="ignore") in blob:
            leaks += 1
        # Nullifier alone does not equal relay_id without blinding.
        if cred.nullifier == rid:
            leaks += 1
    rate = leaks / n_cred
    return {
        "scenario": "verifier_presentation_relay_id_leak",
        "n_credentials": n_cred,
        "relay_id_leak_rate": rate,
        "residual_risk_score": rate,
        "notes": (
            "Presentation carries no RelayId; nullifier hides relay_id given secret "
            "blinding. Unlinkability vs issuer / merge eclipse is separate."
        ),
    }


def scenario_blinding_reuse_same_epoch(
    n_trials: int = 32, epoch: int = 5
) -> Dict[str, Any]:
    """Reused (relay_id, epoch, blinding) ⇒ identical nullifier ⇒ linkable replay."""
    collisions = 0
    for i in range(n_trials):
        rid = bytes([i & 0xFF]) * 32
        blind = bytes([0xEE]) * 32  # reused blinding
        n1 = derive_reputation_nullifier(rid, epoch, blind)
        n2 = derive_reputation_nullifier(rid, epoch, blind)
        if n1 == n2:
            collisions += 1
        # Different relay with same blinding → different nullifier (domain sep).
        other = bytes([(i + 1) & 0xFF]) * 32
        assert derive_reputation_nullifier(other, epoch, blind) != n1
    rate = collisions / n_trials
    return {
        "scenario": "blinding_reuse_same_epoch",
        "n_trials": n_trials,
        "identical_nullifier_rate": rate,
        "residual_risk_score": rate,
        "notes": (
            "Deterministic nullifier derivation: reuse yields the same spend token "
            "and is rejected locally after first spend."
        ),
    }


def failure_mode_catalog() -> List[Dict[str, Any]]:
    """Structured unlinkability / spend failure modes for docs + artifact."""
    return [
        {
            "id": "issuer_sees_relay_id_at_issue",
            "surface": "AnonymousCredentialIssuer::issue",
            "severity": "Partial — software binding",
            "interactive_zk_done": False,
            "lab_scenario": "issuer_correlation_at_issue",
        },
        {
            "id": "blinded_request_exposes_nullifier_to_issuer",
            "surface": "BlindedIssueRequest / issue_from_blinded_request",
            "severity": "Partial — no RelayId in JSON; nullifier linkable",
            "interactive_zk_done": False,
            "lab_scenario": "issuer_nullifier_link_to_spend",
        },
        {
            "id": "local_double_spend_detected",
            "surface": "NullifierRegistry::try_register",
            "severity": "Mitigated on single node",
            "interactive_zk_done": False,
            "lab_scenario": "local_double_spend",
        },
        {
            "id": "partition_or_delayed_merge_double_accept",
            "surface": "NullifierRegistry::merge_from_file",
            "severity": "Partial — operator file exchange only",
            "interactive_zk_done": False,
            "lab_scenario": "partition_double_spend_pre_merge",
        },
        {
            "id": "merge_path_eclipse",
            "surface": "export_to_file / merge_from_file operator channel",
            "severity": "Partial — suppressible out-of-band path",
            "interactive_zk_done": False,
            "lab_scenario": "merge_eclipse_suppressed",
        },
        {
            "id": "presentation_omits_relay_id",
            "surface": "AnonymousReputationPresentation",
            "severity": "Mitigated for verifier-facing proof bytes",
            "interactive_zk_done": False,
            "lab_scenario": "verifier_presentation_relay_id_leak",
        },
    ]


def run_all_scenarios() -> Dict[str, Any]:
    """Execute the C4 characterization suite (deterministic, CI-fast)."""
    scenarios = [
        scenario_issuer_correlation_at_issue(),
        scenario_issuer_nullifier_link_to_spend(),
        scenario_local_double_spend(),
        scenario_partition_double_spend_pre_merge(),
        scenario_delayed_merge_window(),
        scenario_merge_eclipse_suppressed(suppress_prob=1.0),
        scenario_verifier_presentation_unlinkability(),
        scenario_blinding_reuse_same_epoch(),
    ]
    by_name = {s["scenario"]: s for s in scenarios}
    residual = {
        name: float(by_name[name]["residual_risk_score"])
        for name in (
            "issuer_correlation_at_issue",
            "issuer_nullifier_link_to_spend",
            "local_double_spend",
            "partition_double_spend_pre_merge",
            "delayed_merge_window",
            "merge_eclipse_suppressed",
            "verifier_presentation_relay_id_leak",
            "blinding_reuse_same_epoch",
        )
    }
    # Composite: emphasize cross-node + issuer residuals (not a close claim).
    composite = (
        0.25 * residual["issuer_correlation_at_issue"]
        + 0.20 * residual["issuer_nullifier_link_to_spend"]
        + 0.05 * residual["local_double_spend"]
        + 0.20 * residual["partition_double_spend_pre_merge"]
        + 0.15 * residual["delayed_merge_window"]
        + 0.15 * residual["merge_eclipse_suppressed"]
    )
    return {
        "scenarios": scenarios,
        "residual_risk_scores": residual,
        "composite_residual_risk": round(composite, 4),
        "failure_modes": failure_mode_catalog(),
    }


def build_characterization_artifact() -> Dict[str, Any]:
    """Committed JSON body for sim/data/ac_nullifier_unlinkability.json."""
    suite = run_all_scenarios()
    return {
        "tag": ARTIFACT_TAG,
        "wave": "C4",
        "status": ARTIFACT_STATUS,
        "characterizes_not_closes": True,
        "claims_interactive_zk_done": False,
        "claims_paper_complete_ac": False,
        "claims_cross_node_nullifier_consensus": False,
        "product_surfaces": {
            "nullifier_registry": "aegis_trust::NullifierRegistry",
            "merge": "NullifierRegistry::merge_from_file",
            "issuer": "AnonymousCredentialIssuer",
            "blinded": "BlindedIssueRequest / issue_from_blinded_request",
            "nullifier_derive": "derive_reputation_nullifier",
            "ops_doc": "docs/ops/anonymous_reputation.md",
            "playbook": "docs/ops/ATTACK_PLAYBOOK.md §10",
        },
        "risk_bands_expected": RISK_BANDS,
        "residual_risk_scores": suite["residual_risk_scores"],
        "composite_residual_risk": suite["composite_residual_risk"],
        "scenarios": suite["scenarios"],
        "failure_modes": suite["failure_modes"],
        "honesty": {
            "interactive_zk_issuance": "External — not done",
            "unlinkable_multi_show_ac": "External — not done",
            "cross_node_nullifier_consensus": "External — file merge only",
            "local_replay_prevention": "Done (single node)",
            "presentation_omits_relay_id": "Done (proof bytes)",
        },
    }


def write_artifact(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    art = build_characterization_artifact()
    path.write_text(json.dumps(art, indent=2) + "\n", encoding="utf-8")
    return path


def assert_scores_in_bands(scores: Mapping[str, float]) -> None:
    for key, (lo, hi) in RISK_BANDS.items():
        if key not in scores:
            raise AssertionError(f"missing residual score {key}")
        val = float(scores[key])
        if not (lo <= val <= hi):
            raise AssertionError(
                f"{key} residual {val} outside expected band [{lo}, {hi}]"
            )


if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "data" / "ac_nullifier_unlinkability.json"
    write_artifact(out)
    print("Wrote", out)
