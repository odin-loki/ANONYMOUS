"""
Faction / Sybil jurisdiction-skew profiling for roster admission (wave C3).

Pure-Python policy mirror of:
  - ``ThresholdConsortium`` M-of-N verify (`aegis-topology` roster.rs)
  - ``RosterAdmissionPolicy`` default rate limit (5 / 24h)
  - ``GUARD_SET_SIZE`` = 3, ``TopologyConfig::high_threat`` L=4
  - Charter diversity goals ([`CONSORTIUM_CHARTER.md`] §5)

Tag: **[O] QUANTIFIED** — characterizes roster skew under correlated authorities;
does **not** close governance. Legal vetting / sanctions screening remain **External**.
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np

# --- Policy params mirrored from code / charter ---------------------------------

# roster.rs RosterAdmissionPolicy::default
DEFAULT_MAX_ADMISSIONS_PER_WINDOW = 5
DEFAULT_WINDOW_SECS = 24 * 60 * 60

# guards.rs
GUARD_SET_SIZE = 3

# types.rs TopologyConfig::high_threat
LAYER_COUNT = 4

# path.rs JurisdictionPolicy::default
MAX_PER_JURISDICTION_PATH = 1

# CONSORTIUM_CHARTER.md §5 (policy targets — not enforced by cryptography)
CHARTER_MIN_GUARD_JURISDICTIONS = 3
CHARTER_MAX_JURISDICTION_PATH_FRACTION = 0.40
CHARTER_MAX_EXITS_PER_JURISDICTION = 1
CHARTER_MIN_AUTHORITY_JURISDICTIONS = 2

HONEST_JURISDICTIONS = ("US", "DE", "FR", "UK", "JP", "CA")
FACTION_JURISDICTION = "SY"

DISCLAIMER = (
    "Faction/Sybil jurisdiction-skew characterization of M-of-N roster admission. "
    "Does not close consortium governance. Legal vetting and sanctions screening "
    "are External (policy/counsel), not software deliverables."
)

CI_THRESHOLD_GRID = ((2, 3), (3, 5), (4, 7))
CI_FACTION_FRAC_GRID = (0.0, 0.2, 0.34, 0.5, 0.67, 1.0)
CI_RELAY_SKEW_GRID = (0.2, 0.5, 0.8)


@dataclass(frozen=True)
class Authority:
    auth_id: int
    jurisdiction: str
    faction: bool


@dataclass(frozen=True)
class RelayCandidate:
    relay_id: int
    jurisdiction: str
    sybil: bool


@dataclass
class AdmissionOutcome:
    relay_id: int
    sybil: bool
    jurisdiction: str
    signatures: int
    admitted: bool
    rate_limited: bool


@dataclass
class SkewMetrics:
    """Core metrics for one (M, N, faction_frac, relay_skew) scenario."""

    m: int
    n: int
    faction_key_fraction: float
    faction_keys: int
    authority_jurisdictions: int
    authorities_meet_charter_diversity: bool
    faction_can_unilateral_admit: bool
    relay_pool_skew: float
    sybil_candidates: int
    honest_candidates: int
    sybil_admission_success_rate: float
    honest_admission_success_rate: float
    admitted_total: int
    admitted_sybil: int
    admitted_sybil_fraction: float
    rate_limited_rejects: int
    guard_distinct_jurisdictions_mean: float
    guard_max_jurisdiction_share_mean: float
    guard_charter_min_jurisdictions_pass_rate: float
    exit_max_per_jurisdiction: float
    exit_charter_pass: bool
    path_max_jurisdiction_fraction_mean: float
    path_charter_40pct_pass_rate: float
    layer1_sybil_fraction: float
    primary_guard_sybil_rate: float
    guard_set_any_sybil_rate: float
    path_any_sybil_rate: float
    disclaimer: str = DISCLAIMER


@dataclass
class SweepReport:
    tag: str
    characterization: str
    claims_governance_closed: bool
    legal_vetting: str
    policy_params: dict[str, Any]
    points: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    disclaimer: str = DISCLAIMER


def _fraction_faction_keys(n: int, faction_key_fraction: float) -> int:
    if n <= 0:
        raise ValueError("n must be positive")
    frac = float(np.clip(faction_key_fraction, 0.0, 1.0))
    return int(round(frac * n))


def build_authorities(
    n: int,
    faction_key_fraction: float,
    *,
    correlate_faction_jurisdiction: bool = True,
    honest_jurisdictions: Sequence[str] = HONEST_JURISDICTIONS,
) -> list[Authority]:
    """Build N authorities; faction keys optionally share one jurisdiction."""
    n_faction = _fraction_faction_keys(n, faction_key_fraction)
    authorities: list[Authority] = []
    for i in range(n):
        faction = i < n_faction
        if faction and correlate_faction_jurisdiction:
            jur = FACTION_JURISDICTION
        elif faction:
            jur = honest_jurisdictions[i % len(honest_jurisdictions)]
        else:
            # Spread honest trustees (charter: ≥2 jurisdictions among N).
            jur = honest_jurisdictions[(i - n_faction) % len(honest_jurisdictions)]
        authorities.append(Authority(auth_id=i, jurisdiction=jur, faction=faction))
    return authorities


def build_relay_pool(
    honest_count: int,
    sybil_count: int,
    relay_pool_skew: float,
    *,
    honest_jurisdictions: Sequence[str] = HONEST_JURISDICTIONS,
    rng: np.random.Generator | None = None,
) -> list[RelayCandidate]:
    """
    Honest relays uniform over honest jurisdictions; Sybils concentrated in
    ``FACTION_JURISDICTION`` with probability ``relay_pool_skew``.
    """
    rng = rng or np.random.default_rng(0)
    skew = float(np.clip(relay_pool_skew, 0.0, 1.0))
    pool: list[RelayCandidate] = []
    for i in range(honest_count):
        jur = honest_jurisdictions[i % len(honest_jurisdictions)]
        pool.append(RelayCandidate(relay_id=i + 1, jurisdiction=jur, sybil=False))
    for j in range(sybil_count):
        if rng.random() < skew:
            jur = FACTION_JURISDICTION
        else:
            jur = honest_jurisdictions[int(rng.integers(0, len(honest_jurisdictions)))]
        pool.append(
            RelayCandidate(relay_id=10_000 + j, jurisdiction=jur, sybil=True)
        )
    return pool


def collect_signatures(
    candidate: RelayCandidate,
    authorities: Sequence[Authority],
    *,
    honest_sign_sybils: bool = False,
) -> int:
    """
    Count authority signatures a candidate would receive.

    Faction authorities sign Sybils; honest authorities sign honest relays only
    (unless ``honest_sign_sybils`` for ablation).
    """
    sigs = 0
    for auth in authorities:
        if candidate.sybil:
            if auth.faction or honest_sign_sybils:
                sigs += 1
        else:
            # Honest relays: all non-colluding authorities sign; faction may also
            # sign honest traffic to stay stealthy (model: always signs).
            sigs += 1
    return sigs


def admit_with_threshold(
    candidate: RelayCandidate,
    authorities: Sequence[Authority],
    m: int,
    *,
    honest_sign_sybils: bool = False,
) -> tuple[bool, int]:
    """Mirror ``ThresholdSignedRelayRecord::verify_threshold``: need ≥M distinct sigs."""
    if m <= 0 or m > len(authorities):
        raise ValueError(f"invalid threshold m={m} for n={len(authorities)}")
    sigs = collect_signatures(
        candidate, authorities, honest_sign_sybils=honest_sign_sybils
    )
    return sigs >= m, sigs


def admit_pool(
    pool: Sequence[RelayCandidate],
    authorities: Sequence[Authority],
    m: int,
    *,
    max_admissions_per_window: int = DEFAULT_MAX_ADMISSIONS_PER_WINDOW,
    apply_rate_limit: bool = True,
    honest_sign_sybils: bool = False,
) -> list[AdmissionOutcome]:
    """
    Attempt admission for each candidate in order.

    Rate limit mirrors default ``RosterAdmissionPolicy`` (5/window). When
    ``apply_rate_limit`` is False, mirrors ``permissive_for_tests``.
    """
    admitted_in_window = 0
    outcomes: list[AdmissionOutcome] = []
    for cand in pool:
        ok, sigs = admit_with_threshold(
            cand, authorities, m, honest_sign_sybils=honest_sign_sybils
        )
        rate_limited = False
        admitted = ok
        if ok and apply_rate_limit:
            if admitted_in_window >= max_admissions_per_window:
                admitted = False
                rate_limited = True
            else:
                admitted_in_window += 1
        elif ok:
            admitted_in_window += 1
        outcomes.append(
            AdmissionOutcome(
                relay_id=cand.relay_id,
                sybil=cand.sybil,
                jurisdiction=cand.jurisdiction,
                signatures=sigs,
                admitted=admitted,
                rate_limited=rate_limited,
            )
        )
    return outcomes


def _fisher_yates(ids: list[int], rng: np.random.Generator) -> None:
    for i in range(len(ids) - 1, 0, -1):
        j = int(rng.integers(0, i + 1))
        ids[i], ids[j] = ids[j], ids[i]


def build_layers(
    admitted: Sequence[AdmissionOutcome],
    *,
    layer_count: int = LAYER_COUNT,
    epoch_seed: int = 99,
    epoch: int = 7,
) -> list[list[AdmissionOutcome]]:
    """Mirror ``build_topology``: epoch shuffle then round-robin into L layers."""
    if layer_count <= 0:
        raise ValueError("layer_count must be positive")
    live = [a for a in admitted if a.admitted]
    live.sort(key=lambda a: a.relay_id)
    seed = (epoch_seed * 0x9E3779B97F4A7C15 + epoch) & 0xFFFFFFFFFFFFFFFF
    rng = np.random.default_rng(seed)
    order = list(live)
    # Shuffle by index permutation for determinism matching spirit of StdRng shuffle.
    idxs = list(range(len(order)))
    _fisher_yates(idxs, rng)
    shuffled = [order[i] for i in idxs]
    layers: list[list[AdmissionOutcome]] = [[] for _ in range(layer_count)]
    for i, relay in enumerate(shuffled):
        layers[i % layer_count].append(relay)
    return layers


def guard_exposure_plateau(c: float, g: int = GUARD_SET_SIZE) -> float:
    """``1 - (1-c)^g`` — same closed form as Rust ``guard_exposure_plateau``."""
    c = float(np.clip(c, 0.0, 1.0))
    return 1.0 - (1.0 - c) ** g


def _jurisdiction_shares(relays: Iterable[AdmissionOutcome]) -> dict[str, float]:
    items = list(relays)
    if not items:
        return {}
    counts = Counter(r.jurisdiction for r in items)
    n = len(items)
    return {j: c / n for j, c in counts.items()}


def measure_topology_skew(
    layers: Sequence[Sequence[AdmissionOutcome]],
    *,
    guard_set_size: int = GUARD_SET_SIZE,
    client_seeds: int = 400,
    path_trials: int = 400,
    rng: np.random.Generator | None = None,
) -> dict[str, float]:
    """
    Measure guard / exit / path jurisdiction concentration and Sybil exposure.

    Layer 0 = guards (entry); last layer = exits (clearnet-facing).
    """
    rng = rng or np.random.default_rng(0)
    if not layers or any(len(layer) == 0 for layer in layers):
        return {
            "guard_distinct_jurisdictions_mean": 0.0,
            "guard_max_jurisdiction_share_mean": 0.0,
            "guard_charter_min_jurisdictions_pass_rate": 0.0,
            "exit_max_per_jurisdiction": 0.0,
            "exit_charter_pass": 0.0,
            "path_max_jurisdiction_fraction_mean": 0.0,
            "path_charter_40pct_pass_rate": 0.0,
            "layer1_sybil_fraction": 0.0,
            "primary_guard_sybil_rate": 0.0,
            "guard_set_any_sybil_rate": 0.0,
            "path_any_sybil_rate": 0.0,
        }

    layer1 = list(layers[0])
    exits = list(layers[-1])
    l1_sybil = sum(1 for r in layer1 if r.sybil) / len(layer1)

    # Exit charter: ≤1 exit per jurisdiction (declarative count on assigned exits).
    exit_counts = Counter(r.jurisdiction for r in exits)
    exit_max = float(max(exit_counts.values())) if exit_counts else 0.0
    exit_charter_pass = float(exit_max <= CHARTER_MAX_EXITS_PER_JURISDICTION)

    g = min(guard_set_size, len(layer1))
    distinct_sum = 0.0
    max_share_sum = 0.0
    charter_guard_pass = 0
    primary_sybil = 0
    set_any_sybil = 0

    for seed in range(client_seeds):
        local = np.random.default_rng(seed + int(rng.integers(0, 1_000_000)))
        chosen_idx = local.choice(len(layer1), size=g, replace=False)
        guards = [layer1[int(i)] for i in chosen_idx]
        # Sticky primary = first held guard (mirrors primary pin from held set).
        primary = guards[0]
        if primary.sybil:
            primary_sybil += 1
        if any(x.sybil for x in guards):
            set_any_sybil += 1
        shares = _jurisdiction_shares(guards)
        distinct = len(shares)
        distinct_sum += distinct
        max_share_sum += max(shares.values()) if shares else 0.0
        if distinct >= CHARTER_MIN_GUARD_JURISDICTIONS:
            charter_guard_pass += 1

    path_max_frac_sum = 0.0
    path_charter_pass = 0
    path_any_sybil = 0
    for _ in range(path_trials):
        path: list[AdmissionOutcome] = []
        for layer in layers:
            path.append(layer[int(rng.integers(0, len(layer)))])
        # Path slot jurisdiction fraction (charter: no single jur > 40% of L slots).
        shares = _jurisdiction_shares(path)
        max_frac = max(shares.values()) if shares else 0.0
        path_max_frac_sum += max_frac
        if max_frac <= CHARTER_MAX_JURISDICTION_PATH_FRACTION + 1e-12:
            path_charter_pass += 1
        if any(r.sybil for r in path):
            path_any_sybil += 1

    return {
        "guard_distinct_jurisdictions_mean": distinct_sum / client_seeds,
        "guard_max_jurisdiction_share_mean": max_share_sum / client_seeds,
        "guard_charter_min_jurisdictions_pass_rate": charter_guard_pass / client_seeds,
        "exit_max_per_jurisdiction": exit_max,
        "exit_charter_pass": exit_charter_pass,
        "path_max_jurisdiction_fraction_mean": path_max_frac_sum / path_trials,
        "path_charter_40pct_pass_rate": path_charter_pass / path_trials,
        "layer1_sybil_fraction": l1_sybil,
        "primary_guard_sybil_rate": primary_sybil / client_seeds,
        "guard_set_any_sybil_rate": set_any_sybil / client_seeds,
        "path_any_sybil_rate": path_any_sybil / path_trials,
    }


def run_scenario(
    m: int,
    n: int,
    faction_key_fraction: float,
    relay_pool_skew: float,
    *,
    honest_count: int = 24,
    sybil_count: int = 24,
    apply_rate_limit: bool = False,
    max_admissions_per_window: int = DEFAULT_MAX_ADMISSIONS_PER_WINDOW,
    correlate_faction_jurisdiction: bool = True,
    client_seeds: int = 400,
    path_trials: int = 400,
    rng: np.random.Generator | None = None,
) -> SkewMetrics:
    """End-to-end scenario: authorities → admission → layers → skew metrics."""
    rng = rng or np.random.default_rng(0)
    authorities = build_authorities(
        n,
        faction_key_fraction,
        correlate_faction_jurisdiction=correlate_faction_jurisdiction,
    )
    n_faction = sum(1 for a in authorities if a.faction)
    auth_jurs = {a.jurisdiction for a in authorities}
    pool = build_relay_pool(
        honest_count, sybil_count, relay_pool_skew, rng=rng
    )
    outcomes = admit_pool(
        pool,
        authorities,
        m,
        max_admissions_per_window=max_admissions_per_window,
        apply_rate_limit=apply_rate_limit,
    )
    sybils = [o for o in outcomes if o.sybil]
    honest = [o for o in outcomes if not o.sybil]
    sybil_ok = sum(1 for o in sybils if o.admitted) / max(len(sybils), 1)
    # For success rate under threshold (ignore rate limit): crypto admit.
    sybil_crypto = sum(
        1 for o in sybils if o.signatures >= m
    ) / max(len(sybils), 1)
    honest_crypto = sum(
        1 for o in honest if o.signatures >= m
    ) / max(len(honest), 1)
    admitted = [o for o in outcomes if o.admitted]
    admitted_sybil = sum(1 for o in admitted if o.sybil)
    layers = build_layers(outcomes)
    topo = measure_topology_skew(
        layers, client_seeds=client_seeds, path_trials=path_trials, rng=rng
    )
    return SkewMetrics(
        m=m,
        n=n,
        faction_key_fraction=float(faction_key_fraction),
        faction_keys=n_faction,
        authority_jurisdictions=len(auth_jurs),
        authorities_meet_charter_diversity=(
            len(auth_jurs) >= CHARTER_MIN_AUTHORITY_JURISDICTIONS
        ),
        faction_can_unilateral_admit=n_faction >= m,
        relay_pool_skew=float(relay_pool_skew),
        sybil_candidates=len(sybils),
        honest_candidates=len(honest),
        sybil_admission_success_rate=sybil_crypto if not apply_rate_limit else sybil_ok,
        honest_admission_success_rate=honest_crypto,
        admitted_total=len(admitted),
        admitted_sybil=admitted_sybil,
        admitted_sybil_fraction=(
            admitted_sybil / len(admitted) if admitted else 0.0
        ),
        rate_limited_rejects=sum(1 for o in outcomes if o.rate_limited),
        guard_distinct_jurisdictions_mean=topo["guard_distinct_jurisdictions_mean"],
        guard_max_jurisdiction_share_mean=topo["guard_max_jurisdiction_share_mean"],
        guard_charter_min_jurisdictions_pass_rate=topo[
            "guard_charter_min_jurisdictions_pass_rate"
        ],
        exit_max_per_jurisdiction=topo["exit_max_per_jurisdiction"],
        exit_charter_pass=bool(topo["exit_charter_pass"]),
        path_max_jurisdiction_fraction_mean=topo[
            "path_max_jurisdiction_fraction_mean"
        ],
        path_charter_40pct_pass_rate=topo["path_charter_40pct_pass_rate"],
        layer1_sybil_fraction=topo["layer1_sybil_fraction"],
        primary_guard_sybil_rate=topo["primary_guard_sybil_rate"],
        guard_set_any_sybil_rate=topo["guard_set_any_sybil_rate"],
        path_any_sybil_rate=topo["path_any_sybil_rate"],
    )


def policy_params_dict() -> dict[str, Any]:
    return {
        "max_admissions_per_window": DEFAULT_MAX_ADMISSIONS_PER_WINDOW,
        "window_secs": DEFAULT_WINDOW_SECS,
        "guard_set_size": GUARD_SET_SIZE,
        "layer_count": LAYER_COUNT,
        "max_per_jurisdiction_path": MAX_PER_JURISDICTION_PATH,
        "charter_min_guard_jurisdictions": CHARTER_MIN_GUARD_JURISDICTIONS,
        "charter_max_jurisdiction_path_fraction": CHARTER_MAX_JURISDICTION_PATH_FRACTION,
        "charter_max_exits_per_jurisdiction": CHARTER_MAX_EXITS_PER_JURISDICTION,
        "charter_min_authority_jurisdictions": CHARTER_MIN_AUTHORITY_JURISDICTIONS,
        "faction_jurisdiction_label": FACTION_JURISDICTION,
        "legal_vetting": "External",
    }


def ci_sweep(
    *,
    honest_count: int = 24,
    sybil_count: int = 24,
    client_seeds: int = 200,
    path_trials: int = 200,
    threshold_grid: Sequence[tuple[int, int]] = CI_THRESHOLD_GRID,
    faction_frac_grid: Sequence[float] = CI_FACTION_FRAC_GRID,
    relay_skew_grid: Sequence[float] = CI_RELAY_SKEW_GRID,
    seed: int = 42,
) -> SweepReport:
    """Bounded sweep for CI artifact regeneration (~seconds)."""
    rng = np.random.default_rng(seed)
    points: list[dict[str, Any]] = []
    for m, n in threshold_grid:
        for frac in faction_frac_grid:
            for skew in relay_skew_grid:
                metrics = run_scenario(
                    m,
                    n,
                    frac,
                    skew,
                    honest_count=honest_count,
                    sybil_count=sybil_count,
                    apply_rate_limit=False,
                    client_seeds=client_seeds,
                    path_trials=path_trials,
                    rng=rng,
                )
                points.append(asdict(metrics))

    # Rate-limit ablation at the critical M-of-N boundary (3-of-5, faction ≥ M).
    rate_pts = []
    for frac in (0.4, 0.6, 0.8):
        metrics = run_scenario(
            3,
            5,
            frac,
            0.8,
            honest_count=honest_count,
            sybil_count=sybil_count,
            apply_rate_limit=True,
            client_seeds=client_seeds,
            path_trials=path_trials,
            rng=rng,
        )
        d = asdict(metrics)
        d["apply_rate_limit"] = True
        rate_pts.append(d)

    unilateral = [p for p in points if p["faction_can_unilateral_admit"]]
    blocked = [p for p in points if not p["faction_can_unilateral_admit"]]
    summary = {
        "n_points": len(points),
        "mean_sybil_success_when_faction_ge_m": (
            float(np.mean([p["sybil_admission_success_rate"] for p in unilateral]))
            if unilateral
            else None
        ),
        "mean_sybil_success_when_faction_lt_m": (
            float(np.mean([p["sybil_admission_success_rate"] for p in blocked]))
            if blocked
            else None
        ),
        "mean_path_charter_pass_high_skew_unilateral": (
            float(
                np.mean(
                    [
                        p["path_charter_40pct_pass_rate"]
                        for p in unilateral
                        if p["relay_pool_skew"] >= 0.8
                    ]
                )
            )
            if any(p["relay_pool_skew"] >= 0.8 for p in unilateral)
            else None
        ),
        "rate_limit_ablation": rate_pts,
        "honest_leftover": (
            "Legal vetting, sanctions screening, and binding diversity-quota "
            "compliance audits remain External / policy — not closed by this sim."
        ),
    }
    return SweepReport(
        tag="[O] QUANTIFIED",
        characterization="faction_sybil_jurisdiction_skew",
        claims_governance_closed=False,
        legal_vetting="External",
        policy_params=policy_params_dict(),
        points=points,
        summary=summary,
    )


def write_artifact(path: Path | str, report: SweepReport | None = None) -> Path:
    path = Path(path)
    report = report or ci_sweep()
    payload = {
        "tag": report.tag,
        "characterization": report.characterization,
        "claims_governance_closed": report.claims_governance_closed,
        "legal_vetting": report.legal_vetting,
        "disclaimer": report.disclaimer,
        "policy_params": report.policy_params,
        "summary": report.summary,
        "points": report.points,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def load_artifact(path: Path | str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
