================================================================================
              AEGIS — PHASE 8 HARDENING NOTES (implementation addendum)
================================================================================
This is an ADDENDUM, not a replacement. `AEGIS_SPEC_v3_consolidated.md` remains
the single source of truth; this file records what Phase 8 work actually did
against its §10 gate ("documented epsilon per tier; zero unclaimed guarantees")
and §13 open items, and is intentionally honest about what remains open.

--------------------------------------------------------------------------------
1. WHAT WAS ADDED
--------------------------------------------------------------------------------
`sim/aegis_sim/traffic.py`:
  - `load_trace_counts(events, slot_seconds, t0, t1)` — bins a real timestamped
    event log into per-slot counts. This is the INGESTION path for a genuine
    trace; no parser for a specific capture format ships here since no real
    trace is available in this repo.
  - `synthetic_c2_like_counts(...)` — a deliberately messier synthetic stand-in
    (diurnal cycle x heavy-tailed burst multiplier x jitter) used ONLY to
    pipeline-test the shaping code against something structurally harder than
    the clean Gaussian/lognormal/Pareto families already in this module. This
    is NOT evidence about real operational traffic and must not be cited as
    such — see open item below.

`sim/aegis_sim/metrics.py`:
  - `shapeability_report(counts)` — one-call honest characterization: CV,
    Hurst, min-multiple shaping cost, and a coarse tier label (cheap / feasible
    / unshapeable) per the §6 CV rule of thumb. Intended as the tool a future
    session points at a REAL trace to produce the "documented epsilon per
    tier" the Phase 8 gate asks for.

`sim/aegis_sim/adversaries.py`:
  - `adaptive_guard_exposure(c, g, epochs, mode)` — quantifies spec §13 open
    item "adaptive adversary varying the compromised-mix set across epochs".
    `mode='static'` reproduces the closed-form guard plateau 1-(1-c)^g (a
    regression control). `mode='adaptive'` redraws the compromised set every
    epoch and shows cumulative exposure growing with horizon length EVEN
    against a stable guard set — i.e. guard *membership* stability alone does
    not neutralize an adversary that can move its compromise budget over time.

`sim/tests/test_hardening.py` — regression tests for all of the above.

--------------------------------------------------------------------------------
2. OPEN ITEMS -- STATUS AFTER THIS PASS (do not oversell any of these)
--------------------------------------------------------------------------------
- "Adaptive adversary varying the compromised-mix set across epochs." [O -> O,
  QUANTIFIED] Simulated and shown to matter (long-horizon adaptive exposure is
  substantial, see test_adaptive_adversary_increases_exposure_over_horizon).
  NOT mitigated. A real mitigation needs a rate-limiting/detection mechanism
  for relay recompromise, which is future work (candidate: combine with the
  Izaac/GRIA anomaly detection mentioned for Phase 7).
- "Real-trace shapeability (measure CV/tail on actual C2/telemetry, not
  synthetic)." [O, STILL OPEN] Tooling now exists (`load_trace_counts`,
  `shapeability_report`); no genuine trace has been run through it. The
  synthetic C2-like generator is a pipeline test only, not a substitute.
  ACTION FOR A FUTURE SESSION: feed a real (or realistic declassified/public)
  C2/telemetry interarrival log through `shapeability_report` and record the
  resulting tier + multiple in the evidence ledger (§12) as [T], replacing
  this [O].
- "Combined active(n-1)+intersection over long horizons on Mode 1." [O, NOT
  ADDRESSED this pass] — would need a combined attack simulation (compose
  `active_confirm` and `intersection` against the same synthetic population
  over a shared epoch timeline); left for a future session.
- "Sphinx crypto correctness -- proof/test vectors, not simulation." [O ->
  partially addressed] — see `docs/AEGIS_phase2_implementation_notes.md` for
  the Phase 2 implementation's concrete packet layout and its test-vector
  coverage. Test vectors now exist and pass; a formal proof does not.
- "Consortium governance." [O, NOT ADDRESSED] — business/political, out of
  scope for this codebase.

--------------------------------------------------------------------------------
3. EXIT-TIER HONEST CHARACTERIZATION (spec §8)
--------------------------------------------------------------------------------
The spec is explicit: strong guarantees are INTERNAL (client<->client, both
run AEGIS); clearnet exit is a weaker tier because an external server cannot
be made to run the constant-rate emitter / hard-cap receiver padding that
Mode 1's guarantees depend on (§4.2, §4.3). Concretely, for exit traffic:
  - Sender-side unobservability still holds up to the exit relay (the client's
    emission is still constant-rate).
    - Receiver-side hard-cap padding CANNOT be applied, because the real
    endpoint (an arbitrary clearnet server) does not participate in AEGIS —
    only the exit relay's link to that server is unshaped, and that link is
    exactly as observable to a GPA positioned there as any ordinary encrypted
    connection to that server.
  - Practically: exit traffic gets AEGIS's sender-anonymity-set guarantees
    (an observer at the exit cannot tell WHICH of the M clients originated a
    given exit flow, if multiple clients exit through it in the same window)
    but NOT the receiver-side long-term-intersection / active-confirmation
    resistance that internal traffic gets, because that resistance is
    fundamentally a receiver-side property in this design (§4.3) and an
    external server is not a receiver AEGIS controls.
  - No new simulation was added for this in Phase 8; the existing
    `test_evidence_ledger.py` receiver-side tests already document (by their
    absence of an exit-specific variant) that the padding guarantees are
    scoped to AEGIS-participating receivers. Sales/positioning material must
    say "exit is weaker" per §8 and never claim receiver-side hard-cap
    protection for exit flows.
================================================================================
