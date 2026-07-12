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
4. REAL TESTNET TRACE — FIRST GENUINE RUN (this pass)
--------------------------------------------------------------------------------
Open item "Real-trace shapeability" status: [O -> T for this benign client-send
capture; still [O] for operational C2/telemetry — see honest limits below].

### Capture method (fallback used)
Multi-process orchestration (`sim/scripts/capture_multiprocess_trace.py`: four
`aegis-node` OS processes + repeated `aegis-client` invocations) was attempted
first but failed mid-run (~send 23/48) with client exit 101 after relay peer
routing errors. **Fallback:** in-process real-socket capture via
`crates/aegis-node/tests/trace_capture.rs` (`capture_burst_trace_to_csv`), which
reuses the same loopback `TcpListener`/`TcpStream` path as `tcp_testnet.rs` but
drives a bursty 48-packet schedule over ~75 s. This is a genuine non-synthetic
trace of the real Sphinx-build/fragment/seal/send code path; it is **not** a
true multi-machine deployment capture.

### Vantage point
**Client-send wall-clock timestamps** recorded immediately before each
`send_payload()` call (ingress of the first TCP hop). Columns also record
`payload_bytes` (32–256 B varying) and `cell_count` (= 18 =
`SPHINX_FRAGMENT_COUNT` per Sphinx packet). This is the simplest reliable
observation point; relay-side timestamps were not instrumented.

### Artifacts
- `sim/data/real_testnet_trace.csv` — 48 timestamped send events
- `sim/data/real_testnet_trace.analysis.json` — machine-readable report
- `sim/scripts/analyze_real_trace.py` — loads trace → `load_trace_counts` →
  `shapeability_report`, compares to `synthetic_c2_like_counts`
- `sim/tests/test_real_trace.py` — regression gate on the committed trace
- `sim/scripts/capture_multiprocess_trace.py` — best-effort multi-process
  re-capture (not used for the committed trace)
- `crates/aegis-node/tests/trace_capture.rs` — in-process capture test that
  writes the CSV

### Trace shape (rough)
| Quantity | Value |
|----------|-------|
| Events | 48 Sphinx packets |
| Duration | ~71.9 s |
| 1 s slot bins | 72 slots, mean 0.67 events/slot, max 4/slot |
| Mean payload | ~154 B |
| Total wire cells (client→ingress) | 864 (= 48 × 18) |
| Pattern | Bursty clusters (50–180 ms gaps) + idle gaps (0.8–3.5 s) |

### `shapeability_report` findings (1 s slots, budget_slots=5, hi=6)
| Metric | Real testnet trace | `synthetic_c2_like_counts` stand-in (n=40000, seed=103) |
|--------|-------------------|--------------------------------------------------------|
| CV | **1.39** | 1.25 |
| Hurst | NaN (series too short; need ≥128 slots) | 0.75 |
| min_multiple | **1.1** | 2.6 |
| tier | feasible | feasible |

### Comparison — did the synthetic model match reality?
**Partially, with a cost mismatch in the other direction from CV.** Per-slot CV on
the real burst is *slightly higher* than the synthetic stand-in (ratio ≈ 1.11),
because the committed capture includes tight 4-packet clusters (up to 4
events/slot) that the diurnal-smoothed synthetic series does not reproduce at
this short horizon. However:
- **Shaping cost is still much lower on the real trace** (min_multiple 1.1 vs 2.6).
  The synthetic C2-like generator's diurnal × Pareto × lognormal layering
  produces heavier *tail deferral* under `hard_cap` than this 48-packet burst
  schedule, even when CV is similar or lower on the synthetic side.
- **Hurst cannot be estimated** on the 72-slot real series; the synthetic stand-in
  reports LRD-ish H≈0.75 — unverified on real traffic at this horizon.
- This capture is **benign client traffic**, not adversarial C2/telemetry; do not
  cite these numbers as operational C2 evidence.

Record for evidence ledger (§12): benign real-client-send trace, 4-hop in-process
testnet, CV≈1.39, min_multiple=1.1, tier=feasible [T].

### Rust instrumentation note
No relay/client timestamp logging was added. A minimal `Debug` impl for
`CoverFlow`/`CoverEmitResult` in `aegis-relay/src/cover_flow.rs` was required
because concurrent work left the crate non-compiling (`Cell` lacks `Debug`).
`cargo test -p aegis-relay` reports one pre-existing failure in
`cover_flow_count_accumulates_across_rounds` (unrelated to trace capture).

### Future work
- Re-capture from relay-observed forward timestamps (instrument `RelayStats`).
- Multi-process re-run once peer-routing in standalone `aegis-node` configs is
  debugged (in-process path uses dynamically bound ports + consistent peer table).
- Longer horizon (≥128 slots) for Hurst; adversarial/malicious-like emission
  patterns; constant-rate emitter output (post-shaping wire view) vs raw client
  sends.

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
  synthetic)." [O -> T for benign in-process testnet client-send capture;
  still [O] for operational C2/telemetry] First genuine trace committed at
  `sim/data/real_testnet_trace.csv`; see §4 above. Synthetic stand-in CV was
  close but slightly lower (1.25 vs 1.39 real); synthetic overstated shaping
  cost (min_multiple 2.6 vs 1.1).
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
