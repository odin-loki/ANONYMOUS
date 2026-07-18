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

### Capture method
**In-process (first pass):** real-socket capture via
`crates/aegis-node/tests/trace_capture.rs` (`capture_burst_trace_to_csv`), which
reuses the same loopback `TcpListener`/`TcpStream` path as `tcp_testnet.rs` but
drives a bursty 48-packet schedule over ~72 s. Single Tokio runtime; dynamically
bound ports; peer table built in-memory.

**Multi-process (Phase-8 residual, now working on Windows):** four separate
`aegis-node` OS processes + 48 `aegis-client --raw` invocations orchestrated by
`sim/scripts/capture_multiprocess_trace.py` (or the Rust gate
`crates/aegis-node/tests/multiprocess_trace_capture.rs`). Output:
`sim/data/real_multiprocess_trace.csv`.

#### What failed before (multi-process)
1. **`cargo run` per client send** — on Windows each invocation re-linked/locked
   the binary; mid-run failures (client exit 101 / 4294967295) around send 3–23
   were orchestration flakes, not Sphinx/crypto bugs.
2. **Static ports (`19200–19203`)** — stale processes after aborted runs caused
   bind conflicts; peer tables pointed at wrong addresses.
3. **Default paced session (`cover_secs=2`, `tau=0.35`)** — each send opened a
   new TCP session, ran cover, then closed; 48× ~7 s ≈ 7 min and increased
   connection churn. Trace capture now uses `--raw` (unpaced one-shot sends).
4. **Misdiagnosed “peer routing errors”** — exit relay logs
   `no peer for next_hop RelayId([random…])` were **terminal Sphinx peels** (peel-pad
   bytes in the routing slot) hitting the outbound dispatcher without an `exit_tx` sink,
   not client Sphinx misroutes. Fixed: cover cells carry a reserved-byte marker and are
   discarded before reassembly; unknown `next_hop` without a peer route is dropped
   silently when no exit sink is configured, or delivered via `exit_tx` / TOML exit
   sink when enabled (2026-07-17).

#### Fixes applied
- Build once; invoke `target/debug/aegis-node(.exe)` and `aegis-client(.exe)`
  directly.
- OS-assigned loopback ports written to temp configs; TCP readiness probe before
  sends.
- `--raw` client sends; `taskkill /T /F` process-tree cleanup on Windows.
- Rust `Command`-based integration test as a reliable regeneration path when
  Python is unavailable.

Both captures are genuine non-synthetic traces of the real Sphinx-build/fragment/
seal/send code path over TCP; neither is a multi-machine WAN deployment.

### Vantage point — in-process vs multi-process
| Aspect | In-process (`real_testnet_trace.csv`) | Multi-process (`real_multiprocess_trace.csv`) |
|--------|---------------------------------------|-----------------------------------------------|
| Timestamp locus | Immediately before in-test `send_payload()` | Orchestrator wall-clock immediately before spawning `aegis-client` |
| Process model | Single Tokio runtime, shared address space | 4 relay processes + 1 client process per send |
| Pacing | Unpaced (`send_payload`) | Unpaced (`--raw`) |
| Typical duration | ~71.9 s | ~66.1 s |
| Extra overhead | Minimal (in-process await) | Process spawn + TCP connect per send (~100 ms) |

The multi-process vantage timestamps **slightly earlier** than in-process
(client not yet connected); bursty gap schedule is identical (seed 42). Shape
metrics should agree within noise — and do (see below).

Columns for both: `payload_bytes` (32–256 B varying) and `cell_count` (= 18 =
`SPHINX_FRAGMENT_COUNT` per Sphinx packet). Client-send captures timestamp at
orchestrator/client vantage; relay-side post-forward timestamps are now available
via optional `trace.path` (see §5 below).

### Artifacts
- `sim/data/real_testnet_trace.csv` — 48 events, in-process capture
- `sim/data/real_multiprocess_trace.csv` — 48 events, multi-process capture
- `sim/data/real_testnet_trace.analysis.json` — in-process shapeability report
- `sim/data/real_multiprocess_trace.analysis.json` — mp vs ip comparison
- `sim/scripts/analyze_real_trace.py` — in-process trace → shapeability
- `sim/scripts/analyze_multiprocess_trace.py` — mp vs ip comparison
- `sim/scripts/capture_multiprocess_trace.py` — Python orchestrator (fixed)
- `sim/tests/test_real_trace.py` — regression gate on in-process trace
- `sim/tests/test_multiprocess_trace.py` — mp trace + comparison gate
- `crates/aegis-node/tests/trace_capture.rs` — in-process capture test
- `crates/aegis-node/tests/multiprocess_trace_capture.rs` — multi-process gate

--------------------------------------------------------------------------------
5. RELAY POST-FORWARD TRACE + EXIT SINK (this pass)
--------------------------------------------------------------------------------
### Exit sink (`aegis-node`, off by default)
Terminal Sphinx peels (unknown `next_hop` in the peer table) can be delivered to an
optional sink instead of being dropped. Enable **only on exit relays** — mix relays
should leave this disabled.

TOML (`crates/aegis-node/src/config.rs`):
```toml
[exit]
log_payloads = true              # stderr hex preview of peeled payload
deliver_to = "stdout"            # or "file:/path/to/exit.log"
```

Wiring: `aegis-node` spawns [`spawn_exit_sink`](../../crates/aegis-node/src/exit_sink.rs)
and passes the channel to [`spawn_link_bridge`](../../crates/aegis-relay/src/net.rs)
as `exit_tx`. Payload bytes are trimmed from the Sphinx delta region (trailing
zero padding stripped) and written as hex lines.

Tests: `tcp_testnet_exit_sink_file_receives_payload` in
`crates/aegis-node/tests/tcp_testnet.rs`.

**Residual:** `aegis-node` passes `exit_tx: None` when `[exit]` is unset (correct for
mix relays). Multi-process capture enables a file sink on the last hop only
(`sim/data/testnet_configs/exit_peels.log` via `[exit].deliver_to` in
`capture_multiprocess_trace.py` / `multiprocess_trace_capture.rs`).

### Post-forward timestamp trace (relay vantage, off by default)
Optional instrumentation records **post-shaping** wire events: immediately after a
Sphinx packet is sealed on a hop link, after cover bursts egress, or when a peel is
delivered to the exit sink.

TOML:
```toml
[trace]
path = "relay_forward_trace.csv"
```

Format (`crates/aegis-relay/src/trace.rs`):
```
timestamp,cell_count,event_type
1730000000.123456,18,forward
1730000000.456789,18,cover
1730000000.789012,18,exit
```

Event types: `forward` (Sphinx after mix delay), `cover` (bulk cover burst on wire),
`exit` (terminal peel to exit sink). `cell_count` is `SPHINX_FRAGMENT_COUNT` (18) for
forward/exit, or the cover burst length for `cover`.

Tests / artifacts:
- `crates/aegis-node/tests/relay_forward_trace.rs` — integration gate + `#[ignore]`
  sample regenerator
- `sim/data/relay_forward_trace_sample.csv` — committed sample for pytest
- `sim/scripts/load_relay_forward_trace.py` — loader CLI
- `sim/tests/test_relay_forward_trace.py` — shapeability gate on sample
- `sim/aegis_sim/traffic.py` — `load_relay_forward_trace` / `load_relay_forward_timestamps`

Threat model future work **#8** status: **[T] committed** — paced multi-process relay forward
capture at `sim/data/real_multiprocess_relay_forward_trace.csv` + shapeability analysis
(see below). Mix relays should keep trace off in production.

### Paced multi-process relay forward capture (2026-07-18) [T]
**Methodology:** 4-hop loopback testnet, 12 paced CLI sends (`--tau-secs 0.05
--cover-secs 0.1`, not `--raw`), `[trace].path` on ingress (forward/cover rows) and
exit (exit rows), merged to `sim/data/real_multiprocess_relay_forward_trace.csv`.
Regenerate: `cargo test -p aegis-node capture_multiprocess_paced_relay_forward_trace_to_csv
-- --ignored` or `sim/scripts/capture_multiprocess_relay_forward_trace.py`.

**Loopback limits (honest):**
- **127.0.0.1 only** — no WAN latency/jitter; multi-hop mix delay collapsed vs production.
- **Trace on ingress + exit only** — not every hop; exit rows lag forwards by path RTT.
- **One CLI process per send** — TCP connect + handshake each send (~seconds overhead);
  wall span ~230 s for 12 sends vs ~66 s for 48 raw client-send events (§4).
- **Ingress rate limit defaults** — production token bucket (~1/τ cells/s) can drop excess
  paced cells; capture uses default node TOML (not `without_ingress_rate_limit()`).
- **Partial row counts** — forward/cover/exit row totals need not match 1:1 per send on
  loopback (async trace flush, exit peel timing).

**Artifacts:**
- `sim/data/real_multiprocess_relay_forward_trace.csv` — committed paced MP relay trace
- `sim/data/real_multiprocess_relay_forward_trace.analysis.json` — shapeability + baseline compare
- `sim/scripts/analyze_multiprocess_relay_forward_trace.py` — analysis CLI
- `sim/tests/test_relay_forward_trace.py` — sample + committed capture gates
- `crates/aegis-node/tests/multiprocess_trace_capture.rs` — `#[ignore]` regenerator

### `shapeability_report` — relay post-forward vs client-send (1 s slots, budget_slots=5, hi=6)
| Metric | Relay post-forward (paced MP) | In-process client-send | Multi-process client-send |
|--------|------------------------------|------------------------|---------------------------|
| Events | 31 (12 fwd / 13 cover / 6 exit) | 48 | 48 |
| Duration | ~230 s | ~71.9 s | ~66.1 s |
| 1 s slot bins | 231; mean 0.13; max 2 | 72; mean 0.67; max 4 | 67; mean 0.72; max 5 |
| CV | **3.06** | **1.39** | **1.48** |
| Hurst | 0.34 (231 slots) | NaN (short) | NaN (short) |
| min_multiple | **2.5** | **1.1** | **1.2** |
| tier | **unshapeable** | feasible | feasible |

**Comparison vs §4 client-send baselines:** CV ratio relay/client ≈ **2.06–2.20**; tiers
**differ** (post-shaping relay vantage at 1 s resolution reads *harder* than client-send,
not easier). Long idle gaps between paced CLI invocations dominate the 1 s marginal — not
evidence that production shaping fails, but evidence that **vantage and bin width matter**:
coarser bins (5–10 s) on the same capture read feasible (CV ≈ 1.2–1.5).

Record for evidence ledger: paced loopback relay-forward trace [T]; client-send baselines
unchanged [T]; relay 1 s tier=unshapeable is a **measurement artifact** under sparse
post-cover sampling, documented not oversold.

### Future work (§5 residual — was open)
- ~~Re-capture **full-path** relay forward traces over paced multi-process testnet~~ **[T]**
  committed capture above; longer single-session paced run (one `PacedSession`, many sends)
  would tighten CV at 1 s slots.
- Longer horizon (≥128 slots) for Hurst stability; adversarial emission at relay vantage.
- Production re-capture with ingress rate limit disabled for lab parity (`max_cells_per_sec = 0`).

### Rust instrumentation note
Relay post-forward trace via [`RelayForwardTrace`](../../crates/aegis-relay/src/trace.rs)
(optional `trace.path` in node TOML). Exit sink via
[`spawn_exit_sink`](../../crates/aegis-node/src/exit_sink.rs) (optional `[exit]`).
A minimal `Debug` impl for `CoverFlow`/`CoverEmitResult` in
`aegis-relay/src/cover_flow.rs` was required because concurrent work left the crate
non-compiling (`Cell` lacks `Debug`).

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
  synthetic)." [O -> T for benign testnet client-send capture (in-process and
  multi-process); still [O] for operational C2/telemetry] Traces at
  `sim/data/real_testnet_trace.csv` and `sim/data/real_multiprocess_trace.csv`;
  see §4. Synthetic stand-in CV was close but slightly lower (1.25 vs 1.39–1.48
  real); synthetic overstated shaping cost (min_multiple 2.6 vs 1.1–1.2).
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
