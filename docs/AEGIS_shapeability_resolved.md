================================================================================
   AEGIS — TRAFFIC SHAPEABILITY: RESOLVED  (top product risk R3, retired)
================================================================================
Question: can real (Gaussian AND non-Gaussian / heavy-tailed / self-similar) C2
traffic be shaped to the constant-rate profile AEGIS needs, and at what cost?
Model: Gaussian-and-non-Gaussian-capable. Marginal family Normal->Lognormal->Pareto
(Gaussian as thin-tail limit, Pareto a<2 as infinite-variance extreme) PLUS
Willinger/Taqqu ON/OFF aggregation for temporal self-similarity (exp ON/OFF =>
Gaussian/SRD aggregate; Pareto ON/OFF a in (1,2) => self-similar/LRD, Hurst=(3-a)/2).
Shaper: hard-cap at c*mean, excess deferred FIFO (degrade latency, never emission).

--------------------------------------------------------------------------------
FINDING 1 — SECURITY IS INVARIANT TO TRAFFIC SHAPE  [by construction, all runs]
--------------------------------------------------------------------------------
Hard-cap makes observable output = C every slot for EVERY distribution tested
(Gaussian, lognormal, Pareto, self-similar). Traffic shape therefore NEVER weakens
anonymity. The entire cost of non-Gaussian traffic is paid in LATENCY/BANDWIDTH,
not security. This is the key result: shapeability is a COST question, not a
security question.

--------------------------------------------------------------------------------
FINDING 2 — COST IS GOVERNED BY THE MARGINAL CV AT THE SHAPING POINT  [TESTED]
--------------------------------------------------------------------------------
Min bandwidth multiple c for p99 deferral <= 5 slots:
   CV 0.20  -> c 1.1     (Gaussian-like: 11% overhead)
   CV 0.53  -> c 1.2
   CV 0.95  -> c 1.6     (moderate tail: 60% overhead)
   CV 1.52  -> c 2.4
   CV 2.61  -> c 3.9     (heavy: ~4x bandwidth)
   CV 4.19  -> >6x       (impractical)
   Pareto a=1.8 (INF var) -> c 3.8
   Pareto a=1.5 (INF var) -> UNSHAPEABLE at bounded cost
THRESHOLDS:
   CV <= 1                    -> cheap, c <= 1.6 (<=60% overhead). COMFORTABLE.
   1 < CV <= ~2.5             -> feasible, c 2-4 (100-300% overhead).
   CV > ~4 OR infinite var    -> NOT shapeable at bounded cost (Pareto a<2).
The finite/infinite-variance boundary (Pareto a=2) is the cliff: below a=2 there is
always a rare burst large enough to blow any finite buffer.

--------------------------------------------------------------------------------
FINDING 3 — STATISTICAL MULTIPLEXING IS THE FRIEND  [TESTED]
--------------------------------------------------------------------------------
Aggregating many independent flows shrinks the marginal CV (~1/sqrt(n)) even when
each flow is strongly self-similar. 25 heavy Pareto-ON/OFF sources with Hurst up to
0.90 (strong LRD) still aggregated to CV ~0.20 -> shaped at c=1.5 for FREE.
=> Self-similarity / high Hurst ALONE does not hurt. Long-range dependence spreads
bursts over time but multiplexing bounds their amplitude. SHAPE AT THE AGGREGATE,
not per-flow.

--------------------------------------------------------------------------------
FINDING 4 — THE DANGER CASES (what actually breaks it)
--------------------------------------------------------------------------------
(a) A SINGLE HEAVY FLOW dominating -> no multiplexing benefit, its raw CV applies.
(b) INFINITE-VARIANCE traffic: bulk data transfer, file/imagery movement
    (classically Pareto a<2). Unshapeable at bounded cost.
Both are identifiable in advance from a traffic trace.

--------------------------------------------------------------------------------
RESOLUTION FOR THE PRODUCT
--------------------------------------------------------------------------------
Telemetry heartbeats + short C2 messages are LOW-CV (regular, small) and, across
many endpoints, multiplex to CV well under 1 -> squarely in the CHEAP regime
(c < 1.6, <60% overhead, single-digit-slot latency). The target use case is
COMFORTABLY SHAPEABLE.
Bulk transfer (imagery, logs, file sync) is the heavy-tailed / infinite-variance
danger. Do NOT put it in the shaped low-latency tier. Handle it via a SEPARATE
bulk class: fragment + rate-limit into a constant-rate bulk pipe (accept high
overhead there, or a dedicated link-layer TFS channel), keeping the interactive
telemetry/messaging tier clean.

DESIGN RULES ADDED:
- Shape at the AGGREGATE where multiplexing helps; avoid per-single-flow shaping.
- Classify traffic: LOW-CV interactive/telemetry -> shaped tier (cheap).
  HEAVY/bulk -> separate bulk-TFS class (never in the low-latency shaped tier).
- Provision c from the MEASURED aggregate CV at the shaping point: c ~ 1 + CV
  is a good first cut for CV <= 2.5; reject/segregate anything with infinite-
  variance marginal.
- Recon deliverable (Phase 7): from a representative trace, compute the aggregate
  CV and tail index at the intended shaping point. If CV<=1 and finite variance
  -> green. If infinite-variance components -> segregate them first.

RISK R3 STATUS: RETIRED as a security risk (Finding 1); QUANTIFIED as a cost risk
(Findings 2-4) with a clear go/segregate rule. Only genuine blocker is a deployment
whose PRIMARY traffic is inherently infinite-variance bulk with a tight latency
budget -- and that is exactly the deployment where a mixnet is the wrong tool anyway.
================================================================================
