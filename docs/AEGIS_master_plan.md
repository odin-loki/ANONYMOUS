================================================================================
      AEGIS — MASTER BUILD PLAN: a decent anonymity engine, start to finish
================================================================================
Consolidates AEGIS_v2 (redesign), v2.1 (red-team fixes), v2.2 (intersection
findings) into one architecture and a phased plan we work through together.
Governing principle (the lesson of the whole exercise):
    NOTHING IS DONE UNTIL AN ATTACK SIMULATION CONFIRMS IT.
    Intuition was wrong at every stage; only measurement was trustworthy.
Every phase therefore pairs a BUILD with the specific RED-TEAM GATE it must pass.

Working assumptions (flip any and the plan re-cuts):
- Rust datapath (tokio). Python for the simulation harness.
- Permissioned / consortium relay set (defence deployment).
- Primary product = INTERNAL STANDING tier (delay-tolerant), not interactive/exit.
- Dev/sim on existing workstation (RTX 3090 not needed for sim; useful later for
  the Izaac/GRIA anomaly-detection component).

================================================================================
PART A — THE CONSOLIDATED ENGINE (what "decent" means, validated)
================================================================================
Class      : continuous-time / synchronous-round stratified mixnet
             (Loopix -> Vuvuzela/Karaoke lineage). NOT a low-latency onion router.
Packet     : Sphinx. Constant size, position-hiding, tagging-resistant, replay-
             protected. Hybrid X25519+ML-KEM-768 KEM. LIONESS payload.
             ChaCha20-Poly1305 link. (BLS/Groth16 used only for beacon/reputation,
             explicitly NOT claimed post-quantum.)
Topology   : stratified, L=4 high-threat default (L=3 standard). Stable membership
             per long epoch (hours), slow relay churn. NO 10s topology mutation.
Paths      : fresh CSPRNG-random per packet (NOT deterministic). Sphinx hides them.
Tiers      : STANDING (default, persistent links) = synchronous constant-rate
             rounds on BOTH ends: constant-rate send (D1) + receiver volume
             padding (D2). The only tier that provably survived intersection.
             ASYNC-LITE = short-lived/low-sensitivity flows; weaker, documented.
Emission   : constant-rate slotting; utilization rho <= 0.7; traffic shaped
             low-variance BEFORE entering the anonymity layer.
Receiver   : quota Q >= ~3x mean volume (~4 sigma). Priced to the TAIL.
Mixing     : per-hop Exp(mu) delay sized ONLY to let rounds/cover mix -- delay is
             not the security primitive (proven).
Guards     : stable + vetted (permissioned -> effective adversary c ~1%) + layered
             vanguards (deanon needs c^2, not c) + jurisdiction diversity.
Sybil      : permissioned/consortium admission (a FEATURE for the buyer).
Beacon     : threshold-BLS drand-style -> cover scheduling + committee assignment.
Trust      : ZK reputation (scoped, non-PQ). TEE = defense-in-depth, NOT load-bearing
             (security must hold with the enclave assumed fully broken).
Analytics  : Izaac/GRIA telemetry anomaly detection, OUT of the core datapath.

--------------------------------------------------------------------------------
THE SECURITY-COST MODEL (the single most valuable output of the red-team)
--------------------------------------------------------------------------------
Every defense in this class is priced by the TAIL of the traffic distribution,
not the mean:
   receiver quota Q  ~ PEAK receiver volume (~4 sigma)   [Provisioning Rule #1]
   slot rate 1/tau   ~ PEAK send rate (rho <= 0.7)       [Provisioning Rule #2]
   path length L     -> full-path compromise = f^L        [cheap knob]
Consequence: LOW-VARIANCE traffic is cheap to protect; BURSTY traffic is expensive
or insecure. Traffic shaping to a bounded profile is a PRODUCT CONSTRAINT, not an
afterthought. Standing high-value links => synchronous constant-rate rounds both ends.

--------------------------------------------------------------------------------
HONEST BOUNDARIES (state these to any evaluator; do not oversell)
--------------------------------------------------------------------------------
- All baseline-level guarantees are for INTERNAL (client<->client) traffic where
  both ends run AEGIS. EXIT-to-clearnet is a weaker tier (can't pad an external
  server). Never sell exit traffic as carrying the internal guarantee.
- Results are EMPIRICAL BOUNDS under a global-passive + f-fraction-compromised
  model, through 800 epochs of intersection -- not unconditional proofs.
- Not interactive. Multi-second latency is inherent, not an implementation defect.

================================================================================
PART B — THE PHASED PLAN (each phase = a work session with a hard gate)
================================================================================

PHASE 0 — Threat model & parameter budget            [paper, ~1 session]
  Build : lock the adversary model; pick target epsilon per tier; choose a target
          application traffic profile (mean + tail); derive the parameter envelope
          (tau, Q, mu, L, rho) from the cost model.
  Gate  : parameters self-consistent; Q>=3x tail and rho<=0.7 both satisfiable at
          the chosen bandwidth/latency budget. If not, revise the traffic profile.
  Why 1st: you cannot build without knowing which point in the cost model you target.

PHASE 1 — Simulation harness (productionize what we built)   [before real code]
  Build : turn the ad-hoc attack scripts into `aegis-sim` -- pluggable DEFENSE
          configs and pluggable ADVERSARIES (timing, volume, intersection, and the
          still-open ACTIVE FLOODING + intersection). Reproducible, seeded, charted.
  Gate  : reproduces v2.2 results (intersection defeated at Q>=3x, rho<=0.7;
          constant-rate-only fails ~25 epochs). Adds the flooding adversary result.
  Why 2nd: the whole thesis is empirical validation -- build the measuring rig
           BEFORE the system, so every later phase has a gate to pass.
  ** This is also where we retire the last open red-team item (flooding+intersection),
     which directly de-risks the Phase 4 gate. Strong candidate for our NEXT session. **

PHASE 2 — Sphinx crypto core (Rust)                  [correctness, not simulation]
  Build : /src/crypto -- hybrid X25519+ML-KEM-768 header, LIONESS payload, replay
          cache, tagging-safe MAC, ChaCha20-Poly1305 link, 512B fixed cell.
  Gate  : test vectors + property tests: replay rejected; tampered packet fully
          randomized; constant size across all path lengths; known-answer KEM.

PHASE 3 — Mix relay + stratified topology (Rust/tokio)
  Build : /src/relay (Sphinx process, Exp(mu) delay, forward), /src/topology
          (L-tier stratified, stable membership). Local N-mix testnet.
  Gate  : testnet routes Sphinx packets correctly end-to-end; measured latency
          profile matches the Phase-0 budget.

PHASE 4 — Standing tier: synchronous rounds + padding   [THE make-or-break phase]
  Build : /src/rounds (synchronous constant-rate rounds), client constant-rate
          emitter with rho-bounded queue, receiver quota padding (D1+D2, both ends).
  Gate  : pipe LIVE testnet traffic into the Phase-1 harness's intersection AND
          flooding adversaries -> held at the random baseline over long horizons.
          THIS gate is the product. If it fails, the engine fails.

PHASE 5 — Guards, vanguards, beacon, admission
  Build : /src/guard (stable layered vanguards), /src/beacon (drand-style BLS),
          /src/admission (permissioned relay vetting + jurisdiction diversity).
  Gate  : predecessor/guard-exposure sim on the live system matches the vetted-c
          plateau (~3% at c=1%, g=3); joint multi-layer exposure ~ c^2.

PHASE 6 — Trust & attestation
  Build : /src/trust (ZK reputation), /src/attest (TEE + self-hosted DCAP option),
          /src/analytics (Izaac/GRIA anomaly detection, out-of-path).
  Gate  : re-run the Phase-4 core gates with the ENCLAVE ASSUMED FULLY BROKEN ->
          baseline still holds (proves TEE is defense-in-depth, not load-bearing).
          Anomaly detector flags injected Sybil/flooding relays.

PHASE 7 — Hardening & honest characterization
  Build : combined active(n-1)+intersection over long horizons; adaptive
          per-epoch compromised-set adversary; REAL-trace traffic shaping (not
          synthetic Poisson); exit-tier characterization.
  Gate  : documented residual epsilon per tier; a red-team report; ZERO unclaimed
          guarantees. This is the artifact that survives due diligence.

================================================================================
PART C — RISK REGISTER (top risks and where each is retired)
================================================================================
R1 Traffic-analysis defeat (core anonymity)   -> retired at Phase 4 gate.
R2 Flooding forces receiver-quota overflow     -> retired at Phase 1 (flooding sim)
                                                  then confirmed at Phase 4.
R3 Real traffic is too bursty to protect cheaply -> tested at Phase 7 (real traces);
   MITIGATION owned from Phase 0 (traffic-shaping as a product constraint).
R4 TEE break collapses security                -> retired at Phase 6 (broken-enclave
                                                  re-run). Design must not depend on it.
R5 Guard capture / predecessor attack          -> retired at Phase 5 (vetted + vanguard).
R6 PQ exposure of harvested traffic            -> retired at Phase 2 (hybrid KEM);
   BLS/Groth16 scoped away from traffic content in Phase 0.
R7 Sphinx crypto correctness                   -> retired at Phase 2 (test vectors).

================================================================================
PART D — IMMEDIATE NEXT ACTIONS
================================================================================
1. Phase 0: I draft the one-page threat-model + parameter-budget spec against a
   concrete target traffic profile you name (mean + peak message rate, tolerable
   latency, tolerable bandwidth overhead). ~1 session.
2. Phase 1: we build `aegis-sim` and settle the OPEN question -- does a flooding
   adversary that forces overflow epochs defeat a well-provisioned Q? This is the
   highest-value next experiment; it gates Phase 4.
Recommended start: run Phase 0 and the Phase-1 flooding experiment together next,
since the flooding result may change the Q provisioning rule before any code exists.
================================================================================
