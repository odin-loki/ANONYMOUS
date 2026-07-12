================================================================================
                    AEGIS — CONSOLIDATED SPECIFICATION v3.0
     A metadata-hiding transport for a permissioned multi-party consortium
================================================================================
SUPERSEDES the entire chain (v2, v2.1, v2.2, master plan, phase-0/product,
shapeability, dual-plane, bulk-confirmation). Single source of truth. Every
quantitative claim is traceable to a simulation in the evidence ledger (Sec. 12);
claims are tagged [T]=tested, [R]=reasoned, [O]=open.

--------------------------------------------------------------------------------
1. WHAT IT IS, AND ITS DEFENSIBLE NICHE
--------------------------------------------------------------------------------
AEGIS hides COMMUNICATION METADATA -- who talks to whom, when, and how much --
against a nation-state global passive adversary, for a PERMISSIONED set of
endpoints. Content encryption is assumed already solved; AEGIS protects the
traffic pattern, which is what content crypto leaks.

Killer capability: OP-TEMPO DENIAL. A VPN/link encryptor hides payloads but leaks
"HQ->forward traffic just surged 10x" -- the signal that precedes operations.
AEGIS presents a flat, constant, relationship-opaque wall. The adversary cannot
read operational tempo or command structure off the comms layer.

DEFENSIBLE NICHE = multi-party RELATIONSHIP-GRAPH hiding against a GPA for a
permissioned consortium. Do NOT sell it outside this niche (Sec. 9 tool-fit).

--------------------------------------------------------------------------------
2. THREAT MODEL & SECURITY PROPERTIES
--------------------------------------------------------------------------------
Adversary:
- Global Passive Adversary: sees every link, timing, and volume.
- Active fraction f of compromised mixes (graceful degradation, quantified).
- TEE-compromised variant: enclave assumed FULLY broken on compromised relays;
  base guarantee must survive this (TEE is defense-in-depth only). [R]
- Active confirmation: adversary can suppress a chosen sender and observe. [T]
- NOT defended: adversary controlling ALL mixes on a path, or the endpoint itself.

Properties (empirical bounds under the above model, NOT unconditional proofs):
- Sender unobservability (constant-rate emission -> information-theoretic at entry).
- Sender-receiver unlinkability (mixing + hard-cap receiver padding).
- Long-term intersection resistance (hard-cap padding, held 800 epochs). [T]
- Active-confirmation resistance (hard-cap; and relay cover on the bulk plane). [T]
- Command-graph concealment at full strength on Mode 1.

--------------------------------------------------------------------------------
3. ARCHITECTURE: TWO PLANES
--------------------------------------------------------------------------------
MODE 1 (SHAPED) carries small/bursty data AND all control/negotiation. Full
metadata hiding, cheap. The command/coordination graph is hidden here -- the crown
jewel. MODE 2 (BULK) carries large files over a separately negotiated path with an
explicit, threat-matched security dial. Bulk is NEVER forced through Mode 1
(infinite-variance -> unshapeable). The NEGOTIATOR (a protocol, not a server) runs
end-to-end over Mode 1; no third party learns any pairing.

--------------------------------------------------------------------------------
4. MODE 1 -- THE SHAPED MIXNET (the core product)
--------------------------------------------------------------------------------
4.1 Packet: SPHINX. Constant size, position-hiding, tagging-resistant, replay-
    protected. Hybrid X25519+ML-KEM-768 onion KEM (the only credible PQ claim).
    LIONESS payload. ChaCha20-Poly1305 link. Fixed 512B cell. [R]
4.2 Emission: CONSTANT-RATE. Each client emits one cell per slot tau (real if
    queued, else dummy) -> every client's emission is identical -> zero sender-side
    signal. Keeps timing attack at random baseline; scales to M>=100. [T]
    Utilization rho = lambda_peak * tau <= 0.7 or the latency tail explodes. [T]
4.3 Receiver padding: HARD-CAP. Observable = exactly Q every round; excess DEFERRED
    (degrade latency, never emission shape). Defeats BOTH passive intersection and
    active confirmation at ANY Q >= mean. Set Q >= ~1.2x sustained mean receiver
    rate (Q = mean is unstable). ~2.5x cheaper and strictly more secure than the
    old "pad up to 3x". [T]  (This supersedes v2.2 Rule #1.)
4.4 Mixing: per-hop Exp(mu) delay, sized ONLY to let cover mix. Delay is NOT a
    security primitive -- alone it is nearly useless (40-100% deanon at 15s). [T]
4.5 Topology: stratified, L=4 high-threat default (L=3 standard). Stable membership
    per long epoch. Fresh CSPRNG-random path per packet (NOT deterministic;
    determinism retroactively deanonymizes). Full-path compromise = f^L; L=4 keeps
    it <1% at 30% adversary. [T]
4.6 Guards: STABLE + VETTED + LAYERED (vanguards) + jurisdiction-diverse. Rotating
    guards -> certain exposure over time; stable plateau = 1-(1-c)^g. Vetting drives
    effective c from ~10% (27% plateau) to ~1% (~3% plateau); vanguards make deanon
    need c^2 not c. [T/R]
4.7 Beacon: threshold-BLS drand-style, for cover scheduling + committee assignment.
    NOT topology churn (churn accelerates intersection), NOT path determinism. [R]
4.8 Trust: ZK reputation (scoped, non-PQ). TEE = defense-in-depth; security must
    hold with the enclave assumed broken. Self-hosted DCAP option for sovereignty.
4.9 Sybil: PERMISSIONED/consortium admission -- a feature for the buyer.

--------------------------------------------------------------------------------
5. MODE 2 -- THE BULK PLANE + NEGOTIATOR
--------------------------------------------------------------------------------
5.1 Why not P2P: a large file has no anonymity set; a GPA correlates "S out of A"
    with "S into B" trivially. Raw rendezvous -> relationship recovered ~100%.
    Hiding the bulk relationship costs the SAME padding the mixnet does. [T]
5.2 The SECURITY DIAL (negotiator picks minimum cost meeting the threat):
    L0 raw rendezvous  : near-line-rate; hides content+setup; EXPOSES relationship.
    L1 bucketed+aligned: partial hiding; improves with concurrency.
    L2 uniform+batched : full relationship hiding (~baseline at k~40 concurrent),
                         WITH relay bulk loop-cover to hold observed flow-count
                         constant (else confirmation succeeds at ~97%). [T]
5.3 Confirmation resistance requires constant observed flow-count via relay bulk
    cover -> a hard FILE-SIZE CEILING: F_max = cover_budget x round_period. [T]
    (10 MB/s x 60s -> 120 MB; 50 MB/s x 5min -> 3 GB; 200 MB/s x 15min -> 36 GB.)
    Above F_max: fragment (pays mixnet-class cost) or accept exposure.
5.4 Negotiator = protocol, not server: end-to-end KEM key agreement (relays/
    scheduler never see key or identities); rotating rendezvous (resist bulk
    intersection); beacon-timed batched-bulk-round timetable that endpoints opt
    into without revealing partners. Its most important function is the BATCHING
    SCHEDULER that manufactures the bulk anonymity set, not hop selection. [R]

--------------------------------------------------------------------------------
6. THE SECURITY-COST MODEL (the most valuable single artifact)
--------------------------------------------------------------------------------
Every defense is priced by the TAIL of the traffic distribution, not the mean:
   send slot 1/tau  ~ PEAK send rate (rho <= 0.7)
   receiver Q       ~ 1.2x sustained mean receiver rate (hard-cap)
   path length L    -> f^L compromise (cheap knob)
   bulk F_max       = cover_budget x round_period
SHAPEABILITY [T]: hard-cap makes SECURITY INVARIANT to traffic shape; non-Gaussian
traffic costs only LATENCY/BANDWIDTH. Cost by marginal CV at the shaping point:
   CV <= 1            -> c <= 1.6 (<=60% overhead)      cheap
   1 < CV <= ~2.5     -> c 2-4 (100-300%)               feasible
   CV > ~4 / inf var  -> unshapeable at bounded cost    (Pareto a<2: segregate)
   rule of thumb: c ~ 1 + CV for finite-variance traffic.
MULTIPLEXING is the friend: aggregating many independent flows shrinks CV ~1/sqrt(n);
strong self-similarity (Hurst 0.9) still multiplexes to CV~0.2 -> shaped for free.
Shape at the AGGREGATE, classify heavy/bulk into Mode 2.

--------------------------------------------------------------------------------
7. PARAMETER BUDGET (worked: coalition telemetry/messaging, 500 endpoints) [T-derived]
--------------------------------------------------------------------------------
  mean 1 msg/s, peak 2 msg/s (shaped), 512B cells, L=4, latency tol ~10s:
    tau = 0.35 s ; send p99 queue ~2.5 s ; mixing ~2 s mean / ~5 s p99
    END-TO-END p99 ~ 7.5 s (within tolerance)
    bandwidth: ~1.4-2.9x send, ~1.2x recv ; aggregate ~0.7 MB/s (trivial)
    relays: 20-40 (4 layers x 5-10), vetted, jurisdiction-distributed
  FEASIBLE. Binding constraint is traffic SHAPEABILITY (Sec 6), not bw/crypto.

--------------------------------------------------------------------------------
8. HONEST BOUNDARIES
--------------------------------------------------------------------------------
- Strong guarantees are INTERNAL (client<->client, both run AEGIS). Clearnet exit
  is a weaker tier (cannot pad an external server). Never sell exit as internal.
- Bulk relationship-hiding is TUNABLE and bounded (F_max ceiling), not free.
- Results are EMPIRICAL BOUNDS under the Sec-2 model, not unconditional proofs.
- Not interactive. Multi-second latency is inherent.

--------------------------------------------------------------------------------
9. TOOL-FIT MATRIX (the honesty that makes it sellable)
--------------------------------------------------------------------------------
  Need                                    Right tool
  Content only, metadata irrelevant       VPN / link encryption
  2 sites, hide op-tempo only             Link-layer traffic-flow security (cheaper,
                                          ~zero latency). AEGIS is OVERKILL here.
  N sites, hide the RELATIONSHIP GRAPH     ===> AEGIS. Nothing cheaper works.
  Open public low-latency anonymity        Tor (NOT metadata-secure vs GPA)
  Open incentivized mixnet                 Nym (public token network)
If the requirement is two-party op-tempo hiding, recommend TFS and walk away. That
credibility is worth more than the sale.

--------------------------------------------------------------------------------
10. BUILD PLAN (each phase = a work session with a hard red-team gate)
--------------------------------------------------------------------------------
P0 Threat model + parameter budget (paper). Gate: params self-consistent. [DONE]
P1 aegis-sim harness: pluggable defenses + adversaries (timing, volume,
   intersection, confirmation, bulk-correlation, bulk-confirmation) as regression
   gates. Gate: reproduces the evidence ledger. [attacks DONE, harness TODO]
P2 Sphinx crypto core (Rust). Gate: test vectors -- replay rejected, tampered
   packet randomized, constant size across path lengths, KAT KEM.
P3 Mix relay + stratified topology (Rust/tokio). Gate: testnet routes Sphinx e2e;
   latency matches P0 budget.
P4 Standing tier: synchronous rounds + hard-cap padding (Mode 1 core). Gate: live
   traffic through the P1 intersection+confirmation adversaries -> baseline. THIS
   gate == the sales demo (Sec 11).
P5 Guards/vanguards, beacon, permissioned admission. Gate: guard-exposure sim
   matches vetted-c plateau (~3%).
P6 Bulk plane + negotiator + batched rounds + relay bulk cover. Gate: bulk-
   correlation and bulk-confirmation sims at chosen dial levels -> target bounds.
P7 Trust/attestation (ZK rep, TEE broken-enclave re-run, Izaac/GRIA anomaly
   detection). Gate: core gates hold with enclave assumed broken.
P8 Hardening + honest characterization: real-trace shapeability (CV/tail at the
   shaping point), adaptive adversary, exit-tier. Gate: documented epsilon per
   tier; zero unclaimed guarantees.

--------------------------------------------------------------------------------
11. THE DEMO THAT CLOSES THE DEAL
--------------------------------------------------------------------------------
Live side-by-side: underlying C2 runs a simulated operational surge (quiet->spike
->quiet). LEFT pane = true application traffic (clear surge). RIGHT pane =
adversary's view of the AEGIS wire = a flat, unchanged wall. "Here is your comms
during the operation. Here is what the adversary sees: nothing moved." The Phase-4
acceptance gate and this demo are the SAME artifact.

--------------------------------------------------------------------------------
12. EVIDENCE LEDGER (every tested claim, traceable)
--------------------------------------------------------------------------------
- Delay alone: 40-100% deanon even at 15s e2e latency (no cover).
- Poisson cover: 0x->8x moved 100%->12%; hard floor ~3x random. (motivated redesign)
- Constant-rate emission: timing 0.86->0.044 (=random); scales to M=100 (0.007).
- Receiver padding (worst-case volume adv): 0.52->0.048.
- Long-term intersection: constant-rate ALONE fails ~25 epochs; hard-cap/Q-high flat
  at baseline through 800 epochs; Q-low fails ~100 epochs.
- Q provisioning (pad-up): safe ~3x mean (~4 sigma); fails 1-2x.
- HARD-CAP: defeats passive+active confirmation at ANY Q>=mean; Q>=1.2x mean stable
  (Q=mean -> 150-epoch backlog). Active confirm: pad-up needs 3x & still weaker.
- Guards: rotating P->1.0; stable plateau 1-(1-c)^g (27% at c=10%; ~3% at c=1%).
- Path compromise f^L: L=4 -> <1% at 30% adversary.
- Queue M/D/1: rho=0.7 p99 7tau; rho=0.95 p99 36tau.
- Shapeability: security invariant to shape; CV<=1 -> c<=1.6; inf-variance
  unshapeable; 25 self-similar sources (H=0.9) -> CV 0.2 -> free.
- Bulk correlation: raw rendezvous ~1.0 recovered; uniform+batched ~baseline at k~40.
- Bulk confirmation: opt-in/const-partic ~0.97; const-count (relay cover) baseline;
  size ceiling F_max = cover_budget x round_period.

--------------------------------------------------------------------------------
13. OPEN ITEMS (do not claim these)
--------------------------------------------------------------------------------
- Adaptive adversary varying the compromised-mix set across epochs. [O]
- Combined active(n-1)+intersection over long horizons on Mode 1. [O]
- Real-trace shapeability (measure CV/tail on actual C2/telemetry, not synthetic). [O]
- Sphinx crypto correctness -- proof/test vectors, not simulation. [O]
- Consortium governance: who runs/vets relays across nations (business/political). [O]
================================================================================
