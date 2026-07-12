================================================================================
   AEGIS — PHASE 0 (parameter budget) + PRODUCT ANALYSIS
================================================================================
Two things locked here: (1) the corrected receiver-padding mechanism and the
parameter envelope it produces, and (2) the honest product definition -- what
AEGIS is, when it is the RIGHT tool, who buys it, and how it fails.

================================================================================
PART A — DESIGN CORRECTION: HARD-CAP RECEIVER PADDING  [TESTED, supersedes v2.2 Rule #1]
================================================================================
The active confirmation attack (adversary suppresses S in chosen epochs and
watches R's observable volume) weaponizes overflow. Result vs padding scheme
(P(confirm S<->R), baseline 0.033, 400 epochs, 50% suppression):

  Q (x mean_bg)   PAD_UP(max(real,Q))   HARD_CAP(=Q always, defer excess)
  1.5x            1.000  (broken)        0.030  (baseline)
  2.75x           0.210                  0.043
  3.1x            0.033                  0.037

HARD_CAP defeats BOTH the passive intersection AND the active confirmation attack
STRUCTURALLY, at ANY Q >= mean, because the observable is exactly Q every epoch --
zero signal to correlate. Excess real traffic (>Q) is deferred to later epochs
(degrade latency, never emission shape). Cost (receiver-side deferral latency):

  Q / real_mean   mean defer     p99 defer
  1.00x           150 epochs     289 epochs   (UNSTABLE -- queue at rho=1)
  1.09x           0.33 epochs    2.25 epochs
  1.20x           ~0             <1 epoch
  1.64x+          ~0             ~0

NEW RULE #1: hard-cap the observable at Q; set Q >= ~1.2x the SUSTAINED mean
receiver rate. Bursts within headroom absorbed as latency; sustained real > Q is a
capacity-planning failure, not a security failure. This is both MORE SECURE and
~2.5x CHEAPER than v2.2's "pad up to 3x mean."

================================================================================
PART B — PHASE 0 PARAMETER ENVELOPE
================================================================================
Derivation (from the cost model; every term traces to a measured result):
  send slot  tau      : keep rho_send = lambda_peak * tau <= 0.7  =>  tau = 0.7/lambda_peak
  send p99 queue      : ~7 tau  (M/D/1 at rho=0.7, measured)
  mixing              : L hops; mean hop delay tuned so L*hop fits latency budget
  receiver quota Q    : >= 1.2x sustained mean receiver rate (hard-cap, measured)
  path length L       : full-path compromise = f^L; L=4 high-threat (measured)
  send bandwidth mult : (1/tau)/lambda_mean = lambda_peak/(0.7*lambda_mean)
  recv bandwidth mult : Q / mean_recv ~ 1.2x

WORKED PROFILE — coalition telemetry/messaging C2:
  N endpoints            500
  mean rate/endpoint     1 msg/s   (shaped)
  peak sustained         2 msg/s   (shaped to 2x mean by design)
  cell                   512 B
  latency tolerance      ~10 s
  path length L          4
DERIVED:
  tau = 0.7/2 = 0.35 s           (slot rate ~2.86 cells/s per client)
  send p99 queue ~ 7*tau ~ 2.5 s
  mixing ~ 2 s mean / ~5 s p99   (mean hop ~0.5 s, Gamma over 4 hops)
  end-to-end p99 ~ 7.5 s          (WITHIN tolerance)
  send bandwidth mult ~ 2.86x     (peak/(0.7*mean); ~1.4x if provisioned to mean)
  recv bandwidth mult ~ 1.2x
  aggregate send ~ 500 * 2.86 * 512 B ~ 0.7 MB/s   (trivial)
  relays ~ 20-40   (4 layers x 5-10, vetted, jurisdiction-distributed)
FEASIBLE. Binding constraint is NOT bandwidth/crypto -- it is whether real traffic
can be SHAPED low-variance. That is reconnaissance (Phase 7), not engineering.

Sensitivity: if peak/mean = 5 (bursty, unshaped), send mult -> ~7x and the case
weakens. Low-variance shaping is the single most important cost lever.

================================================================================
PART C — WHAT THE PRODUCT ACTUALLY IS
================================================================================
AEGIS sells METADATA CONCEALMENT against a nation-state global passive adversary:
hides WHO talks to WHOM, WHEN, and HOW MUCH. Content encryption is assumed already
solved; AEGIS protects the traffic pattern, which is what content crypto leaks.

Killer capability: OP-TEMPO DENIAL. A VPN/link encryptor hides payloads but leaks
"HQ->forward traffic just surged 10x" -- the signal that precedes operations.
AEGIS presents a flat, constant, relationship-opaque wall regardless of underlying
activity. The adversary cannot read operational tempo or command structure off the
comms layer. This is SIGINT denial, not just confidentiality.

================================================================================
PART D — WHEN IS A MIXNET THE RIGHT TOOL? (the honesty that makes it sellable)
================================================================================
A full mixnet is justified ONLY when ALL hold:
  1. MANY endpoints whose RELATIONSHIP GRAPH must be hidden from their traffic.
  2. GLOBAL PASSIVE adversary (sees all links).
  3. Traffic SHAPEABLE to low-variance (or pay the tail cost).
  4. MULTI-SECOND latency acceptable.

TOOL-FIT MATRIX (do not oversell -- an evaluator will test this):
  Need                                      Right tool
  ----                                      ----------
  Content only, metadata irrelevant         VPN / link encryption
  2 sites, hide OP-TEMPO only               Link-layer traffic-flow security (TFS)
                                            = constant-rate encrypted bulk pipe.
                                            ~zero latency, no mixnet. AEGIS overkill.
  N sites, hide the RELATIONSHIP GRAPH       ===> AEGIS. Nothing cheaper works.
  Open, public, low-latency anonymity        Tor (but NOT metadata-secure vs GPA)
  Open, incentivized mixnet                  Nym (public token network)

AEGIS's defensible niche is MULTI-PARTY RELATIONSHIP-HIDING against a GPA for a
PERMISSIONED set of endpoints. If the requirement is two-party op-tempo hiding,
recommend TFS and walk away -- that credibility is worth more than the sale.

================================================================================
PART E — BUYER, DIFFERENTIATION, GO/NO-GO
================================================================================
BUYER: a coalition or agency that runs its OWN relays across member nations. Each
nation operates guards; no single nation sees the whole graph. The permissioned /
vetted / attested / jurisdiction-diverse model IS the sovereignty story, not a
limitation. Natural shape: Five-Eyes-style consortium.

DIFFERENTIATION (vs Tor/Nym/academic/classified COTS):
  - permissioned + vetted + jurisdiction-controlled (no Sybil, known operators)
  - PQ-hybrid onion KEM
  - Izaac/GRIA telemetry anomaly detection as an operational SIGINT-defence layer
  - THE RIGOROUS, MEASURED epsilon-CHARACTERIZATION. Most vendors hand-wave
    "strong anonymity." Handing an evaluator an epsilon-bound per tier, an honest
    tool-fit matrix, and a red-team report documenting WHERE IT FAILS is itself the
    edge with a technical buyer. Rigor is the product.

GO/NO-GO (product risks, in priority order):
  1. Does the buyer's real traffic shape to low-variance?  -> Phase 7 recon on real
     traces. If inherently bursty/unshapeable, cost balloons. HIGHEST risk.
  2. Is multi-second latency acceptable for the target flows? Scope to delay-
     tolerant telemetry/messaging/store-and-forward C2. Not voice/real-time.
  3. Is relationship-hiding across MANY endpoints genuinely required, or would TFS
     suffice? If TFS suffices, no sale (and say so).
  4. Consortium governance: who runs and vets relays across nations? A business/
     political problem, not technical -- but it gates deployment.

================================================================================
PART F — THE DEMO THAT CLOSES THE DEAL
================================================================================
Live side-by-side capture: underlying C2 runs a SIMULATED OPERATIONAL SURGE
(quiet -> spike -> quiet). Show two panes:
  LEFT  : the true application traffic (clear surge).
  RIGHT : the adversary's view of the AEGIS wire -- a flat, constant, unchanged wall.
Caption: "Here is your comms during the operation. Here is what the adversary sees:
nothing moved." One picture proves op-tempo denial better than any spec.
Build this as the Phase-4 acceptance artifact -- the make-or-break gate and the
sales demo are the SAME test.

================================================================================
PART G — UPDATED IMMEDIATE PLAN
================================================================================
- Rule #1 replaced (hard-cap). Update master plan Phase 4 to build hard-cap, not
  pad-up. Q >= 1.2x sustained mean.
- Active confirmation attack: RETIRED at baseline via hard-cap (was open R2).
- Next build step (Phase 1 -> 2): stand up `aegis-sim` with the hard-cap +
  confirmation + intersection adversaries wired in as regression gates, then begin
  the Sphinx crypto core (Phase 2). The Phase-4 gate == the sales demo (Part F).
- Phase 7 recon (real-trace shapeability) is the top PRODUCT risk -- start
  gathering representative traffic profiles in parallel with engineering.
================================================================================
