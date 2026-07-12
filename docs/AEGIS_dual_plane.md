================================================================================
   AEGIS — DUAL-PLANE ARCHITECTURE: shaped mode + bulk mode + negotiator
================================================================================
Resolves the bulk / infinite-variance problem via a CONTROL-PLANE / DATA-PLANE
split. Control + small data ride the shaped mixnet (Mode 1). Bulk is negotiated
per-transfer over a separate path (Mode 2) with an explicit security dial.
Analogous to Tor rendezvous / SIP signaling-vs-media. Every claim below is tagged
TESTED or REASONED.

--------------------------------------------------------------------------------
1. THE TWO MODES
--------------------------------------------------------------------------------
MODE 1 — SHAPED (small/bursty data + ALL control/negotiation)
  - The constant-rate hard-cap mixnet already specified (v2..v2.2 + hard-cap).
  - Carries: telemetry, messages, and every negotiation/control message.
  - Low-CV traffic -> multiplexes to CV<1 -> cheap to shape (<=60% overhead).
  - Property: the COORDINATION/COMMAND GRAPH (who directs whom) is fully hidden
    here at full strength and near-zero marginal cost. This is the crown jewel.

MODE 2 — BULK (large files)
  - NOT forced through Mode 1 (bulk is infinite-variance -> unshapeable there).
  - Negotiated per-transfer path with a SECURITY DIAL (Section 3).
  - Removing bulk from Mode 1 makes Mode 1 STRICTLY better: no infinite-variance
    contamination, no head-of-line blocking. [TESTED: shapeability analysis]

--------------------------------------------------------------------------------
2. WHY BULK CANNOT JUST GO P2P  [TESTED — corrects "shortest hop = better"]
--------------------------------------------------------------------------------
A large file has almost NO anonymity set: it is big, distinctive, and rare. A
global passive adversary correlates "S bytes out of A" with "S bytes into B"
trivially, even through a rendezvous. Measured P(relationship recovered),
k concurrent transfers, baseline 1/k:
   defense                 k=10   k=20   k=40
   raw rendezvous          1.00   1.00   1.00
   size-bucketed           0.99   0.98   0.96
   bucketed + round-align   0.75   0.55   0.32
   uniform (pad-to-max +
     single round)          0.11   0.05   0.03   (~baseline)
CONCLUSION: hiding the bulk RELATIONSHIP costs the SAME padding the mixnet costs
(uniform size + synchronized rounds), and needs ~tens of concurrent transfers to
form an anonymity set. P2P does not escape this cost -- it relocates it. What P2P
DOES buy: content is encrypted (safe on any path) and the SETUP is hidden (Mode 1),
forcing the adversary from targeted to BLANKET correlation. [REASONED]

--------------------------------------------------------------------------------
3. THE NEGOTIATOR (a PROTOCOL, not a server) + the SECURITY DIAL
--------------------------------------------------------------------------------
Runs end-to-end over Mode 1. No third party ever learns the A<->B pairing:
  - Key agreement END-TO-END (piggyback the hybrid X25519+ML-KEM KEM). Rendezvous
    relays and schedulers never see the key or the identities.
  - Rendezvous points ROTATE per transfer (resist intersection on the bulk plane,
    same logic as guard/intersection analysis).
Per transfer it selects the MINIMUM-COST configuration that meets the required
unlinkability -- "shortest path consistent with the threat model", NOT shortest
absolute:

  DIAL LEVEL 0 -- raw rendezvous / near-P2P
    speed: near-line-rate. hides: content + setup. EXPOSES: bulk relationship to GPA.
    use when relationship-hiding for THIS transfer is not required.
  DIAL LEVEL 1 -- size-bucketed + round-aligned
    partial relationship-hiding; improves with concurrency; moderate overhead.
  DIAL LEVEL 2 -- uniform-padded + batched bulk rounds
    full relationship-hiding (~baseline at k~40). costs like the mixnet.
    use for the highest threat / most sensitive transfers.

Negotiator inputs: file size, threat level, latency budget, and CURRENT concurrent
bulk demand (for batching). Output: dial level, rendezvous point(s), hop count,
pad size bucket, and bulk-round assignment.

--------------------------------------------------------------------------------
4. THE KEY ENABLER: BATCHED BULK ROUNDS (manufacture the anonymity set)  [TESTED]
--------------------------------------------------------------------------------
Rare large flows have no natural anonymity set. The negotiator MANUFACTURES one by
aggregating concurrent bulk demand into scheduled BULK ROUNDS (e.g. every T_bulk
minutes, beacon-scheduled public timetable) where multiple transfers run together,
each padded to a common size bucket. Endpoints opt into a round without revealing
their partner. Measured: uniform padding + batching reaches ~baseline at k~40.
This scheduler -- not hop selection -- is the negotiator's most important function.

--------------------------------------------------------------------------------
5. HONEST SECURITY ACCOUNTING (what is hidden vs tunable)
--------------------------------------------------------------------------------
ALWAYS HIDDEN (full strength, cheap):
  - Content (both modes; ordinary + PQ-hybrid encryption).
  - Coordination/command graph and all small-data relationships (Mode 1).
  - The FACT and PARTIES of a pending bulk transfer (setup hidden in Mode 1).
TUNABLE (negotiator dial, priced per transfer):
  - The bulk-transfer RELATIONSHIP (Level 0 exposed -> Level 2 hidden).
EXPOSED unavoidably at Level 0:
  - That a large volume moved between two endpoints (to a GPA), though not its
    content, context, or coordination.
Product framing: hide the command graph at full strength always; make bulk
relationship-hiding a deliberate, per-transfer, threat-matched expense.

--------------------------------------------------------------------------------
6. "FASTER BOTH WAYS" -- adjudicated  [REASONED]
--------------------------------------------------------------------------------
- Mode 1 faster: YES, unambiguous (decontaminated of bulk; no HOL blocking).
- Bulk faster: YES vs forcing bulk through Mode 1's tiny constant-rate slots
  (which would be glacial). Bulk speed then trades against the chosen dial level:
  Level 0 ~ line rate; Level 2 ~ mixnet-class. The negotiator makes that trade
  explicit and per-transfer rather than one-size-fits-all.

--------------------------------------------------------------------------------
7. ATTACKS ON THE BULK PLANE (do not forget these)
--------------------------------------------------------------------------------
- Confirmation via suppression: adversary suppresses A, watches if a bulk flow to
  B stops. Bulk is not hard-capped (variable by nature) -> vulnerable at Levels
  0-1. Mitigation: Level 2 batched rounds + rendezvous rotation.
- Intersection over repeated transfers between the same pair via a common RP ->
  rotate rendezvous; prefer batched rounds; cap repeat frequency per pair.
- Rendezvous relay as observer: learns only "two anonymous parties meet here",
  never identities or key (end-to-end).

--------------------------------------------------------------------------------
8. IMPLICATIONS FOR THE PLAN
--------------------------------------------------------------------------------
- Add MODE 2 + negotiator as a distinct subsystem (/src/bulk, /src/negotiator).
- The negotiator is protocol-only, end-to-end over Mode 1; no omniscient server.
- Batched-bulk-round scheduler is a first-class component (beacon-timed timetable).
- New regression gates in aegis-sim: bulk-correlation vs dial level and k;
  bulk confirmation + intersection over repeated transfers.
- Product line: sell Mode 1 (command-graph concealment) as the core guarantee;
  present Mode 2 as a threat-matched bulk option with an explicit, measured dial --
  never as "anonymous fast file transfer for free."
================================================================================
