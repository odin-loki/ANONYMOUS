================================================================================
        AEGIS PROTOCOL v2.0 — REASSESSED ARCHITECTURE & SPECIFICATION
================================================================================
Version: 2.0.0
Class: Continuous-time stratified mix network (Loopix/Nym lineage)
Supersedes: AEGIS v1.0.0 (Tor-cell onion router)
Purpose: Corrected technical blueprint for programmatic ingestion via Cursor/LLM

--------------------------------------------------------------------------------
0. WHAT CHANGED FROM v1 AND WHY
--------------------------------------------------------------------------------

v1 was a low-latency onion router that claimed traffic-analysis resistance and
post-quantum security it could not deliver. v2 resolves the contradiction by
committing to one coherent point in the design space:

  A continuous-time stratified mixnet with Sphinx packets, Poisson mixing, and
  Loopix-style cover traffic — providing PROVABLE unobservability against a
  global passive adversary, at the cost of being a delay-tolerant transport
  (messaging, telemetry backhaul, store-and-forward C2) rather than a
  general-purpose low-latency browser proxy.

Key corrections:
  C1. PQ claim made honest: hybrid X25519 + ML-KEM-768 KEM for onion layers;
      BLS/Groth16 explicitly scoped as non-PQ topology-authentication only.
  C2. Path selection is now FRESH RANDOM per packet (CSPRNG), not a deterministic
      function of a long-term key. The v1 blinding machinery is deleted — Sphinx
      already hides the path from every relay.
  C3. Packet format replaced: Tor-cell -> Sphinx (constant size, position-hiding,
      tagging-resistant, replay-protected).
  C4. Mixing replaced: <50ms Poisson jitter -> independent Exp(mu) per-hop delay
      PLUS three Poisson cover-traffic streams (this is what makes it provable).
  C5. DRB repurposed: no longer churns topology every 10s (which aids intersection
      attacks). It now seeds verifiable cover scheduling and hours-scale committee
      assignment. Clients keep a STABLE entry-guard set.
  C6. Formal adversary model and target properties stated explicitly (Section 1).
  C7. TEE demoted from load-bearing assumption to defense-in-depth (Section 7).

--------------------------------------------------------------------------------
1. THREAT MODEL & SECURITY PROPERTIES (state this first, buyers will demand it)
--------------------------------------------------------------------------------

1.1 Adversary
- Global Passive Adversary (GPA): observes every link, timing, and volume.
- Active fraction: controls up to f of the mixes (default target: any 2 of the
  3 tiers on a path may be honest-but-curious; security degrades gracefully as f
  rises, and is quantified rather than assumed away).
- TEE-compromised variant: assume the enclave is fully broken on compromised
  relays. The base anonymity guarantee must survive this (TEE only raises cost).
- Explicitly NOT defended: an adversary controlling ALL mixes on a client's path,
  or the client endpoint itself.

1.2 Target properties (borrow the AnoA / Loopix framing for credibility)
- Sender unobservability: GPA cannot tell whether a given client is transmitting.
- Sender-receiver unlinkability: GPA cannot link a sender to a receiver.
- Receiver unobservability (optional, via receiver loops).
- Active-attack detection: (n-1)/trickle attacks are detectable via loop traffic.

Each property is tied to an assumption (cover-traffic rates, honest-mix fraction,
mixing parameter mu). Do not claim any property without stating its assumption.

--------------------------------------------------------------------------------
2. CRYPTOGRAPHIC PRIMITIVES & PACKET FORMAT (Sphinx)
--------------------------------------------------------------------------------

2.1 Suite
- Onion KEM (per-hop): HYBRID X25519 + ML-KEM-768. Shared secret =
  KDF(ss_x25519 || ss_mlkem). This is the only credible "PQ" claim in the system.
- Payload wide-block cipher: LIONESS (SHA3-256 + ChaCha20 as the round primitives)
  so any tampering with ciphertext randomizes the whole block (anti-tagging).
- Link encryption (hop-to-hop transport): ChaCha20-Poly1305 AEAD.
- KDF / hashing: SHA3-256 via HKDF.
- Randomness beacon (topology/committee/cover scheduling): threshold BLS on
  BLS12-381 (drand-style). NOTE: NOT post-quantum. Scoped to authenticating
  public network state, never to protecting harvested user traffic.
- ZK reputation: Groth16 or Bulletproofs. Also NOT post-quantum; acceptable
  because it proves relay standing, not traffic content.

2.2 Sphinx packet (replaces the v1 Aegis Cell)
Constant total size for ALL packets regardless of path length. Layout (conceptual):

  +-------------------------------------------------------------------+
  | alpha  (32B)  | group element (X25519 pub for this hop's KEM)     |
  | beta   (var)  | encrypted routing header (next hop + per-hop MAC)  |
  | gamma  (16B)  | HMAC over beta (integrity, prevents tagging)       |
  | delta  (fixed)| LIONESS-encrypted payload (fixed length)           |
  +-------------------------------------------------------------------+
  (Hybrid note: alpha additionally carries an ML-KEM-768 ciphertext; the header
   budget must be sized for the larger PQ ciphertext up front.)

Each mix:
  1. Derives shared secret from alpha (hybrid KEM) using its private key.
  2. Verifies gamma over beta. If MAC fails -> DROP (tagging attempt).
  3. Checks replay cache: if this packet's tag was seen this epoch -> DROP.
  4. Peels one layer of beta/delta, blinds alpha for the next hop.
  5. Applies the mixing delay (Section 4), then forwards.

This gives: constant size (no length fingerprint), no CircuitID linkage across
packets, per-hop bitwise unlinkability, integrity against tagging, and replay
protection. All four were missing or broken in v1.

--------------------------------------------------------------------------------
3. STRATIFIED TOPOLOGY & THE (REPURPOSED) RANDOMNESS BEACON
--------------------------------------------------------------------------------

3.1 Topology
Stratified into L layers (default L=3: Ingress / Mix / Egress). A packet visits
exactly one node per layer. Layers are fully connected between adjacent tiers.
Topology membership is STABLE across a long epoch (hours), with slow relay churn.
This directly resists the intersection attacks that v1's 10s churn accelerated.

3.2 Node scoring (unchanged formula, hardened measurement)
  S_i = w1*U_i + w2*log2(B_i) + w3*J_i,  sum(w)=1.0
The vulnerability is not the formula, it is TRUSTING B_i. Bandwidth self-reporting
is the single most-attacked part of Tor. Mandate ACTIVE adversarial measurement
(FlashFlow/sbws-style) with cross-validation across dirauths; never trust a relay's
self-reported throughput.

3.3 Beacon (drand-style threshold BLS), repurposed
  Epoch_Message = "AEGIS_BEACON_" + Epoch_Index
  Each dirauth i: Sig_i = BLS_Sign(sk_i, Epoch_Message)
  If |shares| >= t (e.g. 67/100):
     Seed = BLS_Aggregate(shares); assert BLS_Verify(PK, Seed, Epoch_Message)
     Broadcast Seed
  Else: halt, invoke fallback consensus.

Seed is now used for: (a) publicly-verifiable cover-traffic scheduling, (b)
hours-scale committee/shard assignment, (c) tie-breaking in relay set selection.
It is NOT used to make client paths deterministic and NOT used to churn topology
every 10s. Threshold raised to a supermajority (67) to survive a larger malicious
minority than v1's bare 51.

--------------------------------------------------------------------------------
4. MIXING: POISSON DELAY + THREE COVER STREAMS (the real anonymity engine)
--------------------------------------------------------------------------------

4.1 Per-hop mixing delay
Each mix independently delays each packet by an exponential draw:
  delay ~ Exp(mu)      # mu tuned to the latency budget, NOT capped cosmetically
Interactive-ish profile: mean ~65ms/hop -> ~200ms end-to-end over 3 hops.
Delay-tolerant profile: seconds-to-minutes for maximal anonymity set.
The delay only buys anonymity BECAUSE of the cover traffic below — an empty mix
cannot mix. State this honestly.

4.2 The three cover streams (this is the Loopix core v1 was groping toward)
- Client LOOP cover (rate lambda_L): client sends packets addressed to ITSELF
  through the network. Provides sender unobservability and lets the client detect
  (n-1) attacks (a dropped loop = someone is flushing the mix).
- Client DROP cover (rate lambda_D): packets to random destinations, discarded at
  egress. Fills the sender's output process.
- Mix LOOP cover (rate lambda_M): each mix sends loops to itself, guaranteeing every
  mix always carries traffic even at zero user load. THIS is the provable noise
  floor — v1's "increase loops if density drops" heuristic is replaced by a fixed
  Poisson rate so the mix's output is a Poisson process independent of real load.

Property: total output of each mix is Poisson(lambda_real + lambda_cover) shaped to
a constant rate -> the GPA cannot distinguish real from cover, at any load.

--------------------------------------------------------------------------------
5. CLIENT PATH SELECTION (fresh random — the v1 bug, fixed)
--------------------------------------------------------------------------------

import os, secrets

class AegisPathSelector:
    """Fresh random, capacity/trust-weighted selection per PACKET.
       No long-term key, no reproducibility, no deterministic profiling surface."""

    def __init__(self, network_topology, guard_set):
        self.topo = network_topology
        # Stable per-client entry guards (slow rotation, Tor-style) resist the
        # predecessor/long-term-intersection attack at the entry.
        self.guard_set = guard_set

    def select_path(self):
        path = []
        # Layer 1: draw from the client's stable guard set (not the whole tier).
        path.append(self._weighted_choice(self.guard_set))
        # Layers 2..L: fresh weighted-random per packet.
        for layer in self.topo.middle_and_exit_layers():
            path.append(self._weighted_choice(self.topo.nodes_in(layer)))
        return path

    def _weighted_choice(self, candidates):
        # CSPRNG, NOT a reproducible stream. Weighted by verified score S_i.
        r = secrets.randbelow(2**64) / (2**64)
        total = sum(n.score for n in candidates)
        acc = 0.0
        for n in candidates:
            acc += n.score / total
            if r <= acc:
                return n
        return candidates[-1]

--------------------------------------------------------------------------------
6. RELAY PROCESSING LOOP (Sphinx-aware, replay + tagging safe)
--------------------------------------------------------------------------------

import random, math, asyncio

async def process_packet(pkt, node):
    # 1. Hybrid KEM: derive shared secret from pkt.alpha.
    ss = node.hybrid_kem_decap(pkt.alpha)          # X25519 || ML-KEM-768
    # 2. Integrity: verify gamma over beta. Fail -> silent drop (tagging attempt).
    if not node.verify_mac(pkt.gamma, pkt.beta, ss):
        return
    # 3. Replay protection: per-epoch seen-tag cache.
    if node.replay_cache.seen(pkt.tag()):
        return
    node.replay_cache.add(pkt.tag())
    # 4. Peel one layer; determine next hop and command.
    next_hop, cmd, pkt2 = node.peel(pkt, ss)
    # 5. Loop/drop cover handling.
    if cmd == "LOOP_TO_SELF" and next_hop == node.id:
        node.register_own_loop_returned(pkt2)      # (n-1) attack detector
        return
    if cmd == "DROP":
        return
    # 6. Poisson mixing delay, then forward.
    u = random.random()
    delay = -math.log(1.0 - u) / node.mu           # Exp(mu); mu is tunable, uncapped
    await asyncio.sleep(delay)
    await node.forward(pkt2, next_hop)              # ChaCha20-Poly1305 link layer

--------------------------------------------------------------------------------
7. TRUST: SYBIL RESISTANCE, ZK REPUTATION, AND TEE AS DEFENSE-IN-DEPTH
--------------------------------------------------------------------------------

7.1 Sybil resistance — pick a model explicitly (v1 had none)
- PERMISSIONED / consortium relay set: vetted operators, known jurisdictions.
  For a sovereign or coalition defence deployment this is a FEATURE — it kills
  most Sybil and bandwidth-gaming attacks outright. Recommended default.
- Open + bonded: stake/bond per relay (Nym model) with slashing on misbehavior.
- Reputation-weighted (below) layered on either of the above.

7.2 ZK reputation (kept, correctly scoped)
Relay proves "my score exceeds threshold" without revealing exact metrics or
identity, via a Groth16/Bulletproof commitment: C = Hash(Rep || blinding). Note
this is non-PQ and authenticates standing only, never traffic.

7.3 TEE — demoted to defense-in-depth
The anonymity guarantee (Sections 4-5) must hold even if the enclave is fully
compromised. TEE then ADDS: sealed key storage, attested code, resistance to a
relay operator passively reading state. It is NOT the root of security.
Caveats to document for the buyer:
- SGX/SEV-SNP have a long side-channel history (Foreshadow, Plundervolt, SEV-SNP
  ciphertext side channels). Do not present the enclave as unbreakable.
- Remote attestation depends on the chip vendor's attestation service (Intel DCAP,
  AMD KDS). For a sovereign customer this is a supply-chain dependency on a foreign
  chipmaker — flag it early, offer a self-hosted DCAP caching option.

--------------------------------------------------------------------------------
8. WHERE THE PORTFOLIO ACTUALLY PLUGS IN (honest fit, not shoehorned)
--------------------------------------------------------------------------------

- Beacon: threshold BLS (drand) is the correct, provably-unbiasable primitive.
  Izaac would have to BEAT it on a specific axis to justify replacing it; do not
  swap it in by default.
- Strong Izaac/GRIA fit: relay-telemetry anomaly detection. Apply the algebraic
  sequence-fingerprinting + GRIA-alpha edge-of-chaos scoring to relay traffic and
  timing signatures to flag Sybil clusters, bandwidth liars, and (n-1) attackers.
  This is a genuine differentiator in your wheelhouse and lives OUTSIDE the crypto
  core, so it can't weaken the anonymity guarantee if it's wrong.

--------------------------------------------------------------------------------
9. IMPLEMENTATION ROADMAP (Rust/tokio recommended over Python for the datapath)
--------------------------------------------------------------------------------

Phase 1  /src/crypto/    Sphinx (hybrid X25519+ML-KEM-768 header, LIONESS payload,
                         replay cache, tagging-safe MAC). ChaCha20-Poly1305 link.
Phase 2  /src/topology/  Stratified L-tier topology; AegisPathSelector (fresh
                         random); stable guard sets; active bandwidth measurement.
Phase 3  /src/mixing/    Exp(mu) per-hop delay; the three Poisson cover streams;
                         loop-return accounting for active-attack detection.
Phase 4  /src/beacon/    Threshold-BLS drand-style beacon; cover scheduling and
                         committee assignment (NOT topology churn, NOT path determinism).
Phase 5  /src/trust/     Permissioned/bonded Sybil model; ZK reputation; TEE
                         attestation as defense-in-depth with self-hosted DCAP option.
Phase 6  /src/analytics/ Izaac/GRIA telemetry anomaly detection (out-of-core-path).

--------------------------------------------------------------------------------
10. THE STRATEGIC CALL (read before you build)
--------------------------------------------------------------------------------

This v2 is more buildable AND more defensible than v1, but it is a MIXNET, not a
Tor-browser replacement. The single most important decision is accepting that
repositioning: sell it as unobservable messaging / telemetry backhaul / delay-
tolerant C2 for a permissioned coalition relay set — a story a procurement
evaluator can believe — rather than a "stronger anonymous internet," a claim their
technical reviewers will (correctly) tear apart on the low-latency-vs-GPA point.
================================================================================
