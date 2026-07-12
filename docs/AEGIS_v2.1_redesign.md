================================================================================
     AEGIS v2.1 — RED-TEAM-DRIVEN REDESIGN (empirically grounded delta)
================================================================================
Supersedes selected mechanisms of AEGIS v2.0. Every change below is tied to a
measured result from the red-team simulation, not to intuition. Feed this to
Cursor alongside AEGIS_v2.md; where they conflict, v2.1 wins.

--------------------------------------------------------------------------------
0. WHAT THE RED-TEAM PROVED (the five load-bearing facts)
--------------------------------------------------------------------------------
L1. Mixing DELAY is not a security primitive. With zero cover, a global passive
    adversary matched 25 senders->receivers at 40-100% accuracy even at 15s
    end-to-end latency (random = 4%). Delay only buys time for cover to work.
L2. The leak is the SENDER'S EMISSION PROCESS, not per-message timing. Mixing
    scrambles individual messages; the statistical shape of how a client emits
    survives and is what the adversary exploits.
L3. Poisson cover works but has sharp diminishing returns and a hard floor:
    0x->8x cover moved deanon 100%->12%, never to the 4% random baseline.
    Residual ~3x advantage remained. More cover != structured cover.
L4. Rotating guards -> certain exposure over time (P->1.0). Stable guards ->
    bounded exposure, plateau 1-(1-c)^g (=27% at c=10%, g=3), never rising.
    The lever that matters is lowering effective c at the guard.
L5. Real anonymity costs ~O(bandwidth) in cover and O(seconds) in latency.
    This forces delay-tolerant positioning. Physical, not fixable.

--------------------------------------------------------------------------------
1. D1 — CONSTANT-RATE EMISSION (replaces Poisson cover)   [TESTED: 0.86 -> 0.044]
--------------------------------------------------------------------------------
Mechanism: each client emits exactly one fixed-size cell every slot tau. If a
real cell is queued, send it; otherwise send an indistinguishable dummy. Dummies
are dropped inside the network (loop) or at egress (drop). tau is identical and
public for all clients in a service class.

Why it beats Poisson cover: every client's emission process becomes byte-for-byte
identical and load-independent, so the entry link carries ZERO sender-side signal
(neither timing nor volume, since dummies mask real count). This directly kills
L2. Measured: the timing-correlation attack fell from 0.860 (Poisson cover, same
bandwidth) to 0.044 -- the 4% random baseline. Sender unobservability at the entry
becomes information-theoretic rather than statistical.

Parameters:
- tau chosen per service class from the latency/bandwidth budget (Section 5).
- Bursts above 1/tau are QUEUED (bounded buffer); queue overflow degrades latency,
  never anonymity. Never emit faster than tau to "catch up" -- that reintroduces
  the emission signature.

Cost (honest): fixed bandwidth ALWAYS, even when idle. Queueing latency under
burst. This is the price of L2/L3 and is acceptable for delay-tolerant transport.

--------------------------------------------------------------------------------
2. D2 — RECEIVER QUOTA PADDING (internal traffic)          [TESTED: 0.52 -> 0.048]
--------------------------------------------------------------------------------
Residual after D1: a worst-case adversary handed each sender's TRUE real volume
could still match on receiver arrival COUNT (volume adversary: 0.524).
Mechanism: every receiver in the internal service class is filled to a fixed
per-epoch quota Q with indistinguishable recipient dummies, so all receivers show
identical arrival volume. Q must exceed peak real receiver volume (a quota BELOW
the mean is a no-op -- verified failure mode in testing).
Measured: volume adversary fell from 0.524 to 0.048 (random). Combined with D1,
BOTH the timing and worst-case volume adversaries are driven to the baseline.
Cost: extra egress bandwidth to every active receiver. Applies to INTERNAL
(client<->client) traffic only; see D6.

--------------------------------------------------------------------------------
3. D3 — VETTED, JURISDICTION-DIVERSE GUARDS               [reasoned from Attack B]
--------------------------------------------------------------------------------
L4 says the plateau is 1-(1-c)^g. The lever is c, not g. A permissioned/vetted
relay set (already the recommended Sybil model) lets you drive the effective
guard-adversary fraction from ~10% toward ~1%:
   c=10%, g=3 -> plateau 27.1%   (open network)
   c= 1%, g=3 -> plateau  3.0%   (vetted guards)
Add hard jurisdiction diversity in the guard set (no two guards in one AS/ISP/
nation) so a single legal authority cannot compel a client's whole guard set.

--------------------------------------------------------------------------------
4. D4 — LAYERED GUARDS / VANGUARDS                        [reasoned]
--------------------------------------------------------------------------------
Stable guards at the ENTRY layer alone still expose the 3-27% who drew a bad
guard. Borrow Tor's vanguard design: maintain stable guard sets at layers 1 AND 2
with different (slow) rotation periods. A single malicious guard then sees only
one hop of the path and cannot deanonymize alone; deanonymization now requires
compromising a guard at multiple layers simultaneously, which is c^2 per client,
not c. Turns the 27% single-point entry exposure into a much smaller joint event.

--------------------------------------------------------------------------------
5. D5 — DEFAULT L=4 FOR HIGH-THREAT PROFILE               [TESTED: f^L curve]
--------------------------------------------------------------------------------
Full-path compromise = f^L (measured). At 30% adversary: L=3 -> 2.7%, L=4 -> 0.8%.
Because the latency budget is already dominated by constant-rate slotting and
mixing (multi-second), the marginal latency of a 4th hop is cheap relative to the
compromise reduction. Default: L=3 standard, L=4 high-threat, L=2 never.

--------------------------------------------------------------------------------
6. D6 — TWO SERVICE CLASSES (the honest boundary)         [reasoned]
--------------------------------------------------------------------------------
INTERNAL (client <-> client, both run AEGIS):
  D1 + D2 apply fully. Timing AND volume adversaries -> random baseline (tested).
  This is the strong product. Target it: unobservable messaging, telemetry
  backhaul between owned endpoints, store-and-forward C2 between AEGIS nodes.
EXIT (client -> clearnet server):
  D1 protects the sender side. D2 CANNOT apply -- an external web server will not
  emit recipient dummies -- so the exit->destination volume/timing leaks to a GPA
  watching that server. Document this as a weaker tier. Do not sell exit traffic
  as carrying the internal guarantee.

--------------------------------------------------------------------------------
7. PARAMETERS & THE FORMAL BUDGET (replace "use lots of cover")
--------------------------------------------------------------------------------
Stop specifying cover as a ratio. Specify a target adversary advantage epsilon and
derive parameters:
- Pick epsilon (max tolerable deanonymization advantage over random).
- D1 sets sender-side leak to ~0 by construction (identical emission). The
  residual is dominated by (a) honest-mix fraction via f^L and (b) exit-tier
  observability (D6). Size L so f^L < epsilon for your assumed f. Size the
  internal quota Q above peak volume so receiver-count leak < epsilon.
- Report the residual per tier. Never claim zero: the internal tier reaches the
  random baseline in simulation, but that is an empirical bound under this
  adversary model, not a proof of unconditional anonymity.

Cost summary (internal, high-threat):
  bandwidth : fixed at 1/tau per client + receiver quota Q  (constant, load-indep)
  latency   : L * mean-hop-mix + constant-rate queueing under burst  (multi-second)
  security  : timing + worst-case volume adversary at random baseline (tested);
              full-path compromise f^L (L=4 -> <1% at 30% adversary)

--------------------------------------------------------------------------------
8. STILL OPEN (do not pretend these are solved)
--------------------------------------------------------------------------------
- Exit-tier leak (D6) is fundamental, not engineered away.
- Long-term intersection on the INTERNAL tier: tested single-window; a persistent
  fixed sender<->receiver relationship over very many epochs should be simulated
  before claiming the random-baseline result holds asymptotically.
- Constant-rate under heavy real load: queueing latency behaviour needs a real
  buffer-sizing study; overflow policy must degrade latency, never emission shape.
- Crypto layer (Sphinx replay/tagging) is unaffected by this delta and still needs
  proof/test-vector validation, not simulation.
================================================================================
