================================================================================
   AEGIS v2.2 — LONG-TERM INTERSECTION FINDINGS & CORRECTED PRIORITIES
================================================================================
This addendum revises v2.1 in light of the long-term intersection (statistical
disclosure) attack. It reprioritizes the v2.1 defenses and adds two hard
provisioning rules. Where this conflicts with v2.1, v2.2 wins.

--------------------------------------------------------------------------------
0. THE CENTRAL DISCOVERY: single-window anonymity != long-term anonymity
--------------------------------------------------------------------------------
v2.1's headline result (constant-rate emission drives the timing attack to the
random baseline, 0.86 -> 0.044) was measured over a SINGLE observation window.
The long-term intersection attack observed a persistent, fixed sender->receiver
pair over many epochs and found:

  Config                              epochs to full deanonymization
  A. Poisson cover                    ~100 epochs   (P: 0.27@5 -> 1.0@100)
  B. constant-rate ONLY               ~25 epochs    (P: 0.59@5 -> 1.0@25)  << WORSE
  C. const-rate + padding (Q high)    NEVER          (flat at 0.04 baseline @800)
  D. const-rate + padding (Q too low) ~100 epochs   (overflow leaks, compounds)

Constant-rate emission alone is not merely insufficient over time -- it fails
FASTER than Poisson cover. Reason: constant-rate perfectly hides S's TIMING, but
S's real traffic still lands at R as a persistent VOLUME surplus (R's mean
arrival count = background + S's rate). A cumulative mean-shift statistic
accumulates that surplus cleanly, reaching certainty in ~25 epochs. The
single-window test could not see a per-epoch signal this small; hundreds of
epochs integrate it to 1.0.

--------------------------------------------------------------------------------
1. CORRECTED PRIORITY: receiver padding (D2) is the PRIMARY defense
--------------------------------------------------------------------------------
v2.1 billed D1 (constant-rate) as primary and D2 (receiver padding) as worst-case
cleanup. The intersection attack REVERSES this for any persistent relationship:

  - D2 (receiver volume padding) is the load-bearing long-term defense. Properly
    provisioned it defeats intersection FLAT, forever (config C, 0.04 @ 800 epochs).
  - D1 (constant-rate emission) remains necessary -- it kills the timing channel
    and hides WHEN S sends -- but it is SECONDARY and insufficient alone.
  - Both are required. Neither alone survives a global passive adversary over time.

--------------------------------------------------------------------------------
2. PROVISIONING RULE #1 -- the receiver quota Q  [TESTED]
--------------------------------------------------------------------------------
Padding pads UP to Q; it can NEVER hide an epoch where real volume exceeds Q. Any
overflow epoch leaks, and rare leaks compound over hundreds of epochs. Measured
disclosure at E=200 vs quota (background mean = 8/receiver):

  Q / mean_bg     disclosure@200
  1.0 - 2.0x      1.00   (fails completely)
  2.25x           0.85
  2.5x            0.54
  2.75x           0.23
  3.1x            0.036  (random baseline -- SAFE)
  3.75x           0.032

RULE: set Q at ~3x the mean receiver volume, i.e. roughly 4 sigma above the mean,
so virtually every real epoch is clamped. Q at 1-2x mean is worthless. Cost: the
quota is billed in bandwidth to every active receiver every epoch regardless of
real traffic -- so the design is priced by the TAIL of the receiver-volume
distribution, not the mean. Heavy-tailed / bursty receiver traffic is expensive
or insecure; shape traffic to be low-variance where possible.

--------------------------------------------------------------------------------
3. PROVISIONING RULE #2 -- constant-rate utilization  [TESTED]
--------------------------------------------------------------------------------
Constant-rate emission is an M/D/1-style queue (one cell per slot tau, Poisson
real arrivals). Queueing wait vs utilization rho = real_rate * tau:

  rho     mean wait   p99 wait
  0.50    1.0 tau     3.9 tau
  0.70    1.7 tau     7.1 tau
  0.90    5.0 tau     23 tau
  0.95    9.1 tau     36 tau

RULE: keep rho <= ~0.7. Above that the latency tail explodes. So the slot rate
1/tau must be provisioned well above MEAN real traffic -- again pricing the design
by the peak, not the mean, and burning the slack as dummy bandwidth. Burst
overflow policy must degrade LATENCY (deeper queue), never the emission shape.

--------------------------------------------------------------------------------
4. WHAT SCALES / WHAT DOESN'T
--------------------------------------------------------------------------------
- Constant-rate timing defense SCALES: single-window match accuracy stays at the
  1/M baseline through M=100 (0.047 -> 0.010 -> 0.007). Not a small-M artifact.
- Full-path compromise still f^L (v2.1 D5); unaffected.
- The intersection defense (padding) does NOT scale for free: its cost grows with
  the tail of the per-receiver volume distribution and with the number of active
  receivers that must be padded each epoch.

--------------------------------------------------------------------------------
5. UNIFYING INSIGHT & CONVERGENT DESIGN
--------------------------------------------------------------------------------
Every measured defense in this class is priced by the TAIL of the traffic
distribution: receiver quota Q ~ peak receiver volume; slot rate 1/tau ~ peak send
rate. The mean is almost irrelevant to security; the peak sets both cost and
safety. Two consequences:

(a) Shape traffic to be low-variance BEFORE it enters the anonymity layer.
    A bounded, near-constant application traffic profile is dramatically cheaper
    to protect than a bursty one. This should be an explicit product constraint,
    not an afterthought.
(b) For persistent, high-value relationships the design converges on SYNCHRONOUS
    CONSTANT-RATE ROUNDS on BOTH ends (send AND receive) -- the Vuvuzela/Karaoke
    class -- because that is exactly what makes both the send-timing AND the
    receive-volume observably constant. The v2 "max-security internal tier" is
    therefore not optional flavour; it is the only configuration that provably
    survives long-term intersection. Specify it as the default for standing C2 /
    standing telemetry links, and reserve the lighter asynchronous tier for
    short-lived or low-sensitivity flows.

--------------------------------------------------------------------------------
6. REVISED HONEST CLAIM (what you may tell an evaluator)
--------------------------------------------------------------------------------
INTERNAL tier, synchronous constant-rate rounds, Q >= ~3x mean receiver volume,
rho <= 0.7, L=4, vetted layered guards:
  - Timing, worst-case volume, AND long-term intersection adversaries held at the
    random baseline in simulation (through 800 epochs for intersection).
  - This is an empirical bound under a global-passive + f-fraction-compromised
    model, not an unconditional proof.
Costs: fixed bandwidth provisioned to peak send AND receive volume; multi-second
latency (queue wait <=~7 tau at rho=0.7, plus L hop-mix delays); requires
low-variance traffic shaping to be economical.
DISQUALIFIED: bursty traffic at acceptable cost; clearnet-exit traffic (receiver
padding cannot apply to an external server); any interactive low-latency use.

--------------------------------------------------------------------------------
7. REMAINING OPEN (still not solved -- do not claim these)
--------------------------------------------------------------------------------
- Active (n-1)/flooding attack over long horizons combined with intersection.
- Adversary who adaptively varies the compromised-mix set across epochs.
- Traffic-shaping the application layer to hit the low-variance profile in
  practice (measured on real C2/telemetry traces, not synthetic Poisson).
- Sphinx crypto correctness (replay/tagging) -- proof/test vectors, not simulation.
================================================================================
