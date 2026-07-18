//! Relay bulk cover-flow generation (spec §5.2 L2 uniform+batched, §5.3).
//!
//! [`aegis_negotiator::cover`] computes how many synthetic flows a relay must inject;
//! this module generates and accounts for them.
//!
//! ## Flow definition (this layer)
//!
//! [`crate::RelayNode`] receives traffic as reassembled [`aegis_crypto::sphinx::SphinxPacket`]s
//! (after link-layer fragmentation is undone upstream). We treat **one Sphinx packet = one
//! bulk flow**, which corresponds to one [`aegis_crypto::fragment::PacketId`]-correlated
//! fragment stream on the wire.
//!
//! ## Round definition
//!
//! A bulk round is an explicit counting window opened by [`BulkRoundCommand::Begin`] and
//! closed by [`BulkRoundCommand::EndRound`]. Real flows observed while the window is open
//! are counted; at close the relay emits synthetic cover flows so the observed total
//! reaches [`CoverRequirement::target_flow_count`] (baseline), or a matched/scaffold/onion
//! plan under [`CoverMultihopDefense`].
//!
//! ## Cover flow shape
//!
//! Baseline / matched / scaffold cover is a bounded burst of
//! [`aegis_crypto::cell::Command::SphinxFragment`] cells — same command byte and
//! [`SPHINX_FRAGMENT_COUNT`] as real bulk — with a random [`PacketId`] and CSPRNG payload
//! slots tagged by reserved markers. Peelable [`CoverMultihopDefense::CoverOnions`] flows
//! are **valid Sphinx** fragments (reserved zero) built to a terminal hop then
//! [`COVER_SINK_HOP_ID`].
//!
//! ## Honest limitation
//!
//! Cover padding holds **observed flow count and per-flow cell volume** at this relay,
//! and each cover cell is a fixed-width AEAD link frame indistinguishable in length from
//! real traffic. Local-discard cover (`COVER_FRAGMENT_RESERVED` /
//! `COVER_ONION_SCAFFOLD_RESERVED`) never reaches peel. Peelable cover onions restore
//! **one hop** of Sphinx peel-then-sink continuity when a terminal peer KEM public is
//! configured; they are **not** real client exit traffic (payload discarded at the sink
//! hop id). Residual: full multi-hop forwardable cover onions and info-theoretic
//! indistinguishability are not claimed.
//!
//! ## Multi-hop defense (wave A3 / B1 productization)
//!
//! Sim ranking in `sim/aegis_sim/cover_multihop_defense.py` prefers **cover onions**
//! (peel/forward then sink) to raise `implied_packet_continuity` toward Sphinx, with
//! **matched local discard** as the low-risk ops lever. Product ships:
//! - [`CoverMultihopDefense::MatchedLocalDiscard`] — fixed cover flow count per round
//!   (peer-aligned discard volume); still `COVER_FRAGMENT_RESERVED`.
//! - [`CoverMultihopDefense::CoverOnions`] — valid Sphinx to terminal peer then
//!   peel-then-discard at [`COVER_SINK_HOP_ID`] (requires terminal KEM public).
//! - [`CoverMultihopDefense::CoverOnionsScaffold`] — tagged scaffold; **still discarded**.

use aegis_crypto::cell::{Cell, Command, CELL_LEN};
use aegis_crypto::fragment::{
    fragment_with_random_id, PacketId, FRAGMENT_HEADER_LEN, FRAGMENT_PAYLOAD_LEN,
    LAST_FRAGMENT_DATA_LEN, SPHINX_FRAGMENT_COUNT,
};
use aegis_crypto::kem::{RelayKemPublic, RelayKemSecret};
use aegis_crypto::sphinx::{self, PathHop};
use aegis_negotiator::cover::{
    dial_needs_cover_plan, required_cover_flow_count, CoverRequirement,
};
use aegis_negotiator::SecurityDial;
use rand_core::{CryptoRngCore, RngCore};

const OFF_COMMAND: usize = 0;
const OFF_FRAG_IDX: usize = 1;
const OFF_PACKET_ID: usize = 2;
const OFF_RESERVED: usize = 10;
const OFF_PAYLOAD: usize = FRAGMENT_HEADER_LEN;

/// Reserved-byte tag on relay bulk-cover fragments (real Sphinx keeps reserved zero).
///
/// Inbound link handlers discard cells carrying this marker before reassembly so
/// cover padding never enters the Sphinx peel/forward path.
pub const COVER_FRAGMENT_RESERVED: [u8; 2] = [0xC0, 0x01];

/// Reserved-byte tag for cover-onion **scaffold** fragments (still local-discard).
pub const COVER_ONION_SCAFFOLD_RESERVED: [u8; 2] = [0xC0, 0x02];

/// Well-known next-hop id meaning "peel then discard" (not client exit delivery).
///
/// After a terminal hop peels a cover onion, Sphinx returns `Forward` with this
/// `next_hop`. [`crate::RelayNode`] sinks the packet — it must never be treated as
/// real client exit traffic.
pub const COVER_SINK_HOP_ID: [u8; 32] = [
    0xA3, 0xC0, 0x53, 0x4B, // "aegis cover sink" marker bytes
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53,
];

/// Payload prefix stamped into cover-onion delta (not a client application message).
pub const COVER_ONION_PAYLOAD_PREFIX: &[u8] = b"aegis-cover-onion-sink-v1";

/// Default fixed cover flows when [`CoverMultihopDefense::MatchedLocalDiscard`] is on.
pub const DEFAULT_MATCHED_COVER_FLOWS: u32 = 1;

/// Default cover-onion flows when onion modes are on.
pub const DEFAULT_COVER_ONION_FLOWS: u32 = 1;

/// Multi-hop cover defense mode (sim S4 → product A3 / B1).
///
/// Opt-in via TOML `[cover] multihop_defense`. Default keeps today's pad-to-target
/// local discard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CoverMultihopDefense {
    /// Pad to negotiator target from local real count; discard via reserved marker.
    #[default]
    BaselineLocalDiscard,
    /// Emit a fixed matched cover volume each round (peer-aligned discard/volume).
    MatchedLocalDiscard,
    /// Valid Sphinx cover onion to a terminal hop, then peel-then-discard at sink id.
    CoverOnions,
    /// Scaffold tagged cover-onion flows; still local-discard (no Sphinx continuity).
    CoverOnionsScaffold,
}

impl CoverMultihopDefense {
    /// Parse TOML / CLI tokens (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "baseline" | "baseline_local_discard" | "local_discard" => {
                Some(Self::BaselineLocalDiscard)
            }
            "matched" | "matched_local_discard" => Some(Self::MatchedLocalDiscard),
            // Peelable product path (B1) — distinct from scaffold.
            "cover_onions" | "onions" | "peelable_cover_onions" => Some(Self::CoverOnions),
            "cover_onions_scaffold" | "onions_scaffold" => Some(Self::CoverOnionsScaffold),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BaselineLocalDiscard => "baseline_local_discard",
            Self::MatchedLocalDiscard => "matched_local_discard",
            Self::CoverOnions => "cover_onions",
            Self::CoverOnionsScaffold => "cover_onions_scaffold",
        }
    }
}

/// Terminal hop that peels a cover onion before the sink discard.
#[derive(Clone)]
pub struct CoverOnionTerminal {
    pub id: [u8; 32],
    pub pk: RelayKemPublic,
}

impl std::fmt::Debug for CoverOnionTerminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoverOnionTerminal")
            .field("id", &self.id)
            .field("pk_commitment", &self.pk.commitment())
            .finish()
    }
}

impl CoverOnionTerminal {
    #[must_use]
    pub fn new(id: [u8; 32], pk: RelayKemPublic) -> Self {
        Self { id, pk }
    }

    #[must_use]
    pub fn path_hop(&self) -> PathHop {
        PathHop {
            id: self.id,
            pk: self.pk.clone(),
        }
    }
}

/// How many local-discard / scaffold / peelable-onion flows a round close should emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverEmitPlan {
    /// Classic `COVER_FRAGMENT_RESERVED` flows (local discard at next hop).
    pub local_discard_flows: u32,
    /// Scaffold `COVER_ONION_SCAFFOLD_RESERVED` flows (also discarded).
    pub onion_scaffold_flows: u32,
    /// Peelable valid-Sphinx cover onions (terminal → sink).
    pub onion_peelable_flows: u32,
}

impl CoverEmitPlan {
    #[must_use]
    pub const fn total_flows(self) -> u32 {
        self.local_discard_flows
            .saturating_add(self.onion_scaffold_flows)
            .saturating_add(self.onion_peelable_flows)
    }

    #[must_use]
    pub const fn total_cells(self, cells_per_flow: usize) -> u64 {
        self.total_flows() as u64 * cells_per_flow as u64
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.total_flows() == 0
    }
}

/// Plan cover emission for a closed bulk round under the chosen multi-hop defense.
///
/// - **Baseline:** `max(0, target - real)` local-discard flows.
/// - **Matched:** exactly `matched_cover_flows` local-discard flows.
/// - **Cover onions:** baseline pad (if any) plus `cover_onion_flows` peelable onions.
/// - **Cover onions scaffold:** baseline pad plus scaffold-tagged discard flows.
#[must_use]
pub fn plan_cover_emit(
    defense: CoverMultihopDefense,
    dial: SecurityDial,
    real_participants: usize,
    target: u32,
    matched_cover_flows: u32,
    cover_onion_flows: u32,
) -> CoverEmitPlan {
    if !matches!(dial, SecurityDial::L2UniformBatched) {
        return CoverEmitPlan {
            local_discard_flows: 0,
            onion_scaffold_flows: 0,
            onion_peelable_flows: 0,
        };
    }
    match defense {
        CoverMultihopDefense::BaselineLocalDiscard => CoverEmitPlan {
            local_discard_flows: required_cover_flow_count(real_participants, target),
            onion_scaffold_flows: 0,
            onion_peelable_flows: 0,
        },
        CoverMultihopDefense::MatchedLocalDiscard => CoverEmitPlan {
            local_discard_flows: matched_cover_flows,
            onion_scaffold_flows: 0,
            onion_peelable_flows: 0,
        },
        CoverMultihopDefense::CoverOnions => CoverEmitPlan {
            local_discard_flows: required_cover_flow_count(real_participants, target),
            onion_scaffold_flows: 0,
            onion_peelable_flows: cover_onion_flows,
        },
        CoverMultihopDefense::CoverOnionsScaffold => CoverEmitPlan {
            local_discard_flows: required_cover_flow_count(real_participants, target),
            onion_scaffold_flows: cover_onion_flows,
            onion_peelable_flows: 0,
        },
    }
}

/// True when `next_hop` is the cover-onion sink (peel-then-discard).
#[must_use]
pub fn is_cover_sink_hop(next_hop: &[u8; 32]) -> bool {
    next_hop == &COVER_SINK_HOP_ID
}

/// True when `cell` is a relay-origin bulk-cover fragment (not client Sphinx).
#[must_use]
pub fn is_relay_cover_fragment(cell: &Cell) -> bool {
    let b = cell.as_bytes();
    if Command::from_u8(b[OFF_COMMAND]) != Some(Command::SphinxFragment) {
        return false;
    }
    b[OFF_RESERVED..OFF_RESERVED + COVER_FRAGMENT_RESERVED.len()] == COVER_FRAGMENT_RESERVED
}

/// True when `cell` is a cover-onion scaffold fragment (still discarded before peel).
#[must_use]
pub fn is_cover_onion_scaffold_fragment(cell: &Cell) -> bool {
    let b = cell.as_bytes();
    if Command::from_u8(b[OFF_COMMAND]) != Some(Command::SphinxFragment) {
        return false;
    }
    b[OFF_RESERVED..OFF_RESERVED + COVER_ONION_SCAFFOLD_RESERVED.len()]
        == COVER_ONION_SCAFFOLD_RESERVED
}

/// True when inbound must discard the cell before Sphinx reassembly.
///
/// Peelable cover onions are **not** matched — they use reserved-zero Sphinx fragments.
#[must_use]
pub fn is_discard_cover_fragment(cell: &Cell) -> bool {
    is_relay_cover_fragment(cell) || is_cover_onion_scaffold_fragment(cell)
}

/// Cells emitted per synthetic cover flow (one bulk Sphinx packet on the wire).
#[derive(Debug, Clone)]
pub struct CoverFlowConfig {
    pub cells_per_flow: usize,
    pub multihop_defense: CoverMultihopDefense,
    /// Fixed local-discard flows when defense is [`CoverMultihopDefense::MatchedLocalDiscard`].
    pub matched_cover_flows: u32,
    /// Onion flows when defense is cover_onions or cover_onions_scaffold.
    pub cover_onion_flows: u32,
    /// Terminal hop for peelable cover onions (required to emit peelable flows).
    pub cover_onion_terminal: Option<CoverOnionTerminal>,
}

impl Default for CoverFlowConfig {
    fn default() -> Self {
        Self {
            cells_per_flow: SPHINX_FRAGMENT_COUNT,
            multihop_defense: CoverMultihopDefense::BaselineLocalDiscard,
            matched_cover_flows: DEFAULT_MATCHED_COVER_FLOWS,
            cover_onion_flows: DEFAULT_COVER_ONION_FLOWS,
            cover_onion_terminal: None,
        }
    }
}

impl CoverFlowConfig {
    #[must_use]
    pub fn matched_local_discard(matched_cover_flows: u32) -> Self {
        Self {
            multihop_defense: CoverMultihopDefense::MatchedLocalDiscard,
            matched_cover_flows,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn cover_onions_scaffold(cover_onion_flows: u32) -> Self {
        Self {
            multihop_defense: CoverMultihopDefense::CoverOnionsScaffold,
            cover_onion_flows,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn cover_onions(cover_onion_flows: u32, terminal: CoverOnionTerminal) -> Self {
        Self {
            multihop_defense: CoverMultihopDefense::CoverOnions,
            cover_onion_flows,
            cover_onion_terminal: Some(terminal),
            ..Self::default()
        }
    }

    /// Cover cell count peers emit under matched mode (volume-alignment check).
    #[must_use]
    pub fn matched_discard_cell_count(&self) -> u64 {
        self.matched_cover_flows as u64 * self.cells_per_flow as u64
    }
}

/// One synthetic cover flow: a burst of wire-shaped fragment cells.
#[derive(Clone)]
pub struct CoverFlow {
    pub cells: Vec<Cell>,
}

impl std::fmt::Debug for CoverFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoverFlow")
            .field("cell_count", &self.cells.len())
            .finish()
    }
}

/// Produces the cover flows needed to pad a bulk round to the negotiator's target.
#[derive(Debug, Clone)]
pub struct CoverFlowGenerator {
    requirement: CoverRequirement,
    config: CoverFlowConfig,
}

impl CoverFlowGenerator {
    #[must_use]
    pub fn new(requirement: CoverRequirement) -> Self {
        Self {
            requirement,
            config: CoverFlowConfig::default(),
        }
    }

    #[must_use]
    pub fn with_config(requirement: CoverRequirement, config: CoverFlowConfig) -> Self {
        Self {
            requirement,
            config,
        }
    }

    #[must_use]
    pub fn requirement(&self) -> CoverRequirement {
        self.requirement
    }

    #[must_use]
    pub fn config(&self) -> &CoverFlowConfig {
        &self.config
    }

    /// Delegate to negotiator — single source of truth for **baseline** padding arithmetic.
    #[must_use]
    pub fn cover_flows_needed(&self, real_participants: usize) -> u32 {
        self.requirement.cover_flows_needed(real_participants)
    }

    /// Emit exactly [`Self::cover_flows_needed`] synthetic flows (possibly zero).
    ///
    /// Baseline helper; prefer [`Self::generate_plan`] when multi-hop defense is configured.
    pub fn generate<R: RngCore + CryptoRngCore>(
        &self,
        real_participants: usize,
        rng: &mut R,
    ) -> Vec<CoverFlow> {
        let count = self.cover_flows_needed(real_participants);
        (0..count)
            .map(|_| self.generate_one_flow(rng, COVER_FRAGMENT_RESERVED))
            .collect()
    }

    /// Emit flows according to [`plan_cover_emit`].
    ///
    /// Peelable onion flows require [`CoverFlowConfig::cover_onion_terminal`]; without it
    /// those slots are skipped (honest residual — cannot build Sphinx without a peer pk).
    pub fn generate_plan<R: RngCore + CryptoRngCore>(
        &self,
        dial: SecurityDial,
        real_participants: usize,
        rng: &mut R,
    ) -> (CoverEmitPlan, Vec<CoverFlow>) {
        let mut plan = plan_cover_emit(
            self.config.multihop_defense,
            dial,
            real_participants,
            self.requirement.target_flow_count,
            self.config.matched_cover_flows,
            self.config.cover_onion_flows,
        );
        let mut flows = Vec::with_capacity(plan.total_flows() as usize);
        for _ in 0..plan.local_discard_flows {
            flows.push(self.generate_one_flow(rng, COVER_FRAGMENT_RESERVED));
        }
        for _ in 0..plan.onion_scaffold_flows {
            flows.push(self.generate_one_flow(rng, COVER_ONION_SCAFFOLD_RESERVED));
        }
        let mut emitted_peelable = 0u32;
        if plan.onion_peelable_flows > 0 {
            if let Some(terminal) = &self.config.cover_onion_terminal {
                for _ in 0..plan.onion_peelable_flows {
                    match build_peel_to_sink_cover_flow(terminal, rng) {
                        Ok(flow) => {
                            flows.push(flow);
                            emitted_peelable += 1;
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        // Reflect actual peelable emissions when terminal missing / build failed.
        plan.onion_peelable_flows = emitted_peelable;
        (plan, flows)
    }

    fn generate_one_flow<R: RngCore + CryptoRngCore>(
        &self,
        rng: &mut R,
        reserved: [u8; 2],
    ) -> CoverFlow {
        let mut packet_id = [0u8; 8];
        rng.fill_bytes(&mut packet_id);
        let cells = (0..self.config.cells_per_flow)
            .map(|i| encode_cover_fragment_cell(rng, packet_id, i as u8, reserved))
            .collect();
        CoverFlow { cells }
    }
}

/// Build one peelable cover onion: valid Sphinx `[terminal → COVER_SINK]`, fragmented.
///
/// Wire cells have reserved-zero headers (enter reassembly). Terminal peel yields
/// [`COVER_SINK_HOP_ID`]; the mix must sink/discard — **not** client exit delivery.
pub fn build_peel_to_sink_cover_flow<R: RngCore + CryptoRngCore>(
    terminal: &CoverOnionTerminal,
    rng: &mut R,
) -> Result<CoverFlow, aegis_crypto::CryptoError> {
    let (sink_sec, sink_pk) = RelayKemSecret::generate(rng);
    let _ = sink_sec; // sink never peels in-network; id alone triggers discard.
    let path = [
        terminal.path_hop(),
        PathHop {
            id: COVER_SINK_HOP_ID,
            pk: sink_pk,
        },
    ];
    let mut payload = [0u8; sphinx::DELTA_LEN];
    let n = COVER_ONION_PAYLOAD_PREFIX.len().min(sphinx::DELTA_LEN);
    payload[..n].copy_from_slice(&COVER_ONION_PAYLOAD_PREFIX[..n]);
    rng.fill_bytes(&mut payload[n..]);
    let packet = sphinx::build(&path, &payload[..n], rng)?;
    let (cells, _) = fragment_with_random_id(&packet, rng);
    Ok(CoverFlow {
        cells: cells.to_vec(),
    })
}

/// Operator/automation commands that drive per-round cover accounting on a relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BulkRoundCommand {
    /// Open a bulk round with the negotiated dial and target flow count.
    Begin {
        dial: SecurityDial,
        requirement: CoverRequirement,
    },
    /// Close the round and emit synthetic cover flows if the dial requires it.
    EndRound,
}

/// Tracks one active bulk round and emits cover padding at close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkRoundTracker {
    active: bool,
    dial: SecurityDial,
    requirement: CoverRequirement,
    real_flow_count: usize,
}

impl BulkRoundTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            active: false,
            dial: SecurityDial::L0Raw,
            requirement: CoverRequirement::new(0),
            real_flow_count: 0,
        }
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    #[must_use]
    pub fn real_flow_count(&self) -> usize {
        self.real_flow_count
    }

    /// Start a new round; resets the real-flow counter.
    pub fn begin(&mut self, dial: SecurityDial, requirement: CoverRequirement) {
        self.active = true;
        self.dial = dial;
        self.requirement = requirement;
        self.real_flow_count = 0;
    }

    /// Record one real bulk flow (one forwarded Sphinx packet) during an active round.
    pub fn observe_real_flow(&mut self) {
        if self.active {
            self.real_flow_count += 1;
        }
    }

    /// Close the round. Returns cover flows when the defense plan is non-empty; always resets.
    pub fn close_and_emit<R: RngCore + CryptoRngCore>(
        &mut self,
        rng: &mut R,
        config: &CoverFlowConfig,
    ) -> Option<CoverEmitResult> {
        if !self.active {
            return None;
        }

        let dial = self.dial;
        let real = self.real_flow_count;
        let target = self.requirement.target_flow_count;
        self.active = false;
        self.real_flow_count = 0;

        let plan = plan_cover_emit(
            config.multihop_defense,
            dial,
            real,
            target,
            config.matched_cover_flows,
            config.cover_onion_flows,
        );

        // Baseline: keep legacy gate (no emit when already at/over target).
        // Matched / onion modes: emit whenever the planned slots are non-empty.
        let should_emit = match config.multihop_defense {
            CoverMultihopDefense::BaselineLocalDiscard => {
                dial_needs_cover_plan(dial, real, target)
            }
            CoverMultihopDefense::MatchedLocalDiscard
            | CoverMultihopDefense::CoverOnions
            | CoverMultihopDefense::CoverOnionsScaffold => {
                matches!(dial, SecurityDial::L2UniformBatched) && !plan.is_empty()
            }
        };
        if !should_emit {
            return None;
        }

        let generator = CoverFlowGenerator::with_config(self.requirement, config.clone());
        let (plan, cover_flows) = generator.generate_plan(dial, real, rng);
        if plan.is_empty() && cover_flows.is_empty() {
            return None;
        }
        let cover_flow_count = cover_flows.len() as u32;
        let cover_cell_count = cover_flows
            .iter()
            .map(|f| f.cells.len())
            .sum::<usize>() as u64;

        Some(CoverEmitResult {
            cover_flows,
            cover_flow_count,
            cover_cell_count,
            plan,
            multihop_defense: config.multihop_defense,
        })
    }
}

impl Default for BulkRoundTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of closing a bulk round with cover padding applied.
#[derive(Clone)]
pub struct CoverEmitResult {
    pub cover_flows: Vec<CoverFlow>,
    pub cover_flow_count: u32,
    pub cover_cell_count: u64,
    pub plan: CoverEmitPlan,
    pub multihop_defense: CoverMultihopDefense,
}

impl std::fmt::Debug for CoverEmitResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoverEmitResult")
            .field("cover_flow_count", &self.cover_flow_count)
            .field("cover_cell_count", &self.cover_cell_count)
            .field("cover_flows_len", &self.cover_flows.len())
            .field("plan", &self.plan)
            .field("multihop_defense", &self.multihop_defense.as_str())
            .finish()
    }
}

/// One [`Command::SphinxFragment`] cell with random payload (invalid Sphinx after reassembly).
fn encode_cover_fragment_cell<R: RngCore + CryptoRngCore>(
    rng: &mut R,
    packet_id: PacketId,
    index: u8,
    reserved: [u8; 2],
) -> Cell {
    let mut buf = [0u8; CELL_LEN];
    buf[OFF_COMMAND] = Command::SphinxFragment as u8;
    buf[OFF_FRAG_IDX] = index;
    buf[OFF_PACKET_ID..OFF_PACKET_ID + 8].copy_from_slice(&packet_id);
    buf[OFF_RESERVED..OFF_RESERVED + reserved.len()].copy_from_slice(&reserved);

    let copy_len = if usize::from(index) == SPHINX_FRAGMENT_COUNT - 1 {
        LAST_FRAGMENT_DATA_LEN
    } else {
        FRAGMENT_PAYLOAD_LEN
    };
    rng.fill_bytes(&mut buf[OFF_PAYLOAD..OFF_PAYLOAD + copy_len]);
    Cell::from_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_crypto::fragment::reassemble;
    use aegis_crypto::kem::RelayKemSecret;
    use aegis_crypto::replay::ReplayCache;
    use aegis_crypto::sphinx::{process, Processed};
    use aegis_negotiator::cover::required_cover_flow_count;
    use rand_core::OsRng;

    fn test_terminal(rng: &mut OsRng) -> (RelayKemSecret, CoverOnionTerminal) {
        let (sec, pk) = RelayKemSecret::generate(rng);
        let mut id = [0u8; 32];
        id[0] = 0x7E;
        (sec, CoverOnionTerminal::new(id, pk))
    }

    #[test]
    fn generator_produces_exact_count_when_under_target() {
        let req = CoverRequirement::new(8);
        let gen = CoverFlowGenerator::new(req);
        let mut rng = OsRng;

        for real in [0usize, 1, 3, 7] {
            let flows = gen.generate(real, &mut rng);
            assert_eq!(
                flows.len() as u32,
                required_cover_flow_count(real, 8),
                "real={real}"
            );
            assert_eq!(flows.len(), gen.cover_flows_needed(real) as usize);
            for flow in &flows {
                assert_eq!(flow.cells.len(), SPHINX_FRAGMENT_COUNT);
                assert!(
                    flow.cells
                        .iter()
                        .all(|c| c.as_bytes()[0] == Command::SphinxFragment as u8)
                );
                assert!(
                    flow.cells.iter().all(is_relay_cover_fragment),
                    "cover cells must carry the relay-cover reserved marker"
                );
                let pid = &flow.cells[0].as_bytes()[OFF_PACKET_ID..OFF_PACKET_ID + 8];
                for (i, cell) in flow.cells.iter().enumerate() {
                    assert_eq!(cell.as_bytes()[OFF_FRAG_IDX], i as u8);
                    assert_eq!(&cell.as_bytes()[OFF_PACKET_ID..OFF_PACKET_ID + 8], pid);
                }
            }
        }
    }

    #[test]
    fn generator_produces_zero_when_at_or_over_target() {
        let req = CoverRequirement::new(8);
        let gen = CoverFlowGenerator::new(req);
        let mut rng = OsRng;

        for real in [8usize, 9, 100] {
            let flows = gen.generate(real, &mut rng);
            assert!(flows.is_empty(), "real={real}");
            assert_eq!(gen.cover_flows_needed(real), 0);
        }
    }

    #[test]
    fn dial_gates_cover_generation() {
        let mut tracker = BulkRoundTracker::new();
        let mut rng = OsRng;
        let config = CoverFlowConfig::default();

        tracker.begin(SecurityDial::L0Raw, CoverRequirement::new(8));
        tracker.observe_real_flow();
        assert!(tracker.close_and_emit(&mut rng, &config).is_none());

        tracker.begin(SecurityDial::L1Bucketed, CoverRequirement::new(8));
        tracker.observe_real_flow();
        assert!(tracker.close_and_emit(&mut rng, &config).is_none());

        tracker.begin(SecurityDial::L2UniformBatched, CoverRequirement::new(8));
        for _ in 0..3 {
            tracker.observe_real_flow();
        }
        let result = tracker
            .close_and_emit(&mut rng, &config)
            .expect("L2 under target should pad");
        assert_eq!(result.cover_flow_count, 5);
        assert_eq!(
            result.cover_cell_count,
            5 * SPHINX_FRAGMENT_COUNT as u64
        );
        assert_eq!(
            result.multihop_defense,
            CoverMultihopDefense::BaselineLocalDiscard
        );
    }

    #[test]
    fn matched_local_discard_aligns_volume_across_unequal_real() {
        let config = CoverFlowConfig::matched_local_discard(2);
        let mut rng = OsRng;

        let mut low = BulkRoundTracker::new();
        low.begin(SecurityDial::L2UniformBatched, CoverRequirement::new(8));
        low.observe_real_flow(); // real=1
        let a = low
            .close_and_emit(&mut rng, &config)
            .expect("matched emits fixed volume");

        let mut high = BulkRoundTracker::new();
        high.begin(SecurityDial::L2UniformBatched, CoverRequirement::new(8));
        for _ in 0..8 {
            high.observe_real_flow(); // real=8 — baseline would emit 0
        }
        let b = high
            .close_and_emit(&mut rng, &config)
            .expect("matched ignores real>=target");

        assert_eq!(a.cover_flow_count, 2);
        assert_eq!(b.cover_flow_count, 2);
        assert_eq!(a.cover_cell_count, b.cover_cell_count);
        assert_eq!(a.cover_cell_count, config.matched_discard_cell_count());
        assert_eq!(a.plan.local_discard_flows, 2);
        assert_eq!(a.plan.onion_scaffold_flows, 0);
        assert!(a.cover_flows.iter().flat_map(|f| &f.cells).all(is_relay_cover_fragment));
        assert_eq!(a.multihop_defense, CoverMultihopDefense::MatchedLocalDiscard);
    }

    #[test]
    fn cover_onions_scaffold_tags_distinct_reserved_still_discard() {
        let config = CoverFlowConfig::cover_onions_scaffold(2);
        let mut tracker = BulkRoundTracker::new();
        let mut rng = OsRng;

        tracker.begin(SecurityDial::L2UniformBatched, CoverRequirement::new(8));
        for _ in 0..8 {
            tracker.observe_real_flow(); // baseline pad = 0
        }
        let result = tracker
            .close_and_emit(&mut rng, &config)
            .expect("scaffold emits onion flows even when pad is zero");

        assert_eq!(result.plan.local_discard_flows, 0);
        assert_eq!(result.plan.onion_scaffold_flows, 2);
        assert_eq!(result.plan.onion_peelable_flows, 0);
        assert_eq!(result.cover_flow_count, 2);
        assert!(result
            .cover_flows
            .iter()
            .flat_map(|f| &f.cells)
            .all(is_cover_onion_scaffold_fragment));
        assert!(result
            .cover_flows
            .iter()
            .flat_map(|f| &f.cells)
            .all(is_discard_cover_fragment));
        assert_eq!(
            result.multihop_defense,
            CoverMultihopDefense::CoverOnionsScaffold
        );
    }

    #[test]
    fn cover_onions_peel_to_sink_is_valid_sphinx_not_discard_marker() {
        let mut rng = OsRng;
        let (term_sec, terminal) = test_terminal(&mut rng);
        let config = CoverFlowConfig::cover_onions(1, terminal);
        let mut tracker = BulkRoundTracker::new();

        tracker.begin(SecurityDial::L2UniformBatched, CoverRequirement::new(8));
        for _ in 0..8 {
            tracker.observe_real_flow();
        }
        let result = tracker
            .close_and_emit(&mut rng, &config)
            .expect("peelable onions emit when pad is zero");

        assert_eq!(result.plan.onion_peelable_flows, 1);
        assert_eq!(result.plan.onion_scaffold_flows, 0);
        assert_eq!(result.multihop_defense, CoverMultihopDefense::CoverOnions);
        let flow = &result.cover_flows[0];
        assert!(flow.cells.iter().all(|c| !is_discard_cover_fragment(c)));

        let packet = reassemble(&flow.cells).expect("peelable cover must reassemble");
        let mut replay = ReplayCache::new();
        match process(&packet, &term_sec, &mut replay).expect("terminal peel") {
            Processed::Forward { next_hop, .. } => {
                assert!(
                    is_cover_sink_hop(&next_hop),
                    "terminal peel must reveal cover sink hop"
                );
            }
            other => panic!("expected Forward to sink, got {other:?}"),
        }
    }

    #[test]
    fn cover_onions_without_terminal_emits_no_peelable() {
        let config = CoverFlowConfig {
            multihop_defense: CoverMultihopDefense::CoverOnions,
            cover_onion_flows: 2,
            cover_onion_terminal: None,
            ..CoverFlowConfig::default()
        };
        let mut tracker = BulkRoundTracker::new();
        let mut rng = OsRng;
        tracker.begin(SecurityDial::L2UniformBatched, CoverRequirement::new(8));
        for _ in 0..8 {
            tracker.observe_real_flow();
        }
        // Planned non-empty, but no terminal → generate_plan emits nothing peelable.
        assert!(tracker.close_and_emit(&mut rng, &config).is_none());
    }

    #[test]
    fn cover_onions_scaffold_plus_baseline_pad() {
        let config = CoverFlowConfig::cover_onions_scaffold(1);
        let mut tracker = BulkRoundTracker::new();
        let mut rng = OsRng;

        tracker.begin(SecurityDial::L2UniformBatched, CoverRequirement::new(8));
        for _ in 0..3 {
            tracker.observe_real_flow();
        }
        let result = tracker.close_and_emit(&mut rng, &config).unwrap();
        assert_eq!(result.plan.local_discard_flows, 5);
        assert_eq!(result.plan.onion_scaffold_flows, 1);
        assert_eq!(result.cover_flow_count, 6);
        let local = result.cover_flows[..5]
            .iter()
            .flat_map(|f| &f.cells)
            .all(is_relay_cover_fragment);
        let onion = result.cover_flows[5]
            .cells
            .iter()
            .all(is_cover_onion_scaffold_fragment);
        assert!(local && onion);
    }

    #[test]
    fn plan_matched_independent_of_real() {
        let p0 = plan_cover_emit(
            CoverMultihopDefense::MatchedLocalDiscard,
            SecurityDial::L2UniformBatched,
            0,
            8,
            3,
            0,
        );
        let p7 = plan_cover_emit(
            CoverMultihopDefense::MatchedLocalDiscard,
            SecurityDial::L2UniformBatched,
            7,
            8,
            3,
            0,
        );
        assert_eq!(p0, p7);
        assert_eq!(p0.local_discard_flows, 3);
    }

    #[test]
    fn parse_multihop_defense_tokens_distinct() {
        assert_eq!(
            CoverMultihopDefense::parse("matched_local_discard"),
            Some(CoverMultihopDefense::MatchedLocalDiscard)
        );
        assert_eq!(
            CoverMultihopDefense::parse("cover_onions"),
            Some(CoverMultihopDefense::CoverOnions)
        );
        assert_eq!(
            CoverMultihopDefense::parse("cover_onions_scaffold"),
            Some(CoverMultihopDefense::CoverOnionsScaffold)
        );
        assert_ne!(
            CoverMultihopDefense::parse("cover_onions"),
            CoverMultihopDefense::parse("cover_onions_scaffold")
        );
        assert_eq!(
            CoverMultihopDefense::parse("baseline"),
            Some(CoverMultihopDefense::BaselineLocalDiscard)
        );
        assert_eq!(CoverMultihopDefense::parse("nope"), None);
    }

    #[test]
    fn cover_sink_hop_id_is_stable_and_non_zero() {
        assert_ne!(COVER_SINK_HOP_ID, [0u8; 32]);
        assert!(is_cover_sink_hop(&COVER_SINK_HOP_ID));
        assert!(!is_cover_sink_hop(&[0u8; 32]));
    }
}
