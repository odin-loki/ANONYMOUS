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
//! reaches [`CoverRequirement::target_flow_count`].
//!
//! ## Cover flow shape
//!
//! Each synthetic cover flow is a bounded burst of
//! [`aegis_crypto::cell::Command::SphinxFragment`] cells — the same command byte and
//! [`SPHINX_FRAGMENT_COUNT`] as a real bulk Sphinx packet on the wire — with a random
//! [`PacketId`] and CSPRNG payload slots. [`crate::RelayNode`] forwards the burst on the
//! optional cover outbound channel; the link bridge seals each cell with hop AEAD before
//! writing TCP frames.
//!
//! ## Honest limitation
//!
//! Cover padding holds **observed flow count and per-flow cell volume** at this relay,
//! and each cover cell is a fixed-width AEAD link frame indistinguishable in length from
//! real traffic. After decryption, cover fragments carry random payload bytes (not a valid
//! Sphinx onion); downstream peers that reassemble and peel will reject them as integrity
//! failures. Cover does not replicate inter-cell timing, multi-hop forwarding semantics,
//! or valid Sphinx ciphertext. A GPA with deep timing analysis may still distinguish cover
//! bursts from genuine bulk traffic.

use aegis_crypto::cell::{Cell, Command, CELL_LEN};
use aegis_crypto::fragment::{
    PacketId, FRAGMENT_HEADER_LEN, FRAGMENT_PAYLOAD_LEN, LAST_FRAGMENT_DATA_LEN,
    SPHINX_FRAGMENT_COUNT,
};
use aegis_negotiator::cover::{dial_needs_cover_plan, CoverRequirement};
use aegis_negotiator::SecurityDial;
use rand_core::{CryptoRngCore, RngCore};

const OFF_COMMAND: usize = 0;
const OFF_FRAG_IDX: usize = 1;
const OFF_PACKET_ID: usize = 2;
const OFF_PAYLOAD: usize = FRAGMENT_HEADER_LEN;

/// Cells emitted per synthetic cover flow (one bulk Sphinx packet on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverFlowConfig {
    pub cells_per_flow: usize,
}

impl Default for CoverFlowConfig {
    fn default() -> Self {
        Self {
            cells_per_flow: SPHINX_FRAGMENT_COUNT,
        }
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

    /// Delegate to negotiator — single source of truth for padding arithmetic.
    #[must_use]
    pub fn cover_flows_needed(&self, real_participants: usize) -> u32 {
        self.requirement.cover_flows_needed(real_participants)
    }

    /// Emit exactly [`Self::cover_flows_needed`] synthetic flows (possibly zero).
    pub fn generate<R: RngCore + CryptoRngCore>(
        &self,
        real_participants: usize,
        rng: &mut R,
    ) -> Vec<CoverFlow> {
        let count = self.cover_flows_needed(real_participants);
        (0..count)
            .map(|_| self.generate_one_flow(rng))
            .collect()
    }

    fn generate_one_flow<R: RngCore + CryptoRngCore>(&self, rng: &mut R) -> CoverFlow {
        let mut packet_id = [0u8; 8];
        rng.fill_bytes(&mut packet_id);
        let cells = (0..self.config.cells_per_flow)
            .map(|i| encode_cover_fragment_cell(rng, packet_id, i as u8))
            .collect();
        CoverFlow { cells }
    }
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

    /// Close the round. Returns cover flows when L2 padding is required; always resets state.
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

        if !dial_needs_cover_plan(dial, real, target) {
            return None;
        }

        let generator = CoverFlowGenerator::with_config(self.requirement, *config);
        let cover_flows = generator.generate(real, rng);
        let cover_flow_count = cover_flows.len() as u32;
        let cover_cell_count = cover_flows
            .iter()
            .map(|f| f.cells.len())
            .sum::<usize>() as u64;

        Some(CoverEmitResult {
            cover_flows,
            cover_flow_count,
            cover_cell_count,
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
}

impl std::fmt::Debug for CoverEmitResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoverEmitResult")
            .field("cover_flow_count", &self.cover_flow_count)
            .field("cover_cell_count", &self.cover_cell_count)
            .field("cover_flows_len", &self.cover_flows.len())
            .finish()
    }
}

/// One [`Command::SphinxFragment`] cell with random payload (invalid Sphinx after reassembly).
fn encode_cover_fragment_cell<R: RngCore + CryptoRngCore>(
    rng: &mut R,
    packet_id: PacketId,
    index: u8,
) -> Cell {
    let mut buf = [0u8; CELL_LEN];
    buf[OFF_COMMAND] = Command::SphinxFragment as u8;
    buf[OFF_FRAG_IDX] = index;
    buf[OFF_PACKET_ID..OFF_PACKET_ID + 8].copy_from_slice(&packet_id);
    // reserved [OFF_RESERVED..OFF_PAYLOAD] stays zero

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
    use aegis_negotiator::cover::required_cover_flow_count;
    use rand_core::OsRng;

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
    }
}
