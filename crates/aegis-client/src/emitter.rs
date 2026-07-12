//! Constant-rate emitter — one cell per slot τ, real-or-dummy (§4.2).
//!
//! Utilization ρ = λ_peak · τ must stay ≤ 0.7 or the latency tail explodes (§7).

use std::collections::VecDeque;
use std::time::Duration;

use aegis_crypto::cell::{Cell, Command, CELL_LEN};
use rand_core::{CryptoRngCore, RngCore};

use crate::transport::{OutboundCell, Transport};

/// Maximum payload bytes in a real data cell (header + padding must fit in 512 B).
pub const DATA_HEADER_LEN: usize = 1 + 2; // command + u16 length

/// Maximum application payload per cell.
pub const MAX_CELL_PAYLOAD: usize = CELL_LEN - DATA_HEADER_LEN;

/// Configuration for the constant-rate emitter.
#[derive(Clone, Debug)]
pub struct EmitterConfig {
    /// Slot period τ (spec worked example ≈ 0.35 s).
    pub tau: Duration,
}

impl Default for EmitterConfig {
    fn default() -> Self {
        Self {
            tau: Duration::from_millis(350),
        }
    }
}

/// Constant-rate client emitter: exactly one cell every tick.
pub struct ConstantRateEmitter<R: RngCore + CryptoRngCore> {
    config: EmitterConfig,
    queue: VecDeque<Vec<u8>>,
    tick: u64,
    rng: R,
}

impl<R: RngCore + CryptoRngCore> ConstantRateEmitter<R> {
    pub fn new(config: EmitterConfig, rng: R) -> Self {
        Self {
            config,
            queue: VecDeque::new(),
            tick: 0,
            rng,
        }
    }

    pub fn config(&self) -> &EmitterConfig {
        &self.config
    }

    pub fn tau(&self) -> Duration {
        self.config.tau
    }

    /// Queue a real message for FIFO emission on a future tick.
    pub fn enqueue(&mut self, payload: Vec<u8>) {
        debug_assert!(
            payload.len() <= MAX_CELL_PAYLOAD,
            "payload exceeds single-cell capacity"
        );
        self.queue.push_back(payload);
    }

    /// Current send-side backlog (queued real messages awaiting a slot).
    pub fn backlog(&self) -> usize {
        self.queue.len()
    }

    pub fn tick_count(&self) -> u64 {
        self.tick
    }

    /// Emit exactly one cell on this slot — real if queued, else dummy cover.
    pub fn tick(&mut self, transport: &mut impl Transport) {
        let cell = if let Some(payload) = self.queue.pop_front() {
            encode_data_cell(&payload, &mut self.rng)
        } else {
            encode_dummy_cell(&mut self.rng)
        };
        transport.send(self.tick, cell);
        self.tick += 1;
    }

    /// Conceptual peak utilization ρ given a peak enqueue rate (messages / second).
    pub fn rho_at_peak_rate(peak_rate_per_sec: f64, tau: Duration) -> f64 {
        peak_rate_per_sec * tau.as_secs_f64()
    }
}

fn encode_data_cell<R: RngCore + CryptoRngCore>(payload: &[u8], rng: &mut R) -> OutboundCell {
    let mut buf = [0u8; CELL_LEN];
    buf[0] = Command::Data as u8;
    let len = u16::try_from(payload.len()).expect("payload length");
    buf[1..3].copy_from_slice(&len.to_be_bytes());
    buf[3..3 + payload.len()].copy_from_slice(payload);
    rng.fill_bytes(&mut buf[3 + payload.len()..]);
    OutboundCell(Cell::from_bytes(buf))
}

fn encode_dummy_cell<R: RngCore + CryptoRngCore>(rng: &mut R) -> OutboundCell {
    let mut buf = [0u8; CELL_LEN];
    buf[0] = Command::Drop as u8;
    rng.fill_bytes(&mut buf[1..]);
    OutboundCell(Cell::from_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::ObserverRecord;
    use rand_core::OsRng;

    struct RecordingTransport {
        records: Vec<ObserverRecord>,
    }

    impl RecordingTransport {
        fn new() -> Self {
            Self {
                records: Vec::new(),
            }
        }
    }

    impl Transport for RecordingTransport {
        fn send(&mut self, tick: u64, cell: OutboundCell) {
            self.records.push(ObserverRecord {
                tick,
                size: cell.wire_len(),
            });
        }
    }

    #[test]
    fn every_tick_emits_exactly_one_constant_size_cell() {
        let mut emitter = ConstantRateEmitter::new(EmitterConfig::default(), OsRng);
        let mut transport = RecordingTransport::new();

        for _ in 0..20 {
            emitter.tick(&mut transport);
        }

        assert_eq!(transport.records.len(), 20);
        assert!(transport.records.windows(2).all(|w| w[1].tick == w[0].tick + 1));
        assert!(transport
            .records
            .iter()
            .all(|r| r.size == CELL_LEN));
    }

    #[test]
    fn rho_below_threshold_keeps_backlog_bounded() {
        let tau = Duration::from_millis(350);
        let mut emitter = ConstantRateEmitter::new(EmitterConfig { tau }, OsRng);
        let mut transport = RecordingTransport::new();

        // ρ = 0.5 * 0.35 = 0.175 << 0.7
        let peak_rate = 0.5;
        let ticks = 500usize;
        let enqueue_every =
            (1.0 / (peak_rate * tau.as_secs_f64())).round() as usize;

        for t in 0..ticks {
            if t > 0 && t % enqueue_every.max(1) == 0 {
                emitter.enqueue(vec![0xAB; 32]);
            }
            emitter.tick(&mut transport);
        }

        assert!(
            emitter.backlog() <= 3,
            "low ρ should keep backlog tiny, got {}",
            emitter.backlog()
        );
    }

    #[test]
    fn rho_above_threshold_grows_backlog() {
        let tau = Duration::from_millis(350);
        let mut emitter = ConstantRateEmitter::new(EmitterConfig { tau }, OsRng);
        let mut transport = RecordingTransport::new();

        // ρ = λ_peak · τ > 1 ⇒ arrivals exceed one cell/slot ⇒ backlog grows without bound.
        let rho = 1.2_f64;
        assert!(rho > 0.7, "test setup: rho must exceed 0.7");

        let ticks = 400usize;
        let mut arrival_credit = 0.0_f64;

        for _ in 0..ticks {
            arrival_credit += rho;
            while arrival_credit >= 1.0 {
                emitter.enqueue(vec![0xCD; 16]);
                arrival_credit -= 1.0;
            }
            emitter.tick(&mut transport);
        }

        assert!(
            emitter.backlog() > 20,
            "ρ > 1 should accumulate backlog, got {}",
            emitter.backlog()
        );
    }
}
