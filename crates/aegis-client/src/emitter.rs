//! Constant-rate emitter — one cell per slot τ, real-or-dummy (§4.2).
//!
//! Utilization ρ = λ_peak · τ must stay ≤ 0.7 or the latency tail explodes (§7).
//! Real-cell queues are capped at [`EmitterConfig::max_backlog`] (default
//! [`DEFAULT_MAX_BACKLOG`]); Mode-1 prefers returning [`BacklogFullError`] over
//! unbounded memory growth.

use std::collections::VecDeque;
use std::time::Duration;

use aegis_crypto::cell::{Cell, Command, CELL_LEN};
use rand_core::{CryptoRngCore, RngCore};
use thiserror::Error;

use crate::transport::{OutboundCell, Transport};

/// Spec §4.2 / §7: offered load ρ = λ_peak · τ must stay ≤ this value.
pub const DEFAULT_MAX_RHO: f64 = 0.7;

/// Worked-example peak enqueue rate (msg/s) paired with τ ≈ 0.35 s → ρ = 0.7.
pub const DEFAULT_PEAK_RATE_PER_SEC: f64 = 2.0;

/// Default cap on queued real cells (payload + pre-formed wire cells).
///
/// Holds roughly fourteen full Sphinx packets at [`SPHINX_FRAGMENT_COUNT`] fragments
/// each (~252 cells) with headroom; Mode-1 prefers failing send over unbounded memory.
pub const DEFAULT_MAX_BACKLOG: usize = 256;

/// Lab override: set `AEGIS_ALLOW_HIGH_RHO=1` (or `true`) to skip ρ enforcement.
pub fn env_allows_high_rho() -> bool {
    std::env::var("AEGIS_ALLOW_HIGH_RHO")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[derive(Debug, Error, PartialEq)]
#[error(
    "offered load ρ = {rho:.4} exceeds maximum {max_rho} \
     (peak_rate {peak_rate} msg/s × τ {tau_secs:.4}s); \
     increase τ or reduce peak_rate, or enable allow_high_rho for lab use"
)]
pub struct RhoLimitError {
    pub rho: f64,
    pub max_rho: f64,
    pub peak_rate: f64,
    pub tau_secs: f64,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error(
    "emitter backlog full (max {max_backlog} queued real cells); \
     Mode-1 prefers failing send over unbounded memory"
)]
pub struct BacklogFullError {
    pub max_backlog: usize,
}

/// Maximum payload bytes in a real data cell (header + padding must fit in 512 B).
pub const DATA_HEADER_LEN: usize = 1 + 2; // command + u16 length

/// Maximum application payload per cell.
pub const MAX_CELL_PAYLOAD: usize = CELL_LEN - DATA_HEADER_LEN;

/// Configuration for the constant-rate emitter.
#[derive(Clone, Debug)]
pub struct EmitterConfig {
    /// Slot period τ (spec worked example ≈ 0.35 s).
    pub tau: Duration,
    /// Peak application enqueue rate (messages / second) used for ρ validation.
    pub peak_rate_per_sec: f64,
    /// Maximum queued real cells before [`ConstantRateEmitter::enqueue`] fails.
    pub max_backlog: usize,
}

impl Default for EmitterConfig {
    fn default() -> Self {
        Self {
            tau: Duration::from_millis(350),
            peak_rate_per_sec: DEFAULT_PEAK_RATE_PER_SEC,
            max_backlog: DEFAULT_MAX_BACKLOG,
        }
    }
}

impl EmitterConfig {
    /// Offered load ρ = λ_peak · τ for this configuration.
    pub fn rho(&self) -> f64 {
        rho_at_peak_rate(self.peak_rate_per_sec, self.tau)
    }

    /// Reject configurations that would exceed [`DEFAULT_MAX_RHO`].
    pub fn validate_rho(&self) -> Result<(), RhoLimitError> {
        self.validate_rho_with_options(DEFAULT_MAX_RHO, false)
    }

    /// Reject when ρ > `max_rho` unless `allow_high_rho` is set (lab override).
    pub fn validate_rho_with_options(
        &self,
        max_rho: f64,
        allow_high_rho: bool,
    ) -> Result<(), RhoLimitError> {
        if allow_high_rho {
            return Ok(());
        }
        let rho = self.rho();
        if rho > max_rho {
            Err(RhoLimitError {
                rho,
                max_rho,
                peak_rate: self.peak_rate_per_sec,
                tau_secs: self.tau.as_secs_f64(),
            })
        } else {
            Ok(())
        }
    }
}

/// Conceptual peak utilization ρ given a peak enqueue rate (messages / second).
pub fn rho_at_peak_rate(peak_rate_per_sec: f64, tau: Duration) -> f64 {
    peak_rate_per_sec * tau.as_secs_f64()
}

/// Constant-rate client emitter: exactly one cell every tick.
pub struct ConstantRateEmitter<R: RngCore + CryptoRngCore> {
    config: EmitterConfig,
    /// Application payloads encoded as `Command::Data` cells.
    queue: VecDeque<Vec<u8>>,
    /// Pre-formed wire cells (e.g. Sphinx fragments) emitted as-is.
    cell_queue: VecDeque<OutboundCell>,
    tick: u64,
    /// Cells rejected at capacity (drop-newest path / driver defense-in-depth).
    dropped_enqueue_count: u64,
    rng: R,
}

impl<R: RngCore + CryptoRngCore> ConstantRateEmitter<R> {
    pub fn new(config: EmitterConfig, rng: R) -> Self {
        Self {
            config,
            queue: VecDeque::new(),
            cell_queue: VecDeque::new(),
            tick: 0,
            dropped_enqueue_count: 0,
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
    ///
    /// Returns [`BacklogFullError`] when at [`EmitterConfig::max_backlog`] (Mode-1:
    /// fail the send rather than grow memory without bound).
    pub fn enqueue(&mut self, payload: Vec<u8>) -> Result<(), BacklogFullError> {
        debug_assert!(
            payload.len() <= MAX_CELL_PAYLOAD,
            "payload exceeds single-cell capacity"
        );
        self.try_push_real()?;
        self.queue.push_back(payload);
        Ok(())
    }

    /// Queue a pre-formed 512-byte wire cell (e.g. a Sphinx fragment).
    pub fn enqueue_cell(&mut self, cell: OutboundCell) -> Result<(), BacklogFullError> {
        self.try_push_real()?;
        self.cell_queue.push_back(cell);
        Ok(())
    }

    /// Like [`Self::enqueue`], but drops the incoming cell when full and increments
    /// [`Self::dropped_enqueue_count`] (lab / defense-in-depth only).
    pub fn enqueue_drop_newest(&mut self, payload: Vec<u8>) {
        debug_assert!(
            payload.len() <= MAX_CELL_PAYLOAD,
            "payload exceeds single-cell capacity"
        );
        if self.pending_emissions() >= self.config.max_backlog {
            self.dropped_enqueue_count += 1;
            return;
        }
        self.queue.push_back(payload);
    }

    /// Cells dropped by [`Self::enqueue_drop_newest`] or [`Self::note_dropped_enqueue`].
    pub fn dropped_enqueue_count(&self) -> u64 {
        self.dropped_enqueue_count
    }

    /// Record one dropped enqueue (e.g. driver defense when channel/emitter disagree).
    pub fn note_dropped_enqueue(&mut self) {
        self.dropped_enqueue_count += 1;
    }

    fn try_push_real(&mut self) -> Result<(), BacklogFullError> {
        if self.pending_emissions() >= self.config.max_backlog {
            Err(BacklogFullError {
                max_backlog: self.config.max_backlog,
            })
        } else {
            Ok(())
        }
    }

    /// Real cells still queued (payload or pre-formed).
    pub fn pending_emissions(&self) -> usize {
        self.cell_queue.len() + self.queue.len()
    }

    /// Current send-side backlog (queued real messages awaiting a slot).
    pub fn backlog(&self) -> usize {
        self.queue.len()
    }

    pub fn tick_count(&self) -> u64 {
        self.tick
    }

    /// Produce exactly one cell for this slot — real if queued, else dummy cover.
    pub fn next_cell(&mut self) -> (u64, OutboundCell) {
        let tick = self.tick;
        let cell = if let Some(cell) = self.cell_queue.pop_front() {
            cell
        } else if let Some(payload) = self.queue.pop_front() {
            encode_data_cell(&payload, &mut self.rng)
        } else {
            encode_dummy_cell(&mut self.rng)
        };
        self.tick += 1;
        (tick, cell)
    }

    /// Emit exactly one cell on this slot — real if queued, else dummy cover.
    pub fn tick(&mut self, transport: &mut impl Transport) {
        let (tick, cell) = self.next_cell();
        transport.send(tick, cell);
    }

    /// Conceptual peak utilization ρ given a peak enqueue rate (messages / second).
    pub fn rho_at_peak_rate(peak_rate_per_sec: f64, tau: Duration) -> f64 {
        rho_at_peak_rate(peak_rate_per_sec, tau)
    }
}

fn encode_data_cell<R: RngCore + CryptoRngCore>(payload: &[u8], rng: &mut R) -> OutboundCell {
    debug_assert!(
        payload.len() <= MAX_CELL_PAYLOAD,
        "payload exceeds single-cell capacity"
    );
    let mut buf = [0u8; CELL_LEN];
    buf[0] = Command::Data as u8;
    let len = u16::try_from(payload.len()).unwrap_or(u16::MAX);
    buf[1..3].copy_from_slice(&len.to_be_bytes());
    let copy_len = payload.len().min(MAX_CELL_PAYLOAD);
    buf[3..3 + copy_len].copy_from_slice(&payload[..copy_len]);
    rng.fill_bytes(&mut buf[3 + copy_len..]);
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
    use aegis_crypto::fragment::SPHINX_FRAGMENT_COUNT;
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
        let mut emitter = ConstantRateEmitter::new(
            EmitterConfig {
                tau,
                ..Default::default()
            },
            OsRng,
        );
        let mut transport = RecordingTransport::new();

        // ρ = 0.5 * 0.35 = 0.175 << 0.7
        let peak_rate = 0.5;
        let ticks = 500usize;
        let enqueue_every =
            (1.0 / (peak_rate * tau.as_secs_f64())).round() as usize;

        for t in 0..ticks {
            if t > 0 && t % enqueue_every.max(1) == 0 {
                emitter.enqueue(vec![0xAB; 32]).unwrap();
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
        let mut emitter = ConstantRateEmitter::new(
            EmitterConfig {
                tau,
                ..Default::default()
            },
            OsRng,
        );
        let mut transport = RecordingTransport::new();

        // ρ = λ_peak · τ > 1 ⇒ arrivals exceed one cell/slot ⇒ backlog grows without bound.
        let rho = 1.2_f64;
        assert!(rho > 0.7, "test setup: rho must exceed 0.7");

        let ticks = 400usize;
        let mut arrival_credit = 0.0_f64;

        for _ in 0..ticks {
            arrival_credit += rho;
            while arrival_credit >= 1.0 {
                emitter.enqueue(vec![0xCD; 16]).unwrap();
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

    #[test]
    fn default_config_rho_at_limit() {
        let cfg = EmitterConfig::default();
        let rho = cfg.rho();
        assert!(
            (rho - DEFAULT_MAX_RHO).abs() < 1e-9,
            "default τ and peak_rate should yield ρ = 0.7, got {rho}"
        );
        cfg.validate_rho().expect("default config must pass");
    }

    #[test]
    fn validate_rho_rejects_high_load() {
        let cfg = EmitterConfig {
            tau: Duration::from_millis(500),
            peak_rate_per_sec: 2.0,
            ..Default::default()
        };
        assert!(cfg.rho() > DEFAULT_MAX_RHO);
        let err = cfg.validate_rho().unwrap_err();
        assert_eq!(err.max_rho, DEFAULT_MAX_RHO);
        assert!(err.rho > DEFAULT_MAX_RHO);
    }

    #[test]
    fn validate_rho_accepts_below_limit() {
        let cfg = EmitterConfig {
            tau: Duration::from_millis(200),
            peak_rate_per_sec: 2.0,
            ..Default::default()
        };
        assert!(cfg.rho() < DEFAULT_MAX_RHO);
        cfg.validate_rho().expect("ρ below limit must pass");
    }

    #[test]
    fn validate_rho_allows_lab_override() {
        let cfg = EmitterConfig {
            tau: Duration::from_millis(500),
            peak_rate_per_sec: 2.0,
            ..Default::default()
        };
        cfg.validate_rho_with_options(DEFAULT_MAX_RHO, true)
            .expect("allow_high_rho must skip enforcement");
    }

    #[test]
    fn rho_at_peak_rate_matches_helper() {
        let tau = Duration::from_millis(350);
        assert_eq!(
            rho_at_peak_rate(2.0, tau),
            ConstantRateEmitter::<OsRng>::rho_at_peak_rate(2.0, tau)
        );
    }

    #[test]
    fn enqueue_rejects_when_backlog_at_cap() {
        let cap = 4usize;
        let mut emitter = ConstantRateEmitter::new(
            EmitterConfig {
                max_backlog: cap,
                ..Default::default()
            },
            OsRng,
        );

        for i in 0..cap {
            emitter.enqueue(vec![i as u8]).expect("under cap");
        }
        assert_eq!(emitter.pending_emissions(), cap);

        let err = emitter.enqueue(vec![0xFF]).unwrap_err();
        assert_eq!(
            err,
            BacklogFullError {
                max_backlog: cap,
            }
        );
        assert_eq!(emitter.pending_emissions(), cap);
    }

    #[test]
    fn enqueue_cell_rejects_when_backlog_at_cap() {
        let cap = 2usize;
        let mut emitter = ConstantRateEmitter::new(
            EmitterConfig {
                max_backlog: cap,
                ..Default::default()
            },
            OsRng,
        );

        emitter
            .enqueue_cell(OutboundCell(Cell::zeroed()))
            .unwrap();
        emitter
            .enqueue_cell(OutboundCell(Cell::zeroed()))
            .unwrap();
        assert!(emitter.enqueue_cell(OutboundCell(Cell::zeroed())).is_err());
    }

    #[test]
    fn enqueue_drop_newest_increments_counter_without_growing_queue() {
        let cap = 2usize;
        let mut emitter = ConstantRateEmitter::new(
            EmitterConfig {
                max_backlog: cap,
                ..Default::default()
            },
            OsRng,
        );

        emitter.enqueue(vec![1]).unwrap();
        emitter.enqueue(vec![2]).unwrap();
        emitter.enqueue_drop_newest(vec![3]);
        emitter.enqueue_drop_newest(vec![4]);

        assert_eq!(emitter.pending_emissions(), cap);
        assert_eq!(emitter.dropped_enqueue_count(), 2);
    }

    #[test]
    fn default_max_backlog_fits_multiple_sphinx_packets() {
        assert!(
            DEFAULT_MAX_BACKLOG >= SPHINX_FRAGMENT_COUNT * 10,
            "default backlog should hold at least ten fragmented packets"
        );
    }
}
