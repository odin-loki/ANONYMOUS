//! Hard-cap receiver padding — observable exactly Q every round (§4.3).
//!
//! Ports the deferral semantics of `sim/aegis_sim/shaper.py::hard_cap`: per-round
//! release capped at Q, excess carried forward FIFO. Externally every round emits
//! exactly Q delivery slots (real releases + dummy filler).

use std::collections::VecDeque;

/// Configuration for hard-cap receiver padding.
#[derive(Clone, Debug)]
pub struct HardCapConfig {
    /// Observable deliveries per round (spec: Q ≥ ~1.2× sustained mean).
    pub q: u32,
}

impl HardCapConfig {
    pub fn new(q: u32) -> Self {
        Self { q }
    }
}

/// One observable delivery slot (real payload or cover).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeliverySlot<T> {
    Real(T),
    Dummy,
}

/// Result of one padding round — always exactly `Q` observable slots.
#[derive(Clone, Debug)]
pub struct RoundOutput<T> {
    pub round: u64,
    pub slots: Vec<DeliverySlot<T>>,
    /// Test-only introspection: how many slots were real vs dummy this round.
    pub real_count: u32,
    pub dummy_count: u32,
}

impl<T> RoundOutput<T> {
    pub fn observable_count(&self) -> u32 {
        self.slots.len() as u32
    }
}

/// Incremental hard-cap padder driven round-by-round.
pub struct HardCapPadder<T> {
    config: HardCapConfig,
    pending: VecDeque<T>,
    round: u64,
    /// Deferred work in slot-units after the last round (backlog / Q).
    deferral_slots: f64,
    last_real_count: u32,
    last_dummy_count: u32,
}

impl<T> HardCapPadder<T> {
    pub fn new(config: HardCapConfig) -> Self {
        Self {
            config,
            pending: VecDeque::new(),
            round: 0,
            deferral_slots: 0.0,
            last_real_count: 0,
            last_dummy_count: 0,
        }
    }

    pub fn q(&self) -> u32 {
        self.config.q
    }

    /// Enqueue one real arrival (FIFO deferral when over cap).
    pub fn deliver_real(&mut self, item: T) {
        self.pending.push_back(item);
    }


    /// Pending real items not yet released to the observer.
    pub fn backlog(&self) -> usize {
        self.pending.len()
    }

    /// Deferral latency in round-units (mirrors Python `lat[i] = backlog / C`).
    pub fn deferral_slots(&self) -> f64 {
        self.deferral_slots
    }

    /// Whether sustained mean arrival rate `< Q` per round (Python `stable: mean < C`).
    pub fn is_stable_for_mean_arrival(mean_per_round: f64, q: u32) -> bool {
        mean_per_round < q as f64
    }

    pub fn last_round_real_count(&self) -> u32 {
        self.last_real_count
    }

    pub fn last_round_dummy_count(&self) -> u32 {
        self.last_dummy_count
    }

    /// Advance one round; observable output is exactly Q slots every time.
    pub fn round_tick(&mut self) -> RoundOutput<T> {
        let q = self.config.q as usize;
        let mut slots = Vec::with_capacity(q);

        for _ in 0..q {
            if let Some(item) = self.pending.pop_front() {
                slots.push(DeliverySlot::Real(item));
            } else {
                slots.push(DeliverySlot::Dummy);
            }
        }

        let real_count = slots
            .iter()
            .filter(|s| matches!(s, DeliverySlot::Real(_)))
            .count() as u32;
        let dummy_count = q as u32 - real_count;

        self.last_real_count = real_count;
        self.last_dummy_count = dummy_count;
        self.deferral_slots = self.pending.len() as f64 / self.config.q as f64;

        let round = self.round;
        self.round += 1;

        RoundOutput {
            round,
            slots,
            real_count,
            dummy_count,
        }
    }
}

/// Count-based padder for simulations (payload type is unit).
pub type CountHardCapPadder = HardCapPadder<()>;

impl CountHardCapPadder {
    /// Enqueue `n` real arrivals before the next round tick.
    pub fn arrive(&mut self, n: u32) {
        for _ in 0..n {
            self.deliver_real(());
        }
    }
}

/// Batch analysis matching `shaper.hard_cap` for regression against Python.
#[derive(Debug)]
pub struct HardCapStats {
    pub cap: f64,
    pub mean_deferral: f64,
    pub p99_deferral: f64,
    pub stable: bool,
}

pub fn analyze_hard_cap(counts: &[f64], c: f64) -> HardCapStats {
    let m = if counts.is_empty() {
        0.0
    } else {
        counts.iter().sum::<f64>() / counts.len() as f64
    };
    let cap = c * m;
    let mut backlog = 0.0_f64;
    let mut lat = Vec::with_capacity(counts.len());

    for &x in counts {
        backlog += x;
        backlog -= backlog.min(cap);
        lat.push(if cap > 0.0 { backlog / cap } else { 0.0 });
    }

    let mean_deferral = if lat.is_empty() {
        0.0
    } else {
        lat.iter().sum::<f64>() / lat.len() as f64
    };

    HardCapStats {
        cap,
        mean_deferral,
        p99_deferral: percentile(&lat, 99.0),
        stable: m < cap,
    }
}

fn percentile(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observable_always_exactly_q() {
        let mut padder = CountHardCapPadder::new(HardCapConfig::new(10));
        for round in 0..50 {
            padder.arrive((round % 5) as u32 * 3);
            let out = padder.round_tick();
            assert_eq!(out.observable_count(), 10);
            assert_eq!(out.real_count + out.dummy_count, 10);
        }
    }

    #[test]
    fn burst_arrivals_deferred_not_observable() {
        let q = 8_u32;
        let mut padder = CountHardCapPadder::new(HardCapConfig::new(q));

        // Quiet
        for _ in 0..5 {
            padder.arrive(1);
            let out = padder.round_tick();
            assert_eq!(out.observable_count(), q);
        }

        // Spike: 40 arrivals in one round worth of time (batched before tick)
        padder.arrive(40);
        let spike_out = padder.round_tick();
        assert_eq!(spike_out.observable_count(), q);
        assert_eq!(spike_out.real_count, q);
        assert!(padder.backlog() > 0, "excess must be deferred");

        // Observable stays flat while backlog drains
        let mut observable_counts = Vec::new();
        for _ in 0..10 {
            let out = padder.round_tick();
            observable_counts.push(out.observable_count());
        }
        assert!(observable_counts.iter().all(|&c| c == q));
    }

    #[test]
    fn stability_mean_below_q_bounded_deferral() {
        let q = 12_u32;
        let mean = 8.0_f64;
        assert!(HardCapPadder::<u32>::is_stable_for_mean_arrival(mean, q));

        let mut padder = CountHardCapPadder::new(HardCapConfig::new(q));
        for _ in 0..200 {
            padder.arrive(mean.round() as u32);
            padder.round_tick();
        }
        assert!(
            padder.deferral_slots() < 5.0,
            "stable provisioning should keep deferral low, got {}",
            padder.deferral_slots()
        );
    }

    #[test]
    fn batch_analyze_matches_python_semantics() {
        let counts: Vec<f64> = (0..100).map(|i| (i % 7) as f64 + 1.0).collect();
        let stats = analyze_hard_cap(&counts, 1.5);
        assert!(stats.cap > 0.0);
        assert_eq!(stats.stable, stats.cap > counts.iter().sum::<f64>() / counts.len() as f64);
    }
}
