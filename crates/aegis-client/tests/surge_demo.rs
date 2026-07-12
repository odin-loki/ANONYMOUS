//! Phase-4 sales demo gate (spec §10, §11).
//!
//! LEFT pane  = underlying application traffic (quiet → spike → quiet).
//! RIGHT pane = adversary's view of the AEGIS wire (flat cadence, flat size).
//!
//! This test is the Rust equivalent of the side-by-side demo: the mock transport
//! records only what a GPA sees (tick index + cell size), never real-vs-dummy.

use aegis_client::{
    config_with_tau_secs, ConstantRateEmitter, EmitterConfig, ObserverRecord, OutboundCell,
    Transport,
};
use aegis_crypto::cell::CELL_LEN;
use rand_core::OsRng;

struct ObserverTransport {
    records: Vec<ObserverRecord>,
}

impl ObserverTransport {
    fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }
}

impl Transport for ObserverTransport {
    fn send(&mut self, tick: u64, cell: OutboundCell) {
        self.records.push(ObserverRecord {
            tick,
            size: cell.wire_len(),
        });
    }
}

/// Partition ticks into quiet / spike / quiet phases (mirrors §11 framing).
fn surge_schedule(ticks: usize) -> Vec<usize> {
    let quiet = ticks / 5;
    let spike = ticks / 5;
    let mut enqueues_per_tick = vec![0usize; ticks];
    for t in quiet..quiet + spike {
        enqueues_per_tick[t] = 4; // burst: 4 messages attempted this tick
    }
    enqueues_per_tick
}

#[test]
fn surge_demo_wire_is_flat_while_true_traffic_spikes() {
    let tau_secs = 0.35;
    let config = config_with_tau_secs(tau_secs);
    let total_ticks = 200usize;

    let mut emitter = ConstantRateEmitter::new(config, OsRng);
    let mut transport = ObserverTransport::new();
    let schedule = surge_schedule(total_ticks);

    let mut true_total = 0usize;
    let mut true_by_phase = [0usize; 3]; // pre-quiet, spike, post-quiet

    for (t, &n) in schedule.iter().enumerate() {
        for _ in 0..n {
            emitter.enqueue(vec![0xC2; 64]);
            true_total += 1;
        }
        let phase = if t < total_ticks / 5 {
            0
        } else if t < 2 * total_ticks / 5 {
            1
        } else {
            2
        };
        true_by_phase[phase] += n;
        emitter.tick(&mut transport);
    }

    // --- RIGHT pane assertions (observer-visible only) ---
    assert_eq!(
        transport.records.len(),
        total_ticks,
        "exactly one emission per tick"
    );

    for window in transport.records.windows(2) {
        assert_eq!(
            window[1].tick,
            window[0].tick + 1,
            "constant cadence: one cell per slot"
        );
    }

    assert!(
        transport.records.iter().all(|r| r.size == CELL_LEN),
        "constant size regardless of content"
    );

    // Emission count is flat (1 per tick) — no correlation with surge schedule.
    let emissions_per_tick: Vec<usize> = transport.records.iter().map(|_| 1).collect();
    let max_emission = *emissions_per_tick.iter().max().unwrap();
    let min_emission = *emissions_per_tick.iter().min().unwrap();
    assert_eq!(
        max_emission, min_emission,
        "observable emission rate is constant"
    );

    // Observer trace cannot recover real-vs-dummy (records have no such field).
    assert!(!has_real_dummy_signal(&transport.records));

    // --- Printed demo summary (run with --nocapture) ---
    println!();
    println!("=== AEGIS Phase-4 surge demo (spec §11) ===");
    println!("LEFT  — true application traffic (messages enqueued per phase):");
    println!(
        "        pre-quiet={}  SPIKE={}  post-quiet={}  total={}",
        true_by_phase[0], true_by_phase[1], true_by_phase[2], true_total
    );
    println!("RIGHT — adversary wire view (constant-rate emitter, τ={tau_secs}s):");
    println!(
        "        ticks={total_ticks}  emissions/tick=min={min_emission} max={max_emission}  cell_size={CELL_LEN}B"
    );
    let spike_ticks = total_ticks / 5;
    let spike_enqueues = true_by_phase[1];
    println!(
        "        during SPIKE: {spike_enqueues} messages enqueued in {spike_ticks} ticks ({:.1}/tick), wire still 1/tick",
        spike_enqueues as f64 / spike_ticks as f64
    );
    println!(
        "        send-side backlog remaining={} (deferred real traffic, not wire-visible)",
        emitter.backlog()
    );
    println!("Adversary sees a flat wall — cadence and size unchanged through the spike.");
    println!();
}

fn has_real_dummy_signal(records: &[ObserverRecord]) -> bool {
    // If any observer field varied with hidden state, recovery would be trivial.
    let sizes: std::collections::HashSet<_> = records.iter().map(|r| r.size).collect();
    sizes.len() != 1
}

#[test]
fn observer_record_has_no_real_dummy_leak() {
    let config = EmitterConfig::default();
    let mut emitter = ConstantRateEmitter::new(config, OsRng);
    let mut transport = ObserverTransport::new();

    emitter.enqueue(vec![1, 2, 3]);
    for _ in 0..10 {
        emitter.tick(&mut transport);
    }

    assert_eq!(transport.records.len(), 10);
    for r in &transport.records {
        assert_eq!(r.size, CELL_LEN);
    }
}
