//! Constant-rate paced send integration tests.

use std::time::{Duration, Instant};

use aegis_crypto::cell::{Cell, Command, CELL_LEN};
use aegis_crypto::fragment::{
    FRAGMENT_PAYLOAD_LEN, LAST_FRAGMENT_DATA_LEN, SPHINX_FRAGMENT_COUNT,
};
use aegis_client::emitter::{ConstantRateEmitter, EmitterConfig};
use aegis_client::send::build_packet;
use aegis_client::transport::{OutboundCell, Transport};
use aegis_crypto::kem::RelayKemSecret;
use aegis_crypto::sphinx::MAX_HOPS;
use rand_core::OsRng;

struct TimedRecordingTransport {
    instants: Vec<Instant>,
    sizes: Vec<usize>,
}

impl TimedRecordingTransport {
    fn new() -> Self {
        Self {
            instants: Vec::new(),
            sizes: Vec::new(),
        }
    }
}

impl Transport for TimedRecordingTransport {
    fn send(&mut self, _tick: u64, cell: OutboundCell) {
        self.instants.push(Instant::now());
        self.sizes.push(cell.wire_len());
    }
}

fn sample_hops(n: usize) -> Vec<aegis_client::send::ClientHop> {
    let mut rng = OsRng;
    (0..n)
        .map(|i| {
            let (_sec, pk) = RelayKemSecret::generate(&mut rng);
            let mut id = [0u8; 32];
            id[0] = i as u8;
            aegis_client::send::ClientHop::new(id, pk, None)
        })
        .collect()
}

#[tokio::test(flavor = "current_thread")]
async fn paced_emitter_ticks_are_tau_spaced() {
    let tau = Duration::from_millis(30);
    let tick_count = 8usize;
    let mut emitter = ConstantRateEmitter::new(EmitterConfig { tau }, OsRng);
    for _ in 0..tick_count {
        emitter.enqueue_cell(OutboundCell(Cell::zeroed()));
    }

    let mut transport = TimedRecordingTransport::new();
    let mut interval = tokio::time::interval(tau);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    for _ in 0..tick_count {
        interval.tick().await;
        emitter.tick(&mut transport);
    }

    assert_eq!(transport.instants.len(), tick_count);
    // Catch burst emission (sub-ms gaps). Allow late ticks — Windows timer jitter
    // under load regularly overshoots a hard upper bound.
    let burst_ceiling = Duration::from_millis(5);
    for window in transport.instants.windows(2).skip(1) {
        let delta = window[1].duration_since(window[0]);
        assert!(
            delta >= burst_ceiling,
            "tick looks bursty (unpaced): {delta:?} vs τ={tau:?}"
        );
    }
    let mean = transport.instants[tick_count - 1]
        .duration_since(transport.instants[0])
        / (tick_count as u32 - 1);
    let mean_tol = Duration::from_millis(50);
    assert!(
        mean >= tau.saturating_sub(mean_tol) && mean <= tau + mean_tol,
        "mean inter-tick {mean:?} not near τ={tau:?}"
    );
}

#[test]
fn dummy_cover_emitted_when_cell_queue_drains_early() {
    let mut emitter = ConstantRateEmitter::new(EmitterConfig::default(), OsRng);
    emitter.enqueue_cell(OutboundCell(Cell::zeroed()));
    emitter.enqueue_cell(OutboundCell(Cell::zeroed()));

    let mut transport = TimedRecordingTransport::new();
    for _ in 0..5 {
        emitter.tick(&mut transport);
    }

    assert_eq!(transport.sizes.len(), 5);
    assert!(transport.sizes.iter().all(|&s| s == CELL_LEN));
    assert_eq!(emitter.pending_emissions(), 0);
}

#[test]
fn sphinx_fragments_are_fixed_width_and_last_slot_padded() {
    let hops = sample_hops(3);
    let mut rng = OsRng;
    let packet = build_packet(&hops, b"padded-fragment-check", &mut rng).unwrap();
    let (cells, _) = aegis_crypto::fragment::fragment_with_random_id(&packet, &mut rng);

    assert_eq!(cells.len(), SPHINX_FRAGMENT_COUNT);
    for (i, cell) in cells.iter().enumerate() {
        assert_eq!(cell.as_bytes().len(), CELL_LEN);
        assert_eq!(cell.as_bytes()[0], Command::SphinxFragment as u8);
        assert_eq!(cell.as_bytes()[1], i as u8);
    }

    let last = cells.last().unwrap().as_bytes();
    let payload = &last[12..12 + FRAGMENT_PAYLOAD_LEN];
    let packet_bytes = packet.as_bytes();
    assert_eq!(
        payload[..LAST_FRAGMENT_DATA_LEN],
        packet_bytes[packet_bytes.len() - LAST_FRAGMENT_DATA_LEN..]
    );
    assert!(payload[LAST_FRAGMENT_DATA_LEN..].iter().all(|&b| b == 0));
}

#[test]
fn max_hops_packet_fragments_reassemble() {
    let hops = sample_hops(MAX_HOPS);
    let mut rng = OsRng;
    let packet = build_packet(&hops, &[0xFE; 128], &mut rng).unwrap();
    let (cells, _) = aegis_crypto::fragment::fragment_with_random_id(&packet, &mut rng);
    let recovered = aegis_crypto::fragment::reassemble(&cells).unwrap();
    assert_eq!(recovered, packet);
}
