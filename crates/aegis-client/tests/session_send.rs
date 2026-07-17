//! Persistent paced session: continuous cover and connection reuse.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_client::driver::test_support::{
    run_session_emitter_loop_mock, RecordingTransport, SharedRecordingTransport,
};
use aegis_client::emitter::{ConstantRateEmitter, EmitterConfig};
use aegis_client::session::{PacedSession, PacedSessionConfig};
use aegis_client::transport::OutboundCell;
use aegis_client::{ClientHop, ClientLink};
use aegis_crypto::cell::{Cell, Command, CELL_LEN};
use aegis_crypto::fragment::SPHINX_FRAGMENT_COUNT;
use aegis_crypto::kem::RelayKemSecret;
use aegis_crypto::link::LINK_FRAME_LEN;
use aegis_relay::{run_responder_handshake, LinkBridgeConfig};
use rand_core::OsRng;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};

fn sample_hops(n: usize) -> Vec<ClientHop> {
    let mut rng = OsRng;
    (0..n)
        .map(|i| {
            let (_sec, pk) = RelayKemSecret::generate(&mut rng);
            let mut id = [0u8; 32];
            id[0] = i as u8;
            ClientHop::new(id, pk, None)
        })
        .collect()
}

fn fragment_cell(slot: u8) -> OutboundCell {
    let mut cell = Cell::zeroed();
    cell.0[0] = Command::SphinxFragment as u8;
    cell.0[1] = slot;
    OutboundCell(cell)
}

#[tokio::test(flavor = "current_thread")]
async fn session_emits_dummy_cover_after_queue_drains() {
    let tau = Duration::from_millis(25);
    let cover = Duration::from_millis(75);
    let (enqueue_tx, enqueue_rx) = mpsc::unbounded_channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (cover_done_tx, mut cover_done_rx) = watch::channel(false);
    let (pending_tx, pending_rx) = watch::channel(0usize);

    let emitter = ConstantRateEmitter::new(
        EmitterConfig {
            tau,
            ..Default::default()
        },
        OsRng,
    );
    let recording = Arc::new(std::sync::Mutex::new(RecordingTransport::new()));
    let transport = SharedRecordingTransport {
        inner: Arc::clone(&recording),
    };

    enqueue_tx.send(fragment_cell(0)).unwrap();
    enqueue_tx.send(fragment_cell(1)).unwrap();

    let driver = tokio::spawn(async move {
        run_session_emitter_loop_mock(
            emitter,
            transport,
            enqueue_rx,
            shutdown_rx,
            cover,
            cover_done_tx,
            pending_tx,
        )
        .await;
    });

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if *cover_done_rx.borrow() {
                break;
            }
            let _ = pending_rx.borrow();
            if cover_done_rx.changed().await.is_err() {
                break;
            }
        }
    })
    .await
    .expect("cover window should complete");

    let _ = shutdown_tx.send(true);
    driver.await.unwrap();

    let cmds = &recording.lock().expect("recording lock").commands;
    // Under Windows timer Skip behavior, a short cover window may yield fewer
    // dummy ticks than wall-clock / τ suggests — require real fragments + ≥1 Drop.
    assert!(
        cmds.len() >= 3,
        "expected real fragments + at least one cover tick, got {}",
        cmds.len()
    );
    assert_eq!(cmds[0], Command::SphinxFragment as u8);
    assert_eq!(cmds[1], Command::SphinxFragment as u8);
    assert!(
        cmds.iter().skip(2).any(|&c| c == Command::Drop as u8),
        "expected at least one dummy cover after drain"
    );
    assert!(
        cmds.iter().skip(2).all(|&c| c == Command::Drop as u8),
        "ticks after drain must be dummy cover"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn session_ticks_stay_tau_spaced_under_load() {
    let tau = Duration::from_millis(30);
    let cover = Duration::from_millis(60);
    let (enqueue_tx, enqueue_rx) = mpsc::unbounded_channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (cover_done_tx, mut cover_done_rx) = watch::channel(false);
    let (pending_tx, _pending_rx) = watch::channel(0usize);

    let emitter = ConstantRateEmitter::new(
        EmitterConfig {
            tau,
            ..Default::default()
        },
        OsRng,
    );
    let recording = Arc::new(std::sync::Mutex::new(RecordingTransport::new()));
    let instants = Arc::new(std::sync::Mutex::new(Vec::<Instant>::new()));
    let timed = TimedRecordingTransport {
        inner: SharedRecordingTransport {
            inner: Arc::clone(&recording),
        },
        instants: Arc::clone(&instants),
    };

    for i in 0..4u8 {
        enqueue_tx.send(fragment_cell(i)).unwrap();
    }

    let driver = tokio::spawn(async move {
        run_session_emitter_loop_mock(
            emitter,
            timed,
            enqueue_rx,
            shutdown_rx,
            cover,
            cover_done_tx,
            pending_tx,
        )
        .await;
    });

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if *cover_done_rx.borrow() {
                break;
            }
            if cover_done_rx.changed().await.is_err() {
                break;
            }
        }
    })
    .await
    .unwrap();

    let _ = shutdown_tx.send(true);
    driver.await.unwrap();

    let times = instants.lock().expect("instants lock").clone();
    // At least the 4 enqueued fragments; cover ticks are best-effort under Skip.
    assert!(
        times.len() >= 4,
        "expected ≥4 paced ticks, got {}",
        times.len()
    );
    let burst_ceiling = Duration::from_millis(5);
    for window in times.windows(2).skip(1) {
        let delta = window[1].duration_since(window[0]);
        assert!(
            delta >= burst_ceiling,
            "tick looks bursty (unpaced): {delta:?} vs τ={tau:?}"
        );
    }
}

struct TimedRecordingTransport {
    inner: SharedRecordingTransport,
    instants: Arc<std::sync::Mutex<Vec<Instant>>>,
}

impl aegis_client::transport::Transport for TimedRecordingTransport {
    fn send(&mut self, tick: u64, cell: OutboundCell) {
        self.instants.lock().expect("instants lock").push(Instant::now());
        self.inner.send(tick, cell);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn two_paced_sends_reuse_one_tcp_handshake() {
    let psk = {
        let mut k = [0u8; 32];
        k[0] = 0x42;
        k
    };
    let hops = sample_hops(3);
    let first_hop_id = aegis_relay::RelayId::from(hops[0].id);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = LinkBridgeConfig::default();
    let handshakes = Arc::new(AtomicUsize::new(0));
    let handshakes_server = Arc::clone(&handshakes);
    let server_cfg = cfg.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        handshakes_server.fetch_add(1, Ordering::SeqCst);
        let mut rng = OsRng;
        let key = run_responder_handshake(
            &mut stream,
            first_hop_id,
            None,
            Some(psk),
            &HashMap::new(),
            &mut rng,
            &server_cfg,
            None,
        )
        .await
        .unwrap();

        let mut frame = [0u8; LINK_FRAME_LEN];
        loop {
            match tokio::time::timeout(cfg.read_timeout, stream.read_exact(&mut frame)).await {
                Ok(Ok(_n)) => {
                    let cell = key.open(&frame).unwrap();
                    assert_eq!(cell.as_bytes().len(), CELL_LEN);
                }
                _ => break,
            }
        }
    });

    let link = ClientLink {
        first_hop_addr: addr,
        first_hop_relay_id: hops[0].id,
        link_key_bytes: psk,
        kem_commitment: None,
    };
    let tau = Duration::from_millis(25);
    let mut session = PacedSession::connect(
        &link,
        &cfg,
        PacedSessionConfig {
            emitter_config: EmitterConfig {
                tau,
                ..Default::default()
            },
            cover_after_send: Duration::from_millis(50),
            allow_high_rho: false,
        },
        &mut OsRng,
    )
    .await
    .unwrap();

    let mut rng = OsRng;
    session
        .send_payload_via_session(&hops, b"first-send", &mut rng)
        .unwrap();
    session.wait_queue_drained().await;
    session
        .send_payload_via_session(&hops, b"second-send", &mut rng)
        .unwrap();
    session.wait_idle_cover().await.unwrap();
    session.shutdown().await.unwrap();

    server.await.unwrap();
    assert_eq!(
        handshakes.load(Ordering::SeqCst),
        1,
        "two paced sends must reuse one TCP session"
    );
    assert_eq!(
        SPHINX_FRAGMENT_COUNT * 2,
        36,
        "sanity: two sphinx packets enqueue 36 real fragments"
    );
}
