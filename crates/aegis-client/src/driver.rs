//! Async tokio driver loop over the sync emitter core.

use std::time::{Duration, Instant};

use rand_core::{CryptoRngCore, RngCore};
use tokio::sync::{mpsc, watch};
use tokio::time;

use crate::emitter::ConstantRateEmitter;
use crate::tcp_transport::TcpCellTransport;
use crate::transport::OutboundCell;

/// Run the constant-rate emitter until `shutdown` resolves.
///
/// The caller owns timing: one `tick` per interval period τ. For deterministic
/// unit tests, call [`ConstantRateEmitter::tick`] directly instead.
pub async fn run_emitter_loop<R, T>(
    mut emitter: ConstantRateEmitter<R>,
    mut transport: T,
    mut shutdown: watch::Receiver<bool>,
) where
    R: RngCore + CryptoRngCore,
    T: crate::transport::Transport,
{
    let tau = emitter.tau();
    let mut interval = time::interval(tau);
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                emitter.tick(&mut transport);
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

/// Session driver: continuous τ ticks, async fragment enqueue, post-send dummy cover.
pub async fn run_session_emitter_loop<R>(
    mut emitter: ConstantRateEmitter<R>,
    transport: TcpCellTransport,
    mut enqueue_rx: mpsc::Receiver<OutboundCell>,
    mut shutdown: watch::Receiver<bool>,
    cover_after_send: Duration,
    cover_done_tx: watch::Sender<bool>,
    pending_tx: watch::Sender<usize>,
) -> Result<(), aegis_relay::NetError>
where
    R: RngCore + CryptoRngCore,
{
    let tau = emitter.tau();
    let mut interval = time::interval(tau);
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    let mut cover_deadline: Option<Instant> = None;
    let mut saw_real_since_cover = false;

    let sync_pending = |emitter: &ConstantRateEmitter<R>| {
        let _ = pending_tx.send(emitter.pending_emissions());
    };

    sync_pending(&emitter);

    loop {
        tokio::select! {
            maybe_cell = enqueue_rx.recv() => {
                match maybe_cell {
                    Some(cell) => {
                        if emitter.enqueue_cell(cell).is_err() {
                            emitter.note_dropped_enqueue();
                        }
                        cover_deadline = None;
                        saw_real_since_cover = true;
                        let _ = cover_done_tx.send(false);
                        sync_pending(&emitter);
                    }
                    None => break,
                }
            }
            _ = interval.tick() => {
                let (_tick, cell) = emitter.next_cell();
                transport.send_outbound(cell).await?;
                sync_pending(&emitter);

                if emitter.pending_emissions() == 0 && saw_real_since_cover {
                    if cover_after_send.is_zero() {
                        let _ = cover_done_tx.send(true);
                        saw_real_since_cover = false;
                    } else if cover_deadline.is_none() {
                        cover_deadline = Some(Instant::now() + cover_after_send);
                    }
                }

                if let Some(deadline) = cover_deadline {
                    if Instant::now() >= deadline {
                        let _ = cover_done_tx.send(true);
                        cover_deadline = None;
                        saw_real_since_cover = false;
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    break;
                }
            }
        }
    }

    transport.flush().await?;
    Ok(())
}

/// Convenience: build config from τ seconds (spec worked example 0.35).
pub fn config_with_tau_secs(tau_secs: f64) -> crate::emitter::EmitterConfig {
    crate::emitter::EmitterConfig {
        tau: Duration::from_secs_f64(tau_secs),
        ..crate::emitter::EmitterConfig::default()
    }
}

/// Build emitter config from τ and peak enqueue rate (msg/s).
pub fn config_with_tau_and_peak(tau_secs: f64, peak_rate_per_sec: f64) -> crate::emitter::EmitterConfig {
    crate::emitter::EmitterConfig {
        tau: Duration::from_secs_f64(tau_secs),
        peak_rate_per_sec,
        ..crate::emitter::EmitterConfig::default()
    }
}

#[doc(hidden)]
pub mod test_support {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use rand_core::{CryptoRngCore, RngCore};
    use tokio::sync::{mpsc, watch};
    use tokio::time;

    use crate::emitter::ConstantRateEmitter;
    use crate::transport::{OutboundCell, Transport};

    /// Recording transport shared across async driver and test assertions.
    pub struct SharedRecordingTransport {
        pub inner: Arc<Mutex<RecordingTransport>>,
    }

    pub struct RecordingTransport {
        pub commands: Vec<u8>,
        pub tick_count: u64,
    }

    impl RecordingTransport {
        pub fn new() -> Self {
            Self {
                commands: Vec::new(),
                tick_count: 0,
            }
        }
    }

    impl Transport for SharedRecordingTransport {
        fn send(&mut self, _tick: u64, cell: OutboundCell) {
            let cmd = cell.as_bytes()[0];
            let mut guard = self.inner.lock().expect("recording transport lock");
            guard.commands.push(cmd);
            guard.tick_count += 1;
        }
    }

    /// Generic session loop for unit tests (mock transport, no TCP).
    pub async fn run_session_emitter_loop_mock<R, T>(
        mut emitter: ConstantRateEmitter<R>,
        mut transport: T,
        mut enqueue_rx: mpsc::Receiver<OutboundCell>,
        mut shutdown: watch::Receiver<bool>,
        cover_after_send: Duration,
        cover_done_tx: watch::Sender<bool>,
        pending_tx: watch::Sender<usize>,
    ) where
        R: RngCore + CryptoRngCore,
        T: Transport,
    {
        let tau = emitter.tau();
        let mut interval = time::interval(tau);
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        let mut cover_deadline: Option<Instant> = None;
        let mut saw_real_since_cover = false;

        let sync_pending = |emitter: &ConstantRateEmitter<R>| {
            let _ = pending_tx.send(emitter.pending_emissions());
        };

        sync_pending(&emitter);

        loop {
            tokio::select! {
                maybe_cell = enqueue_rx.recv() => {
                    match maybe_cell {
                        Some(cell) => {
                            if emitter.enqueue_cell(cell).is_err() {
                                emitter.note_dropped_enqueue();
                            }
                            cover_deadline = None;
                            saw_real_since_cover = true;
                            let _ = cover_done_tx.send(false);
                            sync_pending(&emitter);
                        }
                        None => break,
                    }
                }
                _ = interval.tick() => {
                    emitter.tick(&mut transport);
                    sync_pending(&emitter);

                    if emitter.pending_emissions() == 0 && saw_real_since_cover {
                        if cover_after_send.is_zero() {
                            let _ = cover_done_tx.send(true);
                            saw_real_since_cover = false;
                        } else if cover_deadline.is_none() {
                            cover_deadline = Some(Instant::now() + cover_after_send);
                        }
                    }

                    if let Some(deadline) = cover_deadline {
                        if Instant::now() >= deadline {
                            let _ = cover_done_tx.send(true);
                            cover_deadline = None;
                            saw_real_since_cover = false;
                        }
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_ok() && *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }

}
