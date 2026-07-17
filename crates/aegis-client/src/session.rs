//! Session-scoped paced egress — one TCP link, continuous τ-shaped emission.
//!
//! A [`PacedSession`] connects and handshakes once, runs a background emitter loop
//! (real Sphinx fragments + dummy cover), and accepts further sends on the same link.

use std::time::Duration;

use aegis_crypto::fragment::fragment_with_random_id;
use aegis_crypto::sphinx::SphinxPacket;
use aegis_relay::{LinkBridgeConfig, NetError};
use rand_core::{CryptoRngCore, OsRng, RngCore};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::driver::run_session_emitter_loop;
use crate::emitter::{ConstantRateEmitter, EmitterConfig, env_allows_high_rho};
use crate::send::{build_packet_with_options, BuildPacketOptions, ClientHop, ClientLink, SendError};
use crate::tcp_transport::TcpCellTransport;
use crate::transport::OutboundCell;

/// Configuration for a long-lived paced client session.
#[derive(Clone, Debug)]
pub struct PacedSessionConfig {
    pub emitter_config: EmitterConfig,
    /// Dummy cover duration after the fragment queue drains following a send.
    pub cover_after_send: Duration,
    /// Skip ρ ≤ 0.7 enforcement (lab / adversarial trace only).
    pub allow_high_rho: bool,
}

impl Default for PacedSessionConfig {
    fn default() -> Self {
        Self {
            emitter_config: EmitterConfig::default(),
            cover_after_send: Duration::from_secs(2),
            allow_high_rho: false,
        }
    }
}

fn validate_paced_config(config: &PacedSessionConfig) -> Result<(), crate::send::SendError> {
    let allow = config.allow_high_rho || env_allows_high_rho();
    config
        .emitter_config
        .validate_rho_with_options(crate::emitter::DEFAULT_MAX_RHO, allow)?;
    Ok(())
}

/// Established first-hop session with a running constant-rate emitter task.
pub struct PacedSession {
    tau: Duration,
    max_backlog: usize,
    enqueue_tx: mpsc::Sender<OutboundCell>,
    shutdown_tx: watch::Sender<bool>,
    cover_done_tx: watch::Sender<bool>,
    cover_done_rx: watch::Receiver<bool>,
    pending_rx: watch::Receiver<usize>,
    driver: JoinHandle<Result<(), NetError>>,
    cover_after_send: Duration,
}

impl PacedSession {
    /// Connect to the first hop once and start the background emitter loop.
    pub async fn connect<R: RngCore + CryptoRngCore>(
        link: &ClientLink,
        bridge_config: &LinkBridgeConfig,
        config: PacedSessionConfig,
        connect_rng: &mut R,
    ) -> Result<Self, SendError> {
        validate_paced_config(&config)?;
        let transport = TcpCellTransport::connect(link, bridge_config, connect_rng).await?;
        Self::start_with_transport(config, transport)
    }

    /// Start a session on an already-connected transport (tests / injection).
    pub fn start_with_transport(
        config: PacedSessionConfig,
        transport: TcpCellTransport,
    ) -> Result<Self, SendError> {
        validate_paced_config(&config)?;
        let tau = config.emitter_config.tau;
        let max_backlog = config.emitter_config.max_backlog;
        let cover_after_send = config.cover_after_send;
        let (enqueue_tx, enqueue_rx) = mpsc::channel(max_backlog);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (cover_done_tx, cover_done_rx) = watch::channel(false);
        let (pending_tx, pending_rx) = watch::channel(0usize);

        let emitter = ConstantRateEmitter::new(config.emitter_config, OsRng);

        let cover_done_tx_driver = cover_done_tx.clone();
        let driver = tokio::spawn(async move {
            run_session_emitter_loop(
                emitter,
                transport,
                enqueue_rx,
                shutdown_rx,
                cover_after_send,
                cover_done_tx_driver,
                pending_tx,
            )
            .await
        });

        Ok(Self {
            tau,
            max_backlog,
            enqueue_tx,
            shutdown_tx,
            cover_done_tx,
            cover_done_rx,
            pending_rx,
            driver,
            cover_after_send,
        })
    }

    /// Slot period τ for this session.
    pub fn tau(&self) -> Duration {
        self.tau
    }

    /// Queue Sphinx fragments on the running emitter (does not reconnect).
    pub fn enqueue_packet<R: RngCore + CryptoRngCore>(
        &self,
        packet: &SphinxPacket,
        rng: &mut R,
    ) -> Result<(), SendError> {
        let (fragments, _) = fragment_with_random_id(packet, rng);
        self.enqueue_fragments(fragments.into_iter().map(OutboundCell))
    }

    /// Build, fragment, and enqueue one Sphinx packet on this session.
    pub fn send_payload_via_session<R: RngCore + CryptoRngCore>(
        &self,
        hops: &[ClientHop],
        payload: &[u8],
        rng: &mut R,
    ) -> Result<SphinxPacket, SendError> {
        self.send_payload_via_session_with_options(
            hops,
            payload,
            rng,
            BuildPacketOptions::default(),
        )
    }

    /// Like [`Self::send_payload_via_session`] with explicit roster binding policy.
    pub fn send_payload_via_session_with_options<R: RngCore + CryptoRngCore>(
        &self,
        hops: &[ClientHop],
        payload: &[u8],
        rng: &mut R,
        options: BuildPacketOptions,
    ) -> Result<SphinxPacket, SendError> {
        let packet = build_packet_with_options(hops, payload, rng, options)?;
        self.enqueue_packet(&packet, rng)?;
        Ok(packet)
    }

    fn enqueue_fragments(
        &self,
        cells: impl IntoIterator<Item = OutboundCell>,
    ) -> Result<(), SendError> {
        let _ = self.cover_done_tx.send(false);
        for cell in cells {
            self.enqueue_tx.try_send(cell).map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => SendError::EmitterBacklogFull(
                    crate::emitter::BacklogFullError {
                        max_backlog: self.max_backlog,
                    },
                ),
                mpsc::error::TrySendError::Closed(_) => SendError::SessionClosed,
            })?;
        }
        Ok(())
    }

    /// Wait until all queued real cells are emitted.
    ///
    /// Waits for `pending` to become non-zero first so a race between enqueue
    /// and this waiter cannot observe the pre-enqueue empty queue and return early.
    pub async fn wait_queue_drained(&mut self) {
        // Phase 1: wait until at least one cell is acknowledged by the driver.
        loop {
            if *self.pending_rx.borrow() > 0 {
                break;
            }
            if *self.cover_done_rx.borrow() {
                // Driver already drained and signaled (fast path / empty send).
                return;
            }
            tokio::select! {
                changed = self.pending_rx.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                changed = self.cover_done_rx.changed() => {
                    if changed.is_err() || *self.cover_done_rx.borrow() {
                        return;
                    }
                }
            }
        }
        // Phase 2: wait until the queue is empty again.
        loop {
            if *self.pending_rx.borrow() == 0 {
                return;
            }
            if self.pending_rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// Wait until the post-send dummy cover window completes (after queue drain).
    ///
    /// Always waits for the driver's `cover_done` signal — including when
    /// `cover_after_send` is zero — so we never shut down before fragments hit the wire.
    pub async fn wait_idle_cover(&mut self) -> Result<(), SendError> {
        loop {
            if *self.cover_done_rx.borrow() {
                return Ok(());
            }
            if self.cover_done_rx.changed().await.is_err() {
                return Err(SendError::SessionClosed);
            }
        }
    }

    /// Pre-formed cells still waiting for a τ slot.
    pub fn pending_emissions(&self) -> usize {
        *self.pending_rx.borrow()
    }

    pub fn cover_after_send(&self) -> Duration {
        self.cover_after_send
    }

    /// Signal shutdown, wait for the driver (which flushes the TCP session).
    pub async fn shutdown(self) -> Result<(), SendError> {
        let _ = self.shutdown_tx.send(true);
        self.driver
            .await
            .map_err(|_| SendError::SessionClosed)??;
        Ok(())
    }
}
