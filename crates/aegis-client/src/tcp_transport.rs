//! Real TCP hop-link transport — one sealed cell frame per [`Transport::send`] call.

use std::sync::Arc;
use std::time::Duration;

use aegis_crypto::cell::Cell;
use aegis_relay::{LinkBridgeConfig, LinkSession, NetError};
use rand_core::{CryptoRngCore, OsRng, RngCore};
use tokio::runtime::Handle;
use tokio::sync::Mutex;

use crate::emitter::ConstantRateEmitter;
use crate::send::ClientLink;
use crate::transport::{OutboundCell, Transport};

struct LinkSessionState {
    session: LinkSession,
    seal_rng: OsRng,
}

/// Sends shaped cells over an established first-hop TCP link session.
#[derive(Clone)]
pub struct TcpCellTransport {
    inner: Arc<Mutex<LinkSessionState>>,
    runtime: Handle,
}

impl TcpCellTransport {
    /// Connect, handshake once, and return a transport ready for paced cell emission.
    pub async fn connect<R: RngCore + CryptoRngCore>(
        link: &ClientLink,
        bridge_config: &LinkBridgeConfig,
        connect_rng: &mut R,
    ) -> Result<Self, NetError> {
        let session = LinkSession::connect(
            link.first_hop_addr,
            &link.link_key_bytes,
            aegis_relay::RelayId::from(link.first_hop_relay_id),
            link.kem_commitment,
            None,
            connect_rng,
            bridge_config,
        )
        .await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(LinkSessionState {
                session,
                seal_rng: OsRng,
            })),
            runtime: Handle::current(),
        })
    }

    /// Seal and write one outbound cell (async, preferred in paced loops).
    pub async fn send_outbound(&self, cell: OutboundCell) -> Result<(), NetError> {
        let mut guard = self.inner.lock().await;
        let LinkSessionState {
            ref mut session,
            ref mut seal_rng,
        } = &mut *guard;
        session
            .send_cell(&Cell::from_bytes(*cell.as_bytes()), seal_rng)
            .await
    }

    /// Flush any buffered TCP writes.
    pub async fn flush(&self) -> Result<(), NetError> {
        self.inner.lock().await.session.flush().await
    }

    fn send_cell_sync(&self, cell: OutboundCell) -> Result<(), NetError> {
        let handle = self.runtime.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::block_in_place(|| {
            handle.block_on(async move {
                let mut guard = inner.lock().await;
                let LinkSessionState {
                    ref mut session,
                    ref mut seal_rng,
                } = &mut *guard;
                session
                    .send_cell(&Cell::from_bytes(*cell.as_bytes()), seal_rng)
                    .await
            })
        })
    }
}

impl Transport for TcpCellTransport {
    fn send(&mut self, _tick: u64, cell: OutboundCell) {
        self.send_cell_sync(cell)
            .expect("tcp cell transport send failed");
    }
}

/// Async paced tick: emit one cell from `emitter` and write it on `transport`.
pub async fn emit_tick_async<R: RngCore + CryptoRngCore>(
    emitter: &mut ConstantRateEmitter<R>,
    transport: &TcpCellTransport,
) {
    let (_tick, cell) = emitter.next_cell();
    transport
        .send_outbound(cell)
        .await
        .expect("paced tcp send failed");
}

/// Run `count` emitter ticks at real wall-clock τ intervals.
pub async fn run_paced_ticks<R: RngCore + CryptoRngCore>(
    emitter: &mut ConstantRateEmitter<R>,
    transport: &TcpCellTransport,
    count: usize,
) where
    R: RngCore + CryptoRngCore,
{
    let tau = emitter.tau();
    run_paced_ticks_with_tau(emitter, transport, count, tau).await;
}

/// Run paced ticks with an explicit τ (useful in fast tests).
pub async fn run_paced_ticks_with_tau<R: RngCore + CryptoRngCore>(
    emitter: &mut ConstantRateEmitter<R>,
    transport: &TcpCellTransport,
    count: usize,
    tau: Duration,
) where
    R: RngCore + CryptoRngCore,
{
    let mut interval = tokio::time::interval(tau);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    for _ in 0..count {
        interval.tick().await;
        emit_tick_async(emitter, transport).await;
    }
    transport.flush().await.expect("tcp flush failed");
}
