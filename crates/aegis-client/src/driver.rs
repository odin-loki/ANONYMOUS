//! Async tokio driver loop over the sync emitter core.

use std::time::Duration;

use rand_core::{CryptoRngCore, RngCore};
use tokio::time;

use crate::emitter::{ConstantRateEmitter, EmitterConfig};
use crate::transport::Transport;

/// Run the constant-rate emitter until `shutdown` resolves.
///
/// The caller owns timing: one `tick` per interval period τ. For deterministic
/// unit tests, call [`ConstantRateEmitter::tick`] directly instead.
pub async fn run_emitter_loop<R, T>(
    mut emitter: ConstantRateEmitter<R>,
    mut transport: T,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) where
    R: RngCore + CryptoRngCore,
    T: Transport,
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

/// Convenience: build config from τ seconds (spec worked example 0.35).
pub fn config_with_tau_secs(tau_secs: f64) -> EmitterConfig {
    EmitterConfig {
        tau: Duration::from_secs_f64(tau_secs),
    }
}
