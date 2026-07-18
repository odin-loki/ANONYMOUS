//! Optional exit sink for terminal Sphinx peels (last hop only in normal operation).
//!
//! Wave A2: opt-in [`PresencePadSettings`] emits matched-Q decoy/idle pad toward an
//! egress rate target (sim `presence_pad`). Default off — enable on exit hops only.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aegis_crypto::sphinx::SphinxPacket;
use aegis_relay::{packet_delta, ExitSink, RELAY_CHANNEL_CAPACITY};
use rand_core::{OsRng, RngCore};
use tokio::sync::mpsc;

/// Sim-aligned defaults (`exit_tier_defense.DEFAULT_PAD_Q` / `DEFAULT_PRESENCE_RATE`).
pub const DEFAULT_PRESENCE_PAD_Q: u32 = 10;
pub const DEFAULT_PRESENCE_RATE_PCT: u8 = 55;
pub const DEFAULT_PRESENCE_EPOCH_MS: u64 = 1_000;

/// Where peeled exit payloads are delivered when configured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitDeliverTarget {
    Stdout,
    File(PathBuf),
}

/// Matched-Q presence pad (sim `presence_pad`) — opt-in, exit hops only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresencePadSettings {
    /// When true, epoch ticks pad active egress up to `pad_q` and may inject idle decoys.
    pub enabled: bool,
    /// Target cells per epoch (matched-Q).
    pub pad_q: u32,
    /// Epoch length in milliseconds.
    pub epoch_ms: u64,
    /// Idle-epoch decoy injection probability in percent (0–100); sim default 55.
    pub presence_rate_pct: u8,
}

impl Default for PresencePadSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            pad_q: DEFAULT_PRESENCE_PAD_Q,
            epoch_ms: DEFAULT_PRESENCE_EPOCH_MS,
            presence_rate_pct: DEFAULT_PRESENCE_RATE_PCT,
        }
    }
}

/// Exit sink tunables (off unless delivery, logging, or presence pad is set).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExitSinkSettings {
    pub log_payloads: bool,
    pub deliver_to: Option<ExitDeliverTarget>,
    pub presence_pad: PresencePadSettings,
}

impl ExitSinkSettings {
    pub fn enabled(&self) -> bool {
        self.log_payloads || self.deliver_to.is_some() || self.presence_pad.enabled
    }
}

/// Coarse counters for operators / tests (not exported on the wire metrics path).
#[derive(Debug, Default)]
pub struct PresencePadCounters {
    pub real_cells: AtomicU64,
    pub decoy_cells: AtomicU64,
    pub epochs: AtomicU64,
    pub idle_injects: AtomicU64,
}

impl PresencePadCounters {
    pub fn snapshot(&self) -> PresencePadStats {
        PresencePadStats {
            real_cells: self.real_cells.load(Ordering::Relaxed),
            decoy_cells: self.decoy_cells.load(Ordering::Relaxed),
            epochs: self.epochs.load(Ordering::Relaxed),
            idle_injects: self.idle_injects.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PresencePadStats {
    pub real_cells: u64,
    pub decoy_cells: u64,
    pub epochs: u64,
    pub idle_injects: u64,
}

/// Pure epoch decision for matched-Q presence pad (testable without tokio).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochPadDecision {
    pub decoy_cells: u32,
    pub idle_inject: bool,
}

/// Compute decoy cells for one epoch.
///
/// - Active (`real_cells > 0`): pad **up** to `pad_q` (no truncation of real peels).
/// - Idle: with probability `presence_rate_pct`, emit `pad_q` decoys.
///
/// `roll_0_99` is a uniform draw in `0..=99` (caller supplies RNG).
pub fn presence_pad_epoch(
    real_cells: u32,
    pad_q: u32,
    presence_rate_pct: u8,
    roll_0_99: u8,
) -> EpochPadDecision {
    if pad_q == 0 {
        return EpochPadDecision {
            decoy_cells: 0,
            idle_inject: false,
        };
    }
    let rate = presence_rate_pct.min(100);
    if real_cells > 0 {
        EpochPadDecision {
            decoy_cells: pad_q.saturating_sub(real_cells),
            idle_inject: false,
        }
    } else if roll_0_99 < rate {
        EpochPadDecision {
            decoy_cells: pad_q,
            idle_inject: true,
        }
    } else {
        EpochPadDecision {
            decoy_cells: 0,
            idle_inject: false,
        }
    }
}

/// Spawn the async exit sink task and return the channel wired into [`spawn_link_bridge`].
pub fn spawn_exit_sink(settings: ExitSinkSettings) -> Option<ExitSink> {
    spawn_exit_sink_with_counters(settings, None)
}

/// Like [`spawn_exit_sink`], optionally exposing pad counters for tests/ops hooks.
pub fn spawn_exit_sink_with_counters(
    settings: ExitSinkSettings,
    counters: Option<Arc<PresencePadCounters>>,
) -> Option<ExitSink> {
    if !settings.enabled() {
        return None;
    }
    let (tx, mut rx) = mpsc::channel::<SphinxPacket>(RELAY_CHANNEL_CAPACITY);
    let log_payloads = settings.log_payloads;
    let deliver_to = settings.deliver_to;
    let pad = settings.presence_pad;
    let counters = counters.unwrap_or_else(|| Arc::new(PresencePadCounters::default()));

    tokio::spawn(async move {
        let mut real_this_epoch: u32 = 0;
        let mut interval = if pad.enabled {
            let ms = pad.epoch_ms.max(1);
            let mut i = tokio::time::interval(Duration::from_millis(ms));
            i.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // First tick completes immediately — skip so the first epoch is full-length.
            i.tick().await;
            Some(i)
        } else {
            None
        };

        loop {
            if let Some(ref mut tick) = interval {
                tokio::select! {
                    packet = rx.recv() => {
                        match packet {
                            Some(packet) => {
                                handle_real_peel(
                                    &packet,
                                    log_payloads,
                                    deliver_to.as_ref(),
                                    &counters,
                                );
                                real_this_epoch = real_this_epoch.saturating_add(1);
                            }
                            None => break,
                        }
                    }
                    _ = tick.tick() => {
                        finish_epoch(
                            real_this_epoch,
                            &pad,
                            deliver_to.as_ref(),
                            log_payloads,
                            &counters,
                        );
                        real_this_epoch = 0;
                    }
                }
            } else {
                match rx.recv().await {
                    Some(packet) => {
                        handle_real_peel(
                            &packet,
                            log_payloads,
                            deliver_to.as_ref(),
                            &counters,
                        );
                    }
                    None => break,
                }
            }
        }
    });
    Some(tx)
}

fn handle_real_peel(
    packet: &SphinxPacket,
    log_payloads: bool,
    deliver_to: Option<&ExitDeliverTarget>,
    counters: &PresencePadCounters,
) {
    counters.real_cells.fetch_add(1, Ordering::Relaxed);
    let payload = payload_prefix(packet);
    if log_payloads {
        eprintln!(
            "aegis-node exit: payload {} bytes ({})",
            payload.len(),
            hex_preview(payload)
        );
    }
    if let Some(target) = deliver_to {
        deliver_line(target, &hex_encode(payload));
    }
}

fn finish_epoch(
    real_cells: u32,
    pad: &PresencePadSettings,
    deliver_to: Option<&ExitDeliverTarget>,
    log_payloads: bool,
    counters: &PresencePadCounters,
) {
    counters.epochs.fetch_add(1, Ordering::Relaxed);
    let roll = (OsRng.next_u32() % 100) as u8;
    let decision = presence_pad_epoch(real_cells, pad.pad_q, pad.presence_rate_pct, roll);
    if decision.idle_inject {
        counters.idle_injects.fetch_add(1, Ordering::Relaxed);
    }
    if decision.decoy_cells == 0 {
        return;
    }
    counters
        .decoy_cells
        .fetch_add(u64::from(decision.decoy_cells), Ordering::Relaxed);
    for i in 0..decision.decoy_cells {
        let line = decoy_line(i, decision.idle_inject);
        if log_payloads {
            eprintln!(
                "aegis-node exit: presence_pad decoy {}/{} idle={}",
                i + 1,
                decision.decoy_cells,
                decision.idle_inject
            );
        }
        if let Some(target) = deliver_to {
            deliver_line(target, &line);
        }
    }
}

/// Operator-auditable decoy marker (matched-size cover for clearnet wiring is ops-side).
fn decoy_line(index: u32, idle_inject: bool) -> String {
    let kind = if idle_inject { "idle" } else { "active" };
    format!(
        "decoy:presence_pad:{kind}:{:08x}:{}",
        index,
        hex_encode(b"aegis-presence-pad-decoy-cell")
    )
}

fn deliver_line(target: &ExitDeliverTarget, line: &str) {
    match target {
        ExitDeliverTarget::Stdout => {
            let out = format!("{line}\n");
            let _ = std::io::stdout().write_all(out.as_bytes());
        }
        ExitDeliverTarget::File(path) => {
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let _ = writeln!(file, "{line}");
            }
        }
    }
}

fn payload_prefix(packet: &SphinxPacket) -> &[u8] {
    let delta = packet_delta(packet);
    let end = delta
        .iter()
        .rposition(|&b| b != 0)
        .map(|i| i + 1)
        .unwrap_or(0);
    &delta[..end]
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_preview(bytes: &[u8]) -> String {
    const MAX: usize = 32;
    if bytes.len() <= MAX {
        hex_encode(bytes)
    } else {
        format!("{}…", hex_encode(&bytes[..MAX]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_when_unconfigured() {
        assert!(!ExitSinkSettings::default().enabled());
        assert!(spawn_exit_sink(ExitSinkSettings::default()).is_none());
    }

    #[test]
    fn presence_pad_alone_enables_sink() {
        let mut settings = ExitSinkSettings::default();
        settings.presence_pad.enabled = true;
        assert!(settings.enabled());
    }

    #[test]
    fn presence_pad_defaults_match_sim() {
        let d = PresencePadSettings::default();
        assert!(!d.enabled);
        assert_eq!(d.pad_q, 10);
        assert_eq!(d.presence_rate_pct, 55);
        assert_eq!(d.epoch_ms, 1_000);
    }

    #[test]
    fn active_epoch_pads_up_to_q() {
        let d = presence_pad_epoch(3, 10, 55, 0);
        assert_eq!(d.decoy_cells, 7);
        assert!(!d.idle_inject);
    }

    #[test]
    fn active_epoch_no_pad_when_at_or_above_q() {
        assert_eq!(
            presence_pad_epoch(10, 10, 55, 0),
            EpochPadDecision {
                decoy_cells: 0,
                idle_inject: false
            }
        );
        assert_eq!(
            presence_pad_epoch(15, 10, 55, 0).decoy_cells,
            0
        );
    }

    #[test]
    fn idle_epoch_injects_when_roll_below_rate() {
        let d = presence_pad_epoch(0, 10, 55, 54);
        assert_eq!(d.decoy_cells, 10);
        assert!(d.idle_inject);
        let skip = presence_pad_epoch(0, 10, 55, 55);
        assert_eq!(skip.decoy_cells, 0);
        assert!(!skip.idle_inject);
    }

    #[test]
    fn idle_epoch_never_injects_at_rate_zero() {
        let d = presence_pad_epoch(0, 10, 0, 0);
        assert_eq!(d.decoy_cells, 0);
        assert!(!d.idle_inject);
    }

    #[test]
    fn payload_prefix_trims_trailing_zeros() {
        use aegis_crypto::sphinx::{ALPHA_LEN, BETA_LEN, GAMMA_LEN, SPHINX_PACKET_LEN};

        let mut bytes = [0u8; SPHINX_PACKET_LEN];
        let off = ALPHA_LEN + BETA_LEN + GAMMA_LEN;
        bytes[off] = b'h';
        bytes[off + 1] = b'i';
        let packet = SphinxPacket::from_bytes(bytes);
        assert_eq!(payload_prefix(&packet), b"hi");
    }

    #[tokio::test]
    async fn presence_pad_emits_idle_decoys_to_file() {
        use std::fs;

        let dir = std::env::temp_dir().join(format!(
            "aegis_presence_pad_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("decoy.log");
        let counters = Arc::new(PresencePadCounters::default());

        let tx = spawn_exit_sink_with_counters(
            ExitSinkSettings {
                log_payloads: false,
                deliver_to: Some(ExitDeliverTarget::File(path.clone())),
                presence_pad: PresencePadSettings {
                    enabled: true,
                    pad_q: 4,
                    epoch_ms: 40,
                    presence_rate_pct: 100,
                },
            },
            Some(counters.clone()),
        )
        .expect("pad sink");

        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(tx);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let stats = counters.snapshot();
        assert!(
            stats.epochs >= 2,
            "expected several epochs, got {:?}",
            stats
        );
        assert!(
            stats.decoy_cells >= 4,
            "expected idle decoys, got {:?}",
            stats
        );
        assert!(stats.idle_injects >= 1);
        let text = fs::read_to_string(&path).expect("decoy log");
        assert!(
            text.contains("decoy:presence_pad:idle:"),
            "log should contain idle decoy lines:\n{text}"
        );
        let _ = fs::remove_dir_all(dir);
    }
}
