//! Optional exit sink for terminal Sphinx peels (last hop only in normal operation).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use aegis_crypto::sphinx::SphinxPacket;
use aegis_relay::{packet_delta, ExitSink, RELAY_CHANNEL_CAPACITY};
use tokio::sync::mpsc;

/// Where peeled exit payloads are delivered when configured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitDeliverTarget {
    Stdout,
    File(PathBuf),
}

/// Exit sink tunables (off unless `log_payloads` or `deliver_to` is set).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExitSinkSettings {
    pub log_payloads: bool,
    pub deliver_to: Option<ExitDeliverTarget>,
}

impl ExitSinkSettings {
    pub fn enabled(&self) -> bool {
        self.log_payloads || self.deliver_to.is_some()
    }
}

/// Spawn the async exit sink task and return the channel wired into [`spawn_link_bridge`].
pub fn spawn_exit_sink(settings: ExitSinkSettings) -> Option<ExitSink> {
    if !settings.enabled() {
        return None;
    }
    let (tx, mut rx) = mpsc::channel::<SphinxPacket>(RELAY_CHANNEL_CAPACITY);
    let log_payloads = settings.log_payloads;
    let deliver_to = settings.deliver_to;
    tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            let payload = payload_prefix(&packet);
            if log_payloads {
                eprintln!(
                    "aegis-node exit: payload {} bytes ({})",
                    payload.len(),
                    hex_preview(payload)
                );
            }
            if let Some(ref target) = deliver_to {
                match target {
                    ExitDeliverTarget::Stdout => {
                        let line = format!("{}\n", hex_encode(payload));
                        let _ = std::io::stdout().write_all(line.as_bytes());
                    }
                    ExitDeliverTarget::File(path) => {
                        if let Ok(mut file) = OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(path)
                        {
                            let _ = writeln!(file, "{}", hex_encode(payload));
                        }
                    }
                }
            }
        }
    });
    Some(tx)
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
    fn payload_prefix_trims_trailing_zeros() {
        use aegis_crypto::sphinx::{ALPHA_LEN, BETA_LEN, GAMMA_LEN, SPHINX_PACKET_LEN};

        let mut bytes = [0u8; SPHINX_PACKET_LEN];
        let off = ALPHA_LEN + BETA_LEN + GAMMA_LEN;
        bytes[off] = b'h';
        bytes[off + 1] = b'i';
        let packet = SphinxPacket::from_bytes(bytes);
        assert_eq!(payload_prefix(&packet), b"hi");
    }
}
