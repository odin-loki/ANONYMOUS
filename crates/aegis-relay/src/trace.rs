//! Optional post-shaping forward trace (Phase 8 relay vantage).
//!
//! When enabled, appends `(unix_secs_f64, cell_count, event_type)` rows to a trace file
//! immediately after a Sphinx packet is written on a hop link or delivered to an exit sink,
//! and after cover cell bursts are sealed on the wire.

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, Mutex};

/// One relay-side post-forward observation.
#[derive(Clone, Debug)]
struct TraceRow {
    unix_secs: f64,
    cell_count: u32,
    event_type: &'static str,
}

/// Handle for recording post-shaping forward events from the link bridge.
#[derive(Clone)]
pub struct RelayForwardTrace {
    tx: mpsc::Sender<TraceRow>,
}

impl RelayForwardTrace {
    /// Open (or create) `path` and spawn a background writer task.
    pub fn spawn(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let header_needed = file.metadata().map(|m| m.len() == 0).unwrap_or(true);
        let writer = Arc::new(Mutex::new(BufWriter::new(file)));
        let (tx, mut rx) = mpsc::channel::<TraceRow>(512);
        tokio::spawn(async move {
            let mut header_needed = header_needed;
            while let Some(row) = rx.recv().await {
                let mut w = writer.lock().await;
                if header_needed {
                    let _ = writeln!(w, "timestamp,cell_count,event_type");
                    let _ = writeln!(w, "# vantage=relay_post_forward");
                    header_needed = false;
                }
                let _ = writeln!(
                    w,
                    "{:.6},{},{}",
                    row.unix_secs, row.cell_count, row.event_type
                );
                let _ = w.flush();
            }
        });
        Ok(Self { tx })
    }

    pub fn record(&self, event_type: &'static str, cell_count: u32) {
        let row = TraceRow {
            unix_secs: unix_secs_f64(),
            cell_count,
            event_type,
        };
        let _ = self.tx.try_send(row);
    }

    pub fn record_forward(&self, cell_count: u32) {
        self.record("forward", cell_count);
    }

    pub fn record_cover(&self, cell_count: u32) {
        self.record("cover", cell_count);
    }

    pub fn record_exit(&self, cell_count: u32) {
        self.record("exit", cell_count);
    }
}

fn unix_secs_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Parse a relay forward trace CSV into event timestamps (seconds).
pub fn load_trace_timestamps(path: impl AsRef<Path>) -> std::io::Result<Vec<f64>> {
    let text = std::fs::read_to_string(path)?;
    Ok(parse_trace_timestamps(&text))
}

/// Parse relay forward trace text (header + `#` comments allowed).
pub fn parse_trace_timestamps(text: &str) -> Vec<f64> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("timestamp,") {
                return None;
            }
            line.split(',').next()?.parse().ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_trace_timestamps_skips_header_and_comments() {
        let text = "\
timestamp,cell_count,event_type
# vantage=relay_post_forward
1000.5,18,forward
1001.0,3,cover
";
        assert_eq!(parse_trace_timestamps(text), vec![1000.5, 1001.0]);
    }

    #[tokio::test]
    async fn spawn_writes_rows_to_file() {
        let dir = std::env::temp_dir().join(format!("aegis_trace_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trace.csv");
        let trace = RelayForwardTrace::spawn(&path).unwrap();
        trace.record_forward(18);
        trace.record_cover(4);
        drop(trace);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("timestamp,cell_count,event_type"));
        assert!(text.contains(",18,forward"));
        assert!(text.contains(",4,cover"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
