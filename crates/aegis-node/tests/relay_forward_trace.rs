//! Relay forward trace sample regeneration (`#[ignore]`).

use std::fs;
use std::time::Duration;

use aegis_crypto::fragment::SPHINX_FRAGMENT_COUNT;
use aegis_relay::RelayForwardTrace;

fn workspace_sample_trace_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("sim")
        .join("data")
        .join("relay_forward_trace_sample.csv")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "regenerates sim/data/relay_forward_trace_sample.csv; run with --ignored"]
async fn capture_relay_forward_trace_sample() {
    let out_path = workspace_sample_trace_path();
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("sim/data");
    }
    let trace = RelayForwardTrace::spawn(&out_path).expect("spawn");
    trace.record_forward(SPHINX_FRAGMENT_COUNT as u32);
    trace.record_cover(18);
    trace.record_exit(SPHINX_FRAGMENT_COUNT as u32);
    drop(trace);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let text = fs::read_to_string(&out_path).expect("sample trace");
    assert!(text.contains(",forward"));
    eprintln!("wrote sample relay forward trace to {}", out_path.display());
}
