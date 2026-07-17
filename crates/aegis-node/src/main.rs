//! Runnable mix relay process: config file + TCP link bridge + [`RelayNode`].

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aegis_node::{exit_sink, NodeConfigFile};
use aegis_relay::{
    spawn_link_bridge, start_bulk_cover, PeerHealthTracker, RelayForwardTrace, RelayNode,
};
use aegis_trust::RelayPruningPolicy;
use clap::Parser;
use rand_core::OsRng;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
#[command(name = "aegis-node", about = "AEGIS mix relay node")]
struct Cli {
    /// Path to the node TOML configuration file.
    #[arg(long)]
    config: PathBuf,

    /// Override listen address from the config file.
    #[arg(long)]
    listen: Option<String>,

    /// Mixing rate μ (overrides config).
    #[arg(long)]
    mu: Option<f64>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut file = NodeConfigFile::load(&cli.config)?;
    NodeConfigFile::load_or_init_kem(&cli.config, &mut file, &mut OsRng)?;
    if let Some(listen) = cli.listen {
        file.listen = listen;
    }
    if let Some(mu) = cli.mu {
        file.mu = mu;
    }
    let runtime = file.into_runtime()?;

    if let Some(ref roster) = runtime.roster {
        eprintln!("loaded roster ({} relays)", roster.len());
    }

    eprintln!(
        "starting relay {:?} on {}",
        runtime.relay_id.as_bytes()[0],
        runtime.listen
    );

    let peer_health = Arc::new(PeerHealthTracker::new());
    let pruning_policy = Arc::new(Mutex::new(RelayPruningPolicy::new(0.9, 0.2, 3.0)?));

    let health_drain = Arc::clone(&peer_health);
    let policy_drain = Arc::clone(&pruning_policy);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let fed = health_drain.drain_into_policy(
                &mut *policy_drain.lock().await,
                PeerHealthTracker::DEFAULT_MIN_SAMPLES,
            );
            if fed > 0 {
                eprintln!("peer health: fed {fed} peer failure-rate sample(s) into pruning policy");
            }
        }
    });

    let (inbound_tx, inbound_rx) = mpsc::channel(64);
    let (outbound_tx, outbound_rx) = mpsc::channel(64);
    let (cover_tx, cover_rx) = mpsc::channel(64);

    let relay_id = runtime.relay_id;
    let bulk_cover = runtime.relay_config.bulk_cover.clone();
    let node = RelayNode::new(
        relay_id,
        runtime.kem_secret,
        runtime.relay_config,
    );
    // Fail-closed when `[cover].require` and cover channel/policy cannot run.
    let (handle, relay_task) = node.spawn(inbound_rx, outbound_tx, Some(cover_tx), OsRng)?;
    let cover_task = start_bulk_cover(&handle, &bulk_cover).await?;
    if bulk_cover.enabled {
        eprintln!(
            "bulk cover started (target_flow_count={}, round_secs={})",
            bulk_cover.target_flow_count, bulk_cover.round_secs
        );
    }

    let exit_settings = runtime.exit.into_settings()?;
    let exit_tx = exit_sink::spawn_exit_sink(exit_settings);
    let forward_trace = match runtime.trace.path {
        Some(ref path) => Some(RelayForwardTrace::spawn(path)?),
        None => None,
    };

    let (_listener_task, _dispatcher_task) = spawn_link_bridge(
        runtime.listen,
        relay_id,
        runtime.local_kem_commitment,
        runtime.peer_table,
        runtime.ingress_link_key,
        inbound_tx,
        outbound_rx,
        Some(cover_rx),
        exit_tx,
        forward_trace,
        OsRng,
        runtime.link_bridge_config,
        Some(peer_health),
    );

    eprintln!(
        "relay listening; coarse_stats={:?}",
        handle.coarse_stats()
    );

    tokio::signal::ctrl_c().await?;
    eprintln!("shutting down");
    if let Some(task) = cover_task {
        task.abort();
    }
    relay_task.abort();
    Ok(())
}
