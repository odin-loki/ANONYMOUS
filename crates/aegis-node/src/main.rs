//! Runnable mix relay process: config file + TCP link bridge + [`RelayNode`].

mod config;

use std::path::PathBuf;

use aegis_relay::{RelayNode, spawn_link_bridge};
use clap::Parser;
use rand_core::OsRng;
use tokio::sync::mpsc;

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
    let mut file = config::NodeConfigFile::load(&cli.config)?;
    config::NodeConfigFile::load_or_init_kem(&cli.config, &mut file, &mut OsRng)?;
    if let Some(listen) = cli.listen {
        file.listen = listen;
    }
    if let Some(mu) = cli.mu {
        file.mu = mu;
    }
    let runtime = file.into_runtime()?;

    eprintln!(
        "starting relay {:?} on {}",
        runtime.relay_id.as_bytes()[0],
        runtime.listen
    );

    let (inbound_tx, inbound_rx) = mpsc::channel(64);
    let (outbound_tx, outbound_rx) = mpsc::channel(64);

    let node = RelayNode::new(
        runtime.relay_id,
        runtime.kem_secret,
        runtime.relay_config,
    );
    let (handle, relay_task) = node.spawn(inbound_rx, outbound_tx, OsRng);

    let (_listener_task, _dispatcher_task) = spawn_link_bridge(
        runtime.listen,
        runtime.peer_table,
        runtime.ingress_link_key,
        inbound_tx,
        outbound_rx,
        None,
        OsRng,
    );

    eprintln!(
        "relay listening; forwarded_count={}",
        handle.forwarded_count()
    );

    tokio::signal::ctrl_c().await?;
    eprintln!("shutting down");
    relay_task.abort();
    Ok(())
}
