//! Runnable mix relay process: config file + TCP link bridge + [`RelayNode`].

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aegis_node::{exit_sink, NodeConfigFile, ReputationConfig};
use aegis_relay::{
    spawn_link_bridge, start_bulk_cover, unix_timestamp_secs, GossipOutbound, HealthQuorumLog,
    PeerHealthAdvert, PeerHealthTracker, RelayForwardTrace, RelayId, RelayNode,
    RELAY_CHANNEL_CAPACITY,
};
use clap::Parser;
use rand_core::OsRng;
use std::collections::HashSet;
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
    let runtime = file.into_runtime(&cli.config)?;

    if let Some(ref roster) = runtime.roster {
        eprintln!("loaded roster ({} relays)", roster.len());
    }

    eprintln!(
        "starting relay {:?} on {}",
        runtime.relay_id.as_bytes()[0],
        runtime.listen
    );

    let peer_health = Arc::new(PeerHealthTracker::with_gossip_majority_k(
        runtime.health_gossip.majority_k.max(1),
    ));
    let reputation_cfg: ReputationConfig = runtime.reputation.clone();
    let pruning_policy = Arc::new(Mutex::new(reputation_cfg.load_pruning_policy()?));
    // Optional local nullifier registry (anonymous presentation replay prevention).
    // Not an AC issuer — see docs/ops/anonymous_reputation.md.
    let nullifier_registry = Arc::new(Mutex::new(reputation_cfg.load_nullifier_registry()?));

    let health_drain = Arc::clone(&peer_health);
    let policy_drain = Arc::clone(&pruning_policy);
    let nullifier_drain = Arc::clone(&nullifier_registry);
    let rep_drain = reputation_cfg.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let mut policy = policy_drain.lock().await;
            let fed = health_drain.drain_into_policy(
                &mut *policy,
                PeerHealthTracker::DEFAULT_MIN_SAMPLES,
            );
            if fed > 0 {
                eprintln!("peer health: fed {fed} peer failure-rate sample(s) into pruning policy");
            }
            rep_drain.save_ledger(&policy);
            rep_drain.save_nullifier_registry(&*nullifier_drain.lock().await);
        }
    });

    // Bounded queues: drop-newest under flood (see aegis_relay::node queue policy).
    let (inbound_tx, inbound_rx) = mpsc::channel(RELAY_CHANNEL_CAPACITY);
    let (outbound_tx, outbound_rx) = mpsc::channel(RELAY_CHANNEL_CAPACITY);
    let (cover_tx, cover_rx) = mpsc::channel(RELAY_CHANNEL_CAPACITY);

    let gossip_rx = if runtime.health_gossip.enabled {
        let signing = runtime.health_gossip.resolve_signing_key()?;
        if let Some(sk) = signing {
            let (gossip_tx, gossip_rx) = mpsc::channel::<GossipOutbound>(RELAY_CHANNEL_CAPACITY);
            let tracker = Arc::clone(&peer_health);
            let reporter = *runtime.relay_id.as_bytes();
            let peer_ids: Vec<RelayId> = runtime.peer_table.keys().copied().collect();
            let peer_count = peer_ids.len();
            let interval_secs = runtime.health_gossip.interval_secs.max(1);
            let min_samples = PeerHealthTracker::DEFAULT_MIN_SAMPLES;
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
                loop {
                    interval.tick().await;
                    let now = unix_timestamp_secs();
                    for (subject, ok, fail) in tracker.snapshot() {
                        if ok.saturating_add(fail) < min_samples {
                            continue;
                        }
                        // Do not gossip a peer its own local window about itself.
                        if subject == reporter {
                            continue;
                        }
                        let advert =
                            PeerHealthAdvert::sign(&sk, reporter, subject, ok, fail, now);
                        let cell = advert.to_cell();
                        for peer_id in &peer_ids {
                            let _ = gossip_tx.send((*peer_id, cell.clone())).await;
                        }
                    }
                }
            });
            eprintln!(
                "health gossip enabled (interval_secs={interval_secs}, peers={peer_count})"
            );
            Some(gossip_rx)
        } else {
            eprintln!("warning: health_gossip.enabled but no signing_seed; gossip emit disabled");
            None
        }
    } else {
        None
    };

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

    let mut link_bridge_config = runtime.link_bridge_config;
    if runtime.health_gossip.enabled {
        let authority_set: HashSet<[u8; 32]> = runtime
            .peer_table
            .iter()
            .filter(|(_, info)| info.gossip_verifying_key.is_some())
            .map(|(id, _)| *id.as_bytes())
            .collect();
        let majority_k = runtime.health_gossip.majority_k.max(1);
        let log = if let Some(ref path) = runtime.health_gossip.quorum_log_path {
            HealthQuorumLog::load_or_create(path, majority_k, authority_set).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
            })?
        } else {
            HealthQuorumLog::new(majority_k, authority_set)
        };
        link_bridge_config.health_quorum_log =
            Some(Arc::new(std::sync::Mutex::new(log)));
        link_bridge_config.gossip_epoch_secs = runtime.health_gossip.interval_secs.max(1);
    }

    let (_listener_task, _dispatcher_task) = spawn_link_bridge(
        runtime.listen,
        relay_id,
        runtime.local_kem_commitment,
        runtime.peer_table,
        runtime.ingress_link_key,
        inbound_tx,
        outbound_rx,
        Some(cover_rx),
        gossip_rx,
        exit_tx,
        forward_trace,
        OsRng,
        link_bridge_config,
        Some(peer_health),
    );

    eprintln!(
        "relay listening; coarse_stats={:?}",
        handle.coarse_stats()
    );

    tokio::signal::ctrl_c().await?;
    eprintln!("shutting down");
    reputation_cfg.save_ledger(&*pruning_policy.lock().await);
    reputation_cfg.save_nullifier_registry(&*nullifier_registry.lock().await);
    if let Some(task) = cover_task {
        task.abort();
    }
    relay_task.abort();
    Ok(())
}
