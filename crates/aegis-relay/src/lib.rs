//! # aegis-relay — Phase 3
//!
//! Mix relay: Sphinx process (via `aegis-crypto`), per-hop Exp(μ) mixing delay,
//! loop-cover accounting for active-attack detection, then forward. Delay is sized
//! only to let cover mix — it is **not** the security primitive (spec §4.4).
//!
//! See `docs/AEGIS_SPEC_v3_consolidated.md` §4.4 and the Phase gate in §10.
//!
//! ## Loop-cover accounting (minimal scope)
//!
//! [`RelayHandle::loop_return_count`] increments when `sphinx::process` returns
//! [`aegis_crypto::sphinx::Processed::LoopReturned`]. Full active-confirmation
//! detection logic is deferred to later phases; this crate only wires the counter.
//!
//! ## Bulk cover-flow padding (spec §5.2 L2, §5.3)
//!
//! [`cover_flow`] synthesizes [`aegis_crypto::cell::Command::SphinxFragment`] cell bursts
//! so observed bulk flow count reaches the negotiator target. Use
//! [`RelayHandle::begin_bulk_round`] / [`RelayHandle::end_bulk_round`] to open and close a
//! counting window; cover bursts are emitted on the optional cover outbound channel and
//! sealed by [`net::spawn_link_bridge`].
//!
//! Production path: set [`BulkCoverConfig::require`] (via [`BulkCoverConfig::production`]),
//! pass a cover channel into [`RelayNode::spawn`] (fails closed otherwise), then call
//! [`start_bulk_cover`] so rounds actually start — a misconfigured node cannot accept
//! bulk while silently skipping cover.
//!
//! ## TCP link bridge
//!
//! Real hop links are implemented in [`net`]: fixed-width AEAD frames over
//! `tokio::net::TcpStream`, with Sphinx fragmentation and per-connection
//! ephemeral handshake for link-layer forward secrecy.
//!
//! ## Bounded queues (drop-newest) + per-peer fair drain
//!
//! [`RelayNode::spawn`] and production `aegis-node` use bounded `mpsc` channels of
//! capacity [`RELAY_CHANNEL_CAPACITY`]. Full queues drop the newest item via
//! [`try_send_drop_newest`] and increment coarse counters
//! ([`RelayCoarseStats::queue_dropped`] outbound; [`QueueDropStats`] inbound).
//! Link-bridge ingress uses per-connection queues (`PER_PEER_INBOUND_CAPACITY`)
//! with weighted fair (WFQ-style) drain into the shared mix inbound. Egress uses
//! symmetric per-next-hop queues (`PER_PEER_OUTBOUND_CAPACITY`) with health-weighted
//! WFQ before TCP writes. See [`node`] / [`net`].

pub mod config;
pub mod cover_flow;
pub mod delay;
pub mod health_gossip;
pub mod health_quorum_log;
pub mod metrics_export;
pub mod net;
pub mod node;
pub mod peer_health;
pub mod relay_id;
pub mod trace;

pub use config::{
    BulkCoverConfig, CoverPolicyError, RelayConfig, DEFAULT_COVER_ROUND_SECS,
    DEFAULT_COVER_TARGET_FLOW_COUNT, DEFAULT_MU,
};
pub use cover_flow::{
    is_cover_onion_scaffold_fragment, is_discard_cover_fragment, is_relay_cover_fragment,
    plan_cover_emit, BulkRoundCommand, BulkRoundTracker, CoverEmitPlan, CoverEmitResult,
    CoverFlow, CoverFlowConfig, CoverFlowGenerator, CoverMultihopDefense,
    COVER_FRAGMENT_RESERVED, COVER_ONION_SCAFFOLD_RESERVED, DEFAULT_COVER_ONION_FLOWS,
    DEFAULT_MATCHED_COVER_FLOWS,
};
pub use delay::sample_mixing_delay;
pub use health_gossip::{
    accept_advert, accept_advert_quorum, unix_timestamp_secs, GossipAcceptOutcome,
    HealthGossipError, PeerHealthAdvert, ADVERT_BODY_LEN, ADVERT_SIG_LEN, ADVERT_WIRE_LEN,
    DEFAULT_MAX_ADVERT_AGE_SECS, GOSSIP_MAJORITY_K,
};
pub use health_quorum_log::{
    advert_epoch, HealthEpochCheckpoint, HealthEpochMedianSummary, HealthQuorumLog,
    HealthQuorumLogEntry, QuorumAppendOutcome, QuorumLogError, QUORUM_LOG_RECORD_LEN,
};
pub use metrics_export::{
    quantize_coarse, quantize_u64, ExportedRelayStats, MetricsExportConfig, MetricsExportError,
    MetricsExportGate, DEFAULT_MIN_SCRAPE_INTERVAL_SECS, DEFAULT_QUANTIZE_BUCKET,
};
pub use net::{
    send_link_cell, send_sphinx_packet, write_packet, GossipOutbound, IngressRateLimitConfig,
    IngressRateLimitStats, InboundListen, LinkBridgeConfig, LinkHandshakeMode, LinkSession,
    NetError, PeerInfo, QueueDropStats, ExitSink, spawn_link_bridge,
    spawn_link_bridge_with_listener, run_initiator_handshake, run_responder_handshake,
    DEFAULT_COVER_CELL_TAU, DEFAULT_EXPECTED_INGRESS_CLIENTS, DEFAULT_GLOBAL_MAX_CELLS_PER_SEC,
    DEFAULT_INGRESS_BURST, DEFAULT_INGRESS_MAX_CELLS_PER_SEC, DEFAULT_LINK_READ_TIMEOUT,
    DEFAULT_MAX_INBOUND_CONNECTIONS, DEFAULT_PEER_QUEUE_WEIGHT, MAX_PEER_QUEUE_WEIGHT,
    MODE1_TAU_SECS, PER_PEER_INBOUND_CAPACITY, peer_queue_weight_from_success_rate,
};
pub use node::{
    packet_delta, start_bulk_cover, try_send_drop_newest, ForwardedPacket, RelayCoarseStats,
    RelayDebugStats, RelayHandle, RelayNode, RelayStoppedError, RELAY_CHANNEL_CAPACITY,
};
pub use peer_health::{
    gossip_diversity_key, GossipMergeOutcome, GossipMergePolicy, PeerHealthTracker,
    DEFAULT_ECLIPSE_DETECT, DEFAULT_ECLIPSE_HONEST_BASELINE, DEFAULT_ECLIPSE_LOCAL_MIN_SAMPLES,
    DEFAULT_ECLIPSE_MEDIAN_GAP, DEFAULT_GOSSIP_MAJORITY_K, DEFAULT_GOSSIP_MIN_ORGS,
    GOSSIP_WEIGHT_DEN, GOSSIP_WEIGHT_NUM,
};
pub use relay_id::RelayId;
pub use trace::{load_trace_timestamps, parse_trace_timestamps, RelayForwardTrace};
