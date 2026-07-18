//! Library surface for integration tests and the `aegis-node` binary.

pub mod config;
pub mod exit_sink;
pub mod kem_seed_protect;
pub mod operator_check;

pub use config::{
    kem_seed_file_path, load_roster_from_config, persist_kem_seeds_file,
    persist_kem_seeds_file_with_account, resolve_kem_seeds, CoverFileConfig, ExitConfig,
    HealthGossipConfig, KemFileConfig, KemSeeds, MetricsFileConfig, NodeConfigFile,
    NodeRuntimeConfig, ReputationConfig, RosterFileConfig, TraceConfig, DEFAULT_KEM_SEED_FILENAME,
};
pub use exit_sink::{
    presence_pad_epoch, spawn_exit_sink, spawn_exit_sink_with_counters, EpochPadDecision,
    ExitDeliverTarget, ExitSinkSettings, PresencePadCounters, PresencePadSettings,
    PresencePadStats, DEFAULT_PRESENCE_EPOCH_MS, DEFAULT_PRESENCE_PAD_Q,
    DEFAULT_PRESENCE_RATE_PCT,
};
pub use kem_seed_protect::{
    is_dpapi_protected, is_keyring_protected, kem_keyring_account, protect_seed_bytes,
    unprotect_seed_bytes, KEM_KEYRING_SERVICE, KEM_SEED_DPAPI_MAGIC, KEM_SEED_KEYRING_MAGIC,
};
pub use operator_check::{validate_production_config, ValidationReport};
