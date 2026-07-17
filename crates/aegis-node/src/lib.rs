//! Library surface for integration tests and the `aegis-node` binary.

pub mod config;
pub mod exit_sink;

pub use config::{
    kem_seed_file_path, load_roster_from_config, persist_kem_seeds_file, resolve_kem_seeds,
    CoverFileConfig, ExitConfig, KemFileConfig, KemSeeds, NodeConfigFile, NodeRuntimeConfig,
    ReputationConfig, RosterFileConfig, TraceConfig, DEFAULT_KEM_SEED_FILENAME,
};
pub use exit_sink::{spawn_exit_sink, ExitDeliverTarget, ExitSinkSettings};
