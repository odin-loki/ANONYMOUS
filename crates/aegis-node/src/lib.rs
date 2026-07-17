//! Library surface for integration tests and the `aegis-node` binary.

pub mod config;
pub mod exit_sink;

pub use config::{
    load_roster_from_config, ExitConfig, NodeConfigFile, NodeRuntimeConfig, RosterFileConfig,
    TraceConfig,
};
pub use exit_sink::{spawn_exit_sink, ExitDeliverTarget, ExitSinkSettings};
