//! Library surface for integration tests and the `aegis-node` binary.

pub mod config;
pub mod exit_sink;

pub use config::{ExitConfig, NodeConfigFile, NodeRuntimeConfig, TraceConfig};
pub use exit_sink::{spawn_exit_sink, ExitDeliverTarget, ExitSinkSettings};
