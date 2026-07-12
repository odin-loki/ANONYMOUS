//! Topology error types.

use thiserror::Error;

use crate::types::RelayId;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TopologyError {
    #[error("no admitted relays on roster")]
    EmptyRoster,

    #[error("layer count must be at least 1, got {0}")]
    InvalidLayerCount(usize),

    #[error("layer {layer} is empty in epoch {epoch}")]
    EmptyLayer { layer: usize, epoch: u64 },

    #[error("relay {relay:?} is not admitted")]
    NotAdmitted { relay: RelayId },

    #[error("not enough layer-1 relays ({available}) for {needed} guards")]
    InsufficientGuards { available: usize, needed: usize },

    #[error("relay {relay:?} not found in roster")]
    RelayNotFound { relay: RelayId },
}
