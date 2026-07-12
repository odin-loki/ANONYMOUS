//! Permissioned relay admission (spec §4.9).
//!
//! Signing, persistence, and consortium governance are future work (Phase 5).

use std::collections::HashMap;

use crate::types::{RelayId, RelayRecord};

/// In-memory admission list: only rostered relays are eligible for layer assignment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayRoster {
    relays: HashMap<RelayId, RelayRecord>,
}

impl RelayRoster {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit a relay to the permissioned set.
    pub fn admit(&mut self, relay: RelayRecord) {
        self.relays.insert(relay.id, relay);
    }

    /// Remove a relay; returns `true` if it was present.
    pub fn remove(&mut self, id: RelayId) -> bool {
        self.relays.remove(&id).is_some()
    }

    pub fn is_admitted(&self, id: RelayId) -> bool {
        self.relays.contains_key(&id)
    }

    pub fn get(&self, id: RelayId) -> Option<&RelayRecord> {
        self.relays.get(&id)
    }

    pub fn len(&self) -> usize {
        self.relays.len()
    }

    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }

    /// All admitted relays in stable id order (for deterministic epoch assignment).
    pub fn admitted_sorted(&self) -> Vec<RelayRecord> {
        let mut relays: Vec<_> = self.relays.values().cloned().collect();
        relays.sort_by_key(|r| r.id);
        relays
    }
}
