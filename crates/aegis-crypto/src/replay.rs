//! Per-epoch replay cache. §4.1.
//!
//! Each mix records the per-packet tag it has seen this epoch and rejects
//! duplicates (defeats replay-based tagging/correlation). Cleared each epoch when
//! ephemeral keys rotate. Implemented in full (non-crypto-sensitive).
//!
//! NOTE for Phase 2: back this with a fixed-capacity structure (e.g. a cuckoo
//! filter or sharded HashSet) sized to the per-epoch packet volume; the naive
//! HashSet here is correct but not memory-bounded.

use std::collections::HashSet;

/// A 32-byte per-packet replay tag (derived from the shared secret in Phase 2).
pub type ReplayTag = [u8; 32];

#[derive(Default)]
pub struct ReplayCache {
    seen: HashSet<ReplayTag>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if the tag is fresh (and records it); false if replayed.
    pub fn check_and_insert(&mut self, tag: ReplayTag) -> bool {
        self.seen.insert(tag)
    }

    /// Call at epoch rollover (keys rotate, so old tags can never re-appear).
    pub fn clear(&mut self) {
        self.seen.clear();
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}
