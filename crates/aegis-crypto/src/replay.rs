//! Per-epoch replay cache. §4.1.
//!
//! Each mix records the per-packet tag it has seen this epoch and rejects
//! duplicates (defeats replay-based tagging/correlation). Cleared each epoch when
//! ephemeral keys rotate. Implemented in full (non-crypto-sensitive).
//!
//! ## Capacity and eviction
//!
//! The cache is bounded (default [`DEFAULT_REPLAY_CACHE_CAPACITY`]) using a
//! [`HashSet`] for O(1) membership plus a [`VecDeque`] for FIFO eviction when
//! full. This is a **DoS backstop** against unbounded memory growth under flood
//! traffic; it is **not** the primary replay boundary.
//!
//! ### Security trade-off
//!
//! Once eviction begins, a tag that was inserted early in a long epoch *could*
//! theoretically be replayed if it is evicted before the epoch ends (keys still
//! valid). [`clear()`] at epoch rollover is the real defense — old tags cannot
//! reappear after key rotation. Size the capacity so that, for your expected
//! per-epoch packet volume and epoch length (hours in the AEGIS design), eviction
//! never occurs in practice; the cap only bounds worst-case memory.

use std::collections::{HashSet, VecDeque};

/// A 32-byte per-packet replay tag (derived from the shared secret in Phase 2).
pub type ReplayTag = [u8; 32];

/// Default bound: ~1M tags ≈ 32 MiB of tag storage (plus deque overhead).
///
/// At a sustained 1 000 packets/s through one mix, 1M entries cover roughly
/// 17 minutes of unique traffic — well within a multi-hour epoch, so FIFO
/// eviction should not occur under normal load. Tune [`ReplayCache::with_capacity`]
/// if your deployment sees higher per-hop volume.
pub const DEFAULT_REPLAY_CACHE_CAPACITY: usize = 1_000_000;

pub struct ReplayCache {
    seen: HashSet<ReplayTag>,
    order: VecDeque<ReplayTag>,
    capacity: usize,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_REPLAY_CACHE_CAPACITY)
    }

    /// Bounded cache; when full, the oldest inserted tag is evicted (FIFO) before
    /// recording a new one.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(capacity.min(4096)),
            order: VecDeque::with_capacity(capacity.min(4096)),
            capacity,
        }
    }

    /// Returns true if the tag is fresh (and records it); false if replayed.
    pub fn check_and_insert(&mut self, tag: ReplayTag) -> bool {
        if self.seen.contains(&tag) {
            return false;
        }
        if self.capacity > 0 && self.seen.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        self.seen.insert(tag);
        self.order.push_back(tag);
        true
    }

    /// Call at epoch rollover (keys rotate, so old tags can never re-appear).
    pub fn clear(&mut self) {
        self.seen.clear();
        self.order.clear();
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(n: u8) -> ReplayTag {
        let mut t = [0u8; 32];
        t[0] = n;
        t
    }

    #[test]
    fn capacity_eviction_keeps_len_bounded() {
        let cap = 8;
        let k = 5;
        let mut cache = ReplayCache::with_capacity(cap);
        for i in 0..(cap + k) {
            assert!(cache.check_and_insert(tag(i as u8)));
        }
        assert_eq!(cache.len(), cap);
    }

    #[test]
    fn duplicate_detection_within_window() {
        let cap = 4;
        let mut cache = ReplayCache::with_capacity(cap);
        for i in 0..cap {
            assert!(cache.check_and_insert(tag(i as u8)));
        }
        for i in 0..cap {
            assert!(!cache.check_and_insert(tag(i as u8)));
        }
    }

    #[test]
    fn evicted_tag_accepted_again() {
        let cap = 3;
        let mut cache = ReplayCache::with_capacity(cap);
        assert!(cache.check_and_insert(tag(1)));
        assert!(cache.check_and_insert(tag(2)));
        assert!(cache.check_and_insert(tag(3)));
        // Evicts tag(1), accepts tag(4)
        assert!(cache.check_and_insert(tag(4)));
        assert_eq!(cache.len(), cap);
        // tag(1) was evicted — no longer rejected
        assert!(cache.check_and_insert(tag(1)));
    }

    #[test]
    fn clear_resets_cache() {
        let mut cache = ReplayCache::with_capacity(16);
        assert!(cache.check_and_insert(tag(9)));
        assert!(!cache.check_and_insert(tag(9)));
        cache.clear();
        assert!(cache.is_empty());
        assert!(cache.check_and_insert(tag(9)));
    }
}
