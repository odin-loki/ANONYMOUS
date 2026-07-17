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
//! ### Generation batches (load hardening)
//!
//! Each insert is tagged with a monotonic **generation** counter. [`advance_epoch`]
//! drops the entire oldest generation in one step — under sustained flood this
//! **shortens the effective replay window** instead of silently re-admitting tags
//! one-at-a-time via FIFO. When fill exceeds [`DEFAULT_AUTO_ADVANCE_FILL_RATIO`]
//! of capacity, [`ReplayCache::check_and_insert`] auto-advances before inserting,
//! aggressively shrinking the window under pressure.
//!
//! ### Security trade-off
//!
//! Once eviction begins, a tag that was inserted early in a long epoch *could*
//! theoretically be replayed if it is evicted before the epoch ends (keys still
//! valid). [`clear()`] at epoch rollover is the real defense — old tags cannot
//! reappear after key rotation. Size the capacity so that, for your expected
//! per-epoch packet volume and epoch length (hours in the AEGIS design), eviction
//! never occurs in practice; the cap only bounds worst-case memory.
//!
//! **Residual:** `HashSet::contains` is not constant-time; membership timing may
//! still leak cache state (see `docs/AEGIS_crypto_constant_time_review.md`).

use std::collections::{HashMap, HashSet, VecDeque};

/// A 32-byte per-packet replay tag (derived from the shared secret in Phase 2).
pub type ReplayTag = [u8; 32];

/// Default bound: ~1M tags ≈ 32 MiB of tag storage (plus deque overhead).
///
/// At a sustained 1 000 packets/s through one mix, 1M entries cover roughly
/// 17 minutes of unique traffic — well within a multi-hour epoch, so FIFO
/// eviction should not occur under normal load. Tune [`ReplayCache::with_capacity`]
/// if your deployment sees higher per-hop volume.
pub const DEFAULT_REPLAY_CACHE_CAPACITY: usize = 1_000_000;

/// When `len >= capacity * ratio`, [`ReplayCache::check_and_insert`] may auto-
/// advance a generation before inserting (shortens window under flood).
pub const DEFAULT_AUTO_ADVANCE_FILL_RATIO: f64 = 0.85;

/// Default number of generation batches retained before the oldest is dropped.
pub const DEFAULT_MAX_GENERATIONS: usize = 4;

/// Minimum capacity before proactive fill-ratio auto-advance runs (small test
/// caches keep legacy FIFO-only behavior).
const MIN_CAPACITY_FOR_PRESSURE_ADVANCE: usize = 1024;

pub struct ReplayCache {
    seen: HashSet<ReplayTag>,
    /// FIFO order for per-tag eviction when a single generation is still full.
    order: VecDeque<(u32, ReplayTag)>,
    /// Tags grouped by insert generation (for bulk drop on advance).
    by_generation: HashMap<u32, HashSet<ReplayTag>>,
    /// Active generations, oldest at the front.
    active_generations: VecDeque<u32>,
    capacity: usize,
    generation: u32,
    max_generations: usize,
    auto_advance_fill_ratio: f64,
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
    /// recording a new one. Under high fill, generations are advanced first.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(capacity.min(4096)),
            order: VecDeque::with_capacity(capacity.min(4096)),
            by_generation: HashMap::new(),
            active_generations: VecDeque::new(),
            capacity,
            generation: 0,
            max_generations: DEFAULT_MAX_GENERATIONS,
            auto_advance_fill_ratio: DEFAULT_AUTO_ADVANCE_FILL_RATIO,
        }
    }

    /// Returns true if the tag is fresh (and records it); false if replayed.
    ///
    /// Auto-advances the oldest generation when fill exceeds
    /// [`DEFAULT_AUTO_ADVANCE_FILL_RATIO`] before accepting a new tag.
    pub fn check_and_insert(&mut self, tag: ReplayTag) -> bool {
        if self.seen.contains(&tag) {
            return false;
        }

        if self.capacity > 0 {
            let proactive = self.capacity >= MIN_CAPACITY_FOR_PRESSURE_ADVANCE;
            if proactive {
                let threshold = ((self.capacity as f64) * self.auto_advance_fill_ratio) as usize;
                if self.seen.len() >= threshold {
                    self.advance_epoch();
                }
            }
        }

        if self.capacity > 0 && self.seen.len() >= self.capacity {
            if self.capacity >= MIN_CAPACITY_FOR_PRESSURE_ADVANCE {
                self.advance_epoch();
            }
            if self.seen.len() >= self.capacity {
                if let Some((gen, oldest)) = self.order.pop_front() {
                    self.remove_tag_from_generation(gen, &oldest);
                }
            }
        }

        self.insert_tag(tag);
        true
    }

    /// Drop the oldest generation batch. Shortens the effective replay window under
    /// sustained load; call explicitly at sub-epoch boundaries if desired.
    pub fn advance_epoch(&mut self) {
        if let Some(old_gen) = self.active_generations.pop_front() {
            self.drop_generation(old_gen);
        }

        self.generation = self.generation.wrapping_add(1);
        self.active_generations.push_back(self.generation);

        while self.active_generations.len() > self.max_generations {
            if let Some(old_gen) = self.active_generations.pop_front() {
                self.drop_generation(old_gen);
            } else {
                break;
            }
        }
    }

    /// Call at epoch rollover (keys rotate, so old tags can never re-appear).
    pub fn clear(&mut self) {
        self.seen.clear();
        self.order.clear();
        self.by_generation.clear();
        self.active_generations.clear();
        self.generation = 0;
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Current insert generation (monotonic until [`Self::clear`]).
    pub fn generation(&self) -> u32 {
        self.generation
    }

    fn insert_tag(&mut self, tag: ReplayTag) {
        if self.active_generations.is_empty() {
            self.active_generations.push_back(self.generation);
        }

        self.seen.insert(tag);
        self.order.push_back((self.generation, tag));
        self.by_generation
            .entry(self.generation)
            .or_default()
            .insert(tag);
    }

    fn remove_tag_from_generation(&mut self, gen: u32, tag: &ReplayTag) {
        self.seen.remove(tag);
        if let Some(gen_set) = self.by_generation.get_mut(&gen) {
            gen_set.remove(tag);
            if gen_set.is_empty() {
                self.by_generation.remove(&gen);
                self.active_generations.retain(|&g| g != gen);
            }
        }
    }

    fn drop_generation(&mut self, gen: u32) {
        if let Some(tags) = self.by_generation.remove(&gen) {
            for tag in tags {
                self.seen.remove(&tag);
            }
        }
        self.order.retain(|(g, _)| *g != gen);
        self.active_generations.retain(|&g| g != gen);
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
        assert_eq!(cache.generation(), 0);
        assert!(cache.check_and_insert(tag(9)));
    }

    #[test]
    fn advance_epoch_drops_oldest_generation() {
        let mut cache = ReplayCache::with_capacity(32);
        cache.auto_advance_fill_ratio = 1.0; // disable auto-advance during setup

        assert!(cache.check_and_insert(tag(1)));
        assert!(cache.check_and_insert(tag(2)));
        cache.advance_epoch();
        assert!(cache.check_and_insert(tag(3)));

        // tag(1) and tag(2) were in generation 0, dropped on advance
        assert!(cache.check_and_insert(tag(1)));
        assert!(cache.check_and_insert(tag(2)));
    }

    fn unique_tag(i: usize) -> ReplayTag {
        let mut t = [0u8; 32];
        t[..8].copy_from_slice(&(i as u64).to_le_bytes());
        t
    }

    #[test]
    fn auto_advance_under_fill_pressure_shortens_window() {
        let cap = MIN_CAPACITY_FOR_PRESSURE_ADVANCE + 8;
        let mut cache = ReplayCache::with_capacity(cap);
        cache.auto_advance_fill_ratio = 0.85;

        let threshold = ((cap as f64) * 0.85) as usize;
        for i in 0..=threshold {
            assert!(cache.check_and_insert(unique_tag(i)));
        }
        assert!(
            cache.generation() >= 1,
            "large cache should proactive-advance before hitting hard capacity"
        );
    }

    #[test]
    fn advance_epoch_on_empty_cache_increments_generation_only() {
        let mut cache = ReplayCache::with_capacity(8);
        cache.advance_epoch();
        assert!(cache.is_empty());
        assert_eq!(cache.generation(), 1);
    }
}
