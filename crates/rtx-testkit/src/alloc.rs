//! Counting allocator with per-scenario labels (`M3-PM1`).
//!
//! The gate vocabulary (`docs/m3-m4-gates.md` §1.4.3) names four counters:
//! `alloc_count`, `free_count`, `allocated_bytes` and `peak_live_bytes`. This
//! module exposes those four plus two derived values (`freed_bytes` and
//! `live_bytes`) in [`Snapshot`].
//!
//! # Two ways to use the allocator
//!
//! - As the process allocator: install a [`CountingAlloc`] wrapper in a
//!   `#[global_allocator]` static. Every allocation made by the process then
//!   reaches the wrapper's counters and, when the allocating thread has an
//!   active scene, the matching scene slot.
//! - As a plain counting wrapper: construct [`CountingAlloc::new`] around any
//!   `GlobalAlloc` and read [`CountingAlloc::counters`]. The wrapper has its
//!   own [`Counters`]; it additionally feeds the scene slot of the allocating
//!   thread.
//!
//! # Scene label semantics
//!
//! 1. [`scene`] registers a `&'static str` label (process-global, at most
//!    [`MAX_SCENES`] distinct labels) and returns a [`SceneTag`]. Labels are
//!    looked up by name, so registering the same name twice yields the same
//!    tag. Registration may allocate: call it outside a measured region.
//! 2. [`enter`] sets the **thread-local** active tag and returns a
//!    [`SceneScope`] guard that restores the previous tag when dropped.
//!    `enter` itself does not allocate.
//! 3. Allocations on a thread with no active tag are counted in the
//!    unlabelled slot ([`SceneTag::UNLABELLED`], index `0`). Allocations on
//!    other threads are never attributed to a scene running on this thread,
//!    which is what single-threaded harness measurements need.
//! 4. [`reset`] zeroes one slot and [`snapshot`] reads it. A snapshot is
//!    taken by independent atomic loads, so it is only consistent when taken
//!    in a quiescent region (no concurrent allocation on that thread);
//!    [`reset`] has the same requirement.
//! 5. No logging happens in the allocation path. The counters are plain
//!    atomics; `println!`/`eprintln!` in an allocator would allocate and
//!    recurse.
//!
//! # `peak_live_bytes`
//!
//! The definition is the peak of the live-byte counter, not the process RSS:
//!
//! ```text
//! recorded_alloc(size): live = live + size; peak_live = max(peak_live, live)
//! recorded_free(size):  live = live - size  (saturating at 0)
//! ```
//!
//! `peak_live_bytes` therefore counts bytes obtained from the allocator and
//! not yet released. It says nothing about page-faulted resident memory;
//! `M3-P5` reports RSS (`VmHWM`, [`crate::proc`]) separately.
//!
//! # Counting caveats
//!
//! - `free_count` counts every deallocation observed in the slot, including
//!   frees of memory that was allocated before the slot was reset.
//! - `realloc` is counted as one allocation plus one deallocation, because
//!   [`CountingAlloc`] relies on the default `GlobalAlloc::realloc` body.
//! - `allocated_bytes` is the sum of requested layout sizes, not the
//!   allocator's real block sizes.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::vec::Vec;

/// Largest number of scene slots, including the unlabelled slot.
///
/// The table is a fixed-size static so that the allocation path never
/// allocates. Registering more than `MAX_SCENES - 1` named labels panics in
/// [`scene`].
pub const MAX_SCENES: usize = 16;

/// Slot index of the unlabelled scene.
const UNLABELLED: usize = 0;

/// The six counters of one slot.
///
/// Every counter is a relaxed atomic; nothing here allocates or locks, so
/// this type is safe to touch from inside a global allocator.
#[derive(Debug)]
pub struct Counters {
    alloc_count: AtomicU64,
    free_count: AtomicU64,
    allocated_bytes: AtomicU64,
    freed_bytes: AtomicU64,
    live_bytes: AtomicU64,
    peak_live_bytes: AtomicU64,
}

impl Counters {
    /// Creates a zeroed counter set (usable in `static` initialisers).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            alloc_count: AtomicU64::new(0),
            free_count: AtomicU64::new(0),
            allocated_bytes: AtomicU64::new(0),
            freed_bytes: AtomicU64::new(0),
            live_bytes: AtomicU64::new(0),
            peak_live_bytes: AtomicU64::new(0),
        }
    }

    /// Records one allocation of `size` bytes.
    ///
    /// This is the primitive [`CountingAlloc`] calls for every successful
    /// allocation. It is public so tests can exercise the arithmetic without
    /// performing a real allocation. It never allocates.
    pub fn record_alloc(&self, size: usize) {
        let bytes = u64::try_from(size).unwrap_or(u64::MAX);
        self.alloc_count.fetch_add(1, Ordering::Relaxed);
        self.allocated_bytes.fetch_add(bytes, Ordering::Relaxed);
        let live = self.live_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.peak_live_bytes
            .fetch_max(live.saturating_add(bytes), Ordering::Relaxed);
    }

    /// Records one deallocation of `size` bytes.
    ///
    /// `live_bytes` saturates at zero, so freeing memory that was allocated
    /// before the counter was reset cannot underflow. It never allocates.
    // fetch_update is deprecated in Rust 1.99 in favour of try_update, but
    // try_update is stable only since 1.95 and this crate's MSRV is 1.85.
    #[allow(deprecated)]
    pub fn record_dealloc(&self, size: usize) {
        let bytes = u64::try_from(size).unwrap_or(u64::MAX);
        self.free_count.fetch_add(1, Ordering::Relaxed);
        self.freed_bytes.fetch_add(bytes, Ordering::Relaxed);
        let _ = self
            .live_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |live| {
                Some(live.saturating_sub(bytes))
            });
    }

    /// Reads the six counters. See the module docs for consistency caveats.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            alloc_count: self.alloc_count.load(Ordering::Relaxed),
            free_count: self.free_count.load(Ordering::Relaxed),
            allocated_bytes: self.allocated_bytes.load(Ordering::Relaxed),
            freed_bytes: self.freed_bytes.load(Ordering::Relaxed),
            live_bytes: self.live_bytes.load(Ordering::Relaxed),
            peak_live_bytes: self.peak_live_bytes.load(Ordering::Relaxed),
        }
    }

    /// Zeroes every counter. Call only when no allocation is in flight.
    pub fn reset(&self) {
        self.alloc_count.store(0, Ordering::Relaxed);
        self.free_count.store(0, Ordering::Relaxed);
        self.allocated_bytes.store(0, Ordering::Relaxed);
        self.freed_bytes.store(0, Ordering::Relaxed);
        self.live_bytes.store(0, Ordering::Relaxed);
        self.peak_live_bytes.store(0, Ordering::Relaxed);
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}

/// One consistent read of a [`Counters`] slot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// Number of successful allocations.
    pub alloc_count: u64,
    /// Number of deallocations.
    pub free_count: u64,
    /// Sum of requested allocation sizes.
    pub allocated_bytes: u64,
    /// Sum of released allocation sizes.
    pub freed_bytes: u64,
    /// `allocated_bytes - freed_bytes`, saturating at zero.
    pub live_bytes: u64,
    /// Peak of `live_bytes`; see the module-level definition.
    pub peak_live_bytes: u64,
}

/// Handle for one registered scene label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SceneTag(usize);

impl SceneTag {
    /// The slot used when no scene is active.
    pub const UNLABELLED: Self = Self(UNLABELLED);

    /// The slot index in the fixed scene table.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }

    /// The registered label, or `"<unlabelled>"` for slot zero.
    ///
    /// # Panics
    ///
    /// Panics if the registry lock is poisoned by a panic while a label was
    /// being registered; registration is a test/harness-only path.
    #[must_use]
    pub fn name(self) -> &'static str {
        if self.0 == UNLABELLED {
            return "<unlabelled>";
        }
        let registry = REGISTRY.lock().unwrap_or_else(PoisonError::into_inner);
        registry
            .names
            .get(self.0 - 1)
            .copied()
            .unwrap_or("<unregistered>")
    }
}

/// The fixed scene table. Slot `0` is unlabelled.
static SLOTS: [Counters; MAX_SCENES] = [const { Counters::new() }; MAX_SCENES];

/// The registry of label names (index `i` stores the name of slot `i + 1`).
static REGISTRY: Mutex<Registry> = Mutex::new(Registry::new());

struct Registry {
    names: Vec<&'static str>,
}

impl Registry {
    const fn new() -> Self {
        Self { names: Vec::new() }
    }
}

std::thread_local! {
    /// The active scene slot of the current thread. Const-initialised so that
    /// reading it from the allocator never allocates.
    static ACTIVE: Cell<usize> = const { Cell::new(UNLABELLED) };
}

/// Registers `name` and returns its tag.
///
/// # Panics
///
/// Panics when more than [`MAX_SCENES`]` - 1` distinct labels are registered.
///
/// Registration may allocate (the label list grows): call it before entering
/// a measured region.
#[must_use]
pub fn scene(name: &'static str) -> SceneTag {
    let mut registry = REGISTRY.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(position) = registry
        .names
        .iter()
        .position(|registered| *registered == name)
    {
        return SceneTag(position + 1);
    }
    assert!(
        registry.names.len() + 1 < MAX_SCENES,
        "rtx-testkit supports at most {} named scene labels",
        MAX_SCENES - 1
    );
    registry.names.push(name);
    SceneTag(registry.names.len())
}

/// Makes `tag` the active scene of the current thread.
///
/// The returned guard restores the previous tag on drop. This function does
/// not allocate.
pub fn enter(tag: SceneTag) -> SceneScope {
    let previous = ACTIVE
        .try_with(|active| active.replace(tag.0))
        .unwrap_or(UNLABELLED);
    SceneScope {
        previous: SceneTag(previous),
    }
}

/// Restores the previous scene tag when dropped.
#[derive(Debug)]
#[must_use = "dropping the scope immediately restores the previous scene"]
pub struct SceneScope {
    previous: SceneTag,
}

impl Drop for SceneScope {
    fn drop(&mut self) {
        let _ = ACTIVE.try_with(|active| active.set(self.previous.0));
    }
}

/// The scene currently active on this thread.
#[must_use]
pub fn current() -> SceneTag {
    SceneTag(ACTIVE.try_with(Cell::get).unwrap_or(UNLABELLED))
}

/// Zeroes the counters of `tag`.
///
/// Call only when no allocation on the owning thread is in flight.
pub fn reset(tag: SceneTag) {
    if let Some(counters) = SLOTS.get(tag.0) {
        counters.reset();
    }
}

/// Reads the counters of `tag`.
#[must_use]
pub fn snapshot(tag: SceneTag) -> Snapshot {
    SLOTS.get(tag.0).map(Counters::snapshot).unwrap_or_default()
}

/// Reads the unlabelled slot.
#[must_use]
pub fn snapshot_unlabelled() -> Snapshot {
    snapshot(SceneTag::UNLABELLED)
}

/// A `GlobalAlloc` wrapper that counts every successful allocation.
///
/// See the module docs for the two usage modes and the `realloc` accounting
/// caveat.
#[derive(Debug)]
pub struct CountingAlloc<A> {
    inner: A,
    counters: Counters,
}

impl<A> CountingAlloc<A> {
    /// Wraps `inner`.
    #[must_use]
    pub const fn new(inner: A) -> Self {
        Self {
            inner,
            counters: Counters::new(),
        }
    }

    /// The wrapper's own counters (independent of the scene slots).
    #[must_use]
    pub const fn counters(&self) -> &Counters {
        &self.counters
    }

    fn record_alloc(&self, size: usize) {
        self.counters.record_alloc(size);
        record_into_active(|counters| counters.record_alloc(size));
    }

    fn record_dealloc(&self, size: usize) {
        self.counters.record_dealloc(size);
        record_into_active(|counters| counters.record_dealloc(size));
    }
}

fn record_into_active(record: impl FnOnce(&Counters)) {
    let slot = ACTIVE.try_with(Cell::get).unwrap_or(UNLABELLED);
    if let Some(counters) = SLOTS.get(slot) {
        record(counters);
    }
}

// `GlobalAlloc` is an unsafe trait, and `unsafe impl` cannot coexist with
// `forbid(unsafe_code)`. This is the single item the crate allows unsafe for
// (see the crate docs and the task's §0 unsafe concession). Safety: the
// wrapper forwards every call to `inner` unchanged and only observes the
// layout size after the inner allocator reports success; it adds no
// invariant, returns the inner pointer, and its counters are plain atomics
// with no shared mutable state outside those atomics. `record_*` never
// allocates, so the allocation path cannot recurse.
#[allow(
    unsafe_code,
    reason = "GlobalAlloc is an unsafe trait; the counters add no allocation invariant"
)]
unsafe impl<A: GlobalAlloc> GlobalAlloc for CountingAlloc<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { self.inner.alloc(layout) };
        if !ptr.is_null() {
            self.record_alloc(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { self.inner.alloc_zeroed(layout) };
        if !ptr.is_null() {
            self.record_alloc(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { self.inner.dealloc(ptr, layout) };
        self.record_dealloc(layout.size());
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CountingAlloc, SceneTag, current, enter, reset, scene, snapshot, snapshot_unlabelled,
    };
    use std::alloc::System;
    use std::vec::Vec;

    /// The counters must agree with a hand-computed allocation sequence.
    #[test]
    fn counter_arithmetic_matches_hand_computation() {
        let counters = super::Counters::new();
        counters.record_alloc(64);
        counters.record_alloc(128);
        counters.record_dealloc(64);
        counters.record_dealloc(32);
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.alloc_count, 2);
        assert_eq!(snapshot.free_count, 2);
        assert_eq!(snapshot.allocated_bytes, 192);
        assert_eq!(snapshot.freed_bytes, 96);
        assert_eq!(snapshot.live_bytes, 96);
        assert_eq!(snapshot.peak_live_bytes, 192);

        counters.record_dealloc(1024);
        let saturated = counters.snapshot();
        assert_eq!(saturated.live_bytes, 0, "live bytes saturate at zero");
        assert_eq!(saturated.peak_live_bytes, 192, "peak is unaffected");
    }

    /// `peak_live_bytes` is the peak of live bytes, not the last value.
    #[test]
    fn peak_tracks_the_high_water_mark() {
        let counters = super::Counters::new();
        counters.record_alloc(100);
        counters.record_alloc(100);
        counters.record_dealloc(150);
        counters.record_alloc(25);
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.live_bytes, 75);
        assert_eq!(snapshot.peak_live_bytes, 200);
    }

    /// Resetting a slot zeroes every counter.
    #[test]
    fn reset_zeroes_a_slot() {
        let tag = scene("reset_zeroes_a_slot");
        reset(tag);
        let scope = enter(tag);
        drop(Vec::<u8>::with_capacity(256));
        drop(scope);
        assert_eq!(snapshot(tag).alloc_count, 1, "one real allocation");
        reset(tag);
        assert_eq!(snapshot(tag), super::Snapshot::default());
    }

    /// Real allocations through the installed counting allocator are counted
    /// in the active scene: known counts, known bytes, then a release.
    #[test]
    fn real_allocations_are_counted_per_scene() {
        let tag = scene("real_allocations_are_counted_per_scene");
        reset(tag);
        {
            let _scope = enter(tag);
            let buffer = Vec::<u8>::with_capacity(1024);
            assert_eq!(buffer.capacity(), 1024);
        }
        let snapshot = snapshot(tag);
        assert_eq!(snapshot.alloc_count, 1);
        assert_eq!(snapshot.free_count, 1);
        assert_eq!(snapshot.allocated_bytes, 1024);
        assert_eq!(snapshot.freed_bytes, 1024);
        assert_eq!(snapshot.live_bytes, 0);
        assert_eq!(snapshot.peak_live_bytes, 1024);
    }

    /// A plain wrapper counts its own allocations and feeds the active scene
    /// slot at the same time.
    #[test]
    fn plain_wrapper_counts_and_feeds_the_scene() {
        let tag = scene("plain_wrapper_counts_and_feeds_the_scene");
        reset(tag);
        let wrapper = CountingAlloc::new(System);
        let scope = enter(tag);
        let layout = std::alloc::Layout::from_size_align(2048, 8).expect("valid layout");
        // Test-only: exercising the `GlobalAlloc` contract requires unsafe
        // calls. This block is not part of the crate's unsafe item; see the
        // crate docs for the single `unsafe impl` and this test's note in the
        // PR description.
        #[allow(unsafe_code)]
        unsafe {
            let ptr = <CountingAlloc<System> as std::alloc::GlobalAlloc>::alloc(&wrapper, layout);
            assert!(!ptr.is_null(), "the system allocator must succeed");
            <CountingAlloc<System> as std::alloc::GlobalAlloc>::dealloc(&wrapper, ptr, layout);
        }
        drop(scope);

        let wrapper_snapshot = wrapper.counters().snapshot();
        assert_eq!(wrapper_snapshot.alloc_count, 1);
        assert_eq!(wrapper_snapshot.allocated_bytes, 2048);
        let scene_snapshot = snapshot(tag);
        assert_eq!(scene_snapshot.alloc_count, 1);
        assert_eq!(scene_snapshot.allocated_bytes, 2048);
    }

    /// Scene registration is idempotent and `current` follows `enter`.
    #[test]
    fn tags_are_named_and_idempotent() {
        let first = scene("tags_are_named_and_idempotent");
        let second = scene("tags_are_named_and_idempotent");
        assert_eq!(first, second);
        assert_ne!(first, SceneTag::UNLABELLED);
        assert_eq!(first.name(), "tags_are_named_and_idempotent");
        assert_eq!(SceneTag::UNLABELLED.name(), "<unlabelled>");
        assert_eq!(current(), SceneTag::UNLABELLED);
        let scope = enter(first);
        assert_eq!(current(), first);
        drop(scope);
        assert_eq!(current(), SceneTag::UNLABELLED);
    }

    /// Nested scopes restore the previous tag.
    #[test]
    fn nested_scopes_restore_the_previous_tag() {
        let outer = scene("nested_scopes_restore_the_previous_tag_outer");
        let inner = scene("nested_scopes_restore_the_previous_tag_inner");
        let outer_scope = enter(outer);
        let inner_scope = enter(inner);
        assert_eq!(current(), inner);
        drop(inner_scope);
        assert_eq!(current(), outer, "the inner scope restores the outer tag");
        drop(outer_scope);
        assert_eq!(current(), SceneTag::UNLABELLED);
    }

    /// The unlabelled slot sees allocations made without a scene.
    #[test]
    fn unlabelled_allocations_land_in_slot_zero() {
        let before = snapshot_unlabelled().alloc_count;
        let buffer = Vec::<u8>::with_capacity(128);
        drop(buffer);
        assert!(
            snapshot_unlabelled().alloc_count > before,
            "an allocation outside a scene must reach the unlabelled slot"
        );
    }

    /// Out-of-range tags read as defaults instead of panicking.
    #[test]
    fn out_of_range_tags_return_defaults() {
        let invalid = SceneTag(usize::MAX);
        assert_eq!(snapshot(invalid), super::Snapshot::default());
        reset(invalid);
        assert_eq!(invalid.name(), "<unregistered>");
        assert_eq!(SceneTag::UNLABELLED.index(), 0);
    }
}
