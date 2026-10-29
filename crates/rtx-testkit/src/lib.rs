#![cfg_attr(not(feature = "std"), no_std)]
//! Test-only support for the `M3-P` benchmark methodology
//! (`docs/m3-m4-gates.md` §1.4.3, `M3-PM1` and `M3-PM2`).
//!
//! This crate is deliberately **not** a production dependency. It exists so
//! that tests and the standalone benchmark harness can measure allocation
//! behaviour and exercise packet loss without a real network:
//!
//! - [`alloc`] is a counting allocator (usable as the process `GlobalAlloc`
//!   and as a plain wrapper) with per-scenario labels, exposing the four
//!   `M3-P6` counters `alloc_count`, `free_count`, `allocated_bytes` and
//!   `peak_live_bytes`.
//! - [`netem`] is a deterministic loss/RTT simulator. It consumes no wall
//!   clock, performs no I/O and never calls `tc netem`; identical input
//!   sequences and seeds produce identical decisions.
//! - `proc` reads `VmHWM` from `/proc/self/status` (`M3-P5`) and is compiled
//!   only for `std`/test builds.
//!
//! # Boundary
//!
//! No `rtx-*` production crate may depend on `rtx-testkit` in its normal
//! dependency graph. `cargo tree -e normal` on a production crate must not
//! list it; only the standalone `benchmarks/m3` harness and `dev-dependencies`
//! of test targets may use it. The crate is a workspace member so the gate
//! path `crates/rtx-testkit/src/alloc.rs` exists and `cargo test -p
//! rtx-testkit` is part of the workspace gates.
//!
//! # Feature gating
//!
//! `default = []` and `std = []` are the only features. The crate is
//! `no_std` without `std`; `alloc` and `proc` need `std` facilities (atomics
//! with 64-bit support, `std::sync::Mutex`, `/proc` I/O) and are therefore
//! compiled only for `std` builds **and** for test builds (the Rust test
//! harness always links `std`, so the unit tests run under the default
//! feature set as well). The bare-metal check
//! (`cargo check --workspace --no-default-features --target
//! thumbv7em-none-eabihf`) compiles only [`netem`], which is `core`-only:
//! `thumbv7em-none-eabihf` has no 64-bit atomics.
//!
//! # The one `unsafe` item
//!
//! `GlobalAlloc` is an unsafe trait. The workspace lints `unsafe_code =
//! "forbid"`, which cannot be relaxed in scope, so this crate uses an
//! explicit `unsafe_code = "deny"` lint and `#[allow(unsafe_code)]` on
//! exactly one item: the `GlobalAlloc` impl in [`alloc`]. No other `unsafe`
//! item, block or trait implementation exists in this crate.

#[cfg(test)]
extern crate std;

#[cfg(any(feature = "std", test))]
pub mod alloc;
pub mod netem;
#[cfg(any(feature = "std", test))]
pub mod proc;

#[cfg(test)]
mod pt2;

/// The unit-test binary installs the counting allocator so `M3-PT2` can
/// observe the codec's allocations. The harness installs its own copy; this
/// static exists only in `cargo test -p rtx-testkit`.
#[cfg(test)]
#[global_allocator]
static TEST_GLOBAL: alloc::CountingAlloc<std::alloc::System> =
    alloc::CountingAlloc::new(std::alloc::System);
