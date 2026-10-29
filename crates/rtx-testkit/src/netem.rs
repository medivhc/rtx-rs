//! Deterministic loss/RTT simulator (`M3-PM2`).
//!
//! The gate (`docs/m3-m4-gates.md` §1.4.3) requires loss and RTT to be
//! injected by a deterministic simulator, with unit tests, no real `tc netem`
//! and no dependency on an external network. This module is that simulator:
//!
//! - it is `core`-only (no clock, no I/O, no allocation),
//! - it is seeded, so the same seed and the same input sequence produce the
//!   same decisions byte for byte,
//! - it expresses delay as **virtual** one-way microseconds; the caller
//!   decides how its pump advances that timeline.
//!
//! # Decision model
//!
//! Each call to [`Netem::next_decision`] consumes two 64-bit values from a
//! `SplitMix64` generator:
//!
//! 1. `roll = value % 100`; the packet is dropped when
//!    `roll < loss_percent`. A loss rate of `0` therefore never drops and a
//!    rate of `100` always drops, without special cases.
//! 2. `jitter = value % (jitter_micros + 1)`; the one-way delay is
//!    `rtt_micros / 2 + jitter`.
//!
//! The sequence number starts at zero and increases by one per decision; it
//! is part of the decision so a caller can log which packet was dropped.
//!
//! # Why not `tc netem`
//!
//! `M3-PM2` forbids it. A kernel qdisc would also make the verdict depend on
//! the host, the kernel version and the wall clock, which is exactly what a
//! benchmark baseline must not do.

use core::fmt;

/// Loss/RTT profile.
///
/// `rtt_micros` is a round-trip time; the simulator reports a one-way delay of
/// `rtt_micros / 2` plus jitter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    seed: u64,
    loss_percent: u8,
    rtt_micros: u64,
    jitter_micros: u64,
}

impl Profile {
    /// Builds a profile.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::LossOutOfRange`] when `loss_percent` is above
    /// 100.
    pub const fn new(
        seed: u64,
        loss_percent: u8,
        rtt_micros: u64,
        jitter_micros: u64,
    ) -> Result<Self, ProfileError> {
        if loss_percent > 100 {
            return Err(ProfileError::LossOutOfRange);
        }
        Ok(Self {
            seed,
            loss_percent,
            rtt_micros,
            jitter_micros,
        })
    }

    /// The seed that fixes the decision sequence.
    #[must_use]
    pub const fn seed(self) -> u64 {
        self.seed
    }

    /// The loss rate in percent (`0..=100`).
    #[must_use]
    pub const fn loss_percent(self) -> u8 {
        self.loss_percent
    }

    /// The round-trip time in virtual microseconds.
    #[must_use]
    pub const fn rtt_micros(self) -> u64 {
        self.rtt_micros
    }

    /// The maximum additional one-way delay in virtual microseconds.
    #[must_use]
    pub const fn jitter_micros(self) -> u64 {
        self.jitter_micros
    }

    /// The nominal one-way delay (`rtt_micros / 2`).
    #[must_use]
    pub const fn one_way_delay_micros(self) -> u64 {
        self.rtt_micros / 2
    }
}

/// Profile construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileError {
    /// `loss_percent` was above 100.
    LossOutOfRange,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LossOutOfRange => formatter.write_str("loss percent must be 0..=100"),
        }
    }
}

/// One simulated packet verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// Zero-based index of the decision in this simulator's sequence.
    pub sequence: u64,
    /// Whether the packet is dropped.
    pub dropped: bool,
    /// One-way delay in virtual microseconds (meaningless when dropped).
    pub delay_micros: u64,
}

/// A deterministic simulator.
#[derive(Debug, Clone)]
pub struct Netem {
    profile: Profile,
    state: u64,
    sequence: u64,
}

impl Netem {
    /// Starts a sequence for `profile`.
    ///
    /// The generator state is the seed itself: two simulators built with the
    /// same profile produce the same sequence, regardless of when they are
    /// constructed.
    #[must_use]
    pub const fn new(profile: Profile) -> Self {
        Self {
            profile,
            state: profile.seed,
            sequence: 0,
        }
    }

    /// The profile driving this sequence.
    #[must_use]
    pub const fn profile(&self) -> Profile {
        self.profile
    }

    /// The index the next decision will carry.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Produces the verdict for the next packet.
    pub fn next_decision(&mut self) -> Decision {
        let roll = next_u64(&mut self.state) % 100;
        let jitter = next_u64(&mut self.state) % (self.profile.jitter_micros + 1);
        self.sequence = self.sequence.wrapping_add(1);
        Decision {
            sequence: self.sequence - 1,
            dropped: roll < u64::from(self.profile.loss_percent),
            delay_micros: self.profile.one_way_delay_micros() + jitter,
        }
    }
}

/// `SplitMix64` (`stea`/Java `SplittableRandom` step), a small and well-known
/// deterministic generator.
fn next_u64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::{Netem, Profile, ProfileError};
    use std::vec::Vec;

    fn profile(seed: u64, loss_percent: u8) -> Profile {
        Profile::new(seed, loss_percent, 50_000, 1_000).expect("valid profile")
    }

    fn decisions(netem: &mut Netem, count: usize) -> Vec<super::Decision> {
        (0..count).map(|_| netem.next_decision()).collect()
    }

    /// `M3-PM2`: the same seed and input sequence reproduce the verdict
    /// sequence exactly.
    #[test]
    fn m3_pm2_netem_deterministic() {
        let mut first = Netem::new(profile(7, 10));
        let mut second = Netem::new(profile(7, 10));
        let first_run = decisions(&mut first, 256);
        let second_run = decisions(&mut second, 256);
        assert_eq!(first_run, second_run);
        assert_eq!(first_run.len(), 256);
        assert_eq!(first_run[0].sequence, 0);
        assert_eq!(first_run[255].sequence, 255);
    }

    /// A different seed produces a different verdict sequence.
    #[test]
    fn different_seeds_produce_different_sequences() {
        let mut first = Netem::new(profile(1, 10));
        let mut second = Netem::new(profile(2, 10));
        let first_run = decisions(&mut first, 64);
        let second_run = decisions(&mut second, 64);
        assert_ne!(first_run, second_run);
    }

    /// A loss rate of 0 passes every packet.
    #[test]
    fn loss_zero_passes_every_packet() {
        let mut netem = Netem::new(profile(9, 0));
        for decision in decisions(&mut netem, 128) {
            assert!(!decision.dropped);
        }
    }

    /// A loss rate of 100 drops every packet.
    #[test]
    fn loss_hundred_drops_every_packet() {
        let mut netem = Netem::new(profile(11, 100));
        for decision in decisions(&mut netem, 128) {
            assert!(decision.dropped);
        }
    }

    /// Without jitter the one-way delay is exactly half the RTT.
    #[test]
    fn delay_is_half_the_rtt_without_jitter() {
        let profile = Profile::new(3, 0, 200_000, 0).expect("valid profile");
        let mut netem = Netem::new(profile);
        for decision in decisions(&mut netem, 16) {
            assert_eq!(decision.delay_micros, 100_000);
        }
    }

    /// Jitter stays within `rtt / 2 ..= rtt / 2 + jitter`.
    #[test]
    fn jitter_stays_within_the_profile_bounds() {
        let profile = Profile::new(5, 0, 40_000, 500).expect("valid profile");
        let mut netem = Netem::new(profile);
        for decision in decisions(&mut netem, 128) {
            assert!((20_000..=20_500).contains(&decision.delay_micros));
        }
    }

    /// An out-of-range loss rate is rejected.
    #[test]
    fn loss_above_hundred_is_rejected() {
        assert_eq!(
            Profile::new(1, 101, 0, 0).expect_err("101% is invalid"),
            ProfileError::LossOutOfRange
        );
        assert_eq!(
            Profile::new(1, 100, 0, 0)
                .expect("100% is valid")
                .loss_percent(),
            100
        );
    }
}
