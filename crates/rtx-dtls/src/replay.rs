//! Bounded replay protection for DTLS 1.2 record sequence numbers.
//!
//! RFC 6347 section 4.1.2.6 requires every record to be checked against a
//! replay window. This module implements a 64-record sliding window: the
//! bitmap records which of the 64 sequence numbers at or below the highest
//! accepted value have already been seen.
//!
//! A sequence number above the window slides it forward. A sequence number
//! below the window is [`RecordError::TooOld`]; a sequence number still inside
//! the window but already seen is [`RecordError::Replay`]. The two causes are
//! deliberately distinguishable so a caller can count drops separately.
//!
//! The window is per epoch: DTLS restarts sequence numbers when the epoch
//! changes, so the owner resets it on a cipher/epoch switch (see
//! [`crate::RecordMachine::install_cipher`]).

use core::cmp::Ordering;

use crate::error::RecordError;
use crate::record::SequenceNumber;

/// Number of sequence numbers the replay window tracks.
pub const REPLAY_WINDOW_SIZE: u64 = 64;

/// Outcome of classifying a sequence number without mutating the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    /// No record has been accepted yet.
    First,
    /// A new sequence number above the highest accepted one, `shift` ahead.
    Ahead(u64),
    /// A new sequence number below the highest accepted one, `delta` behind.
    Behind(u64),
}

/// 64-record sliding replay window.
#[derive(Debug, Clone, Default)]
pub struct ReplayWindow {
    highest: Option<SequenceNumber>,
    /// Bit `n` is set when `highest - n` has been accepted, for `n < 64`.
    bitmap: u64,
}

impl ReplayWindow {
    /// Creates an empty window that accepts the first record it sees.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            highest: None,
            bitmap: 0,
        }
    }

    /// Highest sequence number accepted so far.
    #[must_use]
    pub const fn highest(&self) -> Option<SequenceNumber> {
        self.highest
    }

    /// Clears the window. Called when the epoch changes.
    pub fn reset(&mut self) {
        self.highest = None;
        self.bitmap = 0;
    }

    /// Checks whether `sequence_number` would be accepted, without changing
    /// the window.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::Replay`] when the sequence number is already in
    /// the window, and [`RecordError::TooOld`] when it has fallen below it.
    pub fn check(&self, sequence_number: SequenceNumber) -> Result<(), RecordError> {
        self.classify(sequence_number).map(|_| ())
    }

    /// Classifies and admits `sequence_number` into the window.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`ReplayWindow::check`]. The window is not
    /// modified on error.
    pub fn accept(&mut self, sequence_number: SequenceNumber) -> Result<(), RecordError> {
        match self.classify(sequence_number)? {
            Admission::First => {
                self.highest = Some(sequence_number);
                self.bitmap = 1;
            }
            Admission::Ahead(shift) => {
                // Gaps of 64 or more discard the old bitmap entirely.
                self.bitmap = if shift >= REPLAY_WINDOW_SIZE {
                    1
                } else {
                    (self.bitmap << shift) | 1
                };
                self.highest = Some(sequence_number);
            }
            Admission::Behind(delta) => {
                self.bitmap |= 1u64 << delta;
            }
        }
        Ok(())
    }
}

impl ReplayWindow {
    fn classify(&self, sequence_number: SequenceNumber) -> Result<Admission, RecordError> {
        let Some(highest) = self.highest else {
            return Ok(Admission::First);
        };
        let highest = highest.as_u64();
        let candidate = sequence_number.as_u64();
        match candidate.cmp(&highest) {
            Ordering::Greater => Ok(Admission::Ahead(candidate - highest)),
            Ordering::Equal => Err(RecordError::Replay),
            Ordering::Less => {
                let delta = highest - candidate;
                if delta >= REPLAY_WINDOW_SIZE {
                    Err(RecordError::TooOld)
                } else if self.bitmap & (1u64 << delta) != 0 {
                    Err(RecordError::Replay)
                } else {
                    Ok(Admission::Behind(delta))
                }
            }
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    fn seq(value: u64) -> SequenceNumber {
        SequenceNumber::from_u64(value).expect("48-bit value")
    }

    // DTLS-REPLAY-001 — first record is accepted and fixes the window top.
    #[test]
    fn first_record_is_accepted() {
        let mut window = ReplayWindow::new();
        assert_eq!(window.highest(), None);
        assert_eq!(window.check(seq(0)), Ok(()));
        assert_eq!(window.accept(seq(0)), Ok(()));
        assert_eq!(window.highest(), Some(seq(0)));
        assert_eq!(window.accept(seq(0)), Err(RecordError::Replay));
    }

    // DTLS-REPLAY-002 — reordering inside the window is accepted once.
    #[test]
    fn out_of_order_records_inside_the_window_are_accepted_once() {
        let mut window = ReplayWindow::new();
        for value in [5, 7, 6, 4, 0] {
            window.accept(seq(value)).expect("inside window");
        }
        for value in [0, 4, 5, 6, 7] {
            assert_eq!(window.check(seq(value)), Err(RecordError::Replay));
            assert_eq!(window.accept(seq(value)), Err(RecordError::Replay));
        }
        assert_eq!(window.highest(), Some(seq(7)));
        // 1..=3 remain unseen and are still admissible.
        for value in 1..=3 {
            window.accept(seq(value)).expect("unseen hole");
        }
        assert_eq!(window.accept(seq(1)), Err(RecordError::Replay));
    }

    // DTLS-REPLAY-003 — the 64-record window boundary is exact.
    #[test]
    fn window_boundary_is_exactly_64_records() {
        let mut window = ReplayWindow::new();
        window.accept(seq(0)).expect("first");
        window.accept(seq(63)).expect("delta 63");
        assert_eq!(window.highest(), Some(seq(63)));
        assert_eq!(window.accept(seq(0)), Err(RecordError::Replay));
        // highest = 63, so 0 is delta 63: inside. Move the top to 64.
        window.accept(seq(64)).expect("delta 1");
        assert_eq!(window.accept(seq(0)), Err(RecordError::TooOld));
        assert_eq!(window.check(seq(0)), Err(RecordError::TooOld));
        assert_eq!(window.accept(seq(1)), Ok(())); // delta 63: still inside
        assert_eq!(window.accept(seq(1)), Err(RecordError::Replay));
    }

    // DTLS-REPLAY-004 — a jump beyond the window slides it and drops the old
    // bitmap; records below the new bottom are TooOld.
    #[test]
    fn far_ahead_record_slides_the_window() {
        let mut window = ReplayWindow::new();
        window.accept(seq(3)).expect("first");
        window.accept(seq(100)).expect("jump 97");
        assert_eq!(window.highest(), Some(seq(100)));
        assert_eq!(window.accept(seq(99)), Ok(()));
        assert_eq!(window.accept(seq(99)), Err(RecordError::Replay));
        assert_eq!(window.accept(seq(36)), Err(RecordError::TooOld));
        assert_eq!(window.check(seq(36)), Err(RecordError::TooOld));
        assert_eq!(window.accept(seq(37)), Ok(())); // delta 63 is inside
        assert_eq!(window.check(seq(38)), Ok(()));
    }

    // DTLS-REPLAY-005 — a jump of exactly 64 discards the bitmap.
    #[test]
    fn jump_of_64_resets_the_bitmap() {
        let mut window = ReplayWindow::new();
        window.accept(seq(10)).expect("first");
        window.accept(seq(74)).expect("jump 64");
        assert_eq!(window.accept(seq(73)), Ok(()));
        assert_eq!(window.accept(seq(73)), Err(RecordError::Replay));
        assert_eq!(window.accept(seq(10)), Err(RecordError::TooOld));
    }

    // DTLS-REPLAY-006 — check never mutates, reset clears, default is empty.
    #[test]
    fn check_is_read_only_and_reset_reopens_the_window() {
        let mut window = ReplayWindow::default();
        assert_eq!(window.highest(), None);
        window.accept(seq(9)).expect("first");
        assert_eq!(window.check(seq(10)), Ok(()));
        assert_eq!(window.check(seq(9)), Err(RecordError::Replay));
        assert_eq!(window.highest(), Some(seq(9))); // unchanged by check

        window.reset();
        assert_eq!(window.highest(), None);
        assert_eq!(window.accept(seq(0)), Ok(()));
        assert_eq!(window.accept(seq(0)), Err(RecordError::Replay));
    }
}
