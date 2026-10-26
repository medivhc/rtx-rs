//! Bounded `SRTP` replay protection over 48-bit packet indices.
//!
//! The window is deliberately separate from the DTLS record replay window:
//! DTLS numbers are per-epoch, while `SRTP` indices are `ROC || SEQ` and roll
//! over. This window tracks 64 absolute indices. An index above the top slides
//! the window forward; an index below the bottom is [`Error::TooOld`]; an
//! index inside the window that has already been accepted is [`Error::Replay`].
//!
//! [`ReplayWindow::check`] is read-only and returns an [`Admission`] token.
//! The receiver checks before decryption and calls [`ReplayWindow::accept`]
//! with that token only after the packet is fully processed, which is how the
//! "no state change on failure" rule is enforced without an error path in
//! `accept`.

use core::cmp::Ordering;

use crate::REPLAY_WINDOW_SIZE;
use crate::error::Error;

/// A checked, admissible index. Holding this token proves that
/// [`ReplayWindow::check`] accepted the index, so [`ReplayWindow::accept`]
/// cannot fail and cannot shift the bitmap out of range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    /// No index has been accepted yet.
    First {
        /// The index to record.
        index: u64,
    },
    /// A new index above the highest accepted one.
    Ahead {
        /// The index to record.
        index: u64,
        /// Distance above the previous highest accepted index.
        shift: u64,
    },
    /// A new index below the highest accepted one.
    Behind {
        /// Distance below the highest accepted index, always below 64.
        delta: u64,
    },
}

/// 64-index sliding replay window.
#[derive(Debug, Clone, Default)]
pub(crate) struct ReplayWindow {
    highest: Option<u64>,
    /// Bit `n` is set when `highest - n` has been accepted, for `n < 64`.
    bitmap: u64,
}

impl ReplayWindow {
    pub(crate) const fn new() -> Self {
        Self {
            highest: None,
            bitmap: 0,
        }
    }

    /// Checks whether `index` would be accepted, without changing the window.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Replay`] when the index is already in the window and
    /// [`Error::TooOld`] when it has fallen below it.
    pub(crate) fn check(&self, index: u64) -> Result<Admission, Error> {
        let Some(highest) = self.highest else {
            return Ok(Admission::First { index });
        };
        match index.cmp(&highest) {
            Ordering::Greater => Ok(Admission::Ahead {
                index,
                shift: index - highest,
            }),
            Ordering::Equal => Err(Error::Replay),
            Ordering::Less => {
                let delta = highest - index;
                if delta >= REPLAY_WINDOW_SIZE {
                    Err(Error::TooOld)
                } else if self.bitmap & (1u64 << delta) != 0 {
                    Err(Error::Replay)
                } else {
                    Ok(Admission::Behind { delta })
                }
            }
        }
    }

    /// Admits a previously checked index into the window.
    pub(crate) fn accept(&mut self, admission: Admission) {
        match admission {
            Admission::First { index } => {
                self.highest = Some(index);
                self.bitmap = 1;
            }
            Admission::Ahead { index, shift } => {
                self.bitmap = if shift >= REPLAY_WINDOW_SIZE {
                    1
                } else {
                    (self.bitmap << shift) | 1
                };
                self.highest = Some(index);
            }
            Admission::Behind { delta } => {
                self.bitmap |= 1u64 << delta;
            }
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    fn admit(window: &mut ReplayWindow, index: u64) {
        let admission = window.check(index).expect("admissible index");
        window.accept(admission);
    }

    // SRTP-REPLAY-001 — the first index is accepted and fixes the top.
    #[test]
    fn first_index_is_accepted() {
        let mut window = ReplayWindow::new();
        assert!(matches!(window.check(0), Ok(Admission::First { index: 0 })));
        admit(&mut window, 0);
        assert_eq!(window.check(0), Err(Error::Replay));
    }

    // SRTP-REPLAY-002 — reordering inside the window is accepted exactly once.
    #[test]
    fn out_of_order_indices_inside_the_window_are_accepted_once() {
        let mut window = ReplayWindow::new();
        for value in [5, 7, 6, 4, 0] {
            admit(&mut window, value);
        }
        for value in [0, 4, 5, 6, 7] {
            assert_eq!(window.check(value), Err(Error::Replay));
        }
        for value in 1..=3 {
            admit(&mut window, value);
        }
        assert_eq!(window.check(1), Err(Error::Replay));
    }

    // SRTP-REPLAY-003 — the 64-index boundary is exact.
    #[test]
    fn window_boundary_is_exactly_64_indices() {
        let mut window = ReplayWindow::new();
        admit(&mut window, 0);
        admit(&mut window, 63);
        assert_eq!(window.check(0), Err(Error::Replay));
        admit(&mut window, 64);
        assert_eq!(window.check(0), Err(Error::TooOld));
        admit(&mut window, 1); // delta 63: still inside
        assert_eq!(window.check(1), Err(Error::Replay));
    }

    // SRTP-REPLAY-004 — a jump beyond the window discards the old bitmap.
    #[test]
    fn far_ahead_index_slides_the_window() {
        let mut window = ReplayWindow::new();
        admit(&mut window, 3);
        admit(&mut window, 100);
        admit(&mut window, 99);
        assert_eq!(window.check(99), Err(Error::Replay));
        assert_eq!(window.check(36), Err(Error::TooOld));
        admit(&mut window, 37); // delta 63: inside
        assert!(matches!(
            window.check(38),
            Ok(Admission::Behind { delta: 62 })
        ));
    }

    // SRTP-REPLAY-005 — check never mutates and a jump of 64 resets the bitmap.
    #[test]
    fn check_is_read_only_and_jump_of_64_resets_the_bitmap() {
        let mut window = ReplayWindow::default();
        assert_eq!(window.highest, None);
        admit(&mut window, 10);
        assert!(matches!(
            window.check(11),
            Ok(Admission::Ahead { shift: 1, .. })
        ));
        admit(&mut window, 74);
        admit(&mut window, 73);
        assert_eq!(window.check(73), Err(Error::Replay));
        assert_eq!(window.check(10), Err(Error::TooOld));
        assert_eq!(window.highest, Some(74));
    }
}
