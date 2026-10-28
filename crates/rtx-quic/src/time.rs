//! Mapping between injected [`rtx_core::Timestamp`] values and the
//! `std::time::Instant` values required by `quinn-proto`.
//!
//! One monotonic epoch is captured per process. After that the clock is never
//! read: every protocol decision uses the caller-supplied [`Timestamp`].

use std::sync::OnceLock;
use std::time::Instant;

use rtx_core::Timestamp;

fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// Map an injected timestamp to the `quinn-proto` time base.
pub(crate) fn to_instant(now: Timestamp) -> Instant {
    epoch()
        .checked_add(std::time::Duration::from_micros(now.as_micros()))
        .unwrap_or_else(epoch)
}

/// Map a `quinn-proto` deadline back to the injected time base.
pub(crate) fn to_timestamp(deadline: Instant) -> Timestamp {
    let micros = deadline.saturating_duration_since(epoch()).as_micros();
    Timestamp::from_micros(u64::try_from(micros).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::{to_instant, to_timestamp};
    use rtx_core::Timestamp;

    #[test]
    fn round_trip_is_exact() {
        let timestamp = Timestamp::from_micros(1_234_567);
        assert_eq!(to_timestamp(to_instant(timestamp)), timestamp);
    }

    #[test]
    fn ordering_is_preserved() {
        let earlier = Timestamp::from_micros(10);
        let later = Timestamp::from_micros(20);
        assert!(to_instant(later) > to_instant(earlier));
    }
}
