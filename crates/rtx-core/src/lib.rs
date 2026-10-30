#![cfg_attr(not(feature = "std"), no_std)]

use core::ops::{Add, AddAssign, Sub, SubAssign};

/// Monotonic time in microseconds from a runtime-defined epoch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn from_micros(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_micros(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn saturating_duration_since(self, earlier: Self) -> Duration {
        Duration(self.0.saturating_sub(earlier.0))
    }
}

/// Non-negative duration in microseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration(u64);

impl Duration {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn from_micros(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn from_millis(value: u64) -> Self {
        Self(value.saturating_mul(1_000))
    }

    #[must_use]
    pub const fn as_micros(self) -> u64 {
        self.0
    }
}

impl Add<Duration> for Timestamp {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl AddAssign<Duration> for Timestamp {
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs;
    }
}

impl Sub<Timestamp> for Timestamp {
    type Output = Duration;

    fn sub(self, rhs: Timestamp) -> Self::Output {
        self.saturating_duration_since(rhs)
    }
}

impl Add for Duration {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl AddAssign for Duration {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for Duration {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.saturating_sub(rhs.0))
    }
}

impl SubAssign for Duration {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

/// Runtime-owned monotonic clock.
pub trait Clock {
    fn now(&self) -> Timestamp;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocketAddr {
    pub ip: IpAddr,
    pub port: u16,
}

impl SocketAddr {
    #[must_use]
    pub const fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }
}

/// Metadata supplied by the runtime when a datagram is received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramMeta {
    pub now: Timestamp,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub ecn: Option<EcnCodepoint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcnCodepoint {
    Ect0,
    Ect1,
    Ce,
}

/// Common external stimulus for a Sans-I/O transport state machine.
#[derive(Debug)]
pub enum Input<'a> {
    Datagram {
        meta: DatagramMeta,
        payload: &'a [u8],
    },
    Timeout(Timestamp),
}

/// Common runtime-facing output for a Sans-I/O transport state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeAction {
    WakeAt(Timestamp),
    Idle,
}

/// Minimal state-machine shape used by protocol engines that do not need to own I/O.
pub trait ProtocolMachine {
    type Input<'a>
    where
        Self: 'a;
    type Event;
    type Error;

    /// Feeds one external stimulus into the state machine.
    ///
    /// # Errors
    ///
    /// Returns `Self::Error` when the state machine rejects the input (for
    /// example a malformed datagram); the exact conditions are defined by
    /// each implementation.
    fn handle_input(&mut self, input: Self::Input<'_>) -> Result<(), Self::Error>;

    fn poll_event(&mut self) -> Option<Self::Event>;

    fn next_wakeup(&self) -> Option<Timestamp>;
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use core::cmp::Ordering;
    use std::collections::HashSet;

    // ---- CORE-TIME -------------------------------------------------------

    // CORE-TIME-001 — Timestamp 构造与 as_micros 往返。
    #[test]
    fn timestamp_construction_roundtrip() {
        assert_eq!(Timestamp::ZERO, Timestamp::from_micros(0));
        assert_eq!(Timestamp::ZERO.as_micros(), 0);
        for value in [0, 1, 999, 1_000_000, u64::from(u32::MAX), u64::MAX] {
            assert_eq!(Timestamp::from_micros(value).as_micros(), value);
        }
        assert_eq!(Timestamp::default(), Timestamp::ZERO);
    }

    // CORE-TIME-002 — Duration 构造与 as_micros 往返。
    #[test]
    fn duration_construction_roundtrip() {
        assert_eq!(Duration::ZERO, Duration::from_micros(0));
        assert_eq!(Duration::ZERO.as_micros(), 0);
        for value in [0, 1, 999, 1_000_000, u64::from(u32::MAX), u64::MAX] {
            assert_eq!(Duration::from_micros(value).as_micros(), value);
        }
        assert_eq!(Duration::default(), Duration::ZERO);
    }

    // CORE-TIME-003 — 时间 API 的 const fn 契约（const 上下文可构造）。
    const CONST_TIMESTAMP: Timestamp = Timestamp::from_micros(5);
    const CONST_MILLIS: Duration = Duration::from_millis(3);
    const CONST_SINCE_ZERO: Duration = CONST_TIMESTAMP.saturating_duration_since(Timestamp::ZERO);

    #[test]
    fn time_apis_usable_in_const_contexts() {
        assert_eq!(CONST_SINCE_ZERO.as_micros(), 5);
        assert_eq!(CONST_MILLIS.as_micros(), 3_000);
    }

    // CORE-TIME-004 — Timestamp + Duration 饱和至 u64::MAX。
    #[test]
    fn timestamp_plus_duration_saturates_at_u64_max() {
        assert_eq!(
            Timestamp::from_micros(u64::MAX) + Duration::from_micros(1),
            Timestamp::from_micros(u64::MAX)
        );
        assert_eq!(
            Timestamp::from_micros(u64::MAX - 10) + Duration::from_micros(10),
            Timestamp::from_micros(u64::MAX)
        );
        assert_eq!(
            Timestamp::from_micros(u64::MAX - 10) + Duration::from_micros(11),
            Timestamp::from_micros(u64::MAX)
        );
    }

    // CORE-TIME-005 — Timestamp - Timestamp 反向得 ZERO。
    #[test]
    fn timestamp_subtraction_reverse_saturates_to_zero() {
        assert_eq!(
            Timestamp::from_micros(10) - Timestamp::from_micros(25),
            Duration::ZERO
        );
        assert_eq!(
            Timestamp::from_micros(25) - Timestamp::from_micros(10),
            Duration::from_micros(15)
        );
        let same = Timestamp::from_micros(42);
        assert_eq!(same - same, Duration::ZERO);
    }

    // CORE-TIME-006 — saturating_duration_since 全路径。
    #[test]
    fn saturating_duration_since_covers_all_paths() {
        let earlier = Timestamp::from_micros(30);
        let later = Timestamp::from_micros(100);
        assert_eq!(
            later.saturating_duration_since(earlier),
            Duration::from_micros(70)
        );
        let point = Timestamp::from_micros(7);
        assert_eq!(point.saturating_duration_since(point), Duration::ZERO);
        assert_eq!(earlier.saturating_duration_since(later), Duration::ZERO);
        assert_eq!(
            Timestamp::from_micros(u64::MAX).saturating_duration_since(Timestamp::ZERO),
            Duration::from_micros(u64::MAX)
        );
    }

    // CORE-TIME-007 — Duration + Duration 饱和。
    #[test]
    fn duration_addition_saturates_at_u64_max() {
        assert_eq!(
            Duration::from_micros(u64::MAX) + Duration::from_micros(u64::MAX),
            Duration::from_micros(u64::MAX)
        );
        assert_eq!(
            Duration::from_micros(u64::MAX - 1) + Duration::from_micros(1),
            Duration::from_micros(u64::MAX)
        );
        assert_eq!(
            Duration::from_micros(u64::MAX - 1) + Duration::from_micros(2),
            Duration::from_micros(u64::MAX)
        );
    }

    // CORE-TIME-008 — Duration - Duration 反向饱和为 ZERO。
    #[test]
    fn duration_subtraction_reverse_saturates_to_zero() {
        assert_eq!(
            Duration::from_micros(5) - Duration::from_micros(9),
            Duration::ZERO
        );
        assert_eq!(
            Duration::from_micros(9) - Duration::from_micros(5),
            Duration::from_micros(4)
        );
        assert_eq!(
            Duration::from_micros(u64::MAX) - Duration::from_micros(0),
            Duration::from_micros(u64::MAX)
        );
    }

    // CORE-TIME-009 — from_millis 精确换算与饱和乘法边界。
    #[test]
    fn duration_from_millis_conversion_and_saturation() {
        assert_eq!(Duration::from_millis(0), Duration::ZERO);
        assert_eq!(Duration::from_millis(1), Duration::from_micros(1_000));
        assert_eq!(
            Duration::from_millis(1_000),
            Duration::from_micros(1_000_000)
        );
        let critical = u64::MAX / 1_000;
        assert_eq!(
            Duration::from_millis(critical),
            Duration::from_micros(critical * 1_000)
        );
        assert_eq!(
            Duration::from_millis(critical + 1),
            Duration::from_micros(u64::MAX)
        );
        assert_eq!(
            Duration::from_millis(u64::MAX),
            Duration::from_micros(u64::MAX)
        );
    }

    // CORE-TIME-010 — AddAssign/SubAssign 运算符语义。
    #[test]
    fn compound_assignment_operators_match_binary_ones() {
        let mut timestamp = Timestamp::from_micros(10);
        timestamp += Duration::from_micros(5);
        assert_eq!(timestamp, Timestamp::from_micros(15));

        let mut saturated = Timestamp::from_micros(u64::MAX);
        saturated += Duration::from_micros(7);
        assert_eq!(saturated, Timestamp::from_micros(u64::MAX));

        let mut duration = Duration::from_micros(10);
        duration += Duration::from_micros(5);
        duration -= Duration::from_micros(20);
        assert_eq!(duration, Duration::ZERO);
    }

    // CORE-TIME-011 — Ord 派生全序行为。
    #[test]
    fn derived_ord_matches_internal_representation() {
        assert!(Timestamp::ZERO < Timestamp::from_micros(1));
        assert!(Timestamp::from_micros(1) < Timestamp::from_micros(u64::MAX));
        assert!(Duration::ZERO < Duration::from_micros(1));
        assert!(Duration::from_micros(1) < Duration::from_micros(u64::MAX));
        for (left, right) in [
            (Timestamp::from_micros(5), Timestamp::from_micros(9)),
            (Timestamp::from_micros(9), Timestamp::from_micros(5)),
            (Timestamp::from_micros(7), Timestamp::from_micros(7)),
        ] {
            assert_eq!(left.cmp(&right), left.as_micros().cmp(&right.as_micros()));
        }
        let equal = Timestamp::from_micros(77);
        assert_eq!(equal.cmp(&equal), Ordering::Equal);
    }

    // CORE-TIME-012 — Hash 派生一致性。
    #[test]
    fn derived_hash_deduplicates_equal_values() {
        let mut timestamps = HashSet::new();
        timestamps.insert(Timestamp::from_micros(1));
        timestamps.insert(Timestamp::from_micros(1));
        timestamps.insert(Timestamp::from_micros(2));
        assert_eq!(timestamps.len(), 2);

        let mut durations = HashSet::new();
        durations.insert(Duration::from_micros(1));
        durations.insert(Duration::from_micros(1));
        durations.insert(Duration::from_micros(2));
        assert_eq!(durations.len(), 2);
    }

    // CORE-TIME-013 — Copy/Clone 派生语义。
    #[test]
    fn derived_copy_keeps_source_usable() {
        let timestamp = Timestamp::from_micros(7);
        let copied = timestamp;
        assert_eq!(timestamp, copied);
        assert_eq!(timestamp.as_micros(), 7);

        let duration = Duration::from_micros(9);
        let copied_duration = duration;
        assert_eq!(duration, copied_duration);
        assert_eq!(duration.as_micros(), 9);
    }

    // CORE-TIME-014 支撑 mock：固定时钟与可推进时钟。
    struct FixedClock(Timestamp);

    impl Clock for FixedClock {
        fn now(&self) -> Timestamp {
            self.0
        }
    }

    struct AdvancingClock {
        now: Timestamp,
    }

    impl AdvancingClock {
        fn advance(&mut self, delta: Duration) {
            self.now += delta;
        }
    }

    impl Clock for AdvancingClock {
        fn now(&self) -> Timestamp {
            self.now
        }
    }

    // CORE-TIME-014 — Clock trait 可被 mock 实现且返回绝对 Timestamp。
    #[test]
    fn clock_trait_can_be_mocked() {
        let fixed = FixedClock(Timestamp::from_micros(42));
        assert_eq!(fixed.now(), Timestamp::from_micros(42));

        let mut advancing = AdvancingClock {
            now: Timestamp::from_micros(100),
        };
        advancing.advance(Duration::from_micros(50));
        assert_eq!(advancing.now(), Timestamp::from_micros(150));
    }

    // CORE-TIME-015 — Sub 与 saturating_duration_since 同源一致。
    #[test]
    fn subtraction_operator_matches_explicit_method() {
        for (left, right) in [
            (10u64, 25u64),
            (25, 10),
            (0, 0),
            (u64::MAX, 0),
            (0, u64::MAX),
        ] {
            let first = Timestamp::from_micros(left);
            let second = Timestamp::from_micros(right);
            assert_eq!(first - second, first.saturating_duration_since(second));
        }
    }

    // ---- CORE-ADDR -------------------------------------------------------

    fn sample_meta() -> DatagramMeta {
        DatagramMeta {
            now: Timestamp::from_micros(1_000),
            source: SocketAddr::new(IpAddr::V4([192, 168, 0, 1]), 5_000),
            destination: SocketAddr::new(IpAddr::V4([192, 168, 0, 2]), 6_000),
            ecn: None,
        }
    }

    // CORE-ADDR-001 — IpAddr V4/V6 构造与相等性。
    #[test]
    fn ip_addr_variants_construct_and_compare() {
        let loopback = IpAddr::V4([127, 0, 0, 1]);
        assert_eq!(loopback, IpAddr::V4([127, 0, 0, 1]));
        assert_eq!(IpAddr::V6([0; 16]), IpAddr::V6([0; 16]));
        assert_ne!(loopback, IpAddr::V6([0; 16]));
        assert_ne!(format!("{loopback:?}"), "");
    }

    // CORE-ADDR-002 — SocketAddr::new 与字段访问（含 const 构造）。
    #[test]
    fn socket_addr_new_exposes_public_fields() {
        const CONST_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4([1, 2, 3, 4]), 9_000);

        let dns = SocketAddr::new(IpAddr::V4([8, 8, 8, 8]), 53);
        assert_eq!(dns.ip, IpAddr::V4([8, 8, 8, 8]));
        assert_eq!(dns.port, 53);

        let any = SocketAddr::new(IpAddr::V4([0, 0, 0, 0]), 0);
        assert_eq!(any.port, 0);
        let v6 = SocketAddr::new(
            IpAddr::V6([0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            65_535,
        );
        assert_eq!(v6.port, 65_535);
        assert_ne!(v6, any);

        assert_eq!(CONST_ADDR.port, 9_000);
        assert_eq!(CONST_ADDR.ip, IpAddr::V4([1, 2, 3, 4]));
    }

    // CORE-ADDR-003 — IpAddr/SocketAddr Copy/Hash 派生。
    #[test]
    fn socket_addr_hash_set_deduplicates_and_stays_copyable() {
        let mut addresses = HashSet::new();
        let addr = SocketAddr::new(IpAddr::V4([10, 0, 0, 1]), 8_080);
        addresses.insert(addr);
        addresses.insert(addr);
        assert_eq!(addresses.len(), 1);
        // `addr` 在插入后仍可使用（Copy）。
        assert_eq!(addr.port, 8_080);

        let ip = IpAddr::V4([1, 1, 1, 1]);
        let copied_ip = ip;
        assert_eq!(ip, copied_ip);
    }

    // CORE-ADDR-004 — DatagramMeta 构造。
    #[test]
    fn datagram_meta_constructs_with_and_without_ecn() {
        let without_ecn = sample_meta();
        assert_eq!(without_ecn.ecn, None);
        assert_eq!(without_ecn, sample_meta());

        let mut with_ecn = without_ecn; // Copy
        with_ecn.ecn = Some(EcnCodepoint::Ce);
        assert_ne!(without_ecn, with_ecn);
        assert_eq!(without_ecn.ecn, None); // 原值未被触碰
        assert_ne!(format!("{with_ecn:?}"), "");
    }

    // CORE-ADDR-005 — EcnCodepoint 三变体互异。
    #[test]
    fn ecn_codepoint_variants_are_distinct() {
        assert_ne!(EcnCodepoint::Ect0, EcnCodepoint::Ect1);
        assert_ne!(EcnCodepoint::Ect1, EcnCodepoint::Ce);
        assert_ne!(EcnCodepoint::Ect0, EcnCodepoint::Ce);
        assert_eq!(EcnCodepoint::Ect0, EcnCodepoint::Ect0.clone());
    }

    // ---- CORE-SM ----------------------------------------------------------

    // CORE-SM-001 — Input::Datagram/Timeout 变体可构造、可匹配、payload 借用。
    #[test]
    fn input_variants_construct_match_and_borrow_payload() {
        let meta = sample_meta();
        let payload = [1u8, 2, 3];
        let datagram = Input::Datagram {
            meta,
            payload: &payload,
        };
        match datagram {
            Input::Datagram {
                payload: borrowed, ..
            } => assert_eq!(borrowed, &[1, 2, 3]),
            Input::Timeout(_) => panic!("expected a datagram input"),
        }
        assert_ne!(format!("{datagram:?}"), "");

        let timeout = Input::Timeout(Timestamp::from_micros(1_000));
        match timeout {
            Input::Timeout(at) => assert_eq!(at, Timestamp::from_micros(1_000)),
            Input::Datagram { .. } => panic!("expected a timeout input"),
        }
    }

    // CORE-SM-002 — RuntimeAction::WakeAt/Idle。
    #[test]
    fn runtime_action_variants_carry_absolute_deadlines() {
        let deadline = Timestamp::from_micros(500);
        assert_eq!(RuntimeAction::Idle, RuntimeAction::Idle);
        assert_ne!(RuntimeAction::WakeAt(deadline), RuntimeAction::Idle);
        assert_ne!(
            RuntimeAction::WakeAt(Timestamp::from_micros(500)),
            RuntimeAction::WakeAt(Timestamp::from_micros(501))
        );
        let action = RuntimeAction::WakeAt(deadline);
        let copied = action; // Copy
        assert_eq!(action, copied);
        assert_ne!(format!("{action:?}"), "");
    }

    // CORE-SM-003 支撑 mock：最小 Sans-I/O 状态机。
    #[derive(Debug)]
    enum MiniEvent {
        Datagram,
        Timeout,
    }

    struct MiniMachine {
        events: Vec<MiniEvent>,
        wakeup: Option<Timestamp>,
    }

    impl ProtocolMachine for MiniMachine {
        type Input<'a> = Input<'a>;
        type Event = MiniEvent;
        type Error = core::convert::Infallible;

        fn handle_input(&mut self, input: Self::Input<'_>) -> Result<(), Self::Error> {
            match input {
                Input::Datagram { .. } => self.events.push(MiniEvent::Datagram),
                Input::Timeout(at) => {
                    self.events.push(MiniEvent::Timeout);
                    self.wakeup = Some(at);
                }
            }
            Ok(())
        }

        fn poll_event(&mut self) -> Option<Self::Event> {
            if self.events.is_empty() {
                None
            } else {
                Some(self.events.remove(0))
            }
        }

        fn next_wakeup(&self) -> Option<Timestamp> {
            self.wakeup
        }
    }

    // CORE-SM-003 — ProtocolMachine 最小 mock 状态机（GAT 编译期契约）。
    #[test]
    fn protocol_machine_minimal_mock_state_machine() {
        let mut machine = MiniMachine {
            events: Vec::new(),
            wakeup: None,
        };
        machine
            .handle_input(Input::Timeout(Timestamp::from_micros(1_000)))
            .expect("timeout accepted");
        assert_eq!(machine.next_wakeup(), Some(Timestamp::from_micros(1_000)));
        assert!(matches!(machine.poll_event(), Some(MiniEvent::Timeout)));
        assert!(machine.poll_event().is_none());
    }
}
