//! Per-connection telemetry captured through a delegating congestion
//! controller.
//!
//! `quinn-proto` does not expose `bytes_in_flight` or the latest RTT sample in
//! `ConnectionStats`. Both are observable at the public
//! `congestion::Controller` boundary, so the facade installs a thin delegating
//! controller that records them in atomics while behaving exactly like the
//! wrapped controller (Cubic).

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use quinn_proto::RttEstimator;
use quinn_proto::congestion::{Controller, ControllerFactory, ControllerMetrics, CubicConfig};

pub(crate) const NO_RTT_SAMPLE: u64 = u64::MAX;

#[derive(Debug)]
pub(crate) struct Telemetry {
    bytes_in_flight: AtomicU64,
    latest_rtt_micros: AtomicU64,
}

impl Default for Telemetry {
    fn default() -> Self {
        Self {
            bytes_in_flight: AtomicU64::new(0),
            latest_rtt_micros: AtomicU64::new(NO_RTT_SAMPLE),
        }
    }
}

impl Telemetry {
    fn record_in_flight(&self, in_flight: u64) {
        self.bytes_in_flight.store(in_flight, Ordering::Relaxed);
    }

    fn record_rtt_sample(&self, now: Instant, sent: Instant) {
        let micros = now.saturating_duration_since(sent).as_micros();
        let micros = u64::try_from(micros).unwrap_or(NO_RTT_SAMPLE - 1);
        self.latest_rtt_micros.store(micros, Ordering::Relaxed);
    }

    pub(crate) fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight.load(Ordering::Relaxed)
    }

    pub(crate) fn latest_rtt_micros(&self) -> Option<u64> {
        let value = self.latest_rtt_micros.load(Ordering::Relaxed);
        (value != NO_RTT_SAMPLE).then_some(value)
    }
}

#[derive(Debug)]
pub(crate) struct RecordingFactory {
    telemetry: Arc<Telemetry>,
}

impl RecordingFactory {
    pub(crate) fn new(telemetry: Arc<Telemetry>) -> Self {
        Self { telemetry }
    }
}

impl ControllerFactory for RecordingFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let inner = Arc::new(CubicConfig::default()).build(now, current_mtu);
        Box::new(RecordingController {
            inner,
            telemetry: self.telemetry.clone(),
        })
    }
}

struct RecordingController {
    inner: Box<dyn Controller>,
    telemetry: Arc<Telemetry>,
}

impl Controller for RecordingController {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.inner.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.telemetry.record_rtt_sample(now, sent);
        self.inner.on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.telemetry.record_in_flight(in_flight);
        self.inner
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.inner
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.inner.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        self.inner.window()
    }

    fn metrics(&self) -> ControllerMetrics {
        self.inner.metrics()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            inner: self.inner.clone_box(),
            telemetry: self.telemetry.clone(),
        })
    }

    fn initial_window(&self) -> u64 {
        self.inner.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{NO_RTT_SAMPLE, RecordingFactory, Telemetry};
    use std::sync::Arc;
    use std::time::Instant;

    #[test]
    fn telemetry_starts_without_samples() {
        let telemetry = Telemetry::default();
        assert_eq!(telemetry.bytes_in_flight(), 0);
        assert_eq!(telemetry.latest_rtt_micros(), None);
        assert_eq!(
            telemetry
                .latest_rtt_micros
                .load(std::sync::atomic::Ordering::Relaxed),
            NO_RTT_SAMPLE
        );
    }

    #[test]
    fn factory_builds_a_controller_that_wraps_cubic() {
        let telemetry = Arc::new(Telemetry::default());
        let factory = Arc::new(RecordingFactory::new(telemetry));
        let controller =
            quinn_proto::congestion::ControllerFactory::build(factory, Instant::now(), 1_200);
        assert!(controller.window() > 0);
    }
}
