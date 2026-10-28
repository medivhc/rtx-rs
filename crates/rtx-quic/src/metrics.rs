//! Transport metrics snapshot needed by pacing and observability
//! (`M3-Q8`, `ARCHITECTURE.md` §14).

/// Point-in-time transport metrics.
///
/// The snapshot is a `Copy` value: [`Metrics::snapshot_allocations`] is always
/// `0`. Field provenance is documented in the crate-level “Metrics
/// provenance” section.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Metrics {
    /// Smoothed RTT reported by `quinn-proto`’s RTT estimator, in
    /// microseconds.
    pub smoothed_rtt_micros: u64,
    /// Raw most recent send→ACK interval observed at the congestion
    /// controller boundary, in microseconds; `None` before the first
    /// acknowledged packet.
    pub latest_rtt_micros: Option<u64>,
    /// Minimum RTT seen on the path, in microseconds.
    pub min_rtt_micros: u64,
    /// Current congestion window, in bytes.
    pub congestion_window_bytes: u64,
    /// Bytes in flight as last reported at an ACK batch boundary.
    pub bytes_in_flight: u64,
    /// Packets declared lost on the path.
    pub lost_packets: u64,
    /// DATAGRAM frames transmitted.
    pub datagrams_sent: u64,
    /// DATAGRAM frames received.
    pub datagrams_received: u64,
    /// Application stream bytes accepted by
    /// [`crate::Endpoint::write_stream`].
    pub stream_bytes_sent: u64,
    /// Application stream bytes delivered by
    /// [`crate::Endpoint::read_stream`].
    pub stream_bytes_received: u64,
    /// Congestion controller’s pacing estimate in bits per second.
    ///
    /// `None` with the built-in `Cubic`/`NewReno` controllers, which do not
    /// expose a pacing rate; see the crate-level “Metrics provenance”
    /// section for the upstream source locations.
    pub pacing_rate_bits_per_second: Option<u64>,
    /// Heap allocations performed to produce this snapshot. Always `0`.
    pub snapshot_allocations: u32,
}
