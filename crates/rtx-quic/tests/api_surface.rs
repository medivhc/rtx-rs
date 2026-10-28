#![cfg(feature = "std")]
#![allow(clippy::type_complexity)]
//! Compile-time evidence for `M3-Q0`: the public surface is only the
//! operations required by Q1–Q8 and contains no `quinn-proto` type. This file
//! deliberately does not import the upstream crate.

use rtx_core::{IpAddr, SocketAddr, Timestamp};
use rtx_quic::{
    AcceptError, CloseError, ConnectError, ConnectionId, DatagramError, Direction, Endpoint,
    EndpointConfig, EndpointError, Event, HandshakeFailure, HandshakeInfo, Metrics, MetricsError,
    PeerTransportParameters, StreamError, StreamEvent, StreamId, StreamRead, Transmit,
    TransportConfig,
};

#[test]
fn m3_q0_public_surface_is_narrow_and_allocation_free() {
    let _ = std::mem::size_of::<EndpointConfig>();
    let _ = std::mem::size_of::<TransportConfig>();
    let _ = std::mem::size_of::<Endpoint>();
    let _ = std::mem::size_of::<ConnectionId>();
    let _ = std::mem::size_of::<Transmit>();
    let _ = std::mem::size_of::<Event>();
    let _ = std::mem::size_of::<HandshakeInfo>();
    let _ = std::mem::size_of::<HandshakeFailure>();
    let _ = std::mem::size_of::<PeerTransportParameters>();
    let _ = std::mem::size_of::<StreamEvent>();
    let _ = std::mem::size_of::<StreamId>();
    let _ = std::mem::size_of::<StreamRead>();
    let _ = std::mem::size_of::<Direction>();
    let _ = std::mem::size_of::<Metrics>();
    let _ = std::mem::size_of::<EndpointError>();
    let _ = std::mem::size_of::<ConnectError>();
    let _ = std::mem::size_of::<AcceptError>();
    let _ = std::mem::size_of::<StreamError>();
    let _ = std::mem::size_of::<DatagramError>();
    let _ = std::mem::size_of::<CloseError>();
    let _ = std::mem::size_of::<MetricsError>();

    let _: fn(EndpointConfig) -> Result<Endpoint, EndpointError> = Endpoint::new;
    let _: fn(&mut Endpoint, Timestamp, SocketAddr, &str) -> Result<ConnectionId, ConnectError> =
        Endpoint::connect;
    let _: fn(&mut Endpoint, Timestamp, ConnectionId, &mut Vec<u8>) -> Result<(), AcceptError> =
        Endpoint::accept;
    let _: fn(&mut Endpoint, ConnectionId) -> Result<(), AcceptError> = Endpoint::refuse;
    let _: fn(&mut Endpoint, Timestamp, SocketAddr, Option<IpAddr>, &[u8]) =
        Endpoint::handle_datagram;
    let _: fn(&mut Endpoint) -> Option<Event> = Endpoint::poll_event;
    let _: fn(&mut Endpoint, Timestamp, &mut Vec<u8>) -> Option<Transmit> = Endpoint::poll_transmit;
    let _: fn(&mut Endpoint) -> Option<Timestamp> = Endpoint::poll_timeout;
    let _: fn(&mut Endpoint, Timestamp) = Endpoint::handle_timeout;
    let _: fn(&mut Endpoint, ConnectionId) -> Result<StreamId, StreamError> = Endpoint::open_uni;
    let _: fn(&mut Endpoint, ConnectionId) -> Result<StreamId, StreamError> = Endpoint::open_bi;
    let _: fn(&mut Endpoint, ConnectionId) -> Result<Option<StreamId>, StreamError> =
        Endpoint::accept_uni;
    let _: fn(&mut Endpoint, ConnectionId) -> Result<Option<StreamId>, StreamError> =
        Endpoint::accept_bi;
    let _: fn(&mut Endpoint, ConnectionId, StreamId, &[u8]) -> Result<usize, StreamError> =
        Endpoint::write_stream;
    let _: fn(&mut Endpoint, ConnectionId, StreamId, &mut [u8]) -> Result<StreamRead, StreamError> =
        Endpoint::read_stream;
    let _: fn(&mut Endpoint, ConnectionId, StreamId) -> Result<(), StreamError> =
        Endpoint::finish_stream;
    let _: fn(&mut Endpoint, ConnectionId, StreamId, u64) -> Result<(), StreamError> =
        Endpoint::reset_stream;
    let _: fn(&mut Endpoint, ConnectionId, StreamId, u64) -> Result<(), StreamError> =
        Endpoint::stop_sending;
    let _: fn(&mut Endpoint, ConnectionId, &[u8]) -> Result<usize, DatagramError> =
        Endpoint::send_datagram;
    let _: fn(&mut Endpoint, ConnectionId, &mut [u8]) -> Result<Option<usize>, DatagramError> =
        Endpoint::poll_datagram;
    let _: fn(&mut Endpoint, ConnectionId, Timestamp, u64, &[u8]) -> Result<(), CloseError> =
        Endpoint::close;
    let _: fn(&Endpoint, ConnectionId) -> Result<Metrics, MetricsError> = Endpoint::metrics;

    let mut endpoint = Endpoint::new(
        EndpointConfig::new()
            .with_alpn(vec![b"h3".to_vec()])
            .with_transport(TransportConfig::default()),
    )
    .expect("client-only endpoint");
    let mut buffer = Vec::new();
    assert!(endpoint.poll_event().is_none());
    assert!(endpoint.poll_timeout().is_none());
    assert!(
        endpoint
            .poll_transmit(Timestamp::from_micros(1), &mut buffer)
            .is_none()
    );
}
