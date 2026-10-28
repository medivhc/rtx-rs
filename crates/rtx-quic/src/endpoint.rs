//! The endpoint: connection creation, datagram I/O, timers and per-connection
//! operations.
//!
//! The endpoint owns `quinn-proto` state only. It never opens a socket and
//! never reads a clock after construction.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use quinn_proto::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
use quinn_proto::{
    Connection as QuinnConnection, ConnectionError, ConnectionHandle, DatagramEvent, Dir,
    Event as QuinnEvent, FinishError, ReadError, SendDatagramError, Side,
    StreamEvent as QuinnStreamEvent, TransportErrorCode, VarInt, WriteError,
};
use rtx_core::{IpAddr, SocketAddr, Timestamp};

use crate::addr::{from_std_addr, to_std_addr, to_std_ip};
use crate::config::{EndpointConfig, TransportConfig, build_transport};
use crate::error::{
    AcceptError, CloseError, ConnectError, DatagramError, EndpointError, MetricsError, StreamError,
};
use crate::event::{
    CloseOrigin, CloseReason, Event, EventKind, HandshakeFailure, HandshakeInfo,
    PeerTransportParameters,
};
use crate::metrics::Metrics;
use crate::stream::{Direction, StreamEvent, StreamId, StreamRead};
use crate::telemetry::Telemetry;
use crate::time::{to_instant, to_timestamp};

/// Handle for a connection owned by an [`Endpoint`].
///
/// Handles are local to the endpoint that created them (client connect or
/// server accept) and are never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId(u64);

impl ConnectionId {
    /// The raw handle value, for logging and tests.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// One outgoing UDP datagram produced by [`Endpoint::poll_transmit`].
///
/// The value is immediately sendable: the payload is the first
/// [`Transmit::len`] bytes of the caller-provided buffer and the caller sends
/// those bytes to [`Transmit::destination`]. The facade does not perform the
/// I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transmit {
    /// Destination address.
    pub destination: SocketAddr,
    /// Number of bytes to send from the buffer.
    pub len: usize,
    /// Segment size when the datagram coalesces multiple QUIC packets.
    pub segment_size: Option<usize>,
}

struct ConnectionState {
    handle: ConnectionHandle,
    connection: QuinnConnection,
    telemetry: Arc<Telemetry>,
    handshake_complete: bool,
    close_reported: bool,
    stream_bytes_sent: u64,
    stream_bytes_received: u64,
}

struct PendingTransmit {
    destination: SocketAddr,
    payload: Vec<u8>,
}

/// Sans-I/O QUIC endpoint.
///
/// # Errors and state
///
/// Operations that target an unknown or reaped connection return an explicit
/// `UnknownConnection` variant; operations on a closed connection return
/// `Closed` rather than panicking.
pub struct Endpoint {
    inner: quinn_proto::Endpoint,
    connections: BTreeMap<ConnectionId, ConnectionState>,
    by_quinn_handle: BTreeMap<usize, ConnectionId>,
    pending_incoming: BTreeMap<ConnectionId, quinn_proto::Incoming>,
    pending_transmits: VecDeque<PendingTransmit>,
    events: VecDeque<Event>,
    next_connection_id: u64,
    transport: TransportConfig,
    client_crypto: Arc<QuicClientConfig>,
    server_crypto: Option<Arc<QuicServerConfig>>,
}

impl Endpoint {
    /// Create an endpoint.
    ///
    /// `endpoint_new` in the gate vocabulary. Path-MTU discovery is disabled
    /// (`allow_mtud = false`) because the facade cannot prove that the
    /// caller’s socket suppresses fragmentation.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointError`] when the ALPN list, transport parameters,
    /// certificate chain, private key or trust roots are unusable.
    pub fn new(config: EndpointConfig) -> Result<Self, EndpointError> {
        let built = config.build()?;
        let endpoint_config = Arc::new(quinn_proto::EndpointConfig::default());
        let default_server_config = built.server_crypto.as_ref().map(|crypto| {
            let mut server = quinn_proto::ServerConfig::with_crypto(crypto.clone());
            server.transport = Arc::new(build_transport(
                &built.transport,
                Arc::new(Telemetry::default()),
            ));
            Arc::new(server)
        });
        let inner = quinn_proto::Endpoint::new(
            endpoint_config,
            default_server_config,
            false,
            built.rng_seed,
        );
        Ok(Self {
            inner,
            connections: BTreeMap::new(),
            by_quinn_handle: BTreeMap::new(),
            pending_incoming: BTreeMap::new(),
            pending_transmits: VecDeque::new(),
            events: VecDeque::new(),
            next_connection_id: 0,
            transport: built.transport,
            client_crypto: built.client_crypto,
            server_crypto: built.server_crypto,
        })
    }

    /// Start a client connection.
    ///
    /// `endpoint_connect` in the gate vocabulary. The remote address is a
    /// logical UDP peer; the endpoint does not own the socket.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectError`] for an unusable address, malformed server
    /// name, exhausted connection-ID space or an unsupported QUIC version.
    pub fn connect(
        &mut self,
        now: Timestamp,
        remote: SocketAddr,
        server_name: &str,
    ) -> Result<ConnectionId, ConnectError> {
        let telemetry = Arc::new(Telemetry::default());
        let mut client_config = quinn_proto::ClientConfig::new(self.client_crypto.clone());
        client_config.transport_config(Arc::new(build_transport(
            &self.transport,
            telemetry.clone(),
        )));
        let (handle, connection) = self
            .inner
            .connect(
                to_instant(now),
                client_config,
                to_std_addr(remote),
                server_name,
            )
            .map_err(map_connect_error)?;
        let id = self.allocate_id();
        self.by_quinn_handle.insert(handle.0, id);
        self.connections.insert(
            id,
            ConnectionState {
                handle,
                connection,
                telemetry,
                handshake_complete: false,
                close_reported: false,
                stream_bytes_sent: 0,
                stream_bytes_received: 0,
            },
        );
        self.drain(id);
        Ok(id)
    }

    /// Accept a pending incoming connection.
    ///
    /// `endpoint_accept` in the gate vocabulary. `buffer` is scratch space for
    /// a protocol response; any such response is queued and later returned by
    /// [`Endpoint::poll_transmit`].
    ///
    /// # Errors
    ///
    /// [`AcceptError::UnknownIncoming`] when the handle is not pending;
    /// [`AcceptError::Rejected`] when the server configuration or TLS stack
    /// rejects the connection (a response, if any, is still queued).
    pub fn accept(
        &mut self,
        now: Timestamp,
        incoming: ConnectionId,
        buffer: &mut Vec<u8>,
    ) -> Result<(), AcceptError> {
        let (id, incoming) = self
            .pending_incoming
            .remove_entry(&incoming)
            .ok_or(AcceptError::UnknownIncoming)?;
        let Some(crypto) = self.server_crypto.clone() else {
            return Err(AcceptError::Rejected);
        };
        let telemetry = Arc::new(Telemetry::default());
        let mut server_config = quinn_proto::ServerConfig::with_crypto(crypto);
        server_config.transport = Arc::new(build_transport(&self.transport, telemetry.clone()));
        buffer.clear();
        match self.inner.accept(
            incoming,
            to_instant(now),
            buffer,
            Some(Arc::new(server_config)),
        ) {
            Ok((handle, connection)) => {
                self.by_quinn_handle.insert(handle.0, id);
                self.connections.insert(
                    id,
                    ConnectionState {
                        handle,
                        connection,
                        telemetry,
                        handshake_complete: false,
                        close_reported: false,
                        stream_bytes_sent: 0,
                        stream_bytes_received: 0,
                    },
                );
                self.drain(id);
                Ok(())
            }
            Err(error) => {
                if let Some(transmit) = error.response {
                    self.queue_transmit(buffer, transmit.destination, transmit.size);
                }
                Err(AcceptError::Rejected)
            }
        }
    }

    /// Refuse a pending incoming connection.
    ///
    /// Sends `CONNECTION_REFUSED` through the normal [`Endpoint::poll_transmit`]
    /// path.
    ///
    /// # Errors
    ///
    /// [`AcceptError::UnknownIncoming`] when the handle is not pending.
    pub fn refuse(&mut self, incoming: ConnectionId) -> Result<(), AcceptError> {
        let (_, incoming) = self
            .pending_incoming
            .remove_entry(&incoming)
            .ok_or(AcceptError::UnknownIncoming)?;
        let mut buffer = Vec::new();
        let transmit = self.inner.refuse(incoming, &mut buffer);
        self.queue_transmit(&buffer, transmit.destination, transmit.size);
        Ok(())
    }

    /// Feed one received UDP datagram into the endpoint.
    ///
    /// The endpoint does not own a socket; callers perform the receive and
    /// pass the payload here. Malformed or unrelated datagrams are dropped by
    /// `quinn-proto` per RFC 9000. Protocol responses generated by the
    /// endpoint itself (version negotiation, stateless reset, refusal) are
    /// queued and returned by [`Endpoint::poll_transmit`].
    pub fn handle_datagram(
        &mut self,
        now: Timestamp,
        remote: SocketAddr,
        local_ip: Option<IpAddr>,
        data: &[u8],
    ) {
        let mut buffer = Vec::new();
        let event = self.inner.handle(
            to_instant(now),
            to_std_addr(remote),
            local_ip.map(to_std_ip),
            None,
            BytesMut::from(data),
            &mut buffer,
        );
        let Some(event) = event else {
            return;
        };
        match event {
            DatagramEvent::ConnectionEvent(handle, connection_event) => {
                if let Some(id) = self.by_quinn_handle.get(&handle.0).copied() {
                    if let Some(state) = self.connections.get_mut(&id) {
                        state.connection.handle_event(connection_event);
                    }
                    self.drain(id);
                }
            }
            DatagramEvent::NewConnection(incoming) => {
                let id = self.allocate_id();
                self.pending_incoming.insert(id, incoming);
                self.events.push_back(Event {
                    connection: id,
                    kind: EventKind::Incoming,
                });
            }
            DatagramEvent::Response(transmit) => {
                self.queue_transmit(&buffer, transmit.destination, transmit.size);
            }
        }
    }

    /// Pop the next ordered event.
    ///
    /// `poll_event` (`M3-Q2` handshake subset and `M3-Q7` close subset) in
    /// the gate vocabulary. Events are produced once per transition; duplicate
    /// datagrams do not duplicate events.
    #[must_use]
    pub fn poll_event(&mut self) -> Option<Event> {
        let ids: Vec<ConnectionId> = self.connections.keys().copied().collect();
        for id in ids {
            self.drain(id);
        }
        self.events.pop_front()
    }

    /// Produce one outgoing datagram.
    ///
    /// `poll_transmit` in the gate vocabulary. Calls return one datagram at a
    /// time; repeated calls drain the queue and return `None` when there is
    /// nothing to send. The caller passes a scratch buffer: on `Some`, its
    /// first [`Transmit::len`] bytes are the payload to send. The buffer is
    /// cleared before use on every call.
    #[must_use]
    pub fn poll_transmit(&mut self, now: Timestamp, buffer: &mut Vec<u8>) -> Option<Transmit> {
        if let Some(pending) = self.pending_transmits.pop_front() {
            buffer.clear();
            buffer.extend_from_slice(&pending.payload);
            return Some(Transmit {
                destination: pending.destination,
                len: pending.payload.len(),
                segment_size: None,
            });
        }

        let now = to_instant(now);
        let ids: Vec<ConnectionId> = self.connections.keys().copied().collect();
        for id in ids {
            buffer.clear();
            let transmit = self
                .connections
                .get_mut(&id)
                .and_then(|state| state.connection.poll_transmit(now, 1, buffer));
            if let Some(transmit) = transmit {
                let metadata = Transmit {
                    destination: from_std_addr(transmit.destination),
                    len: transmit.size,
                    segment_size: transmit.segment_size,
                };
                self.drain(id);
                return Some(metadata);
            }
        }
        None
    }

    /// The earliest absolute timeout, if any.
    ///
    /// `poll_timeout` in the gate vocabulary. The value is an absolute
    /// [`Timestamp`]; the caller must later call
    /// [`Endpoint::handle_timeout`] with that (or a later) time. Already
    /// handled deadlines are not reported again.
    #[must_use]
    pub fn poll_timeout(&mut self) -> Option<Timestamp> {
        let mut earliest: Option<std::time::Instant> = None;
        for state in self.connections.values_mut() {
            if let Some(deadline) = state.connection.poll_timeout() {
                earliest = Some(earliest.map_or(deadline, |current| current.min(deadline)));
            }
        }
        earliest.map(to_timestamp)
    }

    /// Drive all expired timers for all connections.
    ///
    /// `handle_timeout` in the gate vocabulary. Uses only the injected time;
    /// never sleeps or reads the clock.
    pub fn handle_timeout(&mut self, now: Timestamp) {
        let now = to_instant(now);
        let ids: Vec<ConnectionId> = self.connections.keys().copied().collect();
        for id in ids {
            if let Some(state) = self.connections.get_mut(&id) {
                state.connection.handle_timeout(now);
            }
            self.drain(id);
        }
        self.reap_drained();
    }

    /// Open a unidirectional stream.
    ///
    /// `open_uni` in the gate vocabulary.
    ///
    /// # Errors
    ///
    /// [`StreamError::UnknownConnection`], [`StreamError::Closed`] or
    /// [`StreamError::StreamLimitReached`].
    pub fn open_uni(&mut self, connection: ConnectionId) -> Result<StreamId, StreamError> {
        self.open_stream(connection, Dir::Uni)
    }

    /// Open a bidirectional stream.
    ///
    /// `open_bi` in the gate vocabulary.
    ///
    /// # Errors
    ///
    /// [`StreamError::UnknownConnection`], [`StreamError::Closed`] or
    /// [`StreamError::StreamLimitReached`].
    pub fn open_bi(&mut self, connection: ConnectionId) -> Result<StreamId, StreamError> {
        self.open_stream(connection, Dir::Bi)
    }

    /// Accept a peer-initiated unidirectional stream.
    ///
    /// `accept_uni` in the gate vocabulary.
    ///
    /// # Errors
    ///
    /// [`StreamError::UnknownConnection`] or [`StreamError::Closed`].
    pub fn accept_uni(
        &mut self,
        connection: ConnectionId,
    ) -> Result<Option<StreamId>, StreamError> {
        self.accept_stream(connection, Dir::Uni)
    }

    /// Accept a peer-initiated bidirectional stream.
    ///
    /// `accept_bi` in the gate vocabulary.
    ///
    /// # Errors
    ///
    /// [`StreamError::UnknownConnection`] or [`StreamError::Closed`].
    pub fn accept_bi(&mut self, connection: ConnectionId) -> Result<Option<StreamId>, StreamError> {
        self.accept_stream(connection, Dir::Bi)
    }

    /// Write stream data.
    ///
    /// Returns the number of bytes accepted; a short write means the peer’s
    /// flow-control window is exhausted and the rest must be retried after a
    /// [`StreamEvent::Writable`] event or further pump rounds.
    ///
    /// # Errors
    ///
    /// [`StreamError::UnknownConnection`], [`StreamError::Closed`],
    /// [`StreamError::WrongDirection`], [`StreamError::Blocked`],
    /// [`StreamError::StreamClosed`] or [`StreamError::StoppedByPeer`].
    pub fn write_stream(
        &mut self,
        connection: ConnectionId,
        stream: StreamId,
        data: &[u8],
    ) -> Result<usize, StreamError> {
        let state = self
            .connections
            .get_mut(&connection)
            .ok_or(StreamError::UnknownConnection)?;
        if state.connection.is_closed() {
            return Err(StreamError::Closed);
        }
        if !allows_send(stream, state.connection.side()) {
            return Err(StreamError::WrongDirection);
        }
        let id = stream.to_quinn().ok_or(StreamError::StreamClosed)?;
        let written = state
            .connection
            .send_stream(id)
            .write(data)
            .map_err(map_write_error)?;
        let written_u64 = u64::try_from(written).unwrap_or(u64::MAX);
        state.stream_bytes_sent = state.stream_bytes_sent.saturating_add(written_u64);
        Ok(written)
    }

    /// Read stream data into a caller-owned buffer.
    ///
    /// [`StreamRead::Finished`] means the peer finished and every byte has
    /// been delivered. Flow-control credit is released even when this call
    /// returns [`StreamError::Blocked`].
    ///
    /// # Errors
    ///
    /// [`StreamError::UnknownConnection`], [`StreamError::WrongDirection`],
    /// [`StreamError::StreamClosed`], [`StreamError::Blocked`],
    /// [`StreamError::ResetByPeer`] or [`StreamError::EmptyBuffer`].
    pub fn read_stream(
        &mut self,
        connection: ConnectionId,
        stream: StreamId,
        buffer: &mut [u8],
    ) -> Result<StreamRead, StreamError> {
        if buffer.is_empty() {
            return Err(StreamError::EmptyBuffer);
        }
        let state = self
            .connections
            .get_mut(&connection)
            .ok_or(StreamError::UnknownConnection)?;
        if !allows_recv(stream, state.connection.side()) {
            return Err(StreamError::WrongDirection);
        }
        let id = stream.to_quinn().ok_or(StreamError::StreamClosed)?;
        let outcome = {
            let mut recv = state.connection.recv_stream(id);
            let mut chunks = recv.read(true).map_err(|_| StreamError::StreamClosed)?;
            let next = chunks.next(buffer.len());
            let outcome = match next {
                Ok(Some(chunk)) => {
                    let len = chunk.bytes.len();
                    buffer[..len].copy_from_slice(&chunk.bytes);
                    Ok(StreamRead::Data { len })
                }
                Ok(None) => Ok(StreamRead::Finished),
                Err(ReadError::Blocked) => Err(StreamError::Blocked),
                Err(ReadError::Reset(error_code)) => Err(StreamError::ResetByPeer {
                    error_code: error_code.into(),
                }),
            };
            // The returned hint only says whether a window update should be
            // transmitted soon; the caller's next `poll_transmit` sends it.
            let _credit_update = chunks.finalize();
            outcome
        };
        if let Ok(StreamRead::Data { len }) = outcome {
            let len = u64::try_from(len).unwrap_or(u64::MAX);
            state.stream_bytes_received = state.stream_bytes_received.saturating_add(len);
        }
        outcome
    }

    /// Finish a send stream (half-close).
    ///
    /// # Errors
    ///
    /// [`StreamError::UnknownConnection`], [`StreamError::Closed`],
    /// [`StreamError::WrongDirection`], [`StreamError::StreamClosed`] or
    /// [`StreamError::StoppedByPeer`].
    pub fn finish_stream(
        &mut self,
        connection: ConnectionId,
        stream: StreamId,
    ) -> Result<(), StreamError> {
        let state = self
            .connections
            .get_mut(&connection)
            .ok_or(StreamError::UnknownConnection)?;
        if state.connection.is_closed() {
            return Err(StreamError::Closed);
        }
        if !allows_send(stream, state.connection.side()) {
            return Err(StreamError::WrongDirection);
        }
        let id = stream.to_quinn().ok_or(StreamError::StreamClosed)?;
        state
            .connection
            .send_stream(id)
            .finish()
            .map_err(map_finish_error)
    }

    /// Reset a send stream with an application error code.
    ///
    /// # Errors
    ///
    /// [`StreamError::UnknownConnection`], [`StreamError::Closed`],
    /// [`StreamError::WrongDirection`], [`StreamError::StreamClosed`] or
    /// [`StreamError::ErrorCodeOutOfRange`].
    pub fn reset_stream(
        &mut self,
        connection: ConnectionId,
        stream: StreamId,
        error_code: u64,
    ) -> Result<(), StreamError> {
        let code = VarInt::from_u64(error_code).map_err(|_| StreamError::ErrorCodeOutOfRange)?;
        let state = self
            .connections
            .get_mut(&connection)
            .ok_or(StreamError::UnknownConnection)?;
        if state.connection.is_closed() {
            return Err(StreamError::Closed);
        }
        if !allows_send(stream, state.connection.side()) {
            return Err(StreamError::WrongDirection);
        }
        let id = stream.to_quinn().ok_or(StreamError::StreamClosed)?;
        state
            .connection
            .send_stream(id)
            .reset(code)
            .map_err(|_| StreamError::StreamClosed)
    }

    /// Ask the peer to stop sending on a receive stream.
    ///
    /// `stop_sending` in the gate vocabulary.
    ///
    /// # Errors
    ///
    /// [`StreamError::UnknownConnection`], [`StreamError::Closed`],
    /// [`StreamError::WrongDirection`], [`StreamError::StreamClosed`] or
    /// [`StreamError::ErrorCodeOutOfRange`].
    pub fn stop_sending(
        &mut self,
        connection: ConnectionId,
        stream: StreamId,
        error_code: u64,
    ) -> Result<(), StreamError> {
        let code = VarInt::from_u64(error_code).map_err(|_| StreamError::ErrorCodeOutOfRange)?;
        let state = self
            .connections
            .get_mut(&connection)
            .ok_or(StreamError::UnknownConnection)?;
        if state.connection.is_closed() {
            return Err(StreamError::Closed);
        }
        if !allows_recv(stream, state.connection.side()) {
            return Err(StreamError::WrongDirection);
        }
        let id = stream.to_quinn().ok_or(StreamError::StreamClosed)?;
        state
            .connection
            .recv_stream(id)
            .stop(code)
            .map_err(|_| StreamError::StreamClosed)
    }

    /// Queue an unreliable QUIC DATAGRAM.
    ///
    /// `send_datagram` in the gate vocabulary. DATAGRAMs are never
    /// retransmitted. Returns the payload length on success.
    ///
    /// # Errors
    ///
    /// [`DatagramError::UnknownConnection`], [`DatagramError::Closed`],
    /// [`DatagramError::Disabled`], [`DatagramError::UnsupportedByPeer`],
    /// [`DatagramError::TooLarge`] or [`DatagramError::WouldBlock`].
    pub fn send_datagram(
        &mut self,
        connection: ConnectionId,
        data: &[u8],
    ) -> Result<usize, DatagramError> {
        let state = self
            .connections
            .get_mut(&connection)
            .ok_or(DatagramError::UnknownConnection)?;
        if state.connection.is_closed() {
            return Err(DatagramError::Closed);
        }
        let mut datagrams = state.connection.datagrams();
        let max_len = datagrams
            .max_size()
            .ok_or(DatagramError::UnsupportedByPeer)?;
        match datagrams.send(Bytes::copy_from_slice(data), false) {
            Ok(()) => Ok(data.len()),
            Err(SendDatagramError::TooLarge) => Err(DatagramError::TooLarge { max_len }),
            Err(SendDatagramError::UnsupportedByPeer) => Err(DatagramError::UnsupportedByPeer),
            Err(SendDatagramError::Disabled) => Err(DatagramError::Disabled),
            Err(SendDatagramError::Blocked(_)) => Err(DatagramError::WouldBlock),
        }
    }

    /// Copy the oldest received DATAGRAM into `buffer`.
    ///
    /// `poll_datagram` in the gate vocabulary. Returns `Ok(None)` when the
    /// receive queue is empty.
    ///
    /// # Errors
    ///
    /// [`DatagramError::UnknownConnection`] or
    /// [`DatagramError::BufferTooSmall`] (the datagram is discarded, never
    /// truncated).
    pub fn poll_datagram(
        &mut self,
        connection: ConnectionId,
        buffer: &mut [u8],
    ) -> Result<Option<usize>, DatagramError> {
        let state = self
            .connections
            .get_mut(&connection)
            .ok_or(DatagramError::UnknownConnection)?;
        let Some(datagram) = state.connection.datagrams().recv() else {
            return Ok(None);
        };
        let len = datagram.len();
        if len > buffer.len() {
            return Err(DatagramError::BufferTooSmall { datagram_len: len });
        }
        buffer[..len].copy_from_slice(&datagram);
        Ok(Some(len))
    }

    /// Close the connection with an application error code and reason.
    ///
    /// `close` in the gate vocabulary. The local close event is emitted once;
    /// repeated calls are idempotent. Close packets are emitted by
    /// [`Endpoint::poll_transmit`] during the draining period.
    ///
    /// # Errors
    ///
    /// [`CloseError::UnknownConnection`] or
    /// [`CloseError::ErrorCodeOutOfRange`].
    pub fn close(
        &mut self,
        connection: ConnectionId,
        now: Timestamp,
        error_code: u64,
        reason: &[u8],
    ) -> Result<(), CloseError> {
        let code = VarInt::from_u64(error_code).map_err(|_| CloseError::ErrorCodeOutOfRange)?;
        let state = self
            .connections
            .get_mut(&connection)
            .ok_or(CloseError::UnknownConnection)?;
        if state.connection.is_closed() {
            return Ok(());
        }
        state
            .connection
            .close(to_instant(now), code, Bytes::copy_from_slice(reason));
        state.close_reported = true;
        self.events.push_back(Event {
            connection,
            kind: EventKind::Closed(CloseReason::Application {
                origin: CloseOrigin::Local,
                error_code,
                reason: reason.to_vec(),
            }),
        });
        Ok(())
    }

    /// Take a transport metrics snapshot.
    ///
    /// `metrics` in the gate vocabulary. The snapshot allocates nothing.
    ///
    /// # Errors
    ///
    /// [`MetricsError::UnknownConnection`] when the handle is unknown or has
    /// been reaped after draining.
    pub fn metrics(&self, connection: ConnectionId) -> Result<Metrics, MetricsError> {
        let state = self
            .connections
            .get(&connection)
            .ok_or(MetricsError::UnknownConnection)?;
        let connection_stats = state.connection.stats();
        let controller_metrics = state.connection.congestion_state().metrics();
        Ok(Metrics {
            smoothed_rtt_micros: micros(state.connection.rtt()),
            latest_rtt_micros: state.telemetry.latest_rtt_micros(),
            min_rtt_micros: micros(state.connection.min_rtt()),
            congestion_window_bytes: connection_stats.path.cwnd,
            bytes_in_flight: state.telemetry.bytes_in_flight(),
            lost_packets: connection_stats.path.lost_packets,
            datagrams_sent: connection_stats.frame_tx.datagram,
            datagrams_received: connection_stats.frame_rx.datagram,
            stream_bytes_sent: state.stream_bytes_sent,
            stream_bytes_received: state.stream_bytes_received,
            pacing_rate_bits_per_second: controller_metrics.pacing_rate,
            snapshot_allocations: 0,
        })
    }

    fn allocate_id(&mut self) -> ConnectionId {
        let id = ConnectionId(self.next_connection_id);
        self.next_connection_id = self.next_connection_id.saturating_add(1);
        id
    }

    fn open_stream(
        &mut self,
        connection: ConnectionId,
        direction: Dir,
    ) -> Result<StreamId, StreamError> {
        let state = self
            .connections
            .get_mut(&connection)
            .ok_or(StreamError::UnknownConnection)?;
        if state.connection.is_closed() {
            return Err(StreamError::Closed);
        }
        state
            .connection
            .streams()
            .open(direction)
            .map(StreamId::from)
            .ok_or(StreamError::StreamLimitReached)
    }

    fn accept_stream(
        &mut self,
        connection: ConnectionId,
        direction: Dir,
    ) -> Result<Option<StreamId>, StreamError> {
        let state = self
            .connections
            .get_mut(&connection)
            .ok_or(StreamError::UnknownConnection)?;
        if state.connection.is_closed() {
            return Err(StreamError::Closed);
        }
        Ok(state
            .connection
            .streams()
            .accept(direction)
            .map(StreamId::from))
    }

    fn queue_transmit(&mut self, buffer: &[u8], destination: std::net::SocketAddr, size: usize) {
        let payload = buffer.get(..size).unwrap_or(buffer).to_vec();
        self.pending_transmits.push_back(PendingTransmit {
            destination: from_std_addr(destination),
            payload,
        });
    }

    fn drain(&mut self, id: ConnectionId) {
        loop {
            let event = self
                .connections
                .get_mut(&id)
                .and_then(|state| state.connection.poll_endpoint_events());
            let Some(event) = event else {
                break;
            };
            let handle = match self.connections.get(&id) {
                Some(state) => state.handle,
                None => break,
            };
            if let Some(connection_event) = self.inner.handle_event(handle, event) {
                if let Some(state) = self.connections.get_mut(&id) {
                    state.connection.handle_event(connection_event);
                }
            }
        }
        loop {
            let event = self
                .connections
                .get_mut(&id)
                .and_then(|state| state.connection.poll());
            let Some(event) = event else {
                break;
            };
            self.translate(id, event);
        }
    }

    fn translate(&mut self, id: ConnectionId, event: QuinnEvent) {
        match event {
            QuinnEvent::HandshakeDataReady | QuinnEvent::DatagramsUnblocked => {}
            QuinnEvent::Connected => {
                if self
                    .connections
                    .get(&id)
                    .is_none_or(|state| state.handshake_complete)
                {
                    return;
                }
                let info = self.handshake_info(id);
                if let Some(state) = self.connections.get_mut(&id) {
                    state.handshake_complete = true;
                }
                self.events.push_back(Event {
                    connection: id,
                    kind: EventKind::HandshakeComplete(info),
                });
            }
            QuinnEvent::ConnectionLost { reason } => self.connection_lost(id, &reason),
            QuinnEvent::Stream(stream_event) => {
                self.events.push_back(Event {
                    connection: id,
                    kind: EventKind::Stream(translate_stream_event(stream_event)),
                });
            }
            QuinnEvent::DatagramReceived => {
                self.events.push_back(Event {
                    connection: id,
                    kind: EventKind::DatagramReceived,
                });
            }
        }
    }

    fn handshake_info(&mut self, id: ConnectionId) -> HandshakeInfo {
        let Some(state) = self.connections.get_mut(&id) else {
            return HandshakeInfo {
                alpn: None,
                peer_transport_parameters: PeerTransportParameters::empty(),
                datagram_supported: false,
            };
        };
        let alpn = state
            .connection
            .crypto_session()
            .handshake_data()
            .and_then(|data| data.downcast::<HandshakeData>().ok())
            .and_then(|data| data.protocol.clone());
        let peer_transport_parameters =
            match state.connection.crypto_session().transport_parameters() {
                Ok(Some(parameters)) => {
                    let mut encoded = Vec::new();
                    parameters.write(&mut encoded);
                    PeerTransportParameters::from_encoded(encoded)
                }
                Ok(None) | Err(_) => PeerTransportParameters::empty(),
            };
        let datagram_supported = state.connection.datagrams().max_size().is_some();
        HandshakeInfo {
            alpn,
            peer_transport_parameters,
            datagram_supported,
        }
    }

    fn connection_lost(&mut self, id: ConnectionId, reason: &ConnectionError) {
        let Some(state) = self.connections.get(&id) else {
            return;
        };
        if state.close_reported {
            return;
        }
        let handshake_complete = state.handshake_complete;
        let kind = if handshake_complete {
            EventKind::Closed(close_reason_from_error(reason))
        } else {
            EventKind::HandshakeFailed(classify_handshake_failure(reason))
        };
        if let Some(state) = self.connections.get_mut(&id) {
            state.close_reported = true;
        }
        self.events.push_back(Event {
            connection: id,
            kind,
        });
    }

    fn reap_drained(&mut self) {
        let drained: Vec<ConnectionId> = self
            .connections
            .iter()
            .filter(|(_, state)| state.connection.is_drained())
            .map(|(id, _)| *id)
            .collect();
        for id in drained {
            if let Some(state) = self.connections.remove(&id) {
                self.by_quinn_handle.remove(&state.handle.0);
            }
        }
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint")
            .field("connections", &self.connections.len())
            .field("pending_incoming", &self.pending_incoming.len())
            .field("queued_events", &self.events.len())
            .field("queued_transmits", &self.pending_transmits.len())
            .finish_non_exhaustive()
    }
}

fn allows_send(stream: StreamId, side: Side) -> bool {
    match stream.direction() {
        Direction::Bi => true,
        Direction::Uni => stream.initiated_by_client() == (side == Side::Client),
    }
}

fn allows_recv(stream: StreamId, side: Side) -> bool {
    match stream.direction() {
        Direction::Bi => true,
        Direction::Uni => stream.initiated_by_client() != (side == Side::Client),
    }
}

fn micros(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "upstream error types are consumed by the facade's error mapping"
)]
fn map_connect_error(error: quinn_proto::ConnectError) -> ConnectError {
    use quinn_proto::ConnectError as Upstream;
    match error {
        Upstream::EndpointStopping | Upstream::NoDefaultClientConfig => {
            ConnectError::EndpointStopping
        }
        Upstream::CidsExhausted => ConnectError::CidsExhausted,
        Upstream::InvalidServerName(_) => ConnectError::InvalidServerName,
        Upstream::InvalidRemoteAddress(_) => ConnectError::InvalidRemoteAddress,
        Upstream::UnsupportedVersion => ConnectError::UnsupportedVersion,
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "upstream error types are consumed by the facade's error mapping"
)]
fn map_write_error(error: WriteError) -> StreamError {
    match error {
        WriteError::Blocked => StreamError::Blocked,
        WriteError::Stopped(error_code) => StreamError::StoppedByPeer {
            error_code: error_code.into(),
        },
        WriteError::ClosedStream => StreamError::StreamClosed,
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "upstream error types are consumed by the facade's error mapping"
)]
fn map_finish_error(error: FinishError) -> StreamError {
    match error {
        FinishError::Stopped(error_code) => StreamError::StoppedByPeer {
            error_code: error_code.into(),
        },
        FinishError::ClosedStream => StreamError::StreamClosed,
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "upstream event types are consumed while translating to facade events"
)]
fn translate_stream_event(event: QuinnStreamEvent) -> StreamEvent {
    match event {
        QuinnStreamEvent::Opened { dir } => StreamEvent::Opened {
            direction: Direction::from_dir(dir),
        },
        QuinnStreamEvent::Readable { id } => StreamEvent::Readable {
            stream: StreamId::from(id),
        },
        QuinnStreamEvent::Writable { id } => StreamEvent::Writable {
            stream: StreamId::from(id),
        },
        QuinnStreamEvent::Finished { id } => StreamEvent::Finished {
            stream: StreamId::from(id),
        },
        QuinnStreamEvent::Stopped { id, error_code } => StreamEvent::Stopped {
            stream: StreamId::from(id),
            error_code: error_code.into(),
        },
        QuinnStreamEvent::Available { dir } => StreamEvent::Available {
            direction: Direction::from_dir(dir),
        },
    }
}

fn classify_handshake_failure(reason: &ConnectionError) -> HandshakeFailure {
    match reason {
        ConnectionError::TimedOut => HandshakeFailure::Timeout,
        ConnectionError::TransportError(error) => classify_transport_code(error.code),
        ConnectionError::ConnectionClosed(close) => classify_transport_code(close.error_code),
        ConnectionError::ApplicationClosed(_) | ConnectionError::Reset => {
            HandshakeFailure::PeerClosed
        }
        ConnectionError::LocallyClosed => HandshakeFailure::LocalClose,
        ConnectionError::VersionMismatch | ConnectionError::CidsExhausted => {
            HandshakeFailure::Protocol
        }
    }
}

fn classify_transport_code(code: TransportErrorCode) -> HandshakeFailure {
    if code == TransportErrorCode::TRANSPORT_PARAMETER_ERROR {
        return HandshakeFailure::TransportParameter;
    }
    let raw = u64::from(code);
    if !(0x100..0x200).contains(&raw) {
        return if code == TransportErrorCode::CONNECTION_REFUSED {
            HandshakeFailure::PeerClosed
        } else {
            HandshakeFailure::Protocol
        };
    }
    let alert = u8::try_from(raw & 0xff).unwrap_or(0);
    match alert {
        120 => HandshakeFailure::Alpn,
        42..=46 | 48..=51 => HandshakeFailure::Certificate,
        _ => HandshakeFailure::Protocol,
    }
}

fn close_reason_from_error(reason: &ConnectionError) -> CloseReason {
    match reason {
        ConnectionError::ApplicationClosed(close) => CloseReason::Application {
            origin: CloseOrigin::Remote,
            error_code: close.error_code.into(),
            reason: close.reason.to_vec(),
        },
        ConnectionError::ConnectionClosed(close) => CloseReason::Transport {
            error_code: u64::from(close.error_code),
        },
        ConnectionError::TransportError(error) => CloseReason::Transport {
            error_code: u64::from(error.code),
        },
        ConnectionError::TimedOut => CloseReason::TimedOut,
        ConnectionError::Reset => CloseReason::Reset,
        ConnectionError::VersionMismatch => CloseReason::VersionMismatch,
        ConnectionError::LocallyClosed => CloseReason::Application {
            origin: CloseOrigin::Local,
            error_code: 0,
            reason: Vec::new(),
        },
        ConnectionError::CidsExhausted => CloseReason::Transport { error_code: 1 },
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectionId, Endpoint, classify_handshake_failure, close_reason_from_error};
    use crate::config::EndpointConfig;
    use crate::error::{
        AcceptError, CloseError, ConnectError, DatagramError, MetricsError, StreamError,
    };
    use crate::event::{CloseOrigin, CloseReason, HandshakeFailure};
    use quinn_proto::{
        ConnectionError, Dir, Side, StreamId as QuinnStreamId, TransportError, TransportErrorCode,
    };
    use rtx_core::{IpAddr, SocketAddr, Timestamp};

    fn endpoint() -> Endpoint {
        Endpoint::new(EndpointConfig::new()).expect("client-only endpoint")
    }

    #[test]
    fn unknown_connections_and_incoming_produce_explicit_errors() {
        let mut endpoint = endpoint();
        let id = ConnectionId(0);
        assert_eq!(
            endpoint.open_uni(id).expect_err("unknown"),
            StreamError::UnknownConnection
        );
        assert_eq!(
            endpoint.open_bi(id).expect_err("unknown"),
            StreamError::UnknownConnection
        );
        assert_eq!(
            endpoint.accept_uni(id).expect_err("unknown"),
            StreamError::UnknownConnection
        );
        assert_eq!(
            endpoint.accept_bi(id).expect_err("unknown"),
            StreamError::UnknownConnection
        );
        assert_eq!(
            endpoint.send_datagram(id, b"x").expect_err("unknown"),
            DatagramError::UnknownConnection
        );
        assert_eq!(
            endpoint
                .poll_datagram(id, &mut [0u8; 8])
                .expect_err("unknown"),
            DatagramError::UnknownConnection
        );
        assert_eq!(
            endpoint
                .close(id, Timestamp::ZERO, 0, b"")
                .expect_err("unknown"),
            CloseError::UnknownConnection
        );
        assert_eq!(
            endpoint.metrics(id).expect_err("unknown"),
            MetricsError::UnknownConnection
        );
        assert_eq!(
            endpoint
                .accept(Timestamp::ZERO, id, &mut Vec::new())
                .expect_err("unknown"),
            AcceptError::UnknownIncoming
        );
        assert_eq!(
            endpoint.refuse(id).expect_err("unknown"),
            AcceptError::UnknownIncoming
        );
    }

    #[test]
    fn empty_read_buffer_is_explicit() {
        let mut endpoint = endpoint();
        let stream = crate::stream::StreamId::from(QuinnStreamId::new(Side::Client, Dir::Bi, 0));
        assert_eq!(
            endpoint
                .read_stream(ConnectionId(0), stream, &mut [])
                .expect_err("empty buffer"),
            StreamError::EmptyBuffer
        );
    }

    #[test]
    fn invalid_remote_address_and_server_name_are_reported() {
        let mut endpoint = endpoint();
        let unspecified = SocketAddr::new(IpAddr::V4([0, 0, 0, 0]), 4433);
        assert_eq!(
            endpoint
                .connect(Timestamp::ZERO, unspecified, "localhost")
                .expect_err("unspecified address"),
            ConnectError::InvalidRemoteAddress
        );
        let remote = SocketAddr::new(IpAddr::V4([127, 0, 0, 1]), 4433);
        assert_eq!(
            endpoint
                .connect(Timestamp::ZERO, remote, "not a server name")
                .expect_err("invalid name"),
            ConnectError::InvalidServerName
        );
    }

    #[test]
    fn timeout_is_a_timeout() {
        assert_eq!(
            classify_handshake_failure(&ConnectionError::TimedOut),
            HandshakeFailure::Timeout
        );
    }

    #[test]
    fn alpn_alert_is_alpn() {
        assert_eq!(
            classify_handshake_failure(&transport_error(TransportErrorCode::crypto(120))),
            HandshakeFailure::Alpn
        );
    }

    #[test]
    fn certificate_alerts_are_certificate() {
        for alert in [42, 43, 44, 45, 46, 48, 49, 50, 51] {
            assert_eq!(
                classify_handshake_failure(&transport_error(TransportErrorCode::crypto(alert))),
                HandshakeFailure::Certificate
            );
        }
    }

    #[test]
    fn transport_parameter_error_is_its_own_class() {
        assert_eq!(
            classify_handshake_failure(&transport_error(
                TransportErrorCode::TRANSPORT_PARAMETER_ERROR
            )),
            HandshakeFailure::TransportParameter
        );
    }

    #[test]
    fn other_transport_errors_are_protocol() {
        assert_eq!(
            classify_handshake_failure(&transport_error(TransportErrorCode::PROTOCOL_VIOLATION)),
            HandshakeFailure::Protocol
        );
    }

    #[test]
    fn local_close_maps_to_local_application_close() {
        let reason = close_reason_from_error(&ConnectionError::LocallyClosed);
        assert!(matches!(
            reason,
            CloseReason::Application {
                origin: CloseOrigin::Local,
                ..
            }
        ));
    }

    fn transport_error(code: TransportErrorCode) -> ConnectionError {
        ConnectionError::TransportError(TransportError {
            code,
            frame: None,
            reason: String::new(),
        })
    }
}
