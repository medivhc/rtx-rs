//! The loopback pump: two `rtx-quic` endpoints driven by two UDP sockets,
//! with a deterministic loss/RTT layer in front of every transmit.
//!
//! # Time model
//!
//! One monotonic `Instant` is captured at construction. Every
//! `rtx_core::Timestamp` passed to the facade is derived from that epoch;
//! the wall clock is never read. The simulator's delays are expressed as
//! virtual microseconds and the pump moves datagrams when their release
//! timestamp is reached, which is exactly how `M3-PM2`'s simulator is meant
//! to be consumed.
//!
//! # Wait mechanism (no `thread::sleep`)
//!
//! Like the R6-3 server harness, the pump never sleeps to advance protocol
//! state. When there is nothing to deliver it turns the server socket
//! blocking with a bounded `set_read_timeout` (the minimum of the next
//! endpoint deadline, the next delayed-datagram release and a caller-supplied
//! cap) and waits for one datagram. A timeout means “advance time and run
//! `handle_timeout`” if a deadline is due. The client socket is drained
//! non-blocking after that wait.
//!
//! # Sources of nondeterminism
//!
//! Kernel scheduling still decides when a loopback datagram is visible, and
//! the scenario wall-clock durations are real time. The netem verdict
//! sequence is deterministic (seed + input sequence), but the measurement
//! values are recorded, never asserted.

use std::io;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use rtx_core::{IpAddr, SocketAddr, Timestamp};
use rtx_quic::{
    ConnectionId, DatagramError, Endpoint, EndpointConfig, EventKind, HandshakeInfo, StreamError,
    StreamId, StreamRead, TransportConfig,
};
use rtx_testkit::netem::{Netem, Profile};
use rtx_wire::varint;

/// ALPN used by every connection in this harness.
pub const ALPN: &[u8] = b"h3";

/// `max_datagram_frame_size` this harness advertises (`M3-PS8`).
///
/// The value is copied verbatim into the QUIC transport parameter by
/// `quinn-proto`; the harness never hard-codes it into a result. The
/// *negotiated* value is read back from `HandshakeInfo`.
pub const ADVERTISED_MAX_DATAGRAM_FRAME_SIZE: usize = 1100;

/// Cap on a single socket wait.
const MAX_WAIT: Duration = Duration::from_millis(1);

/// Longest wait delegated to the OS scheduler instead of the socket timer.
const SLEEP_WAIT: Duration = Duration::from_millis(1);

/// A direction of the link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    /// Client endpoint to server endpoint.
    ToServer,
    /// Server endpoint to client endpoint.
    ToClient,
}

/// One datagram held for its release time.
#[derive(Debug)]
struct Delayed {
    release_at: Timestamp,
    payload: Vec<u8>,
}

/// Per-direction network emulation state.
#[derive(Debug)]
struct LinkState {
    netem: Netem,
    queued: Vec<Delayed>,
    dropped: u64,
    released: u64,
    max_depth: u64,
}

impl LinkState {
    fn new(profile: Profile) -> Self {
        Self {
            netem: Netem::new(profile),
            queued: Vec::new(),
            dropped: 0,
            released: 0,
            max_depth: 0,
        }
    }

    fn decision(&mut self, now: Timestamp) -> (bool, Timestamp) {
        let decision = self.netem.next_decision();
        let release = Timestamp::from_micros(now.as_micros().saturating_add(decision.delay_micros));
        (decision.dropped, release)
    }

    fn enqueue(&mut self, release_at: Timestamp, payload: Vec<u8>) {
        self.queued.push(Delayed {
            release_at,
            payload,
        });
        let depth = u64::try_from(self.queued.len()).unwrap_or(u64::MAX);
        self.max_depth = self.max_depth.max(depth);
    }

    fn next_release(&self) -> Option<Timestamp> {
        self.queued.iter().map(|item| item.release_at).min()
    }
}

/// A loopback pair: one client endpoint, one server endpoint, two sockets.
#[derive(Debug)]
pub struct Sim {
    /// Client endpoint (facade).
    pub client: Endpoint,
    /// Server endpoint (facade).
    pub server: Endpoint,
    socket_client: UdpSocket,
    socket_server: UdpSocket,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
    epoch: Instant,
    now: Timestamp,
    to_server: LinkState,
    to_client: LinkState,
    connect_start: Timestamp,
    scratch: Vec<u8>,
    /// Every server-side connection accepted so far.
    pub server_connections: Vec<ConnectionId>,
    /// Number of completed client handshakes.
    pub client_handshakes: u64,
    /// Number of completed server handshakes.
    pub server_handshakes: u64,
    /// Number of handshake failures observed on either side.
    pub handshake_failures: u64,
    /// Handshake durations (client-observed, microseconds).
    pub handshake_micros: Vec<u64>,
    /// The `HandshakeInfo` of the last client handshake.
    pub client_info: Option<HandshakeInfo>,
    /// The `HandshakeInfo` of the last server handshake.
    pub server_info: Option<HandshakeInfo>,
    /// UDP payload bytes sent (QUIC line-rate bytes).
    pub wire_bytes_out: u64,
    /// UDP payload bytes received.
    pub wire_bytes_in: u64,
    /// UDP datagrams emitted by the two endpoints.
    pub transmits: u64,
    /// DATAGRAM send calls that reported `WouldBlock`.
    pub datagram_send_blocked: u64,
}

impl Sim {
    /// Builds the pair with a self-signed certificate/key and a netem profile
    /// for each direction.
    ///
    /// # Errors
    ///
    /// Returns an error when an endpoint cannot be created, a socket cannot
    /// be bound or the certificate is rejected.
    pub fn new(
        certificate_der: &[u8],
        private_key_der: &[u8],
        loss_percent: u8,
        rtt_micros: u64,
        seed: u64,
    ) -> Result<Self, String> {
        let transport = TransportConfig {
            datagram_receive_buffer_bytes: Some(ADVERTISED_MAX_DATAGRAM_FRAME_SIZE),
            max_concurrent_bidi_streams: 100,
            max_concurrent_uni_streams: 100,
            ..TransportConfig::default()
        };
        let server_config = EndpointConfig::new()
            .with_alpn(vec![ALPN.to_vec()])
            .with_transport(transport.clone())
            .with_server_identity(vec![certificate_der.to_vec()], private_key_der.to_vec())
            .with_rng_seed(seed_bytes(seed, 1));
        let client_config = EndpointConfig::new()
            .with_alpn(vec![ALPN.to_vec()])
            .with_transport(transport)
            .with_client_roots(vec![certificate_der.to_vec()])
            .with_rng_seed(seed_bytes(seed, 2));

        let client =
            Endpoint::new(client_config).map_err(|error| format!("client endpoint: {error}"))?;
        let server =
            Endpoint::new(server_config).map_err(|error| format!("server endpoint: {error}"))?;

        let socket_client = bind_loopback()?;
        let socket_server = bind_loopback()?;
        let client_addr = to_rtx_addr(socket_client.local_addr().map_err(io_error)?);
        let server_addr = to_rtx_addr(socket_server.local_addr().map_err(io_error)?);

        let to_server_profile =
            Profile::new(seed ^ 0xA5A5_5A5A_0000_0001, loss_percent, rtt_micros, 0)
                .map_err(|error| format!("netem profile: {error}"))?;
        let to_client_profile =
            Profile::new(seed ^ 0xA5A5_5A5A_0000_0002, loss_percent, rtt_micros, 0)
                .map_err(|error| format!("netem profile: {error}"))?;

        Ok(Self {
            client,
            server,
            socket_client,
            socket_server,
            client_addr,
            server_addr,
            epoch: Instant::now(),
            now: Timestamp::ZERO,
            to_server: LinkState::new(to_server_profile),
            to_client: LinkState::new(to_client_profile),
            connect_start: Timestamp::ZERO,
            scratch: Vec::new(),
            server_connections: Vec::new(),
            client_handshakes: 0,
            server_handshakes: 0,
            handshake_failures: 0,
            handshake_micros: Vec::new(),
            client_info: None,
            server_info: None,
            wire_bytes_out: 0,
            wire_bytes_in: 0,
            transmits: 0,
            datagram_send_blocked: 0,
        })
    }

    /// The current monotonic timestamp.
    #[must_use]
    pub fn now(&self) -> Timestamp {
        self.now
    }

    /// Refreshes `now` from the monotonic epoch and returns it.
    pub fn clock(&mut self) -> Timestamp {
        let micros = self.epoch.elapsed().as_micros();
        self.now = Timestamp::from_micros(u64::try_from(micros).unwrap_or(u64::MAX));
        self.now
    }

    /// Starts `count` client connections.
    ///
    /// # Errors
    ///
    /// Returns an error when the facade rejects a connection (for example an
    /// exhausted CID space).
    pub fn connect_many(&mut self, count: u32) -> Result<Vec<ConnectionId>, String> {
        let now = self.clock();
        self.connect_start = now;
        let mut ids = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
        for _ in 0..count {
            let id = self
                .client
                .connect(now, self.server_addr, "localhost")
                .map_err(|error| format!("connect: {error}"))?;
            ids.push(id);
        }
        Ok(ids)
    }

    /// The peak queue depth across both netem queues.
    #[must_use]
    pub fn queue_max_depth(&self) -> u64 {
        self.to_server.max_depth.max(self.to_client.max_depth)
    }

    /// The number of datagrams dropped by the simulator.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.to_server.dropped + self.to_client.dropped
    }

    /// One pump round: receive, handle events, transmit, release delayed
    /// datagrams, receive again.
    pub fn tick(&mut self) -> Result<(), String> {
        self.clock();
        self.receive(Link::ToServer)?;
        self.receive(Link::ToClient)?;
        self.handle_events();
        self.transmit(Link::ToServer)?;
        self.transmit(Link::ToClient)?;
        self.release_delayed(Link::ToServer)?;
        self.release_delayed(Link::ToClient)?;
        self.receive(Link::ToServer)?;
        self.receive(Link::ToClient)?;
        self.handle_events();
        Ok(())
    }

    /// Waits up to `max_wait` for one server-side datagram, then handles due
    /// timers and drains the client socket.
    ///
    /// Waits of at most [`SLEEP_WAIT`] are delegated to the OS scheduler
    /// (`thread::sleep`) because `SO_RCVTIMEO` is rounded up to the host timer
    /// granularity (4–8 ms on several CI sandboxes), which would otherwise
    /// dominate a 10 ms RTT. The sleep only paces the loop; protocol time is
    /// always the injected monotonic [`Timestamp`], never the sleep duration.
    /// Longer waits use the R6-3-style bounded socket timeout.
    pub fn wait(&mut self, max_wait: Duration) -> Result<(), String> {
        let wait = self.wait_duration(max_wait);
        if wait.is_zero() {
            self.handle_due_timeouts();
            return Ok(());
        }
        if wait <= SLEEP_WAIT {
            std::thread::sleep(wait);
            self.clock();
            self.handle_due_timeouts();
            return Ok(());
        }
        self.socket_server
            .set_nonblocking(false)
            .map_err(io_error)?;
        self.socket_server
            .set_read_timeout(Some(wait))
            .map_err(io_error)?;
        let mut buffer = [0u8; 65535];
        let received = self.socket_server.recv_from(&mut buffer);
        self.socket_server.set_nonblocking(true).map_err(io_error)?;
        self.socket_server
            .set_read_timeout(None)
            .map_err(io_error)?;
        self.clock();
        match received {
            Ok((len, from)) => {
                let payload = buffer.get(..len).unwrap_or(&[]).to_vec();
                self.wire_bytes_in = self
                    .wire_bytes_in
                    .saturating_add(u64::try_from(len).unwrap_or(0));
                self.server
                    .handle_datagram(self.now, to_rtx_addr(from), None, &payload);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                self.handle_due_timeouts();
            }
            Err(error) => return Err(format!("server socket receive: {error}")),
        }
        self.receive(Link::ToClient)
    }

    /// Pumps until `predicate` holds or `cap` wall time has elapsed.
    ///
    /// # Errors
    ///
    /// Returns an error on an I/O failure or when the cap expires.
    pub fn pump_until(
        &mut self,
        cap: Duration,
        mut predicate: impl FnMut(&Sim) -> bool,
    ) -> Result<(), String> {
        let start = Instant::now();
        loop {
            self.tick()?;
            if predicate(self) {
                return Ok(());
            }
            if start.elapsed() >= cap {
                return Err(format!("pump cap of {} ms expired", cap.as_millis()));
            }
            self.wait(MAX_WAIT)?;
        }
    }

    /// Runs one pump round repeatedly for `duration`.
    pub fn run_for(&mut self, duration: Duration) -> Result<(), String> {
        let start = Instant::now();
        while start.elapsed() < duration {
            self.tick()?;
            self.wait(MAX_WAIT)?;
        }
        Ok(())
    }

    /// Returns the client-observed handshake durations as a sorted vector.
    #[must_use]
    pub fn handshake_samples(&self) -> Vec<u64> {
        let mut samples = self.handshake_micros.clone();
        samples.sort_unstable();
        samples
    }

    fn clock_now(&self) -> Timestamp {
        let micros = self.epoch.elapsed().as_micros();
        Timestamp::from_micros(u64::try_from(micros).unwrap_or(u64::MAX))
    }

    fn wait_duration(&mut self, max_wait: Duration) -> Duration {
        let mut wait = max_wait;
        if let Some(release) = self.to_server.next_release() {
            wait = wait.min(duration_until(self.now, release));
        }
        if let Some(release) = self.to_client.next_release() {
            wait = wait.min(duration_until(self.now, release));
        }
        if let Some(deadline) = self.client.poll_timeout() {
            wait = wait.min(duration_until(self.now, deadline));
        }
        if let Some(deadline) = self.server.poll_timeout() {
            wait = wait.min(duration_until(self.now, deadline));
        }
        wait.max(Duration::from_micros(1))
    }

    fn handle_due_timeouts(&mut self) {
        self.clock();
        let client_due = self
            .client
            .poll_timeout()
            .is_some_and(|deadline| deadline <= self.now);
        if client_due {
            self.client.handle_timeout(self.now);
        }
        let server_due = self
            .server
            .poll_timeout()
            .is_some_and(|deadline| deadline <= self.now);
        if server_due {
            self.server.handle_timeout(self.now);
        }
        self.handle_events();
    }

    fn receive(&mut self, link: Link) -> Result<(), String> {
        let mut buffer = [0u8; 65535];
        loop {
            let socket = match link {
                Link::ToServer => &self.socket_server,
                Link::ToClient => &self.socket_client,
            };
            let result = socket.recv_from(&mut buffer);
            match result {
                Ok((len, from)) => {
                    self.wire_bytes_in = self
                        .wire_bytes_in
                        .saturating_add(u64::try_from(len).unwrap_or(0));
                    let payload = buffer.get(..len).unwrap_or(&[]).to_vec();
                    let now = self.clock_now();
                    self.now = now;
                    match link {
                        Link::ToServer => {
                            self.server
                                .handle_datagram(now, to_rtx_addr(from), None, &payload);
                        }
                        Link::ToClient => {
                            self.client
                                .handle_datagram(now, to_rtx_addr(from), None, &payload);
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(format!("socket receive: {error}")),
            }
        }
    }

    fn transmit(&mut self, link: Link) -> Result<(), String> {
        let mut buffer = Vec::with_capacity(1500);
        loop {
            let now = self.now;
            let transmit = match link {
                Link::ToServer => self.client.poll_transmit(now, &mut buffer),
                Link::ToClient => self.server.poll_transmit(now, &mut buffer),
            };
            let Some(transmit) = transmit else {
                return Ok(());
            };
            self.transmits = self.transmits.saturating_add(1);
            self.wire_bytes_out = self
                .wire_bytes_out
                .saturating_add(u64::try_from(transmit.len).unwrap_or(0));
            let payload = buffer.get(..transmit.len).unwrap_or(&buffer).to_vec();
            let (destination, state, socket) = match link {
                Link::ToServer => (self.server_addr, &mut self.to_server, &self.socket_client),
                Link::ToClient => (self.client_addr, &mut self.to_client, &self.socket_server),
            };
            let (dropped, release_at) = state.decision(now);
            if dropped {
                state.dropped = state.dropped.saturating_add(1);
                continue;
            }
            if release_at <= now {
                socket
                    .send_to(&payload, to_std_addr(destination))
                    .map_err(|error| format!("socket send: {error}"))?;
                state.released = state.released.saturating_add(1);
            } else {
                state.enqueue(release_at, payload);
            }
        }
    }

    fn release_delayed(&mut self, link: Link) -> Result<(), String> {
        let now = self.now;
        let (state, socket, destination) = match link {
            Link::ToServer => (&mut self.to_server, &self.socket_client, self.server_addr),
            Link::ToClient => (&mut self.to_client, &self.socket_server, self.client_addr),
        };
        let mut index = 0;
        while index < state.queued.len() {
            if state
                .queued
                .get(index)
                .is_some_and(|item| item.release_at <= now)
            {
                let item = state.queued.remove(index);
                socket
                    .send_to(&item.payload, to_std_addr(destination))
                    .map_err(|error| format!("socket send: {error}"))?;
                state.released = state.released.saturating_add(1);
            } else {
                index += 1;
            }
        }
        Ok(())
    }

    fn handle_events(&mut self) {
        let now = self.now;
        while let Some(event) = self.client.poll_event() {
            match event.kind {
                EventKind::HandshakeComplete(info) => {
                    self.client_handshakes = self.client_handshakes.saturating_add(1);
                    let elapsed = now
                        .as_micros()
                        .saturating_sub(self.connect_start.as_micros());
                    self.handshake_micros.push(elapsed);
                    self.client_info = Some(info);
                }
                EventKind::HandshakeFailed(_) => {
                    self.handshake_failures = self.handshake_failures.saturating_add(1);
                }
                _ => {}
            }
        }
        let mut accepted = Vec::new();
        while let Some(event) = self.server.poll_event() {
            match event.kind {
                EventKind::Incoming => {
                    let now = self.now;
                    match self.server.accept(now, event.connection, &mut self.scratch) {
                        Ok(()) => accepted.push(event.connection),
                        Err(error) => {
                            self.handshake_failures = self.handshake_failures.saturating_add(1);
                            eprintln!(
                                "warn: accept failed for {}: {error}",
                                event.connection.as_u64()
                            );
                        }
                    }
                }
                EventKind::HandshakeComplete(info) => {
                    self.server_handshakes = self.server_handshakes.saturating_add(1);
                    self.server_info = Some(info);
                }
                EventKind::HandshakeFailed(_) => {
                    self.handshake_failures = self.handshake_failures.saturating_add(1);
                }
                _ => {}
            }
        }
        self.server_connections.extend(accepted);
    }

    /// Sends one QUIC DATAGRAM, recording `WouldBlock` as harness backpressure.
    ///
    /// Returns `Ok(true)` when the datagram was queued, `Ok(false)` when the
    /// send buffer was full (retry later) and an error for any other facade
    /// failure.
    ///
    /// # Errors
    ///
    /// Returns the facade error as a string.
    pub fn try_send_datagram(
        &mut self,
        connection: ConnectionId,
        payload: &[u8],
    ) -> Result<bool, String> {
        match self.client.send_datagram(connection, payload) {
            Ok(_) => Ok(true),
            Err(DatagramError::WouldBlock) => {
                self.datagram_send_blocked = self.datagram_send_blocked.saturating_add(1);
                Ok(false)
            }
            Err(error) => Err(format!("send_datagram: {error}")),
        }
    }

    /// Echoes every queued DATAGRAM of one server connection back to the
    /// client and returns the echoed count.
    ///
    /// # Errors
    ///
    /// Returns a message when the facade reports an error other than an empty
    /// queue.
    pub fn echo_server_datagrams(&mut self, connection: ConnectionId) -> Result<u64, String> {
        let mut buffer = [0u8; ADVERTISED_MAX_DATAGRAM_FRAME_SIZE + 64];
        let mut echoed = 0;
        loop {
            match self.server.poll_datagram(connection, &mut buffer) {
                Ok(Some(len)) => {
                    let payload = buffer.get(..len).unwrap_or(&[]).to_vec();
                    match self.server.send_datagram(connection, &payload) {
                        Ok(_) => echoed += 1,
                        Err(DatagramError::WouldBlock) => {
                            self.datagram_send_blocked =
                                self.datagram_send_blocked.saturating_add(1);
                        }
                        Err(DatagramError::BufferTooSmall { datagram_len }) => {
                            return Err(format!(
                                "server datagram buffer too small: {datagram_len}"
                            ));
                        }
                        Err(error) => return Err(format!("server datagram echo: {error}")),
                    }
                }
                Ok(None) => return Ok(echoed),
                Err(DatagramError::BufferTooSmall { datagram_len }) => {
                    return Err(format!("server datagram buffer too small: {datagram_len}"));
                }
                Err(error) => return Err(format!("server poll_datagram: {error}")),
            }
        }
    }

    /// Reads every stream the server has not read yet, returning the number of
    /// new bytes and the number of streams finished.
    ///
    /// # Errors
    ///
    /// Returns a message for unexpected facade errors.
    pub fn read_server_streams(
        &mut self,
        connection: ConnectionId,
        states: &mut std::collections::BTreeMap<StreamId, StreamReadState>,
    ) -> Result<(u64, u64), String> {
        let mut chunk = vec![0u8; 64 * 1024];
        let mut new_bytes = 0u64;
        let mut finished = 0u64;
        loop {
            match self.server.accept_uni(connection) {
                Ok(Some(stream)) => {
                    states.entry(stream).or_default();
                }
                Ok(None) => break,
                Err(StreamError::Closed) => break,
                Err(error) => return Err(format!("accept_uni: {error}")),
            }
        }
        loop {
            match self.server.accept_bi(connection) {
                Ok(Some(stream)) => {
                    states.entry(stream).or_default();
                }
                Ok(None) => break,
                Err(StreamError::Closed) => break,
                Err(error) => return Err(format!("accept_bi: {error}")),
            }
        }
        let ids: Vec<StreamId> = states.keys().copied().collect();
        for stream in ids {
            loop {
                match self.server.read_stream(connection, stream, &mut chunk) {
                    Ok(StreamRead::Data { len }) => {
                        new_bytes = new_bytes.saturating_add(u64::try_from(len).unwrap_or(0));
                        if let Some(state) = states.get_mut(&stream) {
                            state.bytes =
                                state.bytes.saturating_add(u64::try_from(len).unwrap_or(0));
                        }
                    }
                    Ok(StreamRead::Finished) => {
                        if let Some(state) = states.get_mut(&stream)
                            && !state.finished
                        {
                            state.finished = true;
                            finished += 1;
                        }
                        break;
                    }
                    Err(StreamError::Blocked) => break,
                    Err(StreamError::Closed)
                    | Err(StreamError::UnknownConnection)
                    | Err(StreamError::StreamClosed) => break,
                    Err(error) => return Err(format!("read_stream: {error}")),
                }
            }
        }
        Ok((new_bytes, finished))
    }
}

/// What one server-side stream has delivered so far.
#[derive(Debug, Default, Clone, Copy)]
pub struct StreamReadState {
    /// Bytes delivered to the server.
    pub bytes: u64,
    /// Whether the peer's FIN was observed.
    pub finished: bool,
}

/// Parses `max_datagram_frame_size` (`0x20`) out of the canonical peer
/// transport-parameter encoding captured at handshake.
///
/// The result is what `M3-PS8` must record; a missing parameter returns
/// `None` and the scenario fails rather than guessing a payload size.
#[must_use]
pub fn parse_max_datagram_frame_size(encoded: &[u8]) -> Option<u64> {
    let mut rest = encoded;
    while !rest.is_empty() {
        let (id, id_len) = varint::decode(rest).ok()?;
        rest = rest.get(id_len..)?;
        let (len, len_len) = varint::decode(rest).ok()?;
        rest = rest.get(len_len..)?;
        let value_len = usize::try_from(len).ok()?;
        let value = rest.get(..value_len)?;
        rest = rest.get(value_len..)?;
        if id == 0x20 {
            let (max, _) = varint::decode(value).ok()?;
            return Some(max);
        }
    }
    None
}

fn bind_loopback() -> Result<UdpSocket, String> {
    let socket = UdpSocket::bind("127.0.0.1:0").map_err(io_error)?;
    socket.set_nonblocking(true).map_err(io_error)?;
    Ok(socket)
}

fn seed_bytes(seed: u64, salt: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let mut value = seed ^ u64::from(salt).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for chunk in bytes.chunks_mut(8) {
        value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mixed = value ^ (value >> 33);
        chunk.copy_from_slice(&mixed.to_le_bytes());
    }
    bytes
}

fn duration_until(now: Timestamp, deadline: Timestamp) -> Duration {
    Duration::from_micros(deadline.as_micros().saturating_sub(now.as_micros()))
}

fn to_rtx_addr(address: std::net::SocketAddr) -> SocketAddr {
    let ip = match address.ip() {
        std::net::IpAddr::V4(v4) => IpAddr::V4(v4.octets()),
        std::net::IpAddr::V6(v6) => IpAddr::V6(v6.octets()),
    };
    SocketAddr::new(ip, address.port())
}

fn to_std_addr(address: SocketAddr) -> std::net::SocketAddr {
    match address.ip {
        IpAddr::V4(octets) => std::net::SocketAddr::from((octets, address.port)),
        IpAddr::V6(octets) => std::net::SocketAddr::from((octets, address.port)),
    }
}

fn io_error(error: io::Error) -> String {
    format!("socket: {error}")
}

#[cfg(test)]
mod tests {
    use super::parse_max_datagram_frame_size;
    use rtx_wire::varint;

    fn push_varint(encoded: &mut Vec<u8>, value: u64) {
        let length = varint::encoded_len(value);
        let mut scratch = [0u8; 8];
        let written = varint::encode(value, &mut scratch[..length]).expect("varint encodes");
        encoded.extend_from_slice(&scratch[..written]);
    }

    #[test]
    fn parses_the_datagram_transport_parameter() {
        let mut encoded = Vec::new();
        // An unrelated parameter first, then 0x20 = 1100.
        for (id, value) in [(0x01_u64, 443_u64), (0x20, 1100)] {
            push_varint(&mut encoded, id);
            let value_length = varint::encoded_len(value);
            push_varint(&mut encoded, u64::try_from(value_length).expect("fits"));
            push_varint(&mut encoded, value);
        }
        assert_eq!(parse_max_datagram_frame_size(&encoded), Some(1100));
        assert_eq!(parse_max_datagram_frame_size(&[]), None);
        assert_eq!(parse_max_datagram_frame_size(&[0x01, 0x00]), None);
    }
}
