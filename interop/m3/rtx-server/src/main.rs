//! R6-3 WebTransport-over-HTTP/3 **server harness** built on the `rtx-*` crates.
//!
//! Scope (M3-B pre-work; the Chrome matrix itself is R6-4):
//!
//! - one runnable server binary on `rtx-quic` + `rtx-h3` + `rtx-webtransport`
//!   (+ `rtx-wire` frame/varint headers), std-only, no Tokio, no socket task;
//! - the WebTransport subset the R6-2/R6-2b codecs provide: H3 control stream
//!   SETTINGS, extended CONNECT over a QPACK field section, the HTTP Datagram
//!   mapping, WebTransport data streams and the capsule protocol on the
//!   CONNECT stream;
//! - loopback evidence lives in `tests/loopback.rs`, which drives this binary
//!   with `quinn` + `web-transport-proto` (dev-dependencies only).
//!
//! The server owns no protocol codec: every varint, frame header, QPACK
//! representation, SETTINGS pair, capsule and quarter-stream-ID conversion
//! comes from `rtx-wire`, `rtx-h3` or `rtx-webtransport`. This file only
//! dispatches, logs and moves bytes.
//!
//! # Time model
//!
//! `rtx-quic` takes injected [`rtx_core::Timestamp`] values (monotonic
//! microseconds). This binary captures one `std::time::Instant` at start-up and
//! derives every timestamp from it. The wall clock is used only for the
//! `ts_ms=` prefix of log lines, never for protocol decisions. The pump waits
//! with a bounded `UdpSocket::set_read_timeout`; it never blocks in a sleep call
//! to advance a protocol state machine.
//!
//! # Logging
//!
//! One `ts_ms=<wall clock> event=<name> key=value ...` line per event, flushed
//! immediately. The log file path is a CLI argument (`--log`); the harness
//! never writes to a fixed repository path. The loopback test reads
//! `server_listening` from this file to discover the ephemeral UDP port.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rtx_core::{IpAddr, SocketAddr, Timestamp};
use rtx_h3::connect::{ConnectBuffers, ConnectRequest, ConnectResponse};
use rtx_h3::settings::{
    Settings, SETTINGS_ENABLE_CONNECT_PROTOCOL, SETTINGS_H3_DATAGRAM,
    SETTINGS_QPACK_BLOCKED_STREAMS, SETTINGS_QPACK_MAX_TABLE_CAPACITY,
    SETTINGS_WEBTRANSPORT_MAX_SESSIONS,
};
use rtx_quic::{
    ConnectionId, DatagramError, Endpoint, EndpointConfig, Event, EventKind, StreamError, StreamId,
    StreamRead, TransportConfig,
};
use rtx_webtransport::capsules::{Capsule, CapsuleError};
use rtx_webtransport::datagram;
use rtx_webtransport::ids::{QuarterStreamId, SessionId};
use rtx_wire::h3_frame::Frame;
use rtx_wire::varint::{self, VarInt};
use rtx_wire::{Decode, Encode};

/// H3 control stream (`RFC 9114` section 6.2.1).
const STREAM_CONTROL: u64 = 0x00;
/// H3 QPACK encoder stream (`RFC 9114` section 6.2.1).
const STREAM_QPACK_ENCODER: u64 = 0x02;
/// H3 QPACK decoder stream (`RFC 9114` section 6.2.1).
const STREAM_QPACK_DECODER: u64 = 0x03;
/// WebTransport unidirectional stream type (`draft-ietf-webtrans-http3-15`
/// section 4.2). The body is the type, the session ID, then the payload.
const STREAM_WEBTRANSPORT_UNI: u64 = 0x54;
/// H3 DATA frame (`RFC 9114` section 7.2.6). Capsules travel inside DATA
/// frames (`RFC 9297` section 3.2; see `web-transport-proto`'s
/// `Http3CapsuleReader` for the reference implementation).
const FRAME_DATA: u64 = 0x00;
/// H3 HEADERS frame (`RFC 9114` section 7.2.2).
const FRAME_HEADERS: u64 = 0x01;
/// H3 SETTINGS frame (`RFC 9114` section 7.2.4).
const FRAME_SETTINGS: u64 = 0x04;
/// WebTransport bidirectional stream signal value
/// (`draft-ietf-webtrans-http3-15` section 4.3). It is a frame *type* written
/// as the first bytes of the stream, followed by the session ID and payload.
const FRAME_WEBTRANSPORT_BI: u64 = 0x41;

/// `SETTINGS_H3_DATAGRAM_DEPRECATED`, still sent by Chrome (decode-only in
/// `rtx-h3`).
const SETTINGS_H3_DATAGRAM_DEPRECATED: u64 = 0xFF_D277;
/// `ENABLE_WEBTRANSPORT`, removed after `draft-ietf-webtrans-http3-06`
/// (decode-only).
const SETTINGS_WEBTRANSPORT_ENABLE_DEPRECATED: u64 = 0x2B60_3742;
/// The pre-draft-07 max-sessions identifier (decode-only).
const SETTINGS_WEBTRANSPORT_MAX_SESSIONS_DEPRECATED: u64 = 0x2B60_3743;

/// `max_datagram_frame_size` this harness advertises (TCP id `0x20`,
/// `RFC 9221` section 3). It is the receive-buffer budget of the facade's
/// `TransportConfig`, which `quinn-proto` copies verbatim into the transport
/// parameter. 1100 leaves room under quinn-proto's conservative DATAGRAM frame
/// overhead bound (17 bytes) and under the disabled-MTUD path budget, so a
/// full-size echo fits on both sides.
const ADVERTISED_MAX_DATAGRAM_FRAME_SIZE: usize = 1100;
/// Value advertised for `WEBTRANSPORT_MAX_SESSIONS` (`0xc671706a`). The number
/// 100 is a harness capacity choice (sequential + concurrent loopback
/// sessions), not a protocol requirement.
const WEBTRANSPORT_MAX_SESSIONS_VALUE: u64 = 100;
/// Payload length of the server-initiated unidirectional stream opened for
/// every established session (M3-B2's "server-initiated unidirectional
/// stream, 1 MiB").
const SERVER_UNI_PAYLOAD_LEN: usize = 1024 * 1024;
/// Bytes written on the server-initiated bidirectional stream before it is
/// reset (M3-B2's reset coverage).
const SERVER_RESET_PAYLOAD_LEN: usize = 4096;
/// Application error code used for the deliberate server reset.
const SERVER_RESET_CODE: u64 = 7;
/// `WT_SESSION_GONE` (`draft-ietf-webtrans-http3-15` section 8), used when a
/// session ends and its remaining server-initiated streams are abandoned.
const WT_SESSION_GONE_CODE: u64 = 0x52E4_A40F_A8DB;
/// `H3_SETTINGS_ERROR` (`RFC 9114` section 8.1).
const H3_SETTINGS_ERROR: u64 = 0x0101;

/// Largest capsule payload accepted on the CONNECT stream
/// (`web-transport-proto` uses the same 64 KiB reference bound).
const MAX_CAPSULE_PAYLOAD: usize = 64 * 1024;
/// Largest raw buffer kept per stream (1 MiB payloads plus headers fit).
const MAX_STREAM_BUFFER: usize = 4 * 1024 * 1024;
/// Read chunk size passed to the facade.
const READ_CHUNK: usize = 64 * 1024;
/// Longest socket wait between pump rounds.
const MAX_WAIT: Duration = Duration::from_millis(50);
/// Deterministic payload: the `0..255` cycle repeated.
const PATTERN_PERIOD: usize = 256;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rtx-wt-server: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse()?;

    let certificate_der = read_der(&args.cert_chain_der, "certificate chain")?;
    let private_key_der = read_der(&args.key_der, "private key")?;

    let mut log = Log::open(&args.log)
        .map_err(|error| format!("cannot open log file {}: {error}", args.log.display()))?;

    let transport = TransportConfig {
        datagram_receive_buffer_bytes: Some(ADVERTISED_MAX_DATAGRAM_FRAME_SIZE),
        ..TransportConfig::default()
    };
    let config = EndpointConfig::new()
        .with_alpn(vec![b"h3".to_vec()])
        .with_transport(transport)
        .with_server_identity(vec![certificate_der], private_key_der);

    let endpoint = match Endpoint::new(config) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            log.line(format!("event=config_error error={error}"));
            return Err(format!("invalid endpoint configuration: {error}"));
        }
    };

    let socket = match UdpSocket::bind(args.bind) {
        Ok(socket) => socket,
        Err(error) => {
            log.line(format!("event=bind_error addr={} error={error}", args.bind));
            return Err(format!("cannot bind {}: {error}", args.bind));
        }
    };
    let local = socket
        .local_addr()
        .map_err(|error| format!("cannot read the bound address: {error}"))?;

    log.line(format!("event=server_listening addr={local} alpn=h3"));
    log.line(format!(
        "event=config_loaded max_datagram_frame_size_advertised={ADVERTISED_MAX_DATAGRAM_FRAME_SIZE} webtransport_max_sessions={WEBTRANSPORT_MAX_SESSIONS_VALUE} server_uni_payload_bytes={SERVER_UNI_PAYLOAD_LEN} server_reset_payload_bytes={SERVER_RESET_PAYLOAD_LEN}"
    ));

    let mut server = Server {
        endpoint,
        socket,
        log,
        epoch: Instant::now(),
        connections: BTreeMap::new(),
    };
    server.run()
}

/// One parsed CLI invocation.
#[derive(Debug)]
struct Args {
    bind: std::net::SocketAddr,
    cert_chain_der: PathBuf,
    key_der: PathBuf,
    log: PathBuf,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut bind = None;
        let mut cert_chain_der = None;
        let mut key_der = None;
        let mut log = None;
        let mut arguments = std::env::args().skip(1);
        while let Some(argument) = arguments.next() {
            let slot = match argument.as_str() {
                "--bind" => &mut bind,
                "--cert-chain-der" => &mut cert_chain_der,
                "--key-der" => &mut key_der,
                "--log" => &mut log,
                other => return Err(format!("unknown argument {other}")),
            };
            let value = arguments
                .next()
                .ok_or_else(|| format!("missing value for {argument}"))?;
            *slot = Some(value);
        }

        let bind = match bind {
            Some(value) => value
                .parse()
                .map_err(|error| format!("invalid --bind address {value:?}: {error}"))?,
            None => std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        };
        Ok(Self {
            bind,
            cert_chain_der: PathBuf::from(cert_chain_der.ok_or("--cert-chain-der is required")?),
            key_der: PathBuf::from(key_der.ok_or("--key-der is required")?),
            log: PathBuf::from(log.ok_or("--log is required")?),
        })
    }
}

/// Reads one DER file and refuses PEM input explicitly (the CLI contract is
/// DER only; the harness never embeds key material).
fn read_der(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read {label} {}: {error}", path.display()))?;
    if bytes.starts_with(b"-----BEGIN") {
        return Err(format!(
            "{label} {} is PEM-encoded; only DER is accepted",
            path.display()
        ));
    }
    if bytes.is_empty() {
        return Err(format!("{label} {} is empty", path.display()));
    }
    Ok(bytes)
}

/// Structured `event=` logger. Wall clock appears only in `ts_ms=`.
#[derive(Debug)]
struct Log {
    file: io::BufWriter<fs::File>,
}

impl Log {
    fn open(path: &Path) -> io::Result<Self> {
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            file: io::BufWriter::new(file),
        })
    }

    fn line(&mut self, message: impl fmt::Display) {
        let _ = writeln!(self.file, "ts_ms={} {message}", wall_clock_millis());
        let _ = self.file.flush();
    }
}

fn wall_clock_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

/// The harness process. One socket, one sans-I/O endpoint, one log, one
/// monotonic epoch.
#[derive(Debug)]
struct Server {
    endpoint: Endpoint,
    socket: UdpSocket,
    log: Log,
    epoch: Instant,
    connections: BTreeMap<ConnectionId, ConnState>,
}

impl Server {
    fn run(&mut self) -> Result<(), String> {
        let mut receive_buffer = vec![0u8; 65535];
        let mut transmit_buffer = Vec::with_capacity(READ_CHUNK);

        loop {
            let now = self.now();
            self.drain_transmits(now, &mut transmit_buffer);
            while let Some(event) = self.endpoint.poll_event() {
                self.handle_event(event);
            }

            let ids: Vec<ConnectionId> = self.connections.keys().copied().collect();
            for id in ids {
                self.service_connection(id);
            }

            let now = self.now();
            self.drain_transmits(now, &mut transmit_buffer);

            let deadline = self.endpoint.poll_timeout();
            let wait = wait_duration(now, deadline);
            self.socket
                .set_read_timeout(Some(wait))
                .map_err(|error| format!("cannot set the socket read timeout: {error}"))?;

            match self.socket.recv_from(&mut receive_buffer) {
                Ok((len, remote)) => {
                    let now = self.now();
                    self.endpoint.handle_datagram(
                        now,
                        to_rtx_addr(remote),
                        None,
                        &receive_buffer[..len],
                    );
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    let now = self.now();
                    if let Some(deadline) = deadline {
                        if deadline <= now {
                            self.endpoint.handle_timeout(now);
                        }
                    }
                }
                Err(error) => {
                    self.log
                        .line(format!("event=udp_receive_error error={error}"));
                    return Err(format!("UDP receive failed: {error}"));
                }
            }
        }
    }

    /// Monotonic microseconds from the process epoch; the only time source
    /// given to the facade.
    fn now(&self) -> Timestamp {
        let micros = self.epoch.elapsed().as_micros();
        Timestamp::from_micros(u64::try_from(micros).unwrap_or(u64::MAX))
    }

    fn drain_transmits(&mut self, now: Timestamp, buffer: &mut Vec<u8>) {
        while let Some(transmit) = self.endpoint.poll_transmit(now, buffer) {
            let destination = to_std_addr(transmit.destination);
            if let Err(error) = self.socket.send_to(&buffer[..transmit.len], destination) {
                self.log.line(format!(
                    "event=udp_send_error destination={destination} error={error}"
                ));
            }
        }
    }

    fn handle_event(&mut self, event: Event) {
        let connection = event.connection;
        match event.kind {
            EventKind::Incoming => {
                let mut buffer = Vec::new();
                match self.endpoint.accept(self.now(), connection, &mut buffer) {
                    Ok(()) => {
                        self.connections.insert(connection, ConnState::default());
                        self.log.line(format!(
                            "event=quic_connection_accepted connection={}",
                            connection.as_u64()
                        ));
                    }
                    Err(error) => self.log.line(format!(
                        "event=quic_accept_failed connection={} error={error}",
                        connection.as_u64()
                    )),
                }
            }
            EventKind::HandshakeComplete(info) => {
                let peer_max_datagram_frame_size =
                    parse_max_datagram_frame_size(info.peer_transport_parameters.as_bytes());
                let datagram_supported = info.datagram_supported;
                if let Some(state) = self.connections.get_mut(&connection) {
                    state.peer_max_datagram_frame_size = peer_max_datagram_frame_size
                        .map(|value| usize::try_from(value).unwrap_or(usize::MAX));
                }
                self.log.line(format!(
                    "event=quic_handshake_complete connection={} alpn={:?} datagram_supported={} peer_max_datagram_frame_size={}",
                    connection.as_u64(),
                    info.alpn,
                    datagram_supported,
                    peer_max_datagram_frame_size.map_or_else(|| "absent".to_string(), |value| value.to_string()),
                ));
            }
            EventKind::HandshakeFailed(failure) => self.log.line(format!(
                "event=quic_handshake_failed connection={} reason={failure:?}",
                connection.as_u64()
            )),
            EventKind::Stream(rtx_quic::StreamEvent::Stopped { stream, error_code }) => {
                self.log.line(format!(
                    "event=stream_stopped connection={} stream={} code={error_code}",
                    connection.as_u64(),
                    stream.as_u64()
                ));
            }
            EventKind::DatagramReceived => {}
            EventKind::Closed(reason) => {
                self.connections.remove(&connection);
                self.log.line(format!(
                    "event=connection_close connection={} reason={}",
                    connection.as_u64(),
                    CloseReasonText(&reason)
                ));
            }
            _ => {}
        }
    }

    fn service_connection(&mut self, connection: ConnectionId) {
        let Some(mut state) = self.connections.remove(&connection) else {
            return;
        };
        let now = self.now();
        state.service(connection, now, &mut self.endpoint, &mut self.log);
        self.connections.insert(connection, state);
    }
}

/// One accepted QUIC connection and its H3/WebTransport state.
#[derive(Debug, Default)]
struct ConnState {
    peer_max_datagram_frame_size: Option<usize>,
    settings_received: bool,
    server_settings_sent: bool,
    control_stream: Option<StreamId>,
    streams: BTreeMap<u64, StreamState>,
    sessions: BTreeMap<u64, SessionState>,
    datagrams_received: u64,
    datagrams_echoed: u64,
    closing: bool,
}

#[derive(Debug)]
struct SessionState {
    session: SessionId,
    drained: bool,
}

impl ConnState {
    fn service(
        &mut self,
        connection: ConnectionId,
        now: Timestamp,
        endpoint: &mut Endpoint,
        log: &mut Log,
    ) {
        if self.closing {
            return;
        }
        self.accept_new_streams(connection, endpoint, log);
        self.read_streams(connection, endpoint, log);
        self.process_streams(connection, now, endpoint, log);
        self.poll_datagrams(connection, endpoint, log);
        self.flush_writes(connection, endpoint, log);
    }

    fn accept_new_streams(
        &mut self,
        connection: ConnectionId,
        endpoint: &mut Endpoint,
        log: &mut Log,
    ) {
        loop {
            match endpoint.accept_uni(connection) {
                Ok(Some(stream)) => {
                    log.line(format!(
                        "event=stream_opened connection={} stream={} kind=uni role=client",
                        connection.as_u64(),
                        stream.as_u64()
                    ));
                    self.streams
                        .insert(stream.as_u64(), StreamState::new(stream, Role::UniProbe));
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        loop {
            match endpoint.accept_bi(connection) {
                Ok(Some(stream)) => {
                    log.line(format!(
                        "event=stream_opened connection={} stream={} kind=bi role=client",
                        connection.as_u64(),
                        stream.as_u64()
                    ));
                    self.streams
                        .insert(stream.as_u64(), StreamState::new(stream, Role::BiProbe));
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
    }

    fn read_streams(&mut self, connection: ConnectionId, endpoint: &mut Endpoint, log: &mut Log) {
        let ids: Vec<u64> = self.streams.keys().copied().collect();
        let mut chunk = vec![0u8; READ_CHUNK];
        for id in ids {
            let Some(state) = self.streams.get_mut(&id) else {
                continue;
            };
            if state.finished || state.peer_fin {
                continue;
            }
            // Server-initiated streams have no receive direction this harness
            // reads (the reset stream's peer half is unused).
            if matches!(
                state.role,
                Role::ServerOther | Role::ServerAutoUni { .. } | Role::ServerAutoBiReset { .. }
            ) {
                continue;
            }
            loop {
                match endpoint.read_stream(connection, state.id, &mut chunk) {
                    Ok(StreamRead::Data { len }) => {
                        state.in_buf.extend_from_slice(&chunk[..len]);
                        if state.in_buf.len() > MAX_STREAM_BUFFER {
                            log.line(format!(
                                "event=stream_buffer_overflow connection={} stream={} bytes={}",
                                connection.as_u64(),
                                state.id.as_u64(),
                                state.in_buf.len()
                            ));
                            state.finished = true;
                            let _ = endpoint.stop_sending(connection, state.id, 0);
                            break;
                        }
                    }
                    Ok(StreamRead::Finished) => {
                        state.peer_fin = true;
                        break;
                    }
                    Err(StreamError::Blocked) => break,
                    Err(StreamError::ResetByPeer { error_code }) => {
                        log.line(format!(
                            "event=stream_reset connection={} stream={} role=client direction={} code={error_code}",
                            connection.as_u64(),
                            state.id.as_u64(),
                            direction_name(state.id),
                        ));
                        state.finished = true;
                        break;
                    }
                    Err(StreamError::Closed)
                    | Err(StreamError::UnknownConnection)
                    | Err(StreamError::StreamClosed) => {
                        state.finished = true;
                        break;
                    }
                    Err(error) => {
                        log.line(format!(
                            "event=stream_read_error connection={} stream={} error={error}",
                            connection.as_u64(),
                            state.id.as_u64()
                        ));
                        state.finished = true;
                        break;
                    }
                }
            }
        }
    }

    fn process_streams(
        &mut self,
        connection: ConnectionId,
        now: Timestamp,
        endpoint: &mut Endpoint,
        log: &mut Log,
    ) {
        let ids: Vec<u64> = self.streams.keys().copied().collect();
        for id in ids {
            let action = self.advance_stream(connection, id, log);
            self.apply_action(connection, now, id, action, endpoint, log);
        }
    }

    /// Consumes complete units from one stream and returns the side effect the
    /// stream needs from the connection.
    fn advance_stream(&mut self, connection: ConnectionId, id: u64, log: &mut Log) -> StreamAction {
        loop {
            let Some(state) = self.streams.get_mut(&id) else {
                return StreamAction::None;
            };
            if state.finished {
                return StreamAction::None;
            }
            match state.role {
                Role::UniProbe => match varint::decode(&state.in_buf) {
                    Ok((stream_type, consumed)) => {
                        state.in_buf.drain(..consumed);
                        match stream_type {
                            STREAM_CONTROL => {
                                state.role = Role::ClientControl;
                                log.line(format!(
                                    "event=stream_classified connection={} stream={} kind=uni role=control",
                                    connection.as_u64(),
                                    state.id.as_u64()
                                ));
                            }
                            STREAM_QPACK_ENCODER | STREAM_QPACK_DECODER => {
                                state.role = Role::QpackDrain;
                                log.line(format!(
                                    "event=stream_classified connection={} stream={} kind=uni role={}",
                                    connection.as_u64(),
                                    state.id.as_u64(),
                                    if stream_type == STREAM_QPACK_ENCODER {
                                        "qpack_encoder"
                                    } else {
                                        "qpack_decoder"
                                    }
                                ));
                            }
                            STREAM_WEBTRANSPORT_UNI => {
                                state.role = Role::WtUniPendingSession;
                                log.line(format!(
                                    "event=wt_stream_opened connection={} stream={} kind=uni",
                                    connection.as_u64(),
                                    state.id.as_u64()
                                ));
                            }
                            other => {
                                state.role = Role::OtherUni;
                                state.in_buf.clear();
                                log.line(format!(
                                    "event=uni_stream_unknown_type connection={} stream={} stream_type=0x{other:x} ignored=true",
                                    connection.as_u64(),
                                    state.id.as_u64()
                                ));
                                return StreamAction::None;
                            }
                        }
                        continue;
                    }
                    Err(_) => {
                        if state.peer_fin {
                            state.finished = true;
                            log.line(format!(
                                "event=stream_malformed connection={} stream={} reason=truncated_stream_type",
                                connection.as_u64(),
                                state.id.as_u64()
                            ));
                        }
                        return StreamAction::None;
                    }
                },
                Role::BiProbe => match varint::decode(&state.in_buf) {
                    Ok((frame_type, _)) if frame_type == FRAME_HEADERS => {
                        state.role = Role::Connect { session: None };
                        log.line(format!(
                            "event=stream_classified connection={} stream={} kind=bi role=connect_request",
                            connection.as_u64(),
                            state.id.as_u64()
                        ));
                        continue;
                    }
                    Ok((FRAME_WEBTRANSPORT_BI, consumed)) => {
                        state.in_buf.drain(..consumed);
                        state.role = Role::WtBiPendingSession;
                        log.line(format!(
                            "event=wt_stream_opened connection={} stream={} kind=bi",
                            connection.as_u64(),
                            state.id.as_u64()
                        ));
                        continue;
                    }
                    Ok((frame_type, _)) => {
                        state.role = Role::OtherUni;
                        state.in_buf.clear();
                        log.line(format!(
                            "event=bi_stream_unknown_type connection={} stream={} frame_type=0x{frame_type:x} ignored=true",
                            connection.as_u64(),
                            state.id.as_u64()
                        ));
                        return StreamAction::None;
                    }
                    Err(_) => {
                        if state.peer_fin {
                            state.finished = true;
                            log.line(format!(
                                "event=stream_malformed connection={} stream={} reason=truncated_stream_type",
                                connection.as_u64(),
                                state.id.as_u64()
                            ));
                        }
                        return StreamAction::None;
                    }
                },
                Role::ClientControl => {
                    let mut settings = None;
                    loop {
                        match Frame::decode(&state.in_buf) {
                            Ok((frame, consumed)) => {
                                let frame_type = frame.frame_type().get();
                                let payload = frame.payload().to_vec();
                                state.in_buf.drain(..consumed);
                                if frame_type == FRAME_SETTINGS {
                                    if self.settings_received {
                                        log.line(format!(
                                            "event=h3_settings_duplicate connection={} ignored=true",
                                            connection.as_u64()
                                        ));
                                    } else {
                                        self.settings_received = true;
                                        settings = Some(payload);
                                    }
                                } else {
                                    log.line(format!(
                                        "event=h3_control_frame_ignored connection={} frame_type=0x{frame_type:x}",
                                        connection.as_u64()
                                    ));
                                }
                            }
                            Err(rtx_wire::WireError::UnexpectedEnd) => break,
                            Err(error) => {
                                state.finished = true;
                                log.line(format!(
                                    "event=stream_malformed connection={} stream={} reason=control_frame error={error:?}",
                                    connection.as_u64(),
                                    state.id.as_u64()
                                ));
                                return StreamAction::None;
                            }
                        }
                    }
                    if let Some(payload) = settings {
                        return StreamAction::ClientSettings(payload);
                    }
                    return StreamAction::None;
                }
                Role::QpackDrain | Role::OtherUni | Role::ServerOther => {
                    state.in_buf.clear();
                    if state.peer_fin {
                        state.finished = true;
                    }
                    return StreamAction::None;
                }
                Role::WtUniPendingSession | Role::WtBiPendingSession => {
                    let value = match varint::decode(&state.in_buf) {
                        Ok((value, consumed)) => {
                            state.in_buf.drain(..consumed);
                            value
                        }
                        Err(_) => {
                            if state.peer_fin {
                                state.finished = true;
                                log.line(format!(
                                    "event=stream_malformed connection={} stream={} reason=truncated_session_id",
                                    connection.as_u64(),
                                    state.id.as_u64()
                                ));
                            }
                            return StreamAction::None;
                        }
                    };
                    let session = match SessionId::new(value) {
                        Ok(session) => session,
                        Err(error) => {
                            state.finished = true;
                            log.line(format!(
                                "event=stream_malformed connection={} stream={} reason=invalid_session_id error={error:?}",
                                connection.as_u64(),
                                state.id.as_u64()
                            ));
                            return StreamAction::None;
                        }
                    };
                    if !self.sessions.contains_key(&value) {
                        state.role = Role::OtherUni;
                        state.in_buf.clear();
                        log.line(format!(
                            "event=wt_stream_unknown_session connection={} stream={} session={}",
                            connection.as_u64(),
                            state.id.as_u64(),
                            session.get()
                        ));
                        return StreamAction::None;
                    }
                    state.role = if matches!(state.role, Role::WtUniPendingSession) {
                        Role::WtUni { session }
                    } else {
                        Role::WtBi { session }
                    };
                    continue;
                }
                Role::WtUni { session } => {
                    if state.peer_fin {
                        state.finished = true;
                        let payload = std::mem::take(&mut state.in_buf);
                        log.line(format!(
                            "event=stream_finished connection={} stream={} role=client direction=uni bytes={}",
                            connection.as_u64(),
                            state.id.as_u64(),
                            payload.len()
                        ));
                        return StreamAction::EchoUni { session, payload };
                    }
                    return StreamAction::None;
                }
                Role::WtBi { session } => {
                    if state.peer_fin {
                        state.finished = true;
                        let payload = std::mem::take(&mut state.in_buf);
                        log.line(format!(
                            "event=stream_finished connection={} stream={} role=client direction=bi bytes={}",
                            connection.as_u64(),
                            state.id.as_u64(),
                            payload.len()
                        ));
                        return StreamAction::EchoBi { session, payload };
                    }
                    return StreamAction::None;
                }
                Role::Connect { .. } => {
                    loop {
                        match Frame::decode(&state.in_buf) {
                            Ok((frame, consumed)) => {
                                let frame_type = frame.frame_type().get();
                                let payload = frame.payload().to_vec();
                                state.in_buf.drain(..consumed);
                                match frame_type {
                                    FRAME_HEADERS => {
                                        if state.connect_headers_seen {
                                            log.line(format!(
                                                "event=h3_connect_frame_ignored connection={} stream={} frame_type=0x01",
                                                connection.as_u64(),
                                                state.id.as_u64()
                                            ));
                                        } else {
                                            state.connect_headers_seen = true;
                                            return StreamAction::ConnectHeaders(payload);
                                        }
                                    }
                                    FRAME_DATA => {
                                        if state.capsule_buf.len() + payload.len()
                                            > MAX_CAPSULE_PAYLOAD
                                        {
                                            state.capsule_buf.clear();
                                            log.line(format!(
                                                "event=connect_capsule_buffer_overflow connection={} stream={}",
                                                connection.as_u64(),
                                                state.id.as_u64()
                                            ));
                                        } else {
                                            state.capsule_buf.extend_from_slice(&payload);
                                            return StreamAction::Capsules;
                                        }
                                    }
                                    other => log.line(format!(
                                        "event=h3_connect_frame_ignored connection={} stream={} frame_type=0x{other:x}",
                                        connection.as_u64(),
                                        state.id.as_u64()
                                    )),
                                }
                            }
                            Err(rtx_wire::WireError::UnexpectedEnd) => break,
                            Err(error) => {
                                state.finished = true;
                                log.line(format!(
                                    "event=stream_malformed connection={} stream={} reason=connect_frame error={error:?}",
                                    connection.as_u64(),
                                    state.id.as_u64()
                                ));
                                return StreamAction::None;
                            }
                        }
                    }
                    if state.peer_fin {
                        return StreamAction::ConnectFin;
                    }
                    return StreamAction::None;
                }
                Role::ServerAutoUni { .. } | Role::ServerAutoBiReset { .. } => {
                    return StreamAction::None;
                }
            }
        }
    }

    fn apply_action(
        &mut self,
        connection: ConnectionId,
        now: Timestamp,
        id: u64,
        action: StreamAction,
        endpoint: &mut Endpoint,
        log: &mut Log,
    ) {
        match action {
            StreamAction::None => {}
            StreamAction::ClientSettings(payload) => {
                self.handle_client_settings(connection, now, payload, endpoint, log);
            }
            StreamAction::ConnectHeaders(payload) => {
                self.handle_connect_headers(connection, id, payload, endpoint, log);
            }
            StreamAction::Capsules => {
                self.handle_capsules(connection, id, log);
            }
            StreamAction::ConnectFin => {
                self.handle_connect_fin(connection, id, log);
            }
            StreamAction::EchoUni { session, payload } => {
                self.queue_echo_uni(connection, session, payload, endpoint, log);
            }
            StreamAction::EchoBi { session, payload } => {
                self.queue_echo_bi(connection, id, session, payload, log);
            }
        }
    }

    fn handle_client_settings(
        &mut self,
        connection: ConnectionId,
        now: Timestamp,
        payload: Vec<u8>,
        endpoint: &mut Endpoint,
        log: &mut Log,
    ) {
        let settings = match Settings::decode(&payload) {
            Ok(settings) => settings,
            Err(error) => {
                log.line(format!(
                    "event=h3_settings_frame_rejected connection={} error={error:?}",
                    connection.as_u64()
                ));
                self.request_close(
                    connection,
                    now,
                    H3_SETTINGS_ERROR,
                    b"malformed SETTINGS",
                    endpoint,
                    log,
                );
                return;
            }
        };

        log.line(format!(
            "event=h3_settings_frame_received connection={} payload_bytes={} items={}",
            connection.as_u64(),
            payload.len(),
            settings.len()
        ));
        for setting in settings.iter() {
            let class = classify_setting(setting.id());
            let ignored = matches!(class, "grease" | "unknown" | "deprecated");
            log.line(format!(
                "event=h3_setting connection={} id=0x{:x} value={} class={} ignored={ignored}",
                connection.as_u64(),
                setting.id(),
                setting.value(),
                class
            ));
        }

        // R6-4 relaxation (see README "R6-4 客户端 QPACK 容量声明放宽"):
        // RFC 9114 section 7.2.4.1 makes these values a statement about the
        // *peer's* QPACK decoder capacity, not a requirement on this encoder.
        // This encoder emits static table references and non-Huffman literals
        // only (`encode_fields`), which is legal under any peer capacity; this
        // decoder still rejects every actual dynamic-table reference it sees.
        log.line(format!(
            "event=h3_client_qpack_capacity connection={} max_table_capacity={} blocked_streams={} max_field_section_size={}",
            connection.as_u64(),
            settings.qpack_max_table_capacity().unwrap_or(0),
            settings.qpack_blocked_streams().unwrap_or(0),
            settings
                .max_field_section_size()
                .map_or_else(|| "absent".to_string(), |value| value.to_string()),
        ));

        self.send_server_settings(connection, endpoint, log);
    }

    fn send_server_settings(
        &mut self,
        connection: ConnectionId,
        endpoint: &mut Endpoint,
        log: &mut Log,
    ) {
        if self.server_settings_sent {
            return;
        }
        self.server_settings_sent = true;

        let settings = server_settings();
        let encoded_len = settings.encoded_len();
        let mut payload = vec![0u8; encoded_len];
        if let Err(error) = settings.encode(&mut payload) {
            log.line(format!(
                "event=server_settings_encode_failed connection={} error={error:?}",
                connection.as_u64()
            ));
            return;
        }
        let frame = Frame::new(
            VarInt::new(FRAME_SETTINGS).expect("SETTINGS frame type fits a varint"),
            &payload,
        );
        let frame_len = frame.encoded_len();
        let mut bytes = vec![0u8; 1 + frame_len];
        if let Err(error) = varint::encode(STREAM_CONTROL, &mut bytes) {
            log.line(format!(
                "event=server_settings_encode_failed connection={} error={error:?}",
                connection.as_u64()
            ));
            return;
        }
        let mut scratch = vec![0u8; frame_len];
        if let Err(error) = frame.encode(&mut scratch) {
            log.line(format!(
                "event=server_settings_encode_failed connection={} error={error:?}",
                connection.as_u64()
            ));
            return;
        }
        bytes[1..].copy_from_slice(&scratch);

        match endpoint.open_uni(connection) {
            Ok(stream) => {
                let mut state = StreamState::new(stream, Role::ServerOther);
                state.out_buf = bytes;
                self.control_stream = Some(stream);
                self.streams.insert(stream.as_u64(), state);
                log.line(format!(
                    "event=server_settings_sent connection={} control_stream={} items={} payload_bytes={} frame_bytes={}",
                    connection.as_u64(),
                    stream.as_u64(),
                    settings.len(),
                    payload.len(),
                    frame_len
                ));
                for setting in settings.iter() {
                    log.line(format!(
                        "event=server_setting connection={} id=0x{:x} value={}",
                        connection.as_u64(),
                        setting.id(),
                        setting.value()
                    ));
                }
            }
            Err(error) => log.line(format!(
                "event=server_settings_send_failed connection={} error={error}",
                connection.as_u64()
            )),
        }
    }

    fn handle_connect_headers(
        &mut self,
        connection: ConnectionId,
        id: u64,
        payload: Vec<u8>,
        endpoint: &mut Endpoint,
        log: &mut Log,
    ) {
        let mut scheme = [0u8; 256];
        let mut authority = [0u8; 256];
        let mut path = [0u8; 256];
        let mut protocol = [0u8; 64];
        let buffers = ConnectBuffers::new(&mut scheme, &mut authority, &mut path, &mut protocol);
        let request = match ConnectRequest::decode(&payload, buffers) {
            Ok(request) => request,
            Err(error) => {
                log.line(format!(
                    "event=connect_request_rejected connection={} stream={} reason=decode_failed error={error:?}",
                    connection.as_u64(),
                    id
                ));
                self.queue_connect_response(connection, id, 400, log);
                return;
            }
        };

        if request.protocol() != "webtransport" {
            log.line(format!(
                "event=connect_request_rejected connection={} stream={} reason=wrong_protocol protocol={:?}",
                connection.as_u64(),
                id,
                request.protocol()
            ));
            self.queue_connect_response(connection, id, 400, log);
            return;
        }

        let session = match SessionId::new(id) {
            Ok(session) => session,
            Err(error) => {
                log.line(format!(
                    "event=connect_request_rejected connection={} stream={} reason=invalid_session_id error={error:?}",
                    connection.as_u64(),
                    id
                ));
                self.queue_connect_response(connection, id, 400, log);
                return;
            }
        };

        log.line(format!(
            "event=connect_request_decoded connection={} session={} stream={} scheme={} authority={} path={} protocol={}",
            connection.as_u64(),
            session.get(),
            id,
            request.scheme(),
            request.authority(),
            request.path(),
            request.protocol()
        ));

        if !self.streams.contains_key(&id) {
            log.line(format!(
                "event=connect_request_rejected connection={} stream={} reason=unknown_stream",
                connection.as_u64(),
                id
            ));
            return;
        }
        self.sessions.insert(
            id,
            SessionState {
                session,
                drained: false,
            },
        );
        if let Some(state) = self.streams.get_mut(&id) {
            state.role = Role::Connect {
                session: Some(session),
            };
        }

        self.queue_connect_response(connection, id, 200, log);
        self.open_auto_streams(connection, session, endpoint, log);
    }

    /// Queues a HEADERS frame carrying `:status <status>` on the CONNECT
    /// stream's send side.
    fn queue_connect_response(
        &mut self,
        connection: ConnectionId,
        id: u64,
        status: u16,
        log: &mut Log,
    ) {
        let response = match ConnectResponse::new(status) {
            Ok(response) => response,
            Err(error) => {
                log.line(format!(
                    "event=response_encode_failed connection={} stream={} error={error:?}",
                    connection.as_u64(),
                    id
                ));
                return;
            }
        };
        let qpack_len = response.encoded_len();
        let mut qpack = vec![0u8; qpack_len];
        if let Err(error) = response.encode(&mut qpack) {
            log.line(format!(
                "event=response_encode_failed connection={} stream={} error={error:?}",
                connection.as_u64(),
                id
            ));
            return;
        }
        let frame = Frame::new(
            VarInt::new(FRAME_HEADERS).expect("HEADERS frame type fits a varint"),
            &qpack,
        );
        let frame_len = frame.encoded_len();
        let mut bytes = vec![0u8; frame_len];
        if let Err(error) = frame.encode(&mut bytes) {
            log.line(format!(
                "event=response_encode_failed connection={} stream={} error={error:?}",
                connection.as_u64(),
                id
            ));
            return;
        }

        if let Some(state) = self.streams.get_mut(&id) {
            state.out_buf.extend_from_slice(&bytes);
            if status != 200 {
                state.out_finish = true;
                state.finished = true;
            }
            log.line(format!(
                "event=response_headers_sent connection={} session={} stream={} status={status} qpack_bytes={} frame_bytes={}",
                connection.as_u64(),
                id,
                id,
                qpack_len,
                frame_len
            ));
        }
    }

    /// Opens the two server-initiated streams every session gets in this
    /// harness: a 1 MiB unidirectional stream (M3-B2) and a bidirectional
    /// stream that is reset after a short deterministic prefix (M3-B2 reset
    /// coverage).
    fn open_auto_streams(
        &mut self,
        connection: ConnectionId,
        session: SessionId,
        endpoint: &mut Endpoint,
        log: &mut Log,
    ) {
        match endpoint.open_uni(connection) {
            Ok(stream) => {
                let mut state = StreamState::new(stream, Role::ServerAutoUni { session });
                push_varint(&mut state.out_buf, STREAM_WEBTRANSPORT_UNI);
                push_varint(&mut state.out_buf, session.get());
                state
                    .out_buf
                    .extend_from_slice(&pattern(SERVER_UNI_PAYLOAD_LEN));
                state.out_finish = true;
                self.streams.insert(stream.as_u64(), state);
                log.line(format!(
                    "event=stream_opened connection={} session={} stream={} kind=uni role=server bytes={SERVER_UNI_PAYLOAD_LEN}",
                    connection.as_u64(),
                    session.get(),
                    stream.as_u64()
                ));
            }
            Err(error) => log.line(format!(
                "event=server_uni_open_failed connection={} session={} error={error}",
                connection.as_u64(),
                session.get()
            )),
        }

        match endpoint.open_bi(connection) {
            Ok(stream) => {
                let mut state = StreamState::new(stream, Role::ServerAutoBiReset { session });
                push_varint(&mut state.out_buf, FRAME_WEBTRANSPORT_BI);
                push_varint(&mut state.out_buf, session.get());
                state
                    .out_buf
                    .extend_from_slice(&pattern(SERVER_RESET_PAYLOAD_LEN));
                state.out_reset = Some(SERVER_RESET_CODE);
                self.streams.insert(stream.as_u64(), state);
                log.line(format!(
                    "event=stream_opened connection={} session={} stream={} kind=bi role=server bytes={SERVER_RESET_PAYLOAD_LEN} reset_code={SERVER_RESET_CODE}",
                    connection.as_u64(),
                    session.get(),
                    stream.as_u64()
                ));
            }
            Err(error) => log.line(format!(
                "event=server_bi_open_failed connection={} session={} error={error}",
                connection.as_u64(),
                session.get()
            )),
        }
    }

    fn handle_capsules(&mut self, connection: ConnectionId, id: u64, log: &mut Log) {
        loop {
            let Some(state) = self.streams.get(&id) else {
                return;
            };
            if state.capsule_buf.is_empty() {
                return;
            }
            let parsed = match Capsule::decode(&state.capsule_buf, MAX_CAPSULE_PAYLOAD) {
                Ok(parsed) => parsed,
                Err(CapsuleError::Truncated) => return,
                Err(error) => {
                    if let Some(state) = self.streams.get_mut(&id) {
                        state.capsule_buf.clear();
                    }
                    log.line(format!(
                        "event=capsule_malformed connection={} stream={} error={error:?}",
                        connection.as_u64(),
                        id
                    ));
                    return;
                }
            };
            let consumed = parsed.1;
            let event = match parsed.0 {
                Capsule::CloseSession { code, message } => CapsuleEvent::Close {
                    code,
                    message: message.to_string(),
                },
                Capsule::DrainSession => CapsuleEvent::Drain,
                Capsule::Stream { .. } => CapsuleEvent::Stream,
                Capsule::Unknown {
                    capsule_type,
                    payload,
                } => CapsuleEvent::Unknown {
                    capsule_type,
                    bytes: payload.len(),
                },
            };
            if let Some(state) = self.streams.get_mut(&id) {
                state.capsule_buf.drain(..consumed);
            }

            match event {
                CapsuleEvent::Close { code, message } => {
                    log.line(format!(
                        "event=session_closed connection={} session={} reason=capsule code={code} message={message:?}",
                        connection.as_u64(),
                        id
                    ));
                    self.close_session(connection, id, "capsule", log);
                }
                CapsuleEvent::Drain => {
                    log.line(format!(
                        "event=session_drained connection={} session={}",
                        connection.as_u64(),
                        id
                    ));
                    if let Some(session) = self.sessions.get_mut(&id) {
                        session.drained = true;
                    }
                }
                CapsuleEvent::Stream => log.line(format!(
                    "event=capsule_stream_ignored connection={} session={}",
                    connection.as_u64(),
                    id
                )),
                CapsuleEvent::Unknown {
                    capsule_type,
                    bytes,
                } => log.line(format!(
                    "event=capsule_unknown connection={} session={} capsule_type=0x{capsule_type:x} payload_bytes={bytes}",
                    connection.as_u64(),
                    id
                )),
            }
        }
    }

    fn handle_connect_fin(&mut self, connection: ConnectionId, id: u64, log: &mut Log) {
        if let Some(state) = self.streams.get_mut(&id) {
            state.finished = true;
        }
        if self.sessions.contains_key(&id) {
            log.line(format!(
                "event=session_closed connection={} session={} reason=connect_fin code=0",
                connection.as_u64(),
                id
            ));
            self.close_session(connection, id, "connect_fin", log);
        }
    }

    /// Ends one session: drop it from the routing table, finish the CONNECT
    /// stream's send side and abandon its remaining server-initiated streams
    /// with `WT_SESSION_GONE`. The QUIC connection keeps serving other
    /// sessions.
    fn close_session(&mut self, connection: ConnectionId, id: u64, reason: &str, log: &mut Log) {
        let Some(session) = self.sessions.remove(&id) else {
            return;
        };
        log.line(format!(
            "event=session_removed connection={} session={} reason={reason}",
            connection.as_u64(),
            session.session.get()
        ));

        if let Some(state) = self.streams.get_mut(&id) {
            state.finished = true;
            if !state.out_finished {
                state.out_finish = true;
            }
        }

        let session_key = session.session.get();
        let auto_ids: Vec<u64> = self
            .streams
            .iter()
            .filter(|(_, state)| match state.role {
                Role::ServerAutoUni { session } | Role::ServerAutoBiReset { session } => {
                    session.get() == session_key
                }
                _ => false,
            })
            .map(|(id, _)| *id)
            .collect();
        for auto_id in auto_ids {
            let Some(state) = self.streams.get_mut(&auto_id) else {
                continue;
            };
            if state.out_finished {
                continue;
            }
            state.out_buf.clear();
            state.out_pos = 0;
            state.out_reset = Some(WT_SESSION_GONE_CODE);
            log.line(format!(
                "event=stream_reset connection={} stream={} role=server direction={} code=0x{WT_SESSION_GONE_CODE:x} reason=session_closed",
                connection.as_u64(),
                state.id.as_u64(),
                direction_name(state.id),
            ));
        }
    }

    fn queue_echo_uni(
        &mut self,
        connection: ConnectionId,
        session: SessionId,
        payload: Vec<u8>,
        endpoint: &mut Endpoint,
        log: &mut Log,
    ) {
        match endpoint.open_uni(connection) {
            Ok(stream) => {
                let mut state = StreamState::new(stream, Role::ServerOther);
                push_varint(&mut state.out_buf, STREAM_WEBTRANSPORT_UNI);
                push_varint(&mut state.out_buf, session.get());
                state.out_buf.extend_from_slice(&payload);
                state.out_finish = true;
                self.streams.insert(stream.as_u64(), state);
                log.line(format!(
                    "event=stream_echo_queued connection={} session={} stream={} direction=uni role=server bytes={}",
                    connection.as_u64(),
                    session.get(),
                    stream.as_u64(),
                    payload.len()
                ));
            }
            Err(error) => log.line(format!(
                "event=stream_echo_failed connection={} session={} direction=uni error={error}",
                connection.as_u64(),
                session.get()
            )),
        }
    }

    fn queue_echo_bi(
        &mut self,
        connection: ConnectionId,
        id: u64,
        session: SessionId,
        payload: Vec<u8>,
        log: &mut Log,
    ) {
        if let Some(state) = self.streams.get_mut(&id) {
            state.out_buf = payload;
            state.out_pos = 0;
            state.out_finish = true;
            log.line(format!(
                "event=stream_echo_queued connection={} session={} stream={} direction=bi role=server bytes={}",
                connection.as_u64(),
                session.get(),
                id,
                state.out_buf.len()
            ));
        }
    }

    fn poll_datagrams(&mut self, connection: ConnectionId, endpoint: &mut Endpoint, log: &mut Log) {
        let max_len = ADVERTISED_MAX_DATAGRAM_FRAME_SIZE;
        let mut buffer = vec![0u8; 4096];
        loop {
            match endpoint.poll_datagram(connection, &mut buffer) {
                Ok(Some(len)) => {
                    self.datagrams_received = self.datagrams_received.saturating_add(1);
                    let sequence = self.datagrams_received;
                    let input = buffer[..len].to_vec();
                    self.handle_datagram(connection, sequence, &input, max_len, endpoint, log);
                }
                Ok(None) => break,
                Err(DatagramError::BufferTooSmall { datagram_len }) => log.line(format!(
                    "event=datagram_dropped connection={} reason=buffer_too_small datagram_bytes={datagram_len}",
                    connection.as_u64()
                )),
                Err(_) => break,
            }
        }
    }

    fn handle_datagram(
        &mut self,
        connection: ConnectionId,
        sequence: u64,
        input: &[u8],
        max_len: usize,
        endpoint: &mut Endpoint,
        log: &mut Log,
    ) {
        if input.is_empty() {
            log.line(format!(
                "event=datagram_dropped connection={} seq={sequence} reason=malformed detail=empty",
                connection.as_u64()
            ));
            return;
        }
        let quarter = match QuarterStreamId::decode(input) {
            Ok((quarter, _)) => quarter,
            Err(error) => {
                log.line(format!(
                    "event=datagram_dropped connection={} seq={sequence} reason=malformed error={error:?}",
                    connection.as_u64()
                ));
                return;
            }
        };
        let connect_stream = quarter.stream_id();
        let Some(session) = self.sessions.get(&connect_stream) else {
            log.line(format!(
                "event=datagram_dropped connection={} seq={sequence} reason=wrong_session quarter={} connect_stream={connect_stream}",
                connection.as_u64(),
                quarter.get()
            ));
            return;
        };
        let session = session.session;

        let (decoded, _consumed) = match datagram::decode(input, session, max_len) {
            Ok(decoded) => decoded,
            Err(error) => {
                log.line(format!(
                    "event=datagram_dropped connection={} seq={sequence} session={} reason=decode_failed error={error:?}",
                    connection.as_u64(),
                    session.get()
                ));
                return;
            }
        };
        log.line(format!(
            "event=datagram_received connection={} seq={sequence} session={} bytes={}",
            connection.as_u64(),
            session.get(),
            decoded.payload().len()
        ));

        let mut output = vec![0u8; max_len];
        let encoded_len = match datagram::encode(session, decoded.payload(), max_len, &mut output) {
            Ok(len) => len,
            Err(error) => {
                log.line(format!(
                    "event=datagram_echo_failed connection={} seq={sequence} session={} error={error:?}",
                    connection.as_u64(),
                    session.get()
                ));
                return;
            }
        };
        self.datagrams_echoed = self.datagrams_echoed.saturating_add(1);
        match endpoint.send_datagram(connection, &output[..encoded_len]) {
            Ok(sent) => log.line(format!(
                "event=datagram_sent connection={} seq={} session={} bytes={sent}",
                connection.as_u64(),
                self.datagrams_echoed,
                session.get()
            )),
            Err(error) => log.line(format!(
                "event=datagram_echo_failed connection={} seq={sequence} session={} error={error}",
                connection.as_u64(),
                session.get()
            )),
        }
    }

    fn flush_writes(&mut self, connection: ConnectionId, endpoint: &mut Endpoint, log: &mut Log) {
        let ids: Vec<u64> = self.streams.keys().copied().collect();
        for id in ids {
            let Some(state) = self.streams.get_mut(&id) else {
                continue;
            };
            if state.out_finished {
                continue;
            }
            if state.out_pos < state.out_buf.len() {
                let remaining = &state.out_buf[state.out_pos..];
                match endpoint.write_stream(connection, state.id, remaining) {
                    Ok(0) => continue,
                    Ok(written) => state.out_pos += written,
                    Err(StreamError::Blocked) => continue,
                    Err(error) => {
                        state.out_finished = true;
                        log.line(format!(
                            "event=stream_write_failed connection={} stream={} error={error}",
                            connection.as_u64(),
                            state.id.as_u64()
                        ));
                        continue;
                    }
                }
            }
            if state.out_pos < state.out_buf.len() {
                continue;
            }
            if let Some(code) = state.out_reset {
                match endpoint.reset_stream(connection, state.id, code) {
                    Ok(()) => log.line(format!(
                        "event=stream_reset connection={} stream={} role=server direction={} code={code}",
                        connection.as_u64(),
                        state.id.as_u64(),
                        direction_name(state.id),
                    )),
                    Err(error) => log.line(format!(
                        "event=stream_reset_failed connection={} stream={} error={error}",
                        connection.as_u64(),
                        state.id.as_u64()
                    )),
                }
                state.out_finished = true;
            } else if state.out_finish {
                let bytes = state.out_buf.len();
                match endpoint.finish_stream(connection, state.id) {
                    Ok(()) => log.line(format!(
                        "event=stream_finished connection={} stream={} role=server direction={} bytes={bytes}",
                        connection.as_u64(),
                        state.id.as_u64(),
                        direction_name(state.id),
                    )),
                    Err(error) => log.line(format!(
                        "event=stream_finish_failed connection={} stream={} error={error}",
                        connection.as_u64(),
                        state.id.as_u64()
                    )),
                }
                state.out_finished = true;
            }
        }
    }

    fn request_close(
        &mut self,
        connection: ConnectionId,
        now: Timestamp,
        error_code: u64,
        reason: &[u8],
        endpoint: &mut Endpoint,
        log: &mut Log,
    ) {
        self.closing = true;
        match endpoint.close(connection, now, error_code, reason) {
            Ok(()) => log.line(format!(
                "event=connection_close_requested connection={} error_code=0x{error_code:x}",
                connection.as_u64()
            )),
            Err(error) => log.line(format!(
                "event=connection_close_failed connection={} error={error}",
                connection.as_u64()
            )),
        }
    }
}

/// One stream and the buffers this harness keeps for it.
#[derive(Debug)]
struct StreamState {
    id: StreamId,
    role: Role,
    /// Bytes read from the peer, not yet consumed by the role's parser.
    in_buf: Vec<u8>,
    /// Bytes queued for this stream's send side.
    out_buf: Vec<u8>,
    out_pos: usize,
    out_finish: bool,
    out_reset: Option<u64>,
    out_finished: bool,
    peer_fin: bool,
    finished: bool,
    connect_headers_seen: bool,
    /// Capsule bytes assembled from DATA frames on a CONNECT stream.
    capsule_buf: Vec<u8>,
}

impl StreamState {
    fn new(id: StreamId, role: Role) -> Self {
        Self {
            id,
            role,
            in_buf: Vec::new(),
            out_buf: Vec::new(),
            out_pos: 0,
            out_finish: false,
            out_reset: None,
            out_finished: false,
            peer_fin: false,
            finished: false,
            connect_headers_seen: false,
            capsule_buf: Vec::new(),
        }
    }
}

/// What a stream is, once its first bytes identified it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    UniProbe,
    BiProbe,
    ClientControl,
    QpackDrain,
    OtherUni,
    WtUniPendingSession,
    WtUni { session: SessionId },
    WtBiPendingSession,
    WtBi { session: SessionId },
    Connect { session: Option<SessionId> },
    ServerAutoUni { session: SessionId },
    ServerAutoBiReset { session: SessionId },
    ServerOther,
}

/// A side effect requested by [`ConnState::advance_stream`].
#[derive(Debug)]
enum StreamAction {
    None,
    ClientSettings(Vec<u8>),
    ConnectHeaders(Vec<u8>),
    Capsules,
    ConnectFin,
    EchoUni {
        session: SessionId,
        payload: Vec<u8>,
    },
    EchoBi {
        session: SessionId,
        payload: Vec<u8>,
    },
}

/// An owned view of one decoded capsule, so the stream buffer borrow can end
/// before the capsule's side effects run.
#[derive(Debug)]
enum CapsuleEvent {
    Close { code: u32, message: String },
    Drain,
    Stream,
    Unknown { capsule_type: u64, bytes: usize },
}

/// Builds the fixed five-item SETTINGS payload.
///
/// `rtx-h3`'s encoder refuses deprecated and unknown identifiers, so this
/// payload can never grow the deprecated pairs the R6-2c reference server
/// emits. `0x2c7cf000` (`SETTINGS_WT_ENABLED` in draft-15) is deliberately
/// absent: Chrome 156 negotiates the deprecated `0x2b603742` signal, and this
/// harness does not claim an unverified negotiation behaviour (see README).
fn server_settings() -> Settings {
    let mut settings = Settings::new();
    let items = [
        (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
        (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
        (SETTINGS_H3_DATAGRAM, 1),
        (
            SETTINGS_WEBTRANSPORT_MAX_SESSIONS,
            WEBTRANSPORT_MAX_SESSIONS_VALUE,
        ),
    ];
    for (id, value) in items {
        let _ = settings.set(id, value);
    }
    settings
}

/// Classifies a SETTINGS identifier for the log.
fn classify_setting(id: u64) -> &'static str {
    match id {
        SETTINGS_QPACK_MAX_TABLE_CAPACITY
        | 0x06
        | SETTINGS_QPACK_BLOCKED_STREAMS
        | SETTINGS_ENABLE_CONNECT_PROTOCOL
        | SETTINGS_H3_DATAGRAM
        | SETTINGS_WEBTRANSPORT_MAX_SESSIONS => "known",
        SETTINGS_H3_DATAGRAM_DEPRECATED
        | SETTINGS_WEBTRANSPORT_ENABLE_DEPRECATED
        | SETTINGS_WEBTRANSPORT_MAX_SESSIONS_DEPRECATED => "deprecated",
        other if is_grease(other) => "grease",
        _ => "unknown",
    }
}

/// `RFC 9114` section 7.2.4.1 GREASE pattern: `0x1f * N + 0x21`.
fn is_grease(id: u64) -> bool {
    if id < 0x21 {
        return false;
    }
    (id - 0x21).is_multiple_of(0x1f)
}

/// Parses `max_datagram_frame_size` (`0x20`) out of the canonical peer
/// transport-parameter encoding captured in `HandshakeInfo`.
fn parse_max_datagram_frame_size(encoded: &[u8]) -> Option<u64> {
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

fn direction_name(id: StreamId) -> &'static str {
    match id.direction() {
        rtx_quic::Direction::Bi => "bi",
        rtx_quic::Direction::Uni => "uni",
    }
}

/// Writes one QUIC varint into a growable buffer using `rtx-wire`.
fn push_varint(output: &mut Vec<u8>, value: u64) {
    let len = varint::encoded_len(value);
    let mut scratch = [0u8; 8];
    if let Ok(written) = varint::encode(value, &mut scratch[..len]) {
        output.extend_from_slice(&scratch[..written]);
    }
}

/// Deterministic harness payload: `0..255` repeated, truncated to `len`.
fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from(index % PATTERN_PERIOD).unwrap_or(0))
        .collect()
}

fn wait_duration(now: Timestamp, deadline: Option<Timestamp>) -> Duration {
    match deadline {
        Some(deadline) => {
            let micros = deadline.as_micros().saturating_sub(now.as_micros());
            let capped = micros.min(u64::try_from(MAX_WAIT.as_micros()).unwrap_or(u64::MAX));
            Duration::from_micros(capped.max(1))
        }
        None => MAX_WAIT,
    }
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

/// Formats a facade close reason for the log.
struct CloseReasonText<'a>(&'a rtx_quic::CloseReason);

impl fmt::Display for CloseReasonText<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        use rtx_quic::{CloseOrigin, CloseReason};
        match self.0 {
            CloseReason::Application {
                origin,
                error_code,
                reason,
            } => write!(
                formatter,
                "application origin={} code={error_code} bytes={}",
                match origin {
                    CloseOrigin::Local => "local",
                    CloseOrigin::Remote => "remote",
                },
                reason.len()
            ),
            CloseReason::Transport { error_code } => {
                write!(formatter, "transport code=0x{error_code:x}")
            }
            CloseReason::TimedOut => formatter.write_str("timed_out"),
            CloseReason::Reset => formatter.write_str("reset"),
            CloseReason::VersionMismatch => formatter.write_str("version_mismatch"),
            other => write!(formatter, "other={other:?}"),
        }
    }
}
