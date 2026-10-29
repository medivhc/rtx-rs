//! Minimal WebTransport-over-HTTP/3 session for the WebTransport rows of
//! `M3-PS6` and `M3-PS8`.
//!
//! Scope: exactly the subset the gate needs, built only from the `rtx-h3`
//! and `rtx-webtransport` codecs — one control stream carrying SETTINGS, one
//! extended CONNECT stream, one session, and HTTP Datagram echo via
//! `rtx_webtransport::datagram`. No capsules, no WebTransport streams, no
//! QPACK dynamic table. Every frame header is `rtx_wire::h3_frame::Frame`,
//! every QPACK field section is `rtx_h3::connect`, every SETTINGS pair is
//! `rtx_h3::settings`; this module does not re-implement any wire format.

use std::collections::BTreeMap;

use rtx_h3::connect::{ConnectBuffers, ConnectRequest, ConnectResponse};
use rtx_h3::settings::{
    SETTINGS_ENABLE_CONNECT_PROTOCOL, SETTINGS_H3_DATAGRAM, SETTINGS_QPACK_BLOCKED_STREAMS,
    SETTINGS_QPACK_MAX_TABLE_CAPACITY, Settings,
};
use rtx_quic::{ConnectionId, DatagramError, StreamError, StreamId, StreamRead};
use rtx_webtransport::datagram;
use rtx_webtransport::ids::SessionId;
use rtx_wire::h3_frame::Frame;
use rtx_wire::varint::{self, VarInt};
use rtx_wire::{Decode, Encode};

use crate::net::Sim;

/// H3 control stream type (`RFC 9114` section 6.2.1).
const STREAM_CONTROL: u64 = 0x00;
/// H3 HEADERS frame (`RFC 9114` section 7.2.2).
const FRAME_HEADERS: u64 = 0x01;
/// H3 SETTINGS frame (`RFC 9114` section 7.2.4).
const FRAME_SETTINGS: u64 = 0x04;
/// Largest stream buffer this session keeps.
const MAX_STREAM_BUFFER: usize = 64 * 1024;

/// Builds the four-pair SETTINGS payload both sides emit.
fn settings_payload() -> Result<Vec<u8>, String> {
    let mut settings = Settings::new();
    for (id, value) in [
        (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
        (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
        (SETTINGS_H3_DATAGRAM, 1),
    ] {
        settings
            .set(id, value)
            .map_err(|error| format!("set setting: {error:?}"))?;
    }
    let mut payload = vec![0u8; settings.encoded_len()];
    settings
        .encode(&mut payload)
        .map_err(|error| format!("encode settings: {error:?}"))?;
    Ok(payload)
}

/// Encodes `type` + `frame payload` into one growable buffer.
fn framed(frame_type: u64, payload: &[u8]) -> Result<Vec<u8>, String> {
    let frame_type = VarInt::new(frame_type).map_err(|error| format!("frame type: {error:?}"))?;
    let frame = Frame::new(frame_type, payload);
    let mut output = vec![0u8; frame.encoded_len()];
    frame
        .encode(&mut output)
        .map_err(|error| format!("encode frame: {error:?}"))?;
    Ok(output)
}

/// Encodes one varint followed by `bytes`.
fn with_stream_type(stream_type: u64, bytes: &[u8]) -> Result<Vec<u8>, String> {
    let length = varint::encoded_len(stream_type);
    let mut scratch = [0u8; 8];
    let written = varint::encode(stream_type, &mut scratch[..length])
        .map_err(|error| format!("encode stream type: {error:?}"))?;
    let mut output = Vec::with_capacity(written + bytes.len());
    output.extend_from_slice(&scratch[..written]);
    output.extend_from_slice(bytes);
    Ok(output)
}

/// Decodes the next frame of `buffer` into owned pieces.
fn next_frame(buffer: &[u8]) -> Option<(u64, Vec<u8>, usize)> {
    let decoded = Frame::decode(buffer).ok()?;
    Some((
        decoded.0.frame_type().get(),
        decoded.0.payload().to_vec(),
        decoded.1,
    ))
}

/// The client half of one WebTransport session.
#[derive(Debug, Default)]
pub struct WtClient {
    control: Option<StreamId>,
    connect: Option<StreamId>,
    session: Option<SessionId>,
    status: Option<u16>,
    connect_buffer: Vec<u8>,
    drained: Vec<StreamId>,
}

impl WtClient {
    /// The established session, once the CONNECT response was a 2xx.
    #[must_use]
    pub fn session(&self) -> Option<SessionId> {
        self.session
    }

    /// The `:status` of the CONNECT response.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        self.status
    }

    /// Opens the control stream and the CONNECT stream, then drains the
    /// server's frames. Call once per pump round.
    ///
    /// # Errors
    ///
    /// Returns a message when a facade call or a codec rejects a step.
    pub fn service(
        &mut self,
        sim: &mut Sim,
        connection: ConnectionId,
        authority: &str,
    ) -> Result<(), String> {
        if self.control.is_none() {
            let stream = sim
                .client
                .open_uni(connection)
                .map_err(|error| format!("open control stream: {error}"))?;
            let bytes = with_stream_type(
                STREAM_CONTROL,
                &framed(FRAME_SETTINGS, &settings_payload()?)?,
            )?;
            write_stream(sim, connection, stream, &bytes)?;
            self.control = Some(stream);
        }
        if self.connect.is_none() {
            let stream = sim
                .client
                .open_bi(connection)
                .map_err(|error| format!("open CONNECT stream: {error}"))?;
            let request = ConnectRequest::new("https", authority, "/session", "webtransport");
            let mut qpack = vec![0u8; request.encoded_len()];
            request
                .encode(&mut qpack)
                .map_err(|error| format!("encode CONNECT: {error:?}"))?;
            let bytes = framed(FRAME_HEADERS, &qpack)?;
            write_stream(sim, connection, stream, &bytes)?;
            self.connect = Some(stream);
        }

        let mut chunk = vec![0u8; 16 * 1024];
        if let Some(stream) = self.connect {
            drain_stream(
                sim,
                connection,
                stream,
                &mut chunk,
                &mut self.connect_buffer,
                false,
            )?;
            let mut pending = std::mem::take(&mut self.connect_buffer);
            while let Some((frame_type, payload, consumed)) = next_frame(&pending) {
                pending.drain(..consumed);
                if frame_type == FRAME_HEADERS {
                    let response = ConnectResponse::decode(&payload)
                        .map_err(|error| format!("decode CONNECT response: {error:?}"))?;
                    self.status = Some(response.status());
                    if response.is_success() {
                        self.session = Some(
                            SessionId::new(stream.as_u64())
                                .map_err(|error| format!("session id: {error:?}"))?,
                        );
                    }
                }
            }
            self.connect_buffer = pending;
        }

        // Drain server-initiated uni streams so flow-control credit returns.
        loop {
            match sim.client.accept_uni(connection) {
                Ok(Some(other)) => {
                    self.drained.push(other);
                }
                Ok(None) => break,
                Err(StreamError::Blocked) => break,
                Err(StreamError::Closed) | Err(StreamError::UnknownConnection) => {
                    self.drained.clear();
                    break;
                }
                Err(error) => return Err(format!("client accept_uni: {error}")),
            }
        }
        let drained = std::mem::take(&mut self.drained);
        for stream in drained {
            let mut sink = Vec::new();
            drain_stream(sim, connection, stream, &mut chunk, &mut sink, false)?;
        }
        Ok(())
    }
}

/// The server half of one WebTransport session.
#[derive(Debug, Default)]
pub struct WtServer {
    roles: BTreeMap<StreamId, ServerStreamRole>,
    buffers: BTreeMap<StreamId, Vec<u8>>,
    settings_sent: bool,
    session: Option<SessionId>,
    status: Option<u16>,
    echoed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ServerStreamRole {
    #[default]
    Probe,
    Control,
    Connect,
    Ignored,
}

impl WtServer {
    /// The session established by the CONNECT request.
    #[must_use]
    pub fn session(&self) -> Option<SessionId> {
        self.session
    }

    /// The status written into the CONNECT response.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        self.status
    }

    /// Accepts new streams, answers SETTINGS and CONNECT, and echoes
    /// datagrams. Call once per pump round.
    ///
    /// # Errors
    ///
    /// Returns a message when a facade call or a codec rejects a step.
    pub fn service(
        &mut self,
        sim: &mut Sim,
        connection: ConnectionId,
        max_len: usize,
    ) -> Result<(), String> {
        loop {
            match sim.server.accept_uni(connection) {
                Ok(Some(stream)) => {
                    self.roles.insert(stream, ServerStreamRole::Probe);
                    self.buffers.insert(stream, Vec::new());
                }
                Ok(None) => break,
                Err(StreamError::Closed) | Err(StreamError::UnknownConnection) => break,
                Err(error) => return Err(format!("server accept_uni: {error}")),
            }
        }
        loop {
            match sim.server.accept_bi(connection) {
                Ok(Some(stream)) => {
                    self.roles.insert(stream, ServerStreamRole::Connect);
                    self.buffers.insert(stream, Vec::new());
                }
                Ok(None) => break,
                Err(StreamError::Closed) | Err(StreamError::UnknownConnection) => break,
                Err(error) => return Err(format!("server accept_bi: {error}")),
            }
        }

        let mut chunk = vec![0u8; 16 * 1024];
        let ids: Vec<StreamId> = self.roles.keys().copied().collect();
        for stream in ids {
            if let Some(buffer) = self.buffers.get_mut(&stream) {
                drain_stream(sim, connection, stream, &mut chunk, buffer, true)?;
            }
        }

        let ids: Vec<StreamId> = self.roles.keys().copied().collect();
        for stream in ids {
            let role = self.roles.get(&stream).copied().unwrap_or_default();
            match role {
                ServerStreamRole::Probe => {
                    let Some(buffer) = self.buffers.get_mut(&stream) else {
                        continue;
                    };
                    let Ok((stream_type, consumed)) = varint::decode(buffer) else {
                        continue;
                    };
                    buffer.drain(..consumed);
                    if stream_type == STREAM_CONTROL {
                        self.roles.insert(stream, ServerStreamRole::Control);
                    } else {
                        self.roles.insert(stream, ServerStreamRole::Ignored);
                        buffer.clear();
                    }
                }
                ServerStreamRole::Control => {
                    let mut settings_payload: Option<Vec<u8>> = None;
                    let Some(buffer) = self.buffers.get_mut(&stream) else {
                        continue;
                    };
                    while let Some((frame_type, payload, consumed)) = next_frame(buffer) {
                        buffer.drain(..consumed);
                        if frame_type == FRAME_SETTINGS {
                            settings_payload = Some(payload);
                        }
                    }
                    if let Some(payload) = settings_payload
                        && !self.settings_sent
                    {
                        self.settings_sent = true;
                        let frame = framed(FRAME_SETTINGS, &payload)?;
                        let bytes = with_stream_type(STREAM_CONTROL, &frame)?;
                        let control = sim
                            .server
                            .open_uni(connection)
                            .map_err(|error| format!("server control stream: {error}"))?;
                        write_stream_server(sim, connection, control, &bytes)?;
                    }
                }
                ServerStreamRole::Connect => {
                    let mut headers: Option<Vec<u8>> = None;
                    let Some(buffer) = self.buffers.get_mut(&stream) else {
                        continue;
                    };
                    while let Some((frame_type, payload, consumed)) = next_frame(buffer) {
                        buffer.drain(..consumed);
                        if frame_type == FRAME_HEADERS && headers.is_none() {
                            headers = Some(payload);
                        }
                    }
                    let Some(payload) = headers else {
                        continue;
                    };
                    let mut scheme = [0u8; 64];
                    let mut authority = [0u8; 128];
                    let mut path = [0u8; 128];
                    let mut protocol = [0u8; 64];
                    let buffers =
                        ConnectBuffers::new(&mut scheme, &mut authority, &mut path, &mut protocol);
                    let status = match ConnectRequest::decode(&payload, buffers) {
                        Ok(request) if request.protocol() == "webtransport" => {
                            self.session = Some(
                                SessionId::new(stream.as_u64())
                                    .map_err(|error| format!("session id: {error:?}"))?,
                            );
                            200
                        }
                        Ok(_) | Err(_) => 400,
                    };
                    self.status = Some(status);
                    let response = ConnectResponse::new(status)
                        .map_err(|error| format!("response status: {error:?}"))?;
                    let mut qpack = vec![0u8; response.encoded_len()];
                    response
                        .encode(&mut qpack)
                        .map_err(|error| format!("encode response: {error:?}"))?;
                    let bytes = framed(FRAME_HEADERS, &qpack)?;
                    write_stream_server(sim, connection, stream, &bytes)?;
                }
                ServerStreamRole::Ignored => {
                    if let Some(buffer) = self.buffers.get_mut(&stream) {
                        buffer.clear();
                    }
                }
            }
        }

        self.echo_datagrams(sim, connection, max_len)
    }

    fn echo_datagrams(
        &mut self,
        sim: &mut Sim,
        connection: ConnectionId,
        max_len: usize,
    ) -> Result<(), String> {
        let Some(session) = self.session else {
            return Ok(());
        };
        let mut buffer = vec![0u8; max_len];
        let mut output = vec![0u8; max_len];
        loop {
            match sim.server.poll_datagram(connection, &mut buffer) {
                Ok(Some(len)) => {
                    let input = buffer.get(..len).unwrap_or(&[]).to_vec();
                    let (decoded, _) = datagram::decode(&input, session, max_len)
                        .map_err(|error| format!("server datagram decode: {error:?}"))?;
                    let written =
                        datagram::encode(session, decoded.payload(), max_len, &mut output)
                            .map_err(|error| format!("server datagram encode: {error:?}"))?;
                    match sim.server.send_datagram(connection, &output[..written]) {
                        Ok(_) => self.echoed = self.echoed.saturating_add(1),
                        Err(DatagramError::WouldBlock) => {}
                        Err(error) => return Err(format!("server datagram echo: {error}")),
                    }
                }
                Ok(None) => return Ok(()),
                Err(DatagramError::Closed) | Err(DatagramError::UnknownConnection) => {
                    return Ok(());
                }
                Err(error) => return Err(format!("server poll_datagram: {error}")),
            }
        }
    }
}

/// Appends every readable chunk of `stream` to `buffer`.
fn drain_stream(
    sim: &mut Sim,
    connection: ConnectionId,
    stream: StreamId,
    chunk: &mut [u8],
    buffer: &mut Vec<u8>,
    server: bool,
) -> Result<(), String> {
    loop {
        let result = if server {
            sim.server.read_stream(connection, stream, chunk)
        } else {
            sim.client.read_stream(connection, stream, chunk)
        };
        match result {
            Ok(StreamRead::Data { len }) => {
                if buffer.len() + len <= MAX_STREAM_BUFFER {
                    buffer.extend_from_slice(&chunk[..len]);
                }
            }
            Ok(StreamRead::Finished) | Err(StreamError::Blocked) => return Ok(()),
            Err(StreamError::Closed) | Err(StreamError::StreamClosed) => return Ok(()),
            Err(error) => return Err(format!("stream read: {error}")),
        }
    }
}

/// Writes `bytes` on the client side, pumping blocked writes.
///
/// # Errors
///
/// Returns a message for unexpected facade errors.
pub fn write_stream(
    sim: &mut Sim,
    connection: ConnectionId,
    stream: StreamId,
    bytes: &[u8],
) -> Result<(), String> {
    write_stream_with(sim, connection, stream, bytes, false)
}

fn write_stream_server(
    sim: &mut Sim,
    connection: ConnectionId,
    stream: StreamId,
    bytes: &[u8],
) -> Result<(), String> {
    write_stream_with(sim, connection, stream, bytes, true)
}

fn write_stream_with(
    sim: &mut Sim,
    connection: ConnectionId,
    stream: StreamId,
    bytes: &[u8],
    server: bool,
) -> Result<(), String> {
    let mut offset = 0;
    for _ in 0..64 {
        if offset >= bytes.len() {
            return Ok(());
        }
        let result = if server {
            sim.server
                .write_stream(connection, stream, &bytes[offset..])
        } else {
            sim.client
                .write_stream(connection, stream, &bytes[offset..])
        };
        match result {
            Ok(0) => sim.tick()?,
            Ok(written) => offset += written,
            Err(StreamError::Blocked) => sim.tick()?,
            Err(error) => return Err(format!("write_stream: {error}")),
        }
    }
    if offset >= bytes.len() {
        Ok(())
    } else {
        Err("write_stream did not drain".to_owned())
    }
}

/// Pumps both endpoints until the session is established on both sides.
///
/// # Errors
///
/// Returns a message on a facade/codec error or when the cap expires.
pub fn establish(
    sim: &mut Sim,
    client: &mut WtClient,
    server: &mut WtServer,
    client_connection: ConnectionId,
    server_connection: ConnectionId,
    authority: &str,
    max_len: usize,
) -> Result<(), String> {
    let start = std::time::Instant::now();
    let cap = std::time::Duration::from_secs(3);
    loop {
        client.service(sim, client_connection, authority)?;
        server.service(sim, server_connection, max_len)?;
        sim.tick()?;
        if client.session().is_some() && server.session().is_some() {
            return Ok(());
        }
        if start.elapsed() >= cap {
            return Err(format!(
                "WebTransport session not established within {} ms (client status {:?}, server status {:?})",
                cap.as_millis(),
                client.status(),
                server.status()
            ));
        }
        sim.wait(std::time::Duration::from_millis(1))?;
    }
}
