//! One-shot in-session WebTransport close after the step-13 forward H3
//! handshake: quinn client (web-transport-proto codec) <-> rtx-quic server
//! (rtx-h3 codec), one direction (client -> server), exactly one
//! `CLOSE_WEBTRANSPORT_SESSION` capsule, stop on receipt.
//!
//! This step adds ONLY a session close to the step-16 skeleton (which already
//! established the WT session and exercised one WT uni data stream). No WT
//! data stream, no datagram, no reverse close, no second capsule: the client
//! writes one `CLOSE_WEBTRANSPORT_SESSION` capsule on the CONNECT bi stream,
//! the server reads and asserts it, and that counts as "the peer received the
//! close" — the test stops there.
//!
//! # Close capsule wire format (confirmed from the pinned web-transport
//!   checkout, rev d4e4e458)
//!
//! - The capsule itself is `varint(0x2843) || varint(4 + msg_len) ||
//!   u32be(code) || UTF-8 message`, per `rs/web-transport-proto/src/capsule.rs`
//!   (`CLOSE_WEBTRANSPORT_SESSION_TYPE = 0x2843` at :9; encode at :137-157; the
//!   two-byte varint form `[0x68, 0x43]` is exercised at :354-355).
//! - `rs/web-transport-quinn/src/session.rs:443-457` (`close_with_capsule`)
//!   wraps that capsule in an HTTP/3 DATA frame before writing it on the
//!   CONNECT stream (RFC 9297 section 3.2): `varint(0x00 = Frame::DATA) ||
//!   varint(capsule_len) || capsule_bytes`, then `send.finish()`. The client
//!   side of this test mirrors that reference byte-for-byte, using the
//!   `web-transport-proto` `Capsule::encode` + `Frame::DATA` APIs.
//! - The rtx server side decodes the same DATA frame with `rtx-wire`'s H3
//!   frame codec and the capsule with `rtx-webtransport`'s
//!   `capsules::Capsule::decode` (`WT_CLOSE_SESSION = 0x2843`): a genuine
//!   cross-codec interop check, web-transport-proto encode -> rtx-webtransport
//!   decode, with no changes to `crates/*`.
//!
//! # Ownership / teardown lessons (confirmed pitfalls, applied)
//!
//! - The quinn `Connection` is held by the client task for the whole exchange
//!   and is closed only AFTER the server confirms it read the capsule (a
//!   server->client oneshot signal), so the close never drops bytes the server
//!   has not consumed (step-15 lesson, translated from datagrams to the
//!   reliable CONNECT stream).
//! - Before closing, the client also polls `frame_tx.stream` to confirm the
//!   close capsule's STREAM frame was assembled into a packet, then leaves a
//!   small margin (step-15 emit-then-close lesson).
//! - The test body keeps a second `quinn::Connection` clone alive until the
//!   final teardown, so dropping the client task's handle can never implicitly
//!   close the connection before the server has reported `Closed` (step-10
//!   lesson).
//!
//! The CONNECT stream is deliberately left unfinished during session
//! establishment (steps 13/15/16 pattern); it is only finished when the close
//! capsule is written, exactly like the reference `close_with_capsule`.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use quinn::rustls::pki_types::CertificateDer;
use quinn::rustls::RootCertStore;
use quinn::{rustls, ClientConfig, Endpoint as QuinnEndpoint};
use rcgen;
use rtx_core::{IpAddr as RtxIpAddr, SocketAddr as RtxSocketAddr, Timestamp};
use rtx_h3::connect::{
    ConnectBuffers, ConnectRequest as RtxConnectRequest, ConnectResponse as RtxConnectResponse,
};
use rtx_h3::settings::{
    Settings as RtxSettings, SETTINGS_ENABLE_CONNECT_PROTOCOL, SETTINGS_H3_DATAGRAM,
    SETTINGS_WEBTRANSPORT_MAX_SESSIONS,
};
use rtx_quic::{
    ConnectionId, Endpoint as RtxEndpoint, EndpointConfig, EventKind, StreamId, StreamRead,
};
use rtx_webtransport::capsules::{
    Capsule as RtxCapsule, MAX_CLOSE_MESSAGE_LEN, WT_CLOSE_SESSION,
};
use rtx_webtransport::ids::SessionId;
use rtx_wire::h3_frame::Frame as H3Frame;
use rtx_wire::{varint, Decode, Encode, WireError};
use tokio::net::UdpSocket;
use url::Url;
use web_transport_proto::{
    Capsule as WtProtoCapsule, ConnectRequest, ConnectResponse, Frame as WtFrame, Settings, VarInt as WtVarInt,
};

const ALPN: &[u8] = b"h3";
/// H3 unidirectional stream type CONTROL (`RFC 9114` section 6.2).
const STREAM_TYPE_CONTROL: u64 = 0x00;
/// H3 frame type DATA (`RFC 9114` section 7.2.1) — carries the capsule
/// protocol payload on the CONNECT stream (RFC 9297 section 3.2).
const FRAME_TYPE_DATA: u64 = 0x00;
/// H3 frame type HEADERS (`RFC 9114` section 7.2.1).
const FRAME_TYPE_HEADERS: u64 = 0x01;
/// H3 frame type SETTINGS (`RFC 9114` section 7.2.4).
const FRAME_TYPE_SETTINGS: u64 = 0x04;
const SESSION_URL: &str = "https://localhost/session";
/// `CLOSE_WEBTRANSPORT_SESSION` application error code sent by the client.
const CLOSE_CODE: u32 = 420;
/// `CLOSE_WEBTRANSPORT_SESSION` UTF-8 message sent by the client.
const CLOSE_REASON: &str = "h3-session-close-once";

fn rtx_addr(sa: SocketAddr) -> RtxSocketAddr {
    match sa {
        SocketAddr::V4(v4) => RtxSocketAddr {
            ip: RtxIpAddr::V4(v4.ip().octets()),
            port: v4.port(),
        },
        SocketAddr::V6(v6) => RtxSocketAddr {
            ip: RtxIpAddr::V6(v6.ip().octets()),
            port: v6.port(),
        },
    }
}

fn std_addr(sa: RtxSocketAddr) -> SocketAddr {
    match sa.ip {
        RtxIpAddr::V4(oct) => {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(oct[0], oct[1], oct[2], oct[3]), sa.port))
        }
        RtxIpAddr::V6(oct) => {
            use std::net::{Ipv6Addr, SocketAddrV6};
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(oct), sa.port, 0, 0))
        }
    }
}

/// What the quinn client task reports after driving its H3 + close steps.
struct ClientOutcome {
    /// `supports_webtransport()` decoded from the server SETTINGS reply.
    supports_wt: u64,
    /// `:status` of the CONNECT response.
    status: u16,
    /// Full CONNECT stream ID the quinn side used as the WT session id
    /// (web-transport-quinn caliber; must be 0 in this test).
    session_id: u64,
    /// Exact wire bytes written to the CONNECT stream for the close: the
    /// `varint(0x00) || varint(capsule_len) || capsule_bytes` DATA frame.
    close_wire: Vec<u8>,
}

/// Decodes `varint(CONTROL) + Frame(SETTINGS) + payload` from the accumulated
/// client control-stream bytes. `Ok(None)` means the buffer does not hold a
/// complete frame yet; `Err` means the bytes are definitively wrong.
fn decode_control_settings(buf: &[u8]) -> Result<Option<RtxSettings>, String> {
    let (stream_type, type_len) = match varint::decode(buf) {
        Ok(v) => v,
        Err(WireError::UnexpectedEnd) => return Ok(None),
        Err(e) => return Err(format!("stream type varint: {:?}", e)),
    };
    if stream_type != STREAM_TYPE_CONTROL {
        return Err(format!(
            "stream type {:#x} is not CONTROL ({:#x})",
            stream_type, STREAM_TYPE_CONTROL
        ));
    }
    let (frame, _) = match H3Frame::decode(&buf[type_len..]) {
        Ok(v) => v,
        Err(WireError::UnexpectedEnd) => return Ok(None),
        Err(e) => return Err(format!("settings frame header: {:?}", e)),
    };
    if frame.frame_type().get() != FRAME_TYPE_SETTINGS {
        return Err(format!(
            "frame type {:#x} is not SETTINGS ({:#x})",
            frame.frame_type().get(),
            FRAME_TYPE_SETTINGS
        ));
    }
    RtxSettings::decode(frame.payload())
        .map(Some)
        .map_err(|e| format!("settings payload: {:?}", e))
}

/// Decodes one complete `Frame(HEADERS)` from accumulated bi-stream bytes and
/// returns its payload and the number of bytes consumed (frame header +
/// payload). `Ok(None)` means the frame is not fully buffered yet.
fn decode_headers_frame(buf: &[u8]) -> Result<Option<(&[u8], usize)>, String> {
    let (frame, consumed) = match H3Frame::decode(buf) {
        Ok(v) => v,
        Err(WireError::UnexpectedEnd) => return Ok(None),
        Err(e) => return Err(format!("headers frame header: {:?}", e)),
    };
    if frame.frame_type().get() != FRAME_TYPE_HEADERS {
        return Err(format!(
            "frame type {:#x} is not HEADERS ({:#x})",
            frame.frame_type().get(),
            FRAME_TYPE_HEADERS
        ));
    }
    Ok(Some((frame.payload(), consumed)))
}

/// Decodes one complete `Frame(DATA)` from accumulated CONNECT-stream bytes
/// and returns its payload (the capsule bytes) and the consumed length.
/// `Ok(None)` means the frame is not fully buffered yet.
fn decode_data_frame(buf: &[u8]) -> Result<Option<(&[u8], usize)>, String> {
    let (frame, consumed) = match H3Frame::decode(buf) {
        Ok(v) => v,
        Err(WireError::UnexpectedEnd) => return Ok(None),
        Err(e) => return Err(format!("data frame header: {:?}", e)),
    };
    if frame.frame_type().get() != FRAME_TYPE_DATA {
        return Err(format!(
            "frame type {:#x} is not DATA ({:#x})",
            frame.frame_type().get(),
            FRAME_TYPE_DATA
        ));
    }
    Ok(Some((frame.payload(), consumed)))
}

/// Encodes `Frame(frame_type){payload}`, optionally prefixed by a uni
/// stream-type varint.
fn encode_frame(frame_type: u64, payload: &[u8], stream_type: Option<u64>) -> Vec<u8> {
    let frame = H3Frame::new(
        varint::VarInt::new(frame_type).expect("frame type fits in a varint"),
        payload,
    );
    let prefix_len = stream_type.map_or(0, varint::encoded_len);
    let mut out = vec![0u8; prefix_len + frame.encoded_len()];
    let mut offset = 0;
    if let Some(st) = stream_type {
        offset += varint::encode(st, &mut out).expect("stream type fits");
    }
    offset += frame.encode(&mut out[offset..]).expect("frame fits");
    out.truncate(offset);
    out
}

/// Server SETTINGS reply: `varint(CONTROL) + Frame(SETTINGS){0x08=1, 0x33=1,
/// 0xc671706a=1}`.
fn encode_server_settings() -> Vec<u8> {
    let mut settings = RtxSettings::new();
    settings
        .set(SETTINGS_ENABLE_CONNECT_PROTOCOL, 1)
        .expect("0x08 is encodable");
    settings
        .set(SETTINGS_H3_DATAGRAM, 1)
        .expect("0x33 is encodable");
    settings
        .set(SETTINGS_WEBTRANSPORT_MAX_SESSIONS, 1)
        .expect("0xc671706a is encodable");
    let mut payload = vec![0u8; settings.encoded_len()];
    let n = settings.encode(&mut payload).expect("settings encode");
    payload.truncate(n);
    encode_frame(FRAME_TYPE_SETTINGS, &payload, Some(STREAM_TYPE_CONTROL))
}

/// Server 200 reply: `Frame(HEADERS){ :status 200 }`.
fn encode_connect_response() -> Vec<u8> {
    let response = RtxConnectResponse::new(200).expect("200 is a valid status");
    let mut payload = vec![0u8; response.encoded_len()];
    let n = response.encode(&mut payload).expect("response encode");
    payload.truncate(n);
    encode_frame(FRAME_TYPE_HEADERS, &payload, None)
}

/// Pushes as much of `pending` as the flow controller accepts; leaves the rest
/// for the next pump round.
fn drain_pending(rtx: &mut RtxEndpoint, cid: ConnectionId, stream: StreamId, pending: &mut Vec<u8>) {
    while !pending.is_empty() {
        match rtx.write_stream(cid, stream, pending) {
            Ok(0) | Err(rtx_quic::StreamError::Blocked) => break,
            Ok(n) => {
                pending.drain(..n);
            }
            Err(e) => panic!("write_stream error: {:?}", e),
        }
    }
}

#[tokio::test]
async fn h3_session_close_once() {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate cert");
    let cert_der = certified.cert.der().to_vec();
    let key_der = certified.key_pair.serialize_der();

    let rtx_server = RtxEndpoint::new(
        EndpointConfig::new()
            .with_alpn(vec![ALPN.to_vec()])
            .with_server_identity(vec![cert_der.clone()], key_der.clone()),
    )
    .expect("rtx server endpoint");

    let rtx_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind rtx socket");
    let rtx_addr_std = rtx_socket.local_addr().expect("rtx local addr");

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert_der.clone()))
        .expect("add root");
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
    ));

    let quinn_client = QuinnEndpoint::client("127.0.0.1:0".parse().expect("bind addr"))
        .expect("quinn client");
    quinn_client.set_default_client_config(client_config);

    let connecting = quinn_client
        .connect(rtx_addr_std, "localhost")
        .expect("connect");

    let (tx, mut rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let res = connecting.await;
        let _ = tx.send(res);
    });

    let start = std::time::Instant::now();
    let now = || Timestamp::from_micros(1_000_000 + start.elapsed().as_micros() as u64);

    let mut rtx = rtx_server;
    let mut rtx_handshake = false;
    let mut quinn_handshake = false;
    let mut quinn_error: Option<String> = None;
    let mut rtx_conn: Option<ConnectionId> = None;
    let mut quinn_conn: Option<quinn::Connection> = None;
    let mut client_rx: Option<tokio::sync::oneshot::Receiver<Result<ClientOutcome, String>>> = None;

    // Server-side H3 state machine (step-13 forward pattern) plus the close
    // capsule reader added by this step.
    let mut ctrl_stream: Option<StreamId> = None;
    let mut ctrl_buf: Vec<u8> = Vec::new();
    let mut client_settings: Option<RtxSettings> = None;
    let mut server_ctrl: Option<StreamId> = None;
    let mut server_ctrl_pending: Option<Vec<u8>> = None;
    let mut connect_stream: Option<StreamId> = None;
    let mut connect_buf: Vec<u8> = Vec::new();
    let mut connect_fields: Option<(String, String, String, String)> = None;
    let mut session_id: Option<u64> = None;
    let mut response_pending: Option<Vec<u8>> = None;
    let mut response_written = false;
    // This step's addition: bytes of the capsule-bearing DATA frame read from
    // the CONNECT stream after the HEADERS frame, and the decoded close.
    let mut capsule_buf: Vec<u8> = Vec::new();
    let mut close_received: Option<(u32, String)> = None;
    let mut client_outcome: Option<Result<ClientOutcome, String>> = None;
    let mut close_sent = false;
    let mut rtx_closed = false;

    // Server -> client signal: fired only after the server read and asserted
    // the close capsule, so the client never closes before the server has the
    // capsule in hand (the step-15 emit-then-close lesson, applied to the
    // reliable CONNECT stream).
    let (server_got_close_tx, server_got_close_rx) = tokio::sync::oneshot::channel::<()>();
    let mut server_got_close_tx = Some(server_got_close_tx);

    // One 10s budget for the whole test: handshake + H3 exchange + close.
    let outcome = tokio::time::timeout(Duration::from_secs(10), async {
        // Phase 1: QUIC handshake.
        loop {
            let mut buf = Vec::with_capacity(65535);
            while let Some(tx) = rtx.poll_transmit(now(), &mut buf) {
                let payload = buf[..tx.len].to_vec();
                let dst = std_addr(tx.destination);
                rtx_socket.send_to(&payload, dst).await.expect("send");
            }

            let mut recv_buf = [0u8; 65535];
            loop {
                match rtx_socket.try_recv_from(&mut recv_buf) {
                    Ok((n, src)) => {
                        rtx.handle_datagram(now(), rtx_addr(src), None, &recv_buf[..n]);
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => panic!("recv error: {}", e),
                }
            }

            if let Some(deadline) = rtx.poll_timeout() {
                if now() >= deadline {
                    rtx.handle_timeout(now());
                }
            }

            while let Some(ev) = rtx.poll_event() {
                match ev.kind {
                    EventKind::Incoming => {
                        let mut b = Vec::new();
                        rtx.accept(now(), ev.connection, &mut b).expect("accept");
                        if rtx_conn.is_none() {
                            rtx_conn = Some(ev.connection);
                        }
                    }
                    EventKind::HandshakeComplete(_) => {
                        rtx_handshake = true;
                    }
                    EventKind::HandshakeFailed(e) => {
                        panic!("rtx handshake failed: {:?}", e);
                    }
                    _ => {}
                }
            }

            if !quinn_handshake {
                if let Ok(res) = rx.try_recv() {
                    match res {
                        Ok(conn) => {
                            quinn_conn = Some(conn);
                            quinn_handshake = true;
                        }
                        Err(e) => quinn_error = Some(format!("{:?}", e)),
                    }
                }
            }

            if let Some(e) = &quinn_error {
                panic!("quinn handshake failed: {}", e);
            }

            if rtx_handshake && quinn_handshake {
                break;
            }

            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        let cid = rtx_conn.as_ref().copied().expect("rtx connection id");
        let qconn = quinn_conn.take().expect("quinn connection");
        // Step-10 lesson: the test body keeps a second handle alive until the
        // final teardown, so the client task dropping its handle can never
        // implicitly close the connection before the server reports `Closed`.
        let _qconn_hold = qconn.clone();

        // Spawn the quinn client: SETTINGS, CONNECT, 200, then one
        // CLOSE_WEBTRANSPORT_SESSION capsule, wait for the server-received
        // signal, then close.
        let (client_tx, result_rx) = tokio::sync::oneshot::channel();
        client_rx = Some(result_rx);
        tokio::spawn(async move {
            let result: Result<ClientOutcome, String> = async {
                // (b) Client SETTINGS: default + enable_webtransport(1).
                let mut settings = Settings::default();
                settings.enable_webtransport(1);
                let mut ctrl = qconn
                    .open_uni()
                    .await
                    .map_err(|e| format!("open_uni: {:?}", e))?;
                settings
                    .write(&mut ctrl)
                    .await
                    .map_err(|e| format!("client SETTINGS write: {:?}", e))?;

                // (e) Server SETTINGS from the first accepted uni stream.
                let mut server_ctrl = qconn
                    .accept_uni()
                    .await
                    .map_err(|e| format!("accept_uni: {:?}", e))?;
                let server_settings = Settings::read(&mut server_ctrl)
                    .await
                    .map_err(|e| format!("server SETTINGS read: {:?}", e))?;
                let supports_wt = server_settings.supports_webtransport();

                // (f) Extended CONNECT on a new bi stream. `send`/`recv` stay
                // alive for the whole task; the CONNECT stream is not finished
                // until the close capsule is written (reference
                // `close_with_capsule` behaviour).
                let url = Url::parse(SESSION_URL).map_err(|e| format!("url parse: {}", e))?;
                let request = ConnectRequest::new(url);
                let (mut send, mut recv) = qconn
                    .open_bi()
                    .await
                    .map_err(|e| format!("open_bi: {:?}", e))?;
                request
                    .write(&mut send)
                    .await
                    .map_err(|e| format!("CONNECT write: {:?}", e))?;

                // (i) The 200 response on the same bi stream: session established.
                let response = ConnectResponse::read(&mut recv)
                    .await
                    .map_err(|e| format!("CONNECT response read: {:?}", e))?;
                let status = response.status.as_u16();

                // Session-0 precondition, identical to step 16.
                let session_full =
                    WtVarInt::try_from(quinn::VarInt::from(send.id()).into_inner())
                        .map_err(|e| format!("session id varint: {:?}", e))?;
                if session_full.into_inner() != 0 {
                    return Err(format!(
                        "CONNECT stream id {} != 0: refusing to fake interop outside session 0",
                        session_full
                    ));
                }

                // (close) Build the CLOSE_WEBTRANSPORT_SESSION capsule with the
                // web-transport-proto codec and wrap it in an HTTP/3 DATA frame,
                // byte-for-byte like web-transport-quinn session.rs:443-457.
                let wt_capsule = WtProtoCapsule::CloseWebTransportSession {
                    code: CLOSE_CODE,
                    reason: CLOSE_REASON.to_string(),
                };
                let mut capsule_bytes = Vec::new();
                wt_capsule.encode(&mut capsule_bytes);

                let mut close_wire = Vec::new();
                WtFrame::DATA.encode(&mut close_wire);
                let frame_len = WtVarInt::try_from(capsule_bytes.len())
                    .map_err(|e| format!("close capsule length varint: {:?}", e))?;
                frame_len.encode(&mut close_wire);
                close_wire.extend_from_slice(&capsule_bytes);

                // Streams are reliable, but still confirm the close capsule's
                // STREAM frame was actually assembled into a packet before
                // close, and leave a small margin (step-15 emit-then-close
                // lesson). The primary gate is the server-received signal.
                let pre_stream = qconn.stats().frame_tx.stream;
                send.write_all(&close_wire)
                    .await
                    .map_err(|e| format!("close capsule write_all: {:?}", e))?;
                send.finish()
                    .map_err(|e| format!("close capsule finish: {:?}", e))?;

                let emit_deadline = std::time::Instant::now() + Duration::from_secs(5);
                while qconn.stats().frame_tx.stream <= pre_stream {
                    if std::time::Instant::now() >= emit_deadline {
                        return Err("quinn never emitted the close STREAM frame".to_string());
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;

                // Do NOT close the connection until the server confirms it read
                // and asserted the capsule.
                server_got_close_rx
                    .await
                    .map_err(|_| "server-received close signal channel closed".to_string())?;

                Ok(ClientOutcome {
                    supports_wt,
                    status,
                    session_id: session_full.into_inner(),
                    close_wire,
                })
            }
            .await;
            // Teardown close, only reached after the server got the capsule.
            // The CONNECT send stream is already finished; dropping `send`
            // here is inert (quinn/src/send_stream.rs:355-375).
            qconn.close(quinn::VarInt::from_u32(0), b"h3-session-close-once");
            let _ = client_tx.send(result);
        });

        // Phase 2: pump the rtx server through the H3 exchange and the one
        // session close.
        loop {
            let mut buf = Vec::with_capacity(65535);
            while let Some(tx) = rtx.poll_transmit(now(), &mut buf) {
                let payload = buf[..tx.len].to_vec();
                let dst = std_addr(tx.destination);
                rtx_socket.send_to(&payload, dst).await.expect("send");
            }

            let mut recv_buf = [0u8; 65535];
            loop {
                match rtx_socket.try_recv_from(&mut recv_buf) {
                    Ok((n, src)) => {
                        rtx.handle_datagram(now(), rtx_addr(src), None, &recv_buf[..n]);
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => panic!("recv error: {}", e),
                }
            }

            if let Some(deadline) = rtx.poll_timeout() {
                if now() >= deadline {
                    rtx.handle_timeout(now());
                }
            }

            while let Some(ev) = rtx.poll_event() {
                match ev.kind {
                    EventKind::Incoming => {
                        let mut b = Vec::new();
                        rtx.accept(now(), ev.connection, &mut b).expect("accept");
                    }
                    EventKind::HandshakeFailed(e) => panic!("rtx handshake failed: {:?}", e),
                    EventKind::Closed(_) => {
                        rtx_closed = true;
                    }
                    _ => {}
                }
            }

            // (c) The first client uni stream is the control stream.
            if ctrl_stream.is_none() {
                match rtx.accept_uni(cid) {
                    Ok(Some(s)) => ctrl_stream = Some(s),
                    Ok(None) => {}
                    Err(e) => panic!("accept_uni error: {:?}", e),
                }
            }

            if client_settings.is_none() {
                if let Some(stream) = ctrl_stream {
                    let mut read_buf = [0u8; 65535];
                    loop {
                        match rtx.read_stream(cid, stream, &mut read_buf) {
                            Ok(StreamRead::Data { len }) => {
                                ctrl_buf.extend_from_slice(&read_buf[..len]);
                            }
                            Ok(StreamRead::Finished) => break,
                            Err(rtx_quic::StreamError::Blocked) => break,
                            Err(e) => panic!("read control stream error: {:?}", e),
                        }
                    }
                    match decode_control_settings(&ctrl_buf) {
                        Ok(Some(settings)) => client_settings = Some(settings),
                        Ok(None) => {}
                        Err(e) => panic!(
                            "client SETTINGS decode failed: {} (buffer {})",
                            e,
                            hex::encode(&ctrl_buf)
                        ),
                    }
                }
            }

            // (d) Server SETTINGS reply on a fresh server uni stream, left
            // unfinished like a real H3 control stream.
            if client_settings.is_some() && server_ctrl.is_none() {
                match rtx.open_uni(cid) {
                    Ok(stream) => {
                        server_ctrl = Some(stream);
                        server_ctrl_pending = Some(encode_server_settings());
                    }
                    Err(e) => panic!("open_uni (server control) error: {:?}", e),
                }
            }
            if let (Some(stream), Some(pending)) = (server_ctrl, server_ctrl_pending.as_mut()) {
                drain_pending(&mut rtx, cid, stream, pending);
            }

            // (g) The CONNECT bi stream.
            if connect_stream.is_none() {
                match rtx.accept_bi(cid) {
                    Ok(Some(s)) => connect_stream = Some(s),
                    Ok(None) => {}
                    Err(e) => panic!("accept_bi error: {:?}", e),
                }
            }

            if connect_fields.is_none() {
                if let Some(stream) = connect_stream {
                    let mut read_buf = [0u8; 65535];
                    loop {
                        match rtx.read_stream(cid, stream, &mut read_buf) {
                            Ok(StreamRead::Data { len }) => {
                                connect_buf.extend_from_slice(&read_buf[..len]);
                            }
                            Ok(StreamRead::Finished) => break,
                            Err(rtx_quic::StreamError::Blocked) => break,
                            Err(e) => panic!("read connect stream error: {:?}", e),
                        }
                    }
                    let mut decoded = None;
                    match decode_headers_frame(&connect_buf) {
                        Ok(Some((payload, consumed))) => {
                            let mut scheme = [0u8; 64];
                            let mut authority = [0u8; 256];
                            let mut path = [0u8; 256];
                            let mut protocol = [0u8; 64];
                            let request = RtxConnectRequest::decode(
                                payload,
                                ConnectBuffers::new(
                                    &mut scheme,
                                    &mut authority,
                                    &mut path,
                                    &mut protocol,
                                ),
                            )
                            .unwrap_or_else(|e| {
                                panic!(
                                    "CONNECT decode failed: {:?} (buffer {})",
                                    e,
                                    hex::encode(&connect_buf)
                                )
                            });
                            decoded = Some((
                                request.scheme().to_string(),
                                request.authority().to_string(),
                                request.path().to_string(),
                                request.protocol().to_string(),
                            ));
                            // Any bytes past the HEADERS frame are the start of
                            // the capsule-bearing DATA frame; carry them over.
                            capsule_buf.extend_from_slice(&connect_buf[consumed..]);
                            connect_buf.truncate(consumed);
                        }
                        Ok(None) => {}
                        Err(e) => panic!(
                            "CONNECT frame decode failed: {} (buffer {})",
                            e,
                            hex::encode(&connect_buf)
                        ),
                    }
                    if let Some(fields) = decoded {
                        let session = SessionId::new(stream.as_u64()).unwrap_or_else(|e| {
                            panic!("SessionId::new({}) failed: {:?}", stream.as_u64(), e)
                        });
                        session_id = Some(session.get());
                        connect_fields = Some(fields);
                    }
                }
            }

            // (h) 200 response on the same bi stream; never finished.
            if connect_fields.is_some() && response_pending.is_none() && !response_written {
                response_pending = Some(encode_connect_response());
            }
            if let (Some(stream), Some(pending)) = (connect_stream, response_pending.as_mut()) {
                drain_pending(&mut rtx, cid, stream, pending);
                if pending.is_empty() {
                    response_written = true;
                }
            }

            // (close) Read the close capsule from the CONNECT stream. This is
            // this step's addition: keep reading the CONNECT stream after the
            // 200 response, decode the DATA frame, then the capsule.
            if connect_fields.is_some() && close_received.is_none() {
                if let Some(stream) = connect_stream {
                    let mut read_buf = [0u8; 65535];
                    loop {
                        match rtx.read_stream(cid, stream, &mut read_buf) {
                            Ok(StreamRead::Data { len }) => {
                                capsule_buf.extend_from_slice(&read_buf[..len]);
                            }
                            Ok(StreamRead::Finished) => break,
                            Err(rtx_quic::StreamError::Blocked) => break,
                            Err(e) => panic!("read close capsule stream error: {:?}", e),
                        }
                    }
                    match decode_data_frame(&capsule_buf) {
                        Ok(Some((payload, _))) => {
                            // First, assert the capsule type raw on the wire:
                            // varint(0x2843) = [0x68, 0x43].
                            let (capsule_type, _) =
                                varint::decode(payload).unwrap_or_else(|e| {
                                    panic!(
                                        "close capsule type varint: {:?} (buffer {})",
                                        e,
                                        hex::encode(&capsule_buf)
                                    )
                                });
                            assert_eq!(
                                capsule_type, WT_CLOSE_SESSION,
                                "capsule type must be 0x2843 (buffer {})",
                                hex::encode(&capsule_buf)
                            );
                            // Then decode with the rtx-webtransport capsule API
                            // (web-transport-proto encode -> rtx decode).
                            let (capsule, _) = RtxCapsule::decode(payload, MAX_CLOSE_MESSAGE_LEN + 4)
                                .unwrap_or_else(|e| {
                                    panic!(
                                        "close capsule decode: {:?} (buffer {})",
                                        e,
                                        hex::encode(&capsule_buf)
                                    )
                                });
                            match capsule {
                                RtxCapsule::CloseSession { code, message } => {
                                    assert_eq!(code, CLOSE_CODE, "close capsule error code");
                                    assert_eq!(message, CLOSE_REASON, "close capsule message");
                                    close_received = Some((code, message.to_string()));
                                }
                                other => panic!(
                                    "expected CloseSession capsule, got {:?} (buffer {})",
                                    other,
                                    hex::encode(&capsule_buf)
                                ),
                            }
                            // Release the client to close: the server has the
                            // capsule in hand and asserted it.
                            if let Some(tx) = server_got_close_tx.take() {
                                let _ = tx.send(());
                            }
                        }
                        Ok(None) => {}
                        Err(e) => panic!(
                            "close DATA frame decode failed: {} (buffer {})",
                            e,
                            hex::encode(&capsule_buf)
                        ),
                    }
                }
            }

            if client_outcome.is_none() {
                if let Some(chan) = client_rx.as_mut() {
                    if let Ok(res) = chan.try_recv() {
                        client_outcome = Some(res);
                    }
                }
            }

            // Teardown: server close once the capsule was received and the
            // client is done; idempotent when the client's CONNECTION_CLOSE
            // already drained the connection.
            if response_written && close_received.is_some() && client_outcome.is_some() && !close_sent
            {
                let _ = rtx.close(cid, now(), 0, b"h3-session-close-once");
                close_sent = true;
            }

            if close_received.is_some() && client_outcome.is_some() && rtx_closed {
                break;
            }

            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;

    match outcome {
        Ok(()) => {}
        Err(_) => panic!(
            "h3 session close timed out (10s): handshake=({},{}) client_settings={} \
             server_ctrl={} connect_fields={} response_written={} close_received={} \
             client_outcome={} rtx_closed={} ctrl_buf={} connect_buf={} capsule_buf={}",
            rtx_handshake,
            quinn_handshake,
            client_settings.is_some(),
            server_ctrl.is_some(),
            connect_fields.is_some(),
            response_written,
            close_received.is_some(),
            client_outcome.is_some(),
            rtx_closed,
            hex::encode(&ctrl_buf),
            hex::encode(&connect_buf),
            hex::encode(&capsule_buf),
        ),
    }

    assert!(rtx_handshake, "rtx-quic server did not complete handshake");
    assert!(quinn_handshake, "quinn client did not complete handshake");

    // (c) Server-side SETTINGS assertions.
    let settings = client_settings.expect("server did not decode client SETTINGS");
    assert_eq!(
        settings.enable_connect_protocol(),
        Some(1),
        "ENABLE_CONNECT_PROTOCOL (0x08)"
    );
    assert_eq!(settings.h3_datagram(), Some(1), "H3_DATAGRAM (0x33)");
    assert_eq!(
        settings.webtransport_max_sessions(),
        Some(1),
        "WEBTRANSPORT_MAX_SESSIONS (0xc671706a)"
    );

    // (g) Server-side CONNECT assertions.
    let (scheme, authority, path, protocol) =
        connect_fields.expect("server did not decode CONNECT");
    assert_eq!(scheme, "https", ":scheme");
    assert_eq!(authority, "localhost", ":authority");
    assert_eq!(path, "/session", ":path");
    assert_eq!(protocol, "webtransport", ":protocol");
    let raw_session = session_id.expect("server did not derive a session id");
    let session = SessionId::new(raw_session).expect("CONNECT stream id is a valid session id");
    assert_eq!(
        session.get(),
        0,
        "session-0 precondition: this test covers session ID 0 only"
    );

    // (h) The full 200 went out on the unfinished CONNECT stream.
    assert!(response_written, "server did not write the full 200 response");

    // (e)+(i)+(close) Client-side assertions.
    let client = match client_outcome.expect("client outcome missing") {
        Ok(client) => client,
        Err(e) => panic!("quinn client H3 + close steps failed: {}", e),
    };
    assert_ne!(
        client.supports_wt, 0,
        "server SETTINGS did not indicate WebTransport support"
    );
    assert_eq!(client.status, 200, "CONNECT response status");
    assert_eq!(
        client.session_id, 0,
        "quinn-side full session ID (session-0 only)"
    );
    // The close wire is the full DATA frame: [0x00 = DATA, length, ... capsule
    // bytes]. The capsule starts with varint(0x2843) = [0x68, 0x43]
    // (web-transport-proto capsule.rs:354-355) right after the two-byte DATA
    // frame header, so it sits at offsets [2..4].
    assert_eq!(client.close_wire[0], 0x00, "close wire begins with H3 DATA frame type");
    assert_eq!(
        &client.close_wire[2..4],
        &[0x68, 0x43],
        "capsule type varint 0x2843 in the close wire"
    );
    assert_eq!(
        capsule_buf, client.close_wire,
        "close capsule DATA frame arrived exactly as the quinn side framed it"
    );

    // (close) Server-side close assertions.
    let (code, message) = close_received.expect("server received no close capsule");
    assert_eq!(code, CLOSE_CODE, "CLOSE_WEBTRANSPORT_SESSION error code");
    assert_eq!(message, CLOSE_REASON, "CLOSE_WEBTRANSPORT_SESSION message");
    assert!(rtx_closed, "rtx connection did not report closed");

    println!(
        "H3 SESSION CLOSE ok: session_id=0 capsule_type={:#x} code={} message={:?} \
         connect={}://{}{} protocol={} status={}, close_wire={} bytes received and asserted",
        WT_CLOSE_SESSION,
        code,
        message,
        scheme,
        authority,
        path,
        protocol,
        client.status,
        client.close_wire.len(),
    );
}