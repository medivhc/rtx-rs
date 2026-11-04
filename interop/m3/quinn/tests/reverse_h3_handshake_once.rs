//! One-shot H3/WebTransport handshake, REVERSE direction: rtx-quic client
//! (rtx-h3 codec) <-> quinn server manually driven with the web-transport-proto
//! codec. Exact role swap of `h3_handshake_once.rs` (H3-PROBE.md section 4
//! closing note: steps 2-9 with the sides exchanged).
//!
//! Scope: QUIC handshake on ALPN `h3`, SETTINGS exchange on the two control
//! streams, extended CONNECT on a bi stream, and the 200 response. No
//! datagrams, no WT data streams, no session-close capsules: the CONNECT stream
//! is deliberately left unfinished the way a real WT session keeps it open for
//! capsules (the quinn stream halves are held in `ServerOutcome` so dropping
//! them cannot implicitly finish the stream mid-test).

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use quinn::{Endpoint as QuinnEndpoint, ServerConfig as QuinnServerConfig, rustls};
use rcgen;
use rtx_core::{IpAddr as RtxIpAddr, SocketAddr as RtxSocketAddr, Timestamp};
use rtx_h3::connect::{
    ConnectRequest as RtxConnectRequest, ConnectResponse as RtxConnectResponse,
};
use rtx_h3::settings::{
    Settings as RtxSettings, SETTINGS_ENABLE_CONNECT_PROTOCOL, SETTINGS_H3_DATAGRAM,
    SETTINGS_WEBTRANSPORT_MAX_SESSIONS,
};
use rtx_quic::{
    ConnectionId, Endpoint as RtxEndpoint, EndpointConfig, EventKind, StreamId, StreamRead,
};
use rtx_webtransport::ids::SessionId;
use rtx_wire::h3_frame::Frame as H3Frame;
use rtx_wire::{varint, Decode, Encode, WireError};
use tokio::net::UdpSocket;
use web_transport_proto::{ConnectRequest, ConnectResponse, Settings};

const ALPN: &[u8] = b"h3";
/// H3 unidirectional stream type CONTROL (`RFC 9114` section 6.2).
const STREAM_TYPE_CONTROL: u64 = 0x00;
/// H3 frame type HEADERS (`RFC 9114` section 7.2.1).
const FRAME_TYPE_HEADERS: u64 = 0x01;
/// H3 frame type SETTINGS (`RFC 9114` section 7.2.4).
const FRAME_TYPE_SETTINGS: u64 = 0x04;
/// Legacy `WEBTRANSPORT_MAX_SESSIONS` id (draft-webtrans-http3-06). The rtx
/// decoder stores it as an unknown id; recorded, never asserted.
const LEGACY_WT_MAX_SESSIONS: u64 = 0x2b60_3743;
const SESSION_SCHEME: &str = "https";
const SESSION_AUTHORITY: &str = "localhost";
const SESSION_PATH: &str = "/session";
const SESSION_PROTOCOL: &str = "webtransport";

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

/// What the quinn server task reports after driving its H3 steps. The four
/// stream halves are held (not dropped) so quinn's implicit `finish()` on a
/// dropped `SendStream` (quinn/src/send_stream.rs:355-375) cannot finish the
/// CONNECT stream or the control streams while the exchange is asserted.
struct ServerOutcome {
    /// `supports_webtransport()` decoded from the client SETTINGS.
    supports_wt: u64,
    /// Raw QUIC stream id of the accepted CONNECT bi stream.
    connect_stream_id: u64,
    /// `:scheme` of the decoded CONNECT request.
    scheme: String,
    /// `:authority` of the decoded CONNECT request.
    authority: String,
    /// `:path` of the decoded CONNECT request.
    path: String,
    _client_ctrl: quinn::RecvStream,
    _server_ctrl: quinn::SendStream,
    _connect_send: quinn::SendStream,
    _connect_recv: quinn::RecvStream,
}

/// Decodes `varint(CONTROL) + Frame(SETTINGS) + payload` from the accumulated
/// server control-stream bytes. `Ok(None)` means the buffer does not hold a
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
/// returns its payload. `Ok(None)` means the frame is not fully buffered yet.
fn decode_headers_payload(buf: &[u8]) -> Result<Option<&[u8]>, String> {
    let (frame, _) = match H3Frame::decode(buf) {
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
    Ok(Some(frame.payload()))
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

/// Client SETTINGS (step b, mirroring the forward test's server reply):
/// `varint(CONTROL) + Frame(SETTINGS){0x08=1, 0x33=1, 0xc671706a=1}`. No
/// legacy ids: the rtx encoder whitelist refuses them and the quinn-side
/// `supports_webtransport()` does not need them.
fn encode_client_settings() -> Vec<u8> {
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

/// Extended CONNECT (step f): `Frame(HEADERS){ :method CONNECT, :scheme,
/// :authority, :path, :protocol }` for `https://localhost/session`.
fn encode_connect_request() -> Vec<u8> {
    let request = RtxConnectRequest::new(
        SESSION_SCHEME,
        SESSION_AUTHORITY,
        SESSION_PATH,
        SESSION_PROTOCOL,
    );
    let mut payload = vec![0u8; request.encoded_len()];
    let n = request.encode(&mut payload).expect("request encode");
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
async fn reverse_h3_handshake_once() {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate cert");
    let cert_der = certified.cert.der().to_vec();
    let key_der = certified.key_pair.serialize_der();

    // quinn server: rcgen self-signed localhost cert, ALPN h3, listen 127.0.0.1:0
    // (reverse_bi_stream_once skeleton).
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(cert_der.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.clone())),
    )
    .unwrap();
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quinn_server_config = QuinnServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
    ));
    let quinn_server = QuinnEndpoint::server(
        quinn_server_config,
        "127.0.0.1:0".parse().expect("bind addr"),
    )
    .expect("quinn server");
    let quinn_server_addr = quinn_server.local_addr().expect("quinn server addr");

    // rtx client: trust the self-signed cert, ALPN h3.
    let rtx_client = RtxEndpoint::new(
        EndpointConfig::new()
            .with_alpn(vec![ALPN.to_vec()])
            .with_client_roots(vec![cert_der.clone()]),
    )
    .expect("rtx client endpoint");

    let rtx_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind rtx socket");

    let start = std::time::Instant::now();
    let now = || Timestamp::from_micros(1_000_000 + start.elapsed().as_micros() as u64);

    let mut rtx = rtx_client;
    let cid: ConnectionId = rtx
        .connect(now(), rtx_addr(quinn_server_addr), "localhost")
        .expect("rtx connect");

    // Spawn quinn server accept: incoming -> Connection drives the quinn side.
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    let server = quinn_server.clone();
    tokio::spawn(async move {
        let res = match server.accept().await {
            Some(incoming) => incoming.await,
            None => Err(quinn::ConnectionError::LocallyClosed),
        };
        let _ = tx.send(res);
    });

    let mut rtx_handshake = false;
    let mut quinn_handshake = false;
    let mut quinn_conn: Option<quinn::Connection> = None;
    let mut server_rx: Option<tokio::sync::oneshot::Receiver<Result<ServerOutcome, String>>> = None;

    // Client-side H3 state machine (rtx, sans-IO pump).
    let mut ctrl_stream: Option<StreamId> = None;
    let mut ctrl_pending: Option<Vec<u8>> = None;
    let mut ctrl_written = false;
    let mut server_ctrl: Option<StreamId> = None;
    let mut server_ctrl_buf: Vec<u8> = Vec::new();
    let mut server_settings: Option<RtxSettings> = None;
    let mut connect_stream: Option<StreamId> = None;
    let mut connect_pending: Option<Vec<u8>> = None;
    let mut connect_written = false;
    let mut response_buf: Vec<u8> = Vec::new();
    let mut response_status: Option<u16> = None;
    let mut server_outcome: Option<Result<ServerOutcome, String>> = None;
    let mut close_sent = false;
    let mut rtx_closed = false;

    // One 10s budget for the whole test: handshake + H3 exchange + close.
    let outcome = tokio::time::timeout(Duration::from_secs(10), async {
        // Phase 1: QUIC handshake (reverse_bi_stream_once skeleton).
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
                        Err(e) => panic!("quinn server handshake failed: {:?}", e),
                    }
                }
            }

            if rtx_handshake && quinn_handshake {
                break;
            }

            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        // The main test keeps `qconn` alive until the whole exchange is done:
        // dropping the only quinn Connection handle would implicitly close the
        // server side and the client would get UnknownConnection (step-10
        // lesson). The server task only gets a clone.
        let qconn = quinn_conn.take().expect("quinn connection");

        // Spawn the quinn server: steps c, d, g, h, then report (step j closes
        // from the main test once both sides are done).
        let (stx, srx) = tokio::sync::oneshot::channel();
        server_rx = Some(srx);
        let qconn_task = qconn.clone();
        tokio::spawn(async move {
            let result: Result<ServerOutcome, String> = async {
                // (c) Client SETTINGS arrive on the first accepted uni stream
                // (the client control stream; no other uni stream exists).
                let mut client_ctrl = qconn_task
                    .accept_uni()
                    .await
                    .map_err(|e| format!("accept_uni: {:?}", e))?;
                let client_settings = Settings::read(&mut client_ctrl)
                    .await
                    .map_err(|e| format!("client SETTINGS read: {:?}", e))?;
                let supports_wt = client_settings.supports_webtransport();

                // (d) Server SETTINGS reply on our first uni stream: default +
                // enable_webtransport(1) writes CONTROL 0x00 + Frame(SETTINGS)
                // with the 6 id/value pairs, same as the forward test's (b).
                let mut settings = Settings::default();
                settings.enable_webtransport(1);
                let mut server_ctrl = qconn_task
                    .open_uni()
                    .await
                    .map_err(|e| format!("open_uni: {:?}", e))?;
                settings
                    .write(&mut server_ctrl)
                    .await
                    .map_err(|e| format!("server SETTINGS write: {:?}", e))?;

                // (g) Extended CONNECT arrives on the first bi stream.
                let (mut send, mut recv) = qconn_task
                    .accept_bi()
                    .await
                    .map_err(|e| format!("accept_bi: {:?}", e))?;
                let connect_stream_id = u64::from(recv.id());
                let request = ConnectRequest::read(&mut recv)
                    .await
                    .map_err(|e| format!("CONNECT read: {:?}", e))?;
                // A successful read proves `:protocol` was `webtransport`:
                // decode_headers rejects anything else with WrongProtocol
                // (web-transport-proto connect.rs:161-164).
                let scheme = request.url.scheme().to_string();
                let authority = request.url.authority().to_string();
                let path = request.url.path().to_string();

                // (h) 200 on the same bi stream, deliberately NOT finished: a
                // real WT session keeps the CONNECT stream open for capsules.
                let response = ConnectResponse::OK;
                response
                    .write(&mut send)
                    .await
                    .map_err(|e| format!("CONNECT response write: {:?}", e))?;

                Ok(ServerOutcome {
                    supports_wt,
                    connect_stream_id,
                    scheme,
                    authority,
                    path,
                    _client_ctrl: client_ctrl,
                    _server_ctrl: server_ctrl,
                    _connect_send: send,
                    _connect_recv: recv,
                })
            }
            .await;
            let _ = stx.send(result);
        });

        // Phase 2: pump the rtx client through the H3 exchange.
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
                    EventKind::HandshakeFailed(e) => panic!("rtx handshake failed: {:?}", e),
                    EventKind::Closed(_) => {
                        rtx_closed = true;
                    }
                    _ => {}
                }
            }

            // (b) Client control stream: open right after the handshake and
            // write SETTINGS; left unfinished like a real H3 control stream.
            if ctrl_stream.is_none() {
                match rtx.open_uni(cid) {
                    Ok(stream) => {
                        ctrl_stream = Some(stream);
                        ctrl_pending = Some(encode_client_settings());
                    }
                    Err(e) => panic!("open_uni (client control) error: {:?}", e),
                }
            }
            if let (Some(stream), Some(pending)) = (ctrl_stream, ctrl_pending.as_mut()) {
                drain_pending(&mut rtx, cid, stream, pending);
                if pending.is_empty() {
                    ctrl_written = true;
                }
            }

            // (e) Server SETTINGS from the first accepted uni stream.
            if server_ctrl.is_none() {
                match rtx.accept_uni(cid) {
                    Ok(Some(s)) => server_ctrl = Some(s),
                    Ok(None) => {}
                    Err(e) => panic!("accept_uni error: {:?}", e),
                }
            }
            if server_settings.is_none() {
                if let Some(stream) = server_ctrl {
                    let mut read_buf = [0u8; 65535];
                    loop {
                        match rtx.read_stream(cid, stream, &mut read_buf) {
                            Ok(StreamRead::Data { len }) => {
                                server_ctrl_buf.extend_from_slice(&read_buf[..len]);
                            }
                            Ok(StreamRead::Finished) => break,
                            Err(rtx_quic::StreamError::Blocked) => break,
                            Err(e) => panic!("read server control stream error: {:?}", e),
                        }
                    }
                    match decode_control_settings(&server_ctrl_buf) {
                        Ok(Some(settings)) => server_settings = Some(settings),
                        Ok(None) => {}
                        Err(e) => panic!(
                            "server SETTINGS decode failed: {} (buffer {})",
                            e,
                            hex::encode(&server_ctrl_buf)
                        ),
                    }
                }
            }

            // (f) Extended CONNECT on a fresh bi stream once the server
            // SETTINGS are in (web-transport-quinn ordering: settings
            // exchange, then CONNECT).
            if server_settings.is_some() && connect_stream.is_none() {
                match rtx.open_bi(cid) {
                    Ok(stream) => {
                        connect_stream = Some(stream);
                        connect_pending = Some(encode_connect_request());
                    }
                    Err(e) => panic!("open_bi (CONNECT) error: {:?}", e),
                }
            }
            if let (Some(stream), Some(pending)) = (connect_stream, connect_pending.as_mut()) {
                drain_pending(&mut rtx, cid, stream, pending);
                if pending.is_empty() {
                    connect_written = true;
                }
            }

            // (i) The 200 response on the same bi stream. The stream is never
            // finished by the server, so decode from the accumulated bytes.
            if response_status.is_none() {
                if let Some(stream) = connect_stream {
                    let mut read_buf = [0u8; 65535];
                    loop {
                        match rtx.read_stream(cid, stream, &mut read_buf) {
                            Ok(StreamRead::Data { len }) => {
                                response_buf.extend_from_slice(&read_buf[..len]);
                            }
                            Ok(StreamRead::Finished) => break,
                            Err(rtx_quic::StreamError::Blocked) => break,
                            Err(e) => panic!("read CONNECT stream error: {:?}", e),
                        }
                    }
                    let mut decoded = None;
                    match decode_headers_payload(&response_buf) {
                        Ok(Some(payload)) => {
                            let response = RtxConnectResponse::decode(payload).unwrap_or_else(|e| {
                                panic!(
                                    "CONNECT response decode failed: {:?} (buffer {})",
                                    e,
                                    hex::encode(&response_buf)
                                )
                            });
                            decoded = Some(response.status());
                        }
                        Ok(None) => {}
                        Err(e) => panic!(
                            "CONNECT response frame decode failed: {} (buffer {})",
                            e,
                            hex::encode(&response_buf)
                        ),
                    }
                    if let Some(status) = decoded {
                        response_status = Some(status);
                    }
                }
            }

            if server_outcome.is_none() {
                if let Some(chan) = server_rx.as_mut() {
                    if let Ok(res) = chan.try_recv() {
                        server_outcome = Some(res);
                    }
                }
            }

            // (j) Client close once the response is in and the server task has
            // reported; idempotent. The Closed event fires synchronously
            // (rtx-quic endpoint.rs close()) and the next pump round flushes
            // the CONNECTION_CLOSE datagram before the loop breaks.
            if response_status.is_some() && server_outcome.is_some() && !close_sent {
                let _ = rtx.close(cid, now(), 0, b"reverse-h3-handshake-once");
                close_sent = true;
            }

            if close_sent && rtx_closed {
                break;
            }

            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        // (j) Close the quinn side too; idempotent when the client's
        // CONNECTION_CLOSE already drained the connection. The server task has
        // reported by now, so its stream halves live in `server_outcome` and
        // dropping them after this close is inert. `qconn` is the handle the
        // main test held for the whole exchange (step-10 lesson).
        qconn.close(quinn::VarInt::from_u32(0), b"reverse-h3-handshake-once");
    })
    .await;

    match outcome {
        Ok(()) => {}
        Err(_) => panic!(
            "reverse h3 handshake timed out (10s): handshake=({},{}) ctrl_written={} \
             server_settings={} connect_written={} response_status={} server_outcome={} \
             close_sent={} rtx_closed={} server_ctrl_buf={} response_buf={}",
            rtx_handshake,
            quinn_handshake,
            ctrl_written,
            server_settings.is_some(),
            connect_written,
            response_status.is_some(),
            server_outcome.is_some(),
            close_sent,
            rtx_closed,
            hex::encode(&server_ctrl_buf),
            hex::encode(&response_buf),
        ),
    }

    assert!(rtx_handshake, "rtx-quic client did not complete handshake");
    assert!(quinn_handshake, "quinn server did not complete handshake");

    // (b) The full client SETTINGS went out on the unfinished control stream.
    assert!(ctrl_written, "rtx client did not write the full SETTINGS");

    // (e) Client-side SETTINGS assertions.
    let settings = server_settings.expect("client did not decode server SETTINGS");
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
    // Legacy draft-06 values quinn's enable_webtransport(1) also emits:
    // recorded, not gated (rtx-h3 decodes them but never re-encodes them).
    println!(
        "server SETTINGS legacy values: 0xffd277={:?} 0x2b603742={:?} 0x2b603743={:?}",
        settings.deprecated_h3_datagram(),
        settings.deprecated_webtransport_enable(),
        settings
            .iter()
            .find(|s| s.id() == LEGACY_WT_MAX_SESSIONS)
            .map(|s| s.value())
    );

    // (f) The full CONNECT request went out on the unfinished bi stream, which
    // is the first client-initiated bi stream (raw id 0 => SessionId 0).
    assert!(connect_written, "rtx client did not write the full CONNECT");
    let raw_session = connect_stream.expect("client did not open a CONNECT stream").as_u64();
    assert_eq!(raw_session, 0, "CONNECT stream must be bi stream id 0");
    let session = SessionId::new(raw_session).expect("CONNECT stream id is a valid session id");
    assert_eq!(session.get(), raw_session);

    // (i) Client-side 200 assertion.
    let status = response_status.expect("client did not decode the CONNECT response");
    assert_eq!(status, 200, "CONNECT response status");

    // (c)+(d)+(g)+(h) Server-side assertions.
    match server_outcome.expect("server outcome missing") {
        Ok(server) => {
            assert_ne!(
                server.supports_wt, 0,
                "client SETTINGS did not indicate WebTransport support"
            );
            assert_eq!(
                server.connect_stream_id, 0,
                "quinn server must accept CONNECT on bi stream id 0"
            );
            assert_eq!(server.scheme, SESSION_SCHEME, ":scheme");
            assert_eq!(server.authority, SESSION_AUTHORITY, ":authority");
            assert_eq!(server.path, SESSION_PATH, ":path");
            // :protocol == webtransport was enforced by ConnectRequest::read
            // succeeding (WrongProtocol otherwise).
            println!(
                "REVERSE H3 HANDSHAKE ok: supports_webtransport={} connect={}://{}{} \
                 protocol={} session_id={} status={}",
                server.supports_wt,
                server.scheme,
                server.authority,
                server.path,
                SESSION_PROTOCOL,
                session.get(),
                status
            );
        }
        Err(e) => panic!("quinn server H3 steps failed: {}", e),
    }
    assert!(rtx_closed, "rtx connection did not report closed");
}
