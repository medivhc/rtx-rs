//! One-shot H3/WebTransport handshake: quinn client (web-transport-proto
//! codec) <-> rtx-quic server (rtx-h3 codec), forward direction only.
//!
//! Scope (H3-PROBE.md section 4 steps 1-10): QUIC handshake on ALPN `h3`,
//! SETTINGS exchange on the two control streams, extended CONNECT on a bi
//! stream, and the 200 response. No datagrams, no WT data streams, no
//! session-close capsules: the CONNECT stream is deliberately left unfinished
//! the way a real WT session keeps it open for capsules.

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
use rtx_webtransport::ids::SessionId;
use rtx_wire::h3_frame::Frame as H3Frame;
use rtx_wire::{varint, Decode, Encode, WireError};
use tokio::net::UdpSocket;
use url::Url;
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
const SESSION_URL: &str = "https://localhost/session";

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

/// What the quinn client task reports after driving its H3 steps.
struct ClientOutcome {
    /// `supports_webtransport()` decoded from the server SETTINGS reply.
    supports_wt: u64,
    /// `:status` of the CONNECT response.
    status: u16,
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

/// Server SETTINGS reply: `varint(CONTROL) + Frame(SETTINGS){0x08=1, 0x33=1,
/// 0xc671706a=1}`. No legacy ids: the rtx encoder whitelist refuses them and
/// the quinn-side `supports_webtransport()` does not need them.
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
async fn h3_handshake_once() {
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

    // Server-side H3 state machine.
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
    let mut client_outcome: Option<Result<ClientOutcome, String>> = None;
    let mut close_sent = false;
    let mut rtx_closed = false;

    // One 10s budget for the whole test: handshake + H3 exchange + close.
    let outcome = tokio::time::timeout(Duration::from_secs(10), async {
        // Phase 1: QUIC handshake (bi_stream_once skeleton).
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

        // Spawn the quinn client: steps b, e, f, i, then close (step j).
        let (client_tx, result_rx) = tokio::sync::oneshot::channel();
        client_rx = Some(result_rx);
        tokio::spawn(async move {
            let result: Result<ClientOutcome, String> = async {
                // (b) Client SETTINGS: default + enable_webtransport(1) writes
                // CONTROL 0x00 + Frame(SETTINGS) with the 6 id/value pairs.
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

                // (f) Extended CONNECT on a new bi stream (HEADERS frame with
                // the 5 pseudo-headers).
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

                // (i) The 200 response on the same bi stream.
                let response = ConnectResponse::read(&mut recv)
                    .await
                    .map_err(|e| format!("CONNECT response read: {:?}", e))?;
                Ok(ClientOutcome {
                    supports_wt,
                    status: response.status.as_u16(),
                })
            }
            .await;
            // (j) Close the client side. The server has fully processed both
            // streams by now, so quinn's implicit finish() when the dropped
            // send halves go away (quinn/src/send_stream.rs:355-375) is inert.
            qconn.close(quinn::VarInt::from_u32(0), b"h3-handshake-once");
            let _ = client_tx.send(result);
        });

        // Phase 2: pump the rtx server through the H3 exchange.
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
                    match decode_headers_payload(&connect_buf) {
                        Ok(Some(payload)) => {
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

            if client_outcome.is_none() {
                if let Some(chan) = client_rx.as_mut() {
                    if let Ok(res) = chan.try_recv() {
                        client_outcome = Some(res);
                    }
                }
            }

            // (j) Server close once the client is done; idempotent when the
            // client's CONNECTION_CLOSE already drained the connection.
            if response_written && client_outcome.is_some() && !close_sent {
                let _ = rtx.close(cid, now(), 0, b"h3-handshake-once");
                close_sent = true;
            }

            if client_outcome.is_some() && rtx_closed {
                break;
            }

            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;

    match outcome {
        Ok(()) => {}
        Err(_) => panic!(
            "h3 handshake timed out (10s): handshake=({},{}) client_settings={} server_ctrl={} \
             connect_fields={} response_written={} client_outcome={} rtx_closed={} \
             ctrl_buf={} connect_buf={}",
            rtx_handshake,
            quinn_handshake,
            client_settings.is_some(),
            server_ctrl.is_some(),
            connect_fields.is_some(),
            response_written,
            client_outcome.is_some(),
            rtx_closed,
            hex::encode(&ctrl_buf),
            hex::encode(&connect_buf),
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
    // Legacy draft-06 values quinn's enable_webtransport(1) also emits:
    // recorded, not gated (rtx-h3 decodes them but never re-encodes them).
    println!(
        "client SETTINGS legacy values: 0xffd277={:?} 0x2b603742={:?} 0x2b603743={:?}",
        settings.deprecated_h3_datagram(),
        settings.deprecated_webtransport_enable(),
        settings
            .iter()
            .find(|s| s.id() == LEGACY_WT_MAX_SESSIONS)
            .map(|s| s.value())
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
    assert_eq!(session.get(), raw_session);

    // (h) The full 200 went out on the unfinished CONNECT stream.
    assert!(response_written, "server did not write the full 200 response");

    // (e)+(i) Client-side assertions.
    match client_outcome.expect("client outcome missing") {
        Ok(client) => {
            assert_ne!(
                client.supports_wt, 0,
                "server SETTINGS did not indicate WebTransport support"
            );
            assert_eq!(client.status, 200, "CONNECT response status");
            println!(
                "H3 HANDSHAKE ok: supports_webtransport={} connect={}://{}{} protocol={} \
                 session_id={} status={}",
                client.supports_wt, scheme, authority, path, protocol, session.get(), client.status
            );
        }
        Err(e) => panic!("quinn client H3 steps failed: {}", e),
    }
    assert!(rtx_closed, "rtx connection did not report closed");
}
