//! Reverse one-shot QUIC bidirectional stream: rtx-quic client sends a request,
//! quinn server replies, rtx-quic client reads the response to end.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use quinn::{Endpoint as QuinnEndpoint, ServerConfig as QuinnServerConfig, rustls};
use rcgen;
use rtx_core::{IpAddr as RtxIpAddr, SocketAddr as RtxSocketAddr, Timestamp};
use rtx_quic::{
    ConnectionId, Endpoint as RtxEndpoint, EndpointConfig, EventKind, StreamError, StreamRead,
};
use tokio::net::UdpSocket;

const ALPN: &[u8] = b"h3";
const PAYLOAD: &[u8] = b"reverse-bi-stream-once";
const RESPONSE: &[u8] = b"reverse-bi-response";

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

#[tokio::test]
async fn reverse_bi_stream_once() {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate cert");
    let cert_der = certified.cert.der().to_vec();
    let key_der = certified.key_pair.serialize_der();

    // quinn server: rcgen self-signed localhost cert, ALPN h3, listen 127.0.0.1:0.
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

    // Phase 1: handshake
    let hs = tokio::time::timeout(Duration::from_secs(10), async {
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
    })
    .await;

    match hs {
        Ok(()) => {}
        Err(_) => panic!("handshake timed out"),
    }
    assert!(rtx_handshake, "rtx-quic client did not complete handshake");
    assert!(quinn_handshake, "quinn server did not complete handshake");

    let qconn = quinn_conn.expect("quinn connection");

    // Phase 2: rtx-quic client opens exactly one bi stream.
    let stream = rtx.open_bi(cid).expect("rtx open_bi");

    // Spawn quinn server: accept_bi, read the request to end (FIN), write the
    // response, finish the send side, report the request bytes. The main task
    // keeps `qconn` alive until the round trip completes: dropping the last
    // quinn Connection handle would implicitly close the server side.
    let (stx, mut srx) = tokio::sync::oneshot::channel();
    let qconn_task = qconn.clone();
    tokio::spawn(async move {
        let res = match qconn_task.accept_bi().await {
            Ok((mut send, mut recv)) => match recv.read_to_end(64 * 1024).await {
                Ok(request) => match send.write_all(RESPONSE).await {
                    Ok(()) => match send.finish() {
                        Ok(()) => Ok(request),
                        Err(e) => Err(format!("quinn finish failed: {:?}", e)),
                    },
                    Err(e) => Err(format!("quinn write_all failed: {:?}", e)),
                },
                Err(e) => Err(format!("quinn read_to_end failed: {:?}", e)),
            },
            Err(e) => Err(format!("quinn accept_bi failed: {:?}", e)),
        };
        let _ = stx.send(res);
    });

    // Phase 3: write the request (retrying short writes), finish the send side,
    // read the response via read_stream, and pump until both sides are done.
    let mut written = 0usize;
    let mut send_finished = false;
    let mut response: Vec<u8> = Vec::new();
    let mut response_finished = false;
    let mut server_request: Option<Vec<u8>> = None;

    let roundtrip = tokio::time::timeout(Duration::from_secs(10), async {
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
                    _ => {}
                }
            }

            if !send_finished {
                match rtx.write_stream(cid, stream, &PAYLOAD[written..]) {
                    Ok(n) => written += n,
                    Err(StreamError::Blocked) => {}
                    Err(e) => panic!("rtx write_stream error: {:?}", e),
                }
                if written == PAYLOAD.len() {
                    rtx.finish_stream(cid, stream)
                        .expect("rtx finish_stream");
                    send_finished = true;
                }
            }

            if !response_finished {
                let mut read_buf = [0u8; 65535];
                loop {
                    match rtx.read_stream(cid, stream, &mut read_buf) {
                        Ok(StreamRead::Data { len }) => {
                            response.extend_from_slice(&read_buf[..len]);
                        }
                        Ok(StreamRead::Finished) => {
                            response_finished = true;
                        }
                        Err(StreamError::Blocked) => break,
                        Err(e) => panic!("rtx read_stream error: {:?}", e),
                    }
                    if response_finished {
                        break;
                    }
                }
            }

            if server_request.is_none() {
                if let Ok(res) = srx.try_recv() {
                    match res {
                        Ok(request) => server_request = Some(request),
                        Err(e) => panic!("quinn server bi exchange failed: {}", e),
                    }
                }
            }

            if server_request.is_some() && response_finished {
                break;
            }

            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;

    match roundtrip {
        Ok(()) => {}
        Err(_) => panic!("reverse bi stream round trip timed out"),
    }

    assert!(send_finished, "rtx client did not finish its send side");
    assert!(response_finished, "rtx client did not read the response FIN");
    let request = server_request.expect("quinn server did not complete the bi exchange");
    assert_eq!(request, PAYLOAD, "quinn server request mismatch");
    assert_eq!(response, RESPONSE, "rtx client response mismatch");
    println!(
        "reverse BI STREAM round trip: request {} bytes, response {} bytes, payload matches",
        request.len(),
        response.len()
    );
}
