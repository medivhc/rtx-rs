//! One-shot QUIC unidirectional stream receive: quinn client sends, rtx-quic server receives.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use rtx_core::{IpAddr as RtxIpAddr, SocketAddr as RtxSocketAddr, Timestamp};
use rtx_quic::{ConnectionId, Endpoint as RtxEndpoint, EndpointConfig, EventKind, StreamId, StreamRead};
use quinn::{ClientConfig, Endpoint as QuinnEndpoint, rustls};
use quinn::rustls::pki_types::CertificateDer;
use quinn::rustls::RootCertStore;
use rcgen;
use tokio::net::UdpSocket;

const ALPN: &[u8] = b"h3";
const PAYLOAD: &[u8] = b"uni-stream-once-payload";

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
async fn uni_stream_once() {
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
    })
    .await;

    match hs {
        Ok(()) => {}
        Err(_) => panic!("handshake timed out"),
    }
    assert!(rtx_handshake, "rtx-quic server did not complete handshake");
    assert!(quinn_handshake, "quinn client did not complete handshake");

    let cid = rtx_conn.expect("rtx connection id");
    let qconn = quinn_conn.expect("quinn connection");

    // Spawn quinn client: open uni, write payload, finish.
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
    let qconn_clone = qconn.clone();
    tokio::spawn(async move {
        let mut send = qconn_clone.open_uni().await.expect("quinn open_uni");
        send.write_all(PAYLOAD).await.expect("quinn write_all");
        send.finish().expect("quinn finish");
        let _ = done_tx.send(());
    });

    // Phase 2: pump until rtx receives the uni stream and its data.
    let mut rtx_stream: Option<StreamId> = None;
    let mut received: Vec<u8> = Vec::new();
    let mut finished = false;
    let recv_outcome = tokio::time::timeout(Duration::from_secs(10), async {
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
                    EventKind::Closed(_) => {}
                    EventKind::Stream(_) => {}
                    _ => {}
                }
            }

            if rtx_stream.is_none() {
                match rtx.accept_uni(cid) {
                    Ok(Some(s)) => rtx_stream = Some(s),
                    Ok(None) => {}
                    Err(e) => panic!("accept_uni error: {:?}", e),
                }
            }

            if let Some(stream) = rtx_stream {
                let mut read_buf = [0u8; 65535];
                loop {
                    match rtx.read_stream(cid, stream, &mut read_buf) {
                        Ok(StreamRead::Data { len }) => {
                            received.extend_from_slice(&read_buf[..len]);
                        }
                        Ok(StreamRead::Finished) => {
                            finished = true;
                            // drain any? finished means all delivered
                        }
                        Err(rtx_quic::StreamError::Blocked) => break,
                        Err(e) => panic!("read_stream error: {:?}", e),
                    }
                    if finished {
                        break;
                    }
                }
            }

            if finished && received.len() >= PAYLOAD.len() {
                break;
            }

            // also pump quinn completion not needed
            let _ = done_rx.try_recv();

            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;

    match recv_outcome {
        Ok(()) => {}
        Err(_) => panic!("uni stream receive timed out"),
    }

    assert!(rtx_stream.is_some(), "rtx did not accept uni stream");
    assert!(finished, "rtx did not observe stream finish");
    assert_eq!(received, PAYLOAD, "received payload mismatch");
    println!("UNI STREAM received: {} bytes, payload matches", received.len());
}