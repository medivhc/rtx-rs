//! Reverse loopback QUIC handshake: rtx-quic client -> quinn server.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use quinn::{Endpoint as QuinnEndpoint, ServerConfig as QuinnServerConfig, rustls};
use rcgen;
use rtx_core::{IpAddr as RtxIpAddr, SocketAddr as RtxSocketAddr, Timestamp};
use rtx_quic::{Endpoint as RtxEndpoint, EndpointConfig, EventKind};
use tokio::net::UdpSocket;

const ALPN: &[u8] = b"h3";

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
async fn reverse_loopback_handshake() {
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
    let _conn = rtx
        .connect(now(), rtx_addr(quinn_server_addr), "localhost")
        .expect("rtx connect");

    // Spawn quinn server accept: incoming -> Connection means quinn side is done.
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    let server = quinn_server.clone();
    tokio::spawn(async move {
        let res = match server.accept().await {
            Some(incoming) => incoming.await.map(|_conn| ()),
            None => Err(quinn::ConnectionError::LocallyClosed),
        };
        let _ = tx.send(res);
    });

    let mut rtx_handshake = false;
    let mut quinn_handshake = false;

    let outcome = tokio::time::timeout(Duration::from_secs(10), async {
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
                        Ok(()) => quinn_handshake = true,
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

    match outcome {
        Ok(()) => {}
        Err(_) => panic!("handshake timed out"),
    }

    assert!(rtx_handshake, "rtx-quic client did not complete handshake");
    assert!(quinn_handshake, "quinn server did not complete handshake");
}
