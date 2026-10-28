#![cfg(feature = "std")]
mod common;

use common::{ALPN, Harness, TestPki, client_config, server_config};
use rtx_quic::{ConnectionId, DatagramError, Endpoint, TransportConfig};

fn poll_server_datagram(harness: &mut Harness, connection: ConnectionId) -> Vec<u8> {
    let mut buffer = [0u8; 4096];
    for _ in 0..256 {
        match harness.server.poll_datagram(connection, &mut buffer) {
            Ok(Some(len)) => return buffer[..len].to_vec(),
            Ok(None) => harness.pump(),
            Err(error) => panic!("server poll_datagram failed: {error}"),
        }
    }
    panic!("server never received a datagram");
}

fn poll_client_datagram(harness: &mut Harness, index: usize, connection: ConnectionId) -> Vec<u8> {
    let mut buffer = [0u8; 4096];
    for _ in 0..256 {
        match harness.clients[index]
            .endpoint
            .poll_datagram(connection, &mut buffer)
        {
            Ok(Some(len)) => return buffer[..len].to_vec(),
            Ok(None) => harness.pump(),
            Err(error) => panic!("client poll_datagram failed: {error}"),
        }
    }
    panic!("client never received a datagram");
}

#[test]
fn m3_q4_round_trip() {
    let pki = TestPki::new();
    let server = Endpoint::new(server_config(&pki, &[ALPN], TransportConfig::default()))
        .expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);
    let server_connection = harness.establish();
    let client_connection = harness.clients[index].connection;

    let from_client = b"datagram from client";
    assert_eq!(
        harness.clients[index]
            .endpoint
            .send_datagram(client_connection, from_client)
            .expect("client send_datagram"),
        from_client.len()
    );
    harness.pump();
    assert_eq!(
        poll_server_datagram(&mut harness, server_connection),
        from_client
    );

    let from_server = b"datagram from server";
    harness
        .server
        .send_datagram(server_connection, from_server)
        .expect("server send_datagram");
    harness.pump();
    assert_eq!(
        poll_client_datagram(&mut harness, index, client_connection),
        from_server
    );
}

#[test]
fn m3_q4_oversize_rejected() {
    let pki = TestPki::new();
    let server = Endpoint::new(server_config(&pki, &[ALPN], TransportConfig::default()))
        .expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);
    let _server_connection = harness.establish();
    let client_connection = harness.clients[index].connection;

    let before = harness.clients[index]
        .endpoint
        .metrics(client_connection)
        .expect("metrics")
        .datagrams_sent;
    let payload = vec![0u8; 4096];
    match harness.clients[index]
        .endpoint
        .send_datagram(client_connection, &payload)
    {
        Err(DatagramError::TooLarge { max_len }) => {
            assert!(max_len < payload.len(), "the limit must be reported");
        }
        other => panic!("expected an explicit oversize error, got {other:?}"),
    }
    let after = harness.clients[index]
        .endpoint
        .metrics(client_connection)
        .expect("metrics")
        .datagrams_sent;
    assert_eq!(
        before, after,
        "an oversized datagram must not be truncated or queued"
    );
}

#[test]
fn m3_q4_unsupported_peer_rejected() {
    let pki = TestPki::new();
    let transport = TransportConfig {
        datagram_receive_buffer_bytes: None,
        ..TransportConfig::default()
    };
    let server = Endpoint::new(server_config(&pki, &[ALPN], transport)).expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);
    let _server_connection = harness.establish();
    let client_connection = harness.clients[index].connection;

    assert_eq!(
        harness.clients[index]
            .endpoint
            .send_datagram(client_connection, b"unsupported")
            .expect_err("the peer does not support DATAGRAM"),
        DatagramError::UnsupportedByPeer
    );
}
