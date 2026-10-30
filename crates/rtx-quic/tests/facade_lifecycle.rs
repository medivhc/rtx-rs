#![cfg(feature = "std")]
mod common;

use common::{
    ALPN, Harness, TestPki, client_config, drain_events, handshake_failure, handshake_info,
    server_config,
};
use rtx_quic::{Endpoint, EventKind, HandshakeFailure, TransportConfig};

#[test]
fn m3_q1_client_server_handshake_completes() {
    let pki = TestPki::new();
    let server = Endpoint::new(server_config(&pki, &[ALPN], TransportConfig::default()))
        .expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);

    let _server_connection = harness.establish();

    let server_events = drain_events(&mut harness.server);
    let server_info = handshake_info(&server_events).expect("server handshake completed");
    assert_eq!(server_info.alpn.as_deref(), Some(ALPN));
    assert!(server_info.datagram_supported);
    assert!(
        !server_info.peer_transport_parameters.as_bytes().is_empty(),
        "peer transport parameters are carried in the event"
    );

    let client_events = drain_events(&mut harness.clients[index].endpoint);
    let client_info = handshake_info(&client_events).expect("client handshake completed");
    assert_eq!(client_info.alpn.as_deref(), Some(ALPN));
    assert!(client_info.datagram_supported);
    assert_ne!(client_info.peer_transport_parameters.as_bytes(), []);
}

#[test]
fn m3_q1_server_accepts_and_refuses_incoming() {
    let pki = TestPki::new();
    let server = Endpoint::new(server_config(&pki, &[ALPN], TransportConfig::default()))
        .expect("server endpoint");
    let first = Endpoint::new(client_config(&pki, &[ALPN])).expect("first client");
    let second = Endpoint::new(client_config(&pki, &[ALPN])).expect("second client");
    let mut harness = Harness::new(server);
    let first_index = harness.add_client(first);
    let second_index = harness.add_client(second);

    harness.pump();
    let mut incoming = Vec::new();
    while let Some(event) = harness.server.poll_event() {
        if matches!(event.kind, EventKind::Incoming) {
            incoming.push(event.connection);
        }
    }
    assert_eq!(incoming.len(), 2, "both clients must reach the server");

    let refused = incoming[0];
    let accepted = incoming[1];
    harness.server.refuse(refused).expect("refuse one incoming");
    let mut buffer = Vec::new();
    harness
        .server
        .accept(harness.now, accepted, &mut buffer)
        .expect("accept the other incoming");
    harness.pump();

    let first_events = drain_events(&mut harness.clients[first_index].endpoint);
    let second_events = drain_events(&mut harness.clients[second_index].endpoint);
    let first_completed = handshake_info(&first_events).is_some();
    let second_completed = handshake_info(&second_events).is_some();
    assert_ne!(
        first_completed, second_completed,
        "exactly one client must complete the handshake"
    );

    let (failed_events, completed_events) = if first_completed {
        (second_events, first_events)
    } else {
        (first_events, second_events)
    };
    assert!(
        handshake_info(&completed_events).is_some(),
        "accepted client completes"
    );
    assert_eq!(
        handshake_failure(&failed_events),
        Some(HandshakeFailure::PeerClosed),
        "refused client observes the peer close"
    );
}
