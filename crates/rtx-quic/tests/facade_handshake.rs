#![cfg(feature = "std")]
mod common;

use common::{
    ALPN, Harness, TestPki, client_config, drain_events, handshake_failure, handshake_info,
    server_config,
};
use rtx_quic::{Endpoint, Event, EventKind, HandshakeFailure, TransportConfig};

#[test]
fn m3_q2_handshake_event_sequence() {
    let pki = TestPki::new();
    let server = Endpoint::new(server_config(&pki, &[ALPN], TransportConfig::default()))
        .expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);

    let mut buffer = Vec::new();
    let transmit = harness.clients[index]
        .endpoint
        .poll_transmit(harness.now, &mut buffer)
        .expect("client initial");
    let initial = buffer[..transmit.len].to_vec();
    let client_address = harness.clients[index].address;
    harness
        .server
        .handle_datagram(harness.now, client_address, None, &initial);
    harness
        .server
        .handle_datagram(harness.now, client_address, None, &initial);

    let mut server_events: Vec<Event> = drain_events(&mut harness.server);
    assert_eq!(server_events.len(), 1, "duplicate input creates one event");
    assert!(matches!(server_events[0].kind, EventKind::Incoming));
    let incoming = server_events[0].connection;

    let mut accept_buffer = Vec::new();
    harness
        .server
        .accept(harness.now, incoming, &mut accept_buffer)
        .expect("accept");
    harness.pump();

    server_events = drain_events(&mut harness.server);
    assert_eq!(server_events.len(), 1, "one handshake-complete event");
    assert!(matches!(
        server_events[0].kind,
        EventKind::HandshakeComplete(_)
    ));

    let client_events = drain_events(&mut harness.clients[index].endpoint);
    assert_eq!(client_events.len(), 1, "one handshake-complete event");
    assert!(matches!(
        client_events[0].kind,
        EventKind::HandshakeComplete(_)
    ));

    harness
        .server
        .handle_datagram(harness.now, client_address, None, &initial);
    assert!(
        drain_events(&mut harness.server).is_empty(),
        "a repeated datagram must not repeat an event"
    );
}

#[test]
fn m3_q2_alpn_mismatch_fails() {
    let pki = TestPki::new();
    let server = Endpoint::new(server_config(&pki, &[b"hq"], TransportConfig::default()))
        .expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);

    harness.pump();
    let mut incoming = None;
    while let Some(event) = harness.server.poll_event() {
        if matches!(event.kind, EventKind::Incoming) {
            incoming = Some(event.connection);
        }
    }
    let mut buffer = Vec::new();
    let accepted = harness
        .server
        .accept(harness.now, incoming.expect("incoming"), &mut buffer);
    assert!(
        accepted.is_err(),
        "the server rejects the connection when no ALPN overlaps"
    );
    harness.pump();

    let client_events = drain_events(&mut harness.clients[index].endpoint);
    assert!(handshake_info(&client_events).is_none());
    assert_eq!(
        handshake_failure(&client_events),
        Some(HandshakeFailure::Alpn),
        "the client must classify the alert as an ALPN failure"
    );
}

#[test]
fn m3_q2_peer_datagram_support_is_visible() {
    let pki = TestPki::new();

    let server = Endpoint::new(server_config(&pki, &[ALPN], TransportConfig::default()))
        .expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);
    harness.establish();
    let client_events = drain_events(&mut harness.clients[index].endpoint);
    let server_events = drain_events(&mut harness.server);
    assert!(
        handshake_info(&client_events)
            .expect("client handshake")
            .datagram_supported
    );
    assert!(
        handshake_info(&server_events)
            .expect("server handshake")
            .datagram_supported
    );

    let disabled_transport = TransportConfig {
        datagram_receive_buffer_bytes: None,
        ..TransportConfig::default()
    };
    let server =
        Endpoint::new(server_config(&pki, &[ALPN], disabled_transport)).expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);
    harness.establish();
    let client_events = drain_events(&mut harness.clients[index].endpoint);
    assert!(
        !handshake_info(&client_events)
            .expect("client handshake")
            .datagram_supported,
        "a peer without DATAGRAM must be visible as unsupported"
    );
}
