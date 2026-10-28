#![cfg(feature = "std")]
mod common;

use common::{ALPN, Harness, TestPki, client_config, drain_events, server_config};
use rtx_quic::{CloseReason, Endpoint, EventKind, TransportConfig};

#[test]
fn m3_q6_idle_timeout() {
    let pki = TestPki::new();
    let idle_transport = TransportConfig {
        max_idle_timeout_millis: Some(200),
        ..TransportConfig::default()
    };
    let server = Endpoint::new(server_config(&pki, &[ALPN], idle_transport.clone()))
        .expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN]).with_transport(idle_transport))
        .expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);
    harness.establish();

    let mut timed_out = false;
    for _ in 0..64 {
        harness.advance(10_000);
        harness.clients[index].endpoint.handle_timeout(harness.now);
        harness.server.handle_timeout(harness.now);
        for event in drain_events(&mut harness.clients[index].endpoint) {
            if let EventKind::Closed(CloseReason::TimedOut) = event.kind {
                timed_out = true;
            }
        }
        if timed_out {
            break;
        }
    }
    assert!(timed_out, "the idle timeout must close the connection");
}

#[test]
fn m3_q6_pto_retransmits_without_sleep() {
    let pki = TestPki::new();
    let mut client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut now = rtx_core::Timestamp::from_micros(1_000_000);
    let connection = client
        .connect(now, common::address(1, 4433), "localhost")
        .expect("connect");

    let mut buffer = Vec::new();
    let initial = client
        .poll_transmit(now, &mut buffer)
        .expect("initial transmit");
    assert!(
        initial.len >= 1200,
        "client Initial is padded to 1200 bytes"
    );
    assert_eq!(initial.destination, common::address(1, 4433));

    let deadline = client.poll_timeout().expect("PTO timer armed");
    assert!(deadline > now, "the deadline is absolute and in the future");
    now = deadline;
    client.handle_timeout(now);

    let retransmit = client
        .poll_transmit(now, &mut buffer)
        .expect("PTO produces a retransmission");
    assert!(retransmit.len > 0);
    assert_eq!(retransmit.destination, common::address(1, 4433));
    assert!(
        client.poll_timeout().is_none_or(|next| next > deadline),
        "an already handled deadline is not reported twice"
    );
    let metrics = client.metrics(connection).expect("metrics after PTO");
    assert_eq!(metrics.snapshot_allocations, 0);
}

#[test]
fn m3_q6_timer_after_close_is_ignored() {
    let pki = TestPki::new();
    let server = Endpoint::new(server_config(&pki, &[ALPN], TransportConfig::default()))
        .expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);
    let _server_connection = harness.establish();
    let client_connection = harness.clients[index].connection;

    harness.clients[index]
        .endpoint
        .close(client_connection, harness.now, 0, b"done")
        .expect("close");
    let closed_events = drain_events(&mut harness.clients[index].endpoint);
    let closed_count = closed_events
        .iter()
        .filter(|event| matches!(event.kind, EventKind::Closed(_)))
        .count();
    assert_eq!(closed_count, 1, "the local close is reported once");

    harness.advance(10_000_000);
    for _ in 0..3 {
        harness.clients[index].endpoint.handle_timeout(harness.now);
        harness.server.handle_timeout(harness.now);
    }
    harness.pump();
    let after = drain_events(&mut harness.clients[index].endpoint);
    assert!(
        after
            .iter()
            .all(|event| !matches!(event.kind, EventKind::Closed(_))),
        "expired timers after close must not produce another close event"
    );
    assert!(
        harness.clients[index].endpoint.poll_timeout().is_none(),
        "the drained connection has no timers left"
    );
}
