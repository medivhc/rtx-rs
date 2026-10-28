#![cfg(feature = "std")]
mod common;

use common::{ALPN, Harness, TestPki, client_config, close_reason, drain_events, server_config};
use rtx_quic::{CloseOrigin, CloseReason, DatagramError, Endpoint, StreamError, TransportConfig};

#[test]
fn m3_q7_application_close_round_trip() {
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
        .close(client_connection, harness.now, 42, b"bye")
        .expect("close");
    let local_events = drain_events(&mut harness.clients[index].endpoint);
    assert_eq!(
        close_reason(&local_events),
        Some(&CloseReason::Application {
            origin: CloseOrigin::Local,
            error_code: 42,
            reason: b"bye".to_vec(),
        })
    );

    harness.pump();
    let server_events = drain_events(&mut harness.server);
    assert_eq!(
        close_reason(&server_events),
        Some(&CloseReason::Application {
            origin: CloseOrigin::Remote,
            error_code: 42,
            reason: b"bye".to_vec(),
        })
    );
}

#[test]
fn m3_q7_remote_close_event() {
    let pki = TestPki::new();
    let server = Endpoint::new(server_config(&pki, &[ALPN], TransportConfig::default()))
        .expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);
    let server_connection = harness.establish();
    let client_connection = harness.clients[index].connection;

    harness
        .server
        .close(server_connection, harness.now, 7, b"later")
        .expect("server close");
    harness.pump();

    let client_events = drain_events(&mut harness.clients[index].endpoint);
    assert_eq!(
        close_reason(&client_events),
        Some(&CloseReason::Application {
            origin: CloseOrigin::Remote,
            error_code: 7,
            reason: b"later".to_vec(),
        })
    );
    assert!(
        harness.clients[index]
            .endpoint
            .metrics(client_connection)
            .is_ok()
    );
}

#[test]
fn m3_q7_operations_after_close_fail_explicitly() {
    let pki = TestPki::new();
    let server = Endpoint::new(server_config(&pki, &[ALPN], TransportConfig::default()))
        .expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);
    let _server_connection = harness.establish();
    let client_connection = harness.clients[index].connection;

    let stream = harness.clients[index]
        .endpoint
        .open_bi(client_connection)
        .expect("open_bi");
    harness.clients[index]
        .endpoint
        .write_stream(client_connection, stream, b"pending")
        .expect("write before close");

    harness.clients[index]
        .endpoint
        .close(client_connection, harness.now, 1, b"closing")
        .expect("close");

    assert_eq!(
        harness.clients[index]
            .endpoint
            .open_uni(client_connection)
            .expect_err("open_uni after close"),
        StreamError::Closed
    );
    assert_eq!(
        harness.clients[index]
            .endpoint
            .send_datagram(client_connection, b"x")
            .expect_err("send_datagram after close"),
        DatagramError::Closed
    );
    assert_eq!(
        harness.clients[index]
            .endpoint
            .write_stream(client_connection, stream, b"more")
            .expect_err("write after close"),
        StreamError::Closed
    );
    assert_eq!(
        harness.clients[index]
            .endpoint
            .finish_stream(client_connection, stream)
            .expect_err("finish after close"),
        StreamError::Closed
    );
    assert_eq!(
        harness.clients[index]
            .endpoint
            .reset_stream(client_connection, stream, 0)
            .expect_err("reset after close"),
        StreamError::Closed
    );
}
