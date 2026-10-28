#![cfg(feature = "std")]
mod common;

use common::{ALPN, Harness, TestPki, client_config, server_config};
use rtx_quic::{Endpoint, Transmit, TransportConfig};

fn drain_transmits(harness: &mut Harness, index: usize) -> Vec<Transmit> {
    let mut transmits = Vec::new();
    let mut buffer = Vec::new();
    for _ in 0..256 {
        if let Some(transmit) = harness.clients[index]
            .endpoint
            .poll_transmit(harness.now, &mut buffer)
        {
            assert!(transmit.len > 0);
            assert!(transmit.len <= buffer.len());
            transmits.push(transmit);
        } else {
            let Some(deadline) = harness.clients[index].endpoint.poll_timeout() else {
                break;
            };
            if deadline <= harness.now {
                break;
            }
            harness.advance_to(deadline);
        }
    }
    transmits
}

#[test]
fn m3_q5_transmit_batch_drain() {
    let pki = TestPki::new();
    let server = Endpoint::new(server_config(&pki, &[ALPN], TransportConfig::default()))
        .expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);
    let _server_connection = harness.establish();
    let client_connection = harness.clients[index].connection;

    let payload = vec![0xabu8; 1000];
    for _ in 0..3 {
        harness.clients[index]
            .endpoint
            .send_datagram(client_connection, &payload)
            .expect("queue datagram");
    }

    let transmits = drain_transmits(&mut harness, index);
    assert!(
        transmits.len() >= 3,
        "three full-size datagrams require three transmits, got {}",
        transmits.len()
    );
    for transmit in &transmits {
        assert_eq!(transmit.destination, harness.server_address);
        assert!(transmit.segment_size.is_none());
    }

    let mut buffer = Vec::new();
    assert!(
        harness.clients[index]
            .endpoint
            .poll_transmit(harness.now, &mut buffer)
            .is_none(),
        "the queue is empty after draining"
    );
}

#[test]
fn m3_q5_idle_poll_returns_none() {
    let pki = TestPki::new();
    let server = Endpoint::new(server_config(&pki, &[ALPN], TransportConfig::default()))
        .expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);
    harness.establish();

    let mut buffer = Vec::new();
    for _ in 0..64 {
        if harness.clients[index]
            .endpoint
            .poll_transmit(harness.now, &mut buffer)
            .is_some()
        {
            harness.pump();
        } else {
            break;
        }
    }
    assert!(
        harness.clients[index]
            .endpoint
            .poll_transmit(harness.now, &mut buffer)
            .is_none(),
        "an idle connection must not busy-poll"
    );
}
