#![cfg(feature = "std")]
mod common;

use common::{ALPN, Harness, TestPki, client_config, server_config};
use rtx_quic::{Endpoint, TransportConfig};

#[test]
fn m3_q8_metrics_after_handshake() {
    let pki = TestPki::new();
    let server = Endpoint::new(server_config(&pki, &[ALPN], TransportConfig::default()))
        .expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);
    harness.establish_with_latency(1000);
    let client_connection = harness.clients[index].connection;

    let stream = harness.clients[index]
        .endpoint
        .open_bi(client_connection)
        .expect("open_bi");
    harness.clients[index]
        .endpoint
        .write_stream(client_connection, stream, b"abc")
        .expect("write");
    harness.pump_latency(1000, 4);

    let metrics = harness.clients[index]
        .endpoint
        .metrics(client_connection)
        .expect("metrics");
    assert!(metrics.smoothed_rtt_micros > 0);
    assert!(metrics.latest_rtt_micros.is_some_and(|latest| latest > 0));
    assert!(metrics.min_rtt_micros > 0);
    assert!(metrics.congestion_window_bytes > 0);
    assert_eq!(metrics.lost_packets, 0);
    assert_eq!(metrics.datagrams_sent, 0);
    assert_eq!(metrics.datagrams_received, 0);
    assert_eq!(metrics.stream_bytes_sent, 3);
    assert_eq!(metrics.stream_bytes_received, 0);
    assert_eq!(metrics.pacing_rate_bits_per_second, None);
    assert_eq!(metrics.snapshot_allocations, 0);
}

#[test]
#[allow(clippy::too_many_lines)]
fn m3_q8_metrics_reflect_loss_and_rtt() {
    let pki = TestPki::new();
    let transport = TransportConfig {
        max_idle_timeout_millis: Some(300_000),
        ..TransportConfig::default()
    };
    let server =
        Endpoint::new(server_config(&pki, &[ALPN], transport.clone())).expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN]).with_transport(transport))
        .expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);
    let server_connection = harness.establish_with_latency(1000);
    let client_connection = harness.clients[index].connection;

    harness.clients[index]
        .endpoint
        .send_datagram(client_connection, b"counted")
        .expect("client datagram");
    harness.pump_latency(1000, 4);
    let mut buffer = [0u8; 64];
    assert_eq!(
        harness
            .server
            .poll_datagram(server_connection, &mut buffer)
            .expect("poll server datagram"),
        Some(b"counted".len())
    );
    harness
        .server
        .send_datagram(server_connection, b"echo")
        .expect("server datagram");
    harness.pump_latency(1000, 4);
    assert_eq!(
        harness.clients[index]
            .endpoint
            .poll_datagram(client_connection, &mut buffer)
            .expect("poll client datagram"),
        Some(b"echo".len())
    );

    let stream = harness.clients[index]
        .endpoint
        .open_uni(client_connection)
        .expect("open_uni");
    let payload = vec![0x42_u8; 6000];
    let mut offset = 0;
    for _ in 0..64 {
        if offset == payload.len() {
            break;
        }
        offset += harness.clients[index]
            .endpoint
            .write_stream(client_connection, stream, &payload[offset..])
            .expect("write");
    }
    assert_eq!(offset, payload.len());

    let client_address = harness.clients[index].address;
    let mut transmit_buffer = Vec::new();
    let mut packets = 0;
    let mut dropped = 0;
    while let Some(transmit) = harness.clients[index]
        .endpoint
        .poll_transmit(harness.now, &mut transmit_buffer)
    {
        let bytes = transmit_buffer[..transmit.len].to_vec();
        if packets == 0 {
            dropped += 1;
        } else {
            harness
                .server
                .handle_datagram(harness.now, client_address, None, &bytes);
        }
        packets += 1;
        if packets > 32 {
            break;
        }
    }
    assert!(dropped > 0, "the first stream packet is dropped");
    assert!(
        packets >= 4,
        "several later packets are needed for loss detection, got {packets}"
    );

    harness.pump();
    harness.clients[index]
        .endpoint
        .write_stream(client_connection, stream, b"x")
        .expect("extra ack-eliciting byte");
    harness.pump_latency(1000, 4);
    let metrics = harness.clients[index]
        .endpoint
        .metrics(client_connection)
        .expect("metrics");
    assert!(
        metrics.lost_packets > 0,
        "a dropped packet must be declared lost once later packets are acked"
    );
    assert!(metrics.smoothed_rtt_micros > 0);
    assert!(metrics.latest_rtt_micros.is_some_and(|latest| latest > 0));
    assert_eq!(metrics.datagrams_sent, 1);
    assert_eq!(metrics.datagrams_received, 1);
    assert_eq!(
        metrics.stream_bytes_sent,
        u64::try_from(payload.len()).expect("test payload fits u64") + 1
    );
}

#[test]
fn m3_q8_snapshot_allocations() {
    let pki = TestPki::new();
    let server = Endpoint::new(server_config(&pki, &[ALPN], TransportConfig::default()))
        .expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);
    harness.establish();
    let client_connection = harness.clients[index].connection;

    for _ in 0..1000 {
        let metrics = harness.clients[index]
            .endpoint
            .metrics(client_connection)
            .expect("metrics");
        assert_eq!(
            metrics.snapshot_allocations, 0,
            "the snapshot is a Copy value and must not allocate"
        );
    }
}
