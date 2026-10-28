#![cfg(feature = "std")]
mod common;

use common::{ALPN, Harness, TestPki, client_config, drain_events, server_config};
use rtx_quic::{
    ConnectionId, Direction, Endpoint, EventKind, StreamError, StreamEvent, StreamId, StreamRead,
    TransportConfig,
};

fn write_client_all(
    harness: &mut Harness,
    index: usize,
    connection: ConnectionId,
    stream: StreamId,
    data: &[u8],
) {
    let mut offset = 0;
    for _ in 0..1024 {
        if offset == data.len() {
            return;
        }
        match harness.clients[index]
            .endpoint
            .write_stream(connection, stream, &data[offset..])
        {
            Ok(0) | Err(StreamError::Blocked) => harness.pump(),
            Ok(written) => offset += written,
            Err(error) => panic!("client write failed: {error}"),
        }
    }
    panic!("client write did not complete");
}

fn write_server_all(
    harness: &mut Harness,
    connection: ConnectionId,
    stream: StreamId,
    data: &[u8],
) {
    let mut offset = 0;
    for _ in 0..1024 {
        if offset == data.len() {
            return;
        }
        match harness
            .server
            .write_stream(connection, stream, &data[offset..])
        {
            Ok(0) | Err(StreamError::Blocked) => harness.pump(),
            Ok(written) => offset += written,
            Err(error) => panic!("server write failed: {error}"),
        }
    }
    panic!("server write did not complete");
}

fn accept_server_uni(harness: &mut Harness, connection: ConnectionId) -> StreamId {
    for _ in 0..512 {
        if let Some(stream) = harness
            .server
            .accept_uni(connection)
            .expect("accept_uni on a live connection")
        {
            return stream;
        }
        harness.pump();
    }
    panic!("server never accepted a unidirectional stream");
}

fn accept_server_bi(harness: &mut Harness, connection: ConnectionId) -> StreamId {
    for _ in 0..512 {
        if let Some(stream) = harness
            .server
            .accept_bi(connection)
            .expect("accept_bi on a live connection")
        {
            return stream;
        }
        harness.pump();
    }
    panic!("server never accepted a bidirectional stream");
}

#[test]
fn m3_q3_uni_round_trip() {
    let pki = TestPki::new();
    let server = Endpoint::new(server_config(&pki, &[ALPN], TransportConfig::default()))
        .expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);
    let server_connection = harness.establish();
    let client_connection = harness.clients[index].connection;

    let stream = harness.clients[index]
        .endpoint
        .open_uni(client_connection)
        .expect("open_uni");
    assert_eq!(stream.direction(), Direction::Uni);
    assert_eq!(stream.index(), 0);
    assert_eq!(
        stream.as_u64() & 0b11,
        0b10,
        "client-initiated uni stream ID"
    );

    let payload = b"unidirectional payload";
    write_client_all(&mut harness, index, client_connection, stream, payload);
    harness.clients[index]
        .endpoint
        .finish_stream(client_connection, stream)
        .expect("finish");
    harness.pump();

    let accepted = accept_server_uni(&mut harness, server_connection);
    assert_eq!(
        accepted, stream,
        "the same stream ID is observed by the peer"
    );
    let received = harness.read_from_server(server_connection, accepted);
    assert_eq!(received, payload);
}

#[test]
fn m3_q3_bi_round_trip() {
    let pki = TestPki::new();
    let server = Endpoint::new(server_config(&pki, &[ALPN], TransportConfig::default()))
        .expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);
    let server_connection = harness.establish();
    let client_connection = harness.clients[index].connection;

    let stream = harness.clients[index]
        .endpoint
        .open_bi(client_connection)
        .expect("open_bi");
    assert_eq!(stream.direction(), Direction::Bi);
    assert_eq!(stream.index(), 0);
    assert_eq!(
        stream.as_u64() & 0b11,
        0b00,
        "client-initiated bi stream ID"
    );

    let next = harness.clients[index]
        .endpoint
        .open_bi(client_connection)
        .expect("second open_bi");
    assert_eq!(next.index(), 1, "stream IDs increase monotonically");

    let request = b"request payload";
    write_client_all(&mut harness, index, client_connection, stream, request);
    harness.clients[index]
        .endpoint
        .finish_stream(client_connection, stream)
        .expect("client finish");
    harness.pump();

    let accepted = accept_server_bi(&mut harness, server_connection);
    assert_eq!(accepted, stream);
    assert_eq!(
        harness.read_from_server(server_connection, accepted),
        request
    );

    let response = b"response payload";
    write_server_all(&mut harness, server_connection, accepted, response);
    harness
        .server
        .finish_stream(server_connection, accepted)
        .expect("server finish");
    harness.pump();
    assert_eq!(
        harness.read_from_client(index, client_connection, stream),
        response
    );
}

#[test]
fn m3_q3_flow_control_blocks_then_resumes() {
    let pki = TestPki::new();
    let transport = TransportConfig {
        stream_receive_window_bytes: 256,
        connection_receive_window_bytes: 1024,
        ..TransportConfig::default()
    };
    let server = Endpoint::new(server_config(&pki, &[ALPN], transport)).expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);
    let server_connection = harness.establish();
    let client_connection = harness.clients[index].connection;

    let stream = harness.clients[index]
        .endpoint
        .open_bi(client_connection)
        .expect("open_bi");
    let payload = vec![0x5a_u8; 2048];
    let mut offset = 0;
    let mut blocked = false;
    let mut server_stream = None;
    let mut received = Vec::new();
    let mut buffer = [0u8; 1024];

    for _ in 0..4096 {
        if offset == payload.len() {
            break;
        }
        match harness.clients[index].endpoint.write_stream(
            client_connection,
            stream,
            &payload[offset..],
        ) {
            Ok(0) => harness.pump(),
            Ok(written) => offset += written,
            Err(StreamError::Blocked) => {
                blocked = true;
                harness.pump();
            }
            Err(error) => panic!("write failed: {error}"),
        }
        if server_stream.is_none() {
            server_stream = harness
                .server
                .accept_bi(server_connection)
                .expect("accept_bi");
        }
        if let Some(server_stream) = server_stream {
            loop {
                match harness
                    .server
                    .read_stream(server_connection, server_stream, &mut buffer)
                {
                    Ok(StreamRead::Data { len }) => received.extend_from_slice(&buffer[..len]),
                    Ok(StreamRead::Finished) | Err(StreamError::Blocked) => break,
                    Err(error) => panic!("server read failed: {error}"),
                }
            }
        }
    }

    assert!(blocked, "the tiny receive window must block the writer");
    assert_eq!(offset, payload.len(), "no accepted byte is lost");
    harness.clients[index]
        .endpoint
        .finish_stream(client_connection, stream)
        .expect("finish");
    harness.pump();

    if let Some(server_stream) = server_stream {
        loop {
            match harness
                .server
                .read_stream(server_connection, server_stream, &mut buffer)
            {
                Ok(StreamRead::Data { len }) => received.extend_from_slice(&buffer[..len]),
                Ok(StreamRead::Finished) => break,
                Err(StreamError::Blocked) => harness.pump(),
                Err(error) => panic!("server read failed: {error}"),
            }
        }
    }
    assert_eq!(received, payload, "flow control must resume without loss");
}

#[test]
fn m3_q3_reset_and_stop_sending_are_reported() {
    let pki = TestPki::new();
    let server = Endpoint::new(server_config(&pki, &[ALPN], TransportConfig::default()))
        .expect("server endpoint");
    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
    let mut harness = Harness::new(server);
    let index = harness.add_client(client);
    let server_connection = harness.establish();
    let client_connection = harness.clients[index].connection;

    let bi_stream = harness.clients[index]
        .endpoint
        .open_bi(client_connection)
        .expect("open_bi");
    write_client_all(&mut harness, index, client_connection, bi_stream, b"abc");
    harness.pump();
    let accepted = accept_server_bi(&mut harness, server_connection);
    assert_eq!(accepted, bi_stream);

    harness.clients[index]
        .endpoint
        .reset_stream(client_connection, bi_stream, 9)
        .expect("reset_stream");
    harness.pump();

    let mut buffer = [0u8; 64];
    let mut reset_code = None;
    for _ in 0..256 {
        match harness
            .server
            .read_stream(server_connection, accepted, &mut buffer)
        {
            Ok(StreamRead::Data { .. }) => {}
            Ok(StreamRead::Finished) => break,
            Err(StreamError::Blocked) => harness.pump(),
            Err(StreamError::ResetByPeer { error_code }) => {
                reset_code = Some(error_code);
                break;
            }
            Err(error) => panic!("server read failed: {error}"),
        }
    }
    assert_eq!(reset_code, Some(9), "RESET_STREAM is reported to the peer");

    let uni_stream = harness.clients[index]
        .endpoint
        .open_uni(client_connection)
        .expect("open_uni");
    write_client_all(
        &mut harness,
        index,
        client_connection,
        uni_stream,
        b"stop me",
    );
    harness.pump();
    let server_uni = accept_server_uni(&mut harness, server_connection);
    harness
        .server
        .stop_sending(server_connection, server_uni, 5)
        .expect("stop_sending");
    harness.pump();

    let mut stopped = None;
    for _ in 0..256 {
        for event in drain_events(&mut harness.clients[index].endpoint) {
            if let EventKind::Stream(StreamEvent::Stopped { stream, error_code }) = event.kind {
                if stream == uni_stream {
                    stopped = Some(error_code);
                }
            }
        }
        if stopped.is_some() {
            break;
        }
        harness.pump();
    }
    assert_eq!(stopped, Some(5), "STOP_SENDING is reported to the sender");

    assert_eq!(
        harness.clients[index]
            .endpoint
            .read_stream(client_connection, uni_stream, &mut buffer)
            .expect_err("a send-only stream cannot be read"),
        StreamError::WrongDirection
    );
    assert_eq!(
        harness
            .server
            .write_stream(server_connection, server_uni, b"nope")
            .expect_err("a receive-only stream cannot be written"),
        StreamError::WrongDirection
    );
}
