//! R6-3 loopback matrix for the `rtx-wt-server` harness.
//!
//! The client is deliberately **not** `rtx-quic`: it uses `quinn` +
//! `web-transport-proto` at the revisions pinned by `DEPENDENCY_AUDIT.md` §1,
//! i.e. the same independent protocol oracle R6-2c uses. A harness that only
//! agreed with itself would prove nothing.
//!
//! What the matrix covers (M3-B pre-work; the Chrome matrix is R6-4):
//!
//! - 3 sequential sessions + 2 concurrent sessions, all CONNECT 200;
//! - DATAGRAM echo: 100 datagrams per direction at 1 B, 1000 B and the full
//!   negotiated frame budget, plus one wrong-session and one malformed
//!   datagram (logged and dropped, connection continues);
//! - streams: client uni 1 MiB, client bi 1 MiB, 10 concurrent bi 1 MiB,
//!   server uni 1 MiB (one per session), server reset bi (one per session),
//!   client reset bi, all half-closed;
//! - WT_DRAIN_SESSION (session survives) and WT_CLOSE_SESSION (session ends,
//!   the same QUIC connection then serves a new session).
//!
//! DATAGRAMs are sent one at a time and paired with their echo. The
//! `max_datagram_frame_size` receive budget is also the `quinn-proto` receive
//! queue size, so a burst could drop echoed datagrams for a reason unrelated to
//! the harness. Pairwise echo keeps the loopback loss check meaningful (loopback
//! must lose nothing); R6-4's Chrome matrix is where burst loss is measured.
//!
//! Run through `run-loopback.sh`, or directly with
//! `cargo test --test loopback` (a throw-away `rcgen` identity is used when
//! `RTX_WT_SERVER_CERT_DER` / `RTX_WT_SERVER_KEY_DER` are unset).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use quinn::rustls;
use sha2::{Digest, Sha256};
use web_transport_proto::{
    Capsule, ConnectRequest, ConnectResponse, Frame, Setting, Settings, StreamUni, VarInt,
};

const MIB: usize = 1024 * 1024;
const DATAGRAMS_PER_SIZE: usize = 100;
const CONCURRENT_STREAMS: usize = 10;
const SESSION_TIMEOUT: Duration = Duration::from_secs(30);
/// Envelope the probe uses; the server advertises 1100 and the test client
/// advertises the same value.
const ADVERTISED_MAX_DATAGRAM_FRAME_SIZE: usize = 1100;
/// Prefix the server writes on its deliberate reset stream before resetting.
const SERVER_RESET_PAYLOAD_LEN: usize = 4096;

#[tokio::test(flavor = "current_thread")]
async fn m3_b_loopback_matrix() {
    let output_dir = resolve_output_dir();
    let identity = Identity::resolve();
    let log_path = output_dir.join("server.log");
    let stderr_path = output_dir.join("server.stderr");
    let _ = std::fs::remove_file(&log_path);
    let _ = std::fs::remove_file(&stderr_path);

    let mut server = ServerProcess::spawn(&identity, &log_path, &stderr_path);
    let address = server.wait_for_listening(&log_path);
    println!("rtx-wt-server listening on {address}");

    let (endpoint, client_config) = build_client(&identity);
    let h3 = open_h3(&endpoint, &client_config, address).await;
    let connection = h3.connection.clone();

    // Exercise the other H3 unidirectional stream types the dispatcher must
    // know: QPACK encoder, QPACK decoder and an unknown (GREASE) type.
    for stream_type in [0x02_u64, 0x03, 0x21] {
        let mut stream = connection.open_uni().await.expect("open uni stream");
        let mut header = Vec::new();
        VarInt::from_u64(stream_type)
            .expect("stream type fits a varint")
            .encode(&mut header);
        stream
            .write_all(&header)
            .await
            .expect("write uni stream type");
        stream.finish().expect("finish uni stream");
    }

    let mut rows = Vec::new();
    let mut datagrams_sent = 0usize;

    // ---- session 1: DATAGRAM matrix ------------------------------------
    let mut session1 = connect_session(&connection, address).await;
    let (auto_session, auto_payload) = read_wt_uni(&connection).await;
    assert_eq!(auto_session, session1.id, "server uni session id");
    assert_eq!(auto_payload, pattern(MIB), "server-initiated 1 MiB payload");
    let auto_reset = read_wt_bi_reset(&connection).await;
    if let Some(auto_session) = auto_reset.session {
        assert_eq!(auto_session, session1.id, "server reset session id");
    }
    assert_eq!(
        auto_reset.reset_code,
        Some(7),
        "server-initiated bidirectional stream must reset"
    );
    assert_reset_prefix(&auto_reset);

    let max_datagram_payload = connection
        .max_datagram_size()
        .expect("DATAGRAM must be negotiated");
    assert!(
        max_datagram_payload >= 1000,
        "the full-size DATAGRAM probe needs at least the 1000-byte tier, got {max_datagram_payload}"
    );
    let quarter = session1.id >> 2;
    let mut quarter_header = Vec::new();
    VarInt::from_u64(quarter)
        .expect("quarter stream id")
        .encode(&mut quarter_header);
    // quinn-proto 0.11.19 (the server engine) rejects a received DATAGRAM whose
    // payload plus the queued `Datagram` metadata (one `Bytes`, 32 bytes) exceeds
    // the advertised receive window with PROTOCOL_VIOLATION, while the 0.12
    // client derives its send budget from the frame bound alone. The full-size
    // tier therefore uses the largest payload both accountings accept.
    let datagram_metadata = std::mem::size_of::<Bytes>();
    let max_usable_datagram = ADVERTISED_MAX_DATAGRAM_FRAME_SIZE.saturating_sub(datagram_metadata);
    assert!(
        max_datagram_payload >= max_usable_datagram - 1,
        "the client must be able to send the full usable payload"
    );
    let max_wt_payload = max_usable_datagram
        .checked_sub(quarter_header.len())
        .expect("the quarter header must fit");
    println!(
        "negotiated max_datagram_frame_size={ADVERTISED_MAX_DATAGRAM_FRAME_SIZE} \
         client_max_datagram_size={max_datagram_payload} \
         datagram_metadata_bytes={datagram_metadata} \
         max_usable_datagram={max_usable_datagram} max_wt_payload={max_wt_payload}"
    );

    for (label, size) in [
        ("datagram-echo-1b", 1usize),
        ("datagram-echo-1000b", 1000),
        ("datagram-echo-max", max_wt_payload),
    ] {
        let echoed = datagram_echo(&connection, &quarter_header, size, DATAGRAMS_PER_SIZE).await;
        assert_eq!(echoed.lost, 0, "{label}: loopback must not lose datagrams");
        assert_eq!(
            sha256_hex(&echoed.sent),
            sha256_hex(&echoed.received),
            "{label}: both directions must hash identically"
        );
        datagrams_sent += DATAGRAMS_PER_SIZE;
        rows.push(Row {
            item: label.to_string(),
            sends: DATAGRAMS_PER_SIZE as u64,
            receives: DATAGRAMS_PER_SIZE as u64,
            lost: echoed.lost as u64,
            bytes: (size * DATAGRAMS_PER_SIZE) as u64,
            sha256: sha256_hex(&echoed.sent),
            detail: format!(
                "wt_payload_bytes={size} quic_datagram_payload_max={max_usable_datagram} client_max_datagram_size={max_datagram_payload} advertised_max_datagram_frame_size={ADVERTISED_MAX_DATAGRAM_FRAME_SIZE} quinn_datagram_metadata_bytes={datagram_metadata}"
            ),
        });
    }

    // WrongSession: a quarter stream id that belongs to no session is logged
    // and dropped; the connection keeps echoing.
    let mut wrong_quarter = Vec::new();
    VarInt::from_u64(0x3FFF_FFFF)
        .expect("wrong quarter")
        .encode(&mut wrong_quarter);
    let mut packet = wrong_quarter;
    packet.extend_from_slice(&pattern(64));
    connection
        .send_datagram(Bytes::from(packet))
        .expect("send wrong-session datagram");
    let continuation = datagram_echo(&connection, &quarter_header, 1, 1).await;
    assert_eq!(
        continuation.lost, 0,
        "connection must continue after WrongSession"
    );
    datagrams_sent += 1;
    rows.push(Row {
        item: "datagram-wrong-session".to_string(),
        sends: 1,
        receives: 0,
        lost: 0,
        bytes: 0,
        sha256: "-".to_string(),
        detail: "dropped_by_server=true connection_continued=true".to_string(),
    });

    // Malformed: an empty DATAGRAM payload has no quarter stream id.
    connection
        .send_datagram(Bytes::new())
        .expect("send empty datagram");
    let continuation = datagram_echo(&connection, &quarter_header, 1, 1).await;
    assert_eq!(
        continuation.lost, 0,
        "connection must continue after malformed"
    );
    datagrams_sent += 1;
    rows.push(Row {
        item: "datagram-malformed".to_string(),
        sends: 1,
        receives: 0,
        lost: 0,
        bytes: 0,
        sha256: "-".to_string(),
        detail: "dropped_by_server=true connection_continued=true".to_string(),
    });

    // Close session 1 with a clean CONNECT FIN (no capsule).
    session1.finish().expect("finish CONNECT");
    wait_for_log(
        &log_path,
        |text| {
            text.contains(&format!(
                "event=session_closed connection=0 session={} reason=connect_fin",
                session1.id
            ))
        },
        "session 1 close by CONNECT FIN",
    )
    .await;

    // ---- session 2: streams, capsules, drain, close ---------------------
    let mut session2 = connect_session(&connection, address).await;
    let (auto_session, auto_payload) = read_wt_uni(&connection).await;
    assert_eq!(auto_session, session2.id, "server uni session id");
    assert_eq!(auto_payload, pattern(MIB), "server-initiated 1 MiB payload");
    let auto_reset = read_wt_bi_reset(&connection).await;
    if let Some(auto_session) = auto_reset.session {
        assert_eq!(auto_session, session2.id, "server reset session id");
    }
    assert_eq!(auto_reset.reset_code, Some(7));
    assert_reset_prefix(&auto_reset);

    // Unknown capsule: logged and ignored.
    let unknown = Capsule::Unknown {
        typ: VarInt::from_u64(0x1234).expect("capsule type"),
        payload: Bytes::from_static(b"unknown-capsule"),
    };
    write_capsule(&mut session2.send, &unknown).await;

    // WT_DRAIN_SESSION: the reference codec has no dedicated variant, so it is
    // encoded as an unknown capsule of the registered drain type with a
    // zero-length payload, which is exactly the drain capsule's wire format.
    let drain = Capsule::Unknown {
        typ: VarInt::from_u64(0x78AE).expect("drain capsule type"),
        payload: Bytes::new(),
    };
    write_capsule(&mut session2.send, &drain).await;

    // The session must survive a drain signal.
    let session2_quarter = quarter_header_for(session2.id);
    let drained_echo = datagram_echo(&connection, &session2_quarter, 1, 1).await;
    assert_eq!(
        drained_echo.lost, 0,
        "session must survive WT_DRAIN_SESSION"
    );
    datagrams_sent += 1;
    rows.push(Row {
        item: "session-drain".to_string(),
        sends: 1,
        receives: 1,
        lost: 0,
        bytes: 0,
        sha256: "-".to_string(),
        detail: "capsule=WT_DRAIN_SESSION session_survived=true".to_string(),
    });

    let payload = pattern(MIB);

    // Client unidirectional stream -> echo on a new server unidirectional
    // stream.
    let mut client_uni = connection.open_uni().await.expect("open client uni");
    write_wt_header(&mut client_uni, true, session2.id).await;
    client_uni
        .write_all(&payload)
        .await
        .expect("write uni payload");
    client_uni.finish().expect("finish client uni");
    let (echo_session, echo_payload) = read_wt_uni(&connection).await;
    assert_eq!(echo_session, session2.id, "uni echo session id");
    assert_eq!(
        echo_payload, payload,
        "client unidirectional stream must come back byte-identical"
    );
    rows.push(Row {
        item: "stream-client-uni-1m".to_string(),
        sends: 1,
        receives: 1,
        lost: 0,
        bytes: MIB as u64,
        sha256: sha256_hex(&payload),
        detail: "echo=server-opened-uni bytes=1048576".to_string(),
    });

    // Client bidirectional stream -> echo on the same stream.
    let (mut client_bi, mut client_bi_recv) = connection.open_bi().await.expect("open client bi");
    write_wt_header(&mut client_bi, false, session2.id).await;
    client_bi
        .write_all(&payload)
        .await
        .expect("write bi payload");
    client_bi.finish().expect("finish client bi");
    let echoed = client_bi_recv
        .read_to_end(2 * MIB + 1024)
        .await
        .expect("read bi echo");
    assert_eq!(echoed, payload, "client bidirectional echo");
    rows.push(Row {
        item: "stream-client-bi-1m".to_string(),
        sends: 1,
        receives: 1,
        lost: 0,
        bytes: MIB as u64,
        sha256: sha256_hex(&payload),
        detail: "echo=same-stream half_close=true".to_string(),
    });

    // 10 concurrent client bidirectional streams, 1 MiB each.
    let mut concurrent = Vec::new();
    for _ in 0..CONCURRENT_STREAMS {
        let (mut send, recv) = connection.open_bi().await.expect("open concurrent bi");
        write_wt_header(&mut send, false, session2.id).await;
        send.write_all(&payload)
            .await
            .expect("write concurrent payload");
        send.finish().expect("finish concurrent stream");
        concurrent.push(recv);
    }
    for (index, recv) in concurrent.iter_mut().enumerate() {
        let echoed = recv
            .read_to_end(2 * MIB + 1024)
            .await
            .unwrap_or_else(|error| panic!("read concurrent echo {index}: {error}"));
        assert_eq!(echoed, payload, "concurrent stream {index} echo");
    }
    rows.push(Row {
        item: "stream-concurrent-bi-1m".to_string(),
        sends: CONCURRENT_STREAMS as u64,
        receives: CONCURRENT_STREAMS as u64,
        lost: 0,
        bytes: (CONCURRENT_STREAMS * MIB) as u64,
        sha256: sha256_hex(&payload),
        detail: format!("streams={CONCURRENT_STREAMS} each_bytes=1048576"),
    });

    // Client reset: the server must observe the reset and keep the other
    // streams untouched.
    let (mut reset_send, _reset_recv) = connection.open_bi().await.expect("open reset bi");
    write_wt_header(&mut reset_send, false, session2.id).await;
    reset_send
        .write_all(&pattern(1024))
        .await
        .expect("write before reset");
    reset_send
        .reset(quinn::VarInt::from_u32(7))
        .expect("client reset stream");
    rows.push(Row {
        item: "stream-client-reset-bi".to_string(),
        sends: 1,
        receives: 0,
        lost: 0,
        bytes: 0,
        sha256: "-".to_string(),
        detail: "reset_code=7 server_observed_reset=true".to_string(),
    });

    // WT_CLOSE_SESSION: send the capsule, then FIN the CONNECT stream as the
    // draft requires.
    let close = Capsule::CloseWebTransportSession {
        code: 7,
        reason: "loopback close".to_string(),
    };
    write_capsule(&mut session2.send, &close).await;
    session2
        .finish()
        .expect("finish CONNECT after close capsule");
    let closed = tokio::time::timeout(SESSION_TIMEOUT, session2.recv.read_to_end(64 * 1024))
        .await
        .expect("CONNECT stream should be closed by the server");
    assert!(
        closed.is_ok(),
        "CONNECT stream close must be clean: {closed:?}"
    );
    wait_for_log(
        &log_path,
        |text| {
            text.contains(&format!(
                "event=session_closed connection=0 session={} reason=capsule",
                session2.id
            ))
        },
        "session 2 close by WT_CLOSE_SESSION",
    )
    .await;
    rows.push(Row {
        item: "session-close-capsule".to_string(),
        sends: 1,
        receives: 1,
        lost: 0,
        bytes: 0,
        sha256: "-".to_string(),
        detail: "capsule=WT_CLOSE_SESSION code=7".to_string(),
    });

    // ---- session 3: same connection, new session after WT_CLOSE_SESSION -
    let mut session3 = connect_session(&connection, address).await;
    let (auto_session, auto_payload) = read_wt_uni(&connection).await;
    assert_eq!(auto_session, session3.id);
    assert_eq!(auto_payload, pattern(MIB));
    let auto_reset = read_wt_bi_reset(&connection).await;
    if let Some(auto_session) = auto_reset.session {
        assert_eq!(auto_session, session3.id);
    }
    assert_eq!(auto_reset.reset_code, Some(7));
    assert_reset_prefix(&auto_reset);
    let after_close = datagram_echo(&connection, &quarter_header_for(session3.id), 1, 1).await;
    assert_eq!(after_close.lost, 0, "new session after close");
    datagrams_sent += 1;
    session3.finish().expect("finish CONNECT");
    wait_for_log(
        &log_path,
        |text| {
            text.contains(&format!(
                "event=session_closed connection=0 session={} reason=connect_fin",
                session3.id
            ))
        },
        "session 3 close by CONNECT FIN",
    )
    .await;
    rows.push(Row {
        item: "session-after-close".to_string(),
        sends: 1,
        receives: 1,
        lost: 0,
        bytes: 0,
        sha256: "-".to_string(),
        detail: "new_session_after_flag=true".to_string(),
    });

    connection.close(quinn::VarInt::from_u32(0), b"sequential done");

    // ---- connection 2: two concurrent sessions --------------------------
    let h3b = open_h3(&endpoint, &client_config, address).await;
    let concurrent_conn = h3b.connection.clone();
    let mut session_a = connect_session(&concurrent_conn, address).await;
    let mut session_b = connect_session(&concurrent_conn, address).await;

    let mut auto_uni = BTreeMap::new();
    for _ in 0..2 {
        let (session, payload) = read_wt_uni(&concurrent_conn).await;
        assert_eq!(payload, pattern(MIB), "concurrent auto uni payload");
        auto_uni.insert(session, payload.len());
    }
    assert!(auto_uni.contains_key(&session_a.id), "session a auto uni");
    assert!(auto_uni.contains_key(&session_b.id), "session b auto uni");

    let mut auto_resets = Vec::new();
    for _ in 0..2 {
        let observation = read_wt_bi_reset(&concurrent_conn).await;
        assert_eq!(observation.reset_code, Some(7));
        assert_reset_prefix(&observation);
        auto_resets.push(observation.reset_code);
    }
    assert_eq!(
        auto_resets.len(),
        2,
        "one server reset per concurrent session"
    );

    let echo_a = datagram_echo(&concurrent_conn, &quarter_header_for(session_a.id), 1, 1).await;
    let echo_b = datagram_echo(&concurrent_conn, &quarter_header_for(session_b.id), 1, 1).await;
    assert_eq!(echo_a.lost, 0, "concurrent session a datagram");
    assert_eq!(echo_b.lost, 0, "concurrent session b datagram");
    datagrams_sent += 2;
    session_a.finish().expect("finish session a");
    session_b.finish().expect("finish session b");
    wait_for_log(
        &log_path,
        |text| text.matches("event=session_closed").count() >= 5,
        "all sessions closed",
    )
    .await;
    concurrent_conn.close(quinn::VarInt::from_u32(0), b"concurrent done");

    rows.push(Row {
        item: "session-connect-sequential".to_string(),
        sends: 3,
        receives: 3,
        lost: 0,
        bytes: 0,
        sha256: "-".to_string(),
        detail: "connect_200=3 same_connection=true".to_string(),
    });
    rows.push(Row {
        item: "session-connect-concurrent".to_string(),
        sends: 2,
        receives: 2,
        lost: 0,
        bytes: 0,
        sha256: "-".to_string(),
        detail: "connect_200=2 same_connection=true".to_string(),
    });
    rows.push(Row {
        item: "stream-server-uni-1m".to_string(),
        sends: 5,
        receives: 5,
        lost: 0,
        bytes: (5 * MIB) as u64,
        sha256: sha256_hex(&pattern(MIB)),
        detail: "sessions=5 each_bytes=1048576".to_string(),
    });
    rows.push(Row {
        item: "stream-server-reset-bi".to_string(),
        sends: 5,
        receives: 5,
        lost: 0,
        bytes: 0,
        sha256: "-".to_string(),
        detail: "reset_code=7 resets_observed=5".to_string(),
    });

    // ---- server log gates ----------------------------------------------
    // Signals are asynchronous: wait until the last expected events land, then
    // assert the whole matrix on one snapshot.
    wait_for_log(
        &log_path,
        |text| text.matches("event=connection_close").count() >= 2,
        "two closed connections",
    )
    .await;

    let log = std::fs::read_to_string(&log_path).unwrap_or_default();
    let connect_decoded = log.matches("event=connect_request_decoded").count();
    let responses_200 = log.matches("event=response_headers_sent").count();
    let sessions_closed = log.matches("event=session_closed").count();
    let datagrams_received = log.matches("event=datagram_received").count();
    let datagrams_echoed = log.matches("event=datagram_sent").count();

    assert_eq!(connect_decoded, 5, "one decoded CONNECT per session");
    assert_eq!(responses_200, 5, "one 200 response per session");
    assert!(sessions_closed >= 5, "every session must be closed");
    assert!(
        log.matches("event=session_closed connection=").count() >= 1,
        "session close events must be logged"
    );
    assert!(log.contains("reason=capsule"), "WT_CLOSE_SESSION path");
    assert!(
        log.matches("event=session_drained").count() == 1,
        "WT_DRAIN_SESSION path"
    );
    assert!(
        log.matches("event=capsule_unknown").count() >= 1,
        "unknown capsule must be logged and kept"
    );
    assert!(
        log.matches("reason=wrong_session").count() == 1,
        "wrong-session datagram must be dropped once"
    );
    assert!(
        log.matches("reason=malformed detail=empty").count() == 1,
        "malformed datagram must be dropped once"
    );
    assert_eq!(
        datagrams_received, datagrams_sent,
        "every sent loopback datagram must reach the server"
    );
    assert_eq!(
        datagrams_echoed, datagrams_sent,
        "every received datagram must be echoed (loopback loses nothing)"
    );
    assert!(
        log.contains("peer_max_datagram_frame_size=1100"),
        "the negotiated max_datagram_frame_size must come from the handshake"
    );
    assert!(
        log.matches("event=server_settings_sent").count() >= 2,
        "server SETTINGS per connection"
    );
    assert!(
        log.matches("event=h3_settings_frame_received").count() >= 2,
        "client SETTINGS per connection"
    );
    for item in [
        "event=server_setting connection=",
        "id=0x1 value=0",
        "id=0x7 value=0",
        "id=0x8 value=1",
        "id=0x33 value=1",
        "id=0xc671706a value=100",
    ] {
        assert!(log.contains(item), "missing server SETTINGS line {item:?}");
    }
    assert!(
        !log.contains("id=0x2c7cf000"),
        "0x2c7cf000 must not be advertised (N4 ruling)"
    );
    assert!(
        log.matches("event=uni_stream_unknown_type").count() >= 1,
        "unknown unidirectional stream types must be ignored and logged"
    );
    assert!(
        log.matches("role=qpack_encoder").count() >= 1,
        "QPACK encoder stream dispatch"
    );
    assert!(
        log.matches("role=qpack_decoder").count() >= 1,
        "QPACK decoder stream dispatch"
    );
    assert!(
        log.matches("event=stream_reset").count() >= 6,
        "client and server resets must be logged"
    );
    assert!(
        log.matches("code=7").count() >= 7,
        "one client reset plus six server resets carry code 7"
    );
    assert!(
        log.matches("event=stream_opened").count() >= 20,
        "stream lifecycle events"
    );
    assert!(
        log.matches("event=stream_finished").count() >= 15,
        "stream finish events"
    );
    assert!(
        log.matches("event=connection_close").count() >= 2,
        "connections must close cleanly"
    );
    assert!(
        log.matches("event=stream_echo_queued").count() >= 2,
        "uni and bi echo paths"
    );
    assert!(
        log.matches("event=datagram_echo_failed").count() == 0,
        "no datagram echo may fail on loopback"
    );

    // ---- hashes ---------------------------------------------------------
    let hashes = render_rows(&rows);
    std::fs::write(output_dir.join("hashes.txt"), &hashes).expect("write hashes.txt");
    println!("{hashes}");

    // ---- shutdown -------------------------------------------------------
    let status = server.terminate();
    assert!(
        status.code().is_none(),
        "SIGTERM must terminate the server (status {status:?})"
    );
    std::net::UdpSocket::bind(address).expect("the server must release its UDP port");
}

fn resolve_output_dir() -> PathBuf {
    let directory = match std::env::var_os("RTX_WT_LOOPBACK_DIR") {
        Some(value) => PathBuf::from(value),
        None => std::env::temp_dir().join(format!("rtx-wt-loopback-{}", std::process::id())),
    };
    std::fs::create_dir_all(&directory).expect("create the loopback output directory");
    directory
}

/// Certificate material for the server and the client root store.
///
/// With `RTX_WT_SERVER_CERT_DER`/`RTX_WT_SERVER_KEY_DER` set (the script's
/// openssl output) those DER files are used. Standalone runs generate a
/// throw-away self-signed certificate in a temp directory; nothing key-like is
/// ever written into the repository.
struct Identity {
    certificate_der: Vec<u8>,
    certificate_path: PathBuf,
    key_path: PathBuf,
    _temp_dir: Option<PathBufGuard>,
}

struct PathBufGuard(PathBuf);

impl Drop for PathBufGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Identity {
    fn resolve() -> Self {
        let certificate = std::env::var_os("RTX_WT_SERVER_CERT_DER");
        let key = std::env::var_os("RTX_WT_SERVER_KEY_DER");
        if let (Some(certificate), Some(key)) = (certificate, key) {
            let certificate_path = PathBuf::from(certificate);
            let key_path = PathBuf::from(key);
            let certificate_der =
                std::fs::read(&certificate_path).expect("read the server certificate DER");
            return Self {
                certificate_der,
                certificate_path,
                key_path,
                _temp_dir: None,
            };
        }

        let directory =
            std::env::temp_dir().join(format!("rtx-wt-identity-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("create identity directory");
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate a throw-away localhost certificate");
        let certificate_der = certified.cert.der().to_vec();
        let key_der = certified.key_pair.serialize_der();
        let certificate_path = directory.join("cert.der");
        let key_path = directory.join("key.der");
        std::fs::write(&certificate_path, &certificate_der).expect("write certificate DER");
        std::fs::write(&key_path, &key_der).expect("write key DER");
        Self {
            certificate_der,
            certificate_path,
            key_path,
            _temp_dir: Some(PathBufGuard(directory)),
        }
    }
}

/// One server child process. Its log path is chosen by the caller, never by
/// the server.
struct ServerProcess {
    child: Option<Child>,
}

impl ServerProcess {
    fn spawn(identity: &Identity, log_path: &Path, stderr_path: &Path) -> Self {
        let stderr = std::fs::File::create(stderr_path).expect("create server stderr file");
        let child = Command::new(env!("CARGO_BIN_EXE_rtx-wt-server"))
            .arg("--bind")
            .arg("127.0.0.1:0")
            .arg("--cert-chain-der")
            .arg(&identity.certificate_path)
            .arg("--key-der")
            .arg(&identity.key_path)
            .arg("--log")
            .arg(log_path)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn the harness server");
        Self { child: Some(child) }
    }

    fn wait_for_listening(&mut self, log_path: &Path) -> SocketAddr {
        for _ in 0..600 {
            if let Ok(text) = std::fs::read_to_string(log_path) {
                if let Some(address) = parse_listening_address(&text) {
                    return address;
                }
            }
            if let Some(child) = self.child.as_mut() {
                if let Ok(Some(status)) = child.try_wait() {
                    panic!("the harness server exited before listening ({status})");
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!(
            "the harness server never logged event=server_listening\n{}",
            log_tail(log_path)
        );
    }

    /// SIGTERM (the task requires a terminated child, not a SIGKILL), then
    /// wait for the child to disappear and return its exit status.
    fn terminate(&mut self) -> ExitStatus {
        let Some(mut child) = self.child.take() else {
            panic!("the harness server was already reaped");
        };
        let pid = child.id().to_string();
        let _ = Command::new("kill").arg("-TERM").arg(&pid).status();
        child
            .wait()
            .expect("wait for the harness server after SIGTERM")
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn parse_listening_address(text: &str) -> Option<SocketAddr> {
    text.lines().find_map(|line| {
        if !line.contains("event=server_listening") {
            return None;
        }
        let rest = line.split("addr=").nth(1)?;
        let address = rest.split_whitespace().next()?;
        address.parse().ok()
    })
}

fn log_tail(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let tail: Vec<&str> = text.lines().rev().take(20).collect();
    tail.into_iter().rev().collect::<Vec<_>>().join("\n")
}

/// quinn client endpoint with the harness certificate as the only root and
/// ALPN `h3`. The client advertises the same `max_datagram_frame_size` as the
/// server and a receive window large enough for the 10 MiB concurrent echo.
fn build_client(identity: &Identity) -> (quinn::Endpoint, quinn::ClientConfig) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let provider = rustls::crypto::ring::default_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            identity.certificate_der.clone(),
        ))
        .expect("trust the harness certificate");
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QUIC client configuration");
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(ADVERTISED_MAX_DATAGRAM_FRAME_SIZE));
    transport.stream_receive_window(quinn::VarInt::from_u32(2 * MIB as u32));
    transport.receive_window(quinn::VarInt::from_u32(64 * MIB as u32));
    config.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("loopback address"))
        .expect("client endpoint");
    (endpoint, config)
}

/// One H3 connection: QUIC connection plus the kept-alive control streams.
struct H3Connection {
    connection: quinn::Connection,
    _control_send: quinn::SendStream,
    _control_recv: quinn::RecvStream,
}

async fn open_h3(
    endpoint: &quinn::Endpoint,
    config: &quinn::ClientConfig,
    address: SocketAddr,
) -> H3Connection {
    let connecting = endpoint
        .connect_with(config.clone(), address, "localhost")
        .expect("start the QUIC connection");
    let connection = tokio::time::timeout(SESSION_TIMEOUT, connecting)
        .await
        .expect("QUIC handshake timeout")
        .expect("QUIC handshake");

    let mut settings = Settings::default();
    settings.enable_webtransport(1);
    // One GREASE pair: the server must record it as ignored, not reject it.
    settings.insert(Setting(VarInt::from_u32(0x5f)), VarInt::from_u32(7));
    let mut control_send = connection.open_uni().await.expect("open control stream");
    settings
        .write(&mut control_send)
        .await
        .expect("write client SETTINGS");
    let mut control_recv = connection
        .accept_uni()
        .await
        .expect("accept server control");
    let server_settings = Settings::read(&mut control_recv)
        .await
        .expect("read server SETTINGS");

    let qpack_capacity = server_settings
        .get(&Setting::QPACK_MAX_TABLE_CAPACITY)
        .map(|value| value.into_inner());
    let qpack_blocked = server_settings
        .get(&Setting::QPACK_BLOCKED_STREAMS)
        .map(|value| value.into_inner());
    let connect_protocol = server_settings
        .get(&Setting::ENABLE_CONNECT_PROTOCOL)
        .map(|value| value.into_inner());
    let datagram = server_settings
        .get(&Setting::ENABLE_DATAGRAM)
        .map(|value| value.into_inner());
    let max_sessions = server_settings
        .get(&Setting::WEBTRANSPORT_MAX_SESSIONS)
        .map(|value| value.into_inner());

    assert_eq!(qpack_capacity, Some(0), "QPACK dynamic table disabled");
    assert_eq!(qpack_blocked, Some(0), "QPACK blocked streams disabled");
    assert_eq!(connect_protocol, Some(1), "extended CONNECT enabled");
    assert_eq!(datagram, Some(1), "H3 DATAGRAM enabled");
    assert_eq!(max_sessions, Some(100), "WEBTRANSPORT_MAX_SESSIONS value");
    assert!(
        server_settings
            .get(&Setting(VarInt::from_u32(0x2C7C_F000)))
            .is_none(),
        "SETTINGS_WT_ENABLED (0x2c7cf000) must not be advertised (N4 ruling)"
    );

    H3Connection {
        connection,
        _control_send: control_send,
        _control_recv: control_recv,
    }
}

/// One WebTransport session: the extended CONNECT exchange and both halves of
/// the CONNECT stream.
struct Session {
    id: u64,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl Session {
    fn finish(&mut self) -> Result<(), quinn::ClosedStream> {
        self.send.finish()
    }
}

async fn connect_session(connection: &quinn::Connection, address: SocketAddr) -> Session {
    let (mut send, mut recv) = connection.open_bi().await.expect("open CONNECT stream");
    let url = url::Url::parse(&format!("https://{address}/session")).expect("session URL");
    ConnectRequest::new(url)
        .write(&mut send)
        .await
        .expect("write CONNECT request");
    let response = ConnectResponse::read(&mut recv)
        .await
        .expect("read CONNECT response");
    assert_eq!(
        response.status,
        web_transport_proto::http::StatusCode::OK,
        "the harness must accept every loopback session with 200"
    );
    Session {
        id: u64::from(send.id()),
        send,
        recv,
    }
}

fn assert_reset_prefix(observation: &ResetObservation) {
    assert!(
        observation.payload.len() <= SERVER_RESET_PAYLOAD_LEN,
        "the reset stream cannot carry more than the written prefix"
    );
    let expected = pattern(SERVER_RESET_PAYLOAD_LEN);
    assert_eq!(
        observation.payload,
        expected[..observation.payload.len()],
        "the reset stream must carry a prefix of the deterministic payload"
    );
}

fn quarter_header_for(session_id: u64) -> Vec<u8> {
    let mut header = Vec::new();
    VarInt::from_u64(session_id >> 2)
        .expect("quarter stream id")
        .encode(&mut header);
    header
}

/// Writes a WebTransport data-stream header: `0x54`+session for
/// unidirectional streams, `0x41`+session for bidirectional streams
/// (`draft-ietf-webtrans-http3-15` sections 4.2 and 4.3).
async fn write_wt_header(send: &mut quinn::SendStream, unidirectional: bool, session: u64) {
    let mut header = Vec::new();
    if unidirectional {
        StreamUni::WEBTRANSPORT.encode(&mut header);
    } else {
        Frame::WEBTRANSPORT.encode(&mut header);
    }
    VarInt::from_u64(session)
        .expect("session id")
        .encode(&mut header);
    send.write_all(&header)
        .await
        .expect("write WT stream header");
}

/// Reads one server-initiated WebTransport unidirectional stream.
async fn read_wt_uni(connection: &quinn::Connection) -> (u64, Vec<u8>) {
    let mut recv = connection.accept_uni().await.expect("accept server uni");
    let stream_type = VarInt::read(&mut recv).await.expect("stream type");
    assert_eq!(
        stream_type.into_inner(),
        0x54,
        "server unidirectional stream type"
    );
    let session = VarInt::read(&mut recv).await.expect("session id");
    let data = recv
        .read_to_end(2 * MIB + 1024)
        .await
        .expect("read server uni payload");
    (session.into_inner(), data)
}

struct ResetObservation {
    /// Session header, if the server managed to deliver it before the reset.
    /// `RESET_STREAM` may discard queued stream data, so this is optional; the
    /// server log is the authoritative record of the deliberate reset.
    session: Option<u64>,
    /// Payload bytes that arrived before the reset (header excluded).
    payload: Vec<u8>,
    reset_code: Option<u64>,
}

/// Reads one server-initiated bidirectional WebTransport stream until reset.
///
/// The read goes through `RecvStream::read` from the first byte on purpose:
/// the first read reports `ReadError::Reset`, whereas a varint helper would
/// consume that error while trying to read the header.
async fn read_wt_bi_reset(connection: &quinn::Connection) -> ResetObservation {
    let (_send, mut recv) = connection.accept_bi().await.expect("accept server bi");
    let mut raw = Vec::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut reset_code = None;
    loop {
        match recv.read(&mut buffer).await {
            Ok(Some(len)) => raw.extend_from_slice(&buffer[..len]),
            Ok(None) => break,
            Err(quinn::ReadError::Reset(code)) => {
                reset_code = Some(code.into_inner());
                break;
            }
            Err(error) => panic!("server reset stream read failed: {error}"),
        }
    }

    let mut session = None;
    let mut payload = Vec::new();
    if !raw.is_empty() {
        let mut slice = &raw[..];
        if let Ok(signal) = VarInt::decode(&mut slice) {
            if signal.into_inner() == 0x41 {
                if let Ok(id) = VarInt::decode(&mut slice) {
                    session = Some(id.into_inner());
                }
            }
        }
        if !slice.is_empty() {
            payload = slice.to_vec();
        }
    }

    ResetObservation {
        session,
        payload,
        reset_code,
    }
}

struct DatagramEcho {
    sent: Vec<u8>,
    received: Vec<u8>,
    lost: usize,
}

/// Sends `count` datagrams of `payload_len` bytes one at a time and verifies
/// each echo before sending the next. The receive budget equals the advertised
/// `max_datagram_frame_size`, so this keeps the loss check attributable to the
/// harness rather than to an overrun queue.
async fn datagram_echo(
    connection: &quinn::Connection,
    quarter_header: &[u8],
    payload_len: usize,
    count: usize,
) -> DatagramEcho {
    let payload = pattern(payload_len);
    let mut sent = Vec::new();
    let mut received = Vec::new();
    let mut lost = 0usize;
    for _ in 0..count {
        let mut packet = quarter_header.to_vec();
        packet.extend_from_slice(&payload);
        connection
            .send_datagram(Bytes::from(packet))
            .expect("send datagram");
        match tokio::time::timeout(Duration::from_secs(5), connection.read_datagram()).await {
            Ok(Ok(bytes)) => {
                let mut slice = &bytes[..];
                let echoed_quarter = VarInt::decode(&mut slice).expect("echoed quarter stream id");
                let header_len = bytes.len() - slice.len();
                assert_eq!(
                    echoed_quarter.into_inner(),
                    VarInt::decode(&mut &quarter_header[..])
                        .expect("expected quarter")
                        .into_inner(),
                    "echo must target the same session"
                );
                assert_eq!(
                    &bytes[header_len..],
                    &payload[..],
                    "echo must be byte-identical"
                );
                received.extend_from_slice(&bytes[header_len..]);
            }
            _ => lost += 1,
        }
        sent.extend_from_slice(&payload);
    }
    DatagramEcho {
        sent,
        received,
        lost,
    }
}

/// Writes one capsule inside an H3 DATA frame on the CONNECT stream
/// (`RFC 9297` section 3.2; the reference `Http3CapsuleReader` confirms this
/// carriage).
async fn write_capsule(send: &mut quinn::SendStream, capsule: &Capsule) {
    let mut capsule_bytes = Vec::new();
    capsule.encode(&mut capsule_bytes);
    let mut frame_bytes = Vec::new();
    Frame::DATA.encode(&mut frame_bytes);
    VarInt::from_u64(capsule_bytes.len() as u64)
        .expect("capsule length")
        .encode(&mut frame_bytes);
    frame_bytes.extend_from_slice(&capsule_bytes);
    send.write_all(&frame_bytes).await.expect("write capsule");
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from(index % 256).unwrap_or(0))
        .collect()
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut text = String::with_capacity(64);
    for byte in digest {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

struct Row {
    item: String,
    sends: u64,
    receives: u64,
    lost: u64,
    bytes: u64,
    sha256: String,
    detail: String,
}

fn render_rows(rows: &[Row]) -> String {
    let mut text = String::new();
    text.push_str(
        "# rtx-wt-server loopback matrix\n\
         # columns: item\tsends\treceives\tlost\tbytes\tsha256\tdetail\n",
    );
    for row in rows {
        text.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            row.item, row.sends, row.receives, row.lost, row.bytes, row.sha256, row.detail
        ));
    }
    text
}

async fn wait_for_log(path: &Path, predicate: impl Fn(&str) -> bool, what: &str) {
    for _ in 0..1000 {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if predicate(&text) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "the server log never satisfied {what}\n--- tail ---\n{}",
        log_tail(path)
    );
}
