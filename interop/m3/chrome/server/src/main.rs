//! Minimal HTTP/3 + WebTransport reference server used *only* to record the
//! raw bytes Chrome sends when it establishes a WebTransport session.
//!
//! Responsibilities (deliberately narrow):
//!   1. complete the QUIC handshake (ALPN "h3", runtime self-signed certificate),
//!   2. accept the H3 control stream and record the client's SETTINGS frame
//!      verbatim (frame type varint + length varint + payload),
//!   3. accept the extended CONNECT request and record its HEADERS frame verbatim
//!      (QPACK-encoded field section, never decoded-then-re-encoded), then answer
//!      200 so the browser can finish session establishment and close.
//!
//! This server must not depend on any `rtx-*` crate: it is the independent
//! reference oracle for later interop work, not the object under test.

use std::{
    io::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use quinn::{Connection, RecvStream, ServerConfig, TransportConfig};
use sha2::{Digest, Sha256};
use web_transport_proto::{ConnectRequest, Setting, VarInt};

/// H3 control stream type (RFC 9114 section 6.2.1).
const STREAM_CONTROL: u64 = 0x00;
/// H3 QPACK encoder stream type.
const STREAM_QPACK_ENCODER: u64 = 0x02;
/// H3 QPACK decoder stream type.
const STREAM_QPACK_DECODER: u64 = 0x03;
/// H3 SETTINGS frame type (RFC 9114 section 7.2.4).
const FRAME_SETTINGS: u64 = 0x04;
/// H3 HEADERS frame type (RFC 9114 section 7.2.2).
const FRAME_HEADERS: u64 = 0x01;

/// Hard cap for a single captured frame payload (matches the reference codec's
/// MAX_FRAME_SIZE bound); the frames we care about are a few dozen bytes.
const MAX_CAPTURED_FRAME: usize = 64 * 1024;

type Res<T> = Result<T, String>;

#[derive(Clone)]
struct Log(Arc<Mutex<std::fs::File>>);

impl Log {
    fn open(path: &Path) -> Res<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        Ok(Self(Arc::new(Mutex::new(file))))
    }

    fn line(&self, message: String) {
        let text = format!("ts_ms={} {message}", now_ms());
        eprintln!("{text}");
        if let Ok(mut file) = self.0.lock() {
            let _ = writeln!(file, "{text}");
        }
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Reads one QUIC variable-length integer from the stream, returning both the
/// value and the exact bytes consumed (needed to keep raw frame bytes intact).
async fn read_varint(recv: &mut RecvStream) -> Res<(u64, Vec<u8>)> {
    let mut first = [0u8; 1];
    recv.read_exact(&mut first)
        .await
        .map_err(|e| format!("read varint prefix: {e}"))?;
    let len = 1usize << (first[0] >> 6);
    let mut raw = Vec::with_capacity(len);
    raw.push(first[0]);
    let mut value = u64::from(first[0] & 0x3f);
    for _ in 1..len {
        let mut next = [0u8; 1];
        recv.read_exact(&mut next)
            .await
            .map_err(|e| format!("read varint continuation: {e}"))?;
        raw.push(next[0]);
        value = (value << 8) | u64::from(next[0]);
    }
    Ok((value, raw))
}

/// Reads one H3 frame and returns `(frame_type, raw_frame_bytes, payload)`.
///
/// `raw_frame_bytes` is byte-identical to what the peer put on the wire: frame
/// type varint + length varint + payload. The payload is never rewritten.
async fn read_frame(recv: &mut RecvStream) -> Res<(u64, Vec<u8>, Vec<u8>)> {
    let (frame_type, type_bytes) = read_varint(recv).await?;
    let (length, length_bytes) = read_varint(recv).await?;
    let length = usize::try_from(length)
        .map_err(|_| "frame length does not fit in memory".to_string())?;
    if length > MAX_CAPTURED_FRAME {
        return Err(format!("frame payload {length} exceeds capture cap"));
    }
    let mut payload = vec![0u8; length];
    recv.read_exact(&mut payload)
        .await
        .map_err(|e| format!("read frame payload: {e}"))?;

    let mut raw = Vec::with_capacity(type_bytes.len() + length_bytes.len() + payload.len());
    raw.extend_from_slice(&type_bytes);
    raw.extend_from_slice(&length_bytes);
    raw.extend_from_slice(&payload);
    Ok((frame_type, raw, payload))
}

fn encode_varint(value: u64, buf: &mut Vec<u8>) {
    let varint = VarInt::from_u64(value).expect("value fits in a QUIC varint");
    varint.encode(buf);
}

fn encode_frame(frame_type: u64, payload: &[u8], buf: &mut Vec<u8>) {
    encode_varint(frame_type, buf);
    encode_varint(payload.len() as u64, buf);
    buf.extend_from_slice(payload);
}

/// Server SETTINGS, produced by the audited reference codec so the advertised
/// capabilities match the reference server exactly: ENABLE_CONNECT_PROTOCOL,
/// ENABLE_DATAGRAM (plus the deprecated id Chrome still uses),
/// WEBTRANSPORT_MAX_SESSIONS (plus the pre-draft-07 deprecated ids), and
/// MAX_FIELD_SECTION_SIZE. The dynamic QPACK table stays disabled (capacity 0).
///
/// Returns the exact bytes written to the control stream: stream type varint
/// followed by the SETTINGS frame.
fn server_settings_bytes() -> Vec<u8> {
    let mut settings = web_transport_proto::Settings::default();
    settings.enable_webtransport(1);
    let mut buf = Vec::new();
    settings.encode(&mut buf);
    buf
}

/// Renders the captured SETTINGS payload as an identifier/value table using the
/// reference codec's setting names. Read-only: the raw bytes are untouched.
fn settings_table(payload: &[u8]) -> String {
    let mut cursor: &[u8] = payload;
    let mut out = String::new();
    while !cursor.is_empty() {
        let id = match VarInt::decode(&mut cursor) {
            Ok(v) => v,
            Err(_) => {
                out.push_str("unparsed trailing bytes (kept verbatim in settings-frame.bin)\n");
                break;
            }
        };
        let value = match VarInt::decode(&mut cursor) {
            Ok(v) => v,
            Err(_) => {
                out.push_str("unparsed trailing bytes (kept verbatim in settings-frame.bin)\n");
                break;
            }
        };
        let setting = Setting(id);
        out.push_str(&format!(
            "{setting:?} id=0x{:x} value={} (0x{:x})\n",
            id.into_inner(),
            value.into_inner(),
            value.into_inner()
        ));
    }
    out
}

async fn drain(mut recv: RecvStream, log: Log, label: &'static str) {
    let mut total = 0usize;
    loop {
        let mut buf = vec![0u8; 4096];
        match recv.read(&mut buf).await {
            Ok(None) => {
                log.line(format!("event=stream_closed label={label} bytes_after_capture={total}"));
                return;
            }
            Ok(Some(n)) => total += n,
            Err(err) => {
                log.line(format!(
                    "event=stream_error label={label} bytes_after_capture={total} error={err}"
                ));
                return;
            }
        }
    }
}

async fn handle_uni_stream(
    mut recv: RecvStream,
    tx: tokio::sync::mpsc::Sender<&'static str>,
    out: PathBuf,
    log: Log,
) {
    let (stream_type, _type_bytes) = match read_varint(&mut recv).await {
        Ok(v) => v,
        Err(err) => {
            log.line(format!("event=uni_stream_read_error error={err}"));
            return;
        }
    };
    log.line(format!("event=uni_stream_opened stream_type=0x{stream_type:x}"));

    if stream_type == STREAM_CONTROL {
        match read_frame(&mut recv).await {
            Ok((frame_type, raw, payload)) => {
                if frame_type != FRAME_SETTINGS {
                    log.line(format!(
                        "event=unexpected_first_control_frame frame_type=0x{frame_type:x} frame_bytes={}",
                        raw.len()
                    ));
                } else {
                    let hash = sha256_hex(&raw);
                    log.line(format!(
                        "event=h3_settings_frame_received frame_type=0x04 frame_bytes={} payload_bytes={} sha256={hash}",
                        raw.len(),
                        payload.len()
                    ));
                    let path = out.join("settings-frame.bin");
                    match std::fs::write(&path, &raw) {
                        Ok(()) => log.line(format!(
                            "event=capture_written file={} bytes={} sha256={hash}",
                            path.display(),
                            raw.len()
                        )),
                        Err(err) => {
                            log.line(format!("event=capture_write_failed file={} error={err}", path.display()));
                            return;
                        }
                    }
                    let table = settings_table(&payload);
                    let _ = std::fs::write(out.join("settings-decoded.txt"), table);
                    let _ = tx.send("settings").await;
                }
            }
            Err(err) => {
                log.line(format!("event=settings_read_error error={err}"));
                return;
            }
        }
        drain(recv, log, "control").await;
    } else if stream_type == STREAM_QPACK_ENCODER || stream_type == STREAM_QPACK_DECODER {
        // Not decoded: only recorded so the log shows the client set up QPACK.
        drain(recv, log, "qpack").await;
    } else {
        drain(recv, log, "other_uni").await;
    }
}

async fn handle_uni_loop(
    conn: Connection,
    tx: tokio::sync::mpsc::Sender<&'static str>,
    out: PathBuf,
    log: Log,
) {
    loop {
        let recv = match conn.accept_uni().await {
            Ok(recv) => recv,
            Err(err) => {
                log.line(format!("event=accept_uni_ended error={err}"));
                return;
            }
        };
        let tx = tx.clone();
        let out = out.clone();
        let log = log.clone();
        tokio::spawn(async move { handle_uni_stream(recv, tx, out, log).await });
    }
}

async fn handle_request_stream(
    mut send: quinn::SendStream,
    mut recv: RecvStream,
    tx: tokio::sync::mpsc::Sender<&'static str>,
    out: PathBuf,
    log: Log,
) {
    log.line("event=request_stream_opened".to_string());
    loop {
        let (frame_type, raw, payload) = match read_frame(&mut recv).await {
            Ok(v) => v,
            Err(err) => {
                log.line(format!("event=request_stream_ended error={err}"));
                return;
            }
        };

        if frame_type != FRAME_HEADERS {
            log.line(format!(
                "event=request_frame_skipped frame_type=0x{frame_type:x} frame_bytes={}",
                raw.len()
            ));
            continue;
        }

        let hash = sha256_hex(&raw);
        log.line(format!(
            "event=h3_headers_frame_received frame_type=0x01 frame_bytes={} payload_bytes={} qpack_encoded=true sha256={hash}",
            raw.len(),
            payload.len()
        ));
        let path = out.join("connect-headers-frame.bin");
        match std::fs::write(&path, &raw) {
            Ok(()) => log.line(format!(
                "event=capture_written file={} bytes={} sha256={hash}",
                path.display(),
                raw.len()
            )),
            Err(err) => {
                log.line(format!("event=capture_write_failed file={} error={err}", path.display()));
                return;
            }
        }

        // Reference-codec decode, kept as an appendix-grade check only. The raw
        // bytes above stay authoritative; a decode failure does not alter them.
        match ConnectRequest::decode(&mut Bytes::from(raw.clone())) {
            Ok(request) => {
                let protocols = if request.protocols.is_empty() {
                    "-".to_string()
                } else {
                    request.protocols.join(",")
                };
                log.line(format!(
                    "event=connect_request_decoded url={} protocols={protocols} headers={:?}",
                    request.url, request.headers
                ));
            }
            Err(err) => log.line(format!(
                "event=connect_request_decode_failed error={err} raw_bytes_kept=true"
            )),
        }

        // QPACK-encoded 200 response: required insert count 0, delta base 0,
        // indexed field line with T=1 (static) pointing at QPACK static table
        // index 25 (":status 200"). 0xC0 | 25 = 0xD9; 0x99 would be a dynamic
        // reference and Chrome rejects it as an invalid relative index.
        let mut response = Vec::new();
        encode_frame(FRAME_HEADERS, &[0x00, 0x00, 0xd9], &mut response);
        if let Err(err) = send.write_all(&response).await {
            log.line(format!("event=response_write_failed error={err}"));
            return;
        }
        log.line(format!(
            "event=response_headers_sent status=200 frame_bytes={} sha256={}",
            response.len(),
            sha256_hex(&response)
        ));
        let _ = tx.send("connect").await;

        // The request stream becomes the WebTransport session. Stay event-driven:
        // keep reading until the browser closes the session/connection, and keep
        // the send half open meanwhile.
        drain(recv, log, "request").await;
        let _ = &mut send;
        return;
    }
}

async fn handle_bi_loop(
    conn: Connection,
    tx: tokio::sync::mpsc::Sender<&'static str>,
    out: PathBuf,
    log: Log,
) {
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(v) => v,
            Err(err) => {
                log.line(format!("event=accept_bi_ended error={err}"));
                return;
            }
        };
        let tx = tx.clone();
        let out = out.clone();
        let log = log.clone();
        tokio::spawn(async move { handle_request_stream(send, recv, tx, out, log).await });
    }
}

/// Handles one QUIC connection. Returns `true` once both frames were captured.
async fn handle_connection(conn: Connection, out: PathBuf, log: Log) -> Res<bool> {
    log.line(format!(
        "event=quic_handshake_complete remote={} stable_id={}",
        conn.remote_address(),
        conn.stable_id()
    ));

    // Server control stream must be opened and SETTINGS sent before the browser
    // will consider a WebTransport session at all. The reference codec writes
    // the control stream type byte followed by the SETTINGS frame.
    let mut control = conn
        .open_uni()
        .await
        .map_err(|e| format!("open control stream: {e}"))?;
    let settings = server_settings_bytes();
    control
        .write_all(&settings)
        .await
        .map_err(|e| format!("write server settings: {e}"))?;
    log.line(format!(
        "event=server_settings_sent bytes_including_stream_type={} sha256={}",
        settings.len(),
        sha256_hex(&settings)
    ));

    let (tx, mut rx) = tokio::sync::mpsc::channel::<&'static str>(4);
    let uni = tokio::spawn(handle_uni_loop(conn.clone(), tx.clone(), out.clone(), log.clone()));
    let bi = tokio::spawn(handle_bi_loop(conn.clone(), tx.clone(), out.clone(), log.clone()));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    let mut captured = 0usize;
    while captured < 2 {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(what)) => {
                log.line(format!("event=capture_ready what={what} captured={}", captured + 1));
                captured += 1;
            }
            Ok(None) => {
                uni.abort();
                bi.abort();
                return Err("capture tasks ended before both frames arrived".into());
            }
            Err(_) => {
                uni.abort();
                bi.abort();
                return Err("timed out waiting for SETTINGS and CONNECT HEADERS".into());
            }
        }
    }

    // Give the browser the chance to observe the 200 and close cleanly; this is
    // an event wait with a deadline, not a fixed sleep used as synchronization.
    let closed = tokio::time::timeout(Duration::from_secs(4), conn.closed()).await;
    log.line(match closed {
        Ok(reason) => format!("event=connection_closed reason={reason}"),
        Err(_) => "event=connection_close_wait_timeout_seconds=4".to_string(),
    });

    uni.abort();
    bi.abort();
    // Explicitly keep the server-side control stream alive until the connection ends.
    drop(control);
    Ok(true)
}

struct Args {
    cert: PathBuf,
    key: PathBuf,
    listen: String,
    out: PathBuf,
}

fn parse_args() -> Res<Args> {
    let mut cert = None;
    let mut key = None;
    let mut listen = None;
    let mut out = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let slot = match arg.as_str() {
            "--cert" => &mut cert,
            "--key" => &mut key,
            "--listen" => &mut listen,
            "--out" => &mut out,
            other => return Err(format!("unknown argument {other}")),
        };
        let value = args.next().ok_or_else(|| format!("missing value for {arg}"))?;
        *slot = Some(PathBuf::from(value));
    }
    Ok(Args {
        cert: cert.ok_or("--cert is required")?,
        key: key.ok_or("--key is required")?,
        listen: listen
            .ok_or("--listen is required")?
            .to_string_lossy()
            .into_owned(),
        out: out.ok_or("--out is required")?,
    })
}

fn load_server_config(args: &Args) -> Res<ServerConfig> {
    let cert_der = std::fs::read(&args.cert)
        .map_err(|e| format!("read {}: {e}", args.cert.display()))?;
    let key_der = std::fs::read(&args.key)
        .map_err(|e| format!("read {}: {e}", args.key.display()))?;

    // rustls is re-exported by quinn; the ring provider is the one compiled in
    // through quinn's `rustls-ring` feature.
    let _ = quinn::rustls::crypto::ring::default_provider().install_default();

    let mut tls = quinn::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
        )
        .map_err(|e| format!("invalid certificate/key: {e}"))?;
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let quic = QuicServerConfig::try_from(tls).map_err(|e| format!("quic server config: {e}"))?;
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(30).try_into().map_err(|e| format!("idle timeout: {e}"))?,
    ));
    let mut config = ServerConfig::with_crypto(Arc::new(quic));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("argument error: {err}");
            std::process::exit(2);
        }
    };

    if let Err(err) = std::fs::create_dir_all(&args.out) {
        eprintln!("cannot create {}: {err}", args.out.display());
        std::process::exit(2);
    }
    let log = match Log::open(&args.out.join("server.log")) {
        Ok(log) => log,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };

    let config = match load_server_config(&args) {
        Ok(config) => config,
        Err(err) => {
            log.line(format!("event=config_error error={err}"));
            std::process::exit(3);
        }
    };
    let endpoint = match quinn::Endpoint::server(config, args.listen.parse().expect("invalid --listen")) {
        Ok(endpoint) => endpoint,
        Err(err) => {
            log.line(format!("event=bind_error error={err}"));
            std::process::exit(3);
        }
    };
    log.line(format!(
        "event=endpoint_listening addr={} alpn=h3",
        endpoint.local_addr().map(|a| a.to_string()).unwrap_or_default()
    ));

    let run = async {
        loop {
            let incoming = tokio::time::timeout(Duration::from_secs(30), endpoint.accept())
                .await
                .map_err(|_| "no QUIC connection arrived within 30s".to_string())?
                .ok_or_else(|| "endpoint closed".to_string())?;
            let conn = incoming.await.map_err(|e| format!("handshake failed: {e}"))?;
            match handle_connection(conn, args.out.clone(), log.clone()).await {
                Ok(true) => return Ok::<(), String>(()),
                Ok(false) => continue,
                Err(err) => {
                    log.line(format!("event=connection_attempt_failed error={err}"));
                    continue;
                }
            }
        }
    };

    match tokio::time::timeout(Duration::from_secs(45), run).await {
        Ok(Ok(())) => {
            log.line("event=capture_complete".to_string());
            endpoint.close(0u32.into(), b"done");
        }
        Ok(Err(err)) => {
            log.line(format!("event=capture_failed error={err}"));
            endpoint.close(1u32.into(), b"failed");
            std::process::exit(4);
        }
        Err(_) => {
            log.line("event=capture_failed error=overall_timeout_seconds=45".to_string());
            endpoint.close(1u32.into(), b"failed");
            std::process::exit(4);
        }
    }
}
