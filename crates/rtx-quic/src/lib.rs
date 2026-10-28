#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! Narrow Sans-I/O facade over `quinn-proto` for the Linux QUIC path.
//!
//! This crate is the R6-1 slice of the M3 milestone: it wraps only the
//! `quinn-proto` capabilities that WebTransport actually needs and deliberately
//! does **not** mirror the entire Quinn API
//! (`ARCHITECTURE.md` §14: “Do not mirror the entire Quinn public API”).
//!
//! The facade owns no socket, spawns no task, reads no clock after endpoint
//! construction and never depends on Tokio. The caller feeds UDP datagrams in
//! with [`Endpoint::handle_datagram`], takes datagrams out with
//! [`Endpoint::poll_transmit`] and drives timers with
//! [`Endpoint::poll_timeout`] / [`Endpoint::handle_timeout`]. Time is always
//! the injected [`rtx_core::Timestamp`]; see “Time model” below.
//!
//! # Feature gate
//!
//! The crate is Tier D (`std`, Linux). `std` is a default feature. With
//! `--no-default-features` the crate compiles empty, so the workspace-wide
//! bare-metal check (`cargo check --workspace --no-default-features --target
//! thumbv7em-none-eabihf`) does not attempt to build `quinn-proto`, which
//! requires `std`. No embedded QUIC support is claimed: the ARCH §14 embedded
//! backend (fork/port of `quinn-proto`) is explicitly out of scope for this
//! unit.
//!
//! # 公共外观
//!
//! Every public item and its unique gate consumer. `M3-Q0`–`M3-Q8` and
//! `M3-0-1`–`M3-0-4` are the items in `docs/m3-m4-gates.md` §1.0–§1.1.
//!
//! | 公开项 | 唯一消费者 |
//! |---|---|
//! | [`Endpoint`] | M3-Q1（endpoint/connection creation） |
//! | [`Endpoint::new`] (`endpoint_new`) | M3-Q1 |
//! | [`Endpoint::connect`] (`endpoint_connect`) | M3-Q1 |
//! | [`Endpoint::accept`] (`endpoint_accept`) | M3-Q1 |
//! | [`Endpoint::refuse`] | M3-Q1 |
//! | [`Endpoint::handle_datagram`] | M3-Q1（调用方喂入 datagram，endpoint 不拥有 socket） |
//! | [`EndpointConfig`] | M3-Q1（ALPN、transport parameters、证书/私钥） |
//! | [`EndpointConfig::new`] | M3-Q1 |
//! | [`EndpointConfig::with_alpn`] | M3-Q1 |
//! | [`EndpointConfig::with_transport`] | M3-Q1 |
//! | [`EndpointConfig::with_server_identity`] | M3-Q1 |
//! | [`EndpointConfig::with_client_roots`] | M3-Q1 |
//! | [`EndpointConfig::with_rng_seed`] | M3-Q1（确定性测试） |
//! | [`TransportConfig`] | M3-Q1（transport parameters；其公开字段同属此行） |
//! | [`ConnectionId`] | M3-Q1（连接句柄） |
//! | [`ConnectionId::as_u64`] | M3-Q1 |
//! | [`EndpointError`] | M3-Q1（构造失败） |
//! | [`ConnectError`] | M3-Q1 |
//! | [`AcceptError`] | M3-Q1（accept/refuse） |
//! | [`EventKind::Incoming`] | M3-Q1（server 收到 incoming 并 accept/refuse） |
//! | [`Endpoint::poll_event`] | M3-Q2（握手子集）/ M3-Q7（关闭子集）——门禁把同名操作列在两处 |
//! | [`Event`] | M3-Q2 / M3-Q7（事件封装） |
//! | [`EventKind`] | M3-Q2 / M3-Q7（同上） |
//! | [`EventKind::HandshakeComplete`] | M3-Q2 |
//! | [`EventKind::HandshakeFailed`] | M3-Q2 |
//! | [`HandshakeInfo`] | M3-Q2（协商 ALPN、peer transport parameters、DATAGRAM 标志） |
//! | [`PeerTransportParameters`] | M3-Q2（上游规范化编码的 peer transport parameters） |
//! | [`PeerTransportParameters::as_bytes`] | M3-Q2 |
//! | [`HandshakeFailure`] | M3-Q2（证书 / ALPN / transport parameter / 超时） |
//! | [`Endpoint::open_uni`] (`open_uni`) | M3-Q3 |
//! | [`Endpoint::open_bi`] (`open_bi`) | M3-Q3 |
//! | [`Endpoint::accept_uni`] (`accept_uni`) | M3-Q3 |
//! | [`Endpoint::accept_bi`] (`accept_bi`) | M3-Q3 |
//! | [`Endpoint::write_stream`] | M3-Q3 |
//! | [`Endpoint::read_stream`] | M3-Q3 |
//! | [`Endpoint::finish_stream`] | M3-Q3（finish） |
//! | [`Endpoint::reset_stream`] | M3-Q3（reset） |
//! | [`Endpoint::stop_sending`] | M3-Q3（stop_sending） |
//! | [`StreamId`] | M3-Q3 |
//! | [`StreamId::as_u64`] | M3-Q3（流 ID 递增规则） |
//! | [`StreamId::direction`] | M3-Q3（流 ID 方向规则） |
//! | [`StreamId::index`] | M3-Q3（流 ID 递增规则） |
//! | [`Direction`] | M3-Q3 |
//! | [`StreamEvent`] | M3-Q3（opened/readable/writable/finished/stopped/available） |
//! | [`StreamRead`] | M3-Q3（数据 / FIN） |
//! | [`StreamError`] | M3-Q3 |
//! | [`Endpoint::send_datagram`] (`send_datagram`) | M3-Q4 |
//! | [`Endpoint::poll_datagram`] (`poll_datagram`) | M3-Q4 |
//! | [`DatagramError`] | M3-Q4 |
//! | [`Endpoint::poll_transmit`] (`poll_transmit`) | M3-Q5 |
//! | [`Transmit`] | M3-Q5 |
//! | [`Endpoint::poll_timeout`] (`poll_timeout`) | M3-Q6 |
//! | [`Endpoint::handle_timeout`] (`handle_timeout`) | M3-Q6 |
//! | [`Endpoint::close`] (`close`) | M3-Q7 |
//! | [`CloseReason`] | M3-Q7 |
//! | [`CloseOrigin`] | M3-Q7 |
//! | [`CloseError`] | M3-Q7 |
//! | [`EventKind::Closed`] | M3-Q7 |
//! | [`Endpoint::metrics`] (`metrics`) | M3-Q8 |
//! | [`Metrics`] | M3-Q8 |
//! | [`MetricsError`] | M3-Q8 |
//! | [`EventKind::Stream`] | M3-Q3 |
//! | [`EventKind::DatagramReceived`] | M3-Q4 |
//!
//! Public fields of structs are counted with their struct’s row; enum
//! variants are listed individually above. There is no generic passthrough,
//! no `quinn` runtime re-export, no socket ownership, no connection pool, no
//! automatic reconnect and no qlog output.
//!
//! # 门禁操作名映射
//!
//! `docs/m3-m4-gates.md` §1.1 fixes the operation names. They map to methods
//! as follows (the Rust API does not repeat the `endpoint_` prefix):
//!
//! | 门禁操作名 | 本 facade |
//! |---|---|
//! | `endpoint_new` | [`Endpoint::new`] |
//! | `endpoint_connect` | [`Endpoint::connect`] |
//! | `endpoint_accept` | [`Endpoint::accept`] |
//! | `poll_event` | [`Endpoint::poll_event`] |
//! | `open_uni` / `open_bi` / `accept_uni` / `accept_bi` | same names |
//! | `send_datagram` / `poll_datagram` | same names |
//! | `poll_transmit` | [`Endpoint::poll_transmit`] |
//! | `poll_timeout` / `handle_timeout` | same names |
//! | `close` | [`Endpoint::close`] |
//! | `metrics` | [`Endpoint::metrics`] |
//!
//! # `quinn-proto` version and audit delta
//!
//! `DEPENDENCY_AUDIT.md` §1 audits `quinn-rs/quinn` at
//! `9d729c1b6b7ad30d45d40265037eeeb9d98a7420`. That commit is the unreleased
//! `0.12.0` development line: its workspace manifest declares
//! `rust-version = "1.88.0"` and edition 2024, and it resolves `rand 0.10`,
//! `fastbloom 0.17`, `qlog 0.18` and `rcgen 0.14`. Git-pinning that revision
//! would raise this workspace’s effective MSRV above its declared 1.85 and
//! break the `suite (msrv)` CI job.
//!
//! This crate therefore uses the published crates.io release
//! **`quinn-proto 0.11.19`** (`rust-version = "1.85"`, edition 2021), pinned
//! exactly by `Cargo.lock`. Relationship to the audited revision:
//!
//! - same protocol engine and the same Sans-I/O decomposition that
//!   `DEPENDENCY_AUDIT.md` §5.1 relies on (`Endpoint::handle`,
//!   `Connection::poll`, `poll_transmit`, `poll_timeout`,
//!   `handle_timeout`, `Event`, `StreamEvent`, `DatagramEvent`);
//! - same dependency categories as §5.2 (`bytes`, `lru-slab`, `rustc-hash`,
//!   `rand`, `rand_pcg`, `slab`, `tinyvec(alloc)`, `tracing`, optional
//!   `rustls`/`ring`), plus `thiserror` and the newer `rand 0.10` line that
//!   the audit list does not enumerate;
//! - `bloom`, `log`, `qlog`, `aws-lc-rs` and `platform-verifier` are not
//!   enabled: this crate enables only `rustls-ring`;
//! - the 0.12 development line’s additions (edition 2024, MSRV 1.88,
//!   `fastbloom 0.17`, `qlog 0.18`, `rand 0.10` API churn) are not used by
//!   this facade.
//!
//! This is a deliberate, recorded downgrade from the audited development
//! head to the latest published release, not a silent version drift.
//! `measurements/m3/deps/quinn-tree.txt` and
//! `measurements/m3/deps/normal-tree.txt` archive the resolved graph.
//!
//! # TLS and crypto provider
//!
//! The facade fixes one provider: **rustls 0.23 with the `ring` provider,
//! TLS 1.3 only**. [`EndpointConfig`] takes DER-encoded certificate chains,
//! a PKCS#8 private key and DER-encoded client trust roots; no Rustls or
//! `quinn-proto` type appears in any public signature. Client certificates,
//! 0-RTT, session reuse, certificate pinning policies and platform verifiers
//! are not configured here.
//!
//! Tests generate a throw-away self-signed certificate for `localhost` with
//! `rcgen 0.13` (`generate_simple_self_signed`) inside the test process and
//! pass the DER bytes straight into [`EndpointConfig::with_server_identity`]
//! / [`EndpointConfig::with_client_roots`]. No key material is written to
//! disk or committed.
//!
//! # Time model
//!
//! All public time arguments and return values are [`rtx_core::Timestamp`]
//! (monotonic microseconds). `quinn-proto` requires `std::time::Instant`, so
//! the facade captures one process-local monotonic epoch (`Instant::now()`)
//! the first time an endpoint is built and maps `Timestamp` to
//! `epoch + micros`. No clock is read afterwards; protocol decisions,
//! timeouts and RTT samples use only the injected values. This adapter is
//! documented here because `ARCHITECTURE.md` §8 forbids protocol logic from
//! reading a clock directly.
//!
//! # DATAGRAM semantics
//!
//! QUIC DATAGRAM is unreliable and unordered: queued datagrams are never
//! retransmitted. [`Endpoint::send_datagram`] reports [`DatagramError::WouldBlock`]
//! when the send buffer is full and [`DatagramError::TooLarge`] when the
//! negotiated `max_datagram_frame_size` (or the current path budget) is
//! exceeded; it never truncates. [`Endpoint::poll_datagram`] copies one
//! received datagram into a caller-owned buffer and returns
//! [`DatagramError::BufferTooSmall`] instead of truncating; because the
//! transport is unreliable that datagram is then discarded. If the peer does
//! not advertise DATAGRAM support, [`Endpoint::send_datagram`] returns
//! [`DatagramError::UnsupportedByPeer`].
//!
//! # Resource budgets (`ARCHITECTURE.md` §16)
//!
//! Explicitly bounded by this facade (all values are plain fields of
//! [`TransportConfig`]):
//!
//! | 项 | 默认值 | 有界方式 |
//! |---|---|---|
//! | 并发双向/单向流 | 100 / 100 | `max_concurrent_bidi_streams` / `max_concurrent_uni_streams`（上游 `quinn-proto` 按 TP 执行） |
//! | 单流重组窗口 | 1 250 000 B | `stream_receive_window_bytes` |
//! | 连接级接收窗口 | 16 MiB | `connection_receive_window_bytes`（本 facade 默认，非上游默认） |
//! | DATAGRAM 接收队列 | 1 250 000 B；`None` 禁用 | `datagram_receive_buffer_bytes` |
//! | DATAGRAM 发送队列 | 1 MiB | `datagram_send_buffer_bytes` |
//!
//! Upstream-managed, not re-limited by the facade:
//!
//! - connection IDs: `quinn-proto` issues at most 8 local CIDs per connection
//!   (`LOC_CID_COUNT`) and enforces `active_connection_id_limit`;
//! - ACK state, packet-number spaces and retransmission buffers are internal
//!   `quinn-proto` structures without a public size knob;
//! - pending `Incoming` connections are bounded by `ServerConfig::max_incoming`
//!   (65 536), 10 MiB per incoming buffer and 100 MiB total, using upstream
//!   defaults; this facade does not expose those knobs;
//! - the crypto/TLS buffers use `quinn-proto` defaults (16 KiB for
//!   out-of-order CRYPTO data).
//!
//! Deliberately **not** bounded by this facade: the number of live
//! connections (one caller-created connection per handle; state is removed
//! once the connection drains), and the number of queued [`Event`]s (callers
//! must drain [`Endpoint::poll_event`]; unread events accumulate in order).
//! No pool, automatic reconnect or connection migration is provided.
//!
//! # Metrics provenance
//!
//! [`Metrics`] mixes four sources, all recorded at the facade or an upstream
//! public API:
//!
//! - smoothed/min RTT, cwnd, lost packets and DATAGRAM frame counters come
//!   from the public `ConnectionStats` / `Connection::rtt` /
//!   `Connection::min_rtt` API (`quinn-proto-0.11.19/src/connection/stats.rs`
//!   lines 136–166);
//! - `latest_rtt_micros` is the raw send→ACK interval observed in
//!   `congestion::Controller::on_ack` (upstream keeps `RttEstimator::latest`
//!   private at `src/connection/paths.rs` lines 291–300, and `PathStats`
//!   exposes only `rtt`/`min_rtt`; see `src/connection/stats.rs` lines
//!   136–166);
//! - `bytes_in_flight` is the value last reported to
//!   `congestion::Controller::on_end_acks` at an ACK batch boundary
//!   (`quinn-proto-0.11.19/src/congestion.rs` lines 37–46); it can lag the
//!   true value between ACK batches;
//! - stream byte counters are incremented by this facade when
//!   [`Endpoint::write_stream`] accepts bytes and [`Endpoint::read_stream`]
//!   delivers bytes.
//!
//! Pacing: upstream’s pacer (`quinn-proto-0.11.19/src/connection/pacing.rs`,
//! the `pub(super)` `Pacer` at lines 12–23) exposes neither rate nor token
//! state. The public `congestion::ControllerMetrics::pacing_rate` field
//! (`src/congestion.rs` lines 90–97) is always `None` for the built-in
//! `Cubic` and `NewReno` controllers (`src/congestion/cubic.rs` lines 226–232,
//! `src/congestion/new_reno.rs` lines 115–121). The facade therefore reports
//! `pacing_rate_bits_per_second = None` with the default controller and
//! forwards a value if a replacement controller ever provides one.
//! [`Metrics::snapshot_allocations`] is `0`: the snapshot is a `Copy` value
//! with no heap allocation.
//!
//! # Not implemented
//!
//! H3/WebTransport (R6-2), browser interop (R6-3), allocation/batch
//! benchmarks (P7), embedded ports/forks, socket ownership, batch syscalls,
//! connection pooling, automatic reconnect, qlog, 0-RTT, connection
//! migration and session resumption are out of scope.

#[cfg(feature = "std")]
mod addr;
#[cfg(feature = "std")]
mod config;
#[cfg(feature = "std")]
mod endpoint;
#[cfg(feature = "std")]
mod error;
#[cfg(feature = "std")]
mod event;
#[cfg(feature = "std")]
mod metrics;
#[cfg(feature = "std")]
mod stream;
#[cfg(feature = "std")]
mod telemetry;
#[cfg(feature = "std")]
mod time;

#[cfg(feature = "std")]
pub use config::{EndpointConfig, TransportConfig};
#[cfg(feature = "std")]
pub use endpoint::{ConnectionId, Endpoint, Transmit};
#[cfg(feature = "std")]
pub use error::{
    AcceptError, CloseError, ConnectError, DatagramError, EndpointError, MetricsError, StreamError,
};
#[cfg(feature = "std")]
pub use event::{
    CloseOrigin, CloseReason, Event, EventKind, HandshakeFailure, HandshakeInfo,
    PeerTransportParameters,
};
#[cfg(feature = "std")]
pub use metrics::Metrics;
#[cfg(feature = "std")]
pub use stream::{Direction, StreamEvent, StreamId, StreamRead};
