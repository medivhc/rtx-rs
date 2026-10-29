# R6-3 WebTransport server harness loopback evidence

**What this proves:** the `rtx-wt-server` harness (built on `rtx-quic` +
`rtx-h3` + `rtx-webtransport`) completes the H3 handshake, accepts extended
CONNECT sessions, echoes WebTransport datagrams and streams, handles the
capsule protocol, and serves new sessions on the same QUIC connection. The
client is the independent audit-baseline oracle (`quinn` +
`web-transport-proto`), not `rtx-*` itself.

**What this does NOT prove:** browser (Chrome) interoperability. Chrome is
R6-4, not this unit. No `interop/m3/chrome/` report is produced or claimed
here, and loopback success must not be written up as a Chrome/M3-B pass.

## Environment

| item | value |
|---|---|
| repository commit | `c6c48973cb58098703e3e3d635d8cd83f2b10e09` |
| harness package / version | `rtx-wt-server` / `0.1.0` (standalone crate, not a workspace member) |
| date | 2026-10-29 |
| rustc | `rustc 1.92.0 (ded5c06cf 2025-12-08)` |
| OS | `Linux 6.18.5 x86_64 Ubuntu 24.04 LTS` |
| loopback client | `quinn` @ `9d729c1b6b7ad30d45d40265037eeeb9d98a7420`, `web-transport-proto` @ `d4e4e458da556ac3033c9b63f6db5110d3ab5adc` (dev-dependencies only) |
| server engine | `rtx-quic` -> `quinn-proto 0.11.19` (workspace pin) |
| transport | loopback UDP, ALPN `h3`, runtime self-signed certificate (mktemp, deleted by the EXIT trap) |

## Server SETTINGS actually emitted

`rtx-h3`'s encoder drops deprecated and unknown pairs, so the payload contains
exactly these five items (the R6-2c reference server's six-item payload
includes deprecated pairs that this codec refuses to emit by design):

| id | value | name |
|---|---|---|
| `0x1` | 0 | `QPACK_MAX_TABLE_CAPACITY` |
| `0x7` | 0 | `QPACK_BLOCKED_STREAMS` |
| `0x8` | 1 | `ENABLE_CONNECT_PROTOCOL` |
| `0x33` | 1 | `H3_DATAGRAM` |
| `0xc671706a` | 100 | `WEBTRANSPORT_MAX_SESSIONS` |

`0x2c7cf000` (`SETTINGS_WT_ENABLED` in `draft-ietf-webtrans-http3-15`
section 9.2) is **not** sent. N4 ruling: Chrome 156 negotiates the deprecated
`0x2b603742` signal, so emitting a codepoint no observed peer negotiates
would be an unverified behaviour. The `0xc671706a = 100` value is a harness
capacity choice for sequential + concurrent loopback sessions, not a protocol
requirement.

## DATAGRAM budget

- Negotiated `max_datagram_frame_size` (from the peer transport parameters
  captured at handshake, logged as `peer_max_datagram_frame_size`): **1100**
  bytes. It is not written by hand; the harness reads it out of
  `HandshakeInfo::peer_transport_parameters`.
- The "full" tier uses the largest payload both engines' receive accounting
  accepts: `1100 - 32 = 1068` bytes (quinn-proto 0.11.19 rejects
  `payload + size_of::<Datagram>()` above the advertised receive window; the
  0.12 client's send budget is `window - 9`). The HTTP Datagram payload is
  `1068` bytes = 1-byte quarter stream ID + 1067-byte WebTransport payload.

## Loopback matrix

Everything below is produced by `tests/loopback.rs`; `hashes.txt` is the
machine-readable copy. Payloads are the deterministic `0..255` cycle (first N
bytes), so every SHA-256 repeats across runs.

| item | sends | receives | lost | bytes | SHA-256 | detail |
|---|---|---|---|---|---|---|
| `datagram-echo-1b` | 100 | 100 | 0 | 100 | `cd00e292c5970d3c5e2f0ffa5171e555bc46bfc4faddfb4a418b6840b86e79a3` | wt_payload_bytes=1 quic_datagram_payload_max=1068 client_max_datagram_size=1091 advertised_max_datagram_frame_size=1100 quinn_datagram_metadata_bytes=32 |
| `datagram-echo-1000b` | 100 | 100 | 0 | 100000 | `d542d32400dc07f95f849a45601e811ec37bb68512b1aa1cde654396a8cb094f` | wt_payload_bytes=1000 quic_datagram_payload_max=1068 client_max_datagram_size=1091 advertised_max_datagram_frame_size=1100 quinn_datagram_metadata_bytes=32 |
| `datagram-echo-max` | 100 | 100 | 0 | 106700 | `6d7d7addc03995ccbdc5fa6533d6107020054f284aa60a7212374932db105208` | wt_payload_bytes=1067 quic_datagram_payload_max=1068 client_max_datagram_size=1091 advertised_max_datagram_frame_size=1100 quinn_datagram_metadata_bytes=32 |
| `datagram-wrong-session` | 1 | 0 | 0 | 0 | `-` | dropped_by_server=true connection_continued=true |
| `datagram-malformed` | 1 | 0 | 0 | 0 | `-` | dropped_by_server=true connection_continued=true |
| `session-drain` | 1 | 1 | 0 | 0 | `-` | capsule=WT_DRAIN_SESSION session_survived=true |
| `stream-client-uni-1m` | 1 | 1 | 0 | 1048576 | `fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83` | echo=server-opened-uni bytes=1048576 |
| `stream-client-bi-1m` | 1 | 1 | 0 | 1048576 | `fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83` | echo=same-stream half_close=true |
| `stream-concurrent-bi-1m` | 10 | 10 | 0 | 10485760 | `fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83` | streams=10 each_bytes=1048576 |
| `stream-client-reset-bi` | 1 | 0 | 0 | 0 | `-` | reset_code=7 server_observed_reset=true |
| `session-close-capsule` | 1 | 1 | 0 | 0 | `-` | capsule=WT_CLOSE_SESSION code=7 |
| `session-after-close` | 1 | 1 | 0 | 0 | `-` | new_session_after_flag=true |
| `session-connect-sequential` | 3 | 3 | 0 | 0 | `-` | connect_200=3 same_connection=true |
| `session-connect-concurrent` | 2 | 2 | 0 | 0 | `-` | connect_200=2 same_connection=true |
| `stream-server-uni-1m` | 5 | 5 | 0 | 5242880 | `fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83` | sessions=5 each_bytes=1048576 |
| `stream-server-reset-bi` | 5 | 5 | 0 | 0 | `-` | reset_code=7 resets_observed=5 |

Interpretation:

- all DATAGRAM tiers are pairwise echo (send one, verify one echo, repeat);
  loopback loss is 0 and every echo is byte-identical. Burst behaviour is R6-4
  work, where `M3-B1` records real loss numbers.
- wrong-session and empty (malformed) datagrams are dropped with a log line and
  the connection keeps echoing.
- client uni 1 MiB comes back on a new server uni stream; client bi and the 10
  concurrent bi streams come back on their own streams; half-close is used
  everywhere.
- the server opens a 1 MiB uni stream per session and a bi stream that it resets
  after 4096 bytes (code 7); the client observes the reset. A deliberate
  `RESET_STREAM` may discard stream data, so the session header is optional on
  the reset stream; the server log records the reset.
- `WT_DRAIN_SESSION` is logged and the session survives (a datagram still
  echoes); `WT_CLOSE_SESSION` ends the session and the same QUIC connection
  serves a new session afterwards.

## Protocol boundaries

- **Capsule carriage:** capsules travel inside HTTP/3 DATA frames on the
  CONNECT stream (`RFC 9297` section 3.2; the audited
  `web-transport-proto::Http3CapsuleReader` reads them the same way). The
  capsule bytes themselves are `rtx-webtransport`'s codec.
- **QPACK:** encoder emits static-table references and non-Huffman literals
  only; the prefix is `00 00`. The decoder rejects a SETTINGS combination with
  non-zero `QPACK_MAX_TABLE_CAPACITY` / `QPACK_BLOCKED_STREAMS`
  (`ensure_dynamic_table_disabled`) and closes the connection with
  `H3_SETTINGS_ERROR`. The loopback client deliberately advertises neither
  (the reference codec's `enable_webtransport` does not send them).
- **DATAGRAM semantics:** QUIC DATAGRAM is unreliable and unordered; the
  harness never truncates and logs a failed echo explicitly. Loopback losing
  nothing is an observation about this environment, not a protocol guarantee.
- **Session identifiers:** the session ID is the CONNECT stream ID
  (client-initiated bidirectional, `≡ 0 mod 4`); the HTTP Datagram quarter
  stream ID is `SessionId >> 2` (`rtx-webtransport::ids`). Streams carry
  `0x54`+session ID (uni) or `0x41`+session ID (bi), per
  `draft-ietf-webtrans-http3-15` sections 4.2 and 4.3.
- **CLOSE/DRAIN:** `WT_CLOSE_SESSION` removes the session, finishes the
  CONNECT send side and abandons leftover server-initiated streams with
  `WT_SESSION_GONE`. `WT_DRAIN_SESSION` only logs and marks the session
  drained; it does not close the connection.

## Server log summary

```
ts_ms=1793265462635 event=server_listening addr=127.0.0.1:33916 alpn=h3
ts_ms=1793265462636 event=config_loaded max_datagram_frame_size_advertised=1100 webtransport_max_sessions=100 server_uni_payload_bytes=1048576 server_reset_payload_bytes=4096
ts_ms=1793265462668 event=quic_handshake_complete connection=0 alpn=Some([104, 51]) datagram_supported=true peer_max_datagram_frame_size=1100
ts_ms=1793265462669 event=h3_settings_frame_received connection=0 payload_bytes=31 items=7
ts_ms=1793265462669 event=server_settings_sent connection=0 control_stream=3 items=5 payload_bytes=18 frame_bytes=20
ts_ms=1793265462671 event=connect_request_decoded connection=0 session=0 stream=0 scheme=https authority=127.0.0.1:33916 path=/session protocol=webtransport
ts_ms=1793265462671 event=response_headers_sent connection=0 session=0 stream=0 status=200 qpack_bytes=3 frame_bytes=5
ts_ms=1793265462922 event=session_closed connection=0 session=0 reason=connect_fin code=0
ts_ms=1793265462943 event=connect_request_decoded connection=0 session=4 stream=4 scheme=https authority=127.0.0.1:33916 path=/session protocol=webtransport
ts_ms=1793265462943 event=response_headers_sent connection=0 session=4 stream=4 status=200 qpack_bytes=3 frame_bytes=5
ts_ms=1793265463059 event=session_drained connection=0 session=4
ts_ms=1793265464567 event=session_closed connection=0 session=4 reason=capsule code=7 message="loopback close"
ts_ms=1793265464569 event=connect_request_decoded connection=0 session=56 stream=56 scheme=https authority=127.0.0.1:33916 path=/session protocol=webtransport
ts_ms=1793265464569 event=response_headers_sent connection=0 session=56 stream=56 status=200 qpack_bytes=3 frame_bytes=5
ts_ms=1793265464641 event=session_closed connection=0 session=56 reason=connect_fin code=0
ts_ms=1793265464664 event=connection_close connection=0 reason=application origin=remote code=0 bytes=15
ts_ms=1793265464668 event=quic_handshake_complete connection=1 alpn=Some([104, 51]) datagram_supported=true peer_max_datagram_frame_size=1100
ts_ms=1793265464669 event=h3_settings_frame_received connection=1 payload_bytes=31 items=7
ts_ms=1793265464670 event=server_settings_sent connection=1 control_stream=3 items=5 payload_bytes=18 frame_bytes=20
ts_ms=1793265464670 event=connect_request_decoded connection=1 session=0 stream=0 scheme=https authority=127.0.0.1:33916 path=/session protocol=webtransport
ts_ms=1793265464670 event=response_headers_sent connection=1 session=0 stream=0 status=200 qpack_bytes=3 frame_bytes=5
ts_ms=1793265464688 event=connect_request_decoded connection=1 session=4 stream=4 scheme=https authority=127.0.0.1:33916 path=/session protocol=webtransport
ts_ms=1793265464688 event=response_headers_sent connection=1 session=4 stream=4 status=200 qpack_bytes=3 frame_bytes=5
ts_ms=1793265464801 event=session_closed connection=1 session=0 reason=connect_fin code=0
ts_ms=1793265464801 event=session_closed connection=1 session=4 reason=connect_fin code=0
ts_ms=1793265464889 event=connection_close connection=1 reason=application origin=remote code=0 bytes=15
```

Full log: `server.log` (779 lines).

## Not done (explicitly)

- Chrome / Firefox interoperability (R6-4: B0/B1/B2/B3/B5).
- B4 `quinn` reference interop records (this `quinn` is only the loopback
  client, not an interop statement).
- benchmarks (P7), embedded ports (P8), full HTTP/3, QPACK dynamic table,
  Huffman encoder, 0-RTT, connection migration, multi-session defaults.
- no modification of existing crates, existing docs, `interop/m3/chrome/`,
  CI, or the workspace manifest.

## Reproduce

```
./interop/m3/rtx-server/run-loopback.sh
```

The script generates the DER certificate/key with openssl in a mktemp directory,
runs `cargo test --test loopback`, copies `server.log`/`hashes.txt` here and
regenerates this report. No key material enters the repository.
