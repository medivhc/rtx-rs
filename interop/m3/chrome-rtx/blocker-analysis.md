# R6-4 B0 blocker isolation (diagnostic, not R6-4 evidence)

This note records a **throwaway local diagnostic** run after the R6-4 phase-2
evidence in `2026-10-29-chrome-155.0.8059.39/report.md`. It is not a deliverable
protocol result and it is not part of the committed harness: the diagnostic
binary was a copy of `interop/m3/rtx-server/` under `/tmp`, with the path
dependencies rewritten to the workspace and one environment-driven hook
(`RX_EXTRA_SETTINGS`) that appends extra SETTINGS pairs to the server payload
after `Settings::encode`. No repository file was changed for this diagnostic.

## Observed R6-4 result without the hook

The authorised phase-2 harness accepts Chrome's QPACK capacity and sends its
fixed five-item SETTINGS, then Chrome's netlog records:

```
QUIC_SESSION_WEBTRANSPORT_CLIENT_STATE_CHANGED
  {"error": {"details": "net::ERR_METHOD_NOT_SUPPORTED", "net_error": -322},
   "last_state": "CONNECTING", "next_state": "FAILED"}
```

No extended CONNECT is sent (`connect_request_decoded=0`). This is the
`GAP-M3-B0-02` blocker in the phase-2 report.

## Which server SETTINGS pair unlocks Chrome

Same page, same Chrome 155.0.8059.39, same harness copy; only the server
SETTINGS payload differs. Each probe was a single Chrome run on isolated ports.

| server SETTINGS (on top of the fixed five) | B0 result |
|---|---|
| none (authorised R6-4 harness) | FAIL, `net::ERR_METHOD_NOT_SUPPORTED` |
| `0x2a2a2a2a=1` (GREASE, same 5-byte payload growth) | FAIL, `net::ERR_METHOD_NOT_SUPPORTED` |
| `0x2b603743=1` (pre-draft-07 max-sessions, deprecated) | FAIL, `net::ERR_METHOD_NOT_SUPPORTED` |
| `0x2c7cf000=1` (`SETTINGS_WT_ENABLED`, draft-15) | FAIL, `net::ERR_METHOD_NOT_SUPPORTED` |
| `0x2b603742=1` (legacy `ENABLE_WEBTRANSPORT`) | **PASS**, `WebTransport.ready` in 28 ms |

The GREASE probe rules out "Chrome just needed a longer SETTINGS payload"; the
`0x2b603743` and `0x2c7cf000` probes rule out the adjacent deprecated and
draft-15 identifiers. Chrome 155 requires the legacy **`ENABLE_WEBTRANSPORT`
(`0x2b603742=1`)** from the server, in addition to `ENABLE_CONNECT_PROTOCOL`
(`0x08=1`) and `H3_DATAGRAM` (`0x33=1`), which the harness already sends.

## What the full matrix did with `0x2b603742=1` injected

One complete diagnostic run (page unchanged, ports 4444/8444):

- B0 PASS (ready 28 ms; server `connect_request_decoded` + `status=200`).
- B1 PASS: tiers 1 B / 1000 B / 1067 B, each 1000 sends and 1000 echoes,
  **0 lost**, 0 mismatches, 0 timeouts; per-tier SHA-256
  `6e340b9c…`, `a8af099b…`, `6ddba3c6…`. Server log: 3000
  `datagram_received`, 3000 `datagram_sent`, 0 `datagram_echo_failed`.
- B2: server-initiated uni 1 MiB PASS; client uni 1 MiB PASS; client bi 1 MiB
  PASS; 10 concurrent bi 1 MiB PASS (all SHA-256
  `fbbab289…`); client reset sent (server log `stream_reset role=client` = 1).
  **Server-reset observation FAIL**: `incomingBidirectionalStreams` never
  yielded the harness' 4096-byte-then-`RESET_STREAM(code 7)` stream
  (`bi_streams` empty), although the server log records the reset
  (`stream_reset role=server code=7`). Chrome appears to drop a
  server-initiated bidirectional stream whose reset arrives before the
  WebTransport stream header can be delivered to the page.
- `WT_CLOSE_SESSION` (`transport.close()`) and a second session on the same
  harness process PASS (`connect_request_decoded` = 2, `status=200` = 2,
  `session_closed` = 2).

So one server-SETTINGS pair is the current B0 gate; the B2 server-reset
observation is a separate follow-up question (delay the harness reset, or find
another Chrome-side observable) that also needs a harness change and is not
authorised here.

## Why this is not committed

R6-4's authorised changes are (1) the new `interop/m3/chrome-rtx/` page and
runner and (2) one client-SETTINGS branch in `main.rs`, with "服务端 SETTINGS
5 项不变" explicitly fixed. Emitting `0x2b603742` changes the server SETTINGS
payload, so it is a coordinator decision (follow-up unit), not something this
task may fold in silently. The R6-2c reference server sends the pair (through
`web-transport-proto`'s deprecated setting support) and Chrome establishes the
session against it, which independently corroborates the isolation above.

## Reproduce the diagnostic (outside the repository)

```
cp -a interop/m3/rtx-server /tmp/relaxed-server
sed -i 's#path = "../../../crates/#path = "/workspace/crates/#g' /tmp/relaxed-server/Cargo.toml
# patch send_server_settings to append varint pairs listed in RX_EXTRA_SETTINGS
cargo build --release --manifest-path /tmp/relaxed-server/Cargo.toml
RX_EXTRA_SETTINGS="2b603742=1" /tmp/relaxed-server/target/release/rtx-wt-server ...
```

The environment hook and the run commands are intentionally not committed; the
deliverable harness stays at the five-item SETTINGS payload.
