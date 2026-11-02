# GAP-M3-B0-02 closure evidence — Chrome WebTransport interop against `rtx-wt-server` (Chrome for Testing 155.0.8059.39)

**What this proves:** a real Chrome build completed the M3-B0/B1/B2 matrix against
the `rtx-wt-server` harness (`rtx-quic` + `rtx-h3` + `rtx-webtransport`) after the
harness began appending the Chrome-compat legacy `ENABLE_WEBTRANSPORT`
(`0x2b603742=1`) pair to its SETTINGS payload. The numbers, order checks, byte
counts and SHA-256 values below come from the browser page (`result.json`) and
the harness log (`server.log`).

**What this does not prove:** that `GAP-M3-B0-02` is closed, that the M3 gate
passes, B3 Firefox, B4 `quinn` reference interop, benchmarks, embedded use, or
full HTTP/3. `GAP-M3-B0-02` remains `OPEN` in `docs/m3-m4-gates.md` §5; only a
milestone acceptance PR / the coordinator changes GAP status. This report is
re-run evidence for that review.

## First-page summary

**B0 `PASS`:** extended CONNECT returned `200`, the harness logged
`connect_request_decoded` + `response_headers_sent status=200`, and
`WebTransport.ready` resolved in 69 ms; Chrome's netlog ends in
`CONNECTING -> CONNECTED` (`QUIC_SESSION_WEBTRANSPORT_SESSION_READY`).

**B1 `PASS`:** three tiers (1 B, 1000 B, negotiated 1067 B), each 1000
Chrome→server sends and 1000 echoes received, 0 lost, 0 mismatches, 0 timeouts.

**B2 `PASS`:** server-initiated 1 MiB uni, client uni 1 MiB, client bi 1 MiB and
10 concurrent bi 1 MiB streams all completed with matching SHA-256; client reset
observed by the harness; server reset observed by Chrome after the new 500 ms
delay (4096 bytes then `RESET_STREAM`; Chrome exposed `streamErrorCode=0`, the
harness logged code 7 — see the server-reset section).

**Registered GAP:** `GAP-M3-B0-02` is still `OPEN`; this run has 0 failures in
B0/B1/B2. The GAP status is not changed by this PR.

## Status

| item | status | detail |
|---|---|---|
| B0 | pass | ready 69 ms; extended CONNECT 200; server observed session |
| B1 | pass | 3 tiers × 1000 sends / 1000 echoes; 0 lost; 0 mismatches |
| B2 | pass | 6 stream/reset items; server-reset observed with a 500 ms delay |
| B3 | not_run | Firefox not exercised by this unit (out of scope) |
| B4 | not_run | `quinn` reference interop not exercised by this unit (out of scope) |
| B5 | GAP listed | `GAP-M3-B0-02` remains OPEN; status change belongs to acceptance |

## Environment

| item | value |
|---|---|
| repository commit (git rev-parse HEAD at generation) | `aae52dc0a56adcadd6b0cc229b00447826ad33ca` |
| harness tree id (git rev-parse HEAD:interop/m3/rtx-server) | `4b2b65f8e0f6104a5c1504aef100c4fc6ebd5e58` |
| harness main.rs SHA-256 | `18da6b8279ce7710a10a8e18e09038517c1cc439fb67434d45b33c5845ee9021` |
| harness diff vs HEAD | `none (harness identical to HEAD)` |
| Chrome (from the browser itself) | `Google Chrome for Testing 155.0.8059.39` |
| Chrome binary | `/root/.cache/puppeteer/chrome/linux-155.0.8059.39/chrome-linux64/chrome` |
| version source | `$CHROME --version`; raw output is in `chrome-version.txt` |
| OS | `Linux 6.18.5 x86_64 Ubuntu 24.04 LTS` |
| date | `2026-11-02` |
| harness address | `127.0.0.1:4433` |
| page origin | `https://127.0.0.1:8443` (served by `../page_server.py`) |
| WebTransport URL | `https://127.0.0.1:4433/session` |
| runner phase | `relaxed` (R6-4 lineage: client QPACK capacity relaxation + this unit's Chrome-compat pair) |
| matrix duration | 2767 ms |
| server alive after matrix | `yes` |

## Chrome launch parameters

```
--headless --no-sandbox --disable-gpu --disable-dev-shm-usage --no-proxy-server --ignore-certificate-errors-spki-list=fBfjofv6lKdUs/sSaT/le8QwJ362Ne11ChD6tgm0XOE= --origin-to-force-quic-on=127.0.0.1:4433 --user-data-dir=/tmp/tmp.UKIlNmbMTD/chrome-profile --enable-logging=stderr --log-net-log=/tmp/tmp.UKIlNmbMTD/netlog.json --v=0
https://127.0.0.1:8443/index.html?port=4433&phase=relaxed
```

## Certificate handling

- Self-signed RSA-2048, `CN=localhost`, SAN `DNS:localhost,IP:127.0.0.1`,
  generated at run time by `../run-chrome.sh` with `openssl`.
- Lives only in a `mktemp` directory outside the repository and is deleted by
  the EXIT trap. No private key, `.pem` or `.key` file is committed.
- Chrome accepts it through `--ignore-certificate-errors-spki-list` (test-only;
  this flag covers QUIC, `--ignore-certificate-errors` alone does not).

## Chrome SETTINGS observed (verbatim values)

| id | value | name | class |
|---|---|---|---|
| `0x1` | 65536 | QPACK_MAX_TABLE_CAPACITY | known |
| `0x6` | 16384 | MAX_FIELD_SECTION_SIZE | known |
| `0x7` | 100 | QPACK_BLOCKED_STREAMS | known |
| `0x33` | 1 | H3_DATAGRAM | known |
| `0xffd277` | 1 | H3_DATAGRAM (deprecated) | deprecated |
| `0x2b603742` | 1 | ENABLE_WEBTRANSPORT (deprecated) | deprecated |
| `0x8173b8b6c` | 264958592 | unknown/GREASE | grease |

Frame: `ts_ms=1793606594915 event=h3_settings_frame_received connection=0 payload_bytes=37 items=7`

Chrome sends the legacy `0x2b603742=1` itself and does **not** send
`0xc671706a` or `0x2c7cf000` in this build; the server's added pair is a
compatibility response, not a mirror of an observed draft-15 negotiation.

## Server SETTINGS actually emitted (6 pairs, no `0x2c7cf000`)

The harness logged the exact payload it assembled and put on the control stream:

```
ts_ms=1793606594915 event=server_settings_payload connection=0 payload_bytes=23 hex=0100070008013301c0000000c671706a4064ab60374201
```

Decoding that hex byte-for-byte (QUIC varint, `RFC 9000` §B):

| bytes | id | value | name |
|---|---|---|---|
| `01 00` | `0x1` | 0 | QPACK_MAX_TABLE_CAPACITY |
| `07 00` | `0x7` | 0 | QPACK_BLOCKED_STREAMS |
| `08 01` | `0x8` | 1 | ENABLE_CONNECT_PROTOCOL |
| `33 01` | `0x33` | 1 | H3_DATAGRAM |
| `c0 00 00 00 c6 71 70 6a 40 64` | `0xc671706a` | 100 | WEBTRANSPORT_MAX_SESSIONS |
| `ab 60 37 42 01` | `0x2b603742` | 1 | ENABLE_WEBTRANSPORT (Chrome-compat, deprecated) |

`0x2c7cf000` is **absent**. The base five pairs are byte-identical to the
R6-4 harness; the sixth pair is appended in
`interop/m3/rtx-server/src/main.rs::send_server_settings` *after*
`Settings::encode`, not through `server_settings()`, because `Settings::set`
returns `SettingError::NotEncodable` for deprecated identifiers and
`Settings::encode` skips them.

Corroborating evidence:

- the harness logs each pair (`event=server_setting`), including
  `id=0x2b603742 value=1 class=deprecated source=chrome_compat_after_encode`;
- the loopback oracle (`web-transport-proto`, dev-dependency only) decodes
  `Setting::WEBTRANSPORT_ENABLE_DEPRECATED = 1` from the server's wire SETTINGS
  in `tests/loopback.rs::open_h3`;
- Chrome 155 establishes the session in B0 only with this pair present (the
  R6-4 isolation table in `../blocker-analysis.md` shows the other probes fail).

## B0 — session establishment

| item | observed |
|---|---|
| `WebTransport.ready` | `pass`, 69 ms |
| extended CONNECT response | `status=200` (session 0, stream 0, qpack_bytes=3, frame_bytes=5) |
| server session observation | `event=connect_request_decoded connection=0 session=0 stream=0 scheme=https authority=127.0.0.1:4433 path=/session protocol=webtransport` |
| CONNECT rejections | 0 |
| Chrome netlog | `QUIC_SESSION_WEBTRANSPORT_SESSION_READY` (`http_datagram_version=Rfc`, `webtransport_http3_version=draft-02`); `CONNECTING -> CONNECTED` |

## B1 — DATAGRAM (Chrome ↔ harness)

| item | value |
|---|---|
| `peer_max_datagram_frame_size` (Chrome advertisement) | `65536` |
| harness `max_datagram_frame_size_advertised` | `1100` |
| negotiated tier derivation | `min(65536, 1100) - 32 (QUIC datagram accounting) - 1 (quarter stream ID) = 1067` |

Tier payloads are the deterministic `0..255` cycle (first N bytes); SHA-256 is
computed by the page with `crypto.subtle`. Each send was paired with its own
echo (`send i`, verify `echo i`, then `send i+1`), so the sequence check is
strict alternation rather than payload identity across a batch. QUIC DATAGRAM
is unreliable and unordered by design: 0 loss here is a measured result, not a
protocol guarantee.

| tier | payload bytes | Chrome→server sends | server received | lost | echo sent (server) | echo received (Chrome) | echo lost | order | SHA-256 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 1 | 1000 | 1000 | 0 | 1000 | 1000 | 0 | 0 mismatches / 0 timeouts | `6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d` |
| 1000 | 1000 | 1000 | 1000 | 0 | 1000 | 1000 | 0 | 0 mismatches / 0 timeouts | `a8af099bf2e878609558dbf69d8f88f4a31040a8cf84b549a0cfa912f12ffc3f` |
| negotiated | 1067 | 1000 | 1000 | 0 | 1000 | 1000 | 0 | 0 mismatches / 0 timeouts | `6ddba3c6303155a171c056307637a56d40e8f65b15a27e5daeca478c35222490` |

Server log counters: `datagram_received` 3000, `datagram_sent` 3000,
`datagram_echo_failed` 0, dropped (`wrong_session`/`malformed`/`decode_failed`/
`buffer_too_small`) 0. The harness stayed alive for the whole matrix.

## B2 — streams

| item | status | evidence |
|---|---|---|
| server-initiated uni (1 MiB) | pass | bytes=1048576; SHA-256 `fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83` |
| client uni 1 MiB + half-close echo | pass | sent/echo bytes=1048576; sent/echo SHA-256 `fbbab289…` |
| client bi 1 MiB + half-close echo | pass | sent/echo bytes=1048576; sent/echo SHA-256 `fbbab289…` |
| 10 concurrent bi 1 MiB | pass | streams=10, completed=10, bytes/stream=1048576, SHA-256 `fbbab289…`, mismatches=[] |
| client reset (`writable.abort()`) | reset_sent | 65536 bytes before reset; server log `stream_reset role=client` = 1 |
| server reset (4096 B then `RESET_STREAM`) | observed/pass | 4096 bytes delivered, Chrome error `Received RESET_STREAM.`, `streamErrorCode=0`; server log `stream_reset role=server code=7` = 1 |

Server log counters: `stream_finished role=client` 12, `stream_reset role=client`
1, `stream_reset role=server code=7` 1, `stream_opened kind=uni role=server
bytes=1048576` 2 (one per session), `stream_opened kind=bi role=server
reset_delay_ms=500` 2.

`fbbab289…` above is the full hash
`fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83`, the SHA-256
of the deterministic 1 MiB `0..255` pattern. All stream SHA-256 values match the
page-computed sent pattern.

## B2 server-reset observation — disposition

R6-4's diagnosis (`../blocker-analysis.md`) found that Chrome did not surface the
harness' server-initiated bidirectional stream when `RESET_STREAM` followed the
4096-byte payload immediately: `incomingBidirectionalStreams` stayed empty even
though the server log recorded the reset.

This unit changed only the harness timing: `SERVER_RESET_DELAY_MS = 500` holds
`reset_stream(code=7)` until 500 ms after the stream is opened, after the
4096-byte payload has been accepted by the endpoint. Evidence from the archived
run:

```
ts_ms=1793606594927 event=stream_opened connection=0 session=0 stream=1 kind=bi role=server bytes=4096 reset_code=7 reset_delay_ms=500
ts_ms=1793606595422 event=stream_reset connection=0 stream=1 role=server direction=bi code=7
```

The reset fires 495 ms after the stream opens (500 ms constant, pump granularity
≤ 50 ms). The page's `result.json` records
`bi_streams[0] = {status: "reset", bytes: 4096, error: "Received RESET_STREAM.", reset_code: 0}`
and `items.server_reset = {status: "pass", observed: true,
bytes_before_reset: 4096, reset_code: 0, other_streams_unaffected: true}`.

Disposition: the stream is now **observable** to Chrome with the 4096-byte
prefix, so the B2 server-reset item is not a remaining observation gap. Chrome
did not expose the numeric application code (`streamErrorCode=0`) even though
the harness sent `RESET_STREAM(code=7)`; the harness log is authoritative for
the code, and this browser-side code-reporting difference is recorded here
rather than silently rewritten as "code 7 observed by Chrome".

## Session close and second session

| item | observed |
|---|---|
| `transport.close()` (`WT_CLOSE_SESSION`) | `closed_by_client`; server `session_closed` lines: 2 |
| `transport.closed` event | `{'close_code': 0, 'reason': ''}` |
| second session on the same harness process | `pass` (ready) |
| `connect_request_decoded` / `response_headers_sent 200` totals | 2 / 2 |
| `connect_request_rejected` | 0 |

The second session was established on the same harness process after the first
session closed; its server-initiated pair is also logged (and its reset stream
is abandoned with `WT_SESSION_GONE` when the session closes immediately).

## B5 GAP table

| GAP | item | status in this run | detail |
|---|---|---|---|
| `GAP-M3-B0-02` | B0 | `OPEN` (unchanged by this PR) | R6-4 recorded B0 failure without legacy `0x2b603742`; this re-run at `aae52dc` establishes the session with the Chrome-compat pair, B1/B2 pass. Status change belongs to the milestone acceptance PR / coordinator. |

Failures recorded by the page in this run: **0**. This table does not close
`GAP-M3-B0-02`; it supplies the re-run evidence the acceptance review needs.
Other registered GAPs (including `GAP-M3-B3-01`) were not exercised and are
untouched by this unit.

## Not done (explicitly)

- no change to `crates/rtx-h3` (`ENCODABLE`, `Settings::set`, `Settings::encode`
  and constant values are untouched); the legacy pair is assembled in the
  harness after `Settings::encode`;
- `0x2c7cf000` (`SETTINGS_WT_ENABLED`, draft-15) is not sent;
- no CI change, no `docs/m3-m4-gates.md` §5 status or §6 conclusion change, no
  GAP status change, no other GAP/NB work;
- B3 Firefox and B4 `quinn` reference interop are not exercised;
- benchmarks (P7), embedded port (P8), full HTTP/3, QPACK dynamic table, 0-RTT,
  connection migration and multi-session defaults are out of scope;
- no "M3 pass" or "GAP closed" conclusion; this report is evidence only.

## Evidence files

| file | SHA-256 |
|---|---|
| `server.log` | `4106f37a3d63c5fc67235afef38ea35cc902af4128b8b545900ae18bc2708ec4` |
| `chrome-console.log` | `c30997f9c06cbd710dffaf039f2f154d9c60760badac91b7619e5a1cfd4f9203` |
| `chrome-netlog.txt` | `d5e79476ba57a1770bf9159084dca640eba658cfc8da3e213f1809fcd65b0009` |
| `result.json` | `9e810a7210c1e785ab661cb616406bea92871c83c30c55beee23392dfe479d9f` |
| `chrome-version.txt` | `4f3badc968b348c0f66c14be259ec7f4521104c7845e676130ba7b2d0ad0a32a` |
| `hashes.txt` | `6fc9c5c127ac77eff7294d374f78df9c722c6ceaf9b95a0ba681ecedb273d8b6` |

`hashes.txt` is the machine-readable matrix (item, sends, receives, lost, bytes,
SHA-256, detail); `result.json` is the page's `window.__rtx_result` posted verbatim.
`chrome-netlog.txt` is the filtered WebTransport excerpt of Chrome's own netlog
(the raw netlog stays in the mktemp directory). Test page/client:
`../index.html`; page server: `../page_server.py`; runner: `../run-chrome.sh`.

## Reproduce

```
CHROME_BIN=/root/.cache/puppeteer/chrome/linux-155.0.8059.39/chrome-linux64/chrome \
PHASE=relaxed ./interop/m3/chrome-rtx/run-chrome.sh
```

The runner generates the runtime certificate with `openssl` in a `mktemp`
directory, builds `rtx-wt-server`, starts the harness and `page_server.py`, runs
headless Chrome with the flags above, waits for the page's `POST /result` under
`RESULT_TIMEOUT=420` s, and writes the raw evidence files listed above. It was
executed twice during this unit with the same B0/B1/B2 pass result; the archived
files are from the final run. No key material enters the repository.
