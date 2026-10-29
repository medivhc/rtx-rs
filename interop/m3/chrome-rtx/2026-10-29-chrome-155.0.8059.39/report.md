# R6-4 Chrome WebTransport interop — `Google Chrome for Testing 155.0.8059.39` (relaxed)

**What this proves:** a real Chrome build completed (or failed) the M3-B0/B1/B2
matrix against the `rtx-wt-server` harness (`rtx-quic` + `rtx-h3` +
`rtx-webtransport`), with the numbers, order checks, byte counts and SHA-256
values below coming from the browser page and the harness log.

**What this does not prove:** B3 Firefox (see below), B4 `quinn` reference
interop, benchmarks, embedded use, or full HTTP/3. Loopback success is not
rewritten as a Chrome conclusion anywhere in this directory.

## First-page summary

**Conclusion:** B0/B1/B2 `FAIL`. B3 is `NOT DETERMINED`. Blocking GAPs for the
Chrome matrix: **1**; open B3 GAP: **1**. See the GAP table below.

## Status

| item | status | detail |
|---|---|---|
| B0 | fail | net::ERR_METHOD_NOT_SUPPORTED; server SETTINGS lack legacy ENABLE_WEBTRANSPORT |
| B1 | not_run | 0 tier(s) executed |
| B2 | not_run | not run |
| B3 | NOT DETERMINED | no Firefox binary found (checked command -v firefox, /usr/lib/firefox/firefox, ~/.cache/ms-playwright/firefox-*/firefox/firefox, /snap/bin/firefox) |
| B5 | GAPs listed | 1 blocking, 1 open B3 |

This is **phase 2 (relaxed)**. Phase 1 evidence is
[`../2026-10-29-chrome-155.0.8059.39-baseline/report.md`](../2026-10-29-chrome-155.0.8059.39-baseline/report.md): the untouched `edca8ea` harness rejected Chrome's non-zero
`0x01`/`0x07` with `H3_SETTINGS_ERROR (0x0101)`. The relaxation changed exactly
one place in `interop/m3/rtx-server/src/main.rs` (`handle_client_settings`):
the peer's `0x01`/`0x07`/`0x06` values are logged (`event=h3_client_qpack_capacity`)
and accepted. The rationale (RFC 9114 section 7.2.4.1: the values describe the
peer decoder's capacity, not this encoder; this encoder emits static references
and non-Huffman literals only; this decoder still rejects real dynamic-table
references) is in `interop/m3/rtx-server/README.md`.

Loopback regression: `run-loopback.sh` was rerun after the relaxation and
passed; see `loopback-regression/`. The merged `interop/m3/rtx-server/evidence/2026-10-29-loopback/`
directory was restored byte-for-byte (the new logs live only in the appendix).

## B0 failure analysis (after the authorised relaxation)

Chrome's own netlog records the WebTransport client state machine ending in
`CONNECTING -> FAILED` with `net::ERR_METHOD_NOT_SUPPORTED`, immediately after
the server's control stream carrying the five SETTINGS items arrives. The
server log shows the relaxed branch accepted Chrome's `0x01=65536` /
`0x07=100` and sent its fixed five-item SETTINGS; no extended CONNECT follows.

Chrome 155 requires the server to advertise the legacy `ENABLE_WEBTRANSPORT`
(`0x2b603742=1`) in addition to `ENABLE_CONNECT_PROTOCOL` and `H3_DATAGRAM`.
`rtx-h3`'s encoder deliberately never emits deprecated identifiers, so the
harness' five-item SETTINGS cannot include it. A throwaway diagnostic (see
`../blocker-analysis.md`; not part of this harness and not R6-4 evidence)
appended exactly that pair to the SETTINGS payload: B0 then established, B1
passed 3000/3000 pairwise echoes, and the B2 stream items passed except the
server-reset observation (Chrome did not surface the harness' reset stream).

Emitting `0x2b603742` changes the server SETTINGS payload, which R6-4 was
explicitly told to leave at five items ("服务端 SETTINGS 5 项不变"). This report
therefore records the blocker as `GAP-M3-B0-02` and stops there; adding the pair
is a follow-up decision for the coordinator, not something this task authorises.


## Environment

| item | value |
|---|---|
| repository commit | `edca8eae8dd3a909a6a21c1cb592e3512c1f26b6` |
| phase | `relaxed` |
| harness main.rs SHA-256 | `8906f920844a9de133e0a867466543a5f130a2fb559245e71d97c87650f30f6e` |
| harness diff vs HEAD | `interop/m3/rtx-server/README.md   \| 38 ++++++++++++++++++++++++++++++++++++++  interop/m3/rtx-server/src/main.rs \| 30 +++++++++++++++---------------  2 files changed, 53 insertions(+), 15 deletions(-)` |
| Chrome (from the browser itself) | `Google Chrome for Testing 155.0.8059.39` |
| Chrome binary | `/root/.cache/puppeteer/chrome/linux-155.0.8059.39/chrome-linux64/chrome` |
| version source | `$CHROME --version` (`chrome://version` is not reachable in headless mode; raw output is in `chrome-version.txt`) |
| OS | `Linux 6.18.5 x86_64 Ubuntu 24.04 LTS` |
| date | `2026-10-29` |
| harness address | `127.0.0.1:4433` |
| page origin | `https://127.0.0.1:8443` (served by `page_server.py`) |
| WebTransport URL | `https://127.0.0.1:4433/session` |
| server alive after matrix | `yes` |

## Chrome launch parameters

```
--headless --no-sandbox --disable-gpu --disable-dev-shm-usage --no-proxy-server --ignore-certificate-errors-spki-list=UOUw8IYuD2HoaJUu/wev+qbHOYTo5X6WiMebyRn0n1A= --origin-to-force-quic-on=127.0.0.1:4433 --user-data-dir=/tmp/tmp.nd7HxS2xp6/chrome-profile --enable-logging=stderr --log-net-log=/tmp/tmp.nd7HxS2xp6/netlog.json --v=0
https://127.0.0.1:8443/index.html?port=4433
```

## Certificate handling

- Self-signed RSA-2048, `CN=localhost`, SAN `DNS:localhost,IP:127.0.0.1`,
  generated at run time by `run-chrome.sh` with `openssl`.
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
| `0x7a7a5799e` | 1968668620 | unknown/GREASE | grease |

Frame: `ts_ms=1793275755827 event=h3_settings_frame_received connection=0 payload_bytes=41 items=7`

Presence of the N4 identifiers:

- `0x2b603742` (`ENABLE_WEBTRANSPORT`, deprecated): **present**
- `0xc671706a` (`WEBTRANSPORT_MAX_SESSIONS`): **absent**
- `0x2c7cf000` (`SETTINGS_WT_ENABLED`, draft-15): **absent**

N4 observation: T1 (a Chrome version negotiating `0x2c7cf000`) is **not triggered**;
Chrome's SETTINGS above show that identifier as absent. T3 (Chrome refusing a
session solely because the server omitted `0x2c7cf000`) is **not triggered**:
the failure recorded here is `net::ERR_METHOD_NOT_SUPPORTED` caused by the
missing legacy `0x2b603742` on the server (see the B0 analysis above), and the
throwaway diagnostic in `../blocker-analysis.md` shows that adding `0x2c7cf000`
alone does not establish a session either. The RV-PR24 ruling (do not send
`0x2c7cf000`) therefore remains in force; this task did not add it on its own
authority.

## Server SETTINGS actually emitted (5 items, no `0x2c7cf000`)

| id | value | name |
|---|---|---|
| `0x1` | 0 | QPACK_MAX_TABLE_CAPACITY |
| `0x7` | 0 | QPACK_BLOCKED_STREAMS |
| `0x8` | 1 | ENABLE_CONNECT_PROTOCOL |
| `0x33` | 1 | H3_DATAGRAM |
| `0xc671706a` | 100 | WEBTRANSPORT_MAX_SESSIONS |

## B1 DATAGRAM

Not exercised: no WebTransport session was established (see `GAP-M3-B0-02`).

## B2 streams

Not exercised: no WebTransport session was established (see `GAP-M3-B0-02`).

## Session close and second session

| item | observed |
|---|---|
| `transport.close()` (`WT_CLOSE_SESSION`) | `not_run`; server `session_closed` lines: 0 |
| `transport.closed` event | `{'error': 'Opening handshake failed.'}` |
| second session on the same harness process | `not_run` (not established) |
| `connect_request_decoded` / `response_headers_sent 200` totals | 0 / 0 |
| `connect_request_rejected` | 0 |

## B3 Firefox (conditional)

| item | value |
|---|---|
| status | **NOT DETERMINED** |
| evidence | no Firefox binary found (checked command -v firefox, /usr/lib/firefox/firefox, ~/.cache/ms-playwright/firefox-*/firefox/firefox, /snap/bin/firefox) |
| gap | `GAP-M3-B3-01` |

Firefox is not called "N/A" without a checked version: N/A needs evidence that a
specific Firefox build was inspected and does not support WebTransport over
HTTP/3. This run has no Firefox binary at all, so the honest status is
**NOT DETERMINED**, and `GAP-M3-B3-01` is handed to the coordinator (`xc` has a
Firefox 136 headless precedent).

## B5 GAP table

| GAP | item | detail |
|---|---|---|
| `GAP-M3-B0-02` | B0 | WebTransport.ready rejected: Opening handshake failed. (netlog: net::ERR_METHOD_NOT_SUPPORTED; server SETTINGS carry no 0x2b603742) |
| `GAP-M3-B3-01` | B3 | Firefox NOT DETERMINED: no Firefox binary found (checked command -v firefox, /usr/lib/firefox/firefox, ~/.cache/ms-playwright/firefox-*/firefox/firefox, /snap/bin/firefox); escalated to coordinator xc review |

Blocking GAP count on the first page: **1**. Open B3 GAP count: **1**.

## Not done (explicitly)

- B4 `quinn` reference interop (independent follow-up unit; the `quinn` client
  above only appears in the loopback regression, never as an interop result).
- benchmarks (P7), embedded port (P8), full HTTP/3, QPACK dynamic table,
  `0x2c7cf000` implementation, 0-RTT, connection migration, multi-session
  defaults.
- no change to existing crate logic, existing docs (`docs/m3-m4-gates.md`,
  `DEPENDENCY_AUDIT.md`, `ARCHITECTURE.md`), `interop/m3/chrome/` (R6-2c raw
  capture and reference server untouched), CI, the workspace manifest or the
  merged `interop/m3/rtx-server/evidence/2026-10-29-loopback/` directory.

## Evidence files

| file | SHA-256 |
|---|---|
| `server.log` | `8c072bb5d34580db66ea88504013d19d9952d7fe3de6a61aaad33efb27f58016` |
| `chrome-console.log` | `111a93a187007b722cdf5f5ae9c5e416903d0a79a7aa517f2d60e212ee7dfa57` |
| `chrome-netlog.txt` | `ef80850521bd274617f45bd8901b225a2fe4a01cd44d9084571c9283f2c9e127` |
| `result.json` | `3b1643b43d1ec7d04e1a509b966aa7ee6c4fc1c864fd63a688c47781eae46040` |
| `chrome-version.txt` | `4f3badc968b348c0f66c14be259ec7f4521104c7845e676130ba7b2d0ad0a32a` |
| `hashes.txt` | `8c11af02a12f7d999bfc0d0de4267d29c8884fc0fd8c807d6d004578e3fc668d` |

`hashes.txt` is the machine-readable matrix (item, sends, receives, lost, bytes,
SHA-256, detail); `result.json` is the page's `window.__rtx_result` posted verbatim.
Payload SHA-256 values in this report come from the same JSON, not from the
console summary. `chrome-netlog.txt` is the filtered WebTransport excerpt of
Chrome's own netlog (the raw netlog stays in the mktemp directory).

## Reproduce

```
cd interop/m3/chrome-rtx && PHASE=relaxed ./run-chrome.sh
```

The script generates the runtime certificate with `openssl` in a `mktemp`
directory, starts `rtx-wt-server` and `page_server.py`, runs headless Chrome with
the flags above, waits for the page's `POST /result` under `RESULT_TIMEOUT=420` s,
and writes only the text evidence listed above. No key material enters the
repository.
