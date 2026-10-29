# R6-4 Chrome WebTransport interop — `Google Chrome for Testing 155.0.8059.39` (baseline)

**What this proves:** a real Chrome build completed (or failed) the M3-B0/B1/B2
matrix against the `rtx-wt-server` harness (`rtx-quic` + `rtx-h3` +
`rtx-webtransport`), with the numbers, order checks, byte counts and SHA-256
values below coming from the browser page and the harness log.

**What this does not prove:** B3 Firefox (see below), B4 `quinn` reference
interop, benchmarks, embedded use, or full HTTP/3. Loopback success is not
rewritten as a Chrome conclusion anywhere in this directory.

## First-page summary

**Conclusion:** B0 FAIL with `GAP-M3-B0-01`: Chrome's SETTINGS carry
`0x01=65536` and `0x07=100`, the harness logs `h3_settings_rejected`
(`reason=dynamic_table_not_supported`) and closes the connection with
`error_code=0x101` before extended CONNECT. B1/B2 were not exercised because no
session exists. This log is the phase-1 product; the next step is the
one-place relaxation described in `interop/m3/rtx-server/README.md`.

## Status

| item | status | detail |
|---|---|---|
| B0 | fail | Opening handshake failed. |
| B1 | not_run | 0 tier(s) executed |
| B2 | not_run | not run |
| B3 | NOT DETERMINED | no Firefox binary found (checked command -v firefox, /usr/lib/firefox/firefox, ~/.cache/ms-playwright/firefox-*/firefox/firefox, /snap/bin/firefox) |
| B5 | GAPs listed | 1 blocking, 1 open B3 |

This is **phase 1 (baseline)**. The harness is the untouched `edca8ea` code
(`main.rs` SHA-256 above, no local diff). At edca8ea the harness rejects
non-zero client QPACK capacity with `H3_SETTINGS_ERROR (0x0101)`; a baseline
that ends there is the *expected qualified product* of phase 1, not a test
failure. Phase 2 (`PHASE=relaxed`) is only run if this baseline ends in that
H4 rejection, and its evidence lives in the sibling directory without the
`-baseline` suffix.

Key server log lines (verbatim):

```
ts_ms=1793274474570 event=h3_settings_rejected connection=0 reason=dynamic_table_not_supported error=DynamicTableNotSupported
ts_ms=1793274474570 event=connection_close_requested connection=0 error_code=0x101
```

## Environment

| item | value |
|---|---|
| repository commit | `edca8eae8dd3a909a6a21c1cb592e3512c1f26b6` |
| phase | `baseline` |
| harness main.rs SHA-256 | `0f88f7e6a4ee3473c6ebdff359b1f5c1b2aae48e7896cf5472c2da92770da438` |
| harness diff vs HEAD | `none (harness identical to HEAD)` |
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
--headless --no-sandbox --disable-gpu --disable-dev-shm-usage --no-proxy-server --ignore-certificate-errors-spki-list=QMtWoUBWRwHBFnysmxGkBog6VrRZRQH+3UYcJZIveis= --origin-to-force-quic-on=127.0.0.1:4433 --user-data-dir=/tmp/tmp.5GPM75WsQC/chrome-profile --enable-logging=stderr --v=0
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
| `0x1ce844ac99` | 3664097615 | unknown/GREASE | grease |

Frame: `ts_ms=1793274474570 event=h3_settings_frame_received connection=0 payload_bytes=41 items=7`

Presence of the N4 identifiers:

- `0x2b603742` (`ENABLE_WEBTRANSPORT`, deprecated): **present**
- `0xc671706a` (`WEBTRANSPORT_MAX_SESSIONS`): **absent**
- `0x2c7cf000` (`SETTINGS_WT_ENABLED`, draft-15): **absent**

N4 observation: T1 (a Chrome version negotiating `0x2c7cf000`) is **not triggered**; the
harness does not send `0x2c7cf000`. T3 (Chrome requiring that signal before
establishing a session) is **not triggered**: the session outcome in this phase is `fail`.
The RV-PR24 ruling (do not send `0x2c7cf000`) therefore remains in force; this
task did not add it on its own authority.

## Server SETTINGS actually emitted (5 items, no `0x2c7cf000`)

(no server SETTINGS logged)







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
| `GAP-M3-B0-01` | B0 | WebTransport.ready rejected: Opening handshake failed. |
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
| `server.log` | `b27074a671fb31db22fe19a93d6ccf84753d407770e13375700d1e65f1920166` |
| `chrome-console.log` | `38810a24db123b263b4de84db21e341db4539a6f06da03d5359a99846b83d713` |
| `result.json` | `825e962480b136d606d6b7d5c644f3e66df383120ae33c1082de1b37e7b22fa3` |
| `chrome-version.txt` | `4f3badc968b348c0f66c14be259ec7f4521104c7845e676130ba7b2d0ad0a32a` |
| `hashes.txt` | `8c11af02a12f7d999bfc0d0de4267d29c8884fc0fd8c807d6d004578e3fc668d` |

`hashes.txt` is the machine-readable matrix (item, sends, receives, lost, bytes,
SHA-256, detail); `result.json` is the page's `window.__rtx_result` posted verbatim.
Payload SHA-256 values in this report come from the same JSON, not from the
console summary.

## Reproduce

```
cd interop/m3/chrome-rtx && PHASE=baseline ./run-chrome.sh
```

The script generates the runtime certificate with `openssl` in a `mktemp`
directory, starts `rtx-wt-server` and `page_server.py`, runs headless Chrome with
the flags above, waits for the page's `POST /result` under `RESULT_TIMEOUT=420` s,
and writes only the text evidence listed above. No key material enters the
repository.
