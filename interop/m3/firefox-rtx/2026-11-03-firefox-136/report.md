# M3-B3 Firefox WebTransport interop — `Mozilla Firefox 136.0` (2026-11-03-firefox-136)

**What this proves:** a real Firefox build (Mozilla Firefox 136.0, moz:buildID 20250227124745) was probed for
WebTransport-over-HTTP/3 capability and, where supported, ran the M3-B0/B1/B2
matrix against the `rtx-wt-server` harness (`rtx-quic` + `rtx-h3` +
`rtx-webtransport`). The numbers, order checks, byte counts and SHA-256 values
below come from the browser page (`result.json`) and the harness log
(`server.log`); the capability and pref facts come from the Marionette probe
(`firefox-prefs.json`).

**What this does not prove:** that any gate checkbox is ticked, that
`GAP-M3-B3-01` or any other GAP changes status (only a milestone acceptance
PR / the coordinator changes GAP status), Chrome interop (separate evidence in
`interop/m3/chrome-rtx/`), B4 `quinn` reference interop, benchmarks, embedded
use, or full HTTP/3.

## First-page summary

**B0 `pass`:** ready 15 ms; extended CONNECT 200; server observed the session

**B1 `pass`:** 3 tier(s), sends/echoes/loss from the table below.

**B2 `pass`:** 6 stream/reset item(s).

**B3 verdict: PASS** — Firefox Mozilla Firefox 136.0 exposes WebTransport over HTTP/3 — measured: `typeof WebTransport`=`function` in the secure page content context (`isSecureContext=true`) and in chrome context — and completed the full B0/B1/B2 matrix against the harness: B0 ready in 15 ms, B1 3 tier(s), B2 6 stream/reset item(s), 0 failures, server alive after the matrix: yes.

**Failures recorded by the page: 0.** GAP status changes belong to the
milestone acceptance PR / coordinator, not to this report.

## Status

| item | status | detail |
|---|---|---|
| B0 | pass | ready 15 ms; extended CONNECT 200; server observed the session |
| B1 | pass | 3 tier(s) executed |
| B2 | pass | 6 stream/reset items |
| B3 | PASS | Firefox Mozilla Firefox 136.0 exposes WebTransport over HTTP/3 — measured: `typeof WebTransport`=`function` in the secure page content context (`isSecureContext=true`) and in chrome context — and completed the full B0/B1/B2 matrix against the harness: B0 ready in 15 ms, B1 3 tier(s), B2 6 stream/reset item(s), 0 failures, server alive after the matrix: yes. |
| B5 | no GAP | 0 failure rows |

## Environment

| item | value |
|---|---|
| repository commit (git rev-parse HEAD at generation) | `64abb8ca47d4bc89f4925e19bb149bbcf7fb49e2` |
| harness tree id (git rev-parse HEAD:interop/m3/rtx-server) | `4b2b65f8e0f6104a5c1504aef100c4fc6ebd5e58` |
| harness main.rs SHA-256 | `18da6b8279ce7710a10a8e18e09038517c1cc439fb67434d45b33c5845ee9021` |
| harness diff vs HEAD | `none (harness identical to HEAD)` |
| Firefox (from the browser itself) | `Mozilla Firefox 136.0` |
| Firefox binary | `/usr/bin/firefox` |
| moz:buildID (Marionette capabilities) | `20250227124745` |
| headless (Marionette capabilities) | `True` |
| user agent (page) | `Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0` |
| version source | `$FIREFOX --version` + `application.ini` + Marionette capabilities; raw output is in `firefox-version.txt` |
| OS | `Linux 5.15.0-139-generic x86_64 Ubuntu 20.04.6 LTS` |
| date | `2026-11-03` |
| harness address | `127.0.0.1:33539` |
| page origin | `https://127.0.0.1:32879` (served by `../page_server.py` copy) |
| WebTransport URL | `https://127.0.0.1:33539/session` |
| `serverCertificateHashes` pin (base64url SHA-256 of the served DER) | `7emcnlNoKChni4LnX54N3mBRqlFNXvHBDBZcvezpp6M` |
| runner phase | `relaxed` (harness at HEAD lineage: client QPACK capacity relaxation + PR #29 Chrome-compat legacy pair; unmodified by this runner) |
| test page SHA-256 (`../index.html`, Firefox copy) | `4b1f08b5aff4ddecc5ae2eab2bc04d3710adb022211eabc10f4cb8b50ed58de7` |
| page server SHA-256 (`../page_server.py`, byte-identical copy) | `af6fecfc1b7f7475f5baea15a1946e1f423f5e9bf58c8532821bdfb82664fc5b` |
| matrix duration | 1646 ms |
| server alive after matrix | `yes` |
| driver result timeout | `120` s (the previous uncommitted attempt used 420 s and waited blindly) |
| driver | Marionette protocol 3 over TCP `127.0.0.1:45889` (`../marionette_drive.py`); no CDP, no geckodriver, no Playwright |

## Firefox launch parameters

```
/usr/bin/firefox --headless --marionette --no-remote -profile /tmp/tmp.sbmz6nv4Kq/firefox-profile
(marionette.port=45889; Marionette drives WebDriver:Navigate to:)
https://127.0.0.1:32879/index.html?port=33539&phase=relaxed&browser=firefox&certhash=7emcnlNoKChni4LnX54N3mBRqlFNXvHBDBZcvezpp6M
```

## Certificate handling

- Self-signed **ECDSA P-256** leaf, `CN=localhost`, SAN
  `DNS:localhost,IP:127.0.0.1`, validity 1 day, generated at run time by
  `../run-firefox.sh` with `openssl` via CSR + `x509 -req -signkey -extfile`,
  so the cert carries exactly the intended extensions and nothing else:
  `basicConstraints=critical,CA:FALSE`, `keyUsage=critical,digitalSignature`,
  `extendedKeyUsage=serverAuth`. The same file serves both the HTTPS page
  origin and the harness QUIC endpoint (the harness takes a single DER leaf;
  it has no chain support).
- Lives only in a `mktemp` directory outside the repository and is deleted by
  the EXIT trap. No private key, `.pem` or `.key` file is committed.
- **Page origin (mozilla::pkix):** Firefox has no
  `--ignore-certificate-errors-spki-list` equivalent, so the leaf is imported
  into the temporary profile's NSS database as a trust anchor:
  `certutil -N -d sql:$PROFILE` then
  `certutil -A -d sql:$PROFILE -n rtx-m3-wt-test -t "CT,," -i cert.pem`
  (the mechanism web-platform-tests uses for Firefox). The anchor must be
  `CA:FALSE`: mozilla::pkix rejects a `CA:TRUE` cert used as the server
  end-entity (`MOZILLA_PKIX_ERROR_CA_CERT_USED_AS_END_ENTITY`) even when that
  cert is itself the imported anchor. The profile is a `mktemp` directory too;
  nothing profile-related enters the repository.
- **WebTransport endpoint (serverCertificateHashes):** Firefox enforces the
  W3C WebTransport rule that a *dedicated* session must not authenticate
  through a user-added trust anchor unless `serverCertificateHashes` matches
  (measured without the pin: Firefox closed both H3 sessions immediately
  after a successful TLS authentication —
  `Http3Session::Authenticated [hasThirdPartyRoots=1, servCertHashesSucceeded=0]`
  → `NS_ERROR_NET_RESET`; the harness only saw the client's CONNECTION_CLOSE,
  logged as `quic_handshake_failed reason=Protocol`). The page therefore
  constructs `new WebTransport(url, {serverCertificateHashes:
  [{algorithm: "sha-256", value: <32 B>}]})`, the value being the base64url
  SHA-256 of exactly the DER the harness serves, passed by the runner as the
  `certhash` URL parameter. Per spec a pinned certificate must be self-signed,
  valid < 2 weeks, and use ECDSA secp256r1 (P-256) — RSA keys are rejected
  (measured with an RSA-2048 leaf:
  `AuthCertificateWithServerCertificateHashes failed`) — which is why the
  runtime leaf has the ECDSA / 1-day shape above.
- Certificate hash used by this run (SHA-256, base64url, unpadded): `7emcnlNoKChni4LnX54N3mBRqlFNXvHBDBZcvezpp6M`.

## Method

Order of a run (`../run-firefox.sh`): runtime self-signed ECDSA P-256
certificate (+ its base64url SHA-256 pin) -> `certutil` trust import into a
temporary profile (page origin) -> build the unmodified HEAD harness -> start
harness + HTTPS page server -> launch headless Firefox with `--marionette` ->
the Marionette driver (`../marionette_drive.py`, raw protocol 3 over TCP) opens
a session (identity-checked against `moz:profile`), probes prefs and the API in
chrome context via `Services.prefs` (`getChildList` + typed getters), navigates
to the HTTPS test page with the `certhash` URL parameter (the page turns it
into the WebTransport constructor's `serverCertificateHashes`), probes
`typeof WebTransport`/`isSecureContext` in the secure page's content context,
then waits for the page's `POST /result` with a bounded timeout while
sampling the page state every 5 s.

Corrections over the previous (uncommitted, superseded) attempt of this
evidence — that attempt's conclusions were unsupported and are replaced by
this re-run:

- **`user.js` defect (fixed):** the temporary profile's `user.js` was written
  with `pref(...)` lines, which Firefox rejects (`prefs parse error: expected
  'user_pref' at start of pref definition` — 6 lines in the old
  `firefox.log`); every pref was ignored, the Marionette drive ended rc=1 and
  produced no probe JSON, so the page never ran. The file is now written in
  the required `user_pref("name", value);` form; this re-run starts from it
  and the probe JSON (`firefox-prefs.json`) contains real measured values.
  That failure was a defect of the run tooling — it is recorded here as a
  driver failure that has been fixed, and **not** as a gate GAP.
- **fabricated GAP removed:** the previous runner injected an invented
  `GAP-M3-B0-03` (never registered in `docs/m3-m4-gates.md` §5) into the page
  URL and the fallback stub. It is gone from the runner, the page and this
  report; a Firefox-lineage B0 failure now carries `gap=null` and the report
  states that registration belongs to the coordinator.
- **no blind waiting:** the driver result timeout was shortened from 420 s to
  120 s, the page watchdog from 240 s to 90 s, and the wait loop now samples
  the page through Marionette every 5 s (href, `#status` tail,
  `window.__rtx_result.finished`), recovers a finished-but-unposted result via
  `execute_script`, aborts immediately on a neterror page or a dead browser
  process (`--firefox-pid`), and writes the probe JSON and the page-status
  file on every path, success or failure.
- **explicit unsupported path in the page:** a build without the
  `WebTransport` API now finishes cleanly with `b0.status="unsupported"` and
  `verdict="unsupported"` (the gate's conditional N/A case) instead of
  throwing in the constructor and masquerading as a B0 failure.
- **certificate shape and WT pinning (fixed):** the previous attempt never got
  past `WebDriver:Navigate` (`about:certerror?e=nssBadCert`,
  `MOZILLA_PKIX_ERROR_CA_CERT_USED_AS_END_ENTITY`): openssl 1.1.1's
  `req -x509` adds `basicConstraints=critical,CA:TRUE`, which mozilla::pkix
  rejects for a server end-entity even when that cert is itself the imported
  anchor, and `-addext` cannot replace the default (duplicated extensions ->
  `SEC_ERROR_EXTENSION_VALUE_INVALID`). The anchor is now built via CSR +
  `x509 -req -signkey -extfile` with `CA:FALSE`. With the fixed anchor, page
  navigation worked but both WebTransport connections were torn down by
  Firefox right after TLS authentication (dedicated WT session + user-added
  root without `serverCertificateHashes`; see Certificate handling), and an
  RSA-2048 leaf was rejected by the pinning path itself
  (`AuthCertificateWithServerCertificateHashes failed` — the spec requires
  ECDSA P-256 for pinned certs). The runtime leaf is therefore ECDSA P-256
  and the page pins the WT endpoint with `serverCertificateHashes`.

## Firefox capability probe (WebTransport over HTTP/3)

| probe | value | note |
|---|---|---|
| `dom.webtransport.enabled` | `MISSING` | measured via `Services.prefs.getPrefType`/typed getter in chrome context; `MISSING` = the pref does not exist in this build |
| `network.http.http3.enable` | `True` | necko HTTP/3 master switch (WebTransport itself uses the neqo stack) |
| `network.webtransport.enabled` | `True` | the WebTransport switch that actually exists in this build |
| `network.webtransport.datagrams.enabled` | `True` | datagram support switch |
| `dom.webtransport.*` child prefs | `[]` | enumerated via `Services.prefs.getChildList` in chrome context |
| `network.webtransport.*` child prefs (with measured values) | ``network.webtransport.datagram_size`=1200; `network.webtransport.datagrams.enabled`=true; `network.webtransport.enabled`=true; `network.webtransport.redirect.enabled`=false` | enumerated via `Services.prefs.getChildList` in chrome context |
| `typeof WebTransport` (chrome context) | `function` | Marionette `WebDriver:ExecuteScript` with `Services` access |
| `typeof WebTransport` (content, secure page) | `function` | probed on `https://127.0.0.1:32879/index.html` after navigation |
| `isSecureContext` (content) | `True` | WebTransport is secure-context-only; the probe page is the HTTPS test page |
| `typeof WebTransportDatagramDuplexStream` (content) | `function` | datagram API surface |
| `typeof WebTransportError` (content) | `function` | error API surface |

**Capability conclusion:** `supported` — `typeof WebTransport === "function"` in the content context of the secure HTTPS page (`isSecureContext=true`) and in chrome context. Measured pref state: `dom.webtransport.enabled`="MISSING" (`dom.webtransport.*` children=[]), `network.http.http3.enable`=true, `network.webtransport.datagram_size`=1200; `network.webtransport.datagrams.enabled`=true; `network.webtransport.enabled`=true; `network.webtransport.redirect.enabled`=false.

`WebTransport.prototype` members in this build: `getStats`, `close`, `createBidirectionalStream`, `createUnidirectionalStream`, `ready`, `reliability`, `congestionControl`, `closed`, `datagrams`, `incomingBidirectionalStreams`, `incomingUnidirectionalStreams`, `constructor`.
Full probe JSON (capabilities, pref enumeration, content surface): `firefox-prefs.json`.

## Firefox SETTINGS observed (verbatim values)

| id | value | name | class |
|---|---|---|---|
| `0x1` | 65536 | QPACK_MAX_TABLE_CAPACITY | known |
| `0x7` | 20 | QPACK_BLOCKED_STREAMS | known |
| `0x2b603742` | 1 | ENABLE_WEBTRANSPORT (deprecated) | deprecated |
| `0xffd277` | 1 | H3_DATAGRAM (deprecated) | deprecated |
| `0x33` | 1 | H3_DATAGRAM | known |

Frame: `ts_ms=1793719858432 event=h3_settings_frame_received connection=0 payload_bytes=19 items=5`

## Server SETTINGS actually emitted

| id | value | name |
|---|---|---|
| `0x1` | 0 | QPACK_MAX_TABLE_CAPACITY |
| `0x7` | 0 | QPACK_BLOCKED_STREAMS |
| `0x8` | 1 | ENABLE_CONNECT_PROTOCOL |
| `0x33` | 1 | H3_DATAGRAM |
| `0xc671706a` | 100 | WEBTRANSPORT_MAX_SESSIONS |
| `0x2b603742` | 1 | ENABLE_WEBTRANSPORT (deprecated) |

Wire payload: `ts_ms=1793719858432 event=server_settings_payload connection=0 payload_bytes=23 hex=0100070008013301c0000000c671706a4064ab60374201`

## B0 — session establishment

| item | observed |
|---|---|
| `WebTransport.ready` | `pass`, 15 ms |
| extended CONNECT response | `status=200` x2 (server `response_headers_sent`) |
| server session observation | `connect_request_decoded` x2 |
| CONNECT rejections | 0 |
| QUIC handshakes complete / failed | 4 / 0 |

First decoded CONNECT (verbatim): `ts_ms=1793719858433 event=connect_request_decoded connection=1 session=0 stream=0 scheme=https authority=127.0.0.1:33539 path=/session protocol=webtransport`

## B1 — DATAGRAM (Firefox ↔ harness)

| item | value |
|---|---|
| `peer_max_datagram_frame_size` (Firefox advertisement) | `1200` |
| harness `max_datagram_frame_size_advertised` | `1100` |
| `datagrams.maxDatagramSize` (browser API) | `1099` |
| negotiated tier derivation | `min(peer_max_datagram_frame_size=1200, max_datagram_frame_size_advertised=1100) - 32 (QUIC datagram accounting) - 1 (quarter stream ID) = 1067` |

Tier payloads are the deterministic `0..255` cycle (first N bytes); SHA-256 is
computed by the page with `crypto.subtle`. Each send was paired with its own
echo (`send i`, verify `echo i`, then `send i+1`), so the sequence check is
strict alternation. QUIC DATAGRAM is unreliable and unordered by design: the
loss numbers below are a measured result, not a protocol guarantee.

| tier | payload bytes | Firefox→server sends | server received | lost | echo sent (server) | echo received (Firefox) | echo lost | order | SHA-256 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 1 | 1000 | 1000 | 0 | 1000 | 999 | 1 | 0 mismatches / 1 timeouts | `6e340b9cffb37a98`… |
| 1000 | 1000 | 1000 | 1000 | 0 | 1000 | 1000 | 0 | 0 mismatches / 0 timeouts | `a8af099bf2e87860`… |
| negotiated | 1067 | 1000 | 1000 | 0 | 1000 | 1000 | 0 | 0 mismatches / 0 timeouts | `6ddba3c6303155a1`… |

Server log counters: `datagram_received` 3000, `datagram_sent` 3000,
`datagram_echo_failed` 0, dropped (`wrong_session`/`malformed`/`decode_failed`/
`buffer_too_small`) {'wrong_session': 0, 'malformed': 0, 'decode_failed': 0, 'buffer_too_small': 0}. The harness stayed alive for the whole matrix: `yes`.

## B2 — streams

| item | status | detail |
|---|---|---|
| server-initiated uni (1 MiB) | pass | bytes=1048576; sha256=fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83 |
| client uni 1 MiB + half-close echo | pass | sent bytes=1048576 sha256=fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83; echo bytes=1048576 sha256=fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83 |
| client bi 1 MiB + half-close echo | pass | bytes=1048576; sha256=fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83 |
| 10 concurrent bi 1 MiB | pass | streams=10 completed=10; bytes/stream=1048576 sha256=fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83 |
| client reset (writable.abort) | reset_sent | bytes_before_reset=65536; server log role=client count=1 |
| server reset observed (4096 B then code 7) | pass | observed=True bytes_before_reset=4096 reset_code=0 |

Server log counters: `stream_finished role=client` 12, `stream_reset role=client`
1, `stream_reset role=server code=7` 1, `stream_opened kind=uni role=server
bytes=1048576` 2.

## Session close and second session

| item | observed |
|---|---|
| `transport.close()` (`WT_CLOSE_SESSION`) | `closed_by_client`; server `session_closed` lines: 2 |
| `transport.closed` event | `{"close_code": 0, "reason": ""}` |
| second session on the same harness process | `pass` (ready) |
| `connect_request_decoded` / `response_headers_sent 200` totals | 2 / 2 |
| `connect_request_rejected` | 0 |

## B3 verdict (gate M3-B3)

| item | value |
|---|---|
| verdict | **PASS** |
| basis | Firefox Mozilla Firefox 136.0 exposes WebTransport over HTTP/3 — measured: `typeof WebTransport`=`function` in the secure page content context (`isSecureContext=true`) and in chrome context — and completed the full B0/B1/B2 matrix against the harness: B0 ready in 15 ms, B1 3 tier(s), B2 6 stream/reset item(s), 0 failures, server alive after the matrix: yes. |
| Firefox | `Mozilla Firefox 136.0` (moz:buildID `20250227124745`) |
| platform | `Linux 5.15.0-139-generic x86_64 Ubuntu 20.04.6 LTS` |
| pref/switch state (measured) | `dom.webtransport.enabled`="MISSING"; `network.http.http3.enable`=true; `dom.webtransport.*` children=[]; `network.webtransport.*`: `network.webtransport.datagram_size`=1200; `network.webtransport.datagrams.enabled`=true; `network.webtransport.enabled`=true; `network.webtransport.redirect.enabled`=false |
| methods checked | Marionette chrome-context `Services.prefs` enumeration (`getChildList` + typed getters); content-context `typeof WebTransport`/`isSecureContext` on the secure HTTPS page; the B0/B1/B2 matrix itself where supported |
| gap | none |

## B5 GAP table

No failure was recorded by the page in this run; no GAP row.

## Not done (explicitly)

- no change to `crates/rtx-h3` or any workspace crate; the harness
  (`interop/m3/rtx-server`) is used exactly as at HEAD (`harness diff vs HEAD`
  above);
- no change to `interop/m3/chrome-rtx/` or any Chrome evidence directory;
  `../page_server.py` here is a byte-identical copy (SHA-256 recorded above),
  `../index.html` is a copy with only the adaptations listed in the Method
  section and the page comments;
- no `docs/m3-m4-gates.md` status or GAP-status change; no checkbox ticked —
  that belongs to the milestone acceptance PR;
- B4 `quinn` reference interop, benchmarks, embedded port, full HTTP/3, 0-RTT,
  connection migration and multi-session defaults are out of scope;
- this report is evidence only; it does not declare "M3 pass".

## Evidence files

| file | SHA-256 |
|---|---|
| `server.log` | `8cf5f268251adb64205213d8581c3756527882a9355343561f98a7296fe13d04` |
| `result.json` | `f3d30a02af405e0e8dca61e4f05738141945f4ca5580e908095eef49005928c7` |
| `firefox-version.txt` | `114aa55256230caed01604149c15693cdcd78f0259fd3ce092d7f038b8a5de9e` |
| `firefox-prefs.json` | `25229a418176aa2cc2771957f1030b1e1d9b2ae4aabf6a6ff63a04fe3ab3f00d` |
| `firefox-page-status.txt` | `e2df1836908f721df1d0fd75f8c966ba844575cb04efce99a3c0404786730973` |
| `firefox.log` | `15f17a411bdad92469c9bb855568c632b8d7cef51dd339db8eeb9fd1e7e61aa4` |
| `hashes.txt` | `3628782b3cb7b92cd419d06520196e7f1e5565509101410b038b8bb124b35b62` |

`hashes.txt` is the machine-readable matrix (item, sends, receives, lost, bytes,
SHA-256, detail); `result.json` is the page's `window.__rtx_result` posted
verbatim; `firefox-prefs.json` is the Marionette driver's probe (capabilities,
chrome-context pref enumeration, content-context API surface);
`firefox-page-status.txt` is the page's `#status` text (the console-equivalent
trail; Firefox/Gecko has no CDP-style console export through Marionette);
`firefox.log` is the browser process stdout/stderr. Test page: `../index.html`;
page server: `../page_server.py`; runner: `../run-firefox.sh`; driver:
`../marionette_drive.py`.

## Reproduce

```
./interop/m3/firefox-rtx/run-firefox.sh
```

The runner generates the runtime certificate with `openssl` in a `mktemp`
directory, imports it into a temporary Firefox profile with `certutil`, builds
`rtx-wt-server`, starts the harness and `page_server.py`, launches headless
Firefox with `--marionette --no-remote -profile <tmp>`, drives it over the raw
Marionette protocol (navigate + probes, `RESULT_TIMEOUT=120` s bound), and writes
only the text evidence listed above. No key material enters the repository.
Requires: `firefox` (system package), `certutil` (libnss3-tools), `python3`,
`openssl`, `cargo`.
