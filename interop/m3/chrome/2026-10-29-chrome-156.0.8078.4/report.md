# R6-2c Chrome SETTINGS / CONNECT raw frame capture

**What this capture proves:** Chrome actually emitted the bytes stored in
`capture/settings-frame.bin` and `capture/connect-headers-frame.bin` while
establishing a WebTransport session.

**What this capture does NOT prove:** anything about `rtx-*`. It is not a
statement that `rtx-quic`, `rtx-webtransport` or any future `rtx-h3` interoperates
with Chrome. Browser interoperability (M3-B0-B2) is R6-3 work, not this task.
The server used here is an independent reference oracle built only from the
audited `quinn` and `web-transport-proto` baselines.

## Environment

| item | value |
|---|---|
| repository commit at capture time | `d9663e1de106f612f7b8cb57477d390c4551e46e` |
| Chrome (from the browser itself) | `Google Chrome for Testing 156.0.8078.4` |
| Chrome binary | `/root/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome` |
| version source | `/root/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome --version` (`chrome://version` is not reachable in headless mode; raw output is in `chrome-version.txt`) |
| OS | `Linux 6.18.5 x86_64 Ubuntu 24.04 LTS` |
| capture date | `2026-10-29` |
| page origin | `https://127.0.0.1:8443` (served by `page_server.py`) |
| WebTransport URL | `https://127.0.0.1:4433/session` |

## Chrome launch parameters

```
--headless --no-sandbox --disable-gpu --no-proxy-server --ignore-certificate-errors-spki-list=A+GTDFcUj2cFMMd1l9l3p/7t7M7ViuNId6n+vbsEfWs= --origin-to-force-quic-on=127.0.0.1:4433 --user-data-dir=/tmp/tmp.AkOXIrKXMf/chrome-profile --enable-logging=stderr --v=0
https://127.0.0.1:8443/index.html?port=4433
```

`--ignore-certificate-errors-spki-list` is required only because the certificate
is self-signed; it pins acceptance to this certificate's SPKI hash and is
**local test only, not suitable for production**. `--origin-to-force-quic-on`
pins the WebTransport origin to QUIC (no TCP listener exists behind it).
`--no-sandbox` is needed because this harness runs in a container.

## Certificate handling

- Self-signed RSA-2048, `CN=localhost`, SAN `DNS:localhost,IP:127.0.0.1`,
  generated at run time by `run.sh` with `openssl`.
- Lives only in a `mktemp` directory outside the repository and is deleted by
  the EXIT trap. No private key, `.pem` or `.key` file is committed.

## Reference server

| item | value |
|---|---|
| QUIC runtime | `quinn` @ `9d729c1b6b7ad30d45d40265037eeeb9d98a7420` (DEPENDENCY_AUDIT.md baseline) |
| H3 / WebTransport codec reference | `web-transport-proto` @ `d4e4e458da556ac3033c9b63f6db5110d3ab5adc` (DEPENDENCY_AUDIT.md baseline) |
| `rtx-*` dependencies | none (standalone crate, own `[workspace]` and lock file) |
| ALPN | `h3` |
| server SETTINGS | produced by `web_transport_proto::Settings::enable_webtransport(1)`: MAX_FIELD_SECTION_SIZE, ENABLE_CONNECT_PROTOCOL, ENABLE_DATAGRAM, deprecated datagram id, WEBTRANSPORT_MAX_SESSIONS plus its deprecated ids; QPACK dynamic table disabled |

## Captured frames

| file | bytes | SHA-256 |
|---|---|---|
| `capture/settings-frame.bin` | 43 | `bfa48ebd0fca2fde0d560f13fb6198123c88b66ed2d1245e56de6ace120453ac` |
| `capture/connect-headers-frame.bin` | 90 | `62b04ba11f2bcb7313764b783f57462f29f00b2b3622e027dcd6b560adab0753` |

Both files are the complete frame as received: frame type varint + length
varint + payload. The CONNECT file is in QPACK-encoded form and was never
decoded-then-re-encoded.

## Server log summary

```
ts_ms=1793237263442 event=quic_handshake_complete remote=127.0.0.1:51811 stable_id=94781766075808
ts_ms=1793237263442 event=h3_settings_frame_received frame_type=0x04 frame_bytes=43 payload_bytes=41 sha256=bfa48ebd0fca2fde0d560f13fb6198123c88b66ed2d1245e56de6ace120453ac
ts_ms=1793237263443 event=h3_headers_frame_received frame_type=0x01 frame_bytes=90 payload_bytes=87 qpack_encoded=true sha256=62b04ba11f2bcb7313764b783f57462f29f00b2b3622e027dcd6b560adab0753
ts_ms=1793237263443 event=connect_request_decoded url=https://127.0.0.1:4433/session protocols=- headers={"origin": "https://127.0.0.1:8443", "sec-webtransport-http3-draft02": "1"}
ts_ms=1793237263444 event=response_headers_sent status=200 frame_bytes=5 sha256=59680c85cbb294b8f9910e314fe77585dcd3d992e46171006eedaa02ff37077c
ts_ms=1793237267445 event=connection_close_wait_timeout_seconds=4
ts_ms=1793237267445 event=capture_complete
```

Full log: `capture/server.log`. Frame details: `capture/settings-decoded.txt`.

## SETTINGS identifiers vs draft-ietf-webtrans-http3-15 (record only)

QPACK_MAX_TABLE_CAPACITY id=0x1 value=65536 (0x10000)
MAX_FIELD_SECTION_SIZE id=0x6 value=16384 (0x4000)
QPACK_BLOCKED_STREAMS id=0x7 value=100 (0x64)
ENABLE_DATAGRAM id=0x33 value=1 (0x1)
ENABLE_DATAGRAM_DEPRECATED id=0xffd277 value=1 (0x1)
WEBTRANSPORT_ENABLE_DEPRECATED id=0x2b603742 value=1 (0x1)
GREASE SETTING [12f995de48] id=0x12f995de48 value=3636621627 (0xd8c2713b)

Legend (identifier -> draft / RFC reference):

| id | name | reference |
|---|---|---|
| 0x01 | SETTINGS_QPACK_MAX_TABLE_CAPACITY | RFC 9114 section 7.2.4.1 |
| 0x06 | SETTINGS_MAX_FIELD_SECTION_SIZE | RFC 9114 section 7.2.4.1 |
| 0x07 | SETTINGS_QPACK_BLOCKED_STREAMS | RFC 9114 section 7.2.4.1 |
| 0x08 | SETTINGS_ENABLE_CONNECT_PROTOCOL | RFC 9220 |
| 0x33 | SETTINGS_H3_DATAGRAM | RFC 9297 |
| 0xffd277 | SETTINGS_H3_DATAGRAM (deprecated id Chrome still sends) | RFC 9297 history |
| 0xc671706a | SETTINGS_WEBTRANSPORT_MAX_SESSIONS | draft-ietf-webtrans-http3-15 section 5 |
| 0x2b603742 | SETTINGS_WEBTRANSPORT_ENABLE (deprecated) | removed after draft-06 |
| 0x2b603743 | SETTINGS_WEBTRANSPORT_MAX_SESSIONS (deprecated) | removed after draft-06 |

Grease settings (identifier of the form `0x1f * N + 0x21`) are Chrome's
reserved values. They are recorded verbatim and are not "corrected", and the
raw bytes in `capture/settings-frame.bin` stay authoritative. Chrome randomises
the grease value per connection, so a rerun produces a different SETTINGS hash
with the same non-grease content.

## CONNECT HEADERS frame (QPACK) - appendix only

ts_ms=1793237263443 event=connect_request_decoded url=https://127.0.0.1:4433/session protocols=- headers={"origin": "https://127.0.0.1:8443", "sec-webtransport-http3-draft02": "1"}

The decode above uses the audited `web-transport-proto` reference codec and is
appendix-grade only. `capture/connect-headers-frame.bin` remains the source of
truth. A decode failure would not change the captured bytes.

Observed detail worth recording for R6-2b: this Chrome build signals the
WebTransport draft with the legacy `sec-webtransport-http3-draft02: 1` request
header, not a `sec-webtransport-http3-draft` value naming a draft number.

## Chrome console excerpt

[12291:12291:1029/092743.426917:INFO:CONSOLE:30] "[wt-capture] session url: https://127.0.0.1:4433/session", source: https://127.0.0.1:8443/index.html?port=4433 (30)
[12291:12291:1029/092743.426978:INFO:CONSOLE:30] "[wt-capture] WebTransport constructed", source: https://127.0.0.1:8443/index.html?port=4433 (30)
[12291:12291:1029/092743.446774:INFO:CONSOLE:30] "[wt-capture] ready: session established", source: https://127.0.0.1:8443/index.html?port=4433 (30)
[12291:12291:1029/092743.450294:INFO:CONSOLE:30] "[wt-capture] closed by client after ready", source: https://127.0.0.1:8443/index.html?port=4433 (30)
[12291:12291:1029/092743.451798:INFO:CONSOLE:30] "[wt-capture] closed event: ok", source: https://127.0.0.1:8443/index.html?port=4433 (30)

## Reproduce

`interop/m3/chrome/run.sh` performs all steps automatically. See `README.md`.
