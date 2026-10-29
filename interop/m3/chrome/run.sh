#!/usr/bin/env bash
# One-shot harness for the R6-2c capture:
#   runtime self-signed cert -> reference H3/WebTransport server -> HTTPS page
#   server -> headless Chrome -> client page -> raw SETTINGS + CONNECT HEADERS
#   frames on disk -> report.
#
# Run from anywhere:  ./interop/m3/chrome/run.sh
# Optional env:       CHROME_BIN=/path/to/chrome  QUIC_PORT=4433  PAGE_PORT=8443
#
# Private key material only ever exists in a mktemp directory created here and
# removed by the EXIT trap; nothing key-like is written into the repository.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
QUIC_PORT="${QUIC_PORT:-4433}"
PAGE_PORT="${PAGE_PORT:-8443}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

# ---------------------------------------------------------------- 0. browser
CHROME=""
if [ -n "${CHROME_BIN:-}" ]; then
  CHROME="$CHROME_BIN"
else
  for cand in google-chrome google-chrome-stable chromium chromium-browser chrome; do
    if command -v "$cand" >/dev/null 2>&1; then
      CHROME="$(command -v "$cand")"
      break
    fi
  done
  if [ -z "$CHROME" ]; then
    for cand in "$HOME"/.cache/ms-playwright/chromium-*/chrome-linux64/chrome \
                "$HOME"/.cache/ms-playwright/chromium-*/chrome-linux/chrome \
                "$HOME"/.cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell; do
      if [ -x "$cand" ]; then
        CHROME="$cand"
        break
      fi
    done
  fi
fi
if [ -z "$CHROME" ] || [ ! -x "$CHROME" ]; then
  echo "无可用浏览器，抓包未执行 (no runnable Chrome/Chromium found; set CHROME_BIN)" >&2
  exit 2
fi
command -v python3 >/dev/null 2>&1 \
  || fail "python3 is required for the local HTTPS page server (no report produced)"
command -v openssl >/dev/null 2>&1 \
  || fail "openssl is required to generate the runtime self-signed certificate"

CHROME_VERSION_RAW="$("$CHROME" --version 2>&1 | head -n1 | sed -e 's/[[:space:]]*$//')"
VERSION="$(printf '%s\n' "$CHROME_VERSION_RAW" | grep -oE '[0-9]+(\.[0-9]+)+' | head -n1 || true)"
[ -n "$VERSION" ] || fail "cannot parse Chrome version from: $CHROME_VERSION_RAW"

DATE="$(date +%F)"
OUT="$HERE/$DATE-chrome-$VERSION"
CAPTURE="$OUT/capture"
mkdir -p "$CAPTURE"
rm -f "$CAPTURE"/settings-frame.bin "$CAPTURE"/connect-headers-frame.bin \
      "$CAPTURE"/server.log "$CAPTURE"/settings-decoded.txt \
      "$CAPTURE"/chrome-console.log "$CAPTURE"/hashes.txt \
      "$OUT"/report.md "$OUT"/chrome-version.txt

WORK="$(mktemp -d)"
SERVER_PID=""
CHROME_PID=""
PAGE_PID=""
cleanup() {
  for pid in "$CHROME_PID" "$PAGE_PID" "$SERVER_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  for pid in "$CHROME_PID" "$PAGE_PID" "$SERVER_PID"; do
    [ -n "$pid" ] && wait "$pid" 2>/dev/null || true
  done
  if [ "${KEEP_WORK:-0}" = "1" ]; then
    echo "KEEP_WORK=1: logs and certificate kept in $WORK" >&2
    return
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# ------------------------------------- 1. runtime self-signed test certificate
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" >/dev/null 2>&1 \
  || fail "openssl cert generation failed"
openssl x509 -in "$WORK/cert.pem" -outform DER -out "$WORK/cert.der" >/dev/null 2>&1 \
  || fail "cert pem->der conversion failed"
openssl pkcs8 -topk8 -nocrypt -in "$WORK/key.pem" -outform DER -out "$WORK/key.der" >/dev/null 2>&1 \
  || fail "key pkcs8 conversion failed"
# SHA-256 of the DER SubjectPublicKeyInfo, base64: the exact value Chrome's
# --ignore-certificate-errors-spki-list expects (this flag *does* cover QUIC;
# --ignore-certificate-errors alone does not).
SPKI="$(openssl x509 -in "$WORK/cert.pem" -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | base64)" \
  || fail "SPKI hash computation failed"

# ------------------------------------------------ 2. build the reference server
SERVER_MANIFEST="$HERE/server/Cargo.toml"
SERVER_BIN="$HERE/server/target/release/chrome-h3-capture"
echo "building reference server (standalone crate, not a workspace member)"
cargo build --release --manifest-path "$SERVER_MANIFEST" >"$WORK/build.log" 2>&1 \
  || { cat "$WORK/build.log" >&2; fail "reference server build failed"; }

# ------------------------------------------------- 3. start the page server
python3 "$HERE/page_server.py" "$PAGE_PORT" "$WORK/cert.pem" "$WORK/key.pem" \
  >"$WORK/page.log" 2>&1 &
PAGE_PID=$!
page_ready=0
for _ in $(seq 1 100); do
  if grep -q 'serving on' "$WORK/page.log" 2>/dev/null; then
    page_ready=1
    break
  fi
  kill -0 "$PAGE_PID" 2>/dev/null || break
  sleep 0.1
done
[ "$page_ready" -eq 1 ] || { cat "$WORK/page.log" >&2; fail "HTTPS page server did not start"; }

# ------------------------------------------------------- 4. start the server
"$SERVER_BIN" \
  --cert "$WORK/cert.der" \
  --key "$WORK/key.der" \
  --listen "127.0.0.1:$QUIC_PORT" \
  --out "$CAPTURE" >"$WORK/server.stderr" 2>&1 &
SERVER_PID=$!

listen_ready=0
for _ in $(seq 1 100); do
  if grep -q 'event=endpoint_listening' "$CAPTURE/server.log" 2>/dev/null; then
    listen_ready=1
    break
  fi
  kill -0 "$SERVER_PID" 2>/dev/null || break
  sleep 0.1
done
[ "$listen_ready" -eq 1 ] || { cat "$WORK/server.stderr" >&2; fail "reference server did not start listening"; }

# -------------------------------------------------- 5. headless Chrome client
# --ignore-certificate-errors-spki-list accepts the runtime self-signed cert for
#   both the HTTPS page and the QUIC connection (test-only; not for production)
# --origin-to-force-quic-on makes Chrome use QUIC for the WebTransport origin
#   (no TCP listener exists behind it)
# --no-proxy-server keeps the run off any ambient HTTP proxy
CHROME_FLAGS=(
  --headless
  --no-sandbox
  --disable-gpu
  --no-proxy-server
  --ignore-certificate-errors-spki-list="$SPKI"
  --origin-to-force-quic-on="127.0.0.1:$QUIC_PORT"
  --user-data-dir="$WORK/chrome-profile"
  --enable-logging=stderr
  --v=0
)
CHROME_URL="https://127.0.0.1:$PAGE_PORT/index.html?port=$QUIC_PORT"
"$CHROME" "${CHROME_FLAGS[@]}" "$CHROME_URL" >"$WORK/chrome.log" 2>&1 &
CHROME_PID=$!

# ------------------------- 6. wait for the server to finish (bounded, event-based)
SERVER_RC=0
for _ in $(seq 1 900); do
  kill -0 "$SERVER_PID" 2>/dev/null || break
  sleep 0.1
done
wait "$SERVER_PID" || SERVER_RC=$?
SERVER_PID=""

kill "$CHROME_PID" 2>/dev/null || true
wait "$CHROME_PID" 2>/dev/null || true
CHROME_PID=""
kill "$PAGE_PID" 2>/dev/null || true
wait "$PAGE_PID" 2>/dev/null || true
PAGE_PID=""

# ---------------------------------------------------------------- 7. validate
[ "$SERVER_RC" -eq 0 ] || { tail -n 40 "$CAPTURE/server.log" >&2; echo "--- Chrome console tail ---" >&2; grep -E '\[wt-capture\]|ERR_|ssl_client' "$WORK/chrome.log" 2>/dev/null | tail -n 20 >&2; fail "reference server exited with $SERVER_RC"; }
for artifact in settings-frame.bin connect-headers-frame.bin; do
  [ -s "$CAPTURE/$artifact" ] || fail "missing or empty capture file: $artifact (no empty report is produced)"
done

# --------------------------------------------------------- 8. supporting files
printf '%s\n' "$CHROME_VERSION_RAW" >"$OUT/chrome-version.txt"
grep -E '\[wt-capture\]' "$WORK/chrome.log" >"$CAPTURE/chrome-console.log" 2>/dev/null || true
grep -q '\[wt-capture\] ready' "$CAPTURE/chrome-console.log" \
  || fail "Chrome did not report a ready WebTransport session; refusing to write a report"
( cd "$CAPTURE" && sha256sum settings-frame.bin connect-headers-frame.bin >hashes.txt )

SETTINGS_BYTES="$(wc -c <"$CAPTURE/settings-frame.bin" | tr -d ' ')"
CONNECT_BYTES="$(wc -c <"$CAPTURE/connect-headers-frame.bin" | tr -d ' ')"
SETTINGS_SHA="$(awk '$2=="settings-frame.bin"{print $1}' "$CAPTURE/hashes.txt")"
CONNECT_SHA="$(awk '$2=="connect-headers-frame.bin"{print $1}' "$CAPTURE/hashes.txt")"
COMMIT="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)"
QUINN_REV="$(grep -oE 'rev = "[0-9a-f]{40}"' "$SERVER_MANIFEST" | head -n1 | grep -oE '[0-9a-f]{40}')"
WT_REV="$(grep -oE 'rev = "[0-9a-f]{40}"' "$SERVER_MANIFEST" | tail -n1 | grep -oE '[0-9a-f]{40}')"
OS_TEXT="$( (uname -srm; grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"') | paste -sd' ' -)"
CONNECT_SUMMARY="$(grep -E 'event=(connect_request_decoded|connect_request_decode_failed)' "$CAPTURE/server.log" || true)"

# --------------------------------------------------------------- 9. report.md
{
  cat <<EOF
# R6-2c Chrome SETTINGS / CONNECT raw frame capture

**What this capture proves:** Chrome actually emitted the bytes stored in
\`capture/settings-frame.bin\` and \`capture/connect-headers-frame.bin\` while
establishing a WebTransport session.

**What this capture does NOT prove:** anything about \`rtx-*\`. It is not a
statement that \`rtx-quic\`, \`rtx-webtransport\` or any future \`rtx-h3\` interoperates
with Chrome. Browser interoperability (M3-B0-B2) is R6-3 work, not this task.
The server used here is an independent reference oracle built only from the
audited \`quinn\` and \`web-transport-proto\` baselines.

## Environment

| item | value |
|---|---|
| repository commit at capture time | \`$COMMIT\` |
| Chrome (from the browser itself) | \`$CHROME_VERSION_RAW\` |
| Chrome binary | \`$CHROME\` |
| version source | \`$CHROME --version\` (\`chrome://version\` is not reachable in headless mode; raw output is in \`chrome-version.txt\`) |
| OS | \`$OS_TEXT\` |
| capture date | \`$DATE\` |
| page origin | \`https://127.0.0.1:$PAGE_PORT\` (served by \`page_server.py\`) |
| WebTransport URL | \`https://127.0.0.1:$QUIC_PORT/session\` |

## Chrome launch parameters

\`\`\`
${CHROME_FLAGS[*]}
$CHROME_URL
\`\`\`

\`--ignore-certificate-errors-spki-list\` is required only because the certificate
is self-signed; it pins acceptance to this certificate's SPKI hash and is
**local test only, not suitable for production**. \`--origin-to-force-quic-on\`
pins the WebTransport origin to QUIC (no TCP listener exists behind it).
\`--no-sandbox\` is needed because this harness runs in a container.

## Certificate handling

- Self-signed RSA-2048, \`CN=localhost\`, SAN \`DNS:localhost,IP:127.0.0.1\`,
  generated at run time by \`run.sh\` with \`openssl\`.
- Lives only in a \`mktemp\` directory outside the repository and is deleted by
  the EXIT trap. No private key, \`.pem\` or \`.key\` file is committed.

## Reference server

| item | value |
|---|---|
| QUIC runtime | \`quinn\` @ \`$QUINN_REV\` (DEPENDENCY_AUDIT.md baseline) |
| H3 / WebTransport codec reference | \`web-transport-proto\` @ \`$WT_REV\` (DEPENDENCY_AUDIT.md baseline) |
| \`rtx-*\` dependencies | none (standalone crate, own \`[workspace]\` and lock file) |
| ALPN | \`h3\` |
| server SETTINGS | produced by \`web_transport_proto::Settings::enable_webtransport(1)\`: MAX_FIELD_SECTION_SIZE, ENABLE_CONNECT_PROTOCOL, ENABLE_DATAGRAM, deprecated datagram id, WEBTRANSPORT_MAX_SESSIONS plus its deprecated ids; QPACK dynamic table disabled |

## Captured frames

| file | bytes | SHA-256 |
|---|---|---|
| \`capture/settings-frame.bin\` | $SETTINGS_BYTES | \`$SETTINGS_SHA\` |
| \`capture/connect-headers-frame.bin\` | $CONNECT_BYTES | \`$CONNECT_SHA\` |

Both files are the complete frame as received: frame type varint + length
varint + payload. The CONNECT file is in QPACK-encoded form and was never
decoded-then-re-encoded.

## Server log summary

\`\`\`
EOF
  grep -E 'event=(quic_handshake_complete|h3_settings_frame_received|h3_headers_frame_received|connect_request_decoded|connect_request_decode_failed|response_headers_sent|capture_complete|connection_closed|connection_close_wait)' "$CAPTURE/server.log" || true
  cat <<EOF
\`\`\`

Full log: \`capture/server.log\`. Frame details: \`capture/settings-decoded.txt\`.

## SETTINGS identifiers vs draft-ietf-webtrans-http3-15 (record only)

EOF
  cat "$CAPTURE/settings-decoded.txt" 2>/dev/null || echo "(no decoded table written)"
  cat <<'EOF'

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

EOF
  printf '%s\n' "$CONNECT_SUMMARY"
  cat <<'EOF'

The decode above uses the audited `web-transport-proto` reference codec and is
appendix-grade only. `capture/connect-headers-frame.bin` remains the source of
truth. A decode failure would not change the captured bytes.

Observed detail worth recording for R6-2b: this Chrome build signals the
WebTransport draft with the legacy `sec-webtransport-http3-draft02: 1` request
header, not a `sec-webtransport-http3-draft` value naming a draft number.

## Chrome console excerpt

EOF
  cat "$CAPTURE/chrome-console.log" 2>/dev/null || echo "(none captured)"
  cat <<'EOF'

## Reproduce

`interop/m3/chrome/run.sh` performs all steps automatically. See `README.md`.
EOF
} >"$OUT/report.md"

echo "capture written to $OUT"
echo "  settings-frame.bin         $SETTINGS_BYTES bytes  sha256=$SETTINGS_SHA"
echo "  connect-headers-frame.bin  $CONNECT_BYTES bytes  sha256=$CONNECT_SHA"
