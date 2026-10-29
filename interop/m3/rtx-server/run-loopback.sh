#!/usr/bin/env bash
# R6-3 loopback harness: runtime DER certificate -> rtx-wt-server + quinn /
# web-transport-proto loopback client -> server.log + hashes.txt -> report.md.
#
# Run from anywhere:  ./interop/m3/rtx-server/run-loopback.sh
# Optional env:       KEEP_WORK=1  (keep the temporary certificate/staging dirs)
#
# Private key material only exists in a mktemp directory created here and is
# removed by the EXIT trap; nothing key-like is written into the repository.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
DATE="$(date +%F)"
EVID="$HERE/evidence/$DATE-loopback"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

command -v cargo >/dev/null 2>&1 || fail "cargo is required"
command -v openssl >/dev/null 2>&1 || fail "openssl is required to generate the runtime DER certificate"

WORK="$(mktemp -d)"
STAGE="$(mktemp -d)"
cleanup() {
  if [ "${KEEP_WORK:-0}" = "1" ]; then
    echo "KEEP_WORK=1: temporary directories kept: $WORK $STAGE" >&2
    return
  fi
  rm -rf "$WORK" "$STAGE"
}
trap cleanup EXIT

# ------------------------------------- 1. runtime self-signed test certificate
# The server takes DER only; generation is delegated to openssl and the files
# never leave this temporary directory.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" >/dev/null 2>&1 \
  || fail "openssl certificate generation failed"
openssl x509 -in "$WORK/cert.pem" -outform DER -out "$WORK/cert.der" >/dev/null 2>&1 \
  || fail "certificate PEM -> DER conversion failed"
openssl pkcs8 -topk8 -nocrypt -in "$WORK/key.pem" -outform DER -out "$WORK/key.der" >/dev/null 2>&1 \
  || fail "private key PKCS#8 conversion failed"

# ------------------------------------------------- 2. loopback matrix + evidence
mkdir -p "$EVID"
rm -f "$EVID/report.md" "$EVID/server.log" "$EVID/hashes.txt"

echo "running the loopback matrix (standalone crate; not a workspace member)"
RTX_WT_SERVER_CERT_DER="$WORK/cert.der" \
RTX_WT_SERVER_KEY_DER="$WORK/key.der" \
RTX_WT_LOOPBACK_DIR="$STAGE" \
  cargo test --manifest-path "$HERE/Cargo.toml" --test loopback -- --nocapture

[ -s "$STAGE/server.log" ] || fail "the run produced no server.log"
[ -s "$STAGE/hashes.txt" ] || fail "the run produced no hashes.txt"

cp "$STAGE/server.log" "$STAGE/hashes.txt" "$EVID/"

COMMIT="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)"
VERSION="$(grep -m1 '^version' "$HERE/Cargo.toml" | cut -d'"' -f2)"
QUINN_REV="$(grep -oE 'rev = "[0-9a-f]{40}"' "$HERE/Cargo.toml" | head -n1 | grep -oE '[0-9a-f]{40}')"
WT_REV="$(grep -oE 'rev = "[0-9a-f]{40}"' "$HERE/Cargo.toml" | tail -n1 | grep -oE '[0-9a-f]{40}')"
RUSTC="$(rustc -V 2>/dev/null || echo unknown)"
OS_TEXT="$( (uname -srm; grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"') | paste -sd' ' -)"
NEGOTIATED="$(grep -m1 -o 'peer_max_datagram_frame_size=[0-9]*' "$EVID/server.log" | cut -d= -f2)"
[ -n "$NEGOTIATED" ] || fail "the server log carries no negotiated max_datagram_frame_size"

# The matrix table is the same data as hashes.txt, rendered for reading.
matrix_table() {
  awk -F'\t' '!/^#/ && NF == 7 {
    printf "| `%s` | %s | %s | %s | %s | `%s` | %s |\n", $1, $2, $3, $4, $5, $6, $7
  }' "$EVID/hashes.txt"
}

# The first five server_setting lines are the first connection's SETTINGS; the
# payload is identical for every connection.
settings_table() {
  grep 'event=server_setting ' "$EVID/server.log" | head -n5 | sed -E \
    's/.*id=(0x[0-9a-f]+) value=([0-9]+).*/\1\t\2/' | while IFS=$'\t' read -r id value; do
      case "$id" in
        0x1) name="QPACK_MAX_TABLE_CAPACITY" ;;
        0x7) name="QPACK_BLOCKED_STREAMS" ;;
        0x8) name="ENABLE_CONNECT_PROTOCOL" ;;
        0x33) name="H3_DATAGRAM" ;;
        0xc671706a) name="WEBTRANSPORT_MAX_SESSIONS" ;;
        *) name="UNEXPECTED" ;;
      esac
      printf '| `%s` | %s | `%s` |\n' "$id" "$value" "$name"
    done
}

# --------------------------------------------------------------- 3. report.md
{
  cat <<EOF
# R6-3 WebTransport server harness loopback evidence

**What this proves:** the \`rtx-wt-server\` harness (built on \`rtx-quic\` +
\`rtx-h3\` + \`rtx-webtransport\`) completes the H3 handshake, accepts extended
CONNECT sessions, echoes WebTransport datagrams and streams, handles the
capsule protocol, and serves new sessions on the same QUIC connection. The
client is the independent audit-baseline oracle (\`quinn\` +
\`web-transport-proto\`), not \`rtx-*\` itself.

**What this does NOT prove:** browser (Chrome) interoperability. Chrome is
R6-4, not this unit. No \`interop/m3/chrome/\` report is produced or claimed
here, and loopback success must not be written up as a Chrome/M3-B pass.

## Environment

| item | value |
|---|---|
| repository commit | \`$COMMIT\` |
| harness package / version | \`rtx-wt-server\` / \`$VERSION\` (standalone crate, not a workspace member) |
| date | $DATE |
| rustc | \`$RUSTC\` |
| OS | \`$OS_TEXT\` |
| loopback client | \`quinn\` @ \`$QUINN_REV\`, \`web-transport-proto\` @ \`$WT_REV\` (dev-dependencies only) |
| server engine | \`rtx-quic\` -> \`quinn-proto 0.11.19\` (workspace pin) |
| transport | loopback UDP, ALPN \`h3\`, runtime self-signed certificate (mktemp, deleted by the EXIT trap) |

## Server SETTINGS actually emitted

\`rtx-h3\`'s encoder drops deprecated and unknown pairs, so the payload contains
exactly these five items (the R6-2c reference server's six-item payload
includes deprecated pairs that this codec refuses to emit by design):

| id | value | name |
|---|---|---|
$(settings_table)

\`0x2c7cf000\` (\`SETTINGS_WT_ENABLED\` in \`draft-ietf-webtrans-http3-15\`
section 9.2) is **not** sent. N4 ruling: Chrome 156 negotiates the deprecated
\`0x2b603742\` signal, so emitting a codepoint no observed peer negotiates
would be an unverified behaviour. The \`0xc671706a = 100\` value is a harness
capacity choice for sequential + concurrent loopback sessions, not a protocol
requirement.

## DATAGRAM budget

- Negotiated \`max_datagram_frame_size\` (from the peer transport parameters
  captured at handshake, logged as \`peer_max_datagram_frame_size\`): **$NEGOTIATED**
  bytes. It is not written by hand; the harness reads it out of
  \`HandshakeInfo::peer_transport_parameters\`.
- The "full" tier uses the largest payload both engines' receive accounting
  accepts: \`1100 - 32 = 1068\` bytes (quinn-proto 0.11.19 rejects
  \`payload + size_of::<Datagram>()\` above the advertised receive window; the
  0.12 client's send budget is \`window - 9\`). The HTTP Datagram payload is
  \`1068\` bytes = 1-byte quarter stream ID + 1067-byte WebTransport payload.

## Loopback matrix

Everything below is produced by \`tests/loopback.rs\`; \`hashes.txt\` is the
machine-readable copy. Payloads are the deterministic \`0..255\` cycle (first N
bytes), so every SHA-256 repeats across runs.

| item | sends | receives | lost | bytes | SHA-256 | detail |
|---|---|---|---|---|---|---|
$(matrix_table)

Interpretation:

- all DATAGRAM tiers are pairwise echo (send one, verify one echo, repeat);
  loopback loss is 0 and every echo is byte-identical. Burst behaviour is R6-4
  work, where \`M3-B1\` records real loss numbers.
- wrong-session and empty (malformed) datagrams are dropped with a log line and
  the connection keeps echoing.
- client uni 1 MiB comes back on a new server uni stream; client bi and the 10
  concurrent bi streams come back on their own streams; half-close is used
  everywhere.
- the server opens a 1 MiB uni stream per session and a bi stream that it resets
  after 4096 bytes (code 7); the client observes the reset. A deliberate
  \`RESET_STREAM\` may discard stream data, so the session header is optional on
  the reset stream; the server log records the reset.
- \`WT_DRAIN_SESSION\` is logged and the session survives (a datagram still
  echoes); \`WT_CLOSE_SESSION\` ends the session and the same QUIC connection
  serves a new session afterwards.

## Protocol boundaries

- **Capsule carriage:** capsules travel inside HTTP/3 DATA frames on the
  CONNECT stream (\`RFC 9297\` section 3.2; the audited
  \`web-transport-proto::Http3CapsuleReader\` reads them the same way). The
  capsule bytes themselves are \`rtx-webtransport\`'s codec.
- **QPACK:** encoder emits static-table references and non-Huffman literals
  only; the prefix is \`00 00\`. The decoder rejects a SETTINGS combination with
  non-zero \`QPACK_MAX_TABLE_CAPACITY\` / \`QPACK_BLOCKED_STREAMS\`
  (\`ensure_dynamic_table_disabled\`) and closes the connection with
  \`H3_SETTINGS_ERROR\`. The loopback client deliberately advertises neither
  (the reference codec's \`enable_webtransport\` does not send them).
- **DATAGRAM semantics:** QUIC DATAGRAM is unreliable and unordered; the
  harness never truncates and logs a failed echo explicitly. Loopback losing
  nothing is an observation about this environment, not a protocol guarantee.
- **Session identifiers:** the session ID is the CONNECT stream ID
  (client-initiated bidirectional, \`≡ 0 mod 4\`); the HTTP Datagram quarter
  stream ID is \`SessionId >> 2\` (\`rtx-webtransport::ids\`). Streams carry
  \`0x54\`+session ID (uni) or \`0x41\`+session ID (bi), per
  \`draft-ietf-webtrans-http3-15\` sections 4.2 and 4.3.
- **CLOSE/DRAIN:** \`WT_CLOSE_SESSION\` removes the session, finishes the
  CONNECT send side and abandons leftover server-initiated streams with
  \`WT_SESSION_GONE\`. \`WT_DRAIN_SESSION\` only logs and marks the session
  drained; it does not close the connection.

## Server log summary

\`\`\`
$(grep -E 'event=(server_listening|config_loaded|quic_handshake_complete|h3_settings_frame_received|server_settings_sent|connect_request_decoded|response_headers_sent|session_closed|session_drained|connection_close)' "$EVID/server.log" | head -n 40)
\`\`\`

Full log: \`server.log\` ($(grep -c '' "$EVID/server.log") lines).

## Not done (explicitly)

- Chrome / Firefox interoperability (R6-4: B0/B1/B2/B3/B5).
- B4 \`quinn\` reference interop records (this \`quinn\` is only the loopback
  client, not an interop statement).
- benchmarks (P7), embedded ports (P8), full HTTP/3, QPACK dynamic table,
  Huffman encoder, 0-RTT, connection migration, multi-session defaults.
- no modification of existing crates, existing docs, \`interop/m3/chrome/\`,
  CI, or the workspace manifest.

## Reproduce

\`\`\`
./interop/m3/rtx-server/run-loopback.sh
\`\`\`

The script generates the DER certificate/key with openssl in a mktemp directory,
runs \`cargo test --test loopback\`, copies \`server.log\`/\`hashes.txt\` here and
regenerates this report. No key material enters the repository.
EOF
} >"$EVID/report.md"

# ---------------------------------------------------------------- 4. validate
for artifact in report.md server.log hashes.txt; do
  [ -s "$EVID/$artifact" ] || fail "missing evidence artifact: $artifact"
done
EXTRA="$(find "$EVID" -maxdepth 1 -type f ! -name report.md ! -name server.log ! -name hashes.txt -print -quit)"
[ -z "$EXTRA" ] || fail "unexpected file in the evidence directory: $EXTRA"

echo "evidence written to $EVID"
echo "  server.log  $(grep -c '' "$EVID/server.log") lines"
echo "  hashes.txt  $(grep -c '' "$EVID/hashes.txt") lines"
echo "  max_datagram_frame_size=$NEGOTIATED"
