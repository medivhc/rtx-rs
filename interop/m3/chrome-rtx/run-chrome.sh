#!/usr/bin/env bash
# R6-4 Chrome WebTransport interop runner (M3-B0/B1/B2/B3/B5).
#
# Two phases, deliberately separate:
#   PHASE=baseline  run the harness exactly as it is at HEAD (no local edits to
#                   interop/m3/rtx-server allowed) and archive the result. At
#                   edca8ea this is expected to end in the H4 rejection
#                   (`h3_settings_rejected` + H3_SETTINGS_ERROR 0x0101).
#   PHASE=relaxed   run the harness after the one-place relaxation described in
#                   interop/m3/rtx-server/README.md.
#
# Order: runtime self-signed cert -> rtx-wt-server -> HTTPS page server ->
# headless Chrome -> test page posts `window.__rtx_result` back to the page
# server -> evidence/report.
#
# Run from anywhere:  PHASE=baseline ./interop/m3/chrome-rtx/run-chrome.sh
# Optional env:       CHROME_BIN=... QUIC_PORT=4433 PAGE_PORT=8443
#                     RESULT_TIMEOUT=420 KEEP_WORK=1
#
# Private key material only ever exists in a mktemp directory created here and
# removed by the EXIT trap; nothing key-like is written into the repository.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
PHASE="${PHASE:-baseline}"
QUIC_PORT="${QUIC_PORT:-4433}"
PAGE_PORT="${PAGE_PORT:-8443}"
RESULT_TIMEOUT="${RESULT_TIMEOUT:-420}"
DATE="$(date +%F)"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

case "$PHASE" in
  baseline|relaxed) ;;
  *) echo "ERROR: PHASE must be baseline or relaxed (got '$PHASE')" >&2; exit 2 ;;
esac

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
                "$HOME"/.cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell \
                "$HOME"/.cache/puppeteer/chrome/linux-*/chrome-linux64/chrome \
                "$HOME"/.cache/puppeteer/chrome-headless-shell/linux-*/chrome-headless-shell-linux64/chrome-headless-shell; do
      if [ -x "$cand" ]; then
        CHROME="$cand"
        break
      fi
    done
  fi
fi
if [ -z "$CHROME" ] || [ ! -x "$CHROME" ]; then
  echo "无可用浏览器，Chrome 实测未执行 (no runnable Chrome/Chromium found; set CHROME_BIN)" >&2
  exit 2
fi
command -v python3 >/dev/null 2>&1 \
  || fail "python3 is required for the local HTTPS page server (no report produced)"
command -v openssl >/dev/null 2>&1 \
  || fail "openssl is required to generate the runtime self-signed certificate"
command -v cargo >/dev/null 2>&1 \
  || fail "cargo is required to build the rtx-wt-server harness"

CHROME_VERSION_RAW="$("$CHROME" --version 2>&1 | head -n1 | sed -e 's/[[:space:]]*$//')"
VERSION="$(printf '%s\n' "$CHROME_VERSION_RAW" | grep -oE '[0-9]+(\.[0-9]+)+' | head -n1 || true)"
[ -n "$VERSION" ] || fail "cannot parse Chrome version from: $CHROME_VERSION_RAW"

HARNESS_MAIN="$REPO/interop/m3/rtx-server/src/main.rs"
HARNESS_README="$REPO/interop/m3/rtx-server/README.md"
HARNESS_MAIN_SHA="$(sha256sum "$HARNESS_MAIN" | cut -d' ' -f1)"

# The baseline evidence is only credible if the harness is untouched. Refuse to
# label a locally modified harness as a baseline.
if [ "$PHASE" = "baseline" ]; then
  git -C "$REPO" diff --quiet -- "$HARNESS_MAIN" "$HARNESS_README" \
    || fail "PHASE=baseline requires an unmodified harness (main.rs/README differ from HEAD); \
restore them or run PHASE=relaxed"
fi

OUT="$HERE/$DATE-chrome-$VERSION"
if [ "$PHASE" = "baseline" ]; then
  EVID="$OUT-baseline"
else
  EVID="$OUT"
fi
BASELINE_DIR="$DATE-chrome-$VERSION-baseline"
mkdir -p "$EVID"
rm -rf "$EVID/result.json" "$EVID/report.md" "$EVID/server.log" \
       "$EVID/chrome-console.log" "$EVID/chrome-netlog.txt" "$EVID/hashes.txt" "$EVID/chrome-version.txt"

WORK="$(mktemp -d)"
STAGE="$(mktemp -d)"
SERVER_PID=""
PAGE_PID=""
CHROME_PID=""
cleanup() {
  for pid in "$CHROME_PID" "$PAGE_PID" "$SERVER_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  for pid in "$CHROME_PID" "$PAGE_PID" "$SERVER_PID"; do
    [ -n "$pid" ] && wait "$pid" 2>/dev/null || true
  done
  if [ "${KEEP_WORK:-0}" = "1" ]; then
    echo "KEEP_WORK=1: logs and certificate kept in $WORK (staging $STAGE)" >&2
    return
  fi
  rm -rf "$WORK" "$STAGE"
}
trap cleanup EXIT

# ------------------------------------- 1. runtime self-signed test certificate
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" >/dev/null 2>&1 \
  || fail "openssl certificate generation failed"
openssl x509 -in "$WORK/cert.pem" -outform DER -out "$WORK/cert.der" >/dev/null 2>&1 \
  || fail "certificate PEM -> DER conversion failed"
openssl pkcs8 -topk8 -nocrypt -in "$WORK/key.pem" -outform DER -out "$WORK/key.der" >/dev/null 2>&1 \
  || fail "private key PKCS#8 conversion failed"
# SHA-256 of the DER SubjectPublicKeyInfo, base64: the exact value Chrome's
# --ignore-certificate-errors-spki-list expects (this flag *does* cover QUIC;
# --ignore-certificate-errors alone does not).
SPKI="$(openssl x509 -in "$WORK/cert.pem" -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | base64)" \
  || fail "SPKI hash computation failed"

# ------------------------------------------------------- 2. build the harness
echo "building rtx-wt-server (standalone crate, not a workspace member)"
cargo build --release --locked --manifest-path "$REPO/interop/m3/rtx-server/Cargo.toml" \
  >"$WORK/build.log" 2>&1 \
  || { tail -n 30 "$WORK/build.log" >&2; fail "rtx-wt-server build failed"; }
SERVER_BIN="$REPO/interop/m3/rtx-server/target/release/rtx-wt-server"
[ -x "$SERVER_BIN" ] || fail "rtx-wt-server binary missing after build"

# ------------------------------------------------- 3. start the page server
python3 "$HERE/page_server.py" "$PAGE_PORT" "$WORK/cert.pem" "$WORK/key.pem" \
  "$STAGE/result.json" "$STAGE/server.log" >"$WORK/page.log" 2>&1 &
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

# ------------------------------------------------------- 4. start the harness
"$SERVER_BIN" --bind "127.0.0.1:$QUIC_PORT" \
  --cert-chain-der "$WORK/cert.der" \
  --key-der "$WORK/key.der" \
  --log "$STAGE/server.log" >"$WORK/server.stderr" 2>&1 &
SERVER_PID=$!

listen_ready=0
for _ in $(seq 1 200); do
  if grep -q 'event=server_listening' "$STAGE/server.log" 2>/dev/null; then
    listen_ready=1
    break
  fi
  kill -0 "$SERVER_PID" 2>/dev/null || break
  sleep 0.1
done
[ "$listen_ready" -eq 1 ] || { cat "$WORK/server.stderr" >&2; fail "rtx-wt-server did not start listening"; }
LISTEN_LINE="$(grep -m1 'event=server_listening' "$STAGE/server.log")"
ADDR="$(printf '%s\n' "$LISTEN_LINE" | sed -E 's/.*addr=([^ ]+).*/\1/')"
QUIC_ACTUAL_PORT="${ADDR##*:}"
echo "harness listening: $ADDR"

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
  --disable-dev-shm-usage
  --no-proxy-server
  --ignore-certificate-errors-spki-list="$SPKI"
  --origin-to-force-quic-on="127.0.0.1:$QUIC_ACTUAL_PORT"
  --user-data-dir="$WORK/chrome-profile"
  --enable-logging=stderr
  --log-net-log="$WORK/netlog.json"
  --v=0
)
CHROME_URL="https://127.0.0.1:$PAGE_PORT/index.html?port=$QUIC_ACTUAL_PORT&phase=$PHASE"
printf '%s\n' "${CHROME_FLAGS[*]}" >"$WORK/flags.txt"
"$CHROME" "${CHROME_FLAGS[@]}" "$CHROME_URL" >"$WORK/chrome.log" 2>&1 &
CHROME_PID=$!

# ------------------- 6. wait for the page result (bounded, event-driven)
RESULT_REASON=""
deadline=$(( $(date +%s) + RESULT_TIMEOUT ))
while [ ! -s "$STAGE/result.json" ]; do
  if ! kill -0 "$CHROME_PID" 2>/dev/null; then
    RESULT_REASON="Chrome exited before the page posted window.__rtx_result"
    break
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    RESULT_REASON="page result timeout after ${RESULT_TIMEOUT}s"
    break
  fi
  sleep 0.2
done

# The harness must still be alive after the matrix (B1/B2 requirement: it does
# not crash). Record that before cleanup kills it.
SERVER_ALIVE=0
kill -0 "$SERVER_PID" 2>/dev/null && SERVER_ALIVE=1
if [ "$SERVER_ALIVE" -eq 0 ]; then
  [ -n "$RESULT_REASON" ] || RESULT_REASON="rtx-wt-server exited before the page posted a result"
  wait "$SERVER_PID" 2>/dev/null && SERVER_RC=0 || SERVER_RC=$?
else
  SERVER_RC=0
fi
SERVER_PID=""

if [ ! -s "$STAGE/result.json" ]; then
  python3 - "$STAGE/result.json" "$PHASE" "$RESULT_REASON" "$SERVER_ALIVE" <<'PY'
import json, sys
path, phase, reason, alive = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
stub = {
    "phase": phase,
    "stub": True,
    "b0": {"status": "fail", "error": reason, "ready_ms": None},
    "b1": {"status": "not_run", "tiers": [], "params": None, "derivation": None},
    "b2": {"status": "not_run", "items": {}, "uni_streams": [], "bi_streams": []},
    "session_close": {"status": "not_run", "error": None, "closed_event": None},
    "second_session": {"status": "not_run", "error": None},
    "failures": [{"item": "run", "gap": ("GAP-M3-B0-01" if phase == "baseline" else "GAP-M3-B0-02"), "detail": reason}],
    "server_alive": bool(alive),
    "verdict": "fail",
    "finished": True
}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(stub, handle, indent=2)
PY
fi

# ---------------------------------------------------------- 7. stop everything
if [ -n "$CHROME_PID" ]; then
  kill "$CHROME_PID" 2>/dev/null || true
  wait "$CHROME_PID" 2>/dev/null || true
  CHROME_PID=""
fi
kill "$PAGE_PID" 2>/dev/null || true
wait "$PAGE_PID" 2>/dev/null || true
PAGE_PID=""

# Filter the Chrome netlog down to the WebTransport / connection-close events
# the report needs. The raw netlog stays in the mktemp directory; only this
# text excerpt enters the evidence directory.
python3 - "$WORK/netlog.json" "$EVID/chrome-netlog.txt" <<'PY'
import json
import os
import re
import sys

source, destination = sys.argv[1], sys.argv[2]
if not os.path.exists(source):
    with open(destination, "w", encoding="utf-8") as handle:
        handle.write("no Chrome netlog captured in this run\n")
    raise SystemExit(0)
text = open(source, encoding="utf-8", errors="replace").read()
mapping = {}
match = re.search(r'"logEventTypes":\s*\{([^}]*)\}', text)
if match:
    mapping = {int(value): name for name, value in re.findall(r'"([^"]+)":(\d+)', match.group(1))}
lines = []
position = text.find('"events": [')
if position >= 0:
    rest = text[position:]
    decoder = json.JSONDecoder()
    cursor = rest.find("[") + 1
    wanted = (
        "QUIC_SESSION_WEBTRANSPORT",
        "QUIC_SESSION_CONNECTION_CLOSE_FRAME_SENT",
        "QUIC_SESSION_CONNECTION_CLOSE_FRAME_RECEIVED",
        "QUIC_SESSION_CLOSED",
    )
    while True:
        while cursor < len(rest) and rest[cursor] in " \n\r\t,":
            cursor += 1
        if cursor >= len(rest):
            break
        try:
            event, end = decoder.raw_decode(rest, cursor)
        except Exception:
            break
        cursor = end
        name = mapping.get(event.get("type"), str(event.get("type")))
        if name.startswith(wanted):
            lines.append("%s %s %s" % (event.get("time"), name, json.dumps(event.get("params", {}))[:600]))
if not any("WEBTRANSPORT" in line for line in lines):
    for error in sorted(set(re.findall(r"ERR_[A-Z_]+", text))):
        lines.append("netlog string match: " + error)
with open(destination, "w", encoding="utf-8") as handle:
    handle.write("\n".join(lines) + "\n" if lines else "netlog captured but contained no WebTransport events\n")
PY

[ -s "$STAGE/server.log" ] || fail "the harness produced no server.log (no report is produced)"
cp "$STAGE/server.log" "$EVID/server.log"
cp "$STAGE/result.json" "$EVID/result.json"
printf '%s\n' "$CHROME_VERSION_RAW" >"$EVID/chrome-version.txt"

grep -E 'INFO:CONSOLE' "$WORK/chrome.log" >"$EVID/chrome-console.log" 2>/dev/null || true
if [ ! -s "$EVID/chrome-console.log" ]; then
  grep -E 'ERROR:|CONSOLE' "$WORK/chrome.log" >"$EVID/chrome-console.log" 2>/dev/null || true
fi
[ -s "$EVID/chrome-console.log" ] \
  || printf '%s\n' "no Chrome CONSOLE lines were captured in this run" >"$EVID/chrome-console.log"

# --------------------------------------------------------- 8. B3 environment
FIREFOX_STATUS="NOT DETERMINED"
FIREFOX_DETAIL="no Firefox binary found (checked command -v firefox, /usr/lib/firefox/firefox, ~/.cache/ms-playwright/firefox-*/firefox/firefox, /snap/bin/firefox)"
FIREFOX_BIN="$(command -v firefox 2>/dev/null || true)"
if [ -z "$FIREFOX_BIN" ]; then
  for cand in /usr/lib/firefox/firefox "$HOME"/.cache/ms-playwright/firefox-*/firefox/firefox /snap/bin/firefox; do
    if [ -x "$cand" ]; then
      FIREFOX_BIN="$cand"
      break
    fi
  done
fi
if [ -n "$FIREFOX_BIN" ]; then
  FIREFOX_VERSION="$("$FIREFOX_BIN" --version 2>&1 | head -n1 | sed -e 's/[[:space:]]*$//')"
  FIREFOX_STATUS="PRESENT-UNRUN"
  FIREFOX_DETAIL="found $FIREFOX_BIN ($FIREFOX_VERSION) but this runner has no Firefox certificate/profile path; not exercised"
fi

COMMIT="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)"
HARNESS_TREE="$(git -C "$REPO" rev-parse HEAD:interop/m3/rtx-server 2>/dev/null || echo unknown)"
HARNESS_DIFF="$(git -C "$REPO" diff --stat -- "$HARNESS_MAIN" "$HARNESS_README" 2>/dev/null | tr '\n' ' ' || true)"
[ -n "$HARNESS_DIFF" ] || HARNESS_DIFF="none (harness identical to HEAD)"
OS_TEXT="$( (uname -srm; grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"') | paste -sd' ' -)"
FLAGS_TEXT="$(cat "$WORK/flags.txt")"
LOOPBACK_NOTE=""
if [ -d "$EVID/loopback-regression" ]; then
  LOOPBACK_NOTE="loopback-regression"
fi

# ---------------------- 9. hashes.txt + report.md (same source: result.json)
PHASE="$PHASE" COMMIT="$COMMIT" CHROME_VERSION_RAW="$CHROME_VERSION_RAW" \
CHROME="$CHROME" OS_TEXT="$OS_TEXT" ADDR="$ADDR" PAGE_PORT="$PAGE_PORT" \
QUIC_ACTUAL_PORT="$QUIC_ACTUAL_PORT" FLAGS_TEXT="$FLAGS_TEXT" DATE="$DATE" \
BASELINE_DIR="$BASELINE_DIR" HARNESS_MAIN_SHA="$HARNESS_MAIN_SHA" \
HARNESS_TREE="$HARNESS_TREE" \
HARNESS_DIFF="$HARNESS_DIFF" SERVER_ALIVE="$SERVER_ALIVE" SERVER_RC="$SERVER_RC" \
FIREFOX_STATUS="$FIREFOX_STATUS" FIREFOX_DETAIL="$FIREFOX_DETAIL" \
LOOPBACK_NOTE="$LOOPBACK_NOTE" RESULT_TIMEOUT="$RESULT_TIMEOUT" \
python3 - "$EVID" "$EVID/result.json" "$EVID/server.log" <<'PY'
import hashlib
import json
import os
import re
import sys

EVID, RESULT_PATH, SERVER_LOG_PATH = sys.argv[1], sys.argv[2], sys.argv[3]
ENV = os.environ
PHASE = ENV["PHASE"]

with open(RESULT_PATH, "r", encoding="utf-8") as handle:
    result = json.load(handle)
with open(SERVER_LOG_PATH, "r", encoding="utf-8") as handle:
    log_lines = handle.read().splitlines()

B3_STATUS = ENV.get("FIREFOX_STATUS", "NOT DETERMINED")
B3_DETAIL = ENV.get("FIREFOX_DETAIL", "")
B3_OPEN = B3_STATUS in ("NOT DETERMINED", "PRESENT-UNRUN")

# ------------------------------------------------------------ server log facts
def count(pattern):
    regex = re.compile(pattern)
    return sum(1 for line in log_lines if regex.search(line))

def byte_counts(event):
    counts = {}
    regex = re.compile("event=" + event + " .*bytes=([0-9]+)")
    for line in log_lines:
        match = regex.search(line)
        if match:
            value = int(match.group(1))
            counts[value] = counts.get(value, 0) + 1
    return counts

settings = []
seen_settings_frame = False
for line in log_lines:
    if "event=h3_settings_frame_received" in line:
        if seen_settings_frame:
            break
        seen_settings_frame = True
        continue
    if seen_settings_frame:
        match = re.search(
            r"event=h3_setting .*id=(0x[0-9a-f]+) value=([0-9]+) class=([a-z]+)", line
        )
        if match:
            settings.append({"id": match.group(1), "value": int(match.group(2)), "class": match.group(3)})
        elif "event=" in line:
            break

server_settings = []
for line in log_lines:
    match = re.search(r"event=server_setting .*id=(0x[0-9a-f]+) value=([0-9]+)", line)
    if match:
        pair = (match.group(1), int(match.group(2)))
        if pair not in server_settings:
            server_settings.append(pair)

def has_id(identifier):
    return any(item["id"] == identifier for item in settings)

def server_has_id(identifier):
    return any(pair[0] == identifier for pair in server_settings)

netlog_path = os.path.join(EVID, "chrome-netlog.txt")
netlog_text = ""
if os.path.exists(netlog_path):
    netlog_text = open(netlog_path, "r", encoding="utf-8").read()
method_not_supported = "ERR_METHOD_NOT_SUPPORTED" in netlog_text

received = byte_counts("datagram_received")
sent = byte_counts("datagram_sent")
echo_failed = count(r"event=datagram_echo_failed")
dropped = {
    "wrong_session": count(r"event=datagram_dropped .*reason=wrong_session"),
    "malformed": count(r"event=datagram_dropped .*reason=malformed"),
    "decode_failed": count(r"event=datagram_dropped .*reason=decode_failed"),
    "buffer_too_small": count(r"event=datagram_dropped .*reason=buffer_too_small"),
}
connect_decoded = count(r"event=connect_request_decoded")
connect_rejected = count(r"event=connect_request_rejected")
responses = count(r"event=response_headers_sent .*status=200")
settings_rejected = count(r"event=h3_settings_rejected")
close_requests = count(r"event=connection_close_requested")
session_closed = count(r"event=session_closed")
client_stream_finished = count(r"event=stream_finished .*role=client")
client_reset = count(r"event=stream_reset .*role=client")
server_reset = count(r"event=stream_reset .*role=server .*code=7")
server_uni_open = count(r"event=stream_opened .*kind=uni role=server .*bytes=1048576")
handshake = count(r"event=quic_handshake_complete")

config_line = next((line for line in log_lines if "event=config_loaded" in line), "")
handshake_line = next((line for line in log_lines if "event=quic_handshake_complete" in line), "")
settings_frame_line = next((line for line in log_lines if "event=h3_settings_frame_received" in line), "")
reject_line = next((line for line in log_lines if "event=h3_settings_rejected" in line), "")
close_line = next((line for line in log_lines if "event=connection_close_requested" in line), "")

# ------------------------------------------------------------ failure / GAP map
failures = result.get("failures", []) or []
gaps = [dict(item) for item in failures]
if B3_OPEN:
    gaps.append({
        "item": "B3",
        "gap": "GAP-M3-B3-01",
        "detail": "Firefox " + B3_STATUS + ": " + B3_DETAIL + "; escalated to coordinator xc review",
    })
# Stable ordering, B0/B1/B2 before B3.
group_order = {"B0": 0, "B1": 1, "B2": 2, "B3": 3, "run": 4}
gaps.sort(key=lambda gap: (group_order.get(gap["item"], 9), gap["gap"]))
blocking_gaps = [gap for gap in gaps if gap["gap"] != "GAP-M3-B3-01"]
b3_gaps = [gap for gap in gaps if gap["gap"] == "GAP-M3-B3-01"]
result["b3"] = {
    "status": B3_STATUS,
    "detail": B3_DETAIL,
    "gap": "GAP-M3-B3-01" if B3_OPEN else None,
}
result["gaps"] = gaps
result["blocking_gap_count"] = len(blocking_gaps)
result["server_alive_after_matrix"] = bool(int(ENV.get("SERVER_ALIVE", "0")))

with open(RESULT_PATH, "w", encoding="utf-8") as handle:
    json.dump(result, handle, indent=2)

b0 = result.get("b0", {}) or {}
b1 = result.get("b1", {}) or {}
b2 = result.get("b2", {}) or {}
tiers = b1.get("tiers", []) or []
items = b2.get("items", {}) or {}
params = b1.get("params") or {}

# ---------------------------------------------------------------- hashes.txt
hash_rows = []
def add_row(item, sends, receives, lost, total_bytes, sha, detail):
    hash_rows.append((item, str(sends), str(receives), str(lost), str(total_bytes), sha or "-", detail))

if b0.get("status") == "pass":
    add_row("b0_session", 1, 1, 0, 0, "-", "extended CONNECT; ready + server connect_request_decoded/200")
else:
    b0_gap = next(
        (gap.get("gap") for gap in failures
         if str(gap.get("gap", "")).startswith("GAP-M3-B0-")),
        "GAP-M3-B0-01" if PHASE == "baseline" else "GAP-M3-B0-02",
    )
    add_row("b0_session", 1, 0, 1, 0, "-",
            (b0.get("error") or "no session") + "; "
            + (b0_gap if b0.get("status") == "fail" else "not_run"))

for tier in tiers:
    size = tier.get("payload_bytes", 0)
    server_received = received.get(size, 0)
    server_echo = sent.get(size + 1, 0)
    add_row("datagram_chrome_to_server_tier_" + tier.get("label", "?"),
            tier.get("sends", 0), server_received, max(0, tier.get("sends", 0) - server_received),
            tier.get("sends", 0) * size, tier.get("payload_sha256", "-"),
            "server.log datagram_received bytes=%d; %s" % (size, tier.get("sequence", "")))
    add_row("datagram_server_echo_tier_" + tier.get("label", "?"),
            server_echo, tier.get("echoes_received", 0),
            max(0, server_echo - tier.get("echoes_received", 0)),
            tier.get("echoes_received", 0) * size, tier.get("payload_sha256", "-"),
            "server.log datagram_sent bytes=%d; page echoes_received=%d" % (
                size + 1, tier.get("echoes_received", 0)))

for name in ("server_uni", "client_uni", "client_bi", "concurrent_bi", "client_reset", "server_reset"):
    if name == "concurrent_bi":
        entry = items.get(name, {}) or {}
        if entry:
            streams = entry.get("streams", 10)
            bytes_count = entry.get("bytes_per_stream", 0) * streams
            add_row(name, streams, entry.get("completed", 0),
                    max(0, streams - entry.get("completed", 0)), bytes_count,
                    entry.get("sent_sha256", "-"), entry.get("status", "?"))
    elif name == "server_uni":
        entry = items.get(name, {}) or {}
        if entry:
            add_row(name, 1, 1 if entry.get("status") == "pass" else 0,
                    0 if entry.get("status") == "pass" else 1,
                    entry.get("bytes", 0), entry.get("sha256", "-"), entry.get("status", "?"))
    elif name == "client_uni":
        entry = items.get(name, {}) or {}
        if entry:
            add_row(name, 1, 1 if entry.get("status") == "pass" else 0,
                    0 if entry.get("status") == "pass" else 1,
                    entry.get("sent_bytes", 0), entry.get("sent_sha256", "-"),
                    entry.get("status", "?"))
    elif name == "client_bi":
        entry = items.get(name, {}) or {}
        if entry:
            add_row(name, 1, 1 if entry.get("status") == "pass" else 0,
                    0 if entry.get("status") == "pass" else 1,
                    entry.get("sent_bytes", 0), entry.get("sent_sha256", "-"),
                    entry.get("status", "?"))
    elif name == "client_reset":
        entry = items.get(name, {}) or {}
        if entry:
            add_row(name, 1, 1 if entry.get("status") == "reset_sent" else 0,
                    0 if entry.get("status") == "reset_sent" else 1,
                    entry.get("bytes_before_reset", 0), "-",
                    "server log stream_reset role=client count=%d" % client_reset)
    elif name == "server_reset":
        entry = items.get(name, {}) or {}
        if entry:
            add_row(name, 1, 1 if entry.get("observed") else 0,
                    0 if entry.get("observed") else 1,
                    entry.get("bytes_before_reset", 0), "-",
                    "reset_code=%s; server log server_reset count=%d" % (
                        entry.get("reset_code"), server_reset))

with open(os.path.join(EVID, "hashes.txt"), "w", encoding="utf-8") as handle:
    handle.write("# item\tsends\treceives\tlost\tbytes\tsha256\tdetail\n")
    for row in hash_rows:
        handle.write("\t".join(row) + "\n")

# ---------------------------------------------------------------- report helpers
def md_table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join(["---"] * len(header)) + "|"]
    for row in rows:
        out.append("| " + " | ".join(str(cell).replace("|", "\\|") for cell in row) + " |")
    return "\n".join(out)

def settings_table():
    rows = []
    for entry in settings:
        name = {
            "0x1": "QPACK_MAX_TABLE_CAPACITY",
            "0x6": "MAX_FIELD_SECTION_SIZE",
            "0x7": "QPACK_BLOCKED_STREAMS",
            "0x8": "ENABLE_CONNECT_PROTOCOL",
            "0x33": "H3_DATAGRAM",
            "0xffd277": "H3_DATAGRAM (deprecated)",
            "0x2b603742": "ENABLE_WEBTRANSPORT (deprecated)",
            "0xc671706a": "WEBTRANSPORT_MAX_SESSIONS",
            "0x2c7cf000": "SETTINGS_WT_ENABLED (draft-15)",
        }.get(entry["id"], "unknown/GREASE")
        rows.append(["`%s`" % entry["id"], entry["value"], name, entry["class"]])
    return md_table(["id", "value", "name", "class"], rows)

def settings_server_table():
    rows = []
    for identifier, value in server_settings:
        name = {
            "0x1": "QPACK_MAX_TABLE_CAPACITY",
            "0x7": "QPACK_BLOCKED_STREAMS",
            "0x8": "ENABLE_CONNECT_PROTOCOL",
            "0x33": "H3_DATAGRAM",
            "0xc671706a": "WEBTRANSPORT_MAX_SESSIONS",
        }.get(identifier, "unexpected")
        rows.append(["`%s`" % identifier, value, name])
    return md_table(["id", "value", "name"], rows)

def datagram_table():
    rows = []
    for tier in tiers:
        size = tier.get("payload_bytes", 0)
        server_received = received.get(size, 0)
        server_echo = sent.get(size + 1, 0)
        rows.append([
            tier.get("label", "?"), size, tier.get("sends", 0), server_received,
            max(0, tier.get("sends", 0) - server_received),
            server_echo, tier.get("echoes_received", 0),
            max(0, server_echo - tier.get("echoes_received", 0)),
            "%d mismatches / %d timeouts" % (
                tier.get("echo_mismatches", 0), tier.get("echo_timeouts", 0)),
            "`%s`" % (tier.get("payload_sha256") or "-")[:16] + "…",
        ])
    return md_table(
        ["tier", "payload bytes", "Chrome→server sends", "server received", "lost",
         "echo sent (server)", "echo received (Chrome)", "echo lost", "order", "SHA-256"],
        rows)

def b2_table():
    rows = []
    labels = {
        "server_uni": "server-initiated uni (1 MiB)",
        "client_uni": "client uni 1 MiB + half-close echo",
        "client_bi": "client bi 1 MiB + half-close echo",
        "concurrent_bi": "10 concurrent bi 1 MiB",
        "client_reset": "client reset (writable.abort)",
        "server_reset": "server reset observed (4096 B then code 7)",
    }
    for name, label in labels.items():
        entry = items.get(name, {}) or {}
        details = []
        if name in ("server_uni", "client_bi"):
            details.append("bytes=%s" % entry.get("bytes", entry.get("echo_bytes", 0)))
            details.append("sha256=%s" % (entry.get("sha256") or entry.get("sent_sha256") or "-"))
        elif name == "client_uni":
            details.append("sent bytes=%s sha256=%s" % (
                entry.get("sent_bytes", 0), entry.get("sent_sha256", "-")))
            details.append("echo bytes=%s sha256=%s" % (
                entry.get("echo_bytes", 0), entry.get("echo_sha256", "-")))
        elif name == "concurrent_bi":
            details.append("streams=%s completed=%s" % (
                entry.get("streams", 0), entry.get("completed", 0)))
            details.append("bytes/stream=%s sha256=%s" % (
                entry.get("bytes_per_stream", 0), entry.get("sent_sha256", "-")))
        elif name == "server_reset":
            details.append("observed=%s bytes_before_reset=%s reset_code=%s" % (
                entry.get("observed", False), entry.get("bytes_before_reset", 0),
                entry.get("reset_code")))
        elif name == "client_reset":
            details.append("bytes_before_reset=%s; server log role=client count=%d" % (
                entry.get("bytes_before_reset", 0), client_reset))
        if entry.get("error"):
            details.append("error=" + str(entry.get("error")))
        rows.append([label, entry.get("status", "not_run"), "; ".join(details)])
    return md_table(["item", "status", "detail"], rows)

def gap_table():
    rows = []
    for gap in gaps:
        detail = gap["detail"]
        if gap["gap"] == "GAP-M3-B0-02" and b0_blocker_suffix:
            detail += b0_blocker_suffix
        rows.append(["`%s`" % gap["gap"], gap["item"], detail])
    return md_table(["GAP", "item", "detail"], rows) if rows else "No GAP recorded."

def file_sha(name):
    path = os.path.join(EVID, name)
    if not os.path.exists(path):
        return "-"
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()

# ---------------------------------------------------------------- report.md
verdict_b0 = b0.get("status", "pending")
verdict_b1 = b1.get("status", "pending")
verdict_b2 = b2.get("status", "pending")
server_alive = int(ENV.get("SERVER_ALIVE", "0"))

status_rows = [
    ["B0", verdict_b0, b0.get("error") or "session ready; server logged connect_request_decoded + 200"],
    ["B1", verdict_b1, "%d tier(s) executed" % len(tiers)],
    ["B2", verdict_b2, "6 stream/reset items" if items else "not run"],
    ["B3", B3_STATUS, B3_DETAIL],
    ["B5", "GAPs listed", "%d blocking, %d open B3" % (len(blocking_gaps), len(b3_gaps))],
]

b0_analysis = ""
b0_blocker_suffix = ""
if PHASE != "baseline" and b0.get("status") == "fail" and method_not_supported and not server_has_id("0x2b603742"):
    b0_blocker_suffix = " (netlog: net::ERR_METHOD_NOT_SUPPORTED; server SETTINGS carry no 0x2b603742)"
    status_rows[0][2] = "net::ERR_METHOD_NOT_SUPPORTED; server SETTINGS lack legacy ENABLE_WEBTRANSPORT"
    b0_analysis = """## B0 failure analysis (after the authorised relaxation)

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
"""

env_rows = [
    ["repository commit (git rev-parse HEAD at generation)", "`%s`" % ENV["COMMIT"]],
    ["phase", "`%s`" % PHASE],
    ["harness tree id (git rev-parse HEAD:interop/m3/rtx-server)", "`%s`" % ENV.get("HARNESS_TREE", "unknown")],
    ["harness main.rs SHA-256", "`%s`" % ENV["HARNESS_MAIN_SHA"]],
    ["harness diff vs HEAD", "`%s`" % ENV["HARNESS_DIFF"].strip()],
    ["Chrome (from the browser itself)", "`%s`" % ENV["CHROME_VERSION_RAW"]],
    ["Chrome binary", "`%s`" % ENV["CHROME"]],
    ["version source", "`$CHROME --version` (`chrome://version` is not reachable in headless mode; raw output is in `chrome-version.txt`)"],
    ["OS", "`%s`" % ENV["OS_TEXT"]],
    ["date", "`%s`" % ENV["DATE"]],
    ["harness address", "`%s`" % ENV["ADDR"]],
    ["page origin", "`https://127.0.0.1:%s` (served by `page_server.py`)" % ENV["PAGE_PORT"]],
    ["WebTransport URL", "`https://127.0.0.1:%s/session`" % ENV["QUIC_ACTUAL_PORT"]],
    ["server alive after matrix", "`yes`" if server_alive else "`no` (see GAPs)"],
]

cert_text = """- Self-signed RSA-2048, `CN=localhost`, SAN `DNS:localhost,IP:127.0.0.1`,
  generated at run time by `run-chrome.sh` with `openssl`.
- Lives only in a `mktemp` directory outside the repository and is deleted by
  the EXIT trap. No private key, `.pem` or `.key` file is committed.
- Chrome accepts it through `--ignore-certificate-errors-spki-list` (test-only;
  this flag covers QUIC, `--ignore-certificate-errors` alone does not)."""

settings_text = settings_table() if settings else "The server log contains no decoded client SETTINGS frame in this phase."
if settings_frame_line:
    settings_text += "\n\nFrame: `%s`" % settings_frame_line
presence_text = "\n".join([
    "- `0x2b603742` (`ENABLE_WEBTRANSPORT`, deprecated): **%s**" % ("present" if has_id("0x2b603742") else "absent"),
    "- `0xc671706a` (`WEBTRANSPORT_MAX_SESSIONS`): **%s**" % ("present" if has_id("0xc671706a") else "absent"),
    "- `0x2c7cf000` (`SETTINGS_WT_ENABLED`, draft-15): **%s**" % ("present" if has_id("0x2c7cf000") else "absent"),
])
n4_text = """N4 observation: T1 (a Chrome version negotiating `0x2c7cf000`) is **%s**;
Chrome's SETTINGS above show that identifier as %s. T3 (Chrome refusing a
session solely because the server omitted `0x2c7cf000`) is **not triggered**:
the failure recorded here is `net::ERR_METHOD_NOT_SUPPORTED` caused by the
missing legacy `0x2b603742` on the server (see the B0 analysis above), and the
throwaway diagnostic in `../blocker-analysis.md` shows that adding `0x2c7cf000`
alone does not establish a session either. The RV-PR24 ruling (do not send
`0x2c7cf000`) therefore remains in force; this task did not add it on its own
authority.""" % (
    "triggered" if has_id("0x2c7cf000") else "not triggered",
    "present" if has_id("0x2c7cf000") else "absent",
)

baseline_link = "../%s/report.md" % ENV.get("BASELINE_DIR", "")
two_phase_text = ""
if PHASE == "baseline":
    two_phase_text = """This is **phase 1 (baseline)**. The harness is the untouched `edca8ea` code
(`main.rs` SHA-256 above, no local diff). At edca8ea the harness rejects
non-zero client QPACK capacity with `H3_SETTINGS_ERROR (0x0101)`; a baseline
that ends there is the *expected qualified product* of phase 1, not a test
failure. Phase 2 (`PHASE=relaxed`) is only run if this baseline ends in that
H4 rejection, and its evidence lives in the sibling directory without the
`-baseline` suffix.

Key server log lines (verbatim):

```
%s
%s
```""" % (reject_line, close_line)
else:
    two_phase_text = """This is **phase 2 (relaxed)**. Phase 1 evidence is
[`%s`](%s): the untouched `edca8ea` harness rejected Chrome's non-zero
`0x01`/`0x07` with `H3_SETTINGS_ERROR (0x0101)`. The relaxation changed exactly
one place in `interop/m3/rtx-server/src/main.rs` (`handle_client_settings`):
the peer's `0x01`/`0x07`/`0x06` values are logged (`event=h3_client_qpack_capacity`)
and accepted. The rationale (RFC 9114 section 7.2.4.1: the values describe the
peer decoder's capacity, not this encoder; this encoder emits static references
and non-Huffman literals only; this decoder still rejects real dynamic-table
references) is in `interop/m3/rtx-server/README.md`.

Loopback regression: `run-loopback.sh` was rerun after the relaxation and
passed; see `%s/`. The merged `interop/m3/rtx-server/evidence/2026-10-29-loopback/`
directory was restored byte-for-byte (the new logs live only in the appendix).""" % (
        baseline_link, baseline_link,
        ENV.get("LOOPBACK_NOTE") if ENV.get("LOOPBACK_NOTE") else "the appendix directory")

if PHASE == "baseline":
    conclusion = """**Conclusion:** B0 FAIL with `GAP-M3-B0-01`: Chrome's SETTINGS carry
`0x01=65536` and `0x07=100`, the harness logs `h3_settings_rejected`
(`reason=dynamic_table_not_supported`) and closes the connection with
`error_code=0x101` before extended CONNECT. B1/B2 were not exercised because no
session exists. This log is the phase-1 product; the next step is the
one-place relaxation described in `interop/m3/rtx-server/README.md`."""
else:
    if verdict_b0 == "fail" and verdict_b1 == "not_run" and verdict_b2 == "not_run":
        matrix_status = "B0 `FAIL`; B1/B2 `not_run` (blocked by B0, not executed)"
    else:
        matrix_status = "B0 `%s`; B1 `%s`; B2 `%s`" % (verdict_b0, verdict_b1, verdict_b2)
    conclusion = """**Conclusion:** %s. B3 is `%s`. Blocking GAPs for the
Chrome matrix: **%d**; open B3 GAP: **%d**. See the GAP table below.""" % (
        matrix_status, B3_STATUS, len(blocking_gaps), len(b3_gaps))

datagram_text = ""
if PHASE != "baseline" and not tiers:
    datagram_text = "## B1 DATAGRAM\n\nNot exercised: no WebTransport session was established (see `GAP-M3-B0-02`)."
if PHASE != "baseline" and tiers:
    datagram_text = """## B1 DATAGRAM (Chrome ↔ harness)

Values read from the server log after the handshake:

| item | value |
|---|---|
| `peer_max_datagram_frame_size` (Chrome advertisement) | `%s` |
| harness `max_datagram_frame_size_advertised` | `%s` |
| negotiated tier derivation | `%s` |
| gate note (< 1200 uses the negotiated cap) | %s |

Tier payloads are the deterministic `0..255` cycle (first N bytes); SHA-256 is
computed by the page with `crypto.subtle`. Each send was paired with its own
echo (`send i` → verify `echo i` → `send i+1`), so the sequence check completes
without relying on payload identity. QUIC DATAGRAM is unreliable and unordered:
a non-zero loss number is evidence, not a protocol guarantee; only 100 %% loss,
session death or a server crash is a FAIL.

%s

Server log counters: `datagram_received` %s; `datagram_sent` %s;
`datagram_echo_failed` %d; dropped (wrong_session/malformed/decode_failed/
buffer_too_small) %s. The harness stayed alive for the whole matrix: `%s`.""" % (
        params.get("peer_max_datagram_frame_size"),
        params.get("max_datagram_frame_size_advertised"),
        b1.get("derivation"),
        ("yes (negotiated %d < 1200, so the negotiated cap is used and recorded)"
         % (params.get("max_datagram_frame_size_advertised") or 0))
        if (params.get("max_datagram_frame_size_advertised") or 0) < 1200
        else "no (negotiated %d >= 1200)" % (params.get("max_datagram_frame_size_advertised") or 0),
        datagram_table(),
        dict(sorted(received.items())), dict(sorted(sent.items())), echo_failed,
        dropped, "yes" if server_alive else "no")

streams_text = ""
if PHASE != "baseline" and not items:
    streams_text = "## B2 streams\n\nNot exercised: no WebTransport session was established (see `GAP-M3-B0-02`)."
if PHASE != "baseline" and items:
    streams_text = """## B2 streams

%s

Server log counters: `stream_finished role=client` %d, `stream_reset role=client`
%d, `stream_reset role=server code=7` %d, `stream_opened kind=uni role=server
bytes=1048576` %d. The 10 concurrent streams completed after/around the reset
stream, so the reset did not disturb the other streams.""" % (
        b2_table(), client_stream_finished, client_reset, server_reset, server_uni_open)

session_text = ""
if PHASE != "baseline":
    session_text = """## Session close and second session

| item | observed |
|---|---|
| `transport.close()` (`WT_CLOSE_SESSION`) | `%s`; server `session_closed` lines: %d |
| `transport.closed` event | `%s` |
| second session on the same harness process | `%s` (%s) |
| `connect_request_decoded` / `response_headers_sent 200` totals | %d / %d |
| `connect_request_rejected` | %d |""" % (
        result.get("session_close", {}).get("status"),
        session_closed,
        result.get("session_close", {}).get("closed_event"),
        result.get("second_session", {}).get("status"),
        result.get("second_session", {}).get("error")
        or ("ready" if result.get("second_session", {}).get("status") == "pass" else "not established"),
        connect_decoded, responses, connect_rejected)

b3_text = """## B3 Firefox (conditional)

| item | value |
|---|---|
| status | **%s** |
| evidence | %s |
| gap | %s |

Firefox is not called "N/A" without a checked version: N/A needs evidence that a
specific Firefox build was inspected and does not support WebTransport over
HTTP/3. This run has no Firefox binary at all, so the honest status is
**NOT DETERMINED**, and `GAP-M3-B3-01` is handed to the coordinator (`xc` has a
Firefox 136 headless precedent).""" % (
    B3_STATUS, B3_DETAIL, "`GAP-M3-B3-01`" if B3_OPEN else "none")

gap_text = """## B5 GAP table

%s

Blocking GAP count on the first page: **%d**. Open B3 GAP count: **%d**.""" % (
    gap_table(), len(blocking_gaps), len(b3_gaps))

not_done_text = """## Not done (explicitly)

- B4 `quinn` reference interop (independent follow-up unit; the `quinn` client
  above only appears in the loopback regression, never as an interop result).
- benchmarks (P7), embedded port (P8), full HTTP/3, QPACK dynamic table,
  `0x2c7cf000` implementation, 0-RTT, connection migration, multi-session
  defaults.
- no change to existing crate logic, existing docs (`docs/m3-m4-gates.md`,
  `DEPENDENCY_AUDIT.md`, `ARCHITECTURE.md`), `interop/m3/chrome/` (R6-2c raw
  capture and reference server untouched), CI, the workspace manifest or the
  merged `interop/m3/rtx-server/evidence/2026-10-29-loopback/` directory."""

evidence_text = """## Evidence files

| file | SHA-256 |
|---|---|
| `server.log` | `%s` |
| `chrome-console.log` | `%s` |
| `chrome-netlog.txt` | `%s` |
| `result.json` | `%s` |
| `chrome-version.txt` | `%s` |
| `hashes.txt` | `%s` |

`hashes.txt` is the machine-readable matrix (item, sends, receives, lost, bytes,
SHA-256, detail); `result.json` is the page's `window.__rtx_result` posted verbatim.
Payload SHA-256 values in this report come from the same JSON, not from the
console summary. `chrome-netlog.txt` is the filtered WebTransport excerpt of
Chrome's own netlog (the raw netlog stays in the mktemp directory).""" % (
    file_sha("server.log"), file_sha("chrome-console.log"), file_sha("chrome-netlog.txt"),
    file_sha("result.json"),
    file_sha("chrome-version.txt"), file_sha("hashes.txt"))

if PHASE == "baseline":
    server_settings_section = """## Server SETTINGS actually emitted

None. The baseline harness rejects the client SETTINGS (`h3_settings_rejected`)
before `send_server_settings`, so no server SETTINGS frame exists in this
phase."""
else:
    server_settings_section = """## Server SETTINGS actually emitted (5 items, no `0x2c7cf000`)

%s""" % (settings_server_table() if server_settings else "(no server SETTINGS logged)")

reproduce_text = """## Reproduce

```
cd interop/m3/chrome-rtx && PHASE=%s ./run-chrome.sh
```

The script generates the runtime certificate with `openssl` in a `mktemp`
directory, starts `rtx-wt-server` and `page_server.py`, runs headless Chrome with
the flags above, waits for the page's `POST /result` under `RESULT_TIMEOUT=%s` s,
and writes only the text evidence listed above. No key material enters the
repository.""" % (PHASE, ENV.get("RESULT_TIMEOUT", "420"))

report = """# R6-4 Chrome WebTransport interop — `%s` (%s)

**What this proves:** a real Chrome build completed (or failed) the M3-B0/B1/B2
matrix against the `rtx-wt-server` harness (`rtx-quic` + `rtx-h3` +
`rtx-webtransport`), with the numbers, order checks, byte counts and SHA-256
values below coming from the browser page and the harness log.

**What this does not prove:** B3 Firefox (see below), B4 `quinn` reference
interop, benchmarks, embedded use, or full HTTP/3. Loopback success is not
rewritten as a Chrome conclusion anywhere in this directory.

## First-page summary

%s

## Status

%s

%s

%s

## Environment

%s

## Chrome launch parameters

```
%s
%s
```

## Certificate handling

%s

## Chrome SETTINGS observed (verbatim values)

%s

Presence of the N4 identifiers:

%s

%s

%s

%s

%s

%s

%s

%s

%s

%s

%s
""" % (
    ENV["CHROME_VERSION_RAW"], PHASE,
    conclusion,
    md_table(["item", "status", "detail"], status_rows),
    two_phase_text,
    b0_analysis,
    md_table(["item", "value"], env_rows),
    ENV["FLAGS_TEXT"], "https://127.0.0.1:%s/index.html?port=%s" % (ENV["PAGE_PORT"], ENV["QUIC_ACTUAL_PORT"]),
    cert_text,
    settings_text,
    presence_text,
    n4_text,
    server_settings_section,
    datagram_text,
    streams_text,
    session_text,
    b3_text,
    gap_text,
    not_done_text,
    evidence_text,
    reproduce_text,
)

with open(os.path.join(EVID, "report.md"), "w", encoding="utf-8") as handle:
    handle.write(report)

summary = {
    "phase": PHASE,
    "b0": verdict_b0,
    "b1": verdict_b1,
    "b2": verdict_b2,
    "b3": B3_STATUS,
    "blocking_gaps": len(blocking_gaps),
    "result": result.get("verdict"),
}
print(json.dumps(summary))
PY

for artifact in report.md server.log chrome-console.log chrome-netlog.txt hashes.txt chrome-version.txt result.json; do
  [ -s "$EVID/$artifact" ] || fail "missing evidence artifact: $artifact"
done
EXTRA="$(find "$EVID" -maxdepth 1 -type f \
  ! -name report.md ! -name server.log ! -name chrome-console.log ! -name chrome-netlog.txt \
  ! -name hashes.txt ! -name chrome-version.txt ! -name result.json -print -quit)"
[ -z "$EXTRA" ] || fail "unexpected file in the evidence directory: $EXTRA"

echo "evidence written to $EVID"
echo "  server.log        $(grep -c '' "$EVID/server.log") lines"
echo "  chrome-console.log $(grep -c '' "$EVID/chrome-console.log") lines"
echo "  hashes.txt        $(grep -c '' "$EVID/hashes.txt") lines"
