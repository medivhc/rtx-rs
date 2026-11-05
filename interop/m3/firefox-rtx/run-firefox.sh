#!/usr/bin/env bash
# M3-B3 Firefox WebTransport interop runner (B0/B1/B2 matrix, Firefox edition).
#
# Firefox does not speak CDP and the Playwright cache in this environment only
# has Chromium, so the browser is driven through Gecko's built-in Marionette
# protocol (see marionette_drive.py): system /usr/bin/firefox, headless, no
# geckodriver, no downloads.
#
# Order: runtime self-signed ECDSA P-256 cert -> certutil trust import into a
# temporary profile (page origin) -> rtx-wt-server -> HTTPS page server ->
# headless Firefox (Marionette) -> test page pins the WT endpoint with
# serverCertificateHashes and posts `window.__rtx_result` back to the page
# server -> evidence/report.
#
# The harness (interop/m3/rtx-server) is used exactly as it is at HEAD,
# including the merged client-QPACK relaxation and the Chrome-compat legacy
# ENABLE_WEBTRANSPORT pair from PR #29; this script never edits it.
#
# Run from anywhere:  ./interop/m3/firefox-rtx/run-firefox.sh
# Optional env:       FIREFOX_BIN=... QUIC_PORT=0 PAGE_PORT=<auto>
#                     MARIONETTE_PORT=<auto> RESULT_TIMEOUT=120 KEEP_WORK=1
#                     (QUIC_PORT=0 and the auto defaults pick free ports, so
#                     the run is safe on hosts with unrelated services)
#
# Private key material only ever exists in a mktemp directory created here and
# removed by the EXIT trap; nothing key-like is written into the repository.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
RESULT_TIMEOUT="${RESULT_TIMEOUT:-120}"
DATE="$(date +%F)"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

# Shared-host safety: pick free ephemeral ports at runtime instead of fixed
# defaults (this machine runs unrelated long-lived services, and another
# Firefox instance may already hold Marionette's default 2828).
pick_free_port() {
  python3 - <<'PY'
import socket
handle = socket.socket()
handle.bind(("127.0.0.1", 0))
print(handle.getsockname()[1])
handle.close()
PY
}

QUIC_PORT="${QUIC_PORT:-0}"   # 0 = let the harness pick; actual port parsed from its log
PAGE_PORT="${PAGE_PORT:-$(pick_free_port)}"
MARIONETTE_PORT="${MARIONETTE_PORT:-$(pick_free_port)}"

# ---------------------------------------------------------------- 0. browser
FIREFOX=""
if [ -n "${FIREFOX_BIN:-}" ]; then
  FIREFOX="$FIREFOX_BIN"
else
  for cand in firefox /usr/lib/firefox/firefox /snap/bin/firefox; do
    if command -v "$cand" >/dev/null 2>&1; then
      FIREFOX="$(command -v "$cand")"
      break
    fi
  done
fi
[ -n "$FIREFOX" ] && [ -x "$FIREFOX" ] \
  || fail "no runnable Firefox found (set FIREFOX_BIN); M3-B3 cannot run"
command -v python3 >/dev/null 2>&1 \
  || fail "python3 is required for the local HTTPS page server and the Marionette driver"
command -v openssl >/dev/null 2>&1 \
  || fail "openssl is required to generate the runtime self-signed certificate"
command -v certutil >/dev/null 2>&1 \
  || fail "certutil (libnss3-tools) is required to import the test certificate into the Firefox profile"
command -v cargo >/dev/null 2>&1 \
  || fail "cargo is required to build the rtx-wt-server harness"

FIREFOX_VERSION_RAW="$("$FIREFOX" --version 2>&1 | head -n1 | sed -e 's/[[:space:]]*$//')"
VERSION="$(printf '%s\n' "$FIREFOX_VERSION_RAW" | grep -oE '[0-9]+(\.[0-9]+)+' | head -n1 || true)"
[ -n "$VERSION" ] || fail "cannot parse Firefox version from: $FIREFOX_VERSION_RAW"
VERSION_MAJOR="${VERSION%%.*}"

HARNESS_MAIN="$REPO/interop/m3/rtx-server/src/main.rs"
HARNESS_README="$REPO/interop/m3/rtx-server/README.md"
HARNESS_MAIN_SHA="$(sha256sum "$HARNESS_MAIN" | cut -d' ' -f1)"
PAGE_SHA="$(sha256sum "$HERE/index.html" | cut -d' ' -f1)"
PAGE_SERVER_SHA="$(sha256sum "$HERE/page_server.py" | cut -d' ' -f1)"

EVID="$HERE/$DATE-firefox-$VERSION_MAJOR"
mkdir -p "$EVID"
rm -f "$EVID/result.json" "$EVID/report.md" "$EVID/server.log" \
      "$EVID/firefox-version.txt" "$EVID/firefox-prefs.json" \
      "$EVID/firefox-page-status.txt" "$EVID/firefox.log" "$EVID/hashes.txt"

WORK="$(mktemp -d)"
STAGE="$(mktemp -d)"
SERVER_PID=""
PAGE_PID=""
FIREFOX_PID=""
cleanup() {
  for pid in "$FIREFOX_PID" "$PAGE_PID" "$SERVER_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  for pid in "$FIREFOX_PID" "$PAGE_PID" "$SERVER_PID"; do
    [ -n "$pid" ] && wait "$pid" 2>/dev/null || true
  done
  if [ "${KEEP_WORK:-0}" = "1" ]; then
    echo "KEEP_WORK=1: logs, profile and certificate kept in $WORK (staging $STAGE)" >&2
    return
  fi
  rm -rf "$WORK" "$STAGE"
}
trap cleanup EXIT

# ------------------------------------- 1. runtime self-signed test certificate
# Cert shape is dictated by two independent Firefox validators:
#   * mozilla::pkix (HTTPS page origin, anchor imported into the profile):
#     a CA:TRUE cert used as the server end-entity is rejected with
#     MOZILLA_PKIX_ERROR_CA_CERT_USED_AS_END_ENTITY even when that same cert
#     is the imported trust anchor, so the anchor must be CA:FALSE. Also,
#     openssl 1.1.1 `req -x509` always injects `basicConstraints=critical,
#     CA:TRUE` from its config and `-addext` only appends, which yields
#     duplicate basicConstraints (SEC_ERROR_EXTENSION_VALUE_INVALID).
#     Building the cert via CSR + `x509 -req -signkey -extfile` emits exactly
#     the extensions listed in leaf.ext and nothing else.
#   * W3C WebTransport serverCertificateHashes (the WT endpoint; see §6):
#     Firefox enforces that a *dedicated* WebTransport session must not rely
#     on a user-added trust anchor unless serverCertificateHashes matches,
#     and per spec such a pinned cert must be self-signed, valid < 2 weeks,
#     and use ECDSA secp256r1 (P-256) -- RSA keys are rejected. Hence ECDSA
#     here and a 1-day validity.
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/key.pem" >/dev/null 2>&1 \
  || fail "openssl ECDSA key generation failed"
openssl req -new -key "$WORK/key.pem" \
  -subj "/CN=localhost" \
  -out "$WORK/cert.csr" >/dev/null 2>&1 \
  || fail "openssl CSR generation failed"
cat >"$WORK/leaf.ext" <<'LEAFEXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
LEAFEXT
openssl x509 -req -in "$WORK/cert.csr" -signkey "$WORK/key.pem" \
  -days 1 -sha256 -extfile "$WORK/leaf.ext" -out "$WORK/cert.pem" >/dev/null 2>&1 \
  || fail "openssl certificate signing failed"
openssl x509 -in "$WORK/cert.pem" -outform DER -out "$WORK/cert.der" >/dev/null 2>&1 \
  || fail "certificate PEM -> DER conversion failed"
openssl pkcs8 -topk8 -nocrypt -in "$WORK/key.pem" -outform DER -out "$WORK/key.der" >/dev/null 2>&1 \
  || fail "private key PKCS#8 conversion failed"
# SHA-256 (base64url, unpadded) over exactly the DER the harness presents; the
# test page passes it as WebTransport serverCertificateHashes (§6 URL).
CERT_HASH="$(openssl dgst -sha256 -binary "$WORK/cert.der" | base64 -w0 | tr '+/' '-_' | tr -d '=')"
[ -n "$CERT_HASH" ] || fail "cannot compute the certificate hash"

# ------------------------- 2. Firefox profile with the test cert as trust anchor
# Firefox has no `--ignore-certificate-errors-spki-list` equivalent, so the
# runtime certificate is imported into the temporary profile's cert9.db as a
# trust anchor with certutil (the same mechanism web-platform-tests uses for
# Firefox). The anchor covers the HTTPS page origin; the WebTransport endpoint
# presents the same cert but Firefox authenticates it via
# serverCertificateHashes instead (dedicated WT sessions must not rely on
# user-added anchors), see §1 and §6.
PROFILE="$WORK/firefox-profile"
mkdir -p "$PROFILE"
# NOTE: user.js requires the `user_pref(...)` form; plain `pref(...)` lines are
# a parse error at startup and the whole file is silently ignored.
{
  printf 'user_pref("marionette.port", %s);\n' "$MARIONETTE_PORT"
  cat <<'USERJS'
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("datareporting.policy.firstRunURL", "");
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);
USERJS
} >"$PROFILE/user.js"
printf '\n' >"$WORK/nss-pwfile"
certutil -N -d "sql:$PROFILE" -f "$WORK/nss-pwfile" >/dev/null 2>&1 \
  || fail "certutil could not initialize the profile NSS database"
certutil -A -d "sql:$PROFILE" -n "rtx-m3-wt-test" -t "CT,," \
  -i "$WORK/cert.pem" -f "$WORK/nss-pwfile" >/dev/null 2>&1 \
  || fail "certutil could not import the runtime certificate into the profile"

# ------------------------------------------------------- 3. build the harness
echo "building rtx-wt-server (standalone crate, not a workspace member)"
cargo build --release --locked --manifest-path "$REPO/interop/m3/rtx-server/Cargo.toml" \
  >"$WORK/build.log" 2>&1 \
  || { tail -n 30 "$WORK/build.log" >&2; fail "rtx-wt-server build failed"; }
# Honor a CARGO_TARGET_DIR override (this container sets one); default is the
# crate-local target directory, same as the Chrome runner assumes.
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO/interop/m3/rtx-server/target}"
SERVER_BIN="$TARGET_DIR/release/rtx-wt-server"
[ -x "$SERVER_BIN" ] || fail "rtx-wt-server binary missing after build ($SERVER_BIN)"

# ------------------------------------------------- 4. start the page server
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

# ------------------------------------------------------- 5. start the harness
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

# ------------------------------------------- 6. headless Firefox via Marionette
mkdir -p "$WORK/home"
# No b0gap parameter: the first revision of this runner invented an
# unregistered "GAP-M3-B0-03" for the Firefox lineage. GAP ids are registered
# in docs/m3-m4-gates.md §5 by the coordinator, never fabricated by a runner;
# a Firefox B0 failure is recorded with gap=null (see index.html / report).
# certhash: Firefox authenticates the dedicated WT connection with
# serverCertificateHashes (user-added anchors are rejected for dedicated WT
# sessions without it); the page turns this into the constructor option.
FIREFOX_URL="https://127.0.0.1:$PAGE_PORT/index.html?port=$QUIC_ACTUAL_PORT&phase=relaxed&browser=firefox&certhash=$CERT_HASH"
printf '%s\n' \
  "$FIREFOX --headless --marionette --no-remote -profile $PROFILE" \
  "(marionette.port=$MARIONETTE_PORT; Marionette drives WebDriver:Navigate to:)" \
  "$FIREFOX_URL" >"$WORK/flags.txt"
HOME="$WORK/home" "$FIREFOX" --headless --marionette --no-remote -profile "$PROFILE" \
  >"$WORK/firefox.log" 2>&1 &
FIREFOX_PID=$!

DRIVER_RC=0
python3 "$HERE/marionette_drive.py" \
  --port "$MARIONETTE_PORT" \
  --url "$FIREFOX_URL" \
  --result "$STAGE/result.json" \
  --prefs "$STAGE/firefox-prefs.json" \
  --page-status "$STAGE/firefox-page-status.txt" \
  --expect-profile "$PROFILE" \
  --firefox-pid "$FIREFOX_PID" \
  --timeout "$RESULT_TIMEOUT" >"$WORK/driver.log" 2>&1 || DRIVER_RC=$?
cat "$WORK/driver.log" >&2
if [ "$DRIVER_RC" -ne 0 ]; then
  echo "--- firefox.log tail (driver rc=$DRIVER_RC) ---" >&2
  tail -n 30 "$WORK/firefox.log" >&2 || true
  echo "--- end firefox.log tail ---" >&2
fi

# The harness must still be alive after the matrix (B1/B2 requirement: it does
# not crash). Record that before stopping it.
SERVER_ALIVE=0
kill -0 "$SERVER_PID" 2>/dev/null && SERVER_ALIVE=1
SERVER_RC=0
if [ "$SERVER_ALIVE" -eq 0 ]; then
  wait "$SERVER_PID" 2>/dev/null && SERVER_RC=0 || SERVER_RC=$?
fi
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

if [ ! -s "$STAGE/result.json" ]; then
  # Driver/browser failure: recorded as what it is (a harness-side driver
  # failure), not as a gate GAP and not with a fabricated GAP id.
  RESULT_REASON="driver failure: no page result posted within ${RESULT_TIMEOUT}s (driver rc=$DRIVER_RC)"
  python3 - "$STAGE/result.json" "$RESULT_REASON" "$SERVER_ALIVE" <<'PY'
import json, sys
path, reason, alive = sys.argv[1], sys.argv[2], int(sys.argv[3])
stub = {
    "phase": "relaxed",
    "browser": "firefox",
    "stub": True,
    "driver_failure": reason,
    "b0": {"status": "fail", "error": reason, "ready_ms": None},
    "b1": {"status": "not_run", "tiers": [], "params": None, "derivation": None},
    "b2": {"status": "not_run", "items": {}, "uni_streams": [], "bi_streams": []},
    "session_close": {"status": "not_run", "error": None, "closed_event": None},
    "second_session": {"status": "not_run", "error": None},
    "failures": [],
    "server_alive": bool(alive),
    "verdict": "fail",
    "finished": True
}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(stub, handle, indent=2)
PY
fi

# ---------------------------------------------------------- 7. stop everything
if [ -n "$FIREFOX_PID" ]; then
  kill "$FIREFOX_PID" 2>/dev/null || true
  wait "$FIREFOX_PID" 2>/dev/null || true
  FIREFOX_PID=""
fi
kill "$PAGE_PID" 2>/dev/null || true
wait "$PAGE_PID" 2>/dev/null || true
PAGE_PID=""

[ -s "$STAGE/server.log" ] || fail "the harness produced no server.log (no report is produced)"
cp "$STAGE/server.log" "$EVID/server.log"
cp "$STAGE/result.json" "$EVID/result.json"
{
  printf '%s\n' "\$ $FIREFOX --version"
  printf '%s\n' "$FIREFOX_VERSION_RAW"
  printf '%s\n' "" "\$ /usr/lib/firefox/application.ini (excerpt)"
  grep -E '^(Version|BuildID|SourceRepository|SourceStamp)=' /usr/lib/firefox/application.ini 2>/dev/null \
    || sed -n '/^\[App\]/,/^\[/p' "$(dirname "$(readlink -f "$FIREFOX")")/application.ini" 2>/dev/null \
    || echo "(application.ini not readable)"
} >"$EVID/firefox-version.txt"
[ -s "$STAGE/firefox-prefs.json" ] \
  && cp "$STAGE/firefox-prefs.json" "$EVID/firefox-prefs.json" \
  || printf '%s\n' "marionette driver produced no prefs/probe JSON (rc=$DRIVER_RC)" >"$EVID/firefox-prefs.json"
[ -s "$STAGE/firefox-page-status.txt" ] \
  && cp "$STAGE/firefox-page-status.txt" "$EVID/firefox-page-status.txt" \
  || printf '%s\n' "no page #status text captured" >"$EVID/firefox-page-status.txt"
cp "$WORK/firefox.log" "$EVID/firefox.log" 2>/dev/null \
  || printf '%s\n' "no firefox stdout captured" >"$EVID/firefox.log"

# ------------------------------------------- 8. hashes.txt + report.md (python)
COMMIT="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)"
HARNESS_TREE="$(git -C "$REPO" rev-parse HEAD:interop/m3/rtx-server 2>/dev/null || echo unknown)"
HARNESS_DIFF="$(git -C "$REPO" diff --stat -- "$HARNESS_MAIN" "$HARNESS_README" 2>/dev/null | tr '\n' ' ' || true)"
[ -n "$HARNESS_DIFF" ] || HARNESS_DIFF="none (harness identical to HEAD)"
OS_TEXT="$( (uname -srm; grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"') | paste -sd' ' -)"
FLAGS_TEXT="$(cat "$WORK/flags.txt")"

COMMIT="$COMMIT" FIREFOX_VERSION_RAW="$FIREFOX_VERSION_RAW" FIREFOX="$FIREFOX" \
OS_TEXT="$OS_TEXT" ADDR="$ADDR" PAGE_PORT="$PAGE_PORT" \
QUIC_ACTUAL_PORT="$QUIC_ACTUAL_PORT" FLAGS_TEXT="$FLAGS_TEXT" DATE="$DATE" \
HARNESS_MAIN_SHA="$HARNESS_MAIN_SHA" HARNESS_TREE="$HARNESS_TREE" \
HARNESS_DIFF="$HARNESS_DIFF" SERVER_ALIVE="$SERVER_ALIVE" SERVER_RC="$SERVER_RC" \
PAGE_SHA="$PAGE_SHA" PAGE_SERVER_SHA="$PAGE_SERVER_SHA" \
MARIONETTE_PORT="$MARIONETTE_PORT" RESULT_TIMEOUT="$RESULT_TIMEOUT" \
CERT_HASH="$CERT_HASH" \
python3 "$HERE/make_report.py" "$EVID"

for artifact in report.md server.log firefox-version.txt firefox-prefs.json \
                firefox-page-status.txt firefox.log hashes.txt result.json; do
  [ -s "$EVID/$artifact" ] || fail "missing evidence artifact: $artifact"
done
EXTRA="$(find "$EVID" -maxdepth 1 -type f \
  ! -name report.md ! -name server.log ! -name firefox-version.txt \
  ! -name firefox-prefs.json ! -name firefox-page-status.txt \
  ! -name firefox.log ! -name hashes.txt ! -name result.json -print -quit)"
[ -z "$EXTRA" ] || fail "unexpected file in the evidence directory: $EXTRA"

echo "evidence written to $EVID"
echo "  server.log             $(grep -c '' "$EVID/server.log") lines"
echo "  firefox-page-status.txt $(grep -c '' "$EVID/firefox-page-status.txt") lines"
echo "  hashes.txt             $(grep -c '' "$EVID/hashes.txt") lines"
