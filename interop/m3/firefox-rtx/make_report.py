"""M3-B3 evidence generator: hashes.txt + report.md for the Firefox run.

Reads the artifacts `run-firefox.sh` staged into the evidence directory
(result.json from the page, server.log from the harness, firefox-prefs.json
from the Marionette driver) plus environment facts exported by the runner, and
writes the B3 report in the same section format as the Chrome B0-B2 reports
(interop/m3/chrome-rtx/2026-11-02-chrome-155.0.8059.39/report.md), with the
B3 verdict section required by docs/m3-m4-gates.md M3-B3:

  * supported + matrix pass  -> B3 PASS with the full B0/B1/B2 numbers;
  * supported + matrix fail  -> B3 FAIL, every failure carries a GAP id
                                (gate: "支持但失败按 B1/B2 处理");
  * not supported            -> B3 N/A with Firefox version, platform,
                                pref/switch state and the methods checked.

This script never decides the verdict on its own: every claim below is derived
from the recorded JSON/log facts.
"""

import hashlib
import json
import os
import re
import sys

EVID = sys.argv[1]
ENV = os.environ


def load(name, default):
    path = os.path.join(EVID, name)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


result = load("result.json", {})
prefs = load("firefox-prefs.json", {})
cert_hash = result.get("server_certificate_hash") or ENV.get("CERT_HASH") or "-"
with open(os.path.join(EVID, "server.log"), "r", encoding="utf-8") as handle:
    log_lines = handle.read().splitlines()

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
            settings.append({"id": match.group(1), "value": int(match.group(2)),
                             "class": match.group(3)})
        elif "event=" in line:
            break

server_settings = []
for line in log_lines:
    match = re.search(r"event=server_setting .*id=(0x[0-9a-f]+) value=([0-9]+)", line)
    if match:
        pair = (match.group(1), int(match.group(2)))
        if pair not in server_settings:
            server_settings.append(pair)

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
responses_200 = count(r"event=response_headers_sent .*status=200")
settings_rejected = count(r"event=h3_settings_rejected")
session_closed = count(r"event=session_closed")
client_stream_finished = count(r"event=stream_finished .*role=client")
client_reset = count(r"event=stream_reset .*role=client")
server_reset = count(r"event=stream_reset .*role=server .*code=7")
server_uni_open = count(r"event=stream_opened .*kind=uni role=server .*bytes=1048576")
handshake_complete = count(r"event=quic_handshake_complete")
handshake_failed_lines = [line for line in log_lines if "event=quic_handshake_failed" in line]

# ------------------------------------------------------------ capability probe
caps = prefs.get("capabilities") or {}
chrome_probe = prefs.get("pref_probe_chrome_context") or {}
content_probe = prefs.get("content_probe") or {}
requested_prefs = chrome_probe.get("requested") or {}
child_values = chrome_probe.get("child_values") or {}
pref_children = chrome_probe.get("pref_children") or {}
api_chrome = (chrome_probe.get("api_in_chrome_context") or {})
page_href = str(content_probe.get("href") or "")
page_loaded = page_href.startswith("https://") and "neterror" not in page_href.lower()
api_in_content = content_probe.get("WebTransport") == "function"
secure_context = content_probe.get("isSecureContext") is True
driver_error = prefs.get("driver_error")

wt_children = pref_children.get("network.webtransport") or []
wt_switch_text = ("; ".join("`%s`=%s" % (name, json.dumps(child_values.get(name)))
                           for name in wt_children)
                  if isinstance(wt_children, list) and wt_children else "(none)")
dom_wt_value = requested_prefs.get("dom.webtransport.enabled", "not probed")
http3_value = requested_prefs.get("network.http.http3.enable", "not probed")
typeof_wt_content = content_probe.get("WebTransport", "not probed")
typeof_wt_chrome = api_chrome.get("WebTransport", "not probed")

# "absent" is only ever declared from a positive probe result, never from a
# driver crash or a page that did not load: a blocked run is "undetermined"
# (reported as a failed run, not as N/A).
if api_in_content and secure_context:
    capability = "supported"
    capability_detail = (
        "`typeof WebTransport === \"function\"` in the content context of the "
        "secure HTTPS page (`isSecureContext=true`) and in chrome context. "
        "Measured pref state: `dom.webtransport.enabled`=%s "
        "(`dom.webtransport.*` children=%s), `network.http.http3.enable`=%s, "
        "%s."
        % (json.dumps(dom_wt_value),
           json.dumps(pref_children.get("dom.webtransport")),
           json.dumps(http3_value), wt_switch_text)
    )
elif content_probe and page_loaded and not api_in_content and secure_context:
    capability = "absent"
    capability_detail = (
        "the secure page loaded but `typeof WebTransport === \"%s\"` in the "
        "content context (chrome-context value: `%s`); measured pref state: "
        "`dom.webtransport.enabled`=%s, `network.http.http3.enable`=%s, %s."
        % (typeof_wt_content, typeof_wt_chrome, json.dumps(dom_wt_value),
           json.dumps(http3_value), wt_switch_text)
    )
elif not content_probe and api_chrome.get("WebTransport") not in ("function", None):
    capability = "absent"
    capability_detail = (
        "no WebTransport interface in chrome context (`typeof WebTransport === "
        "\"%s\"`); the content probe did not run (%s)."
        % (api_chrome.get("WebTransport"), driver_error or "driver stopped early")
    )
elif api_chrome.get("WebTransport") == "function":
    capability = "supported_run_blocked"
    capability_detail = (
        "`typeof WebTransport === \"function\"` in chrome context, but the "
        "matrix never ran in the content context (href=`%s`, driver_error=`%s`)."
        % (page_href or "n/a", driver_error or "none recorded")
    )
else:
    capability = "undetermined"
    capability_detail = (
        "no usable probe result (content_probe=%s, chrome api=%s, driver_error=%s); "
        "capability cannot be concluded from this run."
        % (bool(content_probe), api_chrome.get("WebTransport"), driver_error)
    )

b0 = result.get("b0", {}) or {}
b1 = result.get("b1", {}) or {}
b2 = result.get("b2", {}) or {}
tiers = b1.get("tiers", []) or []
items = b2.get("items", {}) or {}
params = b1.get("params") or {}
failures = result.get("failures", []) or []
driver_failure = result.get("driver_failure")
server_alive = int(ENV.get("SERVER_ALIVE", "0"))


def b0_detail():
    """One-line B0 explanation for the status table and the summary."""
    if b0.get("status") == "pass":
        return ("ready %s ms; extended CONNECT 200; server observed the session"
                % b0.get("ready_ms"))
    if b0.get("status") == "unsupported":
        return ("WebTransport not exposed in this build (content `typeof "
                "WebTransport`=%s, `isSecureContext`=%s); matrix not run; "
                "gate M3-B3 conditional N/A"
                % (typeof_wt_content,
                   json.dumps(content_probe.get("isSecureContext"))))
    return b0.get("error") or driver_failure or "not run"


not_run_reason = (b0.get("error")
                  or driver_failure
                  or ("WebTransport not exposed in this build (M3-B3 "
                      "conditional N/A; the matrix was not attempted)"
                      if b0.get("status") == "unsupported" else None)
                  or "no session")

matrix_pass = (
    capability == "supported"
    and b0.get("status") == "pass"
    and b1.get("status") == "pass"
    and b2.get("status") == "pass"
    and not failures
    and result.get("verdict") == "pass"
)
if matrix_pass:
    b3_verdict = "PASS"
    b3_basis = (
        "Firefox %s exposes WebTransport over HTTP/3 — measured: "
        "`typeof WebTransport`=`function` in the secure page content context "
        "(`isSecureContext=true`) and in chrome context — and completed the "
        "full B0/B1/B2 matrix against the harness: B0 ready in %s ms, B1 %d "
        "tier(s), B2 %d stream/reset item(s), 0 failures, server alive after "
        "the matrix: %s."
        % (ENV["FIREFOX_VERSION_RAW"], b0.get("ready_ms"), len(tiers),
           len(items), "yes" if server_alive else "no")
    )
elif capability == "absent":
    b3_verdict = "N/A"
    b3_basis = (
        "Firefox %s on %s does not expose WebTransport. Measured on "
        "`https://127.0.0.1:%s/index.html` (Marionette content context): "
        "`typeof WebTransport`=`%s`, `typeof WebTransportDatagramDuplexStream`"
        "=`%s`, `typeof WebTransportError`=`%s`, `isSecureContext`=%s. "
        "Measured in chrome context (`Services.prefs`): "
        "`dom.webtransport.enabled`=%s, `network.http.http3.enable`=%s, "
        "`dom.webtransport.*` children=%s, `network.webtransport.*` switches: "
        "%s. N/A per gate M3-B3 with this report as the basis."
        % (ENV["FIREFOX_VERSION_RAW"], ENV["OS_TEXT"], ENV["PAGE_PORT"],
           typeof_wt_content,
           content_probe.get("WebTransportDatagramDuplexStream", "not probed"),
           content_probe.get("WebTransportError", "not probed"),
           json.dumps(content_probe.get("isSecureContext", "not probed")),
           json.dumps(dom_wt_value), json.dumps(http3_value),
           json.dumps(pref_children.get("dom.webtransport")), wt_switch_text)
    )
else:
    b3_verdict = "FAIL"
    b3_basis = (
        "capability probe: `%s` (%s). Matrix result: b0=%s b1=%s b2=%s, %d "
        "failure(s). Gate M3-B3 treats supported-but-failed per B1/B2; a "
        "blocked/undetermined run is reported as a failed run, never as N/A. "
        "Firefox-lineage failures carry no fabricated GAP id — registering "
        "one belongs to the coordinator (gate §4/§5)."
        % (capability, capability_detail, b0.get("status"),
           b1.get("status"), b2.get("status"), len(failures))
    )

# ---------------------------------------------------------------- hashes.txt
hash_rows = []


def add_row(item, sends, receives, lost, total_bytes, sha, detail):
    hash_rows.append((item, str(sends), str(receives), str(lost), str(total_bytes),
                      sha or "-", detail))


if b0.get("status") == "pass":
    add_row("b0_session", 1, 1, 0, 0, "-",
            "extended CONNECT; ready + server connect_request_decoded/200")
elif b0.get("status") == "unsupported":
    add_row("b0_session", 0, 0, 0, 0, "-",
            "WebTransport not exposed (content typeof=%s); matrix not run; %s"
            % (typeof_wt_content, b3_verdict))
else:
    # A page-attempted B0 counts one attempted session; a driver-level stub
    # (the page never ran) attempted none — no fabricated numbers.
    attempted = 0 if result.get("stub") else 1
    add_row("b0_session", attempted, 0, attempted, 0, "-",
            (b0.get("error") or driver_failure or "no session") + "; " + b3_verdict)

for tier in tiers:
    size = tier.get("payload_bytes", 0)
    server_received = received.get(size, 0)
    server_echo = sent.get(size + 1, 0)
    add_row("datagram_firefox_to_server_tier_" + tier.get("label", "?").replace(" ", "_"),
            tier.get("sends", 0), server_received,
            max(0, tier.get("sends", 0) - server_received),
            tier.get("sends", 0) * size, tier.get("payload_sha256", "-"),
            "server.log datagram_received bytes=%d; %s" % (size, tier.get("sequence", "")))
    add_row("datagram_server_echo_tier_" + tier.get("label", "?").replace(" ", "_"),
            server_echo, tier.get("echoes_received", 0),
            max(0, server_echo - tier.get("echoes_received", 0)),
            tier.get("echoes_received", 0) * size, tier.get("payload_sha256", "-"),
            "server.log datagram_sent bytes=%d (wire incl. quarter stream ID); page echoes_received=%d"
            % (size + 1, tier.get("echoes_received", 0)))

for name in ("server_uni", "client_uni", "client_bi", "concurrent_bi", "client_reset", "server_reset"):
    entry = items.get(name, {}) or {}
    if not entry:
        continue
    if name == "concurrent_bi":
        streams = entry.get("streams", 10)
        add_row(name, streams, entry.get("completed", 0),
                max(0, streams - entry.get("completed", 0)),
                entry.get("bytes_per_stream", 0) * streams,
                entry.get("sent_sha256", "-"), entry.get("status", "?"))
    elif name == "server_uni":
        add_row(name, 1, 1 if entry.get("status") == "pass" else 0,
                0 if entry.get("status") == "pass" else 1,
                entry.get("bytes", 0), entry.get("sha256", "-"), entry.get("status", "?"))
    elif name in ("client_uni", "client_bi"):
        add_row(name, 1, 1 if entry.get("status") == "pass" else 0,
                0 if entry.get("status") == "pass" else 1,
                entry.get("sent_bytes", 0), entry.get("sent_sha256", "-"),
                entry.get("status", "?"))
    elif name == "client_reset":
        add_row(name, 1, 1 if entry.get("status") == "reset_sent" else 0,
                0 if entry.get("status") == "reset_sent" else 1,
                entry.get("bytes_before_reset", 0), "-",
                "server log stream_reset role=client count=%d" % client_reset)
    elif name == "server_reset":
        add_row(name, 1, 1 if entry.get("observed") else 0,
                0 if entry.get("observed") else 1,
                entry.get("bytes_before_reset", 0), "-",
                "reset_code=%s; server log server_reset count=%d"
                % (entry.get("reset_code"), server_reset))

with open(os.path.join(EVID, "hashes.txt"), "w", encoding="utf-8") as handle:
    handle.write("# item\tsends\treceives\tlost\tbytes\tsha256\tdetail\n")
    for row in hash_rows:
        handle.write("\t".join(row) + "\n")

# ---------------------------------------------------------------- report parts
def md_table(header, rows):
    out = ["| " + " | ".join(header) + " |",
           "|" + "|".join(["---"] * len(header)) + "|"]
    for row in rows:
        out.append("| " + " | ".join(str(cell).replace("|", "\\|") for cell in row) + " |")
    return "\n".join(out)


def file_sha(name):
    path = os.path.join(EVID, name)
    if not os.path.exists(path):
        return "-"
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


SETTING_NAMES = {
    "0x1": "QPACK_MAX_TABLE_CAPACITY",
    "0x6": "MAX_FIELD_SECTION_SIZE",
    "0x7": "QPACK_BLOCKED_STREAMS",
    "0x8": "ENABLE_CONNECT_PROTOCOL",
    "0x33": "H3_DATAGRAM",
    "0xffd277": "H3_DATAGRAM (deprecated)",
    "0x2b603742": "ENABLE_WEBTRANSPORT (deprecated)",
    "0xc671706a": "WEBTRANSPORT_MAX_SESSIONS",
    "0x2c7cf000": "SETTINGS_WT_ENABLED (draft-15)",
}

if failures:
    b5_row = ["B5", "GAPs listed", "%d failure row(s)" % len(failures)]
elif driver_failure:
    b5_row = ["B5", "driver failure (harness-side, not a gate GAP)", driver_failure]
else:
    b5_row = ["B5", "no GAP", "0 failure rows"]

status_rows = [
    ["B0", b0.get("status", "not_run"), b0_detail()],
    ["B1", b1.get("status", "not_run"), "%d tier(s) executed" % len(tiers)],
    ["B2", b2.get("status", "not_run"), "6 stream/reset items" if items else "not run"],
    ["B3", b3_verdict, b3_basis],
    b5_row,
]

env_rows = [
    ["repository commit (git rev-parse HEAD at generation)", "`%s`" % ENV["COMMIT"]],
    ["harness tree id (git rev-parse HEAD:interop/m3/rtx-server)", "`%s`" % ENV["HARNESS_TREE"]],
    ["harness main.rs SHA-256", "`%s`" % ENV["HARNESS_MAIN_SHA"]],
    ["harness diff vs HEAD", "`%s`" % ENV["HARNESS_DIFF"].strip()],
    ["Firefox (from the browser itself)", "`%s`" % ENV["FIREFOX_VERSION_RAW"]],
    ["Firefox binary", "`%s`" % ENV["FIREFOX"]],
    ["moz:buildID (Marionette capabilities)", "`%s`" % caps.get("moz:buildID", "unknown")],
    ["headless (Marionette capabilities)", "`%s`" % caps.get("moz:headless", "unknown")],
    ["user agent (page)", "`%s`" % (content_probe.get("userAgent")
                                     or result.get("user_agent") or "unknown")],
    ["version source", "`$FIREFOX --version` + `application.ini` + Marionette "
                       "capabilities; raw output is in `firefox-version.txt`"],
    ["OS", "`%s`" % ENV["OS_TEXT"]],
    ["date", "`%s`" % ENV["DATE"]],
    ["harness address", "`%s`" % ENV["ADDR"]],
    ["page origin", "`https://127.0.0.1:%s` (served by `../page_server.py` copy)"
                    % ENV["PAGE_PORT"]],
    ["WebTransport URL", "`https://127.0.0.1:%s/session`" % ENV["QUIC_ACTUAL_PORT"]],
    ["`serverCertificateHashes` pin (base64url SHA-256 of the served DER)",
     "`%s`" % cert_hash],
    ["runner phase", "`relaxed` (harness at HEAD lineage: client QPACK capacity "
                     "relaxation + PR #29 Chrome-compat legacy pair; unmodified by this runner)"],
    ["test page SHA-256 (`../index.html`, Firefox copy)", "`%s`" % ENV["PAGE_SHA"]],
    ["page server SHA-256 (`../page_server.py`, byte-identical copy)", "`%s`" % ENV["PAGE_SERVER_SHA"]],
    ["matrix duration", "%s ms" % result.get("duration_ms", "unknown")],
    ["server alive after matrix", "`%s`" % ("yes" if server_alive else "no")],
    ["driver result timeout", "`%s` s (the previous uncommitted attempt used "
                              "420 s and waited blindly)"
                              % ENV.get("RESULT_TIMEOUT", "120")],
    ["driver", "Marionette protocol 3 over TCP `127.0.0.1:%s` (`../marionette_drive.py`); "
               "no CDP, no geckodriver, no Playwright" % ENV["MARIONETTE_PORT"]],
]

launch_text = ENV["FLAGS_TEXT"]

cert_text = """- Self-signed **ECDSA P-256** leaf, `CN=localhost`, SAN
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
- Certificate hash used by this run (SHA-256, base64url, unpadded): `%s`.""" % cert_hash

pref_rows = [
    ["`dom.webtransport.enabled`", "`%s`" % dom_wt_value,
     "measured via `Services.prefs.getPrefType`/typed getter in chrome "
     "context; `MISSING` = the pref does not exist in this build"],
    ["`network.http.http3.enable`", "`%s`" % http3_value,
     "necko HTTP/3 master switch (WebTransport itself uses the neqo stack)"],
    ["`network.webtransport.enabled`",
     "`%s`" % requested_prefs.get("network.webtransport.enabled", "not probed"),
     "the WebTransport switch that actually exists in this build"],
    ["`network.webtransport.datagrams.enabled`",
     "`%s`" % requested_prefs.get("network.webtransport.datagrams.enabled", "not probed"),
     "datagram support switch"],
    ["`dom.webtransport.*` child prefs", "`%s`" % json.dumps(pref_children.get("dom.webtransport")),
     "enumerated via `Services.prefs.getChildList` in chrome context"],
    ["`network.webtransport.*` child prefs (with measured values)",
     "`%s`" % (wt_switch_text if wt_children else json.dumps(wt_children)),
     "enumerated via `Services.prefs.getChildList` in chrome context"],
    ["`typeof WebTransport` (chrome context)", "`%s`" % typeof_wt_chrome,
     "Marionette `WebDriver:ExecuteScript` with `Services` access"],
    ["`typeof WebTransport` (content, secure page)", "`%s`" % typeof_wt_content,
     "probed on `https://127.0.0.1:%s/index.html` after navigation" % ENV["PAGE_PORT"]],
    ["`isSecureContext` (content)", "`%s`" % content_probe.get("isSecureContext", "not probed"),
     "WebTransport is secure-context-only; the probe page is the HTTPS test page"],
    ["`typeof WebTransportDatagramDuplexStream` (content)",
     "`%s`" % content_probe.get("WebTransportDatagramDuplexStream", "not probed"), "datagram API surface"],
    ["`typeof WebTransportError` (content)",
     "`%s`" % content_probe.get("WebTransportError", "not probed"), "error API surface"],
]

capability_text = md_table(["probe", "value", "note"], pref_rows)
capability_text += "\n\n**Capability conclusion:** `%s` — %s" % (capability, capability_detail)

wt_prototype = content_probe.get("WebTransport_prototype")
if wt_prototype:
    capability_text += ("\n\n`WebTransport.prototype` members in this build: `%s`.\n"
                        "Full probe JSON (capabilities, pref enumeration, content "
                        "surface): `firefox-prefs.json`."
                        % "`, `".join(wt_prototype))

settings_text = "The server log contains no decoded client SETTINGS frame in this run."
if settings:
    rows = [["`%s`" % entry["id"], entry["value"],
             SETTING_NAMES.get(entry["id"], "unknown/GREASE"), entry["class"]]
            for entry in settings]
    settings_text = md_table(["id", "value", "name", "class"], rows)
    frame_line = next((line for line in log_lines
                       if "event=h3_settings_frame_received" in line), "")
    if frame_line:
        settings_text += "\n\nFrame: `%s`" % frame_line

server_settings_text = "(no server SETTINGS logged)"
if server_settings:
    rows = [["`%s`" % identifier, value, SETTING_NAMES.get(identifier, "unexpected")]
            for identifier, value in server_settings]
    server_settings_text = md_table(["id", "value", "name"], rows)
    payload_line = next((line for line in log_lines
                         if "event=server_settings_payload" in line), "")
    if payload_line:
        server_settings_text += "\n\nWire payload: `%s`" % payload_line

b0_text = """## B0 — session establishment

| item | observed |
|---|---|
| `WebTransport.ready` | `%s`%s |
| extended CONNECT response | `status=200` x%d (server `response_headers_sent`) |
| server session observation | `connect_request_decoded` x%d |
| CONNECT rejections | %d |
| QUIC handshakes complete / failed | %d / %d |""" % (
    b0.get("status", "not_run"),
    (", %s ms" % b0.get("ready_ms")) if b0.get("ready_ms") is not None else "",
    responses_200, connect_decoded, connect_rejected,
    handshake_complete, len(handshake_failed_lines))
if b0.get("error"):
    b0_text += "\n| error | `%s` |" % b0.get("error")
if b0.get("status") == "unsupported":
    b0_text += ("\n| not attempted | WebTransport is not exposed in this build "
                "(content-context `typeof WebTransport` = `%s`); gate M3-B3 "
                "conditional N/A, no session was attempted |" % typeof_wt_content)
if driver_failure:
    b0_text += ("\n| driver failure | `%s` (harness-side tooling failure, "
                "recorded as a defect of the run, not as a gate GAP) |"
                % driver_failure)
connect_line = next((line for line in log_lines
                     if "event=connect_request_decoded" in line), None)
if connect_line:
    b0_text += "\n\nFirst decoded CONNECT (verbatim): `%s`" % connect_line

b1_text = "## B1 — DATAGRAM (Firefox ↔ harness)\n\nNot exercised: %s" % not_run_reason
if tiers:
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
            "%d mismatches / %d timeouts" % (tier.get("echo_mismatches", 0),
                                             tier.get("echo_timeouts", 0)),
            "`%s`" % (tier.get("payload_sha256") or "-")[:16] + "…",
        ])
    b1_text = """## B1 — DATAGRAM (Firefox ↔ harness)

| item | value |
|---|---|
| `peer_max_datagram_frame_size` (Firefox advertisement) | `%s` |
| harness `max_datagram_frame_size_advertised` | `%s` |
| `datagrams.maxDatagramSize` (browser API) | `%s` |
| negotiated tier derivation | `%s` |

Tier payloads are the deterministic `0..255` cycle (first N bytes); SHA-256 is
computed by the page with `crypto.subtle`. Each send was paired with its own
echo (`send i`, verify `echo i`, then `send i+1`), so the sequence check is
strict alternation. QUIC DATAGRAM is unreliable and unordered by design: the
loss numbers below are a measured result, not a protocol guarantee.

%s

Server log counters: `datagram_received` %d, `datagram_sent` %d,
`datagram_echo_failed` %d, dropped (`wrong_session`/`malformed`/`decode_failed`/
`buffer_too_small`) %s. The harness stayed alive for the whole matrix: `%s`.""" % (
        params.get("peer_max_datagram_frame_size"),
        params.get("max_datagram_frame_size_advertised"),
        params.get("datagrams_max_datagram_size_api"),
        b1.get("derivation"),
        md_table(["tier", "payload bytes", "Firefox→server sends", "server received",
                  "lost", "echo sent (server)", "echo received (Firefox)", "echo lost",
                  "order", "SHA-256"], rows),
        sum(received.values()), sum(sent.values()), echo_failed, dropped,
        "yes" if server_alive else "no")

b2_text = "## B2 — streams\n\nNot exercised: %s" % not_run_reason
if items:
    labels = {
        "server_uni": "server-initiated uni (1 MiB)",
        "client_uni": "client uni 1 MiB + half-close echo",
        "client_bi": "client bi 1 MiB + half-close echo",
        "concurrent_bi": "10 concurrent bi 1 MiB",
        "client_reset": "client reset (writable.abort)",
        "server_reset": "server reset observed (4096 B then code 7)",
    }
    rows = []
    for name, label in labels.items():
        entry = items.get(name, {}) or {}
        details = []
        if name in ("server_uni", "client_bi"):
            details.append("bytes=%s" % entry.get("bytes", entry.get("echo_bytes", 0)))
            details.append("sha256=%s" % (entry.get("sha256") or entry.get("sent_sha256") or "-"))
        elif name == "client_uni":
            details.append("sent bytes=%s sha256=%s" % (entry.get("sent_bytes", 0),
                                                        entry.get("sent_sha256", "-")))
            details.append("echo bytes=%s sha256=%s" % (entry.get("echo_bytes", 0),
                                                        entry.get("echo_sha256", "-")))
        elif name == "concurrent_bi":
            details.append("streams=%s completed=%s" % (entry.get("streams", 0),
                                                        entry.get("completed", 0)))
            details.append("bytes/stream=%s sha256=%s" % (entry.get("bytes_per_stream", 0),
                                                          entry.get("sent_sha256", "-")))
        elif name == "server_reset":
            details.append("observed=%s bytes_before_reset=%s reset_code=%s"
                           % (entry.get("observed", False),
                              entry.get("bytes_before_reset", 0), entry.get("reset_code")))
        elif name == "client_reset":
            details.append("bytes_before_reset=%s; server log role=client count=%d"
                           % (entry.get("bytes_before_reset", 0), client_reset))
        if entry.get("error"):
            details.append("error=" + str(entry.get("error")))
        rows.append([label, entry.get("status", "not_run"), "; ".join(details)])
    b2_text = """## B2 — streams

%s

Server log counters: `stream_finished role=client` %d, `stream_reset role=client`
%d, `stream_reset role=server code=7` %d, `stream_opened kind=uni role=server
bytes=1048576` %d.""" % (
        md_table(["item", "status", "detail"], rows),
        client_stream_finished, client_reset, server_reset, server_uni_open)

session_text = """## Session close and second session

| item | observed |
|---|---|
| `transport.close()` (`WT_CLOSE_SESSION`) | `%s`; server `session_closed` lines: %d |
| `transport.closed` event | `%s` |
| second session on the same harness process | `%s` (%s) |
| `connect_request_decoded` / `response_headers_sent 200` totals | %d / %d |
| `connect_request_rejected` | %d |""" % (
    (result.get("session_close") or {}).get("status"),
    session_closed,
    json.dumps((result.get("session_close") or {}).get("closed_event")),
    (result.get("second_session") or {}).get("status"),
    (result.get("second_session") or {}).get("error") or "ready",
    connect_decoded, responses_200, connect_rejected)

gap_rows = [[("`%s`" % failure["gap"]) if failure.get("gap") else
             "(none — a Firefox-lineage failure carries no fabricated GAP id; "
             "registering one belongs to the coordinator, gate §4)",
             failure.get("item"), failure.get("detail")]
            for failure in failures]
gap_text = md_table(["GAP", "item", "detail"], gap_rows) if gap_rows else \
    "No failure was recorded by the page in this run; no GAP row."
if driver_failure:
    gap_text += ("\n\n**Driver failure (harness-side, not a gate GAP):** `%s`. "
                 "The Marionette driver or the browser failed before the page "
                 "could post a result; this is recorded as a defect of the run "
                 "tooling, never as a registered GAP." % driver_failure)

b3_text = """## B3 verdict (gate M3-B3)

| item | value |
|---|---|
| verdict | **%s** |
| basis | %s |
| Firefox | `%s` (moz:buildID `%s`) |
| platform | `%s` |
| pref/switch state (measured) | `dom.webtransport.enabled`=%s; `network.http.http3.enable`=%s; `dom.webtransport.*` children=%s; `network.webtransport.*`: %s |
| methods checked | Marionette chrome-context `Services.prefs` enumeration (`getChildList` + typed getters); content-context `typeof WebTransport`/`isSecureContext` on the secure HTTPS page; the B0/B1/B2 matrix itself where supported |
| gap | %s |""" % (
    b3_verdict, b3_basis, ENV["FIREFOX_VERSION_RAW"], caps.get("moz:buildID", "unknown"),
    ENV["OS_TEXT"],
    json.dumps(dom_wt_value), json.dumps(http3_value),
    json.dumps(pref_children.get("dom.webtransport")), wt_switch_text,
    "none" if b3_verdict == "PASS" else ("not applicable (N/A)" if b3_verdict == "N/A"
                                          else "see GAP table"))

not_done_text = """## Not done (explicitly)

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
- this report is evidence only; it does not declare "M3 pass"."""

evidence_text = """## Evidence files

| file | SHA-256 |
|---|---|
| `server.log` | `%s` |
| `result.json` | `%s` |
| `firefox-version.txt` | `%s` |
| `firefox-prefs.json` | `%s` |
| `firefox-page-status.txt` | `%s` |
| `firefox.log` | `%s` |
| `hashes.txt` | `%s` |

`hashes.txt` is the machine-readable matrix (item, sends, receives, lost, bytes,
SHA-256, detail); `result.json` is the page's `window.__rtx_result` posted
verbatim; `firefox-prefs.json` is the Marionette driver's probe (capabilities,
chrome-context pref enumeration, content-context API surface);
`firefox-page-status.txt` is the page's `#status` text (the console-equivalent
trail; Firefox/Gecko has no CDP-style console export through Marionette);
`firefox.log` is the browser process stdout/stderr. Test page: `../index.html`;
page server: `../page_server.py`; runner: `../run-firefox.sh`; driver:
`../marionette_drive.py`.""" % (
    file_sha("server.log"), file_sha("result.json"), file_sha("firefox-version.txt"),
    file_sha("firefox-prefs.json"), file_sha("firefox-page-status.txt"),
    file_sha("firefox.log"), file_sha("hashes.txt"))

method_text = """## Method

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
  %s s, the page watchdog from 240 s to 90 s, and the wait loop now samples
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
  and the page pins the WT endpoint with `serverCertificateHashes`.""" \
    % ENV.get("RESULT_TIMEOUT", "120")

reproduce_text = """## Reproduce

```
./interop/m3/firefox-rtx/run-firefox.sh
```

The runner generates the runtime certificate with `openssl` in a `mktemp`
directory, imports it into a temporary Firefox profile with `certutil`, builds
`rtx-wt-server`, starts the harness and `page_server.py`, launches headless
Firefox with `--marionette --no-remote -profile <tmp>`, drives it over the raw
Marionette protocol (navigate + probes, `RESULT_TIMEOUT=%s` s bound), and writes
only the text evidence listed above. No key material enters the repository.
Requires: `firefox` (system package), `certutil` (libnss3-tools), `python3`,
`openssl`, `cargo`.""" % ENV.get("RESULT_TIMEOUT", "120")

summary = """**B0 `%s`:** %s

**B1 `%s`:** %d tier(s), sends/echoes/loss from the table below.

**B2 `%s`:** %d stream/reset item(s).

**B3 verdict: %s** — %s

**Failures recorded by the page: %d.** GAP status changes belong to the
milestone acceptance PR / coordinator, not to this report.""" % (
    b0.get("status", "not_run"), b0_detail(),
    b1.get("status", "not_run"), len(tiers),
    b2.get("status", "not_run"), len(items),
    b3_verdict, b3_basis, len(failures))

report = """# M3-B3 Firefox WebTransport interop — `%s` (%s-firefox-%s)

**What this proves:** a real Firefox build (%s, moz:buildID %s) was probed for
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

%s

## Status

%s

## Environment

%s

## Firefox launch parameters

```
%s
```

## Certificate handling

%s

%s

## Firefox capability probe (WebTransport over HTTP/3)

%s

## Firefox SETTINGS observed (verbatim values)

%s

## Server SETTINGS actually emitted

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
    ENV["FIREFOX_VERSION_RAW"], ENV["DATE"],
    ENV["FIREFOX_VERSION_RAW"].split()[-1].split(".")[0],
    ENV["FIREFOX_VERSION_RAW"], caps.get("moz:buildID", "unknown"),
    summary,
    md_table(["item", "status", "detail"], status_rows),
    md_table(["item", "value"], env_rows),
    launch_text,
    cert_text,
    method_text,
    capability_text,
    settings_text,
    server_settings_text,
    b0_text,
    b1_text,
    b2_text,
    session_text,
    b3_text,
    "## B5 GAP table\n\n" + gap_text,
    not_done_text,
    evidence_text,
    reproduce_text,
)

with open(os.path.join(EVID, "report.md"), "w", encoding="utf-8") as handle:
    handle.write(report)

print(json.dumps({
    "b3": b3_verdict,
    "capability": capability,
    "b0": b0.get("status"),
    "b1": b1.get("status"),
    "b2": b2.get("status"),
    "failures": len(failures),
}))
