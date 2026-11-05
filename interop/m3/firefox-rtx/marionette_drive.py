"""Marionette driver for the M3-B3 Firefox WebTransport matrix.

Firefox does not speak the Chrome DevTools Protocol, so the run is driven
through Gecko's built-in Marionette remote protocol (raw TCP, length-prefixed
JSON, no geckodriver and no Playwright download required — the system
/usr/bin/firefox already ships the server side).

Responsibilities:
  1. open a Marionette session and record the browser's own capabilities;
  2. probe WebTransport-related prefs and the API in chrome context
     (definitive pref values via Services.prefs) -> <prefs.json>;
  3. navigate to the HTTPS test page and probe the content-context API
     surface on the secure origin;
  4. wait for the page to POST its result (the page_server writes
     <result.json>), with a bounded timeout;
  5. capture window.__rtx_result and the page's #status text as fallback
     evidence -> <page-status.txt>.

Usage:
  marionette_drive.py --port 2828 --url https://127.0.0.1:8443/index.html?...
      --result <staging>/result.json --prefs <out>/firefox-prefs.json
      --page-status <out>/firefox-page-status.txt --timeout 120
      [--firefox-pid <pid>]

The wait for the page result is not a blind sleep: every few seconds the
driver re-reads the page state through Marionette (href, `#status` tail,
`window.__rtx_result.finished`), recovers a finished-but-unposted result via
execute_script, aborts immediately on a neterror/certerror page, and aborts
immediately when the Firefox process died (--firefox-pid). On any failure the
page state and the diagnostics land in the probe JSON and the page-status
file instead of an empty 420 s wait (the first revision of this driver timed
out blindly and produced no probe JSON at all).
"""

import argparse
import json
import os
import socket
import sys
import time
import traceback


class MarionetteError(RuntimeError):
    pass


def process_alive(pid):
    """True while the given PID exists (used for fail-fast, not for waiting)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


class Marionette:
    """Minimal Marionette protocol-3 client (length-prefixed JSON frames)."""

    def __init__(self, host, port, timeout=90, pid=None):
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            if pid is not None and not process_alive(pid):
                raise MarionetteError(
                    "firefox process %d exited before Marionette accepted a "
                    "connection (last error: %s)" % (pid, last))
            try:
                self.sock = socket.create_connection((host, port), timeout=10)
                break
            except OSError as error:
                last = error
                time.sleep(0.5)
        else:
            raise MarionetteError("cannot connect to Marionette: %s" % last)
        self.buf = b""
        self.next_id = 0
        self.session_id = None
        hello = self._read_message()
        if hello.get("marionetteProtocol") != 3:
            raise MarionetteError("unexpected handshake: %r" % (hello,))

    def _fill(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise MarionetteError("marionette socket closed")
        self.buf += chunk

    def _read_message(self):
        while b":" not in self.buf:
            self._fill()
        length_str, _, rest = self.buf.partition(b":")
        length = int(length_str)
        while len(rest) < length:
            self._fill()
            length_str, _, rest = self.buf.partition(b":")
        payload, self.buf = rest[:length], rest[length:]
        return json.loads(payload.decode("utf-8"))

    def cmd(self, name, params=None):
        self.next_id += 1
        params = dict(params or {})
        if self.session_id and "sessionId" not in params:
            params["sessionId"] = self.session_id
        payload = json.dumps([0, self.next_id, name, params]).encode("utf-8")
        self.sock.sendall(b"%d:" % len(payload) + payload)
        while True:
            resp = self._read_message()
            if isinstance(resp, list) and len(resp) == 4 and resp[1] == self.next_id:
                _, _, error, result = resp
                if error:
                    raise MarionetteError("%s -> %s: %s" % (
                        name, error.get("error"), error.get("message")))
                return result

    def execute(self, script, chrome=False):
        self.cmd("Marionette:SetContext", {"value": "chrome" if chrome else "content"})
        value = self.cmd("WebDriver:ExecuteScript", {"script": script})
        return value["value"] if isinstance(value, dict) else value

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


PREF_PROBE = r"""
// nsIPrefBranch type constants: PREF_STRING=32, PREF_INT=64, PREF_BOOL=128.
// (The first revision of this probe mapped them incorrectly and called
// getStringPref on the bool network.http.http3.enable, which threw
// NS_ERROR_UNEXPECTED instead of returning the value.)
function readPref(name) {
  try {
    const type = Services.prefs.getPrefType(name);
    if (type === 0) return "MISSING";
    if (type === 128) return Services.prefs.getBoolPref(name);
    if (type === 64) return Services.prefs.getIntPref(name);
    if (type === 32) return Services.prefs.getStringPref(name);
    return "unknown pref type " + type;
  } catch (e) { return "error: " + e; }
}
const out = {requested: {}, pref_children: {}, child_values: {},
             api_in_chrome_context: {}};
for (const name of ["dom.webtransport.enabled",
                    "network.http.http3.enable",
                    "network.webtransport.enabled",
                    "network.webtransport.datagrams.enabled"]) {
  out.requested[name] = readPref(name);
}
for (const branch of ["dom.webtransport", "network.webtransport",
                      "network.http.http3"]) {
  try { out.pref_children[branch] = Services.prefs.getChildList(branch); }
  catch (e) { out.pref_children[branch] = "error: " + e; }
}
for (const branch of ["dom.webtransport", "network.webtransport"]) {
  const children = out.pref_children[branch];
  if (Array.isArray(children)) {
    for (const name of children) out.child_values[name] = readPref(name);
  }
}
out.api_in_chrome_context = {
  WebTransport: typeof WebTransport,
  WebTransportDatagramDuplexStream: typeof WebTransportDatagramDuplexStream,
  WebTransportError: typeof WebTransportError,
};
return out;
"""

CONTENT_PROBE = r"""
const surface = {
  href: location.href,
  title: document.title,
  isSecureContext: window.isSecureContext,
  userAgent: navigator.userAgent,
  WebTransport: typeof WebTransport,
  WebTransportDatagramDuplexStream: typeof WebTransportDatagramDuplexStream,
  WebTransportError: typeof WebTransportError,
};
if (typeof WebTransport === "function") {
  surface.WebTransport_prototype = Object.getOwnPropertyNames(WebTransport.prototype);
}
if (typeof WebTransportDatagramDuplexStream === "function") {
  surface.datagram_stream_prototype =
      Object.getOwnPropertyNames(WebTransportDatagramDuplexStream.prototype);
}
if (typeof WebTransportError === "function") {
  surface.WebTransportError_prototype =
      Object.getOwnPropertyNames(WebTransportError.prototype);
}
return surface;
"""

PAGE_STATE_SCRIPT = r"""
var st = document.getElementById("status");
var r = window.__rtx_result;
return {
  href: location.href,
  title: document.title,
  finished: !!(r && r.finished),
  status_tail: st ? String(st.textContent).slice(-600) : null
};
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2828)
    parser.add_argument("--url", required=True)
    parser.add_argument("--result", required=True,
                        help="path the page_server writes result.json to")
    parser.add_argument("--prefs", required=True, help="output firefox-prefs.json")
    parser.add_argument("--page-status", required=True,
                        help="output firefox-page-status.txt (page #status text)")
    parser.add_argument("--timeout", type=int, default=120,
                        help="seconds to wait for the page result")
    parser.add_argument("--firefox-pid", type=int, default=None,
                        help="browser PID; the driver aborts immediately if it dies")
    parser.add_argument("--expect-profile", default=None,
                        help="moz:profile the session must report; guards "
                             "against connecting to another agent's Firefox "
                             "on a shared host")
    args = parser.parse_args()

    probe = {}
    status_written = False

    def dump_probe():
        with open(args.prefs, "w", encoding="utf-8") as handle:
            json.dump(probe, handle, indent=2)

    def write_page_status(text):
        nonlocal status_written
        with open(args.page_status, "w", encoding="utf-8") as handle:
            handle.write((text or "(no #status text captured)").rstrip("\n") + "\n")
        status_written = True

    def page_state():
        """One defensive snapshot of the loaded page (content context)."""
        return client.execute(PAGE_STATE_SCRIPT, chrome=False)

    def recover_result():
        """Pull window.__rtx_result out of the page when the POST never arrived."""
        late = client.execute("return window.__rtx_result || null;", chrome=False)
        if late:
            with open(args.result, "w", encoding="utf-8") as handle:
                json.dump(late, handle, indent=2)
        return bool(late)

    client = None
    posted = False
    reason = None
    samples = []
    try:
        client = Marionette(args.host, args.port, pid=args.firefox_pid)
        session = client.cmd("WebDriver:NewSession", {"capabilities": {}})
        value = session.get("value", session)
        client.session_id = value.get("sessionId")
        probe["session_id"] = client.session_id
        probe["capabilities"] = value.get("capabilities")
        dump_probe()

        # Identity check: the Marionette endpoint must belong to *our* Firefox.
        if args.expect_profile:
            actual = os.path.realpath(str((value.get("capabilities") or {}).get("moz:profile")))
            expected = os.path.realpath(args.expect_profile)
            if actual != expected:
                raise MarionetteError(
                    "Marionette answered from a different Firefox: moz:profile=%s, "
                    "expected %s (port collision on a shared host?)" % (actual, expected))

        probe["pref_probe_chrome_context"] = client.execute(PREF_PROBE, chrome=True)
        dump_probe()

        # Navigate is a content-context command; execute() left us in chrome.
        client.cmd("Marionette:SetContext", {"value": "content"})
        client.cmd("WebDriver:Navigate", {"url": args.url})
        probe["content_probe"] = client.execute(CONTENT_PROBE, chrome=False)
        dump_probe()

        # Wait for the page's POST /result (same mechanism as the Chrome run),
        # but not blindly: every few seconds the page itself is asked where it
        # is, so a hung, crashed or misnavigated run surfaces immediately
        # instead of after the full timeout.
        started = time.time()
        deadline = started + args.timeout
        reason = "timeout"
        next_sample = 0.0
        while time.time() < deadline:
            if os.path.exists(args.result) and os.path.getsize(args.result) > 0:
                reason = "posted"
                break
            if args.firefox_pid is not None and not process_alive(args.firefox_pid):
                reason = "firefox_process_exited"
                break
            if time.time() >= next_sample:
                next_sample = time.time() + 5
                try:
                    state = page_state()
                except (MarionetteError, OSError) as error:
                    state = {"error": str(error)}
                if not isinstance(state, dict):
                    state = {"error": "unexpected state payload: %r" % (state,)}
                state["t_s"] = round(time.time() - started, 1)
                samples.append(state)
                href = str(state.get("href") or "")
                if href.startswith("about:neterror") or href.startswith("about:certerror"):
                    reason = "navigation_failed"
                    break
                if state.get("finished"):
                    # The page is done but its POST never reached the server;
                    # recover the result object straight out of the page.
                    try:
                        if recover_result():
                            reason = "recovered_via_execute_script"
                            posted = True
                            break
                    except (MarionetteError, OSError) as error:
                        probe["result_recovery_error"] = str(error)
            time.sleep(0.2)
        probe["result_wait"] = {"reason": reason, "timeout_s": args.timeout,
                                "elapsed_s": round(time.time() - started, 1)}
        probe["progress"] = samples
        posted = posted or reason == "posted"

        if not posted:
            # Failure path: capture whatever the page managed to record.
            try:
                probe["late_href"] = client.execute("return location.href;", chrome=False)
            except (MarionetteError, OSError) as error:
                probe["late_href"] = "error: %s" % error
            try:
                if recover_result():
                    probe["result_wait"]["recovered_via_execute_script"] = True
                    posted = True
            except (MarionetteError, OSError) as error:
                probe["result_recovery_error"] = str(error)

        try:
            status = client.execute(
                "var e = document.getElementById('status');"
                "return e ? e.textContent : null;", chrome=False)
        except (MarionetteError, OSError) as error:
            status = "status capture failed: %s" % error
        if reason != "posted":
            status = ("driver: result_wait reason=%s\n"
                      "last progress sample: %s\n"
                      "%s" % (reason,
                              json.dumps(samples[-1] if samples else None),
                              status))
        write_page_status(status)
    except (MarionetteError, OSError) as error:
        probe["driver_error"] = str(error)
        posted = False
    except Exception as error:  # recorded in the probe JSON, never swallowed
        probe["driver_error"] = "%s: %s" % (type(error).__name__, error)
        probe["driver_traceback"] = traceback.format_exc()
        posted = False
    finally:
        if not status_written:
            try:
                write_page_status("driver failed before the page status could be "
                                  "captured: %s" % probe.get("driver_error"))
            except OSError:
                pass
        dump_probe()
        if client is not None:
            try:
                client.cmd("WebDriver:Quit", {})
            except (MarionetteError, OSError):
                pass
            client.close()

    content_probe = probe.get("content_probe")
    print(json.dumps({
        "posted": posted,
        "result_wait": probe.get("result_wait"),
        "driver_error": probe.get("driver_error"),
        "content_probe_surface": (
            {key: content_probe.get(key)
             for key in ("href", "isSecureContext", "WebTransport",
                         "WebTransportDatagramDuplexStream", "WebTransportError")}
            if isinstance(content_probe, dict) else None),
    }))
    return 0 if posted else 1


if __name__ == "__main__":
    sys.exit(main())
