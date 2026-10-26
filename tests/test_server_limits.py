"""Server hardening: Host allow-list, scan cap (429), finished eviction, static
traversal. Run: python tests/test_server_limits.py"""

import http.client
import json
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from webscanx import server as api   # noqa: E402


def _start():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), api.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _req(httpd, method, path, body=None, host=None):
    c = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=10)
    c.putrequest(method, path, skip_host=True)   # raw path: no client-side normalising
    c.putheader("Host", host or "127.0.0.1:%d" % httpd.server_address[1])
    data = json.dumps(body).encode() if body is not None else None
    if data:
        c.putheader("Content-Type", "application/json")
        c.putheader("Content-Length", str(len(data)))
    c.endheaders(data)
    r = c.getresponse()
    out = r.status, r.read()
    c.close()
    return out


def _reset():
    api._JOBS.clear()
    api._ORDER.clear()


def _fake(i, state):
    api._JOBS[i] = {"id": i, "state": state}
    api._ORDER.append(i)


def _wait_idle():
    end = time.time() + 30
    while time.time() < end and any(j["state"] == "running" for j in api._JOBS.values()):
        time.sleep(0.1)


def test_host_header_allowlist():
    h = _start()
    try:
        assert _req(h, "GET", "/api/health")[0] == 200
        assert _req(h, "GET", "/api/health", host="evil.example")[0] == 403
        assert _req(h, "GET", "/api/health", host="127.0.0.1.evil.example")[0] == 403
        assert _req(h, "GET", "/api/health", host="localhost:8765")[0] == 200
    finally:
        h.shutdown(); h.server_close()


def test_running_cap_429():
    h = _start()
    old = api.MAX_RUNNING
    try:
        _reset()
        api.MAX_RUNNING = 2
        _fake("r1", "running"); _fake("r2", "running")
        with tempfile.TemporaryDirectory() as d:
            code, blob = _req(h, "POST", "/api/scan", {"target": d, "kind": "code"})
        assert code == 429, (code, blob)
    finally:
        api.MAX_RUNNING = old
        _reset(); h.shutdown(); h.server_close()


def test_finished_eviction():
    h = _start()
    old = api.MAX_FINISHED
    try:
        _reset()
        api.MAX_FINISHED = 2
        for i in range(5):
            _fake("d%d" % i, "done")
        with tempfile.TemporaryDirectory() as d:
            code, blob = _req(h, "POST", "/api/scan", {"target": d, "kind": "code"})
            assert code == 202, (code, blob)
            _wait_idle()
        done = [i for i, j in api._JOBS.items() if j["state"] == "done" and i.startswith("d")]
        assert len(done) <= 2, done
        assert len(api._JOBS) == len(api._ORDER)
    finally:
        api.MAX_FINISHED = old
        _wait_idle(); _reset(); h.shutdown(); h.server_close()


def test_non_string_target_kind_400():
    h = _start()
    try:
        _reset()
        for body in ({"target": 123}, {"target": ["a"], "kind": "code"},
                     {"target": "http://127.0.0.1/", "kind": 5}, {"target": {"x": 1}}):
            code, blob = _req(h, "POST", "/api/scan", body)
            assert code == 400, (body, code, blob)
    finally:
        _reset(); h.shutdown(); h.server_close()


def test_check_command_shell_quoted():
    import shlex
    from webscanx.core.finding import Finding
    for url in ("http://h.test/a'b", "http://h.test/x';id;`id`", "http://h.test/?q='$(id)`x`;&|"):
        cmd = api._check_command(Finding("t", "low", url, "web.xss"))
        assert cmd, url
        parts = shlex.split(cmd)          # one argv entry == the URL: nothing escapes the quoting
        assert parts[:2] == ["curl", "-s"] and parts[2:] == [url], (url, cmd)


def test_static_traversal_404():
    h = _start()
    old = api.DIST
    try:
        with tempfile.TemporaryDirectory() as t:
            dist = Path(t, "dist").resolve()
            dist.mkdir()
            (dist / "index.html").write_text("<html>ui</html>")
            Path(t, "secret.txt").write_text("TOPSECRET")
            api.DIST = dist
            assert _req(h, "GET", "/")[0] == 200
            assert _req(h, "GET", "/some/route")[0] == 200            # SPA fallback
            for p in ("/../secret.txt", "/..%2fsecret.txt", "/%2e%2e/secret.txt",
                      "/..\\secret.txt", "/a/../../secret.txt"):
                code, blob = _req(h, "GET", p)
                assert b"TOPSECRET" not in blob, p
                assert code == 404, (p, code)
    finally:
        api.DIST = old
        h.shutdown(); h.server_close()


def load_tests(loader, standard_tests, pattern):   # lets unittest/discover run the bare test_* functions
    from tests._fn import collect
    return collect(sys.modules[__name__])


if __name__ == "__main__":
    test_host_header_allowlist()
    test_running_cap_429()
    test_finished_eviction()
    test_static_traversal_404()
    print("server limits: ok")
