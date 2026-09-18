"""Phase 0 self-checks. Run: python -m pytest -q   (or: python tests/test_spine.py)

No framework required — plain asserts. Each core module also has its own demo();
this ties them together plus an end-to-end CLI run against a temp directory.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from webscanx.core import finding, target, engine          # noqa: E402
from webscanx.report import report as report_mod            # noqa: E402
from webscanx.report import render as render_mod            # noqa: E402


def test_module_demos_pass():
    finding.demo()
    target.demo()
    engine.demo()
    report_mod.demo()
    render_mod.demo()
    from webscanx.scanners.web import http as web_http
    web_http.demo()


def test_end_to_end_cli(tmp_path=None):
    """Full CLI path over a clean temp folder: writes every format, exits 0 clean."""
    import tempfile
    with tempfile.TemporaryDirectory() as clean:
        Path(clean, "hello.py").write_text("print('hello, world')\n", encoding="utf-8")
        out = (tmp_path or ROOT / "tests") / "e2e_report"
        cmd = [sys.executable, "-m", "webscanx", "--code", clean,
               "-o", str(out), "-f", "json", "-f", "md", "-f", "html"]
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr        # clean source -> exit 0
        doc = json.loads(Path(f"{out}.json").read_text(encoding="utf-8"))
        assert doc["target_kind"] == "code"
        assert doc["total"] == 0, doc["total"]          # nothing insecure in hello.py
        assert Path(f"{out}.md").exists() and Path(f"{out}.html").exists()
        for ext in (".json", ".md", ".html"):
            Path(f"{out}{ext}").unlink()  # clean up


# ── Phase 1: web scanners against a local vulnerable fixture ─────────────────
import threading                                              # noqa: E402
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402

from webscanx.core.target import Target, TargetKind          # noqa: E402
from webscanx.core.engine import ScanContext, run            # noqa: E402
import webscanx.scanners  # noqa: E402,F401  (registers web.* scanners)


class _VulnHandler(BaseHTTPRequestHandler):
    """A deliberately broken site: no security headers, reflected XSS, SQL error,
    and a tokenless POST form. All on 127.0.0.1 — no external network."""

    def log_message(self, *a):  # silence test output
        pass

    def _send(self, body: str, origin=None):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")  # note: no security headers
        self.send_header("Server", "TestServer/1.0")   # version banner (disclosure)
        # weak CSP present (web.csp), and a cookie with SameSite=None w/o Secure (web.cookies)
        self.send_header("Content-Security-Policy", "default-src *; script-src 'unsafe-inline'")
        self.send_header("Set-Cookie", "sess=1; SameSite=None; Path=/")
        if origin:                                     # reflect Origin (bad CORS)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        path = urlparse(self.path).path
        q = parse_qs(urlparse(self.path).query)
        origin = self.headers.get("Origin")
        if path == "/go" and "next" in q:              # open redirect
            self.send_response(302)
            self.send_header("Location", q["next"][0])
            self.end_headers()
            return
        if path == "/.env":                            # exposed sensitive file
            return self._send("SECRET=1\nAPI_KEY=abc123")
        if path == "/debug":                           # verbose error (web.errors)
            return self._send("Traceback (most recent call last):\n"
                              '  File "app.py", line 10, in <module>\n'
                              "    raise ValueError('boom')\nValueError: boom")
        if "q" in q:
            val = q["q"][0]
            if "'" in val:  # pretend the quote broke a SQL query
                return self._send("You have an error in your SQL syntax; check the "
                                  "MySQL server manual near ''")
            return self._send(f"<p>results for {val}</p>", origin=origin)  # reflected
        # root: links (search, redirect param, debug), a tokenless password form
        # posting over cleartext (web.forms), and a leaked key in source (web.secrets)
        self._send('<a href="/?q=hello">search</a>'
                   '<a href="/go?next=/home">next</a>'
                   '<a href="/debug">debug</a>'
                   '<!-- key AKIAIOSFODNN7EXAMPLE -->'
                   '<form action="/login" method="post">'
                   '<input name="user"><input name="password"></form>', origin=origin)

    def do_POST(self):
        self._send("<p>logged in</p>")

    def do_OPTIONS(self):                              # risky methods advertised
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS")
        self.end_headers()

    def do_TRACE(self):                               # TRACE enabled -> XST
        self.send_response(200)
        self.send_header("Content-Type", "message/http")
        self.end_headers()
        self.wfile.write(b"TRACE / HTTP/1.1\r\nHost: 127.0.0.1\r\n")


def _serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _VulnHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_web_scan_finds_vulns():
    srv = _serve()
    try:
        port = srv.server_address[1]
        target = Target(TargetKind.WEB, f"http://127.0.0.1:{port}/", "fixture")
        found = run(target, ScanContext(aggressive=True))  # aggressive: probe POST form too
        by_scanner = {f.scanner for f in found}
        assert "web.headers" in by_scanner, "missing security-header findings"
        assert "web.xss" in by_scanner, "reflected XSS not detected"
        assert "web.sqli" in by_scanner, "error-based SQLi not detected"
        assert "web.csrf" in by_scanner, "tokenless POST form not flagged"
        assert "web.tls" in by_scanner, "plain-HTTP target should flag TLS"
        assert "web.cors" in by_scanner, "reflected-origin CORS not flagged"
        assert "web.redirect" in by_scanner, "open redirect not detected"
        assert "web.disclosure" in by_scanner, "exposed .env / banner not flagged"
        assert "web.methods" in by_scanner, "risky methods / TRACE not flagged"
        assert "web.csp" in by_scanner, "weak CSP not flagged"
        assert "web.secrets" in by_scanner, "leaked key not flagged"
        assert "web.errors" in by_scanner, "verbose error not flagged"
        assert "web.cookies" in by_scanner, "SameSite=None w/o Secure not flagged"
        assert "web.forms" in by_scanner, "insecure password form not flagged"
        # worst finding is High (XSS/SQLi) -> the CLI would exit 2
        assert max(f.severity for f in found).label in ("High", "Critical")
    finally:
        srv.shutdown()


def test_mixed_content_scanner():
    """web.mixed needs an HTTPS page; drive it with a seeded crawl (no network).
    Exercises the real scan() code path via the shared-context cache."""
    from types import SimpleNamespace
    from webscanx.scanners.web import mixed
    from webscanx.scanners.web.crawler import Sitemap, Page

    page = Page(url="https://site.test/", status=200,
                body='<script src="http://cdn.test/a.js"></script>'
                     '<img src="http://img.test/p.png">')
    ctx = SimpleNamespace(cache={"sitemap": Sitemap(root="https://site.test/",
                                                    pages=[page])},
                          timeout=5.0, aggressive=False, only=set())
    target = SimpleNamespace(location="https://site.test/", kind=TargetKind.WEB)
    found = list(mixed.scan(target, ctx))
    assert found and found[0].scanner == "web.mixed"
    assert found[0].severity.label == "Medium"   # active mixed content (script)


def test_code_scan_finds_vulns():
    """Scan a temp directory of deliberately insecure source (SAST, no network)."""
    import tempfile, os
    vuln = (
        "import os, hashlib, pickle, random, requests\n"
        "password = \"hunter2secret\"\n"                       # code.secrets
        "AWS = 'AKIAIOSFODNN7EXAMPLE'\n"                       # code.secrets
        "os.system('ping ' + host)\n"                          # code.injection (CWE-78)
        "data = pickle.loads(blob)\n"                          # code.injection (CWE-502)
        "h = hashlib.md5(x).hexdigest()\n"                     # code.crypto
        "otp = random.randint(0, 9999)  # otp token\n"         # code.crypto (weak RNG)
        "requests.get(u, verify=False)\n"                      # code.config (TLS off)
        "DEBUG = True\n"                                       # code.config
    )
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "app.py"), "w", encoding="utf-8") as fh:
            fh.write(vuln)
        target = Target(TargetKind.CODE, d, d)
        found = run(target, ScanContext())
        by_scanner = {f.scanner for f in found}
        assert "code.secrets" in by_scanner, "hardcoded secret not flagged"
        assert "code.injection" in by_scanner, "injection sink not flagged"
        assert "code.crypto" in by_scanner, "weak crypto not flagged"
        assert "code.config" in by_scanner, "insecure config not flagged"
        # findings carry file:line locations
        assert any(":" in f.where for f in found)


def test_local_api():
    """The UI bridge: refuses what it should, and runs a real scan end to end."""
    import json as _json, os, tempfile, threading, time, urllib.error, urllib.request
    from http.server import ThreadingHTTPServer
    from webscanx import server as api

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), api.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]

    def post(body, origin=None):
        req = urllib.request.Request(
            base + "/api/scan", data=_json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        if origin:
            req.add_header("Origin", origin)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, _json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, _json.loads(e.read())

    def get(path, origin=None):
        req = urllib.request.Request(base + path)
        if origin:
            req.add_header("Origin", origin)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    try:
        # the permission gate survives the move to HTTP
        code, doc = post({"target": "http://example.com"})
        assert code == 400 and "refused" in doc["error"], doc

        # a hostile page must not be able to drive the scanner
        code, doc = post({"target": "http://example.com", "authorized": True},
                         origin="https://evil.example")
        assert code == 403, doc

        # junk in, honest error out
        assert post({"target": ""})[0] == 400
        assert post({"target": "not a url or folder"})[0] == 400

        # a real code scan, start to finished report
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "app.py"), "w", encoding="utf-8") as fh:
                fh.write('password = "hunter2secret"\nDEBUG = True\n')
            code, job = post({"target": d, "kind": "code"},
                             origin="http://localhost:5173")
            assert code == 202, job
            assert job["progress"]["total"] > 0, "no code scanners registered"

            deadline = time.time() + 60
            while time.time() < deadline:
                _, doc = get("/api/scan/" + job["id"])
                doc = _json.loads(doc)
                if doc["state"] in ("done", "error"):
                    break
                time.sleep(0.1)
            assert doc["state"] == "done", doc.get("error")
            assert doc["findings"], "code scan through the API found nothing"
            first = doc["findings"][0]
            assert set(first) >= {"id", "severity", "name", "path", "module",
                                  "what", "howToCheck", "evidence", "fix", "refs"}
            assert doc["progress"]["done"] == doc["progress"]["total"]

            code, blob = get("/api/scan/%s/report?format=html" % job["id"])
            assert code == 200 and b"<html" in blob.lower()
            assert get("/api/scan/%s/report?format=nope" % job["id"])[0] == 400
            assert get("/api/scan/nosuchid")[0] == 404

            _, listing = get("/api/scans")
            assert any(s["id"] == job["id"] for s in _json.loads(listing)["scans"])
    finally:
        httpd.shutdown()
        httpd.server_close()
        api._JOBS.clear()
        api._ORDER.clear()
    print("server.py: ok")


if __name__ == "__main__":
    test_module_demos_pass()
    test_end_to_end_cli()
    test_web_scan_finds_vulns()
    test_mixed_content_scanner()
    test_code_scan_finds_vulns()
    test_local_api()
    print("\nall spine self-checks passed")
