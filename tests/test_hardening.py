"""SSRF guard, input validation, redaction. stdlib unittest; loopback only, no network."""

import http.client
import json
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from webscanx import cli, server as api                    # noqa: E402
from webscanx.core.finding import Finding                  # noqa: E402
from webscanx.report import Report, Options                # noqa: E402
from webscanx.report import render as R                    # noqa: E402
from webscanx.report.report import _mask                   # noqa: E402
from webscanx.scanners.web import cookies, http as web_http  # noqa: E402


class SsrfGuard(unittest.TestCase):
    def test_private_targets_refused(self):
        for u in ("http://10.0.0.1/", "http://192.168.1.1/", "http://169.254.169.254/"):
            with self.assertRaises(ValueError, msg=u):
                web_http.set_scope(u)

    def test_loopback_target_allowed(self):
        web_http.set_scope("http://127.0.0.1:8000/")   # must not raise

    def test_public_scope_blocks_internal_fetches(self):
        web_http.set_scope("http://93.184.216.34/")    # literal public IP: no DNS
        for u in ("http://[::1]/", "http://127.0.0.1:1/", "http://10.0.0.1/",
                  "http://169.254.169.254/"):
            self.assertTrue(web_http.fetch(u, retries=0).error.startswith("blocked"), u)

    def test_loopback_scope_still_blocks_other_private(self):
        web_http.set_scope("http://127.0.0.1:8000/")
        self.assertTrue(web_http.fetch("http://10.0.0.1/", retries=0).error.startswith("blocked"))


class UnknownScanner(unittest.TestCase):
    def test_cli_exit_3(self):
        self.assertEqual(cli.main(["--only", "web.nope", "http://127.0.0.1:1/", "-y"]), 3)


def _post(port, body=None, content_length=None):
    """POST /api/scan; body is JSON-encoded unless raw bytes. Returns status."""
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.putrequest("POST", "/api/scan")
    c.putheader("Content-Type", "application/json")
    c.putheader("Content-Length", str(len(data)) if content_length is None else content_length)
    c.endheaders(data)
    try:
        return c.getresponse().status
    finally:
        c.close()


class ServerValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), api.Handler)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.port = cls.httpd.server_address[1]
        cls.tmp = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown(); cls.httpd.server_close(); cls.tmp.cleanup()

    def ok(self, **extra):
        return {"target": self.tmp.name, "kind": "code", **extra}

    def test_bad_content_length(self):
        for cl in ("-5", "abc", "1.5"):
            self.assertEqual(_post(self.port, b"", content_length=cl), 400, cl)

    def test_wrong_body_types(self):
        for b in ([], "x", 5, None):
            self.assertEqual(_post(self.port, b), 400, repr(b))
        self.assertEqual(_post(self.port, b"not json"), 400)
        self.assertEqual(_post(self.port, {"target": 5}), 400)
        self.assertEqual(_post(self.port, self.ok(only="web.xss")), 400)

    def test_out_of_range_numbers(self):
        bad = {"timeout": [0, 61, "5", True], "delay": [-1, 11, "1"],
               "maxPages": [0, 501, "3"], "depth": [-1, 11, "2"]}
        for k, vals in bad.items():
            for v in vals:
                self.assertEqual(_post(self.port, self.ok(**{k: v})), 400, (k, v))

    def test_unknown_only_400(self):
        self.assertEqual(_post(self.port, self.ok(only=["web.nope"])), 400)


class Redaction(unittest.TestCase):
    def test_cookie_evidence_hides_value(self):
        out = cookies._mask("sess=SUPERSECRETVALUE; SameSite=None; Path=/")
        self.assertNotIn("SUPERSECRETVALUE", out)
        self.assertIn("sess", out)

    def test_mask_12_char_token_after_cookie(self):
        out = _mask("Cookie: abcdefgh1234")
        self.assertNotIn("abcdefgh1234", out)

    def test_csv_formula_neutralised(self):
        r = Report(target="https://h.test/", target_kind="web")
        r.findings = [Finding("=BAD", "low", "/", "web.x", what="+SUM(1)", evidence="@cmd")]
        for line in R.render(r, "csv", Options()).decode().splitlines()[1:]:
            for cell in line.split(","):
                self.assertFalse(cell and cell[0] in "=+@", cell)


if __name__ == "__main__":
    unittest.main()
