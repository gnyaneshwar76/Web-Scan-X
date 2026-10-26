"""Second, independent web fixture (not _VulnHandler): a clean site, a
comment/textarea reflection page, and a boolean-SQLi page. Run: python tests/test_fixture2.py"""

import re
import sys
import threading
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from webscanx.core.target import Target, TargetKind        # noqa: E402
from webscanx.core.engine import ScanContext, run          # noqa: E402
import webscanx.scanners  # noqa: E402,F401

_ITEM = re.compile(r"^(\d+)(?: AND (\d+)=(\d+)|' AND '(\d+)'='(\d+))?$")
_NAV = ('<a href="/clean?name=bob">c</a><a href="/note?c=hi">n</a>'
        '<a href="/item?id=1">i</a>')


class _Site(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _html(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/clean":          # always escapes; never errors
            return self._html("<p>hello %s</p>" % escape(q.get("name", ""), quote=True))
        if u.path == "/note":           # reflects only in inert contexts
            c = q.get("c", "")
            return self._html("<!-- last: %s --><textarea>%s</textarea>" % (c, c))
        if u.path == "/item":           # boolean SQLi: stable page, no DB error text
            m = _ITEM.match(q.get("id", ""))
            if not m:
                return self._html("<p>invalid id</p>")
            n, a, b, c, d = m.groups()
            if (a is not None and a != b) or (c is not None and c != d):
                return self._html("<p>no rows</p>")
            return self._html("<p>item %s: widget</p>" % n)
        self._html(_NAV)


def _scan(only):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        t = Target(TargetKind.WEB, "http://127.0.0.1:%d/" % srv.server_address[1], "fx2")
        from webscanx.scanners.web import http as web_http
        web_http.set_scope(t.location)
        return run(t, ScanContext(only=only))
    finally:
        srv.shutdown()
        srv.server_close()


def test_clean_site_no_false_positives():
    # /item is the deliberate SQLi page, so it is excluded here
    bad = [f for f in _scan({"web.xss", "web.sqli"})
           if f.severity.label in ("Medium", "High", "Critical") and "/item" not in f.where]
    assert not bad, [(f.title, f.where) for f in bad]


def test_comment_textarea_reflection_not_flagged():
    xss = [f for f in _scan({"web.xss"}) if "/note" in f.where]
    assert not xss, [(f.title, f.where) for f in xss]


def test_boolean_sqli_found():
    found = _scan({"web.sqli"})
    hits = [f for f in found if "boolean" in f.title and "/item" in f.where]
    assert hits, [(f.title, f.where) for f in found]
    assert not [f for f in found if "/clean" in f.where or "/note" in f.where]


def load_tests(loader, standard_tests, pattern):   # lets unittest/discover run the bare test_* functions
    from tests._fn import collect
    return collect(sys.modules[__name__])


if __name__ == "__main__":
    test_clean_site_no_false_positives()
    test_comment_textarea_reflection_not_flagged()
    test_boolean_sqli_found()
    print("fixture2: ok")
