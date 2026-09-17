"""A minimal, safe HTTP client for the web scanners.

stdlib only. Enforces timeouts and a response-size cap (Rule Zero: treat every
target as hostile — never let a target hang us or blow up memory). Never raises
on HTTP errors; an error response still carries a body we want to inspect.
"""

from __future__ import annotations

import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

USER_AGENT = "WebScanX/0.1 (+authorised security testing)"
MAX_BYTES = 3_000_000  # 3 MB response cap

# Process-wide politeness throttle. A scan runs one target at a time, so a single
# global min-interval is enough to rate-limit every scanner's requests.
# ponytail: global throttle; revisit if scans ever run concurrent targets.
_rate_lock = threading.Lock()
_min_interval = 0.0
_last_request = 0.0


def set_rate(delay_seconds: float) -> None:
    """Minimum seconds between outgoing requests (0 = no throttle)."""
    global _min_interval
    _min_interval = max(0.0, float(delay_seconds))


def _throttle() -> None:
    global _last_request
    if _min_interval <= 0:
        return
    with _rate_lock:
        wait = _min_interval - (time.monotonic() - _last_request)
        if wait > 0:
            time.sleep(wait)
        _last_request = time.monotonic()


@dataclass
class Response:
    url: str            # requested url
    final_url: str      # after redirects
    status: int         # 0 = transport error (DNS/refused/timeout)
    headers: dict[str, str] = field(default_factory=dict)  # keys lower-cased
    set_cookie: list[str] = field(default_factory=list)
    body: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status != 0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Turn 3xx into an HTTPError so the caller can read Location without following
    (open-redirect checks must inspect the target, never walk to it)."""

    def http_error_301(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    http_error_302 = http_error_303 = http_error_307 = http_error_308 = http_error_301


def fetch(url: str, method: str = "GET", data: dict | None = None,
          timeout: float = 15.0, verify_tls: bool = True,
          headers: dict | None = None, allow_redirects: bool = True,
          retries: int = 2) -> Response:
    """GET/POST a URL. Returns a Response; transport failures come back as
    status 0 with .error set rather than raising. Extra request headers (e.g.
    Origin for CORS probes) merge over the default User-Agent. With
    allow_redirects=False, a 3xx comes back as-is (status + Location header)
    instead of being followed. Transient transport errors are retried up to
    `retries` times with a short linear backoff; HTTP error responses are never
    retried (they're real answers)."""
    body_bytes = None
    if data is not None:
        body_bytes = urllib.parse.urlencode(data).encode("utf-8")

    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body_bytes, method=method, headers=hdrs)
    ctx = None
    if url.lower().startswith("https"):
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

    opener = None
    if not allow_redirects:
        handlers = [_NoRedirect()]
        if ctx is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        opener = urllib.request.build_opener(*handlers)

    attempt = 0
    while True:
        _throttle()
        try:
            if opener is not None:
                with opener.open(req, timeout=timeout) as resp:
                    return _build(url, resp, resp.status)
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return _build(url, resp, resp.status)
        except urllib.error.HTTPError as e:
            # 3xx (no-follow), 4xx, 5xx: still a real response — never retry.
            return _build(url, e, e.code)
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as e:
            if attempt >= retries:
                return Response(url=url, final_url=url, status=0, error=str(e))
            attempt += 1
            time.sleep(0.3 * attempt)   # linear backoff before retrying


def _build(url: str, resp, status: int) -> Response:
    raw = resp.read(MAX_BYTES)
    charset = "utf-8"
    try:
        charset = resp.headers.get_content_charset() or "utf-8"
    except Exception:
        pass
    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    cookies = resp.headers.get_all("Set-Cookie") or []
    return Response(
        url=url,
        final_url=getattr(resp, "url", url) or url,
        status=status,
        headers=hdrs,
        set_cookie=list(cookies),
        body=raw.decode(charset, "replace"),
    )


def demo() -> None:
    """Self-check retry (transient errors) + throttle timing, with urlopen stubbed."""
    import urllib.request as _u

    # 1. Retry: fail transiently twice, succeed on the third attempt.
    calls = {"n": 0}

    class _FakeResp:
        status = 200
        url = "http://x/"
        headers = type("H", (), {"items": lambda s: [], "get_all": lambda s, k: [],
                                 "get_content_charset": lambda s: "utf-8"})()

        def read(self, n): return b"ok"
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def flaky(req, timeout=None, context=None):
        calls["n"] += 1
        if calls["n"] < 3:
            raise urllib.error.URLError("temporary")
        return _FakeResp()

    orig = _u.urlopen
    try:
        _u.urlopen = flaky
        set_rate(0)
        r = fetch("http://x/", retries=2)
        assert r.status == 200 and calls["n"] == 3, (r.status, calls["n"])

        # 2. Give up after `retries` transient failures -> status 0.
        calls["n"] = 0
        def always_fail(req, timeout=None, context=None):
            calls["n"] += 1
            raise urllib.error.URLError("down")
        _u.urlopen = always_fail
        r = fetch("http://x/", retries=2)
        assert r.status == 0 and calls["n"] == 3, (r.status, calls["n"])  # 1 + 2 retries
    finally:
        _u.urlopen = orig

    # 3. Throttle enforces a minimum gap between requests.
    set_rate(0.05)
    t0 = time.monotonic()
    _throttle(); _throttle()          # second call must wait ~0.05s
    assert time.monotonic() - t0 >= 0.045
    set_rate(0)                        # reset so it never leaks into other tests
    print("http.py: ok")


if __name__ == "__main__":
    demo()
