"""A minimal, safe HTTP client for the web scanners.

stdlib only. Enforces timeouts and a response-size cap (Rule Zero: treat every
target as hostile — never let a target hang us or blow up memory). Never raises
on HTTP errors; an error response still carries a body we want to inspect.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

USER_AGENT = "WebScanX/0.1 (+authorised security testing)"
MAX_BYTES = 3_000_000  # 3 MB response cap

# Per-scan politeness throttle. Each scan runs its scanners on one thread, so the
# rate lives in thread-local state: concurrent API scans can't change each other's
# pacing, and the CLI (one scan on the main thread) works unchanged.
_rate = threading.local()


def set_rate(delay_seconds: float) -> None:
    """Minimum seconds between outgoing requests from this scan's thread (0 = none)."""
    _rate.interval = max(0.0, float(delay_seconds))
    _rate.last = 0.0


def _throttle() -> None:
    interval = getattr(_rate, "interval", 0.0)
    if interval <= 0:
        return
    wait = interval - (time.monotonic() - getattr(_rate, "last", 0.0))
    if wait > 0:
        time.sleep(wait)
    _rate.last = time.monotonic()


class Blocked(OSError, ValueError):
    """The SSRF guard refused a host (private/internal, or unresolvable)."""


def _unwrap(ip):
    """The IPv4 a v6 address embeds (v4-mapped, NAT64 64:ff9b::/96, 6to4 2002::/16)."""
    if ip.version == 6:
        n = int(ip)
        if ip.ipv4_mapped:
            return ip.ipv4_mapped
        if ip in ipaddress.ip_network("64:ff9b::/96"):
            return ipaddress.IPv4Address(n & 0xFFFFFFFF)
        if ip in ipaddress.ip_network("2002::/16"):
            return ipaddress.IPv4Address((n >> 80) & 0xFFFFFFFF)
    return ip


def _resolve(host: str, port: int) -> list:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as e:
        raise Blocked(f"cannot resolve {host} ({e})") from None
    return [i[4][0].split("%")[0] for i in infos]


def resolve_checked(host: str | None, port: int) -> str:
    """Resolve host ONCE, vet every address, return the IP to connect to (callers
    must connect to this IP, not re-resolve - that closes DNS rebinding). Raises
    Blocked (an OSError and ValueError) if refused or unresolvable. The scan's
    declared loopback host may only ever resolve to loopback."""
    if not host:
        raise Blocked("no host in URL")
    ips = _resolve(host, port)
    allowed = host.lower() == getattr(_rate, "allow", None)
    for s in ips:
        ip = ipaddress.ip_address(s)
        eff = _unwrap(ip)
        if not (eff.is_loopback if allowed else eff.is_global):  # private, link-local, metadata...
            raise Blocked(f"{host} resolves to {ip}, a non-public address")
    return ips[0]


def _blocked_reason(host: str | None) -> str:
    try:
        resolve_checked(host, 80)
    except Blocked as e:
        return str(e)
    return ""


def set_scope(url: str) -> None:
    """Declare this scan's target (per thread). Raises ValueError if it is a
    private/internal address, unless it is loopback (the local demo target); the
    loopback host is then the only non-public host this scan may contact."""
    host = urllib.parse.urlparse(url).hostname
    _rate.allow = None
    try:
        resolve_checked(host, 80)
    except Blocked as e:
        try:
            loop = all(_unwrap(ipaddress.ip_address(i)).is_loopback for i in _resolve(host, 80))
        except Blocked:
            loop = False
        if not loop:
            raise ValueError(f"refused: {e} (private/internal targets are blocked)") from None
        _rate.allow = host.lower()


def _guard(url: str) -> str:
    return _blocked_reason(urllib.parse.urlparse(url).hostname)


class _GuardRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = urllib.parse.urljoin(req.full_url, newurl)
        why = "" if new.lower().startswith(("http://", "https://")) else "non-http redirect"
        why = why or _guard(new)
        if why:
            raise urllib.error.URLError(f"blocked redirect: {why}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _pin(sock_host: str, port: int, timeout, src):
    # Connect to the vetted IP; the Host header / TLS SNI still use the hostname.
    return socket.create_connection((resolve_checked(sock_host, port), port), timeout, src)


class _PinnedHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = _pin(self.host, self.port, self.timeout, self.source_address)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def connect(self):
        sock = _pin(self.host, self.port, self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_PinnedHTTP, req)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_PinnedHTTPS, req, context=self._context)


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

    # ProxyHandler({}): env proxies must not route around the pinned-IP guard.
    handlers = [urllib.request.ProxyHandler({}), _HTTPHandler(),
                _NoRedirect() if not allow_redirects else _GuardRedirect()]
    handlers.append(_HTTPSHandler(context=ctx or ssl.create_default_context()))
    opener = urllib.request.build_opener(*handlers)

    attempt = 0
    while True:
        _throttle()
        try:
            with opener.open(req, timeout=timeout) as resp:
                return _build(url, resp, resp.status)
        except urllib.error.HTTPError as e:
            # 3xx (no-follow), 4xx, 5xx: still a real response — never retry.
            return _build(url, e, e.code)
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as e:
            blocked = e if isinstance(e, Blocked) else getattr(e, "reason", None)
            if isinstance(blocked, Blocked) or "blocked redirect" in str(e):
                return Response(url=url, final_url=url, status=0, error=f"blocked: {blocked or e}")
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

    orig = _u.build_opener
    try:
        _u.build_opener = lambda *h: type("O", (), {"open": staticmethod(flaky)})()
        set_rate(0)
        r = fetch("http://x/", retries=2)
        assert r.status == 200 and calls["n"] == 3, (r.status, calls["n"])

        # 2. Give up after `retries` transient failures -> status 0.
        calls["n"] = 0
        def always_fail(req, timeout=None, context=None):
            calls["n"] += 1
            raise urllib.error.URLError("down")
        _u.build_opener = lambda *h: type("O", (), {"open": staticmethod(always_fail)})()
        r = fetch("http://x/", retries=2)
        assert r.status == 0 and calls["n"] == 3, (r.status, calls["n"])  # 1 + 2 retries
    finally:
        _u.build_opener = orig

    # SSRF guard: metadata/private blocked, public literal allowed.
    assert fetch("http://169.254.169.254/").error.startswith("blocked")
    assert fetch("http://10.0.0.1/").error.startswith("blocked")
    assert fetch("http://[::1]/").error.startswith("blocked")

    # 3. Throttle enforces a minimum gap between requests.
    set_rate(0.05)
    t0 = time.monotonic()
    _throttle(); _throttle()          # second call must wait ~0.05s
    assert time.monotonic() - t0 >= 0.045
    set_rate(0)                        # reset so it never leaks into other tests
    print("http.py: ok")


if __name__ == "__main__":
    demo()
