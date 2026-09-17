"""web.xss — reflected cross-site scripting (CWE-79, OWASP A05:2025 Injection).

The loop: inject a unique benign marker into each input, read the response,
decide on unescaped reflection. The marker carries the characters (< > " ')
that a safe app must encode; if they come back verbatim, output encoding is
missing. The marker is inert (no runnable script), and unique per run so it can
never match static page text.

Safe by default: GET parameters and GET forms are read-only and always probed.
POST forms can change data, so they're only probed under --aggressive.
Stored / DOM XSS are out of scope this phase.
"""

from __future__ import annotations

import uuid
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from ...core.engine import register
from ...core.finding import Finding
from ...core.target import TargetKind
from . import http
from .crawler import get_sitemap

_CAT = "A05:2025 Injection / CWE-79"
_REFS = ["https://owasp.org/www-community/attacks/xss/",
         "https://cwe.mitre.org/data/definitions/79.html"]

# Distinctive brackets/quotes an encoding-safe app would turn into entities.
_SENTINEL = '"><wsx'


def _marker() -> str:
    return f'{_SENTINEL}{uuid.uuid4().hex[:10]}>'


def _reflected_unescaped(body: str, marker: str) -> bool:
    return marker in body                      # verbatim = the <>"' were not encoded


def _finding(where: str, marker: str, body: str) -> Finding:
    idx = body.find(marker)
    snippet = body[max(0, idx - 30): idx + len(marker) + 10] if idx >= 0 else marker
    return Finding(
        title="Reflected XSS", severity="high", where=where, scanner="web.xss",
        what="Input sent to this page is echoed back into the HTML without "
             "encoding, so an attacker can craft a link that runs JavaScript in a "
             "victim's browser (session theft, actions as the user).",
        how_to_check=f"Request the URL with a test value like {_SENTINEL}TEST> in "
                     "the parameter and view source — if it appears unescaped, "
                     "it's reflected.",
        evidence=f"Marker reflected unescaped: ...{snippet}...",
        remediation="Context-encode all output (HTML-encode < > \" ' &), prefer a "
                    "framework's auto-escaping template, and add a Content-Security-Policy.",
        category=_CAT, references=_REFS,
    )


def _probe_url_param(url: str, name: str, timeout: float) -> Finding | None:
    marker = _marker()
    parts = urlparse(url)
    q = [(k, marker if k == name else v) for k, v in parse_qsl(parts.query)]
    probe = urlunparse(parts._replace(query=urlencode(q)))
    resp = http.fetch(probe, timeout=timeout)
    if resp.ok and _reflected_unescaped(resp.body, marker):
        return _finding(f"{url} (param: {name})", marker, resp.body)
    return None


def _probe_form(form, timeout: float) -> Finding | None:
    marker = _marker()
    data = {f: marker for f in form.fields}
    if form.method == "GET":
        parts = urlparse(form.action_url)
        probe = urlunparse(parts._replace(query=urlencode(data)))
        resp = http.fetch(probe, timeout=timeout)
    else:
        resp = http.fetch(form.action_url, method="POST", data=data, timeout=timeout)
    if resp.ok and _reflected_unescaped(resp.body, marker):
        loc = f"{form.action_url} (form: {form.method})"
        return _finding(loc, marker, resp.body)
    return None


@register(TargetKind.WEB, "web.xss")
def scan(target, ctx):
    site = get_sitemap(target, ctx)

    for url, name in site.params:
        f = _probe_url_param(url, name, ctx.timeout)
        if f:
            yield f

    for form in site.forms:
        if form.method == "POST" and not ctx.aggressive:
            continue                            # POST can change data — gated
        if not form.fields:
            continue
        f = _probe_form(form, ctx.timeout)
        if f:
            yield f


def demo() -> None:
    # Detection logic is offline-testable: an unescaped echo vs an encoded one.
    m = _marker()
    vulnerable = f"<p>you searched for {m}</p>"
    safe = vulnerable.replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")
    assert _reflected_unescaped(vulnerable, m)
    assert not _reflected_unescaped(safe, m), "encoded reflection must not flag"
    assert m != _marker(), "each marker must be unique per call"
    f = _finding("http://x/?q=", m, vulnerable)
    assert f.severity.label == "High" and f.remediation and "CWE-79" in f.category
    print("xss.py: ok")


if __name__ == "__main__":
    demo()
