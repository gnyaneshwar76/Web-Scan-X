"""web.redirect — open redirect (CWE-601).

The loop: for parameters that look like redirect targets, inject an external URL
and see whether the server sends the browser there. If the final URL lands on an
attacker-controlled host, the redirect is open — usable for phishing and OAuth
token theft. Read-only GET (follows redirects, changes nothing).

Maps to OWASP A01:2025 Broken Access Control (redirect/SSRF family).
"""

from __future__ import annotations

from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from ...core.engine import register
from ...core.finding import Finding
from ...core.target import TargetKind
from . import http
from .crawler import get_sitemap

_CAT = "A01:2025 Broken Access Control / CWE-601"
_REFS = ["https://cheatsheetseries.owasp.org/cheatsheets/"
         "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
         "https://cwe.mitre.org/data/definitions/601.html"]

# Params commonly used for redirects — worth probing even if not obviously so.
_REDIRECT_NAMES = {"next", "url", "redirect", "redirect_uri", "redirect_url",
                   "return", "returnurl", "return_to", "dest", "destination",
                   "continue", "goto", "to", "out", "target", "rurl", "u"}
_MARKER_HOST = "evil.example"
_PAYLOAD = f"https://{_MARKER_HOST}/"


def _set_param(url: str, name: str, value: str) -> str:
    parts = urlparse(url)
    q = [(k, value if k == name else v) for k, v in parse_qsl(parts.query)]
    return urlunparse(parts._replace(query=urlencode(q)))


@register(TargetKind.WEB, "web.redirect")
def scan(target, ctx):
    site = get_sitemap(target, ctx)
    seen: set[tuple[str, str]] = set()
    for url, name in site.params:
        # Focus on likely redirect params unless running aggressively.
        if name.lower() not in _REDIRECT_NAMES and not ctx.aggressive:
            continue
        key = (urlparse(url).path, name)
        if key in seen:
            continue
        seen.add(key)

        probe = _set_param(url, name, _PAYLOAD)
        # Don't follow — inspect the Location the server hands back.
        resp = http.fetch(probe, timeout=ctx.timeout, allow_redirects=False)
        location = resp.headers.get("location", "")
        if 300 <= resp.status < 400 and urlparse(location).hostname == _MARKER_HOST:
            yield Finding(
                title="Open redirect", severity="medium",
                where=f"{url} (param: {name})", scanner="web.redirect",
                what="This parameter redirects to any URL it's given, including "
                     "external sites. Attackers use it to make phishing links look "
                     "like they point at your trusted domain, and to steal OAuth tokens.",
                how_to_check=f"Visit {probe} and confirm the browser lands on "
                             f"{_MARKER_HOST} instead of staying on this site.",
                evidence=f"{name}={_PAYLOAD}  ->  {resp.status} Location: {location}",
                remediation="Don't redirect to user-supplied URLs. Allow only relative "
                            "paths or an allow-list of known hosts; reject absolute "
                            "external URLs.",
                category=_CAT, references=_REFS,
            )


def demo() -> None:
    assert _set_param("http://x/go?next=1&a=2", "next", _PAYLOAD) == \
        "http://x/go?next=https%3A%2F%2Fevil.example%2F&a=2"
    assert "next" in _REDIRECT_NAMES and "redirect_uri" in _REDIRECT_NAMES
    # host-comparison logic: only the attacker host counts as open
    from urllib.parse import urlparse as up
    assert up("https://evil.example/x").hostname == _MARKER_HOST
    assert up("https://safe.site/x").hostname != _MARKER_HOST
    print("redirect.py: ok")


if __name__ == "__main__":
    demo()
