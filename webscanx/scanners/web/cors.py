"""web.cors — Cross-Origin Resource Sharing misconfiguration (CWE-942).

The loop: send an Origin header the server has no reason to trust, read the
Access-Control-Allow-* response headers, decide. The dangerous combo is a
reflected/wildcard origin together with Allow-Credentials: true — that lets any
site read authenticated responses. Read-only GET with one extra header.

Maps to OWASP A02:2025 Security Misconfiguration.
"""

from __future__ import annotations

from ...core.engine import register
from ...core.finding import Finding
from ...core.target import TargetKind
from . import http
from .crawler import get_sitemap

_CAT = "A02:2025 Security Misconfiguration / CWE-942"
_REFS = ["https://portswigger.net/web-security/cors",
         "https://cwe.mitre.org/data/definitions/942.html"]

_EVIL = "https://evil.example"


@register(TargetKind.WEB, "web.cors")
def scan(target, ctx):
    site = get_sitemap(target, ctx)
    if not site.pages:
        return
    url = site.pages[0].url
    resp = http.fetch(url, timeout=ctx.timeout, headers={"Origin": _EVIL})
    if not resp.ok:
        return

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
    if not acao:
        return                              # no CORS headers -> nothing to flag

    reflects = acao == _EVIL                # server echoed our untrusted origin
    wildcard = acao == "*"
    if not (reflects or wildcard):
        return                              # ACAO pinned to a specific trusted origin

    if reflects and acac:
        sev, extra = "high", (" with Allow-Credentials: true, so any origin can "
                              "read authenticated responses (session data, etc.)")
    elif wildcard and acac:
        # browsers ignore '*' + credentials, but it signals a broken CORS policy
        sev, extra = "medium", " combined with Allow-Credentials (an invalid, telling combo)"
    else:
        sev, extra = "low", ""

    yield Finding(
        title="Permissive CORS policy", severity=sev, where=url, scanner="web.cors",
        what=f"The server returned Access-Control-Allow-Origin: {acao}{extra}. A "
             "too-open CORS policy can let untrusted websites read this site's responses.",
        how_to_check=f"curl -s -I -H 'Origin: {_EVIL}' {url} | grep -i access-control "
                     "— see if the origin is reflected or set to '*'.",
        evidence=f"Origin: {_EVIL}  ->  Access-Control-Allow-Origin: {acao}"
                 + (f"; Access-Control-Allow-Credentials: true" if acac else ""),
        remediation="Allow only an explicit allow-list of trusted origins; never reflect "
                    "arbitrary origins, and never combine a wildcard/reflected origin with "
                    "Allow-Credentials.",
        category=_CAT, references=_REFS,
    )


def demo() -> None:
    # Decision logic is offline-testable via crafted header dicts.
    def decide(acao, acac):
        reflects = acao == _EVIL
        wildcard = acao == "*"
        if not acao or not (reflects or wildcard):
            return None
        if reflects and acac:
            return "high"
        if wildcard and acac:
            return "medium"
        return "low"

    assert decide("https://evil.example", True) == "high"
    assert decide("*", True) == "medium"
    assert decide("*", False) == "low"
    assert decide("https://trusted.site", True) is None   # pinned origin: safe
    assert decide("", False) is None                       # no CORS: nothing
    print("cors.py: ok")


if __name__ == "__main__":
    demo()
