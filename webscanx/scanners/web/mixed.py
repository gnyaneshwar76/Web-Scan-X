"""web.mixed — mixed content on HTTPS pages (CWE-311).

On an HTTPS page, any subresource loaded over plain http:// can be intercepted or
tampered with, and browsers block or downgrade the page. This reads the crawled
HTML (no new requests) and flags http:// script/style/iframe/img references.

Maps to OWASP A04:2025 Cryptographic Failures.
"""

from __future__ import annotations

import re

from ...core.engine import register
from ...core.finding import Finding
from ...core.target import TargetKind
from .crawler import get_sitemap

_CAT = "A04:2025 Cryptographic Failures / CWE-311"
_REFS = ["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"]

# src=/href= pointing at an explicit http:// resource
_HTTP_RES = re.compile(r'(?:src|href)\s*=\s*["\'](http://[^"\']+)["\']', re.IGNORECASE)
# active (script/iframe) mixed content is worse than passive (img)
_ACTIVE = re.compile(r'<(?:script|iframe)\b[^>]*\b(?:src)\s*=\s*["\']http://',
                     re.IGNORECASE)


@register(TargetKind.WEB, "web.mixed")
def scan(target, ctx):
    site = get_sitemap(target, ctx)
    for page in site.pages:
        if not page.url.lower().startswith("https"):
            continue                        # mixed content only applies over HTTPS
        refs = _HTTP_RES.findall(page.body)
        if not refs:
            continue
        active = bool(_ACTIVE.search(page.body))
        sample = ", ".join(dict.fromkeys(refs[:3]))     # de-dup, first few
        yield Finding(
            title="Mixed content on HTTPS page",
            severity="medium" if active else "low", where=page.url,
            scanner="web.mixed",
            what="This HTTPS page loads resources over plain HTTP. Those can be read or "
                 "modified in transit; browsers block active mixed content (scripts) and "
                 "warn on passive (images), breaking the page and its security guarantees.",
            how_to_check="Open the page, check the browser console for 'Mixed Content' "
                         "warnings, or search the HTML for http:// resource URLs.",
            evidence=f"{len(refs)} http:// resource(s), e.g. {sample}",
            remediation="Serve every subresource over HTTPS (use https:// or "
                        "protocol-relative //host URLs); add "
                        "'upgrade-insecure-requests' to the CSP.",
            category=_CAT, references=_REFS,
        )


def demo() -> None:
    html = ('<script src="http://cdn.example/a.js"></script>'
            '<img src="http://img.example/p.png">'
            '<link href="https://safe.example/s.css">')
    refs = _HTTP_RES.findall(html)
    assert "http://cdn.example/a.js" in refs and "http://img.example/p.png" in refs
    assert "https://safe.example/s.css" not in refs      # https is fine
    assert _ACTIVE.search(html)                          # the script is active mixed
    assert not _ACTIVE.search('<img src="http://x/p.png">')  # img alone: passive
    print("mixed.py: ok")


if __name__ == "__main__":
    demo()
