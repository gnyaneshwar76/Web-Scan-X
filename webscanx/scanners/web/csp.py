"""web.csp — weak Content-Security-Policy (CWE-693).

headers.py flags a *missing* CSP; this analyses a CSP that IS present and reports
the directives that weaken it: unsafe-inline / unsafe-eval, wildcard sources, and
missing object-src / base-uri. Read-only (reads the crawl's response headers).

Maps to OWASP A02:2025 Security Misconfiguration.
"""

from __future__ import annotations

from ...core.engine import register
from ...core.finding import Finding
from ...core.target import TargetKind
from .crawler import get_sitemap

_CAT = "A02:2025 Security Misconfiguration / CWE-693"
_REFS = ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
         "Content-Security-Policy",
         "https://cheatsheetseries.owasp.org/cheatsheets/"
         "Content_Security_Policy_Cheat_Sheet.html"]


def _weaknesses(csp: str) -> list[str]:
    low = csp.lower()
    out = []
    if "'unsafe-inline'" in low:
        out.append("'unsafe-inline' allows inline scripts/styles (defeats much of XSS "
                   "protection)")
    if "'unsafe-eval'" in low:
        out.append("'unsafe-eval' allows eval()/string-to-code")
    # bare "*" source in a fetch directive that governs scripts/objects
    for part in low.split(";"):
        toks = part.split()
        if not toks:
            continue
        directive, sources = toks[0], toks[1:]
        if directive in ("default-src", "script-src", "object-src", "frame-src") \
                and "*" in sources:
            out.append(f"wildcard '*' source in {directive}")
    if "object-src" not in low:
        out.append("no object-src 'none' (plugins/embeds not locked down)")
    if "base-uri" not in low:
        out.append("no base-uri (allows <base> tag injection)")
    return out


@register(TargetKind.WEB, "web.csp")
def scan(target, ctx):
    site = get_sitemap(target, ctx)
    if not site.pages:
        return
    page = site.pages[0]
    csp = page.headers.get("content-security-policy", "")
    if not csp:
        return                              # missing CSP is headers.py's job
    issues = _weaknesses(csp)
    if not issues:
        return
    sev = "medium" if any("unsafe" in i or "wildcard" in i for i in issues) else "low"
    yield Finding(
        title="Weak Content-Security-Policy", severity=sev, where=page.url,
        scanner="web.csp",
        what="A CSP is present but has gaps that reduce its protection against "
             "cross-site scripting and content injection: " + "; ".join(issues) + ".",
        how_to_check="Inspect the Content-Security-Policy response header and review "
                     "each directive against the OWASP CSP cheat sheet.",
        evidence=f"Content-Security-Policy: {csp}",
        remediation="Remove 'unsafe-inline'/'unsafe-eval' (use nonces or hashes), avoid "
                    "wildcard sources, and add object-src 'none' and base-uri 'self'.",
        category=_CAT, references=_REFS,
    )


def demo() -> None:
    weak = _weaknesses("default-src 'self'; script-src 'self' 'unsafe-inline'")
    assert any("unsafe-inline" in w for w in weak)
    assert any("object-src" in w for w in weak)      # missing -> flagged
    strong = _weaknesses("default-src 'self'; object-src 'none'; base-uri 'self'")
    assert strong == [], strong                      # locked down -> nothing
    print("csp.py: ok")


if __name__ == "__main__":
    demo()
