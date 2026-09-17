"""web.headers — security response headers and cookie flags.

Read-only: inspects the headers the crawler already fetched, sends nothing new.
Maps to OWASP A02:2025 Security Misconfiguration. Every finding carries the
plain-language what / how-to-check / fix that is the point of the tool.
"""

from __future__ import annotations

from ...core.engine import register
from ...core.finding import Finding
from ...core.target import TargetKind
from .crawler import get_sitemap

# header -> (severity, what, how_to_check, fix)
_CHECKS = {
    "content-security-policy": (
        "medium",
        "No Content-Security-Policy header. CSP is the browser's main defence "
        "against cross-site scripting and data injection.",
        "Open the site in a browser, check the Network tab response headers for "
        "'Content-Security-Policy'. Absent = flagged.",
        "Add a Content-Security-Policy header. Start strict, e.g. "
        "default-src 'self'; object-src 'none'; frame-ancestors 'none'.",
    ),
    "strict-transport-security": (
        "medium",
        "No Strict-Transport-Security (HSTS) header. Without it a user can be "
        "downgraded to plain HTTP and have traffic intercepted.",
        "Check the HTTPS response headers for 'Strict-Transport-Security'.",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on "
        "HTTPS responses.",
    ),
    "x-content-type-options": (
        "low",
        "No X-Content-Type-Options header. The browser may MIME-sniff responses "
        "and run a file as a different, dangerous type.",
        "Check the response headers for 'X-Content-Type-Options: nosniff'.",
        "Add 'X-Content-Type-Options: nosniff' to every response.",
    ),
    "x-frame-options": (
        "low",
        "No X-Frame-Options / CSP frame-ancestors. The page can be framed by "
        "another site for clickjacking.",
        "Check for 'X-Frame-Options' or a CSP 'frame-ancestors' directive.",
        "Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors none'.",
    ),
    "referrer-policy": (
        "low",
        "No Referrer-Policy header. Full URLs (which may contain sensitive data) "
        "can leak to other sites via the Referer header.",
        "Check the response headers for 'Referrer-Policy'.",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
    ),
}

_CAT = "A02:2025 Security Misconfiguration"
_REFS = ["https://owasp.org/www-project-secure-headers/"]


def _cookie_findings(where: str, set_cookie: list[str]):
    for raw in set_cookie:
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        missing = [flag for flag, tok in
                   (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite"))
                   if tok not in low]
        if not missing:
            continue
        sev = "medium" if "Secure" in missing or "HttpOnly" in missing else "low"
        yield Finding(
            title=f"Cookie '{name}' missing {', '.join(missing)}",
            severity=sev, where=where, scanner="web.headers",
            what=f"The cookie '{name}' is set without the {', '.join(missing)} "
                 f"flag(s), leaving it exposed to theft or cross-site sending.",
            how_to_check="Inspect the Set-Cookie response header for this cookie "
                         "and confirm the flags are absent.",
            evidence=f"Set-Cookie: {raw}",
            remediation="Set Secure and HttpOnly on session cookies, and "
                        "SameSite=Lax or Strict to limit cross-site sending.",
            category=_CAT, references=_REFS,
        )


@register(TargetKind.WEB, "web.headers")
def scan(target, ctx):
    site = get_sitemap(target, ctx)
    if not site.pages:
        return
    page = site.pages[0]                       # the root response speaks for the site
    where = page.url

    for header, (sev, what, how, fix) in _CHECKS.items():
        if header == "strict-transport-security" and not where.lower().startswith("https"):
            continue                            # HSTS only meaningful over HTTPS
        if header == "x-frame-options":
            csp = page.headers.get("content-security-policy", "").lower()
            if "frame-ancestors" in csp:
                continue                        # covered by CSP instead
        if header not in page.headers:
            yield Finding(title=f"Missing {header} header", severity=sev,
                          where=where, scanner="web.headers",
                          what=what, how_to_check=how, remediation=fix,
                          category=_CAT, references=_REFS)

    yield from _cookie_findings(where, page.set_cookie)


def demo() -> None:
    from types import SimpleNamespace
    from .crawler import Sitemap, Page

    ctx = SimpleNamespace(cache={}, timeout=5.0, aggressive=False, only=set())
    page = Page(url="https://site.test/", status=200,
                headers={"content-type": "text/html"},       # no security headers
                set_cookie=["sid=abc; Path=/"])              # no flags
    ctx.cache["sitemap"] = Sitemap(root="https://site.test/", pages=[page])
    target = SimpleNamespace(location="https://site.test/", kind=TargetKind.WEB)

    found = list(scan(target, ctx))
    titles = [f.title for f in found]
    assert any("content-security-policy" in t for t in titles)
    assert any("strict-transport-security" in t for t in titles)
    assert any("sid" in t and "Secure" in t for t in titles), titles
    assert all(f.remediation for f in found), "every finding must carry a fix"

    # Over plain HTTP, HSTS is not flagged (only meaningful on HTTPS).
    page.url = "http://site.test/"
    ctx.cache["sitemap"] = Sitemap(root="http://site.test/", pages=[page])
    target.location = "http://site.test/"
    titles2 = [f.title for f in scan(target, ctx)]
    assert not any("strict-transport-security" in t for t in titles2)
    print("headers.py: ok")


if __name__ == "__main__":
    demo()
