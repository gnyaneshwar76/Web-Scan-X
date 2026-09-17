"""web.methods — dangerous HTTP methods enabled (CWE-650).

Sends an OPTIONS request to read the advertised Allow list, and a TRACE request
to detect Cross-Site Tracing. Both are read-only; it never sends PUT/DELETE
itself — it only reports them as risky when the server advertises them.

Maps to OWASP A02:2025 Security Misconfiguration.
"""

from __future__ import annotations

from ...core.engine import register
from ...core.finding import Finding
from ...core.target import TargetKind
from . import http
from .crawler import get_sitemap

_CAT = "A02:2025 Security Misconfiguration / CWE-650"
_REFS = ["https://owasp.org/www-project-web-security-testing-guide/"
         "latest/4-Web_Application_Security_Testing/"
         "02-Configuration_and_Deployment_Management_Testing/"
         "06-Test_HTTP_Methods"]

_RISKY = {"PUT", "DELETE", "PATCH", "CONNECT", "TRACE", "TRACK"}


@register(TargetKind.WEB, "web.methods")
def scan(target, ctx):
    site = get_sitemap(target, ctx)
    url = site.pages[0].url if site.pages else target.location

    options = http.fetch(url, method="OPTIONS", timeout=ctx.timeout)
    allow = options.headers.get("allow", "")
    advertised = {m.strip().upper() for m in allow.split(",") if m.strip()}
    risky = sorted(advertised & _RISKY)
    if risky:
        yield Finding(
            title=f"Risky HTTP methods enabled: {', '.join(risky)}",
            severity="medium", where=url, scanner="web.methods",
            what="The server advertises write/diagnostic HTTP methods that most sites "
                 "don't need. Left enabled they widen the attack surface (file upload, "
                 "deletion, request tracing).",
            how_to_check=f"curl -s -i -X OPTIONS {url} | grep -i allow",
            evidence=f"Allow: {allow}",
            remediation="Disable methods the application doesn't use; typically allow "
                        "only GET, HEAD, POST (and OPTIONS for CORS).",
            category=_CAT, references=_REFS,
        )

    # Active TRACE probe -> Cross-Site Tracing (XST).
    trace = http.fetch(url, method="TRACE", timeout=ctx.timeout)
    if trace.status == 200 and "TRACE" in trace.body.upper():
        yield Finding(
            title="HTTP TRACE enabled (Cross-Site Tracing)", severity="medium",
            where=url, scanner="web.methods",
            what="TRACE echoes the request back, which can be abused to read cookies "
                 "or auth headers even when HttpOnly is set (Cross-Site Tracing).",
            how_to_check=f"curl -s -i -X TRACE {url} — a 200 that echoes the request "
                         "confirms it.",
            evidence=f"TRACE returned {trace.status} and echoed the request.",
            remediation="Disable the TRACE method at the web server / load balancer.",
            category=_CAT, references=_REFS,
        )


def demo() -> None:
    allow = "GET, POST, PUT, DELETE, OPTIONS"
    advertised = {m.strip().upper() for m in allow.split(",")}
    risky = sorted(advertised & _RISKY)
    assert risky == ["DELETE", "PUT"], risky
    assert not ({"GET", "POST", "HEAD", "OPTIONS"} & _RISKY)  # safe set: nothing
    print("methods.py: ok")


if __name__ == "__main__":
    demo()
