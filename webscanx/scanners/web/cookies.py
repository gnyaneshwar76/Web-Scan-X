"""web.cookies — cookie policy issues beyond the basic flags (CWE-1275 / CWE-614).

headers.py flags missing Secure/HttpOnly/SameSite. This catches the subtler
misconfigurations: SameSite=None without Secure (browsers reject it, and it's
cross-site exposed), and __Host-/__Secure- prefix rules being violated. Read-only.

Maps to OWASP A02:2025 Security Misconfiguration.
"""

from __future__ import annotations

from ...core.engine import register
from ...core.finding import Finding
from ...core.target import TargetKind
from .crawler import get_sitemap

_CAT = "A02:2025 Security Misconfiguration / CWE-1275"
_REFS = ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"]


def _attrs(raw: str) -> dict:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    flags = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        flags[k.strip().lower()] = v.strip()
    return name, flags


def _issues(name: str, flags: dict) -> list[str]:
    out = []
    has_secure = "secure" in flags
    samesite = flags.get("samesite", "").lower()
    if samesite == "none" and not has_secure:
        out.append("SameSite=None without Secure — browsers reject it and it is sent "
                   "cross-site")
    if name.startswith("__Host-"):
        if not has_secure or flags.get("path") != "/" or "domain" in flags:
            out.append("__Host- prefix requires Secure, Path=/, and no Domain")
    if name.startswith("__Secure-") and not has_secure:
        out.append("__Secure- prefix requires the Secure attribute")
    return out


@register(TargetKind.WEB, "web.cookies")
def scan(target, ctx):
    site = get_sitemap(target, ctx)
    if not site.pages:
        return
    page = site.pages[0]
    for raw in page.set_cookie:
        name, flags = _attrs(raw)
        for issue in _issues(name, flags):
            yield Finding(
                title=f"Cookie '{name}': {issue.split(' —')[0].split(' requires')[0]}",
                severity="medium", where=page.url, scanner="web.cookies",
                what=f"The cookie '{name}' has a policy problem: {issue}.",
                how_to_check="Inspect the Set-Cookie response header for this cookie.",
                evidence=f"Set-Cookie: {raw}",
                remediation="Set Secure whenever SameSite=None, and follow the "
                            "__Host-/__Secure- prefix rules (Secure, Path=/, no Domain).",
                category=_CAT, references=_REFS,
            )


def demo() -> None:
    n, f = _attrs("sid=abc; SameSite=None; Path=/")
    assert n == "sid" and _issues(n, f)              # None without Secure -> flagged
    n, f = _attrs("__Host-sess=1; Secure; Path=/")
    assert _issues(n, f) == []                        # correct __Host- cookie
    n, f = _attrs("__Host-sess=1; Secure; Path=/; Domain=x.com")
    assert _issues(n, f)                              # Domain violates __Host-
    n, f = _attrs("ok=1; Secure; SameSite=Lax")
    assert _issues(n, f) == []
    print("cookies.py: ok")


if __name__ == "__main__":
    demo()
