"""web.disclosure — information disclosure: exposed sensitive files + server banner.

Two read-only checks:
1. Probe a small list of well-known sensitive paths (VCS folders, env files,
   backups, status endpoints) and flag any that return content instead of 404.
2. Read the Server / X-Powered-By headers from the crawl and flag version banners
   that hand an attacker your exact software versions.

Maps to OWASP A02:2025 Security Misconfiguration. Plain GETs, nothing changed.
"""

from __future__ import annotations

import re

from ...core.engine import register
from ...core.finding import Finding
from ...core.target import TargetKind
from . import http
from .crawler import get_sitemap
from urllib.parse import urljoin

_CAT = "A02:2025 Security Misconfiguration"
_REFS = ["https://owasp.org/www-project-web-security-testing-guide/"]

# path -> (what to say, a signature that confirms it's real content not a soft-404)
_SENSITIVE = {
    "/.git/config": ("Exposed .git repository", "[core]"),
    "/.env": ("Exposed .env configuration file", "="),
    "/.htaccess": ("Exposed .htaccess file", ""),
    "/config.php.bak": ("Exposed PHP config backup", ""),
    "/server-status": ("Apache server-status page exposed", "Server Version"),
    "/phpinfo.php": ("phpinfo() page exposed", "PHP Version"),
    "/.DS_Store": ("Exposed .DS_Store file", ""),
}

# Server banners carrying a version number, e.g. "Apache/2.4.29" or "nginx/1.18.0".
_VERSIONED = re.compile(r"[a-zA-Z][\w\-]*/\d+(\.\d+)+")


@register(TargetKind.WEB, "web.disclosure")
def scan(target, ctx):
    site = get_sitemap(target, ctx)
    if not site.pages:
        return
    base = site.pages[0].url

    # 1. Sensitive files.
    for path, (title, sig) in _SENSITIVE.items():
        resp = http.fetch(urljoin(base, path), timeout=ctx.timeout)
        if resp.status != 200 or not resp.body:
            continue
        if sig and sig not in resp.body:
            continue                        # 200 but not the real file (soft-404)
        snippet = resp.body[:120].replace("\n", " ")
        yield Finding(
            title=title, severity="high", where=urljoin(base, path),
            scanner="web.disclosure",
            what="A file that should not be publicly reachable is being served. It "
                 "can leak source code, credentials, or internal configuration.",
            how_to_check=f"Open {urljoin(base, path)} in a browser — if it returns "
                         "content instead of 404, it's exposed.",
            evidence=f"HTTP 200, body starts: {snippet!r}",
            remediation="Block access to this path at the web server, and remove the "
                        "file from the web root if it doesn't belong there.",
            category=_CAT, references=_REFS,
        )

    # 2. Version-leaking server banners (from the crawl's root response).
    for header in ("server", "x-powered-by", "x-aspnet-version"):
        val = site.pages[0].headers.get(header, "")
        if val and _VERSIONED.search(val):
            yield Finding(
                title=f"Version disclosed in {header} header", severity="low",
                where=base, scanner="web.disclosure",
                what=f"The {header} header advertises exact software and version "
                     f"({val}), helping an attacker match known exploits.",
                how_to_check=f"curl -sI {base} | grep -i {header}",
                evidence=f"{header}: {val}",
                remediation="Suppress or genericise version banners "
                            "(e.g. ServerTokens Prod, server_tokens off, remove X-Powered-By).",
                category=_CAT, references=_REFS,
            )


def demo() -> None:
    assert _VERSIONED.search("Apache/2.4.29 (Ubuntu)")
    assert _VERSIONED.search("nginx/1.18.0")
    assert not _VERSIONED.search("nginx")           # no version -> not flagged
    assert not _VERSIONED.search("cloudflare")
    assert "/.git/config" in _SENSITIVE and "/.env" in _SENSITIVE
    print("disclosure.py: ok")


if __name__ == "__main__":
    demo()
