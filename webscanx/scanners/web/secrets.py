"""web.secrets — secrets and keys leaked in page responses (CWE-312).

Scans the crawled HTML/JS bodies for high-confidence secret patterns (cloud keys,
private key blocks, provider tokens). Read-only; only well-shaped patterns are
reported to keep false positives near zero.

Maps to OWASP A04:2025 Cryptographic Failures (sensitive data exposure).
"""

from __future__ import annotations

import re

from ...core.engine import register
from ...core.finding import Finding
from ...core.target import TargetKind
from .crawler import get_sitemap

_CAT = "A04:2025 Cryptographic Failures / CWE-312"
_REFS = ["https://cwe.mitre.org/data/definitions/312.html"]

# name -> compiled high-confidence pattern
_PATTERNS = {
    "AWS access key ID": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "GitHub token": re.compile(r"\bghp_[0-9A-Za-z]{36}\b"),
    "Stripe secret key": re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "JSON Web Token": re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
                                 r"\.[A-Za-z0-9_\-]{10,}\b"),
}


def _redact(s: str) -> str:
    return s[:6] + "…" + s[-4:] if len(s) > 12 else s[:4] + "…"


@register(TargetKind.WEB, "web.secrets")
def scan(target, ctx):
    site = get_sitemap(target, ctx)
    reported: set[tuple[str, str]] = set()
    for page in site.pages:
        for name, pat in _PATTERNS.items():
            m = pat.search(page.body)
            if not m:
                continue
            key = (name, page.url)
            if key in reported:
                continue
            reported.add(key)
            yield Finding(
                title=f"{name} exposed in page source", severity="high", where=page.url,
                scanner="web.secrets",
                what=f"A {name} appears in this page's response. Secrets in client-served "
                     "content are readable by anyone and must be treated as compromised.",
                how_to_check=f"View source of {page.url} and search for the value.",
                evidence=f"{name}: {_redact(m.group(0))}",
                remediation="Remove the secret from client-served code, rotate it "
                            "immediately, and keep secrets server-side / in a vault.",
                category=_CAT, references=_REFS,
            )


def demo() -> None:
    body = 'var k="AKIAIOSFODNN7EXAMPLE"; // and AIza' + "B" * 35
    assert _PATTERNS["AWS access key ID"].search(body)
    assert _PATTERNS["Google API key"].search(body)
    assert not _PATTERNS["AWS access key ID"].search("no secrets here")
    assert _redact("AKIAIOSFODNN7EXAMPLE").startswith("AKIAIO") and "…" in _redact("A" * 20)
    print("secrets.py: ok")


if __name__ == "__main__":
    demo()
