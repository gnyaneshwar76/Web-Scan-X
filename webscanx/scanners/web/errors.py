"""web.errors — verbose errors / stack traces / debug pages (CWE-209).

Scans crawled bodies for framework stack traces and debug output that leak
internal paths, queries, and versions. Read-only. DB error strings are handled
by web.sqli; this catches the broader language/framework signatures.

Maps to OWASP A02:2025 Security Misconfiguration.
"""

from __future__ import annotations

import re

from ...core.engine import register
from ...core.finding import Finding
from ...core.target import TargetKind
from .crawler import get_sitemap

_CAT = "A02:2025 Security Misconfiguration / CWE-209"
_REFS = ["https://cwe.mitre.org/data/definitions/209.html"]

# signature -> human name (kept specific to avoid flagging ordinary prose)
_SIGNATURES = [
    (re.compile(r"Traceback \(most recent call last\)"), "Python traceback"),
    (re.compile(r"Werkzeug Debugger|werkzeug\.debug"), "Werkzeug debugger"),
    (re.compile(r"<b>(?:Fatal error|Warning|Notice)</b>:|on line <b>\d+</b>"), "PHP error"),
    (re.compile(r"\bat [\w.$]+\([\w.]+\.java:\d+\)"), "Java stack trace"),
    (re.compile(r"System\.[\w.]+Exception|\bat [\w.]+\(\) in .+:line \d+"), ".NET stack trace"),
    (re.compile(r"Ruby on Rails.*?(?:exception|error)|actionpack \(", re.I), "Rails error"),
    (re.compile(r"Whoops\\?Exception|stack trace:", re.I), "framework debug page"),
    (re.compile(r"Node\.js.*?\n\s+at .+:\d+:\d+", re.S), "Node.js stack trace"),
]


@register(TargetKind.WEB, "web.errors")
def scan(target, ctx):
    site = get_sitemap(target, ctx)
    reported: set[tuple[str, str]] = set()
    for page in site.pages:
        for pat, name in _SIGNATURES:
            m = pat.search(page.body)
            if not m:
                continue
            key = (name, page.url)
            if key in reported:
                continue
            reported.add(key)
            snippet = m.group(0)[:100].replace("\n", " ")
            yield Finding(
                title=f"Verbose error exposed ({name})", severity="low",
                where=page.url, scanner="web.errors",
                what="The page reveals a stack trace or debug output. These leak file "
                     "paths, framework versions, and internal logic that help an attacker.",
                how_to_check=f"Open {page.url} — a raw stack trace or debug page instead "
                             "of a friendly error confirms it.",
                evidence=f"Matched {name}: {snippet!r}",
                remediation="Turn off debug mode in production and return generic error "
                            "pages; log details server-side only.",
                category=_CAT, references=_REFS,
            )


def demo() -> None:
    def hit(text):
        return any(p.search(text) for p, _ in _SIGNATURES)
    assert hit("Traceback (most recent call last):\n  File ...")
    assert hit("<b>Fatal error</b>: Uncaught Error in /var/www on line <b>42</b>")
    assert hit("at com.app.Main(Main.java:88)")
    assert not hit("<p>Welcome to our shop</p>")          # ordinary page: nothing
    print("errors.py: ok")


if __name__ == "__main__":
    demo()
