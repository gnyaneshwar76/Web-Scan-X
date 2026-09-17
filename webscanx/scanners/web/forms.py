"""web.forms — credential forms that transmit insecurely (CWE-319).

Reads the crawled forms and flags any that carry a password-like field but submit
over cleartext HTTP, or over GET (which puts the password in the URL, logs, and
history). Read-only (uses the existing crawl).

Maps to OWASP A04:2025 Cryptographic Failures.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ...core.engine import register
from ...core.finding import Finding
from ...core.target import TargetKind
from .crawler import get_sitemap

_CAT = "A04:2025 Cryptographic Failures / CWE-319"
_REFS = ["https://cwe.mitre.org/data/definitions/319.html"]

_PW_HINTS = ("pass", "pwd", "passwd", "password")


def _has_password(fields) -> bool:
    return any(any(h in f.lower() for h in _PW_HINTS) for f in fields)


@register(TargetKind.WEB, "web.forms")
def scan(target, ctx):
    site = get_sitemap(target, ctx)
    seen: set[str] = set()
    for form in site.forms:
        if not _has_password(form.fields) or form.action_url in seen:
            continue
        seen.add(form.action_url)
        insecure_action = urlparse(form.action_url).scheme == "http"
        via_get = form.method == "GET"
        if not (insecure_action or via_get):
            continue
        reason = ("submits over plain HTTP" if insecure_action else
                  "submits via GET, placing the password in the URL")
        yield Finding(
            title="Password form transmitted insecurely", severity="high",
            where=f"{form.action_url} (on {form.source_url})", scanner="web.forms",
            what=f"A form containing a password field {reason}. Credentials can be "
                 "intercepted in transit or leaked through browser history, proxies, "
                 "and server logs.",
            how_to_check="Inspect the form's action URL and method; a password field "
                         "with an http:// action or method=GET confirms it.",
            evidence=f"method={form.method}, action={form.action_url}, "
                     f"fields={', '.join(form.fields)}",
            remediation="Submit credential forms over HTTPS using POST; never place "
                        "secrets in a GET query string.",
            category=_CAT, references=_REFS,
        )


def demo() -> None:
    from .crawler import Form
    assert _has_password(["user", "password"]) and not _has_password(["q"])
    http_form = Form("http://s/login", "POST", ["user", "pass"], False, "http://s/")
    get_form = Form("https://s/login", "GET", ["user", "password"], False, "https://s/")
    ok_form = Form("https://s/login", "POST", ["user", "password"], False, "https://s/")
    assert urlparse(http_form.action_url).scheme == "http"     # insecure action
    assert get_form.method == "GET"                            # password via GET
    assert urlparse(ok_form.action_url).scheme == "https" and ok_form.method == "POST"
    print("forms.py: ok")


if __name__ == "__main__":
    demo()
