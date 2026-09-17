"""web.csrf — Cross-Site Request Forgery form audit (CWE-352).

Pure audit: it reads the forms the crawler already found and flags any
state-changing (POST) form with no anti-CSRF token field. Sends no requests of
its own. CSRF is framework-solved and no longer a standalone OWASP Top 10 entry,
but a tokenless POST form is still a real, testable gap — so it's tagged by CWE.

The crawler already sets Form.has_token from field names (csrf/xsrf/token/...);
this module turns the absence into a finding with the full explanation.
"""

from __future__ import annotations

from ...core.engine import register
from ...core.finding import Finding
from ...core.target import TargetKind
from .crawler import get_sitemap

_CAT = "CWE-352 (Cross-Site Request Forgery)"
_REFS = ["https://owasp.org/www-community/attacks/csrf",
         "https://cwe.mitre.org/data/definitions/352.html"]


@register(TargetKind.WEB, "web.csrf")
def scan(target, ctx):
    site = get_sitemap(target, ctx)
    for form in site.forms:
        if form.method != "POST":
            continue                    # GET forms don't change state -> not CSRF
        if form.has_token:
            continue
        yield Finding(
            title="Form without anti-CSRF token", severity="medium",
            where=f"{form.action_url} (on {form.source_url})", scanner="web.csrf",
            what="This form changes state (POST) but carries no anti-CSRF token, so "
                 "another site can force a logged-in user's browser to submit it "
                 "without their intent.",
            how_to_check="Inspect the form's fields: no hidden token (csrf/xsrf/"
                         "authenticity) means the request can be forged from off-site.",
            evidence=f"POST form to {form.action_url}; fields: "
                     f"{', '.join(form.fields) or '(none)'}",
            remediation="Add a per-session/per-request anti-CSRF token and verify it "
                        "server-side; set SameSite=Lax or Strict on session cookies. "
                        "Most frameworks provide this — enable it.",
            category=_CAT, references=_REFS,
        )


def demo() -> None:
    from types import SimpleNamespace
    from .crawler import Sitemap, Form

    ctx = SimpleNamespace(cache={}, timeout=5.0, aggressive=False, only=set())
    forms = [
        Form(action_url="http://s/login", method="POST", fields=["u", "p"],
             has_token=False, source_url="http://s/"),          # flagged
        Form(action_url="http://s/comment", method="POST", fields=["b", "csrf_token"],
             has_token=True, source_url="http://s/"),           # ok, has token
        Form(action_url="http://s/search", method="GET", fields=["q"],
             has_token=False, source_url="http://s/"),          # GET, not state-changing
    ]
    ctx.cache["sitemap"] = Sitemap(root="http://s/", forms=forms)
    target = SimpleNamespace(location="http://s/", kind=TargetKind.WEB)

    found = list(scan(target, ctx))
    assert len(found) == 1, [f.where for f in found]
    assert "login" in found[0].where and found[0].severity.label == "Medium"
    assert found[0].remediation
    print("csrf.py: ok")


if __name__ == "__main__":
    demo()
