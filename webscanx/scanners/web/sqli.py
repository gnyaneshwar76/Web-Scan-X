"""web.sqli — error-based SQL injection (CWE-89, OWASP A05:2025 Injection).

The loop: send a syntax-breaking probe (a single quote), read the response,
decide on a database error signature leaking back. A leaked SQL error proves the
input reached the query builder unsanitised. This is the shallow, high-confidence
class only — blind/boolean/time-based SQLi is out of scope this phase.

Safe by default: a lone quote is read-only. GET params/forms always probed;
POST forms only under --aggressive. To cut false positives, the probe is only
flagged when the quote version errors AND a benign control value does not.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from ...core.engine import register
from ...core.finding import Finding
from ...core.target import TargetKind
from . import http
from .crawler import get_sitemap

_CAT = "A05:2025 Injection / CWE-89"
_REFS = ["https://owasp.org/www-community/attacks/SQL_Injection",
         "https://cwe.mitre.org/data/definitions/89.html"]

# DB error signatures across common engines — a strong tell of error-based SQLi.
_ERROR_SIGNATURES = re.compile(
    r"SQL syntax.*MySQL|Warning.*\bmysqli?_|MySqlException|"
    r"valid MySQL result|PostgreSQL.*ERROR|pg_query\(\)|PG::SyntaxError|"
    r"SQLite/JDBCDriver|SQLite3::|sqlite3.OperationalError|"
    r"Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver|"
    r"Unclosed quotation mark after the character string|"
    r"ORA-\d{5}|Oracle error|quoted string not properly terminated",
    re.IGNORECASE)

_BREAK = "'"          # the syntax-breaking probe
_CONTROL = "1"        # benign control: should NOT error


def _errored(body: str) -> str | None:
    m = _ERROR_SIGNATURES.search(body or "")
    return m.group(0) if m else None


def _finding(where: str, signature: str) -> Finding:
    return Finding(
        title="SQL injection (error-based)", severity="high", where=where,
        scanner="web.sqli",
        what="Input here reaches a database query unsanitised: a single quote "
             "produced a database error, meaning an attacker could read or alter "
             "the database, bypass logins, or exfiltrate data.",
        how_to_check="Append a single quote (') to the value and resend. A raw SQL "
                     "error in the response confirms it.",
        evidence=f"Probe ' triggered a DB error: {signature}",
        remediation="Use parameterised queries / prepared statements (never string "
                    "concatenation), validate input, and hide raw DB errors from users.",
        category=_CAT, references=_REFS,
    )


def _set_param(url: str, name: str, value: str) -> str:
    parts = urlparse(url)
    q = [(k, value if k == name else v) for k, v in parse_qsl(parts.query)]
    return urlunparse(parts._replace(query=urlencode(q)))


def _probe_url_param(url: str, name: str, timeout: float) -> Finding | None:
    broken = http.fetch(_set_param(url, name, _BREAK), timeout=timeout)
    sig = _errored(broken.body) if broken.ok else None
    if not sig:
        return None
    control = http.fetch(_set_param(url, name, _CONTROL), timeout=timeout)
    if control.ok and _errored(control.body):
        return None                     # errors regardless of input -> not our signal
    return _finding(f"{url} (param: {name})", sig)


def _probe_form(form, timeout: float) -> Finding | None:
    def send(value):
        data = {f: value for f in form.fields}
        if form.method == "GET":
            parts = urlparse(form.action_url)
            return http.fetch(urlunparse(parts._replace(query=urlencode(data))),
                              timeout=timeout)
        return http.fetch(form.action_url, method="POST", data=data, timeout=timeout)

    broken = send(_BREAK)
    sig = _errored(broken.body) if broken.ok else None
    if not sig:
        return None
    control = send(_CONTROL)
    if control.ok and _errored(control.body):
        return None
    return _finding(f"{form.action_url} (form: {form.method})", sig)


@register(TargetKind.WEB, "web.sqli")
def scan(target, ctx):
    site = get_sitemap(target, ctx)

    for url, name in site.params:
        f = _probe_url_param(url, name, ctx.timeout)
        if f:
            yield f

    for form in site.forms:
        if form.method == "POST" and not ctx.aggressive:
            continue
        if not form.fields:
            continue
        f = _probe_form(form, ctx.timeout)
        if f:
            yield f


def demo() -> None:
    # Signature detection is offline-testable.
    mysql_err = "You have an error in your SQL syntax; check the MySQL server manual"
    assert _errored(mysql_err)
    assert _errored("ORA-00933: SQL command not properly ended")
    assert _errored("Warning: pg_query(): PostgreSQL ERROR: unterminated string")
    assert _errored("<p>3 results found</p>") is None, "normal page must not flag"
    assert _set_param("http://x/?id=1&p=2", "id", "'") == "http://x/?id=%27&p=2"
    f = _finding("http://x/?id=", "MySQL")
    assert f.severity.label == "High" and "parameterised" in f.remediation
    print("sqli.py: ok")


if __name__ == "__main__":
    demo()
