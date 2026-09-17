"""code.secrets — hardcoded secrets and credentials in source (CWE-798).

Flags high-confidence key/token shapes and quoted credential assignments. Values
sourced from the environment (os.getenv, process.env, ${...}) are skipped, since
those aren't hardcoded.

Maps to OWASP A04:2025 Cryptographic Failures / hardcoded credentials.
"""

from __future__ import annotations

import re

from ...core.engine import register
from ...core.target import TargetKind
from ._rules import Rule, run_rules

_CAT = "A04:2025 / CWE-798 (Hardcoded Credentials)"
_REFS = ("https://cwe.mitre.org/data/definitions/798.html",)

# Skip lines that clearly read from config/env rather than hardcode a literal.
_FROM_ENV = re.compile(r"getenv|os\.environ|process\.env|\$\{|<%=|import |require\(",
                       re.IGNORECASE)

RULES = [
    Rule(re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "Hardcoded AWS access key", "high",
         _CAT, "An AWS access key ID is committed in source.",
         "Remove it, rotate the key, and load credentials from the environment "
         "or a secrets manager.", _REFS),
    Rule(re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Hardcoded Google API key", "high",
         _CAT, "A Google API key is committed in source.",
         "Remove it, rotate the key, and restrict/segregate it via config.", _REFS),
    Rule(re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
         "Private key committed", "critical", _CAT,
         "A private key block is present in source.",
         "Remove and rotate the key immediately; never commit private keys.", _REFS),
    Rule(re.compile(r"\bghp_[0-9A-Za-z]{36}\b|\bxox[baprs]-[0-9A-Za-z-]{10,}\b|"
                    r"\bsk_live_[0-9A-Za-z]{24,}\b"),
         "Hardcoded provider token", "high", _CAT,
         "A GitHub/Slack/Stripe-style token is committed in source.",
         "Remove it, rotate the token, and move it to a secret store.", _REFS),
    # Generic quoted credential assignment, skipping env-sourced lines.
    Rule(re.compile(r"""(?ix)\b(pass(word|wd)?|secret|api[_-]?key|access[_-]?key|
                        auth[_-]?token|token)\b\s*[:=]\s*["'][^"'$\s]{6,}["']""",
                    re.VERBOSE),
         "Hardcoded credential", "high", _CAT,
         "A password/secret/token is assigned a literal string in source.",
         "Load secrets from environment variables or a secrets manager; never hardcode.",
         _REFS, negate=_FROM_ENV),
]


@register(TargetKind.CODE, "code.secrets")
def scan(target, ctx):
    yield from run_rules(target, ctx, "code.secrets", RULES)


def demo() -> None:
    r = RULES[-1]  # generic assignment rule
    assert r.pattern.search('password = "hunter2secret"')
    assert not r.pattern.search('password = os.getenv("PW")') or r.negate.search(
        'password = os.getenv("PW")')
    assert RULES[0].pattern.search("key = 'AKIAIOSFODNN7EXAMPLE'")
    assert not RULES[0].pattern.search("just some text")
    print("code/secrets.py: ok")


if __name__ == "__main__":
    demo()
