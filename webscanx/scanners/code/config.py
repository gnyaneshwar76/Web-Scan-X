"""code.config — insecure configuration in source (CWE-489 / CWE-295 / CWE-942).

Flags settings that weaken security: debug mode in production, disabled TLS
verification, and wide-open CORS declared in code.

Maps to OWASP A02:2025 Security Misconfiguration.
"""

from __future__ import annotations

import re

from ...core.engine import register
from ...core.target import TargetKind
from ._rules import Rule, run_rules

_REFS = ("https://owasp.org/www-project-top-ten/",)

RULES = [
    Rule(re.compile(r"debug\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|"
                    r"\bDEBUG\s*=\s*True\b", re.IGNORECASE),
         "Debug mode enabled", "medium", "A02:2025 Security Misconfiguration / CWE-489",
         "Debug mode exposes stack traces, an interactive console, and internal "
         "details — dangerous in production.",
         "Disable debug in production; drive it from an environment variable.",
         _REFS),
    Rule(re.compile(r"verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False|"
                    r"rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true"),
         "TLS verification disabled", "high",
         "A04:2025 Cryptographic Failures / CWE-295",
         "Disabling certificate verification allows man-in-the-middle attacks.",
         "Keep TLS verification on; trust a proper CA or pin the expected cert.",
         _REFS),
    Rule(re.compile(r"""Access-Control-Allow-Origin["'\s:=]+\*|"""
                    r"""allow_origins\s*=\s*\[\s*["']\*["']|cors\([^)]*origin\s*:\s*["']\*"""),
         "Wildcard CORS in code", "medium",
         "A02:2025 Security Misconfiguration / CWE-942",
         "Allowing any origin ('*') lets untrusted sites call this service.",
         "Restrict CORS to an explicit allow-list of trusted origins.",
         _REFS),
]


@register(TargetKind.CODE, "code.config")
def scan(target, ctx):
    yield from run_rules(target, ctx, "code.config", RULES)


def demo() -> None:
    assert RULES[0].pattern.search("app.run(host='0.0.0.0', debug=True)")
    assert RULES[0].pattern.search("DEBUG = True")
    assert RULES[1].pattern.search("requests.get(url, verify=False)")
    assert RULES[1].pattern.search("rejectUnauthorized: false")
    assert RULES[2].pattern.search('res.header("Access-Control-Allow-Origin: *")')
    assert not RULES[1].pattern.search("verify=True")
    print("code/config.py: ok")


if __name__ == "__main__":
    demo()
