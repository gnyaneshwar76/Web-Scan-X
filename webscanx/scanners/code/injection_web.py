"""code.injection_web — PHP and Java/JSP sinks where request data reaches a dangerous call.

Defensive pattern checks on your own source. Each rule flags the sink on the same
line as request input; whether it is really exploitable is for the reviewer to confirm.
Registered as its own scanner so `--only code.injection_web` works.
"""

from __future__ import annotations

import re

from ...core.engine import register
from ...core.target import TargetKind
from ._rules import Rule, run_rules

_PHP = frozenset({".php", ".phtml"})
_JAVA = frozenset({".jsp", ".jspx", ".java"})
_REQ = r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)"
_REFS = ("https://owasp.org/www-community/Injection_Flaws",)
_INJ = "A05:2025 Injection / "

RULES = [
    Rule(re.compile(r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\([^;\n]*" + _REQ),
         "PHP: request data in a shell command", "high", _INJ + "CWE-78",
         "Request input is passed to a command-running function, which allows command injection.",
         "Never build commands from input; use fixed commands and escapeshellarg() on each argument.",
         _REFS, exts=_PHP),
    Rule(re.compile(r"\b(?:include|include_once|require|require_once)\b[^;\n]*" + _REQ),
         "PHP: request data in include/require", "high", _INJ + "CWE-98",
         "Including a file named by request input can load attacker-chosen code or files.",
         "Map input to a fixed allow-list of files; never include a user-supplied path.",
         _REFS, exts=_PHP),
    Rule(re.compile(r"\b(?:eval|assert)\s*\([^;\n]*(?:" + _REQ + r"|\$[A-Za-z_]+)"),
         "PHP: eval() on a variable", "high", _INJ + "CWE-95",
         "eval()/assert() on a variable runs it as PHP code; with request data this is remote code execution.",
         "Remove dynamic evaluation; use explicit logic or a safe parser.",
         _REFS, exts=_PHP),
    Rule(re.compile(r"\bunserialize\s*\([^;\n]*" + _REQ),
         "PHP: unserialize() on request data", "high", "A08:2025 / CWE-502",
         "unserialize() on untrusted data can create attacker-chosen objects.",
         "Use json_decode for untrusted data, or unserialize with allowed_classes => false.",
         _REFS, exts=_PHP),
    Rule(re.compile(r"\b(?:mysql_query|mysqli_query|->query|->exec)\s*\([^;\n]*(?:\.\s*" + _REQ + r"|\"[^\"\n]*" + _REQ + ")"),
         "PHP: SQL built from request data", "high", _INJ + "CWE-89",
         "A SQL query includes request input directly, so input can change the query.",
         "Use prepared statements (PDO or mysqli) with bound parameters.",
         _REFS, exts=_PHP),
    Rule(re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\([^)]*\+"),
         "Java: command execution with a built string", "high", _INJ + "CWE-78",
         "Running a command assembled from strings allows command injection when input is included.",
         "Pass arguments as a fixed list; never concatenate input into a command.",
         _REFS, exts=_JAVA),
    Rule(re.compile(r"\.(?:executeQuery|executeUpdate|execute)\s*\([^;\n]*\"\s*\+"),
         "Java: SQL built by concatenation", "high", _INJ + "CWE-89",
         "A SQL string is joined with + instead of using a PreparedStatement.",
         "Use PreparedStatement with ? placeholders.",
         _REFS, exts=_JAVA),
    Rule(re.compile(r"<%=\s*request\.getParameter|out\.print(?:ln)?\s*\(\s*request\.getParameter"),
         "JSP: request parameter written to the page", "medium", _INJ + "CWE-79",
         "A request parameter is printed into the page without encoding (cross-site scripting).",
         "Encode output (JSTL <c:out> or the OWASP Java Encoder) before writing it.",
         _REFS, exts=_JAVA),
]


@register(TargetKind.CODE, "code.injection_web")
def scan(target, ctx):
    yield from run_rules(target, ctx, "code.injection_web", RULES)


def demo() -> None:
    def hit(i, s):
        return bool(RULES[i].pattern.search(s))
    assert hit(0, 'system("ping " . $_GET["h"]);') and not hit(0, 'system("uptime");')
    assert hit(1, 'include($_GET["page"] . ".php");') and not hit(1, 'include "header.php";')
    assert hit(2, "eval($code);") and not hit(2, 'eval("1+1");')
    assert hit(3, 'unserialize($_COOKIE["s"]);')
    assert hit(4, 'mysqli_query($c, "select * from t where id=" . $_GET["id"]);')
    assert hit(5, "Runtime.getRuntime().exec(cmd);")
    assert hit(6, 'st.executeQuery("select * from t where id=" + id);')
    assert not hit(6, "ps.executeQuery();")
    assert hit(7, '<%= request.getParameter("q") %>')
    print("code/injection_web.py: ok")


if __name__ == "__main__":
    demo()
