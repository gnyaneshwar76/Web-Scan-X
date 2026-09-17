"""code.injection — dangerous execution, command/SQL injection, unsafe deserialization.

Pattern-matches the classic sinks where untrusted input turns into code, a shell
command, a query, or an object. Covers Python and JS/TS. Static: it flags the
sink; whether input reaches it is for the reviewer to confirm.

Categories: CWE-95 (eval), CWE-78 (command), CWE-89 (SQL), CWE-502 (deserialization).
"""

from __future__ import annotations

import re

from ...core.engine import register
from ...core.target import TargetKind
from ._rules import Rule, run_rules

_PY = frozenset({".py", ".pyw"})
_JS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"})
_REFS = ("https://owasp.org/www-community/Injection_Flaws",)

RULES = [
    Rule(re.compile(r"\beval\s*\(|\bexec\s*\("), "Use of eval()/exec()", "high",
         "A05:2025 Injection / CWE-95",
         "eval()/exec() run their argument as code; with any untrusted input this "
         "is remote code execution.",
         "Avoid dynamic evaluation; use explicit parsing (ast.literal_eval, JSON).",
         _REFS, exts=_PY),
    Rule(re.compile(r"\bos\.system\s*\(|subprocess\.[a-z_]+\([^)]*shell\s*=\s*True"),
         "Shell command execution", "high", "A05:2025 Injection / CWE-78",
         "Building shell commands (os.system / shell=True) invites command injection "
         "when input is interpolated.",
         "Use subprocess with a list of args and shell=False; never interpolate input.",
         _REFS, exts=_PY),
    Rule(re.compile(r"\b(pickle|cPickle|dill)\.loads?\s*\(|yaml\.load\s*\((?![^)]*Safe)"),
         "Unsafe deserialization", "high", "A08:2025 / CWE-502",
         "pickle/dill and yaml.load execute arbitrary objects on untrusted data.",
         "Use yaml.safe_load and a safe format (JSON) for untrusted input.",
         _REFS, exts=_PY),
    Rule(re.compile(r"""\.execute\s*\(\s*(?:f["']|["'][^"']*["']\s*(?:%|\+)|.*%\s*\()""",
                    re.VERBOSE),
         "Possible SQL injection (string-built query)", "high",
         "A05:2025 Injection / CWE-89",
         "A SQL query is assembled with f-strings/%/+ instead of parameters, so "
         "input can alter the query.",
         "Use parameterised queries (execute(sql, params)); never format SQL with input.",
         _REFS, exts=_PY),
    Rule(re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|child_process\.[a-z]*exec\s*\("),
         "Dangerous dynamic execution", "high", "A05:2025 Injection / CWE-95",
         "eval / new Function / child_process.exec run strings as code or shell "
         "commands — RCE with untrusted input.",
         "Avoid dynamic code; use execFile with an args array for processes.",
         _REFS, exts=_JS),
    Rule(re.compile(r"\.innerHTML\s*=|dangerouslySetInnerHTML"),
         "Unsafe HTML sink (DOM XSS)", "medium", "A05:2025 Injection / CWE-79",
         "Assigning untrusted data to innerHTML / dangerouslySetInnerHTML injects "
         "script into the page.",
         "Use textContent, or sanitise with a vetted library before inserting HTML.",
         _REFS, exts=_JS),
]


@register(TargetKind.CODE, "code.injection")
def scan(target, ctx):
    yield from run_rules(target, ctx, "code.injection", RULES)


def demo() -> None:
    def hit(rx, s):
        return bool(rx.search(s))
    assert hit(RULES[0].pattern, "result = eval(user_input)")
    assert hit(RULES[1].pattern, "os.system('ping ' + host)")
    assert hit(RULES[1].pattern, "subprocess.run(cmd, shell=True)")
    assert hit(RULES[2].pattern, "data = pickle.loads(blob)")
    assert not hit(RULES[2].pattern, "yaml.load(x, Loader=yaml.SafeLoader)")
    assert hit(RULES[3].pattern, 'cur.execute(f"select * from t where id={i}")')
    assert hit(RULES[4].pattern, "child_process.exec(cmd)")
    assert hit(RULES[5].pattern, "el.innerHTML = data")
    print("code/injection.py: ok")


if __name__ == "__main__":
    demo()
