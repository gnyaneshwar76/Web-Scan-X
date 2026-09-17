"""code.crypto — weak cryptography and insecure randomness (CWE-327 / CWE-338).

Flags broken/legacy algorithms (MD5, SHA-1, DES, RC4, ECB mode) and the use of
non-cryptographic randomness for security values (tokens, passwords, OTPs).

Maps to OWASP A04:2025 Cryptographic Failures.
"""

from __future__ import annotations

import re

from ...core.engine import register
from ...core.target import TargetKind
from ._rules import Rule, run_rules

_CAT = "A04:2025 Cryptographic Failures / CWE-327"
_RNG = "A04:2025 Cryptographic Failures / CWE-338"
_REFS = ("https://cwe.mitre.org/data/definitions/327.html",)

RULES = [
    Rule(re.compile(r"\bhashlib\.(md5|sha1)\s*\(|\bMD5\b|\bSHA-?1\b|CryptoJS\.(MD5|SHA1)"),
         "Weak hash algorithm (MD5/SHA-1)", "medium", _CAT,
         "MD5/SHA-1 are broken for security use (collisions, fast brute force).",
         "Use SHA-256+ for integrity, and bcrypt/scrypt/argon2 for passwords.",
         _REFS),
    Rule(re.compile(r"\bDES\b|\bRC4\b|\b3DES\b|MODE_ECB|\bECB\b"),
         "Weak cipher or ECB mode", "medium", _CAT,
         "DES/RC4/3DES are obsolete and ECB mode leaks plaintext structure.",
         "Use AES-GCM (or another authenticated mode); never ECB.",
         _REFS),
    Rule(re.compile(r"(?i)(token|secret|password|otp|nonce|api[_-]?key|session)"
                    r".{0,30}\b(random\.(random|randint|choice|randrange)|Math\.random)"
                    r"|(random\.(random|randint|choice|randrange)|Math\.random)"
                    r".{0,30}(token|secret|password|otp|nonce|session)"),
         "Insecure randomness for a security value", "medium", _RNG,
         "Non-cryptographic RNG (random / Math.random) is predictable; unsafe for "
         "tokens, passwords, or OTPs.",
         "Use secrets (Python) or crypto.randomBytes / getRandomValues (JS).",
         _REFS),
]


@register(TargetKind.CODE, "code.crypto")
def scan(target, ctx):
    yield from run_rules(target, ctx, "code.crypto", RULES)


def demo() -> None:
    assert RULES[0].pattern.search("h = hashlib.md5(data).hexdigest()")
    assert RULES[1].pattern.search("cipher = AES.new(key, AES.MODE_ECB)")
    assert RULES[2].pattern.search("token = str(random.randint(0, 9999))")
    assert RULES[2].pattern.search("const otp = Math.random()")
    assert not RULES[0].pattern.search("hashlib.sha256(x)")   # strong hash: fine
    print("code/crypto.py: ok")


if __name__ == "__main__":
    demo()
