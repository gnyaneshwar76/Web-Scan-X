"""The one unit every scanner produces and every renderer consumes.

The whole tool hangs off this: a scanner's only job is to return Findings, a
report is just a list of Findings plus metadata, and every export format is a
function that turns Findings into bytes. Keep this schema stable — adding a
platform must never require changing it.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any


class Severity(enum.IntEnum):
    """Ordered so findings sort worst-first with `sorted(..., reverse=True)`."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def parse(cls, value: str | int | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]

    # Only low/medium (and info) are ever eligible for auto-fix; high/critical
    # are always flagged for a human. See fix/fixer.py (Phase 3).
    @property
    def auto_fixable(self) -> bool:
        return self <= Severity.MEDIUM


@dataclass
class Finding:
    """One problem, everything a reader needs to understand and act on it.

    Fields mirror the plan's promise: severity, category, exactly where, a
    plain-language explanation, how to check it by hand, the evidence, how to
    fix it, and whether we already did.
    """

    title: str
    severity: Severity
    where: str                       # url + parameter, or file:line, or manifest key
    scanner: str                     # which module found it, e.g. "web.headers"
    what: str = ""                   # plain-language: what the problem is
    how_to_check: str = ""           # plain-language: verify it yourself
    evidence: str = ""               # the proof: payload sent / response snippet / code
    remediation: str = ""            # how to fix it
    category: str = ""               # OWASP / CWE tag, e.g. "A03:2021 / CWE-79"
    references: list[str] = field(default_factory=list)
    fixed: bool = False              # did the fixer apply a change for this?
    fingerprint: str = ""            # dedupe key; auto-derived if left blank

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)
        if not self.fingerprint:
            self.fingerprint = self._derive_fingerprint()

    def _derive_fingerprint(self) -> str:
        # Same flaw at the same place from the same scanner = one finding.
        basis = f"{self.scanner}|{self.title}|{self.where}".encode("utf-8", "replace")
        return hashlib.sha1(basis).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d


def demo() -> None:
    """Self-check: ordering, auto-fix eligibility, dedupe fingerprints."""
    order = sorted(
        [Severity.LOW, Severity.CRITICAL, Severity.INFO, Severity.HIGH],
        reverse=True,
    )
    assert order[0] is Severity.CRITICAL and order[-1] is Severity.INFO, order

    assert Severity.parse("high") is Severity.HIGH
    assert Severity.parse(2) is Severity.MEDIUM
    assert Severity.MEDIUM.auto_fixable and not Severity.HIGH.auto_fixable

    a = Finding("Reflected XSS", "high", "/search?q=", "web.xss")
    b = Finding("Reflected XSS", Severity.HIGH, "/search?q=", "web.xss")
    assert a.fingerprint == b.fingerprint, "same flaw must share a fingerprint"
    assert a.to_dict()["severity"] == "High"
    print("finding.py: ok")


if __name__ == "__main__":
    demo()
