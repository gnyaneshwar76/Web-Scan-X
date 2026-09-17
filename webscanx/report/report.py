"""One report object: the findings plus everything about the run that produced
them. Every export format is built from this and nothing else."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..core.finding import Finding, Severity


@dataclass
class Report:
    target: str
    target_kind: str
    findings: list[Finding] = field(default_factory=list)
    started: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished: datetime | None = None
    tool_version: str = ""
    scanners_run: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        """Findings per severity label, highest first — for the summary line."""
        out = {s.label: 0 for s in reversed(Severity)}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def fixed_count(self) -> int:
        return sum(1 for f in self.findings if f.fixed)

    def summary_line(self) -> str:
        c = self.counts()
        parts = [f"{n} {label.lower()}" for label, n in c.items() if n]
        body = ", ".join(parts) if parts else "no findings"
        return f"{self.total} findings ({body})"


def demo() -> None:
    r = Report(target="https://example.com", target_kind="web")
    r.findings = [
        Finding("XSS", "high", "/a", "web.xss"),
        Finding("Missing header", "low", "/", "web.headers"),
        Finding("Old lib", "medium", "req.txt:3", "code.deps", fixed=True),
    ]
    c = r.counts()
    assert c["High"] == 1 and c["Low"] == 1 and c["Medium"] == 1
    assert r.total == 3 and r.fixed_count == 1
    assert "3 findings" in r.summary_line()
    print("report.py: ok")


if __name__ == "__main__":
    demo()
