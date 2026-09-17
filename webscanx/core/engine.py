"""Pick the scanners that fit the target, run them, collect the findings.

Scanners register themselves against one or more TargetKinds. In Phase 0 none
are registered yet, so a scan produces an honest empty report — which still
proves the whole spine (detect -> engine -> report -> render) works end to end.

A scanner is any callable: (Target, ScanContext) -> Iterable[Finding].
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable

from .finding import Finding
from .target import Target, TargetKind

Scanner = Callable[["Target", "ScanContext"], Iterable[Finding]]

# kind -> list of (name, scanner). Modules call register() at import time.
_REGISTRY: dict[TargetKind, list[tuple[str, Scanner]]] = {}


def register(kind: TargetKind, name: str) -> Callable[[Scanner], Scanner]:
    def deco(fn: Scanner) -> Scanner:
        _REGISTRY.setdefault(kind, []).append((name, fn))
        return fn
    return deco


def scanners_for(kind: TargetKind) -> list[tuple[str, Scanner]]:
    return list(_REGISTRY.get(kind, []))


@dataclass
class ScanContext:
    """Knobs shared with every scanner during one run."""

    aggressive: bool = False     # allow data-changing payloads (default: safe)
    timeout: float = 15.0        # per-request / per-read ceiling, seconds
    only: set[str] = field(default_factory=set)   # if set, run only these scanner names
    cache: dict = field(default_factory=dict)     # shared across scanners in one run
                                                   # (e.g. the crawl, built once)
    delay: float = 0.0           # min seconds between requests (0 = no throttle)
    max_pages: int | None = None  # crawl page cap override (None = scanner default)
    max_depth: int | None = None  # crawl depth cap override (None = scanner default)


def run(target: Target, ctx: ScanContext | None = None) -> list[Finding]:
    """Run every applicable scanner and return deduped, worst-first findings."""
    ctx = ctx or ScanContext()
    seen: dict[str, Finding] = {}
    for name, scanner in scanners_for(target.kind):
        if ctx.only and name not in ctx.only:
            continue
        for finding in scanner(target, ctx):
            seen.setdefault(finding.fingerprint, finding)  # first wins on dupes
    return sorted(seen.values(), key=lambda f: f.severity, reverse=True)


def demo() -> None:
    # Use MOBILE — no real scanners register there yet — so the dedupe check stays
    # isolated from the live web.* / code.* scanners when this runs inside the suite.
    dummy_kind = TargetKind.MOBILE

    @register(dummy_kind, "demo.dummy")
    def _dummy(target, ctx):
        yield Finding("Example", "low", target.location, "demo.dummy")
        yield Finding("Example", "low", target.location, "demo.dummy")  # dupe

    findings = run(Target(dummy_kind, "app.apk", "app.apk"))
    assert len(findings) == 1, "duplicates must collapse to one"
    assert findings[0].scanner == "demo.dummy"
    # A kind with no registered scanners -> empty, no crash (offline, no network).
    assert run(Target(TargetKind.DESKTOP, "x.exe", "x.exe")) == []
    _REGISTRY.pop(dummy_kind, None)  # keep the demo self-contained
    print("engine.py: ok")


if __name__ == "__main__":
    demo()
