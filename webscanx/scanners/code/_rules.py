"""Shared line-by-line rule runner for the code scanners.

A rule is a compiled regex plus the finding text it produces. Each code scanner
declares a RULES list and calls run_rules over the shared source tree. Matches are
reported as file:line with the offending line as evidence.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from ...core.finding import Finding
from .walker import get_tree


@dataclass
class Rule:
    pattern: re.Pattern
    title: str
    severity: str
    category: str
    what: str
    remediation: str
    references: tuple = ()
    exts: frozenset | None = None        # restrict to these extensions, or all
    negate: re.Pattern | None = None     # skip the line if this also matches


def run_rules(target, ctx, scanner: str, rules: list[Rule]):
    tree = get_tree(target, ctx)
    for f in tree.files:
        ext = os.path.splitext(f.rel)[1].lower()
        for i, line in enumerate(f.lines, 1):
            if len(line) > 400:              # skip minified/one-line bundles
                continue
            for r in rules:
                if r.exts and ext not in r.exts:
                    continue
                if not r.pattern.search(line):
                    continue
                if r.negate and r.negate.search(line):
                    continue
                yield Finding(
                    title=r.title, severity=r.severity, where=f"{f.rel}:{i}",
                    scanner=scanner, what=r.what,
                    how_to_check=f"Open {f.rel} at line {i} and review the flagged code.",
                    evidence=line.strip()[:160], remediation=r.remediation,
                    category=r.category, references=list(r.references),
                )
