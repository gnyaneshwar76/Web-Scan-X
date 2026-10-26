"""Markdown export."""
from __future__ import annotations

from ..report import Report
import re

from ._registry import AI_TITLE, ai_lines, ai_verdict, meta_rows as _meta_rows, register


def _e(s: str) -> str:
    return re.sub(r"([\\`*_<>\[\]|])", r"\\\1", s)


@register("md", ".md")
def to_md(report: Report) -> bytes:
    out = ["# WebScanX report", ""]
    for k, v in _meta_rows(report):
        out.append(f"- **{k}:** {v}")
    out.append("")
    al = ai_lines(report)
    if al:
        out += [f"## {AI_TITLE}", "", *[f"- {_e(x)}" for x in al], ""]
    if not report.findings:
        out += ["_No findings._", ""]
    for i, f in enumerate(report.findings, 1):
        out += [
            f"## {i}. {f.title}  — {f.severity.label}",
            "",
            f"- **Where:** `{f.where}`",
            f"- **Scanner:** `{f.scanner}`" + (f" · {f.category}" if f.category else ""),
        ]
        if f.what:
            out.append(f"- **What:** {f.what}")
        if f.how_to_check:
            out.append(f"- **How to check:** {f.how_to_check}")
        if f.evidence:
            out += ["- **Evidence:**", "", "  ```", f"  {f.evidence}", "  ```"]
        if f.remediation:
            out.append(f"- **Fix:** {f.remediation}")
        v, w = ai_verdict(report, f)
        if v:
            out.append(f"- **AI note (unchecked):** {v} - {_e(w)}")
        if f.fixed:
            out.append("- **Status:** auto-fixed ✅")
        out.append("")
    return ("\n".join(out)).encode("utf-8")
