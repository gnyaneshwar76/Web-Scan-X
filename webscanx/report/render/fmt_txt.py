"""Plain-text export."""
from __future__ import annotations

from ..report import Report
from ._registry import meta_rows as _meta_rows, register


@register("txt", ".txt")
def to_txt(report: Report) -> bytes:
    out: list[str] = ["WebScanX report", "=" * 40]
    for k, v in _meta_rows(report):
        out.append(f"{k:9}: {v}")
    out.append("")
    if not report.findings:
        out.append("No findings.")
    for i, f in enumerate(report.findings, 1):
        out += [
            f"[{i}] {f.severity.label.upper()}  {f.title}",
            f"    where     : {f.where}",
            f"    scanner   : {f.scanner}" + (f"   ({f.category})" if f.category else ""),
            *( [f"    what      : {f.what}"] if f.what else [] ),
            *( [f"    check     : {f.how_to_check}"] if f.how_to_check else [] ),
            *( [f"    evidence  : {f.evidence}"] if f.evidence else [] ),
            *( [f"    fix       : {f.remediation}"] if f.remediation else [] ),
            *( ["    status    : auto-fixed"] if f.fixed else [] ),
            "",
        ]
    return ("\n".join(out) + "\n").encode("utf-8")
