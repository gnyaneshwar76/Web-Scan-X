"""CSV export."""
from __future__ import annotations

import csv
import io

from ..report import Report
from ._registry import ai_verdict, register


@register("csv", ".csv")
def to_csv(report: Report) -> bytes:
    buf = io.StringIO(newline="")
    w = csv.writer(buf)
    w.writerow(["#", "severity", "title", "where", "scanner", "category",
                "fixed", "what", "how_to_check", "remediation"] + (["ai_verdict", "ai_why"] if report.ai else []))
    for i, f in enumerate(report.findings, 1):
        row = [i, f.severity.label, f.title, f.where, f.scanner, f.category,
               "yes" if f.fixed else "no", f.what, f.how_to_check, f.remediation]
        if report.ai:
            row += ai_verdict(report, f)
        # spreadsheet formula guard
        w.writerow([("'" + c) if isinstance(c, str) and c[:1] in "=+-@\t\r" and c else c for c in row])
    return buf.getvalue().encode("utf-8")
