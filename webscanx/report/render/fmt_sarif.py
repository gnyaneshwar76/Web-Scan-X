"""SARIF export."""
from __future__ import annotations

import json

from ..report import Report
from ._registry import ai_verdict, register


_SARIF_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning",
                "Low": "note", "Info": "note"}


@register("sarif", ".sarif")
def to_sarif(report: Report) -> bytes:
    results = []
    for f in report.findings:
        v, w = ai_verdict(report, f)
        results.append({
            "ruleId": f"{f.scanner}/{f.title}",
            "level": _SARIF_LEVEL.get(f.severity.label, "warning"),
            "message": {"text": f.what or f.title},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.where}}}],
            **({"properties": {"ai": {"verdict": v, "why": w}}} if v else {}),
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "WebScanX", "version": report.tool_version or "0",
                                 "informationUri": "https://github.com/gnyaneshwar76/Projects"}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2).encode("utf-8")
