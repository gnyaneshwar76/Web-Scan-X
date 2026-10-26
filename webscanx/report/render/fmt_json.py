"""JSON export."""
from __future__ import annotations

import json

from ..report import Report
from ._registry import register


@register("json", ".json")
def to_json(report: Report) -> bytes:
    doc = {
        "target": report.target,
        "target_kind": report.target_kind,
        "started": report.started.isoformat(),
        "finished": report.finished.isoformat() if report.finished else None,
        "tool_version": report.tool_version,
        "scanners_run": report.scanners_run,
        "summary": report.counts(),
        "total": report.total,
        "findings": [f.to_dict() for f in report.findings],
    }
    if report.ai:
        doc["ai"] = report.ai
    return json.dumps(doc, indent=2).encode("utf-8")
