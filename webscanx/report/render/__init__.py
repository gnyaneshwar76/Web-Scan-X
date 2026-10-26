"""Every export format lives in its own fmt_*.py module and registers itself
in _registry. The public API is render() / formats() / extension().

Pass options (evidence on/off, ignored fingerprints, redact) via the
``options`` argument or ``Report.options``; the report itself is not changed.
All formats are stdlib-only, PDF included.
"""

from __future__ import annotations

import json

from ..report import Options, Report
from ...core.finding import Finding
from ._registry import _RENDERERS, extension, formats
from . import fmt_json, fmt_txt, fmt_md, fmt_csv, fmt_sarif, fmt_html, fmt_pdf  # noqa: F401

__all__ = ["render", "formats", "extension", "Options"]


def render(report: Report, fmt: str, options: Options | None = None) -> bytes:
    if fmt not in _RENDERERS:
        raise KeyError(f"unknown format {fmt!r}; have: {', '.join(formats())}")
    return _RENDERERS[fmt](report.view(options))


def demo() -> None:
    r = Report(target="https://example.com/?k=secretsecret123456", target_kind="web", tool_version="0.1")
    r.findings = [Finding("Reflected XSS", "high", "/s?q=", "web.xss",
                          what="User input echoed unescaped.",
                          how_to_check="Submit <script>alert(1)</script> and view source.",
                          evidence="<script>alert(1)</script>",
                          remediation="HTML-encode output.", category="A03 / CWE-79")]
    for fmt in ("json", "txt", "md", "csv", "sarif", "html", "pdf"):
        blob = render(r, fmt)
        assert isinstance(blob, bytes) and blob, fmt
        assert b"XSS" in blob or b"xss" in blob, fmt
    assert json.loads(render(r, "json"))["total"] == 1
    json.loads(render(r, "sarif"))
    pdf = render(r, "pdf")
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")
    assert json.loads(render(r, "json", Options(evidence=False)))["findings"][0]["evidence"] == ""
    assert json.loads(render(r, "json", Options(ignored=frozenset({r.findings[0].fingerprint}))))["total"] == 0
    assert b"secretsecret123456" not in render(r, "txt", Options(redact=True))
    assert set(formats()) >= {"json", "txt", "md", "csv", "sarif", "html", "pdf"}
    fp = r.findings[0].fingerprint
    r.ai = {"mode": "local", "model": "m", "summary": "AI-SUM", "fix_first": [fp],
            "notes": {fp: {"verdict": "real", "why": "AI-WHY"}}}
    for fmt in ("txt", "md", "html", "csv", "json", "sarif"):
        assert b"AI-WHY" in render(r, fmt) or fmt == "sarif" and b"real" in render(r, fmt), fmt
    print("render: ok")


if __name__ == "__main__":
    demo()
