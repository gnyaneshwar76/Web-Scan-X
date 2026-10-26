"""Format registry shared by the one-module-per-format renderers."""

from __future__ import annotations

from typing import Callable

from ..report import Report

Renderer = Callable[[Report], bytes]
_RENDERERS: dict[str, Renderer] = {}
_EXT: dict[str, str] = {}


def register(fmt: str, ext: str) -> Callable[[Renderer], Renderer]:
    def deco(fn: Renderer) -> Renderer:
        _RENDERERS[fmt] = fn
        _EXT[fmt] = ext
        return fn
    return deco


def formats() -> list[str]:
    return sorted(_RENDERERS)


def extension(fmt: str) -> str:
    return _EXT[fmt]


def meta_rows(report: Report) -> list[tuple[str, str]]:
    return [
        ("Target", report.target),
        ("Kind", report.target_kind),
        ("Started", report.started.isoformat(timespec="seconds")),
        ("Finished", report.finished.isoformat(timespec="seconds") if report.finished else "—"),
        ("Tool", f"WebScanX {report.tool_version}".strip()),
        ("Summary", report.summary_line()),
    ]


AI_TITLE = "AI suggestions - check them yourself"
AI_NOTE = "AI step failed; the normal results are unaffected."


def ai_verdict(report: Report, f) -> tuple[str, str]:
    n = ((report.ai or {}).get("notes") or {}).get(f.fingerprint)
    return (n["verdict"], n["why"]) if n else ("", "")


def ai_lines(report: Report) -> list[str]:
    """Plain lines for the AI section (empty when there is no AI result)."""
    ai = report.ai
    if not ai:
        return []
    if ai.get("error"):
        return [AI_NOTE, f"({ai['error']})"]
    by_fp = {f.fingerprint: i for i, f in enumerate(report.findings, 1)}
    out = [f"Model: {ai['model']} ({ai['mode']})"] if ai["model"] or ai["mode"] else []
    if ai["summary"]:
        out.append(ai["summary"])
    for fp in ai["fix_first"]:
        out.append(f"Fix first: #{by_fp[fp]} {report.findings[by_fp[fp] - 1].title}")
    return out
