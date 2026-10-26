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
