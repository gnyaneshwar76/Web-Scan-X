"""Command line: take one target, confirm we're allowed to scan it, run the
engine, write the report in whatever formats were asked for.

Phase 0 wires the whole path with no scanners registered yet, so a run produces
a real (empty) report and exits cleanly. Scanners light up in later phases.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .core import engine
from .core.target import Target, TargetKind, detect
from .report import Report
from .report import render as render_mod
from . import scanners  # noqa: F401  (imports register web scanners with the engine)

# CI-friendly exit codes: highest severity found drives the code.
EXIT_CLEAN = 0
EXIT_LOW_MED = 1        # only low/medium findings
EXIT_HIGH = 2          # high/critical findings present
EXIT_ERROR = 3         # something went wrong / refused


def _confirm_permission(target: Target, assume_yes: bool) -> bool:
    """Rule of the tool: never scan without an explicit ok that you're allowed."""
    if target.kind is TargetKind.CODE:
        return True  # scanning your own files on disk needs no target-owner consent
    if assume_yes:
        return True
    prompt = (
        f"\n  WebScanX will actively scan: {target.location}\n"
        f"  Only scan systems you own or have written permission to test.\n"
        f"  Unauthorised scanning is illegal in most jurisdictions.\n"
        f"  Proceed? [y/N] "
    )
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        return False


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webscanx",
        description="Universal security scanner — web, API, code, mobile, desktop.",
    )
    p.add_argument("target", nargs="?",
                   help="URL, a project folder, an .apk/.ipa, or a binary")
    p.add_argument("--code", metavar="PATH",
                   help="shortcut: scan a source folder (your own code)")
    p.add_argument("-f", "--format", action="append", default=[],
                   help=f"report format(s): {', '.join(render_mod.formats())} "
                        "(repeatable; default: md)")
    p.add_argument("-o", "--out", default="report",
                   help="output path prefix (default: ./report)")
    p.add_argument("--aggressive", action="store_true",
                   help="allow data-changing payloads (default: safe, read-only)")
    p.add_argument("--only", action="append", default=[],
                   help="run only the named scanner(s), e.g. web.headers")
    p.add_argument("--timeout", type=float, default=15.0,
                   help="per-request timeout in seconds (default: 15)")
    p.add_argument("--delay", type=float, default=0.0,
                   help="min seconds between requests, to be polite (default: 0)")
    p.add_argument("--max-pages", type=int, default=None,
                   help="max pages to crawl for web targets (default: 25)")
    p.add_argument("--depth", type=int, default=None,
                   help="max crawl depth for web targets (default: 2)")
    p.add_argument("-y", "--yes", action="store_true",
                   help="skip the permission prompt (you assert authorisation)")
    p.add_argument("--list-formats", action="store_true",
                   help="print supported report formats and exit")
    p.add_argument("--version", action="version", version=f"WebScanX {__version__}")
    return p


def _exit_code(findings) -> int:
    from .core.finding import Severity
    worst = max((f.severity for f in findings), default=Severity.INFO)
    if worst >= Severity.HIGH:
        return EXIT_HIGH
    if worst >= Severity.LOW:
        return EXIT_LOW_MED
    return EXIT_CLEAN


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_formats:
        print("\n".join(render_mod.formats()))
        return EXIT_CLEAN

    raw = args.code or args.target
    if not raw:
        print("error: give a target (URL, folder, .apk/.ipa, or binary). "
              "See --help.", file=sys.stderr)
        return EXIT_ERROR

    target = detect(raw)
    if args.code:
        target = Target(TargetKind.CODE, str(Path(args.code).expanduser().resolve()), raw)

    if target.kind is TargetKind.UNKNOWN:
        print(f"error: could not tell what {raw!r} is (not a URL, folder, app, "
              f"or binary).", file=sys.stderr)
        return EXIT_ERROR

    if not _confirm_permission(target, args.yes):
        print("aborted: no authorisation confirmed.", file=sys.stderr)
        return EXIT_ERROR

    ctx = engine.ScanContext(aggressive=args.aggressive, only=set(args.only),
                             timeout=args.timeout, delay=args.delay,
                             max_pages=args.max_pages, max_depth=args.depth)
    from .scanners.web import http as web_http  # apply the politeness throttle
    web_http.set_rate(args.delay)
    report = Report(target=target.location, target_kind=target.kind.value,
                    tool_version=__version__)
    report.scanners_run = [name for name, _ in engine.scanners_for(target.kind)]
    report.findings = engine.run(target, ctx)
    report.finished = datetime.now(timezone.utc)

    formats = args.format or ["md"]
    written = []
    for fmt in formats:
        try:
            blob = render_mod.render(report, fmt)
        except KeyError as e:
            print(f"error: {e}", file=sys.stderr)
            return EXIT_ERROR
        except NotImplementedError as e:
            print(f"skip {fmt}: {e}", file=sys.stderr)
            continue
        path = Path(f"{args.out}{render_mod.extension(fmt)}")
        path.write_bytes(blob)
        written.append(str(path))

    print(f"\n{report.summary_line()}")
    if report.scanners_run:
        print(f"scanners: {', '.join(report.scanners_run)}")
    else:
        print(f"scanners: none registered for {target.kind.value} yet "
              f"(Phase 0 - spine only)")
    for w in written:
        print(f"report  : {w}")

    return _exit_code(report.findings)


if __name__ == "__main__":
    raise SystemExit(main())
