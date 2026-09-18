"""A localhost-only HTTP bridge so the web UI can drive the same engine the CLI
drives. Stdlib only, no deps, nothing leaves the machine.

    python -m webscanx.server            # http://127.0.0.1:8765

Endpoints (all JSON unless noted):
    POST /api/scan            start a scan   -> {"id": ...}
    GET  /api/scan/<id>       poll one scan  -> state, progress, findings
    GET  /api/scans           this session's scans, newest first
    GET  /api/scan/<id>/report?format=html   rendered report (download)

Safety: binds 127.0.0.1 only, and rejects requests whose Origin isn't a
loopback dev server, so a random web page can't use your machine as a scanner.
The CLI's permission rule still applies -- a web scan needs "authorized": true
in the POST body.
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from . import __version__
from .core import engine
from .core.finding import Finding
from .core.target import Target, TargetKind, detect
from .report import Report
from .report import render as render_mod
from . import scanners  # noqa: F401  (import registers the scanners)

HOST = "127.0.0.1"
PORT = 8765
MAX_BODY = 64 * 1024

# Where the UI may legitimately be served from during development.
ALLOWED_ORIGIN_HOSTS = {"127.0.0.1", "localhost", "::1"}

_JOBS: dict[str, dict] = {}
_ORDER: list[str] = []
_LOCK = threading.Lock()


# ---------------------------------------------------------------- shaping

def _finding_json(index: int, f: Finding) -> dict:
    """The shape the UI already renders (see site/src/data/findings.ts)."""
    refs = " - ".join([f.scanner] + ([f.category] if f.category else []))
    return {
        "id": index,
        "severity": f.severity.label.upper(),
        "name": f.title,
        "path": f.where,
        "module": f.scanner.split(".")[-1].upper(),
        "status": "New",
        "what": f.what,
        "howToCheck": f.how_to_check,
        "checkCommand": "",
        "evidence": f.evidence,
        "fix": f.remediation,
        "refs": refs,
        "references": list(f.references),
        "scanner": f.scanner,
        "fingerprint": f.fingerprint,
    }


def _job_json(job: dict, *, with_findings: bool = True) -> dict:
    out = {
        "id": job["id"],
        "state": job["state"],
        "target": job["target"],
        "kind": job["kind"],
        "started": job["started"],
        "finished": job["finished"],
        "toolVersion": __version__,
        "progress": {
            "done": len(job["done_scanners"]),
            "total": len(job["all_scanners"]),
            "current": job["current"],
            "scanners": job["all_scanners"],
        },
        "counts": job["counts"],
        "summary": job["summary"],
        "error": job["error"],
    }
    if with_findings:
        out["findings"] = [_finding_json(i, f)
                           for i, f in enumerate(job["findings"], start=1)]
    return out


# ---------------------------------------------------------------- running

def _run_job(job: dict, ctx: engine.ScanContext, target: Target) -> None:
    def progress(name: str, fresh: list[Finding]) -> None:
        with _LOCK:
            job["done_scanners"].append(name)
            job["findings"].extend(fresh)
            job["findings"].sort(key=lambda f: f.severity, reverse=True)
            remaining = [s for s in job["all_scanners"]
                         if s not in job["done_scanners"]]
            job["current"] = remaining[0] if remaining else None

    try:
        from .scanners.web import http as web_http
        web_http.set_rate(ctx.delay)
        findings = engine.run(target, ctx, on_progress=progress)
        report = Report(target=target.location, target_kind=target.kind.value,
                        tool_version=__version__)
        report.scanners_run = job["all_scanners"]
        report.findings = findings
        report.finished = datetime.now(timezone.utc)
        with _LOCK:
            job["findings"] = findings
            job["report"] = report
            job["counts"] = report.counts()
            job["summary"] = report.summary_line()
            job["state"] = "done"
            job["current"] = None
    except Exception as exc:  # a failed scan must not kill the server
        with _LOCK:
            job["state"] = "error"
            job["error"] = f"{type(exc).__name__}: {exc}"
            job["current"] = None
    finally:
        with _LOCK:
            job["finished"] = datetime.now(timezone.utc).isoformat()


def start_scan(body: dict) -> dict:
    """Validate the request and kick off a scan. Raises ValueError if refused."""
    raw = (body.get("target") or "").strip()
    if not raw:
        raise ValueError("give a target (a URL, or a folder path with kind='code')")

    if (body.get("kind") or "").lower() == "code":
        path = Path(raw).expanduser()
        if not path.is_dir():
            raise ValueError(f"not a folder: {raw}")
        target = Target(TargetKind.CODE, str(path.resolve()), raw)
    else:
        target = detect(raw)

    if target.kind is TargetKind.UNKNOWN:
        raise ValueError(f"could not tell what {raw!r} is (not a URL or folder)")
    if target.kind is not TargetKind.CODE and not body.get("authorized"):
        raise ValueError("refused: confirm you own this target or have written "
                         "permission to test it (send authorized: true)")

    only = set(body.get("only") or [])
    exclude = set(body.get("exclude") or [])
    ctx = engine.ScanContext(
        aggressive=bool(body.get("aggressive")),
        only=only,
        timeout=float(body.get("timeout") or 15.0),
        delay=float(body.get("delay") or 0.0),
        max_pages=body.get("maxPages"),
        max_depth=body.get("depth"),
    )
    names = [n for n, _ in engine.scanners_for(target.kind)
             if (not only or n in only) and n not in exclude]
    if not names:
        raise ValueError("no scanners left to run - check the module filters")
    ctx.only = set(names)  # exclusions are enforced inside the engine too

    job = {
        "id": uuid.uuid4().hex[:12],
        "state": "running",
        "target": target.location,
        "kind": target.kind.value,
        "started": datetime.now(timezone.utc).isoformat(),
        "finished": None,
        "all_scanners": names,
        "done_scanners": [],
        "current": names[0] if names else None,
        "findings": [],
        "report": None,
        "counts": {},
        "summary": "",
        "error": None,
    }
    with _LOCK:
        _JOBS[job["id"]] = job
        _ORDER.insert(0, job["id"])

    threading.Thread(target=_run_job, args=(job, ctx, target), daemon=True).start()
    return job


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = f"WebScanX/{__version__}"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        print(f"  {self.address_string()} {fmt % args}")

    # -- helpers

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True  # curl / same-origin fetches send none
        host = urlparse(origin).hostname or ""
        return host in ALLOWED_ORIGIN_HOSTS

    def _cors(self) -> None:
        origin = self.headers.get("Origin")
        if origin and self._origin_ok():
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def _send(self, code: int, blob: bytes, ctype: str,
              extra: dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(blob)))
        self._cors()
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(blob)

    def _json(self, code: int, doc: dict) -> None:
        self._send(code, json.dumps(doc, indent=2).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _error(self, code: int, msg: str) -> None:
        self._json(code, {"error": msg})

    # -- verbs

    def do_OPTIONS(self) -> None:
        if not self._origin_ok():
            return self._error(403, "cross-origin requests are not allowed")
        self.send_response(204)
        self._cors()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        if not self._origin_ok():
            return self._error(403, "cross-origin requests are not allowed")
        url = urlparse(self.path)
        parts = [p for p in url.path.strip("/").split("/") if p]

        if parts == ["api", "health"]:
            return self._json(200, {"ok": True, "version": __version__})

        if parts == ["api", "scans"]:
            with _LOCK:
                jobs = [_job_json(_JOBS[i], with_findings=False) for i in _ORDER]
            return self._json(200, {"scans": jobs})

        if len(parts) == 3 and parts[:2] == ["api", "scan"]:
            job = _JOBS.get(parts[2])
            if not job:
                return self._error(404, "no such scan")
            return self._json(200, _job_json(job))

        if len(parts) == 4 and parts[:2] == ["api", "scan"] and parts[3] == "report":
            job = _JOBS.get(parts[2])
            if not job:
                return self._error(404, "no such scan")
            if job["state"] != "done":
                return self._error(409, "scan is not finished yet")
            fmt = (parse_qs(url.query).get("format") or ["html"])[0]
            try:
                blob = render_mod.render(job["report"], fmt)
            except KeyError:
                return self._error(400, f"unknown format {fmt!r}; try: "
                                        f"{', '.join(render_mod.formats())}")
            except NotImplementedError as exc:
                return self._error(501, str(exc))
            name = f"webscanx-{job['id']}{render_mod.extension(fmt)}"
            ctype = ("text/html; charset=utf-8" if fmt == "html"
                     else "application/octet-stream")
            disposition = 'attachment; filename="' + name + '"'
            return self._send(200, blob, ctype,
                              {"Content-Disposition": disposition})

        self._error(404, "not found")

    def do_POST(self) -> None:
        if not self._origin_ok():
            return self._error(403, "cross-origin requests are not allowed")
        if urlparse(self.path).path.rstrip("/") != "/api/scan":
            return self._error(404, "not found")

        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            return self._error(413, "request body too large")
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return self._error(400, "body must be JSON")
        if not isinstance(body, dict):
            return self._error(400, "body must be a JSON object")

        try:
            job = start_scan(body)
        except ValueError as exc:
            return self._error(400, str(exc))
        self._json(202, _job_json(job))


class _Server(ThreadingHTTPServer):
    # Refuse to share a port: two engines on 8765 would silently split the
    # UI's requests between them, so the second one must fail loudly.
    allow_reuse_address = False


def serve(host: str = HOST, port: int = PORT) -> None:
    try:
        httpd = _Server((host, port), Handler)
    except OSError:
        print(f"error: port {port} is already in use - another WebScanX engine "
              f"is probably running. Stop it, or pass --port.")
        raise SystemExit(3)
    print(f"WebScanX {__version__} - local API on http://{host}:{port}")
    print("  POST /api/scan   GET /api/scan/<id>   GET /api/scans")
    print("  Ctrl-C to stop.  Nothing leaves this machine.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="python -m webscanx.server",
                                 description="Localhost API for the WebScanX UI.")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--host", default=HOST,
                    help="loopback only; anything else is refused")
    args = ap.parse_args(argv)
    if args.host not in ALLOWED_ORIGIN_HOSTS:
        print("error: refusing to bind a non-loopback address - this API scans "
              "on request and must not be reachable from the network.")
        return 3
    serve(args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
