"""A localhost-only HTTP bridge so the web UI can drive the same engine the CLI
drives. Stdlib only, no deps, nothing leaves the machine.

    python -m webscanx.server            # http://127.0.0.1:8765

Endpoints (all JSON unless noted):
    POST /api/scan            start a scan   -> {"id": ...}
    GET  /api/scan/<id>       poll one scan  -> state, progress, findings
    GET  /api/scans           this session's scans, newest first
    GET  /api/scan/<id>/report?format=html   rendered report (download)
    GET  /<anything else>     the built UI from site/dist (if it has been built)

Safety: binds loopback only, requires the Host header to be a loopback name
(DNS-rebinding defence) and any Origin to be a loopback origin, so a random web
page can't use your machine as a scanner. Max MAX_RUNNING scans at once; only
the newest MAX_FINISHED finished scans are kept in memory.
The CLI's permission rule still applies -- a web scan needs "authorized": true
in the POST body.
"""

from __future__ import annotations

import hmac
import json
import mimetypes
import os
import re
import secrets
import shlex
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

MAX_RUNNING = 2      # concurrent scans; more get a 429
MAX_FINISHED = 20    # finished scans kept in memory (never written to disk)
DIST = Path(__file__).resolve().parent.parent / "site" / "dist"

# Per-process API token: every /api/* call except GET /api/health must send it.
TOKEN = os.environ.get("WEBSCANX_TOKEN") or secrets.token_urlsafe(24)

CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
       "connect-src 'self' http://127.0.0.1:8765 http://localhost:8765; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
SEC_HEADERS = {"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff",
               "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY"}

_JOBS: dict[str, dict] = {}
_ORDER: list[str] = []
_LOCK = threading.Lock()


# ---------------------------------------------------------------- shaping

def _check_command(f: Finding) -> str:
    if not f.scanner.startswith("web.") or not f.where.startswith(("http://", "https://")):
        return ""
    url = f.where.split()[0]
    if urlparse(url).scheme not in ("http", "https"):
        return ""
    head = f.scanner.split(".")[-1] in ("headers", "cookies", "tls")
    return f"curl -sI {shlex.quote(url)}" if head else f"curl -s {shlex.quote(url)}"


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
        "checkCommand": _check_command(f),
        "evidence": f.evidence,
        "fix": f.remediation,
        "refs": refs,
        "references": list(f.references),
        "scanner": f.scanner,
        "fingerprint": f.fingerprint,
    }


def _clean_ai(job: dict):
    rep = job.get("report")
    return rep.view().ai if rep is not None else None


def _job_json(job: dict, *, with_findings: bool = True) -> dict:
    out = {
        "ai": _clean_ai(job),
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
        "error": (job["error"] or "")[:300] or None,
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
        web_http.set_rate(ctx.delay)  # thread-local: this scan only
        if target.kind is TargetKind.WEB:
            web_http.set_scope(target.location)
            if job["ai_plan"]:
                from .cli import apply_ai_plan
                apply_ai_plan(ctx, target, job["ai_mode"], job["ai_model"])
                with _LOCK:  # the plan may have narrowed the scanner list
                    job["all_scanners"] = [n for n in job["all_scanners"] if n in ctx.only]
                    job["current"] = job["all_scanners"][0] if job["all_scanners"] else None
        findings = engine.run(target, ctx, on_progress=progress)
        report = Report(target=target.location, target_kind=target.kind.value,
                        tool_version=__version__)
        report.scanners_run = job["all_scanners"]
        report.findings = findings
        report.finished = datetime.now(timezone.utc)
        if job["ai_mode"] != "off":
            try:
                from .ai import enrich
                enrich(report, job["ai_mode"], model=job["ai_model"])
            except Exception:
                pass  # AI is optional; the scan result stands without it
        with _LOCK:
            job["ai"] = getattr(report, "ai", None)
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


class BusyError(Exception):
    """Too many scans running at once."""


def start_scan(body: dict) -> dict:
    """Validate the request and kick off a scan. Raises ValueError if refused."""
    with _LOCK:  # cheap early cap check, before any DNS lookup (re-checked at insert)
        if sum(j["state"] == "running" for j in _JOBS.values()) >= MAX_RUNNING:
            raise BusyError(f"{MAX_RUNNING} scans are already running - wait "
                            f"for one to finish")
    for key in ("target", "kind", "ai", "aiModel"):
        if body.get(key) is not None and not isinstance(body[key], str):
            raise ValueError(f"{key} must be a string")
    raw = (body.get("target") or "").strip()
    if not raw:
        raise ValueError("give a target (a URL, or a folder path with kind='code')")

    kind = (body.get("kind") or "").lower()
    if kind != "code" and not body.get("authorized"):  # before any filesystem access: no existence oracle
        raise ValueError("refused: confirm you own this target or have written "
                         "permission to test it (send authorized: true)")
    if raw.startswith(("\\\\", "//")):
        raise ValueError("network (UNC) paths are not allowed")
    model = body.get("aiModel")
    if model is not None and not re.fullmatch(r"[A-Za-z0-9._:/-]{1,80}", model):
        raise ValueError("aiModel: max 80 chars of letters, digits and . _ : - /")
    if kind in ("mobile", "desktop"):
        path = Path(raw).expanduser()
        if not (path.is_file() or path.is_dir()):
            raise ValueError(f"no such file: {raw}")
        target = Target(TargetKind(kind), str(path.resolve()), raw)
    elif kind == "code":
        path = Path(raw).expanduser()
        if not path.is_dir():
            raise ValueError(f"not a folder: {raw}")
        target = Target(TargetKind.CODE, str(path.resolve()), raw)
    else:
        target = detect(raw)

    if target.kind in (TargetKind.MOBILE, TargetKind.DESKTOP) and not Path(target.location).exists():
        raise ValueError(f"no such file: {raw}")
    if target.kind is TargetKind.UNKNOWN:
        raise ValueError(f"could not tell what {raw!r} is (not a URL, app file or folder)")
    if target.kind is not TargetKind.CODE and not body.get("authorized"):
        raise ValueError("refused: confirm you own this target or have written "
                         "permission to test it (send authorized: true)")

    def lst(key):
        v = body.get(key) or []
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise ValueError(f"{key} must be a list of scanner names")
        return set(v)

    def num(key, lo, hi, default):
        v = body.get(key)
        if v is None:
            return default
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
            raise ValueError(f"{key} must be a number from {lo} to {hi}")
        return v

    ai_mode = body.get("ai") or "off"
    if ai_mode not in ("off", "local", "cloud"):
        raise ValueError("ai must be off, local or cloud")
    ai_plan = bool(body.get("aiPlan"))
    if ai_plan and ai_mode == "off":
        raise ValueError("aiPlan needs ai set to local or cloud")
    only, exclude = lst("only"), lst("exclude")
    bad = engine.unknown_names(only | exclude)
    if bad:
        raise ValueError(f"unknown scanner(s): {', '.join(bad)}")
    ctx = engine.ScanContext(
        aggressive=bool(body.get("aggressive")),
        only=only,
        timeout=float(num("timeout", 1, 60, 15.0)),
        delay=float(num("delay", 0, 10, 0.0)),
        max_pages=int(num("maxPages", 1, 500, None)) if body.get("maxPages") is not None else None,
        max_depth=int(num("depth", 0, 10, None)) if body.get("depth") is not None else None,
    )
    if target.kind is TargetKind.WEB:
        from .scanners.web import http as web_http
        web_http.set_scope(target.location)  # SSRF guard: ValueError -> 400
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
        "ai": None,
        "ai_mode": ai_mode,
        "ai_model": body.get("aiModel") or None,
        "ai_plan": ai_plan,
    }
    with _LOCK:
        if sum(j["state"] == "running" for j in _JOBS.values()) >= MAX_RUNNING:
            raise BusyError(f"{MAX_RUNNING} scans are already running - wait "
                            f"for one to finish")
        _JOBS[job["id"]] = job
        _ORDER.insert(0, job["id"])
        done = [i for i in _ORDER if _JOBS[i]["state"] != "running"]
        for old in done[MAX_FINISHED:]:  # _ORDER is newest first
            del _JOBS[old]
            _ORDER.remove(old)

    threading.Thread(target=_run_job, args=(job, ctx, target), daemon=True).start()
    return job


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = f"WebScanX/{__version__}"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        print(f"  {self.address_string()} {(fmt % args).replace(TOKEN, '***')}")

    # -- helpers

    def _origin_ok(self) -> bool:
        # Host must be a loopback name (a rebound evil.example fails here); an
        # Origin, when sent, must be an http(s) loopback origin. Exact match only.
        try:
            host = urlparse("//" + (self.headers.get("Host") or "")).hostname
            if host not in ALLOWED_ORIGIN_HOSTS:
                return False
            origin = self.headers.get("Origin")
            if not origin:
                return True  # curl / same-origin fetches send none
            o = urlparse(origin)
            return o.scheme in ("http", "https") and o.hostname in ALLOWED_ORIGIN_HOSTS
        except ValueError:  # malformed port etc.
            return False

    def _authed(self, query: str = "", allow_query: bool = False) -> bool:
        got = self.headers.get("X-WebScanX-Token") or ""
        if not got and allow_query:
            got = (parse_qs(query).get("token") or [""])[0]
        return hmac.compare_digest(got.encode(), TOKEN.encode())

    def _static(self, path: str) -> None:
        rel = path.lstrip("/") or "index.html"
        f = (DIST / rel).resolve()
        if not f.is_relative_to(DIST) or not f.is_file():
            if "." in rel.rsplit("/", 1)[-1]:
                return self._error(404, "not found")
            f = DIST / "index.html"  # SPA route
        if not f.is_file():
            return self._error(404, "UI not built - run the build in site/ "
                                    "(or use the API only)")
        ctype = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        blob = f.read_bytes()
        if f.name == "index.html":
            meta = f'<meta name="webscanx-token" content="{TOKEN}">'.encode()
            blob = re.sub(rb"<head[^>]*>", lambda m: m.group(0) + meta, blob, count=1, flags=re.I)
        self._send(200, blob, ctype)

    def _cors(self) -> None:
        origin = self.headers.get("Origin")
        # API only: never let another local page read the served HTML (it carries the token)
        if origin and self._origin_ok() and self.path.startswith("/api/"):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def _send(self, code: int, blob: bytes, ctype: str,
              extra: dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(blob)))
        for k, v in SEC_HEADERS.items():
            self.send_header(k, v)
        self._cors()
        if code in (401, 403, 411, 413) or self.close_connection:  # request body not read
            self.send_header("Connection", "close")
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
        for k, v in SEC_HEADERS.items():
            self.send_header(k, v)
        self._cors()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-WebScanX-Token")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        if not self._origin_ok():
            return self._error(403, "cross-origin requests are not allowed")
        url = urlparse(self.path)
        parts = [p for p in url.path.strip("/").split("/") if p]

        if parts == ["api", "health"]:
            return self._json(200, {"ok": True, "version": __version__})

        is_report = len(parts) == 4 and parts[:2] == ["api", "scan"] and parts[3] == "report"
        if parts[:1] == ["api"] and not self._authed(url.query, is_report):
            return self._error(401, "missing or wrong X-WebScanX-Token")

        if parts == ["api", "scans"]:
            with _LOCK:
                jobs = [_job_json(_JOBS[i], with_findings=False) for i in _ORDER]
            return self._json(200, {"scans": jobs})

        if len(parts) == 3 and parts[:2] == ["api", "scan"]:
            with _LOCK:
                job = _JOBS.get(parts[2])
                doc = _job_json(job) if job else None
            if not job:
                return self._error(404, "no such scan")
            return self._json(200, doc)

        if len(parts) == 4 and parts[:2] == ["api", "scan"] and parts[3] == "report":
            with _LOCK:
                job = _JOBS.get(parts[2])
                state, report = (job["state"], job["report"]) if job else (None, None)
            if not job:
                return self._error(404, "no such scan")
            if state != "done":
                return self._error(409, "scan is not finished yet")
            q = parse_qs(url.query)
            fmt = (q.get("format") or ["html"])[0]
            opts = render_mod.Options(
                evidence=(q.get("evidence") or ["1"])[0] != "0",
                ignored=frozenset(x for v in q.get("ignored", []) for x in v.split(",") if x),
                redact=(q.get("redact") or ["0"])[0] == "1")
            try:
                blob = render_mod.render(report, fmt, opts)
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

        if parts[:1] == ["api"]:
            return self._error(404, "not found")
        self._static(url.path)

    def do_POST(self) -> None:
        if not self._origin_ok():
            return self._error(403, "cross-origin requests are not allowed")
        if urlparse(self.path).path.rstrip("/") != "/api/scan":
            return self._error(404, "not found")
        if not self._authed():
            return self._error(401, "missing or wrong X-WebScanX-Token")

        cl = self.headers.get("Content-Length")
        if cl is None:
            return self._error(411, "Content-Length required")
        try:
            length = int(cl)
        except ValueError:
            length = -1
        if length < 0:
            self.close_connection = True
            return self._error(400, "bad Content-Length")
        if length > MAX_BODY:
            return self._error(413, "request body too large")
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._error(400, "body must be JSON")
        if not isinstance(body, dict):
            return self._error(400, "body must be a JSON object")

        try:
            job = start_scan(body)
        except BusyError as exc:
            return self._error(429, str(exc))
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
    print(f"  API token: {TOKEN}  (header X-WebScanX-Token; the served UI gets it automatically)")
    print("  POST /api/scan   GET /api/scan/<id>   GET /api/scans")
    print(f"  UI: {'http://%s:%d/' % (host, port) if DIST.is_dir() else 'not built (site/dist missing)'}")
    print("  Ctrl-C to stop.  Scan data stays on this machine; the scanner "
          "contacts only the target you authorise.")
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
