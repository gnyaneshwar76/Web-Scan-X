"""Every export format lives here: one function per format, all taking a Report
and returning bytes, wired into a single registry so the CLI can offer "any
format" without special-casing.

Formats in Phase 0 are pure stdlib (no third-party deps): json, txt, md, csv,
sarif, html. PDF is registered but deferred to Phase 2 (needs a PDF lib); asking
for it now returns a clear message instead of a broken file.
"""

from __future__ import annotations

import csv
import html as _html
import io
import json
from typing import Callable

from ..report import Report
from ...core.finding import Finding

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


def render(report: Report, fmt: str) -> bytes:
    if fmt not in _RENDERERS:
        raise KeyError(f"unknown format {fmt!r}; have: {', '.join(formats())}")
    return _RENDERERS[fmt](report)


def _meta_rows(report: Report) -> list[tuple[str, str]]:
    return [
        ("Target", report.target),
        ("Kind", report.target_kind),
        ("Started", report.started.isoformat(timespec="seconds")),
        ("Finished", report.finished.isoformat(timespec="seconds") if report.finished else "—"),
        ("Tool", f"WebScanX {report.tool_version}".strip()),
        ("Summary", report.summary_line()),
    ]


# ── JSON — the machine-readable source of truth ──────────────────────────────
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
    return json.dumps(doc, indent=2).encode("utf-8")


# ── TXT — plain, human, no markup ────────────────────────────────────────────
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


# ── Markdown — drops into GitHub / docs ──────────────────────────────────────
@register("md", ".md")
def to_md(report: Report) -> bytes:
    out = ["# WebScanX report", ""]
    for k, v in _meta_rows(report):
        out.append(f"- **{k}:** {v}")
    out.append("")
    if not report.findings:
        out += ["_No findings._", ""]
    for i, f in enumerate(report.findings, 1):
        out += [
            f"## {i}. {f.title}  — {f.severity.label}",
            "",
            f"- **Where:** `{f.where}`",
            f"- **Scanner:** `{f.scanner}`" + (f" · {f.category}" if f.category else ""),
        ]
        if f.what:
            out.append(f"- **What:** {f.what}")
        if f.how_to_check:
            out.append(f"- **How to check:** {f.how_to_check}")
        if f.evidence:
            out += ["- **Evidence:**", "", "  ```", f"  {f.evidence}", "  ```"]
        if f.remediation:
            out.append(f"- **Fix:** {f.remediation}")
        if f.fixed:
            out.append("- **Status:** auto-fixed ✅")
        out.append("")
    return ("\n".join(out)).encode("utf-8")


# ── CSV — spreadsheets / triage ──────────────────────────────────────────────
@register("csv", ".csv")
def to_csv(report: Report) -> bytes:
    buf = io.StringIO(newline="")
    w = csv.writer(buf)
    w.writerow(["#", "severity", "title", "where", "scanner", "category",
                "fixed", "what", "how_to_check", "remediation"])
    for i, f in enumerate(report.findings, 1):
        w.writerow([i, f.severity.label, f.title, f.where, f.scanner, f.category,
                    "yes" if f.fixed else "no", f.what, f.how_to_check, f.remediation])
    return buf.getvalue().encode("utf-8")


# ── SARIF — the standard CI / code-scanning interchange format ───────────────
_SARIF_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning",
                "Low": "note", "Info": "note"}


@register("sarif", ".sarif")
def to_sarif(report: Report) -> bytes:
    results = []
    for f in report.findings:
        results.append({
            "ruleId": f"{f.scanner}/{f.title}",
            "level": _SARIF_LEVEL.get(f.severity.label, "warning"),
            "message": {"text": f.what or f.title},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.where}}}],
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


# ── HTML — a self-contained, professional report; opens in any browser ───────
# One severity palette, shared with the dashboard/shop design system. Colour is
# always paired with the text label — never colour alone (accessibility).
_SEV_COLOR = {"Critical": "#ff3b30", "High": "#ef4444", "Medium": "#f97316",
              "Low": "#eab308", "Info": "#8a8a8a"}
_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def _esc(s: str) -> str:
    return _html.escape(str(s), quote=True)


def _duration(report: Report) -> str:
    if not report.finished:
        return "—"
    secs = (report.finished - report.started).total_seconds()
    if secs < 1:
        return "<1s"
    if secs < 60:
        return f"{secs:.1f}s"
    return f"{int(secs // 60)}m {int(secs % 60)}s"


def _risk(report: Report):
    """A weighted 0-100 risk score, a band label, a colour, and a human lede."""
    from ...core.finding import Severity
    weight = {Severity.CRITICAL: 45, Severity.HIGH: 22, Severity.MEDIUM: 9,
              Severity.LOW: 3, Severity.INFO: 0}
    score = min(100, sum(weight[f.severity] for f in report.findings))
    if not report.findings:
        return (0, "All clear", "#22d3a6",
                "No issues were found on this target.")
    worst = max(f.severity for f in report.findings)
    color = _SEV_COLOR[worst.label]
    if worst >= Severity.CRITICAL:
        band, lede = "Critical risk", "Fix the critical issues immediately."
    elif worst >= Severity.HIGH:
        band, lede = "High risk", "Prioritise the high-severity findings first."
    elif worst == Severity.MEDIUM:
        band, lede = "Moderate risk", "Plan remediation for the issues below."
    else:
        band, lede = "Low risk", "Minor hardening opportunities only."
    return (score, band, color, lede)


def _gauge_svg(score: int, color: str) -> str:
    """A circular risk gauge — the report's colourful centrepiece."""
    import math
    r = 54
    circ = 2 * math.pi * r
    dash = circ * score / 100
    return f"""<svg class="gauge" viewBox="0 0 130 130" role="img"
     style="--c:{color}" aria-label="Risk score {score} of 100">
  <circle class="gtrack" cx="65" cy="65" r="{r}"/>
  <circle class="gval" cx="65" cy="65" r="{r}" transform="rotate(-90 65 65)"
    style="stroke:{color};stroke-dasharray:{dash:.1f} {circ:.1f}"/>
  <text class="gnum" x="65" y="63" style="fill:{color}">{score}</text>
  <text class="glab" x="65" y="84">RISK SCORE</text>
</svg>"""


def _stat_tiles(report: Report) -> str:
    """Five colourful severity tiles — count + label, tinted by severity."""
    counts = report.counts()
    out = []
    for s in _SEV_ORDER:
        col, n = _SEV_COLOR[s], counts[s]
        dim = "" if n else " dim"
        out.append(
            f'<div class="tile{dim}" style="--c:{col};--tint:{col}14;--edge:{col}3a">'
            f'<b>{n}</b><span>{s}</span></div>')
    return "".join(out)


def _finding_card(i: int, f: "Finding") -> str:
    from ...core.finding import Severity
    color = _SEV_COLOR.get(f.severity.label, "#8a8a8a")
    blocks = []
    for label, val, mono in (("What it is", f.what, False),
                             ("How to check it yourself", f.how_to_check, False),
                             ("Evidence", f.evidence, True),
                             ("How to fix", f.remediation, False)):
        if val:
            if mono:
                inner = (f'<div class="ev"><pre>{_esc(val)}</pre>'
                         f'<button class="copy" type="button" title="Copy">Copy</button></div>')
            else:
                inner = f'<p>{_esc(val)}</p>'
            blocks.append(f'<div class="block"><h3>{label}</h3>{inner}</div>')
    if f.references:
        links = "".join(
            f'<li><a href="{_esc(r)}" rel="noopener noreferrer" target="_blank">'
            f'{_esc(r)}</a></li>' for r in f.references)
        blocks.append(f'<div class="block"><h3>References</h3><ul>{links}</ul></div>')
    cat = f'<span class="cat">{_esc(f.category)}</span>' if f.category else ""
    fixed = '<span class="fixed">FIXED</span>' if f.fixed else ""
    # High/critical start expanded (act now); lower severities start collapsed.
    open_cls = " open" if f.severity >= Severity.HIGH else ""
    # Everything searchable, lower-cased, escaped for the attribute.
    hay = _esc(" ".join((f.title, f.where, f.scanner, f.category, f.what,
                         f.how_to_check, f.remediation)).lower())
    return f"""
    <article class="finding{open_cls}" data-sev="{f.severity.label.lower()}"
             data-text="{hay}" id="f{i}" style="--c:{color};--tint:{color}12">
      <button class="fhead" type="button" aria-expanded="{'true' if open_cls else 'false'}">
        <span class="sev" style="--c:{color}">{_esc(f.severity.label)}</span>
        <span class="ftitle"><span class="num">{i}.</span> {_esc(f.title)} {fixed}</span>
        <code class="floc">{_esc(f.where)}</code>
        <span class="chev" aria-hidden="true">&#9662;</span>
      </button>
      <div class="fbody">
        <div class="tags"><span class="scanner">{_esc(f.scanner)}</span>{cat}</div>
        {''.join(blocks)}
      </div>
    </article>"""


@register("html", ".html")
def to_html(report: Report) -> bytes:
    counts = report.counts()
    findings = "".join(_finding_card(i, f) for i, f in enumerate(report.findings, 1))
    if not findings:
        findings = ('<div class="empty"><h2>No findings</h2>'
                    '<p>This scan found nothing to report.</p></div>')

    # Only show filter buttons for severities that actually appear.
    present = [s for s in _SEV_ORDER if counts[s]]
    filters = '<button class="fbtn on" data-f="all">All ' \
              f'<b>{report.total}</b></button>'
    filters += "".join(
        f'<button class="fbtn" data-f="{s.lower()}">{s} <b>{counts[s]}</b></button>'
        for s in present)
    toolbar = "" if not report.findings else f"""
<div class="toolbar">
  <input class="search" type="search" placeholder="Search findings…"
         aria-label="Search findings">
  <div class="filters">{filters}</div>
  <div class="tools">
    <span class="count" aria-live="polite">{report.total} shown</span>
    <button class="tbtn" data-x="expand">Expand all</button>
    <button class="tbtn" data-x="collapse">Collapse all</button>
  </div>
</div>"""

    meta = [
        ("Target", report.target),
        ("Type", report.target_kind),
        ("Scan date", report.started.strftime("%Y-%m-%d %H:%M UTC")),
        ("Duration", _duration(report)),
        ("Modules run", ", ".join(report.scanners_run) or "—"),
        ("Tool", f"WebScanX {report.tool_version}".strip()),
    ]
    meta_html = "".join(
        f'<div class="m"><span>{_esc(k)}</span><b>{_esc(v)}</b></div>'
        for k, v in meta)

    doc = f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebScanX report — {_esc(report.target)}</title>
<style>
/* dark-first; light applied by system preference OR the toggle (data-theme) */
:root{{color-scheme:dark light;
  --bg:#0a0f1e;--card:#131a2c;--card2:#182036;--raised:#1e2740;--rule:rgba(255,255,255,.09);
  --ink:#f2f5fb;--mut:#9aa6c0;--faint:#647089;--accent:#38bdf8;
  --brand1:#818cf8;--brand2:#22d3ee;
  --glow1:rgba(99,102,241,.20);--glow2:rgba(34,211,238,.16);
  --shadow:0 8px 30px rgba(0,0,0,.35);
  --sf:-apple-system,BlinkMacSystemFont,"SF Pro Display","SF Pro Text","Segoe UI",Roboto,system-ui,sans-serif;
  --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace}}
:root[data-theme=light]{{--bg:#f4f5fb;--card:#fff;--card2:#fff;--raised:#eef0f6;
  --rule:#e4e6ef;--ink:#141a24;--mut:#5b6577;--faint:#8a92a6;--accent:#4f46e5;
  --brand1:#6d5efc;--brand2:#0ea5c4;
  --glow1:rgba(129,140,248,.14);--glow2:rgba(14,165,196,.10);
  --shadow:0 6px 24px rgba(20,26,54,.08)}}
@media(prefers-color-scheme:light){{:root:not([data-theme=dark]){{--bg:#f4f5fb;--card:#fff;
  --card2:#fff;--raised:#eef0f6;--rule:#e4e6ef;--ink:#141a24;--mut:#5b6577;--faint:#8a92a6;
  --accent:#4f46e5;--brand1:#6d5efc;--brand2:#0ea5c4;
  --glow1:rgba(129,140,248,.14);--glow2:rgba(14,165,196,.10);
  --shadow:0 6px 24px rgba(20,26,54,.08)}}}}
*{{box-sizing:border-box}}
body{{margin:0;color:var(--ink);
  background:
    radial-gradient(1200px 620px at 8% -12%,var(--glow1),transparent 55%),
    radial-gradient(1000px 560px at 108% -6%,var(--glow2),transparent 52%),
    var(--bg);
  background-attachment:fixed;
  font:16px/1.55 var(--sf);-webkit-font-smoothing:antialiased;
  transition:background .25s ease,color .25s ease}}
.wrap{{max-width:960px;margin:0 auto;padding:26px 22px 80px}}
a{{color:var(--accent);text-decoration:none}}
/* top bar */
.top{{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px}}
.brand{{font-weight:800;font-size:21px;letter-spacing:-.02em;
  background:linear-gradient(90deg,var(--brand1),var(--brand2));
  -webkit-background-clip:text;background-clip:text;color:transparent}}
.topr{{display:flex;align-items:center;gap:10px}}
.theme{{width:38px;height:38px;display:grid;place-items:center;font-size:15px;cursor:pointer;
  background:var(--card);border:1px solid var(--rule);border-radius:999px;color:var(--ink);
  box-shadow:var(--shadow)}}
.top .tag{{display:inline-flex;align-items:center;gap:7px;font-size:12px;color:var(--mut);
  background:var(--card);border:1px solid var(--rule);padding:9px 14px;border-radius:999px;
  box-shadow:var(--shadow)}}
.top .tag::before{{content:"";width:7px;height:7px;border-radius:50%;background:#30d158;
  box-shadow:0 0 8px #30d158}}
/* hero */
.hero{{display:grid;grid-template-columns:auto 1fr;gap:30px;align-items:center;
  background:var(--card);border:1px solid var(--rule);border-radius:22px;
  padding:30px 34px;margin:0 0 14px;box-shadow:var(--shadow)}}
.gaugewrap{{display:flex;flex-direction:column;align-items:center;gap:14px}}
.gauge{{width:150px;height:150px}}
.gtrack{{fill:none;stroke:var(--raised);stroke-width:9}}
.gval{{fill:none;stroke-width:9;stroke-linecap:round;
  filter:drop-shadow(0 0 5px color-mix(in srgb,var(--c) 55%,transparent))}}
.gnum{{font:700 36px/1 var(--sf);text-anchor:middle;fill:var(--ink)}}
.glab{{font:600 8.5px/1 var(--sf);letter-spacing:.18em;fill:var(--faint);text-anchor:middle}}
.gband{{font-size:13px;font-weight:600;color:var(--c);
  background:color-mix(in srgb,var(--c) 14%,transparent);border-radius:999px;padding:8px 15px}}
.heromain{{min-width:0}}
.eyebrow{{font-size:13px;font-weight:600;color:var(--accent);letter-spacing:-.01em;margin:0 0 8px}}
.target{{font:700 clamp(24px,3.6vw,36px)/1.1 var(--sf);color:var(--ink);
  margin:0 0 12px;word-break:break-word;letter-spacing:-.03em}}
.lede{{color:var(--mut);font-size:17px;margin:0}}
.lede b{{color:var(--ink);font-weight:600}}
/* severity tiles */
.tiles{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:14px 0 0}}
.tile{{background:var(--card);border:1px solid var(--rule);border-radius:18px;
  padding:18px 12px;text-align:center;box-shadow:var(--shadow)}}
.tile b{{display:block;font:700 30px/1 var(--sf);color:var(--c);margin-bottom:5px;letter-spacing:-.02em}}
.tile span{{font-size:12px;font-weight:500;color:var(--mut)}}
.tile.dim{{box-shadow:none;background:transparent;border-style:dashed;opacity:.6}}
.tile.dim b{{color:var(--faint)}}
@media(max-width:720px){{.hero{{grid-template-columns:1fr;text-align:center}}
  .tiles{{grid-template-columns:repeat(3,1fr)}}}}
@media(max-width:420px){{.tiles{{grid-template-columns:repeat(2,1fr)}}}}
/* meta */
.meta{{display:grid;grid-template-columns:repeat(5,1fr);background:var(--card);
  border:1px solid var(--rule);border-radius:18px;padding:6px;margin:14px 0 34px;
  box-shadow:var(--shadow)}}
@media(max-width:720px){{.meta{{grid-template-columns:repeat(3,1fr)}}}}
@media(max-width:420px){{.meta{{grid-template-columns:repeat(2,1fr)}}}}
.m{{padding:14px 16px}}
.m span{{display:block;font-size:11px;color:var(--faint);margin-bottom:4px}}
.m b{{font-weight:600;font-size:13px;font-family:var(--mono);word-break:break-word}}
/* toolbar */
.toolbar{{position:sticky;top:0;z-index:10;
  background:color-mix(in srgb,var(--bg) 82%,transparent);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  margin:0 0 18px;padding:14px 0;display:flex;flex-wrap:wrap;gap:10px;align-items:center}}
.search{{flex:1 1 220px;min-width:150px;font:15px/1 var(--sf);color:var(--ink);
  background:var(--card);border:1px solid var(--rule);border-radius:12px;
  padding:12px 15px;outline:none;box-shadow:var(--shadow)}}
.search:focus{{border-color:var(--accent)}}
.search::placeholder{{color:var(--faint)}}
.filters{{display:flex;flex-wrap:wrap;gap:6px}}
.fbtn{{font:500 13px/1 var(--sf);color:var(--ink);background:var(--card);
  border:1px solid var(--rule);border-radius:999px;padding:10px 15px;cursor:pointer;
  box-shadow:var(--shadow);transition:background .12s,color .12s}}
.fbtn b{{color:var(--faint);margin-left:5px;font-weight:600}}
.fbtn.on{{background:linear-gradient(90deg,var(--brand1),var(--brand2));
  border-color:transparent;color:#08111f}}
.fbtn.on b{{color:#08111f;opacity:.7}}
.tools{{display:flex;align-items:center;gap:6px;margin-left:auto}}
.count{{font-size:13px;color:var(--faint);white-space:nowrap;margin-right:4px}}
.tbtn{{font:500 13px/1 var(--sf);color:var(--accent);background:none;border:none;
  cursor:pointer;padding:10px 8px;border-radius:8px}}
.tbtn:hover{{background:var(--raised)}}
/* findings */
.finding{{background:var(--card);border:1px solid var(--rule);border-radius:18px;
  margin:0 0 12px;overflow:hidden;box-shadow:var(--shadow)}}
.finding.hide{{display:none}}
.fhead{{display:flex;align-items:center;gap:13px;width:100%;text-align:left;
  background:none;border:0;color:inherit;cursor:pointer;padding:18px 22px;
  font:inherit;transition:background .12s}}
.fhead:hover{{background:var(--raised)}}
.sev{{flex:0 0 auto;font:600 12px/1 var(--sf);color:var(--c);
  background:color-mix(in srgb,var(--c) 15%,transparent);padding:7px 12px;border-radius:999px}}
.ftitle{{font-size:18px;font-weight:600;line-height:1.3;letter-spacing:-.01em}}
.ftitle .num{{color:var(--faint);font-weight:600}}
.floc{{margin-left:auto;font-family:var(--mono);font-size:12.5px;color:var(--faint);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:32%}}
.chev{{flex:0 0 auto;color:var(--faint);transition:transform .2s;font-size:12px}}
.finding.open .chev{{transform:rotate(180deg)}}
.fixed{{font:600 10px/1 var(--sf);color:#fff;background:#30d158;
  padding:5px 8px;border-radius:999px;vertical-align:middle;margin-left:6px}}
.fbody{{display:none;padding:0 22px 22px;border-top:1px solid var(--rule)}}
.finding.open .fbody{{display:block}}
.tags{{display:flex;flex-wrap:wrap;gap:8px;margin:18px 0}}
.scanner,.cat{{font:500 12px/1 var(--mono);padding:6px 11px;
  border-radius:999px;background:var(--raised);color:var(--mut)}}
.block{{margin:0 0 18px}}
.block:last-child{{margin-bottom:0}}
.block h3{{font-size:12px;letter-spacing:.03em;text-transform:uppercase;color:var(--faint);
  margin:0 0 6px;font-weight:600}}
.block p{{margin:0;color:var(--ink);opacity:.86;font-size:15.5px}}
.ev{{position:relative}}
.ev pre,.block pre{{margin:0;font:13px/1.6 var(--mono);
  background:var(--raised);border-radius:12px;
  padding:14px 16px;overflow-x:auto;color:#e0709a;white-space:pre-wrap;word-break:break-word}}
.copy{{position:absolute;top:9px;right:9px;font:500 12px/1 var(--sf);
  color:var(--accent);background:var(--card);
  border:1px solid var(--rule);border-radius:999px;padding:6px 12px;cursor:pointer}}
.copy.done{{color:#fff;background:var(--accent);border-color:transparent}}
.block ul{{margin:0;padding-left:18px}}
.block li{{font:13px/1.7 var(--mono);word-break:break-all;margin:2px 0}}
.noresult{{display:none;color:var(--mut);text-align:center;padding:36px;font-size:15px}}
.empty{{background:var(--card);border:1px solid var(--rule);border-radius:18px;
  padding:44px;text-align:center;color:var(--mut);box-shadow:var(--shadow)}}
.empty h2{{margin:0 0 6px;color:var(--ink)}}
footer{{margin-top:44px;text-align:center;color:var(--faint);font-size:13px}}
@media(max-width:560px){{.floc{{display:none}}.tools{{margin-left:0}}}}
/* print: force light, expand everything, hide controls */
@media print{{
  :root{{--bg:#fff;--card:#fff;--card2:#fff;--raised:#f4f4f4;--rule:#d5d5d5;
    --ink:#111;--mut:#444;--faint:#777;--shadow:none}}
  body{{background:#fff;color:#111}}
  .toolbar,.theme{{display:none}}
  .fbody{{display:block!important}}.chev{{display:none}}
  .finding{{break-inside:avoid;page-break-inside:avoid}}
  .ev pre,.block pre{{color:#8a2b12}}
  a{{color:#06c}}
}}
</style></head><body><div class="wrap">
<div class="top"><span class="brand">webscanx</span>
  <div class="topr">
    <button class="theme" type="button" aria-label="Toggle light or dark">&#9680;</button>
    <span class="tag">Authorised testing only</span>
  </div></div>
<section class="hero">
  <div class="gaugewrap">{_gauge_svg(_risk(report)[0], _risk(report)[2])}
    <span class="gband" style="--c:{_risk(report)[2]}">{_risk(report)[1]}</span>
  </div>
  <div class="heromain">
    <p class="eyebrow">Security scan report</p>
    <h1 class="target">{_esc(report.target)}</h1>
    <p class="lede"><b>{report.total} findings</b> across {len(report.scanners_run)} modules. {_risk(report)[3]}</p>
    <div class="tiles">{_stat_tiles(report)}</div>
  </div>
</section>
<div class="meta">{meta_html}</div>
{toolbar}
{findings}
<p class="noresult">No findings match your search.</p>
<footer>Generated by WebScanX {_esc(report.tool_version)} — a local security scanner.<br>
Nothing in this report left your device. Scan only systems you are authorised to test.</footer>
</div>
<script>
(function(){{
  // theme toggle: dark-first, honours system, remembers the viewer's choice
  var root=document.documentElement, tbtn=document.querySelector('.theme');
  function eff(){{var t=root.getAttribute('data-theme');
    return t||(matchMedia('(prefers-color-scheme:light)').matches?'light':'dark');}}
  function icon(){{if(tbtn) tbtn.textContent=eff()==='dark'?'☀':'☾';}}
  try{{var saved=localStorage.getItem('wsx-theme');if(saved)root.setAttribute('data-theme',saved);}}catch(e){{}}
  icon();
  if(tbtn) tbtn.addEventListener('click',function(){{
    var n=eff()==='dark'?'light':'dark';root.setAttribute('data-theme',n);
    try{{localStorage.setItem('wsx-theme',n);}}catch(e){{}}
    icon();
  }});

  var cards=[].slice.call(document.querySelectorAll('.finding'));
  var fbtns=[].slice.call(document.querySelectorAll('.fbtn'));
  var search=document.querySelector('.search');
  var count=document.querySelector('.count');
  var none=document.querySelector('.noresult');
  var sev='all', q='';

  function apply(){{
    var shown=0;
    cards.forEach(function(c){{
      var ok=(sev==='all'||c.dataset.sev===sev)&&
             (!q||c.dataset.text.indexOf(q)>-1);
      c.classList.toggle('hide',!ok);
      if(ok) shown++;
    }});
    if(count) count.textContent=shown+' shown';
    if(none) none.style.display=shown?'none':'block';
  }}

  fbtns.forEach(function(b){{b.addEventListener('click',function(){{
    fbtns.forEach(function(x){{x.classList.remove('on')}});
    b.classList.add('on'); sev=b.dataset.f; apply();
  }})}});

  if(search) search.addEventListener('input',function(){{
    q=search.value.trim().toLowerCase(); apply();
  }});

  // expand/collapse a single finding
  cards.forEach(function(c){{
    var head=c.querySelector('.fhead');
    head.addEventListener('click',function(){{
      var open=c.classList.toggle('open');
      head.setAttribute('aria-expanded',open?'true':'false');
    }});
  }});

  // expand-all / collapse-all act on currently visible findings
  [].forEach.call(document.querySelectorAll('.tbtn'),function(b){{
    b.addEventListener('click',function(){{
      var open=b.dataset.x==='expand';
      cards.forEach(function(c){{
        if(c.classList.contains('hide')) return;
        c.classList.toggle('open',open);
        c.querySelector('.fhead').setAttribute('aria-expanded',open?'true':'false');
      }});
    }});
  }});

  // copy evidence blocks
  [].forEach.call(document.querySelectorAll('.copy'),function(b){{
    b.addEventListener('click',function(e){{
      e.stopPropagation();
      var txt=b.previousElementSibling.textContent;
      var done=function(){{b.textContent='Copied';b.classList.add('done');
        setTimeout(function(){{b.textContent='Copy';b.classList.remove('done')}},1400);}};
      if(navigator.clipboard&&navigator.clipboard.writeText){{
        navigator.clipboard.writeText(txt).then(done,done);
      }} else {{
        var t=document.createElement('textarea');t.value=txt;document.body.appendChild(t);
        t.select();try{{document.execCommand('copy')}}catch(_){{}};document.body.removeChild(t);done();
      }}
    }});
  }});
}})();
</script>
</body></html>"""
    return doc.encode("utf-8")


# ── PDF — deferred to Phase 2 (needs a PDF lib). Honest placeholder for now. ──
@register("pdf", ".pdf")
def to_pdf(report: Report) -> bytes:
    raise NotImplementedError(
        "PDF export arrives in Phase 2. For now use html and print-to-PDF, "
        "or export md/txt/json/csv/sarif."
    )


def demo() -> None:
    r = Report(target="https://example.com", target_kind="web", tool_version="0.1")
    r.findings = [Finding("Reflected XSS", "high", "/s?q=", "web.xss",
                          what="User input echoed unescaped.",
                          how_to_check="Submit <script>alert(1)</script> and view source.",
                          evidence="<script>alert(1)</script>",
                          remediation="HTML-encode output.", category="A03 / CWE-79")]
    for fmt in ("json", "txt", "md", "csv", "sarif", "html"):
        blob = render(r, fmt)
        assert isinstance(blob, bytes) and blob, fmt
        assert b"XSS" in blob or b"xss" in blob, fmt
    assert json.loads(render(r, "json"))["total"] == 1
    assert render(r, "sarif")  # valid json already asserted by loads below
    json.loads(render(r, "sarif"))
    try:
        render(r, "pdf")
        assert False, "pdf should raise until Phase 2"
    except NotImplementedError:
        pass
    assert set(formats()) >= {"json", "txt", "md", "csv", "sarif", "html", "pdf"}
    print("render: ok")


if __name__ == "__main__":
    demo()
