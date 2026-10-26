"""One report object: the findings plus everything about the run that produced
them. Every export format is built from this and nothing else."""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone

from ..core.finding import Finding, Severity


@dataclass(frozen=True)
class Options:
    """What to leave out of an export. Defaults export everything as found."""

    evidence: bool = True                       # False: drop the evidence field
    ignored: frozenset[str] = frozenset()       # finding fingerprints to omit
    # True: mask URL hosts (scheme kept, host -> <target>), query values, values of
    # Authorization/Cookie/password/token/secret/api-key fields, and long mixed tokens
    # Target note: with redact on, the host is masked in finding text (where/what/...)
    # AND in the report header target, so an export shows e.g. https://<target>/path
    # (scheme and path kept, host gone). Turn redact off to show the real target.
    redact: bool = False


_QUERY = re.compile(r"([?&][^=&#\s]+=)[^&#\s]*")
# long run that mixes letters and digits; plain words/path segments don't match
_TOKEN = re.compile(r"(?<![A-Za-z0-9_\-+=])(?=[A-Za-z_\-+=]*\d)(?=[0-9_\-+=]*[A-Za-z])"
                    r"[A-Za-z0-9_\-+=]{16,}")
# value after a secret-style field name, any length
_FIELD = re.compile(r"(?i)\b(authorization|set-cookie|cookie|passw(?:or)?d|token|secret|api[_ -]?key)"
                    r"(\"?\s*[:=]\s*\"?)[^\r\n&\"']+")
_HOST = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*://)[^/?#\s\"']+")


def _mask(s: str) -> str:
    s = _HOST.sub(lambda m: m.group(1) + "<target>", s)  # hostname (and userinfo) masked
    s = _QUERY.sub(lambda m: m.group(1) + "REDACTED", s)
    s = _FIELD.sub(lambda m: m.group(1) + m.group(2) + "REDACTED", s)
    return _TOKEN.sub(lambda m: m.group(0)[:4] + "***", s)


_VERDICTS = ("real", "likely-false-alarm", "unsure")
_CAP = {"summary": 2000, "why": 500, "model": 80, "error": 300}


def _txt(v, cap: int) -> str:
    return " ".join(v.split())[:cap] if isinstance(v, str) else ""


def clean_ai(ai, fingerprints, mask=None) -> dict | None:
    """Model output is untrusted: keep only known keys, known fingerprints and
    verdicts, cap lengths, and (if mask) redact the text. Never raises."""
    if not isinstance(ai, dict):
        return None
    m = mask or (lambda x: x)
    known = set(fingerprints)
    out = {"mode": ai.get("mode") if ai.get("mode") in ("local", "cloud") else "",
           "model": m(_txt(ai.get("model"), _CAP["model"])),
           "summary": m(_txt(ai.get("summary"), _CAP["summary"])),
           "fix_first": [], "notes": {}}
    ff = ai.get("fix_first")
    for fp in ff[:50] if isinstance(ff, list) else []:
        if isinstance(fp, str) and fp in known and fp not in out["fix_first"]:
            out["fix_first"].append(fp)
    notes = ai.get("notes")
    for fp, n in (notes.items() if isinstance(notes, dict) else []):
        if fp in known and isinstance(n, dict) and n.get("verdict") in _VERDICTS:
            out["notes"][fp] = {"verdict": n["verdict"], "why": m(_txt(n.get("why"), _CAP["why"]))}
    if ai.get("error"):
        out["error"] = m(_txt(ai["error"], _CAP["error"])) or "AI step failed"
    return out


@dataclass
class Report:
    target: str
    target_kind: str
    findings: list[Finding] = field(default_factory=list)
    started: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished: datetime | None = None
    tool_version: str = ""
    scanners_run: list[str] = field(default_factory=list)
    options: Options = field(default_factory=Options)
    ai: dict | None = None   # optional, from webscanx.ai; shown beside findings, never changes them

    def view(self, options: Options | None = None) -> "Report":
        """A copy with the options applied; the original is never changed."""
        o = options or self.options
        out = []
        for f in self.findings:
            if f.fingerprint in o.ignored:
                continue
            ch = {}
            if not o.evidence:
                ch["evidence"] = ""
            if o.redact:
                for k in ("evidence", "where", "what", "how_to_check", "title"):
                    ch[k] = _mask(ch.get(k, getattr(f, k)))
                ch["references"] = [_mask(x) for x in f.references]
            out.append(replace(f, **ch) if ch else f)
        ai = clean_ai(self.ai, [f.fingerprint for f in out], _mask if o.redact else None)
        return replace(self, findings=out, options=Options(), ai=ai,
                       target=_mask(self.target) if o.redact else self.target)

    def counts(self) -> dict[str, int]:
        """Findings per severity label, highest first — for the summary line."""
        out = {s.label: 0 for s in reversed(Severity)}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def fixed_count(self) -> int:
        return sum(1 for f in self.findings if f.fixed)

    def summary_line(self) -> str:
        c = self.counts()
        parts = [f"{n} {label.lower()}" for label, n in c.items() if n]
        body = ", ".join(parts) if parts else "no findings"
        return f"{self.total} findings ({body})"


def demo() -> None:
    r = Report(target="https://example.com", target_kind="web")
    r.findings = [
        Finding("XSS", "high", "/a", "web.xss"),
        Finding("Missing header", "low", "/", "web.headers"),
        Finding("Old lib", "medium", "req.txt:3", "code.deps", fixed=True),
    ]
    c = r.counts()
    assert c["High"] == 1 and c["Low"] == 1 and c["Medium"] == 1
    assert r.total == 3 and r.fixed_count == 1
    assert "3 findings" in r.summary_line()
    v = r.view(Options(ignored=frozenset({r.findings[0].fingerprint}), redact=True))
    assert v.total == 2 and r.total == 3
    assert _mask("https://x/a?token=abcdef1234567890XYZ") == "https://<target>/a?token=REDACTED"
    f0 = r.findings[1]
    r.ai = {"summary": "see <b>x</b> https://h.test/?a=1", "fix_first": [f0.fingerprint, "bogus"],
            "notes": {f0.fingerprint: {"verdict": "real", "why": "w"}, "bogus": {"verdict": "real"},
                      r.findings[2].fingerprint: {"verdict": "evil"}}}
    c = r.view().ai
    assert c["fix_first"] == [f0.fingerprint] and list(c["notes"]) == [f0.fingerprint]
    assert "h.test" not in r.view(Options(redact=True)).ai["summary"] and clean_ai("x", []) is None
    print("report.py: ok")


if __name__ == "__main__":
    demo()
