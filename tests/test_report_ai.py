"""Optional AI results in reports. Run: python tests/test_report_ai.py"""

import csv
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from webscanx.core.finding import Finding                  # noqa: E402
from webscanx.report import Options, Report                # noqa: E402
from webscanx.report import render as R                    # noqa: E402


def _report(kind="web", ai="default"):
    r = Report(target="https://h.example/", target_kind=kind)
    r.findings = [Finding("Reflected XSS", "high", "/a", "web.xss"),
                  Finding("Missing header", "low", "/", "web.headers")]
    a, b = (f.fingerprint for f in r.findings)
    if ai == "default":
        ai = {"mode": "cloud", "model": "m1", "summary": "Sum <script>x</script> https://h.example/p?token=abcdef1234567890",
              "fix_first": [b, "nope"],
              "notes": {a: {"verdict": "real", "why": "WHY-A <b>"},
                        b: {"verdict": "hacked", "why": "bad verdict"},
                        "nope": {"verdict": "real", "why": "unknown fp"}}}
    r.ai = ai
    return r


def test_validation_and_json():
    r = _report()
    doc = json.loads(R.render(r, "json"))
    assert [f["title"] for f in doc["findings"]] == ["Reflected XSS", "Missing header"]
    assert list(doc["ai"]["notes"]) == [r.findings[0].fingerprint]
    assert doc["ai"]["fix_first"] == [r.findings[1].fingerprint]
    assert "ai" not in json.loads(R.render(_report(ai=None), "json"))
    big = _report(ai={"summary": "x" * 99999, "notes": "junk", "fix_first": 5})
    assert len(json.loads(R.render(big, "json"))["ai"]["summary"]) <= 2000


def test_formats():
    r = _report()
    assert b"AI suggestions - check them yourself" in R.render(r, "txt")
    html = R.render(r, "html")
    assert b"<script>x" not in html and b"WHY-A &lt;b&gt;" in html
    md = R.render(r, "md")
    assert b"<script>" not in md and b"WHY-A" in md and b"Fix first: #2" in md
    rows = list(csv.reader(io.StringIO(R.render(r, "csv").decode())))
    assert rows[0][-2:] == ["ai_verdict", "ai_why"] and rows[1][-2:] == ["real", "WHY-A <b>"]
    assert "ai_verdict" not in R.render(_report(ai=None), "csv").decode()
    sar = json.loads(R.render(r, "sarif"))["runs"][0]["results"]
    assert sar[0]["properties"]["ai"]["verdict"] == "real" and "properties" not in sar[1]
    assert R.render(r, "pdf").startswith(b"%PDF")


def test_error_redact_kinds():
    e = _report(ai={"error": "boom"})
    assert b"AI step failed" in R.render(e, "txt") and b"unaffected" in R.render(e, "md")
    red = R.render(_report(), "json", Options(redact=True))
    assert b"abcdef1234567890" not in red and b"h.example" not in red
    for kind in ("mobile", "desktop"):
        for fmt in R.formats():
            assert R.render(_report(kind), fmt), (kind, fmt)


def load_tests(loader, standard_tests, pattern):   # lets unittest/discover run the bare test_* functions
    from tests._fn import collect
    return collect(sys.modules[__name__])


if __name__ == "__main__":
    test_validation_and_json(); test_formats(); test_error_redact_kinds()
    print("test_report_ai: ok")
