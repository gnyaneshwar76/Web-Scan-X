"""Report Options and the stdlib PDF writer. Run: python tests/test_report_options.py"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from webscanx.core.finding import Finding                  # noqa: E402
from webscanx.report import Options, Report                # noqa: E402
from webscanx.report import render as R                    # noqa: E402


def _report():
    r = Report(target="https://example.com/?k=secretsecret123456", target_kind="web")
    r.findings = [
        Finding("Reflected XSS", "high", "/s?token=abcdef1234567890XYZ", "web.xss",
                evidence="EVIDENCE-MARK abcdef1234567890XYZ"),
        Finding("Missing header", "low", "/", "web.headers", evidence="EVIDENCE-LOW"),
    ]
    return r


def test_options():
    r = _report()
    fp = r.findings[0].fingerprint
    assert json.loads(R.render(r, "json"))["total"] == 2
    assert json.loads(R.render(r, "json", Options(ignored=frozenset({fp}))))["total"] == 1
    no_ev = R.render(r, "json", Options(evidence=False))
    assert b"EVIDENCE-MARK" not in no_ev and b"EVIDENCE-LOW" not in no_ev
    red = R.render(r, "json", Options(redact=True))
    assert b"secretsecret123456" not in red and b"abcdef1234567890XYZ" not in red
    assert len(r.findings) == 2 and r.findings[0].evidence.startswith("EVIDENCE-MARK")  # original untouched
    for fmt in R.formats():
        assert R.render(r, fmt, Options(redact=True, evidence=False)), fmt


def test_redact_and_csv():
    from webscanx.report.report import _mask
    assert "abc" not in _mask("Authorization: Bearer abc") and "pw1" not in _mask("password=pw1")
    assert "sid" not in _mask("Set-Cookie: s=sid; Path=/")
    assert _mask("/api/v1/authentication") == "/api/v1/authentication"
    assert _mask("https://evil.example/x") == "https://<target>/x"
    r = Report(target="https://h.test/", target_kind="web")
    r.findings = [Finding("=BAD title", "low", "/", "web.x", references=["https://h.test/?a=1"])]
    v = r.view(Options(redact=True))
    assert "h.test" not in v.findings[0].references[0]
    assert R.render(r, "csv").split(b"\n")[1].split(b",")[1:3] == [b"Low", b"'=BAD title"]


def test_csv_guard_tab_cr():
    import csv, io
    r = Report(target="https://h.test/", target_kind="web")
    r.findings = [Finding(t, "low", "/", "web.x") for t in ("\t=cmd", "\r=cmd", "+1", "-1", "@a")]
    rows = list(csv.reader(io.StringIO(R.render(r, "csv").decode(), newline="")))[1:]
    assert [row[2] for row in rows] == ["'\t=cmd", "'\r=cmd", "'+1", "'-1", "'@a"], rows


def test_pdf():
    pdf = R.render(_report(), "pdf")
    assert pdf.startswith(b"%PDF-") and pdf.rstrip().endswith(b"%%EOF")
    assert b"xref" in pdf and b"trailer" in pdf
    assert R.extension("pdf") == ".pdf"
    assert R.render(Report(target="x", target_kind="web"), "pdf").startswith(b"%PDF-")


def load_tests(loader, standard_tests, pattern):   # lets unittest/discover run the bare test_* functions
    from tests._fn import collect
    return collect(sys.modules[__name__])


if __name__ == "__main__":
    test_options()
    test_redact_and_csv()
    test_pdf()
    print("report options: ok")
