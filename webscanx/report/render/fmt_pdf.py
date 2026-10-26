"""PDF export: a minimal stdlib-only writer (Courier text, A4, paginated)."""

from __future__ import annotations

import textwrap

from ..report import Report
from ._registry import register

_W, _H, _MARGIN, _LEAD, _SIZE = 595, 842, 50, 13, 10
_PER_PAGE = (_H - 2 * _MARGIN) // _LEAD
_COLS = 84  # Courier 10pt = 6pt/char; A4 text width 495pt


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _lines(report: Report) -> list[str]:
    from .fmt_txt import to_txt
    out: list[str] = []
    for raw in to_txt(report).decode("utf-8").split("\n"):
        out += textwrap.wrap(raw, _COLS, subsequent_indent="      ",
                             drop_whitespace=False) or [""]
    return out


@register("pdf", ".pdf")
def to_pdf(report: Report) -> bytes:
    lines = _lines(report)
    pages = [lines[i:i + _PER_PAGE] for i in range(0, len(lines), _PER_PAGE)] or [[]]
    # objects: 1 catalog, 2 pages, 3 font, then (page, content) pairs
    objs: list[bytes] = [b"", b"",
                         b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier "
                         b"/Encoding /WinAnsiEncoding >>"]
    kids = []
    for pg in pages:
        body = [f"BT /F1 {_SIZE} Tf {_LEAD} TL {_MARGIN} {_H - _MARGIN} Td"]
        body += [f"({_esc(t)}) '" for t in pg]
        body.append("ET")
        stream = "\n".join(body).encode("cp1252", "replace")
        page_no = len(objs) + 1
        kids.append(f"{page_no} 0 R")
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {_W} {_H}] "
                    f"/Resources << /Font << /F1 3 0 R >> >> "
                    f"/Contents {page_no + 1} 0 R >>".encode())
        objs.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
    objs[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objs[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(pages)} >>".encode()

    out = bytearray(b"%PDF-1.4\n")
    offs = []
    for n, o in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj\n" % n + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offs:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)
