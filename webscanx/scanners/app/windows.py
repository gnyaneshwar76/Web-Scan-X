"""app.windows - static hardening checks of Windows programs (.exe .dll .sys .msi).

Like the basics of Microsoft BinSkim: reads PE header flags, never runs the file.
Stdlib only. Every offset is bounds-checked; anything odd becomes an Info finding.
"""

from __future__ import annotations

import os
import re
import stat
import struct

from ...core.engine import register
from ...core.finding import Finding
from ...core.target import TargetKind
from ..code.secrets import RULES as SECRET_RULES
from ._safe import MAX_MEMBER, UnsafeFile, read_file

_EXTS = {".exe", ".dll", ".sys", ".msi"}
_REFS = ("https://learn.microsoft.com/en-us/windows/win32/debug/pe-format",)
_DYNAMIC_BASE, _HIGH_ENTROPY, _NX_COMPAT, _GUARD_CF = 0x40, 0x20, 0x100, 0x4000
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_STR = re.compile(rb"[\x20-\x7e]{8,200}")
_URL = re.compile(r"http://[^\s\"'<>]{4,}")
_MAX_STRINGS = 50_000
MAX_SCAN_BYTES = 128 * 1024 * 1024   # total bytes string-scanned per file
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_SIG_STREAM = "\x05DigitalSignature"


class _Bad(Exception):
    pass


def _f(where, title, sev, what, fix="", evidence="", check=""):
    where = _CTRL.sub("", str(where))[:200]
    return Finding(title=title, severity=sev, where=where, scanner="app.windows",
                   what=what, remediation=fix, evidence=evidence,
                   how_to_check=check or "Run a tool such as BinSkim or Sigcheck on the file to confirm.",
                   category="MASVS-CODE / CWE-693 (Protection Mechanism Failure)",
                   references=list(_REFS))


def _mask(s: str) -> str:
    return s[:4] + "***" if len(s) > 4 else "***"


def _u(data, off, fmt):
    size = struct.calcsize(fmt)
    if off < 0 or off + size > len(data):
        raise _Bad("header runs past the end of the file")
    return struct.unpack_from(fmt, data, off)[0]


def parse_pe(data: bytes) -> dict:
    if data[:2] != b"MZ":
        raise _Bad("no MZ header (not a PE file)")
    pe = _u(data, 0x3C, "<I")
    if data[pe:pe + 4] != b"PE\0\0":
        raise _Bad("no PE signature")
    opt_size = _u(data, pe + 20, "<H")
    opt = pe + 24
    magic = _u(data, opt, "<H")
    if magic not in (0x10B, 0x20B):
        raise _Bad("unknown optional header magic")
    plus = magic == 0x20B
    dd = opt + (112 if plus else 96)
    cert_size = 0
    if _u(data, dd - 4, "<I") > 4 and dd + 40 <= opt + opt_size:
        cert_size = _u(data, dd + 4 * 8 + 4, "<I")
    return {"plus": plus, "cert": cert_size > 0, "dll_chars": _u(data, opt + 70, "<H")}


def _ole_has_signature(data: bytes) -> bool:
    """Walk the OLE directory chain (bounded) for the DigitalSignature stream."""
    if len(data) < 512 or data[:8] != _OLE_MAGIC:
        raise _Bad("not an OLE compound file")
    shift = _u(data, 0x1E, "<H")
    if not 7 <= shift <= 16:
        raise _Bad("bad OLE sector size")
    ssz = 1 << shift
    n_fat = min(_u(data, 0x2C, "<I"), 109)   # shortcut: header DIFAT only, upgrade for huge MSIs
    fat = []
    for i in range(n_fat):
        off = (_u(data, 0x4C + 4 * i, "<I") + 1) * ssz
        if off + ssz > len(data):
            raise _Bad("FAT sector outside the file")
        fat += struct.unpack_from(f"<{ssz // 4}I", data, off)
    sec, seen = _u(data, 0x30, "<I"), 0
    while sec < 0xFFFFFFF0 and seen < 4096:
        off = (sec + 1) * ssz
        if off + ssz > len(data):
            raise _Bad("directory sector outside the file")
        for e in range(off, off + ssz - 127, 128):
            n = _u(data, e + 64, "<H")
            if 2 <= n <= 64 and data[e:e + n - 2].decode("utf-16le", "replace") == _SIG_STREAM:
                return True
        if sec >= len(fat):
            raise _Bad("directory chain leaves the FAT")
        sec, seen = fat[sec], seen + 1
    return False


def _string_findings(data: bytes, where: str):
    hits, urls = {}, []
    for i, m in enumerate(_STR.finditer(data)):
        if i >= _MAX_STRINGS:
            break
        s = m.group().decode("ascii")
        for r in SECRET_RULES:
            hit = r.pattern.search(s)
            if hit and not (r.negate and r.negate.search(s)):
                hits.setdefault(r.title, []).append(_mask(hit.group()))
        u = _URL.search(s)
        if u and len(urls) < 5:
            urls.append(u.group()[:80])
    for title, vals in hits.items():
        yield _f(where, f"Likely hardcoded secret in strings: {title}", "high",
                 "A readable string in the program looks like a credential. Anyone can extract it.",
                 "Remove it from the binary, rotate it, and load secrets at run time.",
                 f"{len(vals)} match(es), masked: {', '.join(vals[:3])}",
                 "Run 'strings' on the file and search for the masked prefix.")
    if urls:
        yield _f(where, "Plain http:// URLs found in strings", "low",
                 "The program contains unencrypted URLs; traffic to them can be read or altered.",
                 "Use https:// endpoints.", "; ".join(urls))


def scan_bytes(data: bytes, where: str, ext: str, truncated: bool = False):
    if truncated:
        yield _f(where, "File larger than 64 MB, only the first 64 MB analyzed", "info",
                 "Results may miss later parts of the file.")
    try:
        if ext == ".msi":
            if not _ole_has_signature(data):
                yield _f(where, "MSI package is not signed", "medium",
                         "No digital signature stream found in the installer. Users cannot tell who made it or whether it was altered.",
                         "Sign the installer with an Authenticode code-signing certificate.")
            yield _f(where, "MSI analysis is limited", "info",
                     "Only signature presence and readable strings were checked; tables and custom actions were not.")
        else:
            p = parse_pe(data)
            c = p["dll_chars"]
            if not c & _DYNAMIC_BASE:
                yield _f(where, "ASLR (dynamic base) is off", "medium",
                         "The program always loads at a predictable address, which makes exploits easier.",
                         "Link with /DYNAMICBASE.")
            if not c & _NX_COMPAT:
                yield _f(where, "DEP (NX compatible) is off", "medium",
                         "Data memory may be executable, which makes code injection easier.",
                         "Link with /NXCOMPAT.")
            if p["plus"] and not c & _HIGH_ENTROPY:
                yield _f(where, "64-bit program without high-entropy ASLR", "low",
                         "ASLR in 64-bit space has less randomness than it could.",
                         "Link with /HIGHENTROPYVA.")
            if not c & _GUARD_CF:
                yield _f(where, "Control Flow Guard (CFG) is off", "low",
                         "Indirect calls are not checked against valid targets.",
                         "Compile and link with /guard:cf.")
            if not p["cert"]:
                yield _f(where, "File is not signed (no Authenticode certificate)", "medium",
                         "No certificate table found. Note: when one is present this scanner only sees that it exists; it does not validate it.",
                         "Sign the file with a code-signing certificate.",
                         check="Right-click the file, Properties, Digital Signatures tab; or run signtool verify /pa.")
        if len(data) > MAX_SCAN_BYTES:
            yield _f(where, "String scan stopped at size limit", "info",
                     f"Only the first {MAX_SCAN_BYTES >> 20} MB were scanned for secrets and URLs.")
        yield from _string_findings(data[:MAX_SCAN_BYTES], where)
    except (_Bad, struct.error, IndexError, ValueError) as e:
        yield _f(where, "Could not fully analyze this file", "info", f"Reason: {e}.")


@register(TargetKind.DESKTOP, "app.windows")
def scan(target, ctx):
    path = target.location
    ext = os.path.splitext(path)[1].lower()
    if ext not in _EXTS:
        return
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):      # never open a FIFO or device
            raise UnsafeFile("not a regular file")
        size = st.st_size
        if size > MAX_MEMBER:
            with open(path, "rb") as fh:
                data = fh.read(MAX_MEMBER)
        else:
            data = read_file(path, MAX_MEMBER)
    except (UnsafeFile, OSError) as e:
        yield _f(path, "Could not fully analyze this file", "info", f"Reason: {e}.")
        return
    yield from scan_bytes(data, path, ext, truncated=size > MAX_MEMBER)


def _pe(plus: bool, chars: int, cert: int = 0) -> bytes:
    opt_len = 240 if plus else 224
    opt = bytearray(opt_len)
    struct.pack_into("<H", opt, 0, 0x20B if plus else 0x10B)
    struct.pack_into("<H", opt, 70, chars)
    struct.pack_into("<I", opt, 108 if plus else 92, 16)
    struct.pack_into("<I", opt, (112 if plus else 96) + 36, cert)
    hdr = bytearray(0x40)
    hdr[:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664 if plus else 0x14C, 0, 0, 0, 0, opt_len, 0x2022)
    return bytes(hdr) + b"PE\0\0" + coff + bytes(opt)


def _ole(signed: bool) -> bytes:
    h = bytearray(512)
    h[:8] = _OLE_MAGIC
    struct.pack_into("<H", h, 0x1E, 9)
    struct.pack_into("<I", h, 0x2C, 1)           # one FAT sector (sector 0)
    struct.pack_into("<I", h, 0x30, 1)           # directory at sector 1
    fat = struct.pack("<128I", 0xFFFFFFFD, 0xFFFFFFFE, *([0xFFFFFFFF] * 126))
    d = bytearray(512)
    for i, name in enumerate(["Root Entry"] + ([_SIG_STREAM] if signed else [])):
        raw = name.encode("utf-16le") + b"\0\0"
        d[i * 128:i * 128 + len(raw)] = raw
        struct.pack_into("<H", d, i * 128 + 64, len(raw))
    return bytes(h) + fat + bytes(d)


def demo() -> None:
    def t(data, ext=".exe"):
        return {f.title: f for f in scan_bytes(data, "x", ext)}

    bad = t(_pe(True, 0))
    for k in ("ASLR (dynamic base) is off", "DEP (NX compatible) is off",
              "64-bit program without high-entropy ASLR", "Control Flow Guard (CFG) is off",
              "File is not signed (no Authenticode certificate)"):
        assert k in bad, k
    assert not t(_pe(False, 0x40 | 0x100 | 0x4000, cert=100))     # PE32, hardened, signed
    assert "64-bit program without high-entropy ASLR" not in t(_pe(True, 0x4160, 8))
    secret = t(_pe(False, 0x4140, 8) + b"\0AKIAIOSFODNN7EXAMPLE\0http://example.com/x\0")
    assert any("secret" in k for k in secret) and "Plain http:// URLs found in strings" in secret
    assert "AKIAIOSFODNN7EXAMPLE" not in "".join(f.evidence for f in secret.values())
    assert "MSI package is not signed" in t(_ole(False), ".msi")
    assert "MSI package is not signed" not in t(_ole(True), ".msi")
    assert "MSI analysis is limited" in t(_ole(True), ".msi")
    for junk, ext in ((b"junk bytes", ".exe"), (b"MZ" + b"\xff" * 64, ".exe"), (b"", ".dll"),
                      (_pe(True, 0)[:100], ".exe"), (_OLE_MAGIC + b"\xff" * 600, ".msi")):
        assert "Could not fully analyze this file" in t(junk, ext), (junk[:8], ext)
    global MAX_SCAN_BYTES
    old, MAX_SCAN_BYTES = MAX_SCAN_BYTES, 16
    try:
        assert "String scan stopped at size limit" in t(_pe(True, 0))
    finally:
        MAX_SCAN_BYTES = old
    assert "\x1b" not in _f("a\x1bb" + "q" * 300, "t", "info", "w").where
    assert len(_f("q" * 300, "t", "info", "w").where) == 200
    if hasattr(os, "mkfifo"):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            fp = os.path.join(d, "x.exe")
            os.mkfifo(fp)
            r = list(scan(type("T", (), {"location": fp})(), None))
            assert r and r[0].title == "Could not fully analyze this file"
    print("app/windows.py: ok")


if __name__ == "__main__":
    demo()
