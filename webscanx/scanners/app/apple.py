"""app.ios / app.macos: static hygiene checks of Apple app packages.

.ipa, .app folders, .pkg (xar) and .dmg. Nothing is executed or written to
disk; every file is read with caps via _safe. Findings are configuration
hygiene only, not a full pentest.
"""

from __future__ import annotations

import os
import plistlib
import re
import stat
import struct
import zlib

from ...core.engine import register
from ...core.finding import Finding
from ...core.target import TargetKind
from ..code.secrets import RULES as _SECRET_RULES
from . import _macho
from ._safe import MAX_FILE, SafeZip, UnsafeFile, check_size, read_file

_CAT = "MASVS-CODE / MASVS-NETWORK"
_STR = re.compile(rb"[\x20-\x7e]{6,400}")
_URL = re.compile(r"http://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
_URL_OK = re.compile(r"localhost|127\.0\.0\.1|apple\.com|w3\.org|schemas\.|purl\.org|"
                     r"example\.|xmlns|\.dtd", re.I)
MAX_PLIST = 8 * 1024 * 1024
MAX_TOC = 32 * 1024 * 1024
MAX_SCAN_BYTES = 128 * 1024 * 1024   # total bytes string-scanned per package
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_SECRET_PATS = [r for r in _SECRET_RULES
                if any(w in r.title.lower() for w in ("token", "key", "credential"))]


def _mask(s: str) -> str:
    s = s.strip()
    return f"{s[:4]}...({len(s)} chars)" if len(s) > 8 else "****"


def _f(sev, title, where, scanner, what, fix="", ev="", how=""):
    where = _CTRL.sub("", str(where))[:200]      # archive member names are hostile
    return Finding(title=title, severity=sev, where=where, scanner=scanner, what=what,
                   how_to_check=how, evidence=ev, remediation=fix, category=_CAT)


def _limited(where, scanner, why):
    return _f("info", "Could not fully analyze this package", where, scanner,
              f"The analysis stopped early: {why}.",
              "Re-run on a clean copy, or inspect the package by hand.")


def _strings(data: bytes, where: str, scanner: str, budget: list):
    """Likely hardcoded secrets and http:// URLs; values are masked.

    budget is a one-item list: bytes still allowed for this package."""
    if budget[0] <= 0:
        return
    if len(data) > budget[0]:
        data = data[:budget[0]]
        yield _f("info", "String scan stopped at size limit", where, scanner,
                 f"The package holds more than {MAX_SCAN_BYTES >> 20} MB of scannable data; the rest was skipped.")
    budget[0] -= len(data)
    seen, urls = set(), []
    for m in _STR.finditer(data):
        s = m.group().decode("ascii")
        for r in _SECRET_PATS:
            hit = r.pattern.search(s)
            if hit and not (r.negate and r.negate.search(s)) and hit.group() not in seen:
                seen.add(hit.group())
                yield _f(r.severity, r.title.replace("Hardcoded", "Likely hardcoded"),
                         where, scanner, r.what, r.remediation, _mask(hit.group()),
                         "Run the strings tool on the file and look near this prefix.")
        for u in _URL.findall(s):
            if not _URL_OK.search(u):
                urls.append(u)
    if urls:
        u = sorted(set(urls))
        yield _f("low", "Cleartext http:// URLs embedded", where, scanner,
                 f"{len(u)} plain-HTTP URL(s) are baked into the package.",
                 "Use https:// endpoints.", ", ".join(x[:60] for x in u[:5]))


def _plist_checks(pl: dict, where: str, scanner: str, ios: bool):
    ats = pl.get("NSAppTransportSecurity")
    if isinstance(ats, dict):
        if ats.get("NSAllowsArbitraryLoads") is True:
            yield _f("medium", "App Transport Security disabled", where, scanner,
                     "NSAllowsArbitraryLoads is true, so the app may use unencrypted HTTP to any host.",
                     "Remove it and add narrow per-domain exceptions only if needed.",
                     "NSAllowsArbitraryLoads = true")
        ex = ats.get("NSExceptionDomains")
        bad = [d for d, v in (ex.items() if isinstance(ex, dict) else [])
               if isinstance(v, dict) and v.get("NSExceptionAllowsInsecureHTTPLoads") is True]
        if bad:
            yield _f("low", "ATS exceptions allow insecure HTTP", where, scanner,
                     "Some domains are exempt from HTTPS enforcement.",
                     "Serve these domains over HTTPS and drop the exceptions.",
                     ", ".join(map(str, bad[:8])))
    types = pl.get("CFBundleURLTypes")
    schemes = [s for t in (types if isinstance(types, list) else []) if isinstance(t, dict)
               for s in (t.get("CFBundleURLSchemes") or [])]
    if schemes:
        yield _f("info", "Custom URL schemes registered", where, scanner,
                 "Any app or web page can open these schemes, so the app must treat their "
                 "input as untrusted and validate it.", "Validate and sanitize every URL parameter.",
                 ", ".join(map(str, schemes[:10])))
    if ios:
        mv = str(pl.get("MinimumOSVersion", ""))
        m = re.match(r"\d+", mv)
        if m and int(m.group()) < 15:
            yield _f("low", "Old minimum iOS version", where, scanner,
                     "The app still supports iOS versions that no longer get security updates.",
                     "Raise MinimumOSVersion to 15 or newer.", f"MinimumOSVersion = {mv}")


def _macho_checks(data: bytes, where: str, scanner: str, mac: bool):
    try:
        info = _macho.parse(data)
    except ValueError as e:
        yield _limited(where, scanner, f"executable is not a readable Mach-O ({e})")
        return
    for s in info["slices"]:
        if not s["pie"]:
            yield _f("medium", "Executable is not position independent (no PIE)", where, scanner,
                     f"The {s['cpu']} build lacks ASLR support, making memory attacks easier.",
                     "Build with -pie (default in current Xcode).", s["cpu"])
        if mac and not s["signed"]:
            yield _f("low", "No code signature in executable", where, scanner,
                     f"The {s['cpu']} build has no LC_CODE_SIGNATURE load command.",
                     "Sign the app with codesign.", s["cpu"])
    if not info["stack_guard"]:
        yield _f("low", "No stack-protector symbol found", where, scanner,
                 "The binary does not reference __stack_chk_guard, so stack canaries may be off.",
                 "Build with -fstack-protector-all.")


def _plist_load(raw: bytes) -> dict:
    try:
        pl = plistlib.loads(raw)
    except Exception as e:      # plistlib raises many types on hostile input
        raise UnsafeFile(f"Info.plist unreadable: {e.__class__.__name__}") from None
    if not isinstance(pl, dict):
        raise UnsafeFile("Info.plist is not a dictionary")
    return pl


def _debug_profile(raw: bytes) -> bool:
    i = raw.find(b"<?xml")            # find, not a regex: linear on repeated "<?xml"
    j = raw.find(b"</plist>", i) if i >= 0 else -1
    try:
        ents = plistlib.loads(raw[i:j + 8]).get("Entitlements", {}) if j >= 0 else {}
    except Exception:
        return False
    return isinstance(ents, dict) and ents.get("get-task-allow") is True


@register(TargetKind.MOBILE, "app.ios")
def scan_ios(target, ctx):
    path, sc = target.location, "app.ios"
    if not path.lower().endswith(".ipa"):
        return
    try:
        with SafeZip(path) as z:
            names = z.names()
            plists = [n for n in names if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n)]
            if not plists:
                raise UnsafeFile("no Payload/<name>.app/Info.plist found")
            budget = [MAX_SCAN_BYTES]
            ip = plists[0]
            base = ip[:-len("Info.plist")]
            raw = z.read(ip, MAX_PLIST)
            pl = _plist_load(raw)
            yield from _plist_checks(pl, ip, sc, True)
            yield from _strings(raw, ip, sc, budget)
            prov = base + "embedded.mobileprovision"
            if prov in names and _debug_profile(z.read(prov, MAX_PLIST)):
                yield _f("high", "Debug build (get-task-allow)", prov, sc,
                         "The provisioning profile lets debuggers attach; this is a debug build.",
                         "Ship a distribution-signed release build.", "get-task-allow = true")
            exe = str(pl.get("CFBundleExecutable", ""))
            if not exe or "/" in exe or base + exe not in names:
                raise UnsafeFile("main executable named by CFBundleExecutable not found")
            data = z.read(base + exe)
            yield from _macho_checks(data, base + exe, sc, False)
            yield from _strings(data, base + exe, sc, budget)
    except (UnsafeFile, OSError, struct.error, ValueError, zlib.error) as e:
        yield _limited(path, sc, str(e))


def _in_bundle(root: str, rel: str) -> str:
    """Path of rel inside root; refuses symlinks and escapes."""
    p = root
    for part in rel.split("/"):
        p = os.path.join(p, part)
        if os.path.islink(p):
            raise UnsafeFile(f"{rel} is a symlink, not followed")
    r = os.path.realpath(root)
    if os.path.commonpath([r, os.path.realpath(p)]) != r:
        raise UnsafeFile(f"{rel} escapes the bundle")
    return p


def _regular(p: str) -> str:
    """Refuse FIFOs, devices and the like before anything opens them."""
    if not (os.path.isfile(p) and stat.S_ISREG(os.stat(p).st_mode)):
        raise UnsafeFile(f"{os.path.basename(p)} is not a regular file")
    return p


def _scan_app(root: str, sc: str):
    pl = _plist_load(read_file(_regular(_in_bundle(root, "Contents/Info.plist")), MAX_PLIST))
    yield from _plist_checks(pl, "Contents/Info.plist", sc, False)
    exe = str(pl.get("CFBundleExecutable", ""))
    if not exe or "/" in exe or "\\" in exe or exe.startswith("."):
        raise UnsafeFile("CFBundleExecutable missing or unsafe")
    w = f"Contents/MacOS/{exe}"
    data = read_file(_regular(_in_bundle(root, w)))
    yield from _macho_checks(data, w, sc, True)
    yield from _strings(data, w, sc, [MAX_SCAN_BYTES])


def _scan_pkg(path: str, sc: str):
    check_size(path, MAX_FILE)
    with open(path, "rb") as f:
        head = f.read(28)
        if len(head) < 28 or head[:4] != b"xar!":
            raise UnsafeFile("not a xar installer package (missing xar! magic)")
        hsize, _ver, clen, ulen, _alg = struct.unpack(">HHQQI", head[4:28])
        if hsize < 28 or clen > MAX_TOC or ulen > MAX_TOC:
            raise UnsafeFile("xar header sizes are implausible")
        f.seek(hsize)
        comp = f.read(clen)
    if len(comp) != clen:
        raise UnsafeFile("xar table of contents is truncated")
    d = zlib.decompressobj()
    toc = d.decompress(comp, MAX_TOC)
    if d.unconsumed_tail:
        raise UnsafeFile("xar table of contents expands past the size cap")
    # Regex, not an XML parser: the TOC is hostile and entity expansion is not worth the risk.
    names = re.findall(r"<name>([^<]{1,255})</name>", toc.decode("utf-8", "replace"))[:5000]
    scripts = sorted({n for n in names if n in ("preinstall", "postinstall", "Scripts")})
    if scripts:
        yield _f("info", "Installer runs scripts with installer rights", path, sc,
                 "This package contains install scripts that run with installer rights; "
                 "review them before installing.", "Read the scripts before running the installer.",
                 ", ".join(scripts))


@register(TargetKind.DESKTOP, "app.macos")
def scan_macos(target, ctx):
    path, sc = target.location, "app.macos"
    root = path.rstrip("/\\")
    low = root.lower()
    try:
        if low.endswith(".dmg"):
            yield _f("info", "Disk images cannot be opened here", path, sc,
                     "Disk images cannot be opened here; mount it and scan the .app inside.")
        elif low.endswith(".pkg") and os.path.isfile(path):
            yield from _scan_pkg(path, sc)
        elif low.endswith(".app") and os.path.isdir(path):
            yield from _scan_app(root, sc)
    except (UnsafeFile, OSError, struct.error, ValueError, zlib.error) as e:
        yield _limited(path, sc, str(e))


def demo() -> None:
    import tempfile
    import zipfile
    from types import SimpleNamespace as NS

    def run(fn, p):
        return list(fn(NS(location=p), None))

    pl = {"CFBundleExecutable": "Demo", "MinimumOSVersion": "12.0",
          "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True,
                                     "NSExceptionDomains": {"a.test": {"NSExceptionAllowsInsecureHTTPLoads": True}}},
          "CFBundleURLTypes": [{"CFBundleURLSchemes": ["demoapp"]}]}
    prov = b"junk" + plistlib.dumps({"Entitlements": {"get-task-allow": True}}) + b"x"
    exe = _macho.build(pie=False, stack_guard=False) + b"\0AKIAABCDEFGHIJKLMNOP\0http://api.bad.test/v1\0"
    with tempfile.TemporaryDirectory() as d:
        ipa = os.path.join(d, "t.ipa")
        with zipfile.ZipFile(ipa, "w") as z:
            z.writestr("Payload/Demo.app/Info.plist", plistlib.dumps(pl))
            z.writestr("Payload/Demo.app/Demo", exe)
            z.writestr("Payload/Demo.app/embedded.mobileprovision", prov)
        res = run(scan_ios, ipa)
        t = {x.title for x in res}
        for want in ("App Transport Security disabled", "ATS exceptions allow insecure HTTP",
                     "Custom URL schemes registered", "Old minimum iOS version",
                     "Debug build (get-task-allow)", "Executable is not position independent (no PIE)",
                     "No stack-protector symbol found", "Likely hardcoded AWS access key",
                     "Cleartext http:// URLs embedded"):
            assert want in t, (want, t)
        assert not any("AKIAABCDEFGHIJKLMNOP" in x.evidence for x in res)
        bad = os.path.join(d, "bad.ipa")
        with open(bad, "wb") as f:
            f.write(b"nope")
        r = run(scan_ios, bad)
        assert len(r) == 1 and r[0].title == "Could not fully analyze this package"

        app = os.path.join(d, "X.app")
        os.makedirs(os.path.join(app, "Contents", "MacOS"))
        with open(os.path.join(app, "Contents", "Info.plist"), "wb") as f:
            f.write(plistlib.dumps({"CFBundleExecutable": "X"}))
        with open(os.path.join(app, "Contents", "MacOS", "X"), "wb") as f:
            f.write(_macho.build(pie=False, signed=False))
        t = {x.title for x in run(scan_macos, app)}
        assert "No code signature in executable" in t, t
        assert "Executable is not position independent (no PIE)" in t, t

        toc = b"<xar><toc><file><name>postinstall</name></file></toc></xar>"
        c = zlib.compress(toc)
        pkg = os.path.join(d, "t.pkg")
        with open(pkg, "wb") as f:
            f.write(b"xar!" + struct.pack(">HHQQI", 28, 1, len(c), len(toc), 1) + c)
        r = run(scan_macos, pkg)
        assert len(r) == 1 and "installer rights" in r[0].title, r
        with open(pkg, "wb") as f:
            f.write(b"xar!" + struct.pack(">HHQQI", 28, 1, 5, 10**9, 1) + b"abcde")
        assert run(scan_macos, pkg)[0].title == "Could not fully analyze this package"

        dmg = os.path.join(d, "t.dmg")
        with open(dmg, "wb") as f:
            f.write(b"x")
        assert "mount it" in run(scan_macos, dmg)[0].what
        other = os.path.join(d, "t.exe")
        with open(other, "wb") as f:
            f.write(b"x")
        assert run(scan_macos, other) == []
    # repeated "<?xml" with no closing tag must be linear, and a real profile still parses
    assert _debug_profile(b"<?xml " * 200_000) is False
    assert _debug_profile(b"junk" + plistlib.dumps({"Entitlements": {"get-task-allow": True}})) is True
    # scan budget
    assert any(x.title == "String scan stopped at size limit"
               for x in _strings(b"x" * 100, "w", "s", [10]))
    assert list(_strings(b"x" * 100, "w", "s", [0])) == []
    # hostile member names are cleaned
    assert _f("info", "t", "a\x1b\nb" + "z" * 500, "s", "w").where == "ab" + "z" * 198
    # a FIFO named like a bundle file is skipped, not opened (POSIX only)
    if hasattr(os, "mkfifo"):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "F.app", "Contents"))
            os.mkfifo(os.path.join(d, "F.app", "Contents", "Info.plist"))
            assert run(scan_macos, os.path.join(d, "F.app"))[0].title == "Could not fully analyze this package"
    _macho.demo()
    print("apple.py: ok")


if __name__ == "__main__":
    demo()
