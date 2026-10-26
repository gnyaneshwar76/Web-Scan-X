"""app.android - configuration hygiene of Android packages (.apk, limited for .aab).

Static only: the package is read through SafeZip, nothing is run or extracted.
Maps to OWASP MASVS (platform / network / storage / resilience) and CWE.
"""

from __future__ import annotations

import os
import re
import struct
import tempfile
import zipfile

from ...core.engine import register
from ...core.finding import Finding
from ...core.target import TargetKind
from ..code.secrets import RULES as SECRET_RULES
from . import _axml
from ._safe import SafeZip, UnsafeFile

S = "app.android"
MAX_SCAN_MEMBERS = 40            # dex/arsc/asset files whose strings are scanned
MAX_XML = 200                    # res/xml files tried as network security config
_STR = re.compile(rb"[\x20-\x7e]{6,300}")
_URL = re.compile(r"http://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}")
_SKIP_HOST = re.compile(r"http://(schemas\.android\.com|www\.w3\.org|www\.apache\.org|"
                        r"xmlpull\.org|ns\.adobe\.com|schemas\.xmlsoap\.org|localhost|"
                        r"127\.0\.0\.1|10\.0\.2\.2|purl\.org|www\.example\.com)", re.I)
_COMPONENTS = ("activity", "activity-alias", "service", "receiver", "provider")
_DOC = "https://mas.owasp.org/MASVS/"
MAX_SCAN_BYTES = 128 * 1024 * 1024   # total bytes string-scanned per package
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _where(w):
    """Archive member names are hostile: strip control characters, cap length."""
    return _CTRL.sub("", str(w))[:200]


def _f(title, sev, where, what, check, fix, cat, evidence=""):
    where = _where(where)
    return Finding(title=title, severity=sev, where=where, scanner=S, what=what,
                   how_to_check=check, evidence=evidence, remediation=fix,
                   category=cat, references=[_DOC])


def _mask(s: str) -> str:
    return s[:4] + "****" + f" ({len(s)} chars)"


def _under(els, j, i):
    while j != -1:
        if j == i:
            return True
        j = els[j]["parent"]
    return False


def _chain(els, i):
    i = els[i]["parent"]
    while i != -1:
        yield i
        i = els[i]["parent"]


def _manifest_findings(els):
    app = next((e for e in els if e["name"] == "application"), None)
    a = app["attrs"] if app else {}
    w = "AndroidManifest.xml"
    if a.get("debuggable") == "true":
        yield _f("App is debuggable", "high", w + " <application debuggable>",
                 "The app is built with debugging on, so anyone can attach a debugger, read its private data and change how it runs.",
                 "Open AndroidManifest.xml (for example with 'apkanalyzer manifest print') and look for android:debuggable=\"true\".",
                 "Build the release with debuggable off (the default for release builds) and remove the attribute from the manifest.",
                 "OWASP MASVS-RESILIENCE-4 / CWE-489", 'android:debuggable="true"')
    if a.get("allowBackup", "true") == "true":
        yield _f("App data can be backed up", "low", w + " <application allowBackup>",
                 "Android lets the user (or anyone with a USB cable) copy this app's private data off the phone, because backups are on.",
                 "Look for android:allowBackup in the application tag; if it is missing, the default is true.",
                 'Set android:allowBackup="false", or limit what is saved with android:fullBackupContent / dataExtractionRules.',
                 "OWASP MASVS-STORAGE-1 / CWE-921",
                 'android:allowBackup="true"' if "allowBackup" in a else "android:allowBackup not set (default true)")
    if a.get("usesCleartextTraffic") == "true":
        yield _f("App allows unencrypted (HTTP) traffic", "medium", w + " <application usesCleartextTraffic>",
                 "The app is allowed to talk over plain HTTP, which anyone on the same network can read or change.",
                 'Look for android:usesCleartextTraffic="true" in the application tag.',
                 "Remove the attribute or set it to false, and use HTTPS everywhere.",
                 "OWASP MASVS-NETWORK-1 / CWE-319", 'android:usesCleartextTraffic="true"')
    sdk = next((e for e in els if e["name"] == "uses-sdk"), None)
    try:
        t = int(sdk["attrs"]["targetSdkVersion"]) if sdk else None
    except (KeyError, ValueError):
        t = None
    if t is not None and t < 33:
        yield _f("Old target SDK level", "low", w + " <uses-sdk targetSdkVersion>",
                 f"The app targets Android API {t}. Newer Android versions skip many protections for apps that target old versions, and stores reject them.",
                 "Look for android:targetSdkVersion in the uses-sdk tag.",
                 "Raise targetSdkVersion to a current level (33 or higher) and retest.",
                 "OWASP MASVS-CODE-1", f"targetSdkVersion={t}")
    kids = {}                      # parent index -> child indexes, built once (linear time)
    for j, k in enumerate(els):
        kids.setdefault(k["parent"], []).append(j)
    for i, e in enumerate(els):
        if e["name"] not in _COMPONENTS:
            continue
        at = e["attrs"]
        filters = [j for j in kids.get(i, ()) if els[j]["name"] == "intent-filter"]
        has_filter = bool(filters)
        exported = at.get("exported")
        if not (exported == "true" or (exported is None and has_filter and e["name"] != "provider")):
            continue
        if at.get("permission") or at.get("readPermission") or at.get("writePermission"):
            continue
        launcher = e["name"].startswith("activity") and any(
            "android.intent.category.LAUNCHER" in els[c]["attrs"].get("name", "")
            for j in filters for c in kids.get(j, ()))
        nm = at.get("name", "?")
        yield _f("Exported launcher activity" if launcher else f"Exported {e['name']} without a permission",
                 "info" if launcher else "medium", f"{w} <{e['name']} {nm}>",
                 "Other apps on the phone can start this component." + (
                     " This is the normal launcher screen, so it is expected." if launcher else
                     " If it does something sensitive, a malicious app could trigger it."),
                 f"In the manifest, find the {e['name']} named {nm} and check android:exported and android:permission.",
                 'Set android:exported="false" unless other apps must reach it; otherwise protect it with android:permission.',
                 "OWASP MASVS-PLATFORM-1 / CWE-926",
                 f"android:exported={exported or 'implicit (has intent-filter)'}, no permission")


def _nsc_findings(z, names):
    tried = 0
    for n in names:
        if not (n.startswith("res/xml/") and n.endswith(".xml")):
            continue
        tried += 1
        if tried > MAX_XML:
            break
        try:
            els = _axml.parse(z.read(n, limit=2 * 1024 * 1024))
        except (ValueError, UnsafeFile, KeyError):
            continue
        if not els or els[0]["name"] != "network-security-config":
            continue
        for i, e in enumerate(els):
            at = e["attrs"]
            dbg = any(els[p]["name"] == "debug-overrides" for p in _chain(els, i))
            if e["name"] == "certificates" and at.get("src") == "user" and not dbg:
                yield _f("Network security config trusts user-added certificates", "medium", n,
                         "The app accepts certificates the user (or malware) installed on the phone, so someone with such a certificate can read the app's HTTPS traffic.",
                         f'Open {n} and look for <certificates src="user"/> outside debug-overrides.',
                         "Remove the user certificate source, or limit it to debug-overrides.",
                         "OWASP MASVS-NETWORK-2 / CWE-295", '<certificates src="user"/>')
            if at.get("cleartextTrafficPermitted") == "true" and e["name"] in ("base-config", "domain-config"):
                yield _f("Network security config allows cleartext traffic", "medium", n,
                         "The network security config permits plain HTTP, which can be read or changed on the network.",
                         f'Open {n} and look for cleartextTrafficPermitted="true".',
                         "Set cleartextTrafficPermitted to false and use HTTPS.",
                         "OWASP MASVS-NETWORK-1 / CWE-319", f'<{e["name"]} cleartextTrafficPermitted="true">')


def _string_findings(z, names):
    urls, secrets = {}, {}
    todo = [n for n in names if n.endswith((".dex", "resources.arsc")) or
            (n.startswith(("assets/", "res/raw/")) and
             n.endswith((".json", ".xml", ".txt", ".properties", ".js", ".html", ".cfg")))]
    left, capped = MAX_SCAN_BYTES, False
    for n in todo[:MAX_SCAN_MEMBERS]:
        if left <= 0:
            capped = True
            break
        try:
            data = z.read(n)
        except (UnsafeFile, KeyError):
            continue
        left -= len(data)
        for m in _STR.finditer(data):
            s = m.group().decode("ascii")
            for u in _URL.findall(s):
                if not _SKIP_HOST.match(u) and len(urls) < 50:
                    urls.setdefault(u[:120], n)
            for r in SECRET_RULES[:-1]:       # specific key shapes; the generic assignment rule needs source code
                k = r.pattern.search(s)
                if k and len(secrets) < 20:
                    secrets.setdefault((r.title, k.group(0)), (n, r))
    if capped:
        yield _f("String scan stopped at size limit", "info", "package",
                 f"More than {MAX_SCAN_BYTES >> 20} MB of embedded files were found; the rest were not scanned for URLs and secrets.",
                 "Scan the large files separately with 'strings'.", "No action needed unless you expect secrets in the skipped files.",
                 "OWASP MASVS")
    if urls:
        sample = list(urls)[:5]
        yield _f("Plain http:// addresses found in the app", "low", urls[sample[0]],
                 f"{len(urls)} unencrypted web address(es) are baked into the app. Traffic to them can be read or changed on the network.",
                 "Run 'strings' on the classes.dex / resources.arsc files and search for http://.",
                 "Switch these addresses to https:// (or remove them if unused).",
                 "OWASP MASVS-NETWORK-1 / CWE-319", "; ".join(sample))
    for (title, val), (n, r) in secrets.items():
        yield _f(title + " (in app package)", r.severity, n,
                 "A secret that looks real is stored inside the app, where anyone can unzip the package and read it.",
                 f"Unzip the package and run 'strings' on {n}, searching for the masked prefix.",
                 "Remove the secret from the app, rotate it, and keep it on a server instead.",
                 "OWASP MASVS-STORAGE-2 / CWE-798", _mask(val))


def _signing_findings(names):
    if not any(n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC", ".SF"))
               for n in names):
        yield _f("No v1 signature files found", "info", "META-INF/",
                 "No classic (v1) signature files are inside the package. It is either unsigned or signed only with the newer v2+ block, which this scan cannot read.",
                 "Run 'apksigner verify --verbose app.apk' from the Android SDK build tools.",
                 "Make sure release builds are signed (apksigner) before publishing.",
                 "OWASP MASVS-RESILIENCE-2")


def _could_not(path, why):
    return _f("Could not fully analyze this package", "info", path,
              f"The scan stopped early: {why}. Results may be incomplete.",
              "Open the file with a zip tool and check it is a valid, unmodified package.",
              "Re-export the package from your build system and scan it again.",
              "OWASP MASVS", why)


@register(TargetKind.MOBILE, S)
def scan(target, ctx):
    path = target.location
    ext = os.path.splitext(path)[1].lower()
    if ext not in (".apk", ".aab"):
        return
    try:
        with SafeZip(path) as z:
            names = z.names()
            if ext == ".apk":
                if "AndroidManifest.xml" not in names:
                    raise ValueError("AndroidManifest.xml is missing")
                els = _axml.parse(z.read("AndroidManifest.xml", limit=8 * 1024 * 1024))
                yield from _manifest_findings(els)
                yield from _nsc_findings(z, names)
                yield from _signing_findings(names)
            else:
                yield _f("AAB manifest not analyzed", "info", path,
                         "An .aab stores its manifest in a different format that this scan does not read, so only file names and embedded strings were checked.",
                         "Convert to an APK with bundletool, or scan the APK produced for release.",
                         "Scan the final signed APK as well.", "OWASP MASVS")
            yield from _string_findings(z, names)
    except (UnsafeFile, ValueError, struct.error, OSError, zipfile.BadZipFile) as e:
        yield _could_not(path, str(e))


# ---------------------------------------------------------------- demo
def _axml_build(root):
    """Encode (name, {attr: value}, [children]) as UTF-16 binary XML (test helper)."""
    pool, chunks = [], []

    def sid(s):
        if s not in pool:
            pool.append(s)
        return pool.index(s)

    def walk(node):
        name, attrs, kids = node
        a = b""
        for k, v in attrs.items():
            raw, dt, val = 0xFFFFFFFF, 0x10, 0
            if isinstance(v, bool):
                dt, val = 0x12, 0xFFFFFFFF if v else 0
            elif isinstance(v, int):
                val = v
            else:
                raw = sid(v)
                dt, val = 0x03, raw
            a += struct.pack("<IIIHBBI", 0xFFFFFFFF, sid(k), raw, 8, 0, dt, val)
        ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, sid(name), 20, 20, len(attrs), 0, 0, 0)
        chunks.append(struct.pack("<HHIII", 0x0102, 16, 36 + len(a), 1, 0xFFFFFFFF) + ext + a)
        for c in kids:
            walk(c)
        chunks.append(struct.pack("<HHIII", 0x0103, 16, 24, 1, 0xFFFFFFFF) + struct.pack("<II", 0xFFFFFFFF, sid(name)))

    walk(root)
    strs, offs = b"", []
    for s in pool:
        offs.append(len(strs))
        strs += struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\0\0"
    strs += b"\0" * (-len(strs) % 4)
    hs = 28 + 4 * len(pool)
    pool_c = (struct.pack("<HHIIIIII", 0x0001, 28, hs + len(strs), len(pool), 0, 0, hs, 0)
              + b"".join(struct.pack("<I", o) for o in offs) + strs)
    body = pool_c + b"".join(chunks)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def _apk(path, manifest, extra=None, sig=True):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", manifest)
        if sig:
            z.writestr("META-INF/CERT.RSA", b"x")
        for k, v in (extra or {}).items():
            z.writestr(k, v)


def demo() -> None:
    from ...core.target import Target
    ax = _axml_build
    launcher = ("activity", {"name": ".Main", "exported": True}, [
        ("intent-filter", {}, [("category", {"name": "android.intent.category.LAUNCHER"}, [])])])
    bad = ("manifest", {"package": "a.b"}, [
        ("uses-sdk", {"targetSdkVersion": 30}, []),
        ("application", {"debuggable": True, "usesCleartextTraffic": True}, [
            launcher,
            ("service", {"name": ".Svc", "exported": True}, []),
            ("receiver", {"name": ".Safe", "exported": True, "permission": "p.X"}, [])])])
    good = ("manifest", {}, [("uses-sdk", {"targetSdkVersion": 34}, []),
                             ("application", {"allowBackup": False}, [])])
    nsc = ax(("network-security-config", {}, [
        ("base-config", {"cleartextTrafficPermitted": True},
         [("trust-anchors", {}, [("certificates", {"src": "user"}, [])])])]))
    dex = b"\0\0http://api.evil.test/v1\0\0AKIAIOSFODNN7EXAMPLE\0\0http://schemas.android.com/apk\0"

    def run(p):
        return list(scan(Target(TargetKind.MOBILE, p, p), None))

    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "bad.apk")
        _apk(p, ax(bad), {"res/xml/nsc.xml": nsc, "classes.dex": dex}, sig=False)
        t = {f.title: f for f in run(p)}
        for k in ("App is debuggable", "App data can be backed up", "App allows unencrypted (HTTP) traffic",
                  "Old target SDK level", "Exported service without a permission", "Exported launcher activity",
                  "Network security config trusts user-added certificates",
                  "Network security config allows cleartext traffic", "No v1 signature files found",
                  "Plain http:// addresses found in the app", "Hardcoded AWS access key (in app package)"):
            assert k in t, (k, list(t))
        assert t["App is debuggable"].severity.label.lower() == "high"
        assert t["Exported launcher activity"].severity.label.lower() == "info"
        assert not any(x.startswith("Exported receiver") for x in t)
        assert "AKIAIOSFODNN7EXAMPLE" not in t["Hardcoded AWS access key (in app package)"].evidence
        assert "schemas.android.com" not in t["Plain http:// addresses found in the app"].evidence

        p = os.path.join(d, "good.apk")
        _apk(p, ax(good))
        assert run(p) == [], [f.title for f in run(p)]

        p = os.path.join(d, "x.aab")
        _apk(p, b"protobuf", {"base/dex/classes.dex": dex})
        assert any(f.title == "AAB manifest not analyzed" for f in run(p))

        p = os.path.join(d, "trunc.apk")
        _apk(p, ax(good)[:40])
        r = run(p)
        assert len(r) == 1 and r[0].title == "Could not fully analyze this package", r
        p = os.path.join(d, "junk.apk")
        with open(p, "wb") as fh:
            fh.write(b"not a zip")
        assert run(p)[0].title == "Could not fully analyze this package"
        assert run("x.ipa") == []
    # linear children map; hostile names cleaned; scan budget note
    els = [{"name": "application", "attrs": {}, "parent": -1}] + [
        {"name": "activity", "attrs": {"exported": "true", "name": "a"}, "parent": 0} for _ in range(3000)]
    assert len(list(_manifest_findings(els))) >= 3000
    assert _where("a\x1b[31m\nb" + "x" * 500) == "a[31mb" + "x" * 194 and len(_where("y" * 500)) == 200
    global MAX_SCAN_BYTES
    old, MAX_SCAN_BYTES = MAX_SCAN_BYTES, 10
    try:
        class _Z:
            def read(self, n):
                return b"x" * 100
        assert any(f.title == "String scan stopped at size limit"
                   for f in _string_findings(_Z(), ["a.dex", "b.dex"]))
    finally:
        MAX_SCAN_BYTES = old
    for junk in (b"", b"\x03\x00\x08\x00\xff\xff\xff\xff", ax(good)[:20]):
        try:
            _axml.parse(junk)
            raise AssertionError("must raise")
        except ValueError:
            pass
    print("app/android.py: ok")


if __name__ == "__main__":
    demo()
