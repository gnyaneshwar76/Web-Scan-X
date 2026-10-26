"""App-package scanners end to end through the real CLI. Run: python tests/test_apps.py"""

import json
import os
import plistlib
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from webscanx.scanners.app import _macho                     # noqa: E402
from webscanx.scanners.app.android import _apk, _axml_build  # noqa: E402
from webscanx.scanners.app.windows import _ole, _pe          # noqa: E402

COULD_NOT = "Could not fully analyze"


def scan(path, expect_exit, kind):
    """Run the CLI on one file; return the set of finding titles."""
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "r")
        p = subprocess.run([sys.executable, "-m", "webscanx", str(path), "-y", "-f", "json", "-o", out],
                           cwd=ROOT, capture_output=True, text=True, timeout=120)
        assert "Traceback" not in p.stderr, p.stderr
        assert p.returncode == expect_exit, (p.returncode, p.stdout[-300:], p.stderr[-300:])
        doc = json.loads(Path(out + ".json").read_text(encoding="utf-8"))
    assert doc["target_kind"] == kind, doc["target_kind"]
    return [f["title"] for f in doc["findings"]]


def _manifest(debuggable):
    app = {"debuggable": True} if debuggable else {"allowBackup": False}
    return _axml_build(("manifest", {}, [("uses-sdk", {"targetSdkVersion": 34}, []), ("application", app, [])]))


def test_android():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "bad.apk")
        _apk(p, _manifest(True))
        assert "App is debuggable" in scan(p, 2, "mobile")
        p = os.path.join(d, "good.apk")
        _apk(p, _manifest(False))
        assert scan(p, 0, "mobile") == []
        p = os.path.join(d, "x.aab")
        _apk(p, b"protobuf", {"base/dex/classes.dex": b"\0\0http://api.evil.test/v1\0"})
        t = scan(p, 1, "mobile")
        assert "AAB manifest not analyzed" in t and "Plain http:// addresses found in the app" in t


def test_ios_and_mac():
    pl = {"CFBundleExecutable": "Demo", "MinimumOSVersion": "17.0",
          "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}}
    with tempfile.TemporaryDirectory() as d:
        ipa = os.path.join(d, "t.ipa")
        with zipfile.ZipFile(ipa, "w") as z:
            z.writestr("Payload/Demo.app/Info.plist", plistlib.dumps(pl))
            z.writestr("Payload/Demo.app/Demo", _macho.build())
        assert "App Transport Security disabled" in scan(ipa, 1, "mobile")
        app = os.path.join(d, "X.app")
        os.makedirs(os.path.join(app, "Contents", "MacOS"))
        Path(app, "Contents", "Info.plist").write_bytes(plistlib.dumps({"CFBundleExecutable": "X"}))
        Path(app, "Contents", "MacOS", "X").write_bytes(_macho.build(pie=False, signed=False))
        assert "No code signature in executable" in scan(app, 1, "desktop")
        toc = b"<xar><toc><file><name>postinstall</name></file></toc></xar>"
        c = zlib.compress(toc)
        pkg = os.path.join(d, "t.pkg")
        Path(pkg).write_bytes(b"xar!" + struct.pack(">HHQQI", 28, 1, len(c), len(toc), 1) + c)
        assert "Installer runs scripts with installer rights" in scan(pkg, 0, "desktop")
        dmg = os.path.join(d, "e.dmg")
        Path(dmg).write_bytes(b"")
        assert "Disk images cannot be opened here" in scan(dmg, 0, "desktop")


def test_windows():
    with tempfile.TemporaryDirectory() as d:
        off, on = os.path.join(d, "off.exe"), os.path.join(d, "on.exe")
        Path(off).write_bytes(_pe(True, 0))
        Path(on).write_bytes(_pe(True, 0x40 | 0x20 | 0x100 | 0x4000, cert=100))
        assert "ASLR (dynamic base) is off" in scan(off, 1, "desktop")
        assert scan(on, 0, "desktop") == []
        msi = os.path.join(d, "u.msi")
        Path(msi).write_bytes(_ole(False))
        t = scan(msi, 1, "desktop")
        assert "MSI package is not signed" in t
        sig = os.path.join(d, "s.msi")
        Path(sig).write_bytes(_ole(True))
        assert "MSI package is not signed" not in scan(sig, 0, "desktop")


def test_hostile_inputs():
    good = _manifest(False)
    with tempfile.TemporaryDirectory() as d:
        bomb = os.path.join(d, "bomb.apk")
        with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("AndroidManifest.xml", b"\0" * (5 * 1024 * 1024))
        trav = os.path.join(d, "trav.apk")
        with zipfile.ZipFile(trav, "w") as z:
            z.writestr("../AndroidManifest.xml", good)        # skipped, so the real manifest is missing
        trunc = os.path.join(d, "trunc.apk")
        _apk(trunc, good[:40])
        junk_apk = os.path.join(d, "junk.apk")
        Path(junk_apk).write_bytes(os.urandom(300))
        junk_exe = os.path.join(d, "junk.exe")
        Path(junk_exe).write_bytes(os.urandom(300))
        bad_ipa = os.path.join(d, "bad.ipa")
        Path(bad_ipa).write_bytes(b"nope")
        bad_pkg = os.path.join(d, "bad.pkg")
        Path(bad_pkg).write_bytes(b"xar!" + struct.pack(">HHQQI", 28, 1, 5, 10**9, 1) + b"abcde")
        for p, kind in ((bomb, "mobile"), (trav, "mobile"), (trunc, "mobile"), (junk_apk, "mobile"),
                        (junk_exe, "desktop"), (bad_ipa, "mobile"), (bad_pkg, "desktop")):
            t = scan(p, 0, kind)
            assert len(t) == 1 and t[0].startswith(COULD_NOT), (os.path.basename(p), t)


def load_tests(loader, standard_tests, pattern):   # lets unittest/discover run the bare test_* functions
    from tests._fn import collect
    return collect(sys.modules[__name__])


if __name__ == "__main__":
    test_android(); test_ios_and_mac(); test_windows(); test_hostile_inputs()
    print("test_apps: ok")
