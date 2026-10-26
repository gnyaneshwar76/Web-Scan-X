"""Phase 0 spine: target detection for app files, clean CLI error, server gate."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from webscanx import cli, server  # noqa: E402
from webscanx.core.target import TargetKind, detect  # noqa: E402


class DetectApps(unittest.TestCase):
    def test_extensions(self):
        for ext in (".apk", ".aab", ".ipa"):
            self.assertIs(detect("a" + ext).kind, TargetKind.MOBILE, ext)
        for ext in (".exe", ".dll", ".msi", ".sys", ".dmg", ".pkg"):
            self.assertIs(detect("a" + ext).kind, TargetKind.DESKTOP, ext)

    def test_app_bundle_dir_is_desktop_not_code(self):
        with tempfile.TemporaryDirectory() as d:
            bundle = os.path.join(d, "X.app")
            os.mkdir(bundle)
            self.assertIs(detect(bundle).kind, TargetKind.DESKTOP)
            self.assertIs(detect(d).kind, TargetKind.CODE)


class CliAndServer(unittest.TestCase):
    def test_cli_missing_apk_exits_cleanly(self):
        self.assertEqual(cli.main(["definitely-missing.apk", "-y"]), cli.EXIT_ERROR)

    def test_server_refuses_mobile_without_authorized(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "a.apk")
            open(f, "wb").close()
            with self.assertRaises(ValueError):
                server.start_scan({"target": f})
            with self.assertRaises(ValueError):
                server.start_scan({"target": f, "kind": "mobile"})


class BareTests(unittest.TestCase):  # unittest does not collect bare test_* functions
    def test_all(self):
        for name, fn in list(globals().items()):
            if name.startswith("test_") and callable(fn):
                with self.subTest(name):
                    fn()


if __name__ == "__main__":
    unittest.main()
