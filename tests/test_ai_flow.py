"""AI helper end to end with a fake Ollama, plus file-target scans via the server.
Run: python tests/test_ai_flow.py"""

import contextlib
import http.server
import io
import json
import os
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import webscanx.ai as ai                                      # noqa: E402
from webscanx import cli, server as api                       # noqa: E402
from webscanx.scanners.app.android import _apk, _axml_build   # noqa: E402
from webscanx.scanners.app.windows import _pe                 # noqa: E402

MODE = {"m": "good"}


class _Fake(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        prompt = json.loads(self.rfile.read(int(self.headers["Content-Length"])))["messages"][1]["content"]
        fp = json.loads(prompt.split("Findings:\n", 1)[1])[0]["id"] if "Findings:\n" in prompt else ""
        txt = ("not json at all" if MODE["m"] == "bad" else json.dumps({
            "summary": "FAKE-SUMMARY: debuggable app, fix it first.", "fix_first": [fp, "bogus"],
            "notes": [{"id": fp, "verdict": "real", "why": "FAKE-WHY"}, {"id": "bogus", "verdict": "real", "why": "x"}]}))
        b = json.dumps({"message": {"content": txt}}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


@contextlib.contextmanager
def fake_ollama(mode="good"):
    MODE["m"] = mode
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    old = ai.OLLAMA_URL
    ai.OLLAMA_URL = f"http://127.0.0.1:{srv.server_port}"
    try:
        yield
    finally:
        ai.OLLAMA_URL = old
        srv.shutdown()


def _apk_file(d, debuggable=True):
    p = os.path.join(d, "a.apk")
    app = {"debuggable": True} if debuggable else {"allowBackup": False}
    _apk(p, _axml_build(("manifest", {}, [("uses-sdk", {"targetSdkVersion": 34}, []), ("application", app, [])])))
    return p


def _cli(argv):
    with contextlib.redirect_stdout(io.StringIO()):
        return cli.main(argv)


def test_enrich_flow_and_outputs():
    with tempfile.TemporaryDirectory() as d, fake_ollama():
        out = os.path.join(d, "r")
        code = _cli([_apk_file(d), "-y", "-f", "json", "-f", "md", "-f", "html", "-o", out, "--ai", "local"])
        assert code == 2, code
        doc = json.loads(Path(out + ".json").read_text(encoding="utf-8"))
        fps = {f["fingerprint"] for f in doc["findings"]}
        a = doc["ai"]
        assert a["mode"] == "local" and "FAKE-SUMMARY" in a["summary"]
        assert a["notes"] and set(a["notes"]) <= fps and set(a["fix_first"]) <= fps and "bogus" not in a["notes"]
        assert any(f["title"] == "App is debuggable" for f in doc["findings"])
        for ext in (".md", ".html"):
            txt = Path(out + ext).read_text(encoding="utf-8")
            assert "FAKE-SUMMARY" in txt and "FAKE-WHY" in txt, ext


def test_garbage_answer_keeps_findings():
    with tempfile.TemporaryDirectory() as d:
        base, out = os.path.join(d, "base"), os.path.join(d, "r")
        apk = _apk_file(d)
        _cli([apk, "-y", "-f", "json", "-o", base])
        with fake_ollama("bad"):
            assert _cli([apk, "-y", "-f", "json", "-o", out, "--ai", "local"]) == 2
        a, b = (json.loads(Path(p + ".json").read_text(encoding="utf-8")) for p in (base, out))
        assert [f["fingerprint"] for f in a["findings"]] == [f["fingerprint"] for f in b["findings"]]
        assert "error" in b["ai"] and not b["ai"].get("summary") and not b["ai"].get("notes") and "ai" not in a


def test_cloud_without_key_makes_no_network_call():
    calls = []
    real, key = urllib.request.urlopen, os.environ.pop("ANTHROPIC_API_KEY", None)
    urllib.request.urlopen = lambda *a, **k: calls.append(a) or (_ for _ in ()).throw(AssertionError("network"))
    try:
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "r")
            assert _cli([_apk_file(d), "-y", "-f", "json", "-o", out, "--ai", "cloud"]) == 2
            doc = json.loads(Path(out + ".json").read_text(encoding="utf-8"))
        assert "ANTHROPIC_API_KEY" in doc["ai"]["error"] and not calls
    finally:
        urllib.request.urlopen = real
        if key is not None:
            os.environ["ANTHROPIC_API_KEY"] = key


def test_plan_helpers_degrade():
    with fake_ollama("bad"):
        assert ai.plan_scanners("http://x/", "", ["a", "b"], "local") == ["a", "b"]
        assert ai.extra_urls("http://x/", "", "local") == []


def _run_job(body):
    job = api.start_scan(body)
    end = time.time() + 60
    while job["state"] == "running" and time.time() < end:
        time.sleep(0.1)
    return job


def test_server_file_targets():
    with tempfile.TemporaryDirectory() as d, fake_ollama():
        apk = _apk_file(d)
        exe = os.path.join(d, "p.exe")
        Path(exe).write_bytes(_pe(True, 0))
        j = _run_job({"target": apk, "kind": "mobile", "authorized": True, "ai": "local"})
        assert j["state"] == "done" and j["kind"] == "mobile", j["error"]
        assert any(f.title == "App is debuggable" for f in j["findings"])
        assert "FAKE-SUMMARY" in api._job_json(j)["ai"]["summary"]
        j = _run_job({"target": exe, "kind": "desktop", "authorized": True})
        assert j["state"] == "done" and j["kind"] == "desktop" and j["ai"] is None
        for body in ({"target": apk, "kind": "mobile"}, {"target": exe, "kind": "desktop", "authorized": False}):
            try:
                api.start_scan(body)
                raise AssertionError("must be refused")
            except ValueError as e:
                assert "refused" in str(e)
        try:
            api.start_scan({"target": apk, "kind": "mobile", "authorized": True, "ai": "bogus"})
            raise AssertionError("bad ai mode must be refused")
        except ValueError:
            pass


def load_tests(loader, standard_tests, pattern):   # lets unittest/discover run the bare test_* functions
    from tests._fn import collect
    return collect(sys.modules[__name__])


if __name__ == "__main__":
    test_enrich_flow_and_outputs(); test_garbage_answer_keeps_findings()
    test_cloud_without_key_makes_no_network_call(); test_plan_helpers_degrade(); test_server_file_targets()
    print("test_ai_flow: ok")
