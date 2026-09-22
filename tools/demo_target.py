"""Serve the deliberately-vulnerable fixture from the test suite as a standing
target, so the UI has something real to scan while you click around.

    python tools/demo_target.py            # http://127.0.0.1:8000

It binds 127.0.0.1 only. Scanning it is authorized by definition: it is this
repo's own fixture, running on your machine.
"""

from __future__ import annotations

import argparse
import sys
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.test_spine import _VulnHandler  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8000)
    port = ap.parse_args().port

    httpd = ThreadingHTTPServer(("127.0.0.1", port), _VulnHandler)
    print(f"demo target (intentionally vulnerable) on http://127.0.0.1:{port}")
    print("  point WebScanX at it.  Ctrl-C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
