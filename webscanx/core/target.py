"""What are we scanning? Decide from what the user handed us.

The CLI takes one target string and this module classifies it, so the engine
knows which scanners to run. Detection is deliberately simple and predictable;
when it can't tell, it says UNKNOWN rather than guessing wrong.
"""

from __future__ import annotations

import enum
import os
from dataclasses import dataclass
from urllib.parse import urlparse


class TargetKind(enum.Enum):
    WEB = "web"          # a live website / web app (also APIs, until Phase 4 splits them)
    CODE = "code"        # a directory of the user's own source — the only fixable kind
    MOBILE = "mobile"    # an .apk / .ipa
    DESKTOP = "desktop"  # an executable / binary
    UNKNOWN = "unknown"


_EXECUTABLE_EXTS = {".exe", ".dll", ".so", ".dylib", ".bin", ".app", ".msi"}
_MOBILE_EXTS = {".apk", ".ipa", ".aab"}


@dataclass
class Target:
    kind: TargetKind
    location: str        # normalized: URL for WEB, absolute path otherwise
    raw: str             # exactly what the user typed

    @property
    def is_owned_code(self) -> bool:
        """Only owned code may be auto-fixed — see the plan's hard rule."""
        return self.kind is TargetKind.CODE


def detect(raw: str) -> Target:
    """Classify a target string. Never raises — UNKNOWN is a valid answer."""
    s = raw.strip()

    parsed = urlparse(s)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return Target(TargetKind.WEB, s, raw)

    # Anything else is treated as a filesystem path.
    path = os.path.abspath(os.path.expanduser(s))
    ext = os.path.splitext(path)[1].lower()

    if os.path.isdir(path):
        return Target(TargetKind.CODE, path, raw)
    if ext in _MOBILE_EXTS:
        return Target(TargetKind.MOBILE, path, raw)
    if ext in _EXECUTABLE_EXTS:
        return Target(TargetKind.DESKTOP, path, raw)
    # A bare host like "example.com" is a common shorthand for a web target.
    # (Its ".com" trips splitext, so don't gate on ext here — just make sure
    # it isn't an actual file sitting on disk.)
    if ("." in s and "/" not in s and "\\" not in s and " " not in s
            and not os.path.isfile(path)):
        return Target(TargetKind.WEB, "http://" + s, raw)

    return Target(TargetKind.UNKNOWN, path, raw)


def demo() -> None:
    assert detect("https://example.com").kind is TargetKind.WEB
    assert detect("example.com").kind is TargetKind.WEB
    assert detect("example.com").location == "http://example.com"
    assert detect(".").kind is TargetKind.CODE          # cwd is a directory
    assert detect("app.apk").kind is TargetKind.MOBILE
    assert detect("tool.exe").kind is TargetKind.DESKTOP
    assert detect("nonsense not a path").kind is TargetKind.UNKNOWN
    assert detect(".").is_owned_code and not detect("https://x.com").is_owned_code
    print("target.py: ok")


if __name__ == "__main__":
    demo()
