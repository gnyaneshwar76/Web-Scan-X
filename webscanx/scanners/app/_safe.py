"""Safe reading of untrusted app packages (.apk/.aab/.ipa are zip files).

Every app file is hostile input: zip bombs, huge members, path tricks, lying
headers. Nothing here extracts to disk or executes anything; members are read
into memory with hard caps, and any cap hit raises UnsafeFile so the scanner
reports "could not safely analyze" instead of crashing or hanging.
"""

from __future__ import annotations

import os
import stat
import zipfile

MAX_FILE = 1024 * 1024 * 1024      # 1 GB on disk
MAX_ENTRIES = 50_000
MAX_TOTAL = 2 * 1024 * 1024 * 1024  # 2 GB declared uncompressed in total
MAX_MEMBER = 64 * 1024 * 1024       # 64 MB read from any one member
MAX_RATIO = 200                     # uncompressed/compressed, per member


class UnsafeFile(Exception):
    """The file broke a safety cap or is not a valid package."""


def check_size(path: str, limit: int = MAX_FILE) -> int:
    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode):   # a FIFO or device would hang the read
        raise UnsafeFile("not a regular file")
    size = st.st_size
    if size > limit:
        raise UnsafeFile(f"file is {size} bytes, over the {limit} byte limit")
    return size


def _bad_name(name: str) -> bool:
    n = name.replace("\\", "/")
    return n.startswith("/") or ".." in n.split("/") or ":" in n.split("/")[0]


class SafeZip:
    """A read-only view of a zip with caps. Use as a context manager."""

    def __init__(self, path: str):
        check_size(path)
        try:
            self._z = zipfile.ZipFile(path)
        except (zipfile.BadZipFile, OSError, ValueError) as e:
            raise UnsafeFile(f"not a valid zip package: {e}") from None
        infos = self._z.infolist()
        if len(infos) > MAX_ENTRIES:
            raise UnsafeFile(f"{len(infos)} entries, over the {MAX_ENTRIES} limit")
        if sum(i.file_size for i in infos) > MAX_TOTAL:
            raise UnsafeFile("declared uncompressed size is too large (zip bomb?)")
        # Unsafe names are skipped, never opened (no extraction happens anyway).
        self._infos = {i.filename: i for i in infos
                       if not i.is_dir() and not _bad_name(i.filename)}

    def __enter__(self) -> "SafeZip":
        return self

    def __exit__(self, *exc) -> None:
        self._z.close()

    def names(self) -> list[str]:
        return list(self._infos)

    def read(self, name: str, limit: int = MAX_MEMBER) -> bytes:
        info = self._infos.get(name)
        if info is None:
            raise KeyError(name)
        if info.file_size > limit:
            raise UnsafeFile(f"{name} is {info.file_size} bytes, over the {limit} limit")
        if info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
            raise UnsafeFile(f"{name} compresses {MAX_RATIO}x+ (zip bomb?)")
        try:
            with self._z.open(info) as f:
                data = f.read(limit + 1)    # never trust the declared size
        except (zipfile.BadZipFile, RuntimeError, OSError, EOFError) as e:
            raise UnsafeFile(f"cannot read {name}: {e}") from None
        if len(data) > limit:
            raise UnsafeFile(f"{name} is larger than declared")
        return data


def read_file(path: str, limit: int = MAX_MEMBER) -> bytes:
    """Read a plain (non-zip) file up to `limit` bytes."""
    check_size(path, limit)
    with open(path, "rb") as f:
        return f.read(limit)


def demo() -> None:
    import io
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        ok = os.path.join(d, "ok.zip")
        with zipfile.ZipFile(ok, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("AndroidManifest.xml", b"x" * 100)
            z.writestr("../evil.txt", b"y")
        with SafeZip(ok) as s:
            assert s.names() == ["AndroidManifest.xml"], s.names()  # traversal name skipped
            assert s.read("AndroidManifest.xml") == b"x" * 100

        bomb = os.path.join(d, "bomb.zip")
        with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("big.bin", b"\0" * (5 * 1024 * 1024))     # compresses ~1000x
        with SafeZip(bomb) as s:
            try:
                s.read("big.bin")
                raise AssertionError("bomb ratio must be refused")
            except UnsafeFile:
                pass

        junk = os.path.join(d, "junk.apk")
        with open(junk, "wb") as f:
            f.write(b"not a zip")
        try:
            SafeZip(junk)
            raise AssertionError("junk must be refused")
        except UnsafeFile:
            pass
    print("_safe.py: ok")


if __name__ == "__main__":
    demo()
