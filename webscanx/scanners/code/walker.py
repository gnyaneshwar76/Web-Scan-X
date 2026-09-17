"""One walk of the source tree, shared by every code scanner.

Reads text files under the target directory, skipping the usual noise (VCS, deps,
build output, virtualenvs) and anything too big or binary. Built once per run and
memoised in ctx.cache. stdlib only.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

# ponytail: fixed ceilings; lift if a real project needs a wider sweep.
MAX_FILES = 2000
MAX_BYTES = 1_000_000          # per-file cap (1 MB) — skip generated blobs

_SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
              "__pycache__", "dist", "build", ".idea", ".gradle", "target",
              ".next", ".nuxt", "vendor", "bower_components", ".mypy_cache",
              ".pytest_cache", "coverage", ".tox"}

# Extensions worth reading as source. Everything else is skipped as non-source.
_SOURCE_EXTS = {
    ".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java",
    ".rb", ".php", ".go", ".rs", ".c", ".h", ".cpp", ".cc", ".hpp", ".cs",
    ".kt", ".kts", ".swift", ".scala", ".sh", ".bash", ".pl", ".pm",
    ".sql", ".html", ".htm", ".vue", ".svelte", ".env", ".ini", ".cfg",
    ".conf", ".yml", ".yaml", ".toml", ".json", ".xml", ".properties",
    ".tf", ".gradle", ".dockerfile",
}
_SOURCE_NAMES = {"Dockerfile", ".env", "Makefile", ".htaccess"}


@dataclass
class SourceFile:
    path: str                  # absolute path
    rel: str                   # path relative to the scan root
    text: str
    lines: list[str] = field(default_factory=list)


@dataclass
class Tree:
    root: str
    files: list[SourceFile] = field(default_factory=list)


def _is_source(name: str) -> bool:
    if name in _SOURCE_NAMES:
        return True
    return os.path.splitext(name)[1].lower() in _SOURCE_EXTS


def walk(root: str, max_files: int = MAX_FILES) -> Tree:
    """Read source files under root. Never raises — unreadable files are skipped."""
    tree = Tree(root=root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            if len(tree.files) >= max_files:
                return tree
            if not _is_source(name):
                continue
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) > MAX_BYTES:
                    continue
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except (OSError, ValueError):
                continue
            if "\x00" in text[:1024]:       # looks binary despite the extension
                continue
            tree.files.append(SourceFile(path=full, rel=os.path.relpath(full, root),
                                         text=text, lines=text.splitlines()))
    return tree


def get_tree(target, ctx) -> Tree:
    """Build the walk once per run and memoise it in the shared context cache."""
    cached = ctx.cache.get("sourcetree")
    if cached is None:
        cached = walk(target.location,
                      max_files=getattr(ctx, "max_pages", None) or MAX_FILES)
        ctx.cache["sourcetree"] = cached
    return cached


def demo() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "node_modules"))
        open(os.path.join(d, "node_modules", "junk.js"), "w").write("skip me")
        open(os.path.join(d, "app.py"), "w", encoding="utf-8").write("print(1)\n")
        open(os.path.join(d, "photo.png"), "wb").write(b"\x89PNG\x00\x00")
        tree = walk(d)
        rels = {f.rel for f in tree.files}
        assert "app.py" in rels, rels
        assert not any("node_modules" in r for r in rels), "dep dir must be skipped"
        assert "photo.png" not in rels, "binary extension must be skipped"
        assert tree.files[0].lines == ["print(1)"]
    print("walker.py: ok")


if __name__ == "__main__":
    demo()
