"""Code scanners (target kind: CODE) — static analysis of the user's own source.

This is SAST: it reads files, never runs them. Importing this package registers
every check. Deterministic, stdlib-only (os + re). Each check registers with the
engine as a named scanner (code.secrets, code.injection, code.crypto,
code.config) so `--only` works. They share one walk of the tree via the engine's
per-run cache (see walker.get_tree).

Code is the only target kind the fixer may later touch (see the plan's hard rule);
for now these checks only find and explain.
"""

from . import walker  # noqa: F401  (shared source-tree walk)
from . import secrets, injection, crypto, config  # noqa: F401  (import = register)
