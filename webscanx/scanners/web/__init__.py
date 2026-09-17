"""Web scanners (target kind: WEB). Importing this package registers them all.

Deterministic, stdlib-only (urllib + html.parser) — no third-party deps, in line
with the local-first identity. Each check registers itself with the engine as a
named scanner (web.headers, web.tls, web.xss, web.sqli, web.csrf) so `--only`
works and findings carry a natural scanner tag. They share one crawl of the
target via the engine's per-run cache (see crawler.get_sitemap).
"""

from . import crawler  # noqa: F401  (shared crawl used by every module below)
from . import headers, tls, xss, sqli, csrf  # noqa: F401  (import = register)
from . import cors, redirect, disclosure  # noqa: F401  (import = register)
from . import methods, csp, mixed, secrets, errors  # noqa: F401  (import = register)
from . import cookies, forms  # noqa: F401  (import = register)
