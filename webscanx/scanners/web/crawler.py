"""One crawl, shared by every web scanner.

The engine gives each scanner the same ScanContext, so the crawl is built once,
memoised in ctx.cache, and reused. Same-origin only, hard-capped on pages and
depth — a scanner must never wander off-site or crawl the whole internet.

stdlib only: urllib for URLs, html.parser for links + forms. Network goes
through http.fetch (timeouts + size cap + never-raises) — nothing here opens a
socket directly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urldefrag

from . import http

# Defaults only: ctx.max_pages / ctx.max_depth (CLI --max-pages/--depth, API maxPages/depth) override.
MAX_PAGES = 25
MAX_DEPTH = 2
MAX_SCRIPTS = 5          # same-origin <script src> files read per page for route strings

_SKIP_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
             ".woff2", ".ttf", ".map", ".mp4", ".webp", ".pdf", ".zip")
# quoted absolute-path strings in JS, e.g. "/api/users?id=1"
_JS_ROUTE = re.compile(r"""["'`](/[A-Za-z0-9_\-./]{1,100}(?:\?[A-Za-z0-9_=&%.\-]{1,100})?)["'`]""")


def _js_routes(js: str) -> list[str]:
    out = []
    for r in _JS_ROUTE.findall(js or ""):
        if not r.startswith("//") and not r.split("?")[0].lower().endswith(_SKIP_EXT):
            out.append(r)
    return out


def _seed_urls(root: str, timeout: float) -> list[str]:
    """Extra start URLs from robots.txt (Allow/Disallow paths, Sitemap:) and sitemap.xml."""
    base = f"{urlparse(root).scheme}://{urlparse(root).netloc}"
    urls: list[str] = []
    sitemaps = [base + "/sitemap.xml"]
    r = http.fetch(base + "/robots.txt", timeout=timeout)
    if r.ok and r.status == 200:
        for line in r.body.splitlines():
            key, _, val = line.partition(":")
            key, val = key.strip().lower(), val.strip()
            if key == "sitemap" and val:
                sitemaps.append(val)
            elif key in ("allow", "disallow") and val.startswith("/") and not any(c in val for c in "*$"):
                urls.append(base + val)
    for sm in dict.fromkeys(sitemaps):
        r = http.fetch(sm, timeout=timeout)
        if r.ok and r.status == 200:
            urls += [u.strip() for u in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r.body)]
    return [u for u in dict.fromkeys(urls) if _same_origin(u, root)]


@dataclass
class Form:
    action_url: str                       # absolute, where the form submits
    method: str                           # "GET" or "POST" (upper-cased)
    fields: list[str] = field(default_factory=list)   # input/select/textarea names
    has_token: bool = False               # any field that looks like a CSRF token?
    source_url: str = ""                  # page the form was found on


@dataclass
class Page:
    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    set_cookie: list[str] = field(default_factory=list)
    body: str = ""


@dataclass
class Sitemap:
    root: str
    pages: list[Page] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)

    @property
    def params(self) -> list[tuple[str, str]]:
        """(url, param_name) pairs found in crawled links — XSS/SQLi entry points."""
        out: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for pg in self.pages:
            q = urlparse(pg.url).query
            for pair in q.split("&"):
                name = pair.split("=", 1)[0]
                if name and (pg.url, name) not in seen:
                    seen.add((pg.url, name))
                    out.append((pg.url, name))
        return out


# names that indicate an anti-CSRF token is present on a form
_TOKEN_HINTS = ("csrf", "xsrf", "token", "authenticity", "nonce", "__requestverification")


class _Parser(HTMLParser):
    """Pull <a href> links and <form> definitions out of one page."""

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[Form] = []
        self._form: Form | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            href, _ = urldefrag(urljoin(self.base, a["href"]))
            self.links.append(href)
        elif tag == "script" and a.get("src"):
            self.scripts.append(urljoin(self.base, a["src"]))
        elif tag == "form":
            action = urljoin(self.base, a.get("action") or self.base)
            self._form = Form(action_url=action,
                              method=(a.get("method") or "GET").upper(),
                              source_url=self.base)
        elif tag in ("input", "select", "textarea") and self._form is not None:
            name = a.get("name")
            if name:
                self._form.fields.append(name)
                low = name.lower()
                if any(h in low for h in _TOKEN_HINTS) or a.get("type") == "hidden" and any(
                        h in low for h in _TOKEN_HINTS):
                    self._form.has_token = True

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)


def crawl(root: str, timeout: float = 15.0,
          max_pages: int = MAX_PAGES, max_depth: int = MAX_DEPTH,
          extra_seeds=()) -> Sitemap:
    """Breadth-first, same-origin, capped. Never raises — bad pages are skipped."""
    site = Sitemap(root=root)
    queue: list[tuple[str, int]] = [(root, 0)]
    queue += [(u, 1) for u in _seed_urls(root, timeout)]
    # AI-plan seeds: same-origin only (fetch() applies the SSRF guard); page caps apply below
    queue += [(u, 1) for u in extra_seeds if isinstance(u, str) and _same_origin(u, root)]
    visited: set[str] = set()

    while queue and len(site.pages) < max_pages:
        url, depth = queue.pop(0)
        url, _ = urldefrag(url)
        if url in visited or not _same_origin(url, root):
            continue
        visited.add(url)

        resp = http.fetch(url, timeout=timeout)
        if not resp.ok:
            continue
        site.pages.append(Page(url=url, status=resp.status, headers=resp.headers,
                               set_cookie=resp.set_cookie, body=resp.body))

        ctype = resp.headers.get("content-type", "")
        if "html" not in ctype and ctype:      # only parse HTML for more links/forms
            continue
        p = _Parser(resp.final_url or url)
        try:
            p.feed(resp.body)
        except Exception:
            continue
        site.forms.extend(p.forms)
        if depth < max_depth:
            links = list(p.links)
            for src in [u for u in p.scripts if _same_origin(u, root)][:MAX_SCRIPTS]:
                js = http.fetch(src, timeout=timeout)
                if js.ok:
                    links += [urldefrag(urljoin(root, r))[0] for r in _js_routes(js.body)]
            for link in links:
                if link not in visited and _same_origin(link, root):
                    queue.append((link, depth + 1))

    return site


def get_sitemap(target, ctx) -> Sitemap:
    """Build the crawl once per run and memoise it in the shared context cache.
    Honours ctx.max_pages / ctx.max_depth overrides when set."""
    cached = ctx.cache.get("sitemap")
    if cached is None:
        cached = crawl(target.location, timeout=ctx.timeout,
                       max_pages=getattr(ctx, "max_pages", None) or MAX_PAGES,
                       max_depth=getattr(ctx, "max_depth", None)
                       if getattr(ctx, "max_depth", None) is not None else MAX_DEPTH,
                       extra_seeds=ctx.cache.get("extra_seeds") or ())
        ctx.cache["sitemap"] = cached
    return cached


def demo() -> None:
    # Parse a fixed HTML blob offline — no network needed for the self-check.
    html_doc = """
      <a href="/about">about</a><a href="https://evil.example/x">off</a>
      <a href="?q=1">search</a>
      <form action="/login" method="post">
        <input name="user"><input name="pass" type="password">
      </form>
      <form action="/comment" method="post">
        <input name="body"><input name="csrf_token" type="hidden">
      </form>
    """
    p = _Parser("http://site.test/")
    p.feed(html_doc)
    assert "http://site.test/about" in p.links
    assert "http://site.test/?q=1" in p.links
    assert len(p.forms) == 2
    login, comment = p.forms
    assert login.fields == ["user", "pass"] and not login.has_token
    assert comment.has_token, "csrf_token field must be detected"
    assert _same_origin("http://site.test/a", "http://site.test/b")
    assert not _same_origin("http://site.test/a", "https://site.test/a")  # scheme differs

    assert _js_routes('fetch("/api/u?id=1"); x="//cdn/x"; y="/a.png"; z="/login"') == ["/api/u?id=1", "/login"]
    p2 = _Parser("http://site.test/")
    p2.feed('<script src="/app.js"></script>')
    assert p2.scripts == ["http://site.test/app.js"]

    # Sitemap.params extracts query parameters from crawled page URLs.
    sm = Sitemap(root="http://site.test/")
    sm.pages.append(Page(url="http://site.test/s?q=1&cat=2", status=200))
    names = [n for _, n in sm.params]
    assert names == ["q", "cat"], names
    print("crawler.py: ok")


if __name__ == "__main__":
    demo()
