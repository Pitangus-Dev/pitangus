"""The URLs a passive web scan reads: what katana crawled, what the site lists in robots.txt and its sitemaps, what ZAP's
spider reached and the paths of the API definition, merged into one inventory for nuclei (and the first ones for ZAP).

robots.txt and the sitemaps are fetched like the API definition (`domains.https_get`): from each host's checked
address, with SNI and certificate validation, no redirects, no proxy, a size cap and a time limit. Every URL that comes
back goes through the same check as a crawled one (`web_tools.in_scope_url`): HTTPS on a host of the scope, no user, no
port but 443, without its query string. A sitemap is XML from the site: it is read only below `SITEMAP_MAX` bytes and
refused whole when it declares a DOCTYPE or an entity (no expansion, no external reference), then parsed by the
standard library's expat parser, which resolves no external entity.
"""

from __future__ import annotations

import http.client
import ssl
import time
from typing import Any, Callable
from xml.etree import ElementTree

from pitangus.modules.scanning.web_tools import in_scope_url
from pitangus.modules.sources import domains

ROBOTS = "/robots.txt"
SITEMAP = "/sitemap.xml"
ROBOTS_MAX = 512 * 1024
SITEMAP_MAX = 2 * 1024 * 1024
SITEMAPS_MAX = 5          # sitemap documents read per host, a sitemap index's children included
ROBOTS_LINES = 2000
FETCH_SECONDS = 20
SEEDS_SECONDS = 120  # robots.txt and sitemaps of every host, together
INVENTORY_MAX = 500       # URLs kept in all (stored with the run)
FORBIDDEN_XML = (b"<!doctype", b"<!entity")

Fetch = Callable[..., tuple[int, bytes]]


def robots(text: str, host: str, hosts: list[str]) -> tuple[list[str], list[str]]:
    """(the in-scope URLs of its `Allow` and `Disallow` paths, the sitemaps it names). A wildcard (`*`, `$`) ends a
    path: what comes before it is the folder to read."""
    paths, sitemaps = [], []
    for line in text.splitlines()[:ROBOTS_LINES]:
        field, _, value = line.split("#", 1)[0].partition(":")
        field, value = field.strip().lower(), value.strip()
        if field in ("allow", "disallow") and value.startswith("/"):
            prefix = value.split("*", 1)[0].split("$", 1)[0]
            if url := in_scope_url(f"https://{host}{prefix}", hosts):
                paths.append(url)
        elif field == "sitemap" and (url := in_scope_url(value, hosts)):
            sitemaps.append(url)
    return paths, sitemaps


def _local(tag: Any) -> str:
    return str(tag).rsplit("}", 1)[-1].lower()


def sitemap(data: bytes, hosts: list[str]) -> tuple[list[str], list[str]]:
    """(the in-scope page URLs of a sitemap, the in-scope sitemaps of a sitemap index). Empty when it's too large,
    declares a DOCTYPE or an entity, or isn't XML."""
    if len(data) > SITEMAP_MAX or any(marker in data.lower() for marker in FORBIDDEN_XML):
        return [], []
    try:
        root = ElementTree.fromstring(data)
    except (ElementTree.ParseError, ValueError):
        return [], []
    pages: list[str] = []
    children: list[str] = []
    for entry in root:
        kind = _local(entry.tag)
        for item in entry:
            name = _local(item.tag)
            if name == "loc":
                url = in_scope_url((item.text or "").strip(), hosts)
                if url:
                    (children if kind == "sitemap" else pages).append(url)
            elif name == "link" and kind == "url" and (url := in_scope_url(item.get("href"), hosts)):
                pages.append(url)  # an alternate language of the page (xhtml:link hreflang)
    return pages, children


def _get(fetch: Fetch, url: str, pins: dict[str, str], limit: int) -> bytes | None:
    host, _, path = url.removeprefix("https://").partition("/")
    try:
        status, body = fetch(host, pins[host], "/" + path, limit=limit, seconds=FETCH_SECONDS)
    except (OSError, ssl.SSLError, http.client.HTTPException, KeyError):
        return None
    return body if status == 200 and len(body) <= limit else None


def known_files(hosts: list[str], pins: dict[str, str], *, fetch: Fetch | None = None) -> dict[str, list[str]]:
    """{"robots": URLs from robots.txt, "sitemap": URLs from the sitemaps} of every host of the scope: its robots.txt,
    the sitemaps it names on that host and /sitemap.xml, a sitemap index followed down to `SITEMAPS_MAX` documents."""
    fetch = fetch or domains.https_get
    found: dict[str, list[str]] = {"robots": [], "sitemap": []}
    # One budget for every host: a slow site can't hold the (one at a time) web scan queue for long.
    deadline = time.monotonic() + SEEDS_SECONDS
    for host in hosts:
        if host not in pins or time.monotonic() > deadline:
            continue
        named: list[str] = []
        body = _get(fetch, f"https://{host}{ROBOTS}", pins, ROBOTS_MAX)
        if body is not None:
            paths, named = robots(body.decode("utf-8", "replace"), host, hosts)
            found["robots"] += paths
        queue = list(dict.fromkeys([*(url for url in named if url.startswith(f"https://{host}/")), f"https://{host}{SITEMAP}"]))
        read = 0
        while queue and read < SITEMAPS_MAX and time.monotonic() <= deadline:
            url = queue.pop(0)
            read += 1
            body = _get(fetch, url, pins, SITEMAP_MAX)
            if body is None:
                continue
            pages, children = sitemap(body, hosts)
            found["sitemap"] += pages
            queue += [child for child in children if child.startswith(f"https://{host}/") and child not in queue]
    return found


def zap_urls(text: str, hosts: list[str]) -> list[str]:
    """The in-scope URLs of ZAP's export (one URL a line); anything else on a line, or a line that isn't a URL, is
    ignored."""
    found = []
    for line in text.splitlines()[:50_000]:
        parts = line.strip().split()
        url = in_scope_url(parts[-1] if parts else "", hosts)
        if url:
            found.append(url)
    return found


def api_urls(api: dict | None, target: str, hosts: list[str]) -> list[str]:
    """The definition's GET paths that need no value (no `{parameter}`), at the scan's target."""
    if not api or not target:
        return []
    paths = (api.get("document") or {}).get("paths") or {}
    return [url for route, item in paths.items() if isinstance(route, str) and "{" not in route and isinstance(item, dict) and "get" in item
            for url in [in_scope_url(target.rstrip("/") + route, hosts)] if url]


def merge(groups: dict[str, list[str]], *, limit: int = INVENTORY_MAX) -> tuple[list[str], dict[str, int]]:
    """One inventory: every URL once, shallow ones first, at most `limit`; and how many new URLs each source added
    (in the order given: a URL counts for the first source that had it)."""
    seen: dict[str, str] = {}
    for source, urls in groups.items():
        for url in urls:
            seen.setdefault(url, source)
    kept = sorted(seen, key=lambda url: (url.count("/"), url))[:limit]
    counts = {source: sum(1 for url in kept if seen[url] == source) for source in groups}
    return kept, counts
