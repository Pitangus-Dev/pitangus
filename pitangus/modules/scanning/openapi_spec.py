"""OpenAPI (3.x) and Swagger (2.0) definitions for the passive API scan, read without trusting them.

What ZAP gets is not the uploaded document but a JSON copy reduced to what a passive scan may send: only GET and
HEAD operations survive (ZAP's import calls every operation it finds, and a POST or DELETE with made-up values is not
a passive request), the servers point at the scan's own target, and no `$ref` may leave the document (a remote
reference would make ZAP fetch an arbitrary URL). YAML is read with the safe loader and without aliases, so a small
file can't expand into a huge one. Nothing of the definition is kept after the scan but its SHA-256 and how many
operations it had.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import ssl
from typing import Any
from urllib.parse import urlsplit

from pitangus.modules.sources import domains
from pitangus.shared.i18n import msg, text

MAX_BYTES = 5 * 1024 * 1024
MAX_NODES = 500_000
MAX_DEPTH = 64
MAX_OPERATIONS = 2000
SAFE_METHODS = ("get", "head")
METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
EXTENSIONS = (".json", ".yaml", ".yml")
PATH = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*")


class SpecError(ValueError):
    """`message` is what people read (rendered per reader); str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


def _yaml(raw: str) -> Any:
    import yaml  # type: ignore[import-untyped, unused-ignore]  # stubs (types-PyYAML) are optional

    class NoAliases(yaml.SafeLoader):
        def compose_node(self, parent, index):  # noqa: D401 — PyYAML's own hook
            if self.check_event(yaml.AliasEvent):
                raise yaml.YAMLError("aliases are not accepted")
            return super().compose_node(parent, index)

    # yaml.load's own steps, spelled out with our loader: a SafeLoader, so no tag can construct a Python object.
    try:
        loader = NoAliases(raw)  # the reader already refuses non-printable characters here
        try:
            return loader.get_single_data()
        finally:
            loader.dispose()
    except (yaml.YAMLError, RecursionError, ValueError) as exc:
        raise SpecError(msg("scanning.web.spec.unreadable")) from exc


def _walk(document: Any) -> None:
    """Bounded size and depth, and every `$ref` local to the document."""
    stack, nodes = [(document, 0)], 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise SpecError(msg("scanning.web.spec.too_large", max=MAX_BYTES // (1024 * 1024)))
        if isinstance(value, dict):
            reference = value.get("$ref")
            if reference is not None and not (isinstance(reference, str) and reference.startswith("#/")):
                raise SpecError(msg("scanning.web.spec.remote_ref"))
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)


def parse(raw: bytes, filename: str = "") -> dict:
    """{document (reduced, JSON-ready), sha256, endpoints, version, server: {host, path}}. Raises SpecError."""
    if not isinstance(raw, (bytes, bytearray)) or not raw:
        raise SpecError(msg("scanning.web.spec.empty"))
    if len(raw) > MAX_BYTES:
        raise SpecError(msg("scanning.web.spec.too_large", max=MAX_BYTES // (1024 * 1024)))
    if filename and not filename.lower().endswith(EXTENSIONS):
        raise SpecError(msg("scanning.web.spec.type"))
    try:
        decoded = bytes(raw).decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SpecError(msg("scanning.web.spec.unreadable")) from exc
    if decoded.lstrip().startswith(("{", "[")):
        try:
            document = json.loads(decoded)
        except (ValueError, RecursionError) as exc:
            raise SpecError(msg("scanning.web.spec.unreadable")) from exc
    else:
        document = _yaml(decoded)
    if not isinstance(document, dict):
        raise SpecError(msg("scanning.web.spec.not_openapi"))
    version = document.get("openapi")
    swagger = document.get("swagger")
    if not ((isinstance(version, str) and version.startswith("3.")) or str(swagger) == "2.0"):
        raise SpecError(msg("scanning.web.spec.not_openapi"))
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise SpecError(msg("scanning.web.spec.not_openapi"))
    _walk(document)
    reduced_paths, endpoints = {}, 0
    for route, item in paths.items():
        if not isinstance(route, str) or not route.startswith("/") or not isinstance(item, dict):
            continue
        # A path or an operation may declare its own `servers`: dropped, the target is the scan's.
        kept = {key: value for key, value in item.items() if key not in METHODS and key not in ("$ref", "servers")}
        operations = {method: {key: value for key, value in item[method].items() if key not in ("servers", "callbacks")}
                      for method in SAFE_METHODS if isinstance(item.get(method), dict)}
        if operations:
            reduced_paths[route] = {**kept, **operations}
            endpoints += len(operations)
    if not endpoints:
        raise SpecError(msg("scanning.web.spec.no_operations"))
    if endpoints > MAX_OPERATIONS:
        raise SpecError(msg("scanning.web.spec.too_many_operations", max=MAX_OPERATIONS))
    reduced = {key: value for key, value in document.items() if key not in ("paths", "webhooks", "servers", "host", "basePath", "schemes")}
    reduced["paths"] = reduced_paths
    # YAML may carry dates, sets or binary values: as text, ZAP only needs them as examples.
    try:
        reduced = json.loads(json.dumps(reduced, ensure_ascii=False, default=str))
    except (TypeError, ValueError, RecursionError) as exc:
        raise SpecError(msg("scanning.web.spec.unreadable")) from exc
    return {"document": reduced, "sha256": hashlib.sha256(bytes(raw)).hexdigest(), "endpoints": endpoints,
            "version": "2.0" if swagger else str(version)[:10], "server": _server(document)}


def _server(document: dict) -> dict:
    """The host (None when relative, templated or absent) and base path the definition declares."""
    if str(document.get("swagger")) == "2.0":
        host = document.get("host") if isinstance(document.get("host"), str) else None
        base = document.get("basePath") if isinstance(document.get("basePath"), str) else "/"
        return {"host": (host or "").split(":")[0].lower() or None, "path": base if PATH.fullmatch(base or "") else "/"}
    servers = document.get("servers")
    url = servers[0].get("url") if isinstance(servers, list) and servers and isinstance(servers[0], dict) else None
    if not isinstance(url, str) or "{" in url:
        return {"host": None, "path": "/"}
    if url.startswith("/"):
        return {"host": None, "path": url if PATH.fullmatch(url) else "/"}
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower() or None
    except ValueError:
        return {"host": None, "path": "/"}
    path = parts.path or "/"
    return {"host": host, "path": path if PATH.fullmatch(path) else "/"}


def target_url(parsed: dict, root: str, scope_hosts: list[str]) -> str:
    """Where ZAP sends the operations: the definition's own server when its host is in the scan's scope, else the
    domain's host with the definition's base path. Never anywhere else, whatever the definition says."""
    server = parsed["server"]
    host = server["host"] if server["host"] in scope_hosts else root
    path = server["path"].rstrip("/") or ""
    return f"https://{host}{path}"


def check_url(url, scope_hosts: list[str]) -> tuple[str, str]:
    """(host, path with query) of a definition's URL: HTTPS, no user, port or fragment, on a host of the scan's
    scope that is pinned (not a wildcard). Raises SpecError."""
    if not isinstance(url, str) or len(url) > 2000:
        raise SpecError(msg("scanning.web.spec.bad_url"))
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError as exc:
        raise SpecError(msg("scanning.web.spec.bad_url")) from exc
    if parts.scheme != "https" or parts.username or parts.password or port is not None or parts.fragment or not host:
        raise SpecError(msg("scanning.web.spec.bad_url"))
    if host not in scope_hosts:
        raise SpecError(msg("scanning.web.spec.url_outside", host=host))
    path = parts.path or "/"
    if any(ord(character) <= 32 or ord(character) == 127 for character in path + parts.query):
        raise SpecError(msg("scanning.web.spec.bad_url"))
    return host, path + (f"?{parts.query}" if parts.query else "")


def fetch(url: str, pins: dict[str, str]) -> dict:
    """The definition at `url`, fetched once from its host's checked address (no redirects, MAX_BYTES at most) and
    parsed like an upload."""
    host, path = check_url(url, list(pins))
    try:
        status, body = domains.https_get(host, pins[host], path, limit=MAX_BYTES, seconds=60)
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise SpecError(msg("scanning.web.spec.fetch_failed", url=url)) from exc
    if status != 200:
        raise SpecError(msg("scanning.web.spec.fetch_status", url=url, code=status))
    return parse(body)


def for_zap(parsed: dict, target: str) -> str:
    """The reduced definition as JSON, its servers pointing at `target`."""
    document = dict(parsed["document"])
    if parsed["version"] == "2.0":
        parts = urlsplit(target)
        document.update(host=parts.hostname, basePath=parts.path or "/", schemes=["https"])
    else:
        document["servers"] = [{"url": target}]
    return json.dumps(document, ensure_ascii=False)
