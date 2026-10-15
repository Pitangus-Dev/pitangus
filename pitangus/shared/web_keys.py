"""What a web finding's identity and its coverage read of a URL, pinned before the URL is rendered (shared/render.py
`url`, which may show two pages alike: `/users/***`).

A key is never shown and never a location: `key:` and the URL's scheme, host and port as they are, then each piece of
its path (what lies between `/` and the separators `-_.~`) as a digest of what the location form of 0.13 left of it
(render.location: token-shaped segments and matrix values replaced), and its query and fragment as one digest. No path
segment, query, fragment or user information is in it, two different paths never share one, and the same page keeps it
from scan to scan. The path templates of findings/canonical.py are built on keys, piece for piece as on the location
form, so the identities computed before keys existed keep their value; a URL already in the location form has the key
it had in clear (`render.location` is idempotent), which is how stored runs get theirs.

A web finding pins `web_key` (and each of its instances a `key`) and its identity; a web scan pins in `keys` the page
keys of the pages it reached and of the units its engines declared (`of_record`). Everything that compares pages reads
keys, never the URL shown.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from pitangus.shared import render
from pitangus.shared.code_identity import digest

PREFIX = "key:"
_PIECE = re.compile(r"[^/\-_.~]+")
_DEFAULT_PORTS = {"https": 443, "http": 80}


def _piece(text: str) -> str:
    return hashlib.sha256(b"pitangus-web-piece\0" + text.encode("utf-8", "surrogateescape")).hexdigest()[:16]


def legacy(url: str) -> str:
    """The location form a web identity reads (render.location: idempotent)."""
    return render.location(url)


def key(url: Any) -> str | None:
    """The key of `url` (see the module's docstring); None for what isn't a URL with a host, or is a key already."""
    if not isinstance(url, str) or not render.URL_START.match(url):
        return None
    try:
        parts = urlsplit(legacy(url))
        host = (parts.hostname or "").lower()
    except ValueError:
        return None
    try:
        port = parts.port
    except ValueError:   # a port the location form replaced
        port = None
    if not host:
        return None
    scheme = parts.scheme.lower()
    authority = f"[{host}]" if ":" in host else host
    if port and port != _DEFAULT_PORTS.get(scheme):
        authority += f":{port}"
    # Its query and fragment (in the location form) as one digest: one page with other parameters is another place
    # of a finding, never another page or another template.
    tail = "?" + _piece("?" + parts.query + ("#" + parts.fragment if parts.fragment else "")) if parts.query or parts.fragment else ""
    return f"{PREFIX}{scheme}://{authority}{_PIECE.sub(lambda found: _piece(found.group(0)), parts.path)}{tail}"


def is_key(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def bare(value: str) -> str:
    """A key as the URL-shaped string its templates are built on (`https://host/<digests>`)."""
    return value[len(PREFIX):] if is_key(value) else value


def page(value: str) -> str:
    """The page a key stands for (domains.page_of on keys): its repeated slashes as one and no trailing slash."""
    scheme, _, rest = bare(value).partition("://")
    rest = rest.partition("?")[0]
    slash = rest.find("/")
    authority, path = (rest, "") if slash < 0 else (rest[:slash], rest[slash:])
    return f"{PREFIX}{scheme}://{authority}{re.sub('/{2,}', '/', path).rstrip('/') or '/'}"


def host(value: str) -> str:
    try:
        return (urlsplit(bare(value)).hostname or "").lower()
    except ValueError:
        return ""


def of_finding(finding: Mapping[str, Any]) -> str:
    """The key of a web finding's URL: the one pinned, else computed from its path (in clear, or in the location form
    a run stored before keys existed); "" when it has none."""
    pinned = finding.get("web_key")
    if is_key(pinned):
        return str(pinned)
    return key(str(finding.get("path") or "")) or ""


def of_instance(item: Mapping[str, Any]) -> str:
    pinned = item.get("key")
    return str(pinned) if is_key(pinned) else key(str(item.get("path") or "")) or ""


def as_page(found: str) -> str:
    """A key as the page it stands for (domains.page_of: http and https only); any other key as it is."""
    return page(found) if bare(found).startswith(("http://", "https://")) else found


def of_page(url: Any) -> Any:
    """A unit an engine listed or a page a scan reached, as a page key (`as_page`); anything that isn't a URL as it is
    (`*`, a host)."""
    found = key(url)
    return as_page(found) if found else url


def _units(value: Any) -> Any:
    """A list of units, or {unit: reason}, with each URL as its page key; `*` as it is."""
    if isinstance(value, list):
        return [of_page(item) for item in value]
    if isinstance(value, dict):
        return {of_page(unit): why for unit, why in value.items()}
    return value


def of_record(record: Mapping[str, Any]) -> dict:
    """The keys a web scan pins: the pages its scope says it reached and probed, and the units each engine's coverage
    declares examined and unexamined, as page keys."""
    scope: dict = record["scope"] if isinstance(record.get("scope"), dict) else {}
    coverage: dict = {}
    for engine, spec in (record.get("coverage") or {}).items() if isinstance(record.get("coverage"), dict) else ():
        if isinstance(spec, dict):
            entry = {name: _units(spec[name]) for name in ("examined", "unexamined") if name in spec}
            if isinstance(spec.get("by_scanner"), dict):
                entry["by_scanner"] = {scanner: _units(units) for scanner, units in spec["by_scanner"].items()}
            coverage[engine] = entry
    return {"scope": {name: _units(scope[name]) for name in ("reached", "probed") if name in scope}, "coverage": coverage}


def keyed(record: Mapping[str, Any]) -> dict:
    """A web scan as what compares pages reads it: its scope and coverage with the keys it pinned (computed from its
    URLs when it has none: in clear, or in the location form of runs stored before keys existed)."""
    record = dict(record)
    if record.get("type") != "dast_scan":
        return record
    keys: dict = record["keys"] if isinstance(record.get("keys"), dict) else of_record(record)
    coverage = dict(record.get("coverage") or {}) if isinstance(record.get("coverage"), dict) else {}
    for engine, entry in (keys.get("coverage") or {}).items():
        coverage[engine] = {**(coverage.get(engine) or {}), **entry}
    return {**record, "scope": {**(record.get("scope") or {}), **(keys.get("scope") or {})}, "coverage": coverage, "keys": keys}


def identity(finding: Mapping[str, Any], url: str) -> str:
    """A web finding's identity (findings/canonical.py): its tool, rule, URL (its path template, else its location
    form), evidence and kind of scan."""
    value = " ".join(str((finding.get("web") or {}).get("evidence") or "").split())[:500]
    kind = str((finding.get("web") or {}).get("coverage") or "baseline")
    return digest("web", str(finding.get("tool") or "").lower(), str(finding.get("rule_id") or ""), url, value,
                  *([kind] if kind != "baseline" else []))


def lone_identity(finding: Mapping[str, Any]) -> str:
    """A web finding's identity with no template: its location form."""
    return identity(finding, legacy(str(finding.get("path") or "")))


def pinned(finding: Mapping[str, Any]) -> dict:
    """A web finding with its key, its instances' keys and its identity pinned from its URLs as they are (before they
    are rendered); what is pinned already stays."""
    result = dict(finding)
    if not is_key(result.get("web_key")) and (found := key(str(result.get("path") or ""))):
        result["web_key"] = found
    if isinstance(result.get("instances"), list):
        result["instances"] = [{**item, "key": found} if isinstance(item, dict) and not is_key(item.get("key"))
                               and (found := key(str(item.get("path") or ""))) else item for item in result["instances"]]
    if not result.get("identity") and result.get("path"):
        result["identity"] = lone_identity(result)
    return result


def template_in_clear(location: str, keyed_template: str) -> str:
    """The path template `keyed_template` (built on keys: findings/canonical.py) written on `location`, the location form
    of one of the URLs it was built from: each `{}` where the keys had it, the pieces around it as they were."""
    try:
        parts = urlsplit(location)
    except ValueError:
        return location
    origin = f"{parts.scheme}://{(parts.hostname or '').lower()}"
    rest = keyed_template.partition("://")[2]
    keyed = rest[rest.find("/"):].split("/") if "/" in rest else [""]
    clear = parts.path.split("/")
    if len(keyed) != len(clear):
        return origin + parts.path
    out = []
    for written, segment in zip(keyed, clear):
        if "{}" not in written:
            out.append(segment)
            continue
        head, _, tail = written.partition("{}")
        pieces, digests = re.split(r"([-_.~])", segment), re.split(r"([-_.~])", _PIECE.sub(lambda found: _piece(found.group(0)), segment))
        start = next((count for count in range(len(digests) + 1) if "".join(digests[:count]) == head), 0)
        end = next((count for count in range(len(digests) + 1) if "".join(digests[len(digests) - count:]) == tail), 0) if tail else 0
        out.append("".join(pieces[:start]) + "{}" + ("".join(pieces[len(pieces) - end:]) if end else ""))
    return origin + "/".join(out)
