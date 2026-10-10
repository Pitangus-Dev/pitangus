"""The nuclei templates a passive web scan may run: one pinned release, filtered down to what only looks.

The release (`RELEASE`) is downloaded once from GitHub's archive of its tag and checked against the SHA-256 the
project publishes for it (`SHA256`); nuclei never updates templates itself (`-duc`, and its container can't resolve
GitHub). The archive is opened here, not by nuclei, and only the templates that pass `allowed` are written to the
cache folder that nuclei gets read-only: the rest never reach the disk, so no flag nuclei may misread can bring them
back. A template is kept only when all of this holds:

* it lives under a detection folder (`ROOTS`: exposures, misconfiguration, technologies, CVEs, takeovers, TLS);
* its requests are HTTP (or TLS handshakes) and nothing else: no code, JavaScript, headless browser, raw network,
  DNS, file, workflow or `flow` logic;
* every HTTP request is a GET or a HEAD with no body, no fuzzing, no race or pipelining and no unsafe raw mode;
  its paths are plain path characters (a plain query string at most) with none of the usual attack markers
  (`ATTACK`: traversal, script tags, shell or template injection, time-based SQL, out-of-band callbacks) and nothing
  that names a state change (`STATE`: reset, delete, logout…); a payload list is only a short list of such fixed
  paths (`PAYLOAD_MAX` requests at most, never a wordlist file);
* none of its tags names an attack or a login (`DENY_TAGS`), and no matcher measures time.

A CVE template must also read fixed paths only (no query string, no payload list): one that survives detects a version
or an exposed file; one that would exploit the CVE doesn't.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.request import Request, urlopen

import yaml

from pitangus.version import USER_AGENT

RELEASE = "10.4.9"
URL = f"https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/refs/tags/v{RELEASE}"
# nuclei-templates-10.4.9_checksums.txt in the release: the archive of the tag.
SHA256 = "d7cd989935f9a84943cba8a193f567db37626dbf4e526ff57ba5b1f24badd5d6"
ARCHIVE_MAX = 40_000_000
TEMPLATE_MAX = 200_000
PREFIX = f"nuclei-templates-{RELEASE}/"
ROOTS = ("http/exposures/", "http/misconfiguration/", "http/technologies/", "http/cves/", "http/takeovers/", "ssl/")
PROTOCOLS = frozenset({"http", "requests", "ssl"})
FORBIDDEN_KEYS = frozenset({"code", "javascript", "headless", "network", "tcp", "dns", "file", "workflows", "flow",
                            "websocket", "whois", "self-contained", "variables-js"})
DENY_TAGS = frozenset({
    "intrusive", "dos", "fuzz", "fuzzing", "dast", "bruteforce", "brute-force", "default-login", "authenticated",
    "auth-bypass", "sqli", "time-based-sqli", "rce", "lfi", "rfi", "xss", "ssrf", "ssti", "xxe", "injection",
    "traversal", "deserialization", "file-upload", "crlf", "redirect", "open-redirect", "cmdi", "code-injection",
    "oast", "oob", "interactsh", "headless", "race", "smuggling", "cache-poisoning", "csrf", "idor", "account-takeover",
})
METHODS = frozenset({"GET", "HEAD"})
REQUEST_KEYS = frozenset({"fuzzing", "body", "race", "race_count", "pipeline",
                          "unsafe", "pipeline-concurrent-connections", "self-contained"})
ATTACK = re.compile(r"\.\.|%2e%2e|%252e|%c0%ae|<script|%3cscript|javascript:|\$\{|\$\(|`|\|\||;\s*(?:cat|id|ls|echo)\b|"
                    r"/etc/passwd|win\.ini|sleep\(|waitfor\s+delay|benchmark\(|union\s+select|union\+select|interactsh|"
                    r"\{\{(?:base64|url_encode|hex_encode)", re.IGNORECASE)
TIMING = re.compile(r"\bduration\b", re.IGNORECASE)
RAW_LINE = re.compile(r"^\s*([A-Z]+)\s+(\S+)")
# Variables only (`{{BaseURL}}`, a payload list's `{{paths}}`), never a function call (`{{base64(…)}}`).
PLACEHOLDER = re.compile(r"\{\{[A-Za-z_][A-Za-z0-9_-]*\}\}")
PAYLOAD_MAX = 60  # requests a template's fixed path lists may make: more is guessing (a wordlist), not checking
SAFE_PATH = re.compile(r"[A-Za-z0-9/._~+@:!,-]*")
SAFE_TARGET = re.compile(r"[A-Za-z0-9/._~+@:!,-]*(?:\?[A-Za-z0-9_.~=&/,:+-]*)?")
# A GET that changes something (a CVE's "disconnect" or "reset" endpoint) isn't looking.
STATE = re.compile(r"(?i)(?:reset|delete|remove|disconnect|logout|logoff|unsubscribe|shutdown|reboot|restart|exec|cmd|eval|"
                   r"upload|import|update|install\.php\?|setup\.php\?|action=)")
COMPLETE = ".complete"


class TemplatesError(RuntimeError):
    """The pinned release couldn't be downloaded or didn't match its checksum."""


def _tags(document: dict) -> set[str]:
    raw = (document.get("info") or {}).get("tags") if isinstance(document.get("info"), dict) else None
    items = raw.split(",") if isinstance(raw, str) else raw if isinstance(raw, list) else []
    return {str(item).strip().lower() for item in items if str(item).strip()}


def target_ok(target: str, *, query: bool) -> bool:
    """A request target that only reads: after the placeholders, plain path characters and (with `query`) a plain query
    string; nothing that names a state change."""
    rest = PLACEHOLDER.sub("", target.strip())
    if ATTACK.search(target) or STATE.search(rest):
        return False
    return (SAFE_TARGET if query else SAFE_PATH).fullmatch(rest) is not None


def _http_request_ok(request: Any, *, query: bool) -> bool:
    if not isinstance(request, dict) or REQUEST_KEYS & set(request):
        return False
    paths = request.get("path") or []
    raws = request.get("raw") or []
    if not isinstance(paths, list) or not isinstance(raws, list) or not (paths or raws):
        return False
    if paths and str(request.get("method") or "GET").upper() not in METHODS:
        return False
    targets = [str(item) for item in paths]
    for raw in raws:
        line = RAW_LINE.match(str(raw))
        if line is None or line.group(1) not in METHODS:
            return False
        _, _, rest = str(raw).replace("\r\n", "\n").partition("\n\n")
        if rest.strip():
            return False
        targets.append(line.group(2))
    headers = request.get("headers") or {}
    if not isinstance(headers, dict) or any(ATTACK.search(str(value)) for value in [*headers.values(), *raws]):
        return False
    if not all(target_ok(target, query=query) for target in targets) or not _payloads_ok(request, query=query):
        return False
    return not TIMING.search(json.dumps(request.get("matchers") or [], default=str))


def _payloads_ok(request: dict, *, query: bool) -> bool:
    """Payload lists are allowed only as a short list of fixed paths to look at (`/.env`, `/.env.bak`…) outside the
    CVE folder: no wordlist files, nothing a path couldn't hold, and few requests in all."""
    payloads = request.get("payloads")
    if payloads is None:
        return "attack" not in request
    if not query or not isinstance(payloads, dict) or not payloads:
        return False
    total = 1
    for values in payloads.values():
        if not isinstance(values, list) or not values or not all(isinstance(value, str) for value in values):
            return False  # a string is a wordlist file
        total *= len(values)
        if not all(target_ok("/" + value.lstrip("/"), query=True) for value in values):
            return False
    return total <= PAYLOAD_MAX


def allowed(path: str, document: Any) -> bool:
    """Whether the template at `path` (relative to the release) only looks. See the module's docstring."""
    if not path.endswith(".yaml") or not path.startswith(ROOTS) or not isinstance(document, dict):
        return False
    if not isinstance(document.get("id"), str) or not isinstance(document.get("info"), dict):
        return False
    if FORBIDDEN_KEYS & set(document) or _tags(document) & DENY_TAGS:
        return False
    protocols = PROTOCOLS & set(document)
    if not protocols:
        return False
    for name in ("http", "requests"):
        requests = document.get(name)
        # A CVE template reads fixed paths only: a query string is where its exploits put their payloads.
        query = not path.startswith("http/cves/")
        if requests is not None and (not isinstance(requests, list) or not all(_http_request_ok(item, query=query) for item in requests)):
            return False
    if "ssl" in document and not isinstance(document["ssl"], list):
        return False
    return True


def page_level(document: dict) -> bool:
    """A template that reads only the page it is given (`{{BaseURL}}` alone, GET): run on every crawled URL, where
    nuclei folds all of them into one request per URL."""
    requests = document.get("http") or document.get("requests")
    if "ssl" in document or not isinstance(requests, list) or not requests:
        return False
    return all(isinstance(item, dict) and not item.get("raw") and str(item.get("method") or "GET").upper() == "GET"
               and [str(path).strip() for path in item.get("path") or []] in (["{{BaseURL}}"], ["{{BaseURL}}/"]) for item in requests)


def _download() -> bytes:
    with urlopen(Request(URL, headers={"User-Agent": USER_AGENT}), timeout=120) as response:  # nosemgrep: fixed URL, checked by SHA-256
        data = response.read(ARCHIVE_MAX + 1)
    if len(data) > ARCHIVE_MAX:
        raise TemplatesError("nuclei templates archive too large")
    return data


def extract(data: bytes, destination: Path) -> dict:
    """Writes the allowed templates of the release archive under `destination`, split in `hosts/` (every allowed
    template) and `pages/` (the page-level ones). Returns the counts. Raises TemplatesError on a checksum mismatch."""
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise TemplatesError("nuclei templates archive doesn't match its pinned SHA-256")
    counts = {"read": 0, "hosts": 0, "pages": 0}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            if not member.isfile() or not member.name.startswith(PREFIX) or member.size > TEMPLATE_MAX:
                continue
            relative = member.name[len(PREFIX):]
            parts = PurePosixPath(relative).parts
            if not relative.endswith(".yaml") or not relative.startswith(ROOTS) or any(part in ("", ".", "..") for part in parts):
                continue
            counts["read"] += 1
            handle = archive.extractfile(member)
            if handle is None:
                continue
            text = handle.read()
            try:
                document = yaml.safe_load(text)
            except yaml.YAMLError:
                continue
            if not allowed(relative, document):
                continue
            for folder in ("hosts", *(["pages"] if page_level(document) else [])):
                target = destination / folder / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(text)
                counts[folder] += 1
    return counts


def ensure(cache_dir: Path, *, fetch=_download) -> tuple[Path, dict]:
    """The folder with the filtered templates of the pinned release (downloaded and filtered the first time), and its
    counts. Built aside and renamed into place, so a half-written folder is never used."""
    folder = cache_dir / f"v{RELEASE}"
    marker = folder / COMPLETE
    if marker.is_file():
        try:
            return folder, json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    cache_dir.mkdir(parents=True, exist_ok=True)
    try:
        data = fetch()
    except OSError as exc:
        raise TemplatesError(f"nuclei templates download failed: {exc}") from exc
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=cache_dir))
    try:
        counts = extract(data, staging)
        (staging / COMPLETE).write_text(json.dumps(counts), encoding="utf-8")
        for root, directories, files in os.walk(staging):
            for name in directories:
                os.chmod(os.path.join(root, name), 0o755)
            for name in files:
                os.chmod(os.path.join(root, name), 0o644)
        os.chmod(staging, 0o755)
        if folder.exists():
            shutil.rmtree(folder, ignore_errors=True)
        try:
            staging.rename(folder)
        except OSError:
            if not marker.is_file():  # another worker didn't finish it meanwhile
                raise
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
    return folder, counts
