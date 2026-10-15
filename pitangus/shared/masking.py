"""No value leaves a finding or a run: what each of their texts is, and how it is rendered (shared/render.py).

A run and its findings are walked key by key, and each text goes through the one renderer as what it is:

* **Code** (a finding's `snippet`, a web finding's `evidence` and `attack`, a message parameter that carries code):
  `render.code`, its structure and its common words, never a value.
* **Free text an engine wrote** (a message, a step's detail, a progress line, a limitation, an error's cause, a reason
  and every parameter of a catalog message that isn't structure), and **every other text, whatever its key**:
  `render.prose`.
* **Structure** (`STRUCTURAL`: identifiers, locations, digests, counts, what the registry reads) keeps its value, but
  a URL among it is rendered like a URL in any text (`mask_url`, render.url): its common words kept, its user
  information, query and fragment values and every other word replaced. What a web finding's identity and coverage read
  of a URL is pinned first (shared/web_keys.py): its key, its instances' keys and its identity; and a web scan's, the
  keys of the pages it reached and of the units its engines declared.
* **Rule texts** (`RULE_TEXT`: a title, a remediation, a rule's description, what public feeds publish) are what a rule
  catalog says, never what a result matched, and are kept: an adapter that would put a result's text there renders it
  first (scanning/engines.py). An imported SARIF's are a third-party tool's and are rendered as free text
  (scanning/sarif_import.py).

The values a secret engine detected (read from the snapshot where it pointed, never stored) are also replaced
wherever they appear, in any of their encodings. A secret, or a weakness whose code is a credential
(`NO_SNIPPET_CWES`), keeps no snippet at all.

A finding's identity is read from its code before its code is rendered: when the snippet changes, the identity the
original had (shared/code_identity.py) and its identity anywhere in the repository (the PR gate's) are pinned on it.
"""

from __future__ import annotations

import base64
import html
import json
import re
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import quote, quote_plus

from pitangus.shared import coverage_units, render, web_keys
from pitangus.shared.code_identity import anywhere_identity, content_identity
from pitangus.shared.render import plain_share as _plain_share, random_looking, token_shaped  # noqa: F401 - shared helpers

MASK = render.PLACEHOLDER
VALUE_MIN = 4          # characters of a detected value worth replacing (shorter ones would replace ordinary text)
GLOBAL_MIN = 12        # a detected value this long is replaced in every finding of the run, not only in its own file
B64_CORE_MIN = 8       # characters of a base64 rendering of a value that are worth searching
SHORT_HEX = re.compile(r"[0-9a-fA-F]{16,}")


def plain(text: str) -> bool:
    """Whether `text` reads as words, an identifier or a path (`request.args.get`), not as a value someone chose."""
    if SHORT_HEX.fullmatch(text) and any(ch.isdigit() for ch in text) and any(ch.isalpha() for ch in text):
        return False
    return _plain_share(text) >= 0.8 and not any(not ch.isalnum() and ch not in "._-/" for ch in text)


def _b64_cores(raw: bytes) -> set[str]:
    """The base64 characters that only `raw` decides, whatever bytes precede it (three alignments, both alphabets)."""
    found: set[str] = set()
    for pad in range(3):
        total = pad + len(raw)
        encoded = base64.b64encode(b"\0" * pad + raw).decode()
        core = encoded[-(-8 * pad // 6):(8 * total) // 6]
        if len(core) >= B64_CORE_MIN:
            found.update((core, core.replace("+", "-").replace("/", "_")))
    return found


def _b32_cores(raw: bytes) -> set[str]:
    found: set[str] = set()
    for pad in range(5):
        total = pad + len(raw)
        encoded = base64.b32encode(b"\0" * pad + raw).decode()
        core = encoded[-(-8 * pad // 5):(8 * total) // 5]
        if len(core) >= B64_CORE_MIN:
            found.update((core, core.lower()))
    return found


def variants(value: str) -> frozenset[str]:
    """`value` and the ways it is written encoded."""
    value = str(value or "")
    if len(value) < VALUE_MIN:
        return frozenset()
    raw = value.encode("utf-8", "surrogateescape")
    encoded = {quote(value, safe=""), quote(value), quote_plus(value)}
    escaped = "".join(f"\\u{ord(character):04x}" if ord(character) < 0x10000 else character for character in value)
    found = {value, raw.hex(), raw.hex().upper(), json.dumps(value)[1:-1], html.escape(value), value.replace("/", "\\/"),
             escaped, re.sub(r"\\u[0-9a-f]{4}", lambda match: "\\u" + match.group(0)[2:].upper(), escaped),
             "".join(f"\\x{byte:02x}" for byte in raw),
             *encoded, *(re.sub(r"%[0-9A-F]{2}", lambda match: match.group(0).lower(), item) for item in encoded)}
    found |= _b64_cores(raw) | _b32_cores(raw)
    return frozenset(item for item in found if len(item) >= VALUE_MIN)


def _expanded(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({variant for value in values for variant in variants(value)}, key=len, reverse=True))


def _replaced(text: str, wanted: tuple[str, ...]) -> str:
    """`text` with each of `wanted` (detected values, longest first) replaced."""
    for value in wanted:
        if value in text:
            text = text.replace(value, MASK)
    return text


def mask_url(url: str) -> str:
    """A URL as it may be stored and shown (render.url): idempotent; anything that isn't a URL unchanged. A
    dependency project's unit (`project://<folder>`, shared/coverage_units) isn't a URL: it is a repository folder, kept
    like a finding's `path`, so the registry compares the unit the scan declared."""
    if isinstance(url, str) and url.startswith(coverage_units.PROJECT_PREFIX):
        return url
    return render.url(url)


def url_credentials(url: str) -> list[str]:
    """The values `url` carries that are shaped like a token (its password, a token in its path, query, fragment or
    matrix parameters), as written and decoded: replaced where a web scanner repeats them bare (its evidence), before
    the finding's identity reads them. Every other value a URL carries is replaced when it is rendered."""
    if not isinstance(url, str) or not render.URL_START.match(url):
        return []
    from urllib.parse import unquote, urlsplit
    try:
        parts = urlsplit(url)
    except ValueError:
        return []
    candidates = [parts.password or ""]
    for segment in parts.path.split("/"):
        name, *matrix = segment.split(";")
        candidates += [name, *(item.partition("=")[2] or item for item in matrix)]
    for part in (parts.query, parts.fragment):
        candidates += [piece.partition("=")[2] or piece for piece in re.split(r"[&;]", part)]
    found = {form for item in candidates if item and (item == parts.password or token_shaped(item))
             for form in (item, unquote(item), unquote(item.replace("+", " ")))}
    return sorted(item for item in found if len(item) >= VALUE_MIN)


def mask(text: str, values: Iterable[str] = ()) -> str:
    """A text nobody can say more about (an engine's error, a command's output): detected `values` replaced, then
    rendered as free text (render.prose)."""
    if not isinstance(text, str) or not text:
        return text
    return render.prose(_replaced(text, _expanded(values)))


def mask_code(text: str, values: Iterable[str] = ()) -> str:
    """Code or configuration: detected `values` replaced, then rendered as code (render.code)."""
    if not isinstance(text, str) or not text:
        return text
    return render.code(_replaced(text, _expanded(values)))


# Weaknesses whose fragment is a credential in itself: hard-coded passwords and keys, credentials in a readable place.
CREDENTIAL_CWES = frozenset({259, 321, 522, 798, 200})
# A finding about one of these keeps no snippet at all: its code is the credential (hard-coded password, hard-coded
# key, credentials stored unprotected), whichever way it is written.
NO_SNIPPET_CWES = frozenset({259, 321, 522, 798})


def keeps_no_snippet(finding: Mapping[str, Any]) -> bool:
    """A secret, or a weakness whose code is a credential (`NO_SNIPPET_CWES`): no snippet is stored or shown."""
    cwes = finding.get("cwe")
    return finding.get("scanner") == "secrets" or (isinstance(cwes, list) and bool(NO_SNIPPET_CWES & {item for item in cwes if isinstance(item, int)}))


# What in a finding is an identifier, a location or a count, never text that held code: kept, but a URL among it
# rendered (`mask_url`).
STRUCTURAL = frozenset({"finding_id", "fingerprint", "web_key", "previous_fingerprint", "previous_fingerprints", "value_formers", "family", "identity",
                        "identity_version", "anywhere", "scanner", "tool", "rule_id", "path", "units", "line", "end_line", "span",
                        "severity", "confidence", "verdict", "cwe", "owasp", "cve", "ghsa", "count", "instances", "also_at",
                        "also_detected_by", "related_rules", "malicious", "excluded_by", "validation", "resource", "kev",
                        "epss", "$t", "action", "framework", "method", "parameter", "wasc", "coverage", "detected_at",
                        "excluded_reason", "vendored", "layer", "image", "rule_digest"})
# What a rule catalog or a public feed says (not what a result matched): only detected values replaced.
RULE_TEXT = frozenset({"title", "remediation", "package", "advisory", "guidance", "references", "description", "solution"})
PUBLIC = RULE_TEXT
# Code, wherever it sits in a finding (`web.evidence`: what a response held; `web.attack`: what was sent).
CODE = frozenset({"snippet", "evidence", "attack"})
# What in a run is an identifier, a time, a digest or what the registry reads to judge fixes (the engines and rules that
# ran, the units each examined): kept except for its URLs. Everything else, at any depth (steps, progress,
# limitations, details, causes, summaries, deliveries), is text and is rendered, whatever its key.
RECORD_STRUCTURAL = STRUCTURAL | frozenset({
    "id", "schema_version", "type", "status", "created_at", "started_at", "finished_at", "scanned_at", "updated_at", "at",
    "level", "source", "target", "variant", "trigger", "configuration", "coverage", "unexamined", "dependencies", "inventory",
    "unused_dependencies", "owasp_coverage", "identity_shadow", "pull_request", "requested_by", "image", "commit", "sha256",
    "duration_s", "asset", "batch", "context", "version", "name", "rules", "screened", "withheld", "counts", "files",
    "severities", "priorities", "candidates", "blind", "ecosystem", "languages", "hosts", "urls", "pages", "scope",
    "baseline_run", "wildcards", "test_users", "keys"})
# Parameters of a catalog message that are structure (a count, an engine, a path…): kept, URLs rendered. Any other
# parameter (a detail, a reason, a cause, an engine's message) is rendered as text; one that carries code, as code.
PARAMETERS = frozenset({
    "count", "max", "min", "engine", "engines", "version", "versions", "host", "hosts", "tool", "tools", "name", "names",
    "package", "packages", "path", "paths", "id", "limit", "url", "files", "file", "minutes", "seconds", "months", "rule",
    "rules", "product", "products", "severity", "check", "checks", "status", "fixed", "table", "date", "scope", "step",
    "advisories", "root", "branch", "allowed", "used", "line", "counts", "account", "number", "installed", "alias",
    "languages", "target", "index", "failures", "commit", "asset", "sha", "repository", "start", "end", "method",
    "section", "audited", "new", "schema", "operations", "registry", "user", "problems", "available", "run", "zone", "mb",
    "ref", "base", "reference", "minimum", "probability", "percentile", "score", "stage", "osv", "osv_version",
    "workflows", "template", "release", "findings", "gid", "setting", "rulesets", "category", "dev", "framework",
    "folders", "candidates", "advisory", "total", "both", "only_trivy", "only_grype", "trivy", "grype", "checkov", "cve",
    "project", "type", "label", "variable", "kind", "issue", "direct", "artifact", "address", "provider", "gate",
    "critical", "image", "field", "code", "command", "title", "affected", "results", "skipped", "joined",
    "resource", "location", "locale", "where", "description", "places", "manifests"})
CODE_PARAMETERS = frozenset({"snippet", "evidence", "statement"})


def _urls_masked(value: Any, wanted: tuple[str, ...] = ()) -> Any:
    """`value` as it is, but every URL in it (at any depth) through `mask_url` and detected values replaced."""
    if isinstance(value, str):
        return mask_url(_replaced(value, wanted)) if wanted else mask_url(value)
    if isinstance(value, list):
        return [_urls_masked(item, wanted) for item in value]
    if isinstance(value, dict):   # a URL can be a key too (an engine's unexamined units: {URL: reason})
        return {_urls_masked(key, wanted) if isinstance(key, str) else key: _urls_masked(item, wanted) for key, item in value.items()}
    return value


def _values_replaced(value: Any, wanted: tuple[str, ...]) -> Any:
    if not wanted:
        return value
    if isinstance(value, str):
        return _replaced(value, wanted)
    if isinstance(value, list):
        return [_values_replaced(item, wanted) for item in value]
    if isinstance(value, dict):
        return {key: _values_replaced(item, wanted) for key, item in value.items()}
    return value


def mask_strings(value: Any, values: Iterable[str] = (), *, skip: frozenset[str] = frozenset()) -> Any:
    """Every string inside `value` (at any depth) with the detected `values` replaced; keys in `skip` keep their value
    except for what their URLs carry."""
    wanted = _expanded(values)

    def walk(item: Any) -> Any:
        if isinstance(item, str):
            return _replaced(item, wanted)
        if isinstance(item, list):
            return [walk(entry) for entry in item]
        if isinstance(item, dict):
            return {key: _urls_masked(entry) if key in skip else walk(entry) for key, entry in item.items()}
        return item
    return walk(value)


def _message(value: Mapping[str, Any], wanted: tuple[str, ...]) -> dict:
    """A catalog message: its key kept, each parameter as what it is (`PARAMETERS`, `CODE_PARAMETERS`, else text)."""
    params = value.get("params")
    rendered: dict = {key: item for key, item in value.items() if key != "params"}
    if isinstance(params, dict):
        rendered["params"] = {key: _urls_masked(item, wanted) if key in PARAMETERS and not isinstance(item, dict)
                              else render.code(_replaced(item, wanted)) if key in CODE_PARAMETERS and isinstance(item, str)
                              else _text(item, wanted, frozenset()) for key, item in params.items()}
    elif params is not None:
        rendered["params"] = params
    return rendered


def _text(value: Any, wanted: tuple[str, ...], structural: frozenset[str]) -> Any:
    """Text of unknown origin, at any depth: rendered as free text; catalog messages by parameter; keys in
    `structural` kept (URLs rendered); a finding wherever it sits sanitized as one."""
    if isinstance(value, str):
        return render.prose(_replaced(value, wanted))
    if isinstance(value, list):
        return [_text(item, wanted, structural) for item in value]
    if isinstance(value, dict):
        if "$t" in value:
            return _message(value, wanted)
        if "$l" in value:   # a rule's own text in its languages
            return _values_replaced(value, wanted)
        if _finding_shaped(value):
            return sanitize_finding(value, wanted, expanded=True)
        return {key: _urls_masked(item, wanted) if key in structural
                else render.code(_replaced(item, wanted)) if key in CODE and isinstance(item, str)
                else _text(item, wanted, structural) for key, item in value.items()}
    return value


def _imported(finding: Mapping[str, Any]) -> bool:
    """A finding read from an imported SARIF (scanning/sarif_import.py): its rule texts are a third-party tool's, which
    may retell what a result matched."""
    reason = finding.get("reason")
    return isinstance(reason, dict) and reason.get("$t") == "scanning.sarif.reason"


def _finding_shaped(value: Any) -> bool:
    return isinstance(value, dict) and "fingerprint" in value and "scanner" in value


def sanitize_finding(finding: Mapping[str, Any], values: Iterable[str] = (), *, expanded: bool = False, **_: Any) -> dict:
    """`finding` as it may be stored and shown: its code rendered as code, its other texts as text, its structure and
    rule texts kept (URLs rendered), the detected `values` replaced everywhere; a secret or a credential weakness keeps
    no snippet (`keeps_no_snippet`). When its snippet changes, its identity and its identity anywhere in the repository
    are pinned first, computed from the code as it was; its fingerprint is never touched."""
    wanted = tuple(values) if expanded else _expanded(values)
    if finding.get("scanner") == "dast":
        finding = web_keys.pinned(finding)
    imported = _imported(finding)
    result: dict = {}
    for key, item in finding.items():
        if key in STRUCTURAL:
            result[key] = _urls_masked(item, wanted)
        elif key in RULE_TEXT and imported and key in ("title", "description", "solution") and isinstance(item, str):
            result[key] = render.prose(_replaced(item, wanted))
        elif key in RULE_TEXT:
            result[key] = _values_replaced(item, wanted)
        elif key in CODE and isinstance(item, str):
            result[key] = render.code(_replaced(item, wanted))
        elif key == "web" and isinstance(item, dict):
            result[key] = {name: render.code(_replaced(entry, wanted)) if name in CODE and isinstance(entry, str)
                           else render.prose(_replaced(entry, wanted)) if imported and name in ("description", "solution") and isinstance(entry, str)
                           else _values_replaced(entry, wanted) if name in RULE_TEXT
                           else _urls_masked(entry, wanted) if name in STRUCTURAL
                           else _text(entry, wanted, STRUCTURAL) for name, entry in item.items()}
        else:
            result[key] = _text(item, wanted, STRUCTURAL)
    if "snippet" in result and keeps_no_snippet(finding):
        del result["snippet"]
    if result.get("snippet") != finding.get("snippet"):
        if not finding.get("identity") and (pinned := content_identity(finding)) is not None:
            result["identity"] = pinned
        if "anywhere" not in finding:
            result["anywhere"] = anywhere_identity(finding)
    reason = result.get("reason")
    if isinstance(reason, dict) and reason.get("$t") == "scanning.opengrep.reason" and "snippet" in (reason.get("params") or {}):
        result["reason"] = {**reason, "params": {key: item for key, item in reason["params"].items() if key != "snippet"}}
    return result


def _everywhere(values: Mapping[str, Iterable[str]]) -> set[str]:
    """The detected values long and random enough to replace in every text, not only in their own file's findings."""
    return {value for items in values.values() for value in items if len(value) >= GLOBAL_MIN and not plain(value)}


def sanitize_findings(findings: Iterable[Mapping[str, Any]], values: Mapping[str, Iterable[str]] | None = None, **_: Any) -> list[dict]:
    """Each finding sanitized against the values detected in its own file and the long ones detected anywhere
    (`values`: {path: values})."""
    values = values or {}
    everywhere = _everywhere(values)
    return [sanitize_finding(finding, {*everywhere, *values.get(str(finding.get("path") or ""), ())}) for finding in findings]


def sanitize_record(record: Mapping[str, Any], values: Mapping[str, Iterable[str]] | None = None, **_: Any) -> dict:
    """A run as it may be stored and shown: its findings and excluded findings sanitized (`values`: {path: values}
    detected), every other text at any depth (steps, progress, limitations, details, causes, summaries) rendered as
    text whatever its key; identifiers, times, digests and what the registry reads (`RECORD_STRUCTURAL`) keep their
    value, except what a URL carries."""
    values = values or {}
    wanted = _expanded(_everywhere(values))
    if record.get("type") == "dast_scan" and not isinstance(record.get("keys"), dict):
        record = {**record, "keys": web_keys.of_record(record)}
    result: dict = {}
    for key, item in record.items():
        if key in ("findings", "excluded_findings") and isinstance(item, list):
            result[key] = sanitize_findings([entry for entry in item if isinstance(entry, dict)], values)
        elif key in RECORD_STRUCTURAL:
            result[key] = _urls_masked(item, wanted)
        else:
            result[key] = _text(item, wanted, RECORD_STRUCTURAL)
    return result

