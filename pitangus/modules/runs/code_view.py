"""A finding's code, read when someone opens it: never stored, never cached, never logged.

Pitangus keeps where a finding is (its path, its lines, the commit its run scanned), never its code. Opening it reads
the file from the provider at that commit, with the connection Pitangus already has (the GitHub App or the token), and
returns the lines around it to a signed-in reader, as the provider itself would show them to someone with access.
Every place a secret engine reported in that file is masked first: a value whose columns are known for that commit
(its `span`) is replaced and the rest of its line kept; any other secret's lines are withheld whole, a private key's
block to its end. A secret's own finding, a weakness whose code is a credential, or any finding in a credential file (`.env`,
`id_rsa`…) shows no code at all, only where it is. A local scan's code is on the developer's machine: the server never reads a folder (the CLI does, `--format
prompt`).

Lines and columns are the engines' own: a line ends at "\n" alone and a column counts the characters of its bytes decoded
with `surrogateescape` (scanning/secret_location.py), so masks land on the text read; it becomes display text (invalid
UTF-8 replaced) only after masking. Code is read only at a commit Pitangus scanned: an imported finding's place came
from whoever imported it, so it shows only where it is. A symbolic link, or a file whose secrets are only known at
another commit (their lines may have moved), shows no code either.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from pathlib import Path
from typing import Any, Iterable, Mapping

from pitangus.modules.findings import registry as findings_registry
from pitangus.modules.findings.kinds import IMPORT_RUNS
from pitangus.modules.findings.registry import VIEW_PREFIX
from pitangus.modules.runs.store import load_run
from pitangus.modules.scanning.secret_location import MULTILINE
from pitangus.modules.sources.assets import asset_key
from pitangus.modules.sources.permalinks import code_url
from pitangus.modules.sources.repositories import LinkedPath, credential_path
from pitangus.shared.masking import code_withheld

CONTEXT = 3          # lines shown before and after a finding's own
LINES_MAX = 40       # lines shown at most
SECRET_MASK = "••••••"
CODE_SCANNERS = frozenset({"sast", "iac", "cicd", "secrets"})
PEM_START, PEM_END = "-----BEGIN", "-----END"
PEM_MAX = MULTILINE  # lines a key's block may run: past them, everything from its start on is withheld
COMMIT = re.compile(r"[0-9a-f]{40}")
SCANNED_RUNS = frozenset({"repository_scan", "pr_review"})   # runs whose commit and places Pitangus itself read


class NotFound(LookupError):
    """The run, or the finding in its asset, doesn't exist."""


def _place(finding: Mapping[str, Any]) -> tuple[int, int] | None:
    line = finding.get("line")
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        return None
    end = finding.get("end_line")
    end = end if isinstance(end, int) and not isinstance(end, bool) and end >= line else line
    return line, min(end, line + LINES_MAX)


def secret_places(findings: Iterable[Mapping[str, Any]], path: str, *, certain: bool) -> list[tuple[int, int, tuple[int, int] | None]]:
    """Where secrets are in `path`: (first line, last line, the value's columns when `certain` they apply to the text
    read and it sits on one line). A grouped finding's other places count too."""
    places: list[tuple[int, int, tuple[int, int] | None]] = []
    for finding in findings:
        if not isinstance(finding, Mapping) or not code_withheld(finding):
            continue
        own = (str(finding.get("path") or ""), finding.get("line"))
        spots = [finding, *(item for item in finding.get("instances") or []
                            if isinstance(item, Mapping) and (str(item.get("path") or ""), item.get("line")) != own)]
        for spot in spots:
            if str(spot.get("path") or "") != path or (where := _place(spot)) is None:
                continue
            span = finding.get("span") if spot is finding else None
            if isinstance(span, list) and len(span) == 4 and all(isinstance(item, int) and not isinstance(item, bool) for item in span):
                first, start, last, end = span
                if certain and first == last and 0 <= start < end:
                    places.append((first, first, (start, end)))
                    continue
                if 0 < first <= last:
                    where = (min(first, where[0]), max(last, where[1]))
            places.append((where[0], where[1], None))
    return places


def lines_of(raw: bytes) -> list[str]:
    """A file's lines as its engines count them: ended by "\n" alone, decoded as their columns were counted."""
    parts = raw.split(b"\n")
    if parts[-1] == b"":
        parts.pop()
    return [part.decode("utf-8", "surrogateescape") for part in parts]


def _display(line: str) -> str:
    return line.removesuffix("\r").encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def window(raw: bytes, finding: Mapping[str, Any], secrets: list[tuple[int, int, tuple[int, int] | None]]) -> list[dict]:
    """The lines around `finding` in the file `raw`, every secret place masked (see the module's docstring)."""
    where = _place(finding)
    lines = lines_of(raw)
    if where is None or where[0] > len(lines):
        return []
    first = max(1, where[0] - CONTEXT)
    last = min(len(lines), where[1] + CONTEXT, first + LINES_MAX - 1)
    whole: set[int] = set()
    withheld_from = last + 1      # a key's block with no end within PEM_MAX lines: everything from its start on
    ends: list[int] | None = None
    spans: dict[int, list[tuple[int, int]]] = {}
    for start, end, columns in secrets:
        if columns is not None and start <= len(lines) and columns[1] <= len(lines[start - 1]):
            spans.setdefault(start, []).append(columns)
            continue
        whole.update(range(max(start, first), min(end, last) + 1))
        # A key's block runs to its end whatever line the engine reported.
        if start <= len(lines) and PEM_START in lines[start - 1]:
            if ends is None:
                ends = [number for number, line in enumerate(lines, 1) if PEM_END in line]
            at = bisect_left(ends, start)
            if at < len(ends) and ends[at] - start < PEM_MAX:
                whole.update(range(max(start, first), min(ends[at], last) + 1))
            else:
                withheld_from = min(withheld_from, start)
    shown = []
    for number in range(first, last + 1):
        content = lines[number - 1]
        masked = None
        if number in whole or number >= withheld_from:
            content, masked = "", "line"
        elif number in spans:
            merged: list[list[int]] = []
            for start, end in sorted(spans[number]):   # overlapping values are one masked run
                if merged and start <= merged[-1][1]:
                    merged[-1][1] = max(merged[-1][1], end)
                else:
                    merged.append([start, end])
            for start, end in reversed(merged):
                content = content[:start] + SECRET_MASK + content[end:]
            masked = "span"
        shown.append({"number": number, "text": _display(content), "focus": where[0] <= number <= where[1], **({"masked": masked} if masked else {})})
    return shown


def binary(raw: bytes) -> bool:
    return b"\0" in raw[:8192]


def _unavailable(reason: str, path: str, **extra: Any) -> dict:
    return {"status": "unavailable", "reason": reason, "path": path, "commit": None, "lines": [], "permalink": None, **extra}


def _withheld(reason: str, path: str, commit: str, permalink: str | None) -> dict:
    """Only where it is: the place and the provider's own link, which asks the provider who may read it."""
    return {**_unavailable(reason, path), "status": "withheld", "commit": commit if COMMIT.fullmatch(commit) else None, "permalink": permalink}


def _located(data_dir: Path, run_id: str, key: str, entry: Mapping[str, Any], fingerprint: str) -> tuple[dict | None, dict]:
    """The run the finding's lines belong to (the one asked for when it holds the finding, else the last one that saw
    it) and the finding as that run has it."""
    wanted = [run_id] if not run_id.startswith(VIEW_PREFIX) else []
    for candidate in dict.fromkeys([*wanted, str(entry.get("last_run") or "")]):
        if not candidate:
            continue
        try:
            record: dict[str, Any] = dict(load_run(data_dir, candidate))
        except (ValueError, OSError):
            continue
        if not record.get("source") or asset_key(record) != key:
            continue
        listed = [item for field in ("findings", "excluded_findings") for item in (record.get(field) or [])]
        found = next((item for item in listed if isinstance(item, dict) and item.get("fingerprint") == fingerprint), None)
        if found is not None:
            return record, found
    return None, dict(entry.get("finding") or {})


def view(data_dir: Path, run_id: str, fingerprint: str, reader) -> dict:
    """A finding's code for a signed-in reader. `reader(source, commit, path) -> bytes` reads one file from the
    provider (FileNotFoundError when the commit doesn't hold it, LinkedPath when it is a symbolic link, OSError or
    ValueError when it can't be read)."""
    if run_id.startswith(VIEW_PREFIX):
        key = run_id.removeprefix(VIEW_PREFIX)
    else:
        try:
            key = asset_key(load_run(data_dir, run_id))
        except (ValueError, OSError):
            raise NotFound("run") from None
    entries = findings_registry.load(data_dir, key).get("findings", {})
    entry = entries.get(fingerprint)
    if entry is None or not entry.get("finding"):
        raise NotFound("finding")
    record, finding = _located(data_dir, run_id, key, entry, fingerprint)
    path = str(finding.get("path") or "")
    package = finding.get("package") or {}
    if finding.get("scanner") not in CODE_SCANNERS or package.get("name") or not path:
        return _unavailable("not_code", path)
    source = (record or {}).get("source") or {}
    commit = str(source.get("commit") or "")
    where = _place(finding)
    permalink = code_url(source, path, *(where or (None, None)))
    # A credential file (`.env`, `id_rsa`, `.npmrc`…) is all values, whatever finding points at it (an import can point
    # anywhere): only where it is.
    if code_withheld(finding) or credential_path(tuple(path.split("/"))) is not None:
        return _withheld("secret", path, commit, permalink)
    if record is None or str(source.get("provider") or "") == "local" or str(source.get("id") or "").startswith("local:"):
        return _unavailable("local" if str(source.get("id") or "").startswith("local:") else "no_commit", path)
    # Only a commit Pitangus scanned, at the places its engines reported: an import names any path, line and commit.
    if record.get("type") not in SCANNED_RUNS:
        if record.get("type") in IMPORT_RUNS:
            return _withheld("imported", path, commit, permalink)
        return _unavailable("not_code", path)
    if not COMMIT.fullmatch(commit):
        return _unavailable("no_commit", path)
    if where is None:
        return _unavailable("no_location", path, commit=commit, permalink=permalink)
    same_commit = [*(record.get("findings") or []), *(record.get("excluded_findings") or [])]
    here = {item.get("fingerprint") for item in same_commit if isinstance(item, Mapping)}
    # The registry's other secrets in this file, located at other runs: trusted (their whole lines masked) only when
    # that run read this same commit; otherwise their lines may have moved, so no code.
    others = [item for digest, item in entries.items() if digest not in here and isinstance(item, Mapping)
              and isinstance(item.get("finding"), Mapping) and secret_places([item["finding"]], path, certain=False)]
    commits: dict[str, str | None] = {}
    if any(_commit_of(data_dir, str(item.get("last_run") or ""), commits) != commit for item in others):
        return _withheld("secret_other_commit", path, commit, permalink)
    try:
        raw = reader(source, commit, path)
    except LinkedPath:
        return _withheld("symlink", path, commit, permalink)
    except FileNotFoundError:
        return _unavailable("file_gone", path, commit=commit, permalink=permalink)
    except PermissionError:
        return _unavailable("repository_gone", path, commit=commit, permalink=permalink)
    except (OSError, ValueError):
        return _unavailable("repository_unreachable", path, commit=commit, permalink=permalink)
    if binary(raw):
        return _unavailable("binary", path, commit=commit, permalink=permalink)
    secrets = secret_places(same_commit, path, certain=True) + secret_places([item["finding"] for item in others], path, certain=False) \
        + allowed_places(record, path)
    lines = window(raw, finding, secrets)
    if not lines:
        return _unavailable("file_changed", path, commit=commit, permalink=permalink)
    return {"status": "shown", "reason": None, "path": path, "commit": commit, "lines": lines, "permalink": permalink}


def _commit_of(data_dir: Path, run_id: str, seen: dict[str, str | None]) -> str | None:
    if run_id not in seen:
        seen[run_id] = None
        if run_id:
            try:
                seen[run_id] = str((load_run(data_dir, run_id).get("source") or {}).get("commit") or "") or None
            except (ValueError, OSError):
                pass
    return seen[run_id]


def allowed_places(record: Mapping[str, Any], path: str) -> list[tuple[int, int, tuple[int, int] | None]]:
    """The lines of `path` where a `gitleaks:allow` comment allowed a secret (`suppressed_inline`): masked whole too."""
    places: list[tuple[int, int, tuple[int, int] | None]] = []
    for engine in ("betterleaks", "trivy"):
        for place in ((record.get("coverage") or {}).get(engine) or {}).get("suppressed_inline") or []:
            where, _, line = str(place).rpartition(":")
            if where == path and line.isdigit() and int(line) > 0:
                places.append((int(line), int(line), None))
    return places


def provider_reader(data_dir: Path):
    """Reads a file of a run's repository with the connection Pitangus has now (`view`'s `reader`): PermissionError
    when that repository is no longer reachable with it."""
    from pitangus.modules.integrations import code_tokens
    from pitangus.modules.integrations.installations import github_installations
    from pitangus.modules.sources.repositories import find_source, read_file

    def read(source: Mapping[str, Any], commit: str, path: str) -> bytes:
        tokens = code_tokens.current()
        found = find_source(tokens, github_installations(data_dir), str(source.get("id") or ""))
        if found is None:
            raise PermissionError("repository")
        return read_file(str(found["id"]), commit, path, tokens, found.get("installation_id"))
    return read


def local_lines(root: Path, finding: Mapping[str, Any], findings: Iterable[Mapping[str, Any]], *, certain: bool = False,
                scan: Mapping[str, Any] | None = None) -> list[dict]:
    """The lines around a finding of a local scan, read from the folder now, masked the same way (`certain`: the folder
    is what was scanned, so a value's columns apply); none for a secret, a credential weakness, a file outside the
    folder or one that can't be read."""
    path = str(finding.get("path") or "")
    if code_withheld(finding) or finding.get("scanner") not in CODE_SCANNERS or (finding.get("package") or {}).get("name") \
            or credential_path(tuple(path.split("/"))) is not None:
        return []
    try:
        base = root.resolve()
        target = (base / path).resolve()
        # A link is read where it points: never into a credential file under another name.
        if credential_path(target.relative_to(base).parts) is not None:
            return []
        if not target.is_file() or target.stat().st_size > 1_000_000:
            return []
        raw = target.read_bytes()
    except (OSError, ValueError):
        return []
    if binary(raw):
        return []
    return window(raw, finding, secret_places(findings, path, certain=certain) + allowed_places(scan or {}, path))
