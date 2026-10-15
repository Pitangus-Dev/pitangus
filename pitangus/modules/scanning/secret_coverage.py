"""Which committed files each secret engine read, from its own log, and which it didn't (docs/scanning-code.md, "What
each engine reads").

Pitangus owns each secret engine's exclusion list: Betterleaks runs with a global path prefilter that holds only our
allowlist (secret_rules.betterleaks_toml), Trivy with its built-in allow rules and skip patterns off
(secret_rules.trivy_secret_config). Neither is trusted to have read everything because of that. Each one's log names
the files it read: Betterleaks `scanning path` (at trace level), Trivy `Using streaming scanner` (at debug level). Every
file of the snapshot an engine didn't name, or named as skipped, is unexamined by it, with why. That needs no knowledge
of what the engine skips nor why (a binary, a size, a path list a later version adds): what its log doesn't name as read
wasn't read. A run whose log names nothing read nothing, as far as Pitangus can tell.

The logs carry what the engines matched (Betterleaks traces the value of every candidate it filters out): `keep_*`
drop every line but the listing (reduced to the paths) and the ones the engine prints without being asked (its
errors), as they arrive (engines._filtered), and `read_*` take the listing out of what was kept.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from pathlib import Path

from pitangus.shared import coverage_units, encodings

# A declaration longer than this is coarsened to the top folders (`declared`).
LISTED_MAX = 5_000

# Betterleaks (zerolog's console writer, --no-color): `6:01PM TRC scanning path path=/src/a.js`. A value with spaces,
# quotes or non-ASCII characters is quoted Go-style.
_BETTERLEAKS_RECORD = re.compile(r"^\d{1,2}:\d{2}[AP]M (?P<level>TRC|DBG|INF|WRN|ERR|FTL|PNC) (?P<message>.*)$")
_BETTERLEAKS_PATH = re.compile(r'(?:^|\s)path=(?P<path>"(?:[^"\\]|\\.)*"|\S+)')
# Trivy (its own handler): `2026-10-14T18:04:16Z\tDEBUG\t[secret] Using streaming scanner\tfile_path="a.js"`.
_TRIVY_RECORD = re.compile(r"^\d{4}-\d{2}-\d{2}T\S+\t(?P<level>DEBUG|INFO|WARN|ERROR|FATAL)\t(?P<message>.*)$")
_TRIVY_PATH = re.compile(r'(?:^|\s)file_path=(?P<path>"(?:[^"\\]|\\.)*"|\S+)')
_TRIVY_READ = "[secret] Using streaming scanner"
_CRASH = ("panic:", "fatal error:")
_ALLOWED = "skipping finding: allow signature"   # Betterleaks: a match a `gitleaks:allow` comment allows


def _value(raw: str) -> str | None:
    """A logged value: quoted ones are decoded (a Go escape JSON doesn't know, such as an invalid byte, makes it None:
    then the file was never named, and stays unexamined)."""
    if not raw.startswith('"'):
        return raw
    try:
        value = json.loads(raw)
    except ValueError:
        return None
    return value if isinstance(value, str) else None


class _Keeper:
    """A stateful stderr filter: what to keep of each line (None: nothing). A record is reduced or dropped as a whole,
    its continuation lines (a multi-line value) kept only after a record kept whole. A Go crash is always kept,
    whatever came before it."""

    def __init__(self, record: re.Pattern, reduce: Callable[[str, str, str], str | None]):
        self.record, self.reduce, self.keeping = record, reduce, True

    def __call__(self, line: str) -> str | None:
        if line.startswith(_CRASH):
            self.keeping = True
            return line
        match = self.record.match(line.rstrip("\r\n"))
        if not match:
            return line if self.keeping else None
        kept = self.reduce(line, match.group("level"), match.group("message"))
        self.keeping = kept == line
        return kept


def _betterleaks_listing(level: str, message: str) -> bool:
    """A line about a file read or passed over: `scanning path`, or a `skipping …` that names a path and no finding."""
    if message.startswith("scanning path "):
        return True
    lead, _, _ = message.partition(" path=")
    return message.startswith("skipping ") and " path=" in message and "finding" not in lead


def keep_betterleaks() -> Callable[[str], str | None]:
    """Betterleaks at trace level: only the files it read or skipped, reduced to their path, and what it says at info
    level and above (never the candidates it traces, with their values)."""
    def reduce(line: str, level: str, message: str) -> str | None:
        if level not in ("TRC", "DBG"):
            return line
        if message.startswith(_ALLOWED):
            # A match an inline comment allows: only that it happened, and where (`allowed_inline`), never its value.
            found = _BETTERLEAKS_PATH.search(message)
            return f"0:00AM {level} allow signature path={found.group('path')}\n" if found else None
        if not _betterleaks_listing(level, message):
            return None
        found = _BETTERLEAKS_PATH.search(message)
        if found is None:
            return None
        kind = "scanning path" if message.startswith("scanning path ") else \
            "skipping empty file" if message.startswith("skipping empty file ") else "skipping"
        return f"0:00AM {level} {kind} path={found.group('path')}\n"
    return _Keeper(_BETTERLEAKS_RECORD, reduce)


def _trivy_listing(level: str, message: str) -> bool:
    return (level == "DEBUG" and message.startswith(_TRIVY_READ + "\t")) or (level == "ERROR" and message.startswith("[secret]"))


def keep_trivy() -> Callable[[str], str | None]:
    """Trivy at debug level: only the files its secret scanner read or failed to read, reduced to their path, and what
    `--quiet` would still print (its fatal errors): nothing else of what it logs reaches the adapter, as before."""
    def reduce(line: str, level: str, message: str) -> str | None:
        if level == "FATAL":
            return line
        found = _TRIVY_PATH.search(message) if _trivy_listing(level, message) else None
        if found is None:
            return None
        kind = _TRIVY_READ if level == "DEBUG" else "[secret] failed"
        return f"0000-00-00T00:00:00Z\t{level}\t{kind}\tfile_path={found.group('path')}\n"
    return _Keeper(_TRIVY_RECORD, reduce)


def read_betterleaks(stderr: str, *, root: str = "/src") -> tuple[set[str], str]:
    """(the files Betterleaks read, relative to the snapshot; its stderr without the listing). Read: named by `scanning
    path` and never by a `skipping …` line (a binary, a folder of the allowlist, anything it later says it passed over),
    or named as an empty file it skipped (nothing in it to find)."""
    read: set[str] = set()
    passed: set[str] = set()
    rest: list[str] = []
    for line in (stderr or "").splitlines(keepends=True):
        match = _BETTERLEAKS_RECORD.match(line.rstrip("\r\n"))
        if match and match.group("level") in ("TRC", "DBG") and match.group("message").startswith(("allow signature ", _ALLOWED)):
            continue
        if not match or match.group("level") not in ("TRC", "DBG") or not _betterleaks_listing(match.group("level"), match.group("message")):
            rest.append(line)
            continue
        message = match.group("message")
        found = _BETTERLEAKS_PATH.search(message)
        path = _value(found.group("path")) if found else None
        if path is None or not (path == root or path.startswith(root + "/")):
            continue
        relative = path[len(root) + 1:]
        if message.startswith("scanning path ") or message.startswith("skipping empty file "):
            read.add(relative)
        else:
            passed.add(relative)
    # A skipped folder (`skipping directory`) passes over everything under it.
    folders = tuple(item + "/" for item in passed)
    return {item for item in read if item not in passed and not item.startswith(folders)}, "".join(rest)


def allowed_inline(stderr: str) -> int:
    """How many matches Betterleaks says an inline comment (`gitleaks:allow`, `betterleaks:allow`) allowed."""
    return sum(1 for line in (stderr or "").splitlines() if (match := _BETTERLEAKS_RECORD.match(line))
               and match.group("message").startswith(("allow signature ", _ALLOWED)))


def read_trivy(stderr: str) -> tuple[set[str], str]:
    """(the files Trivy's secret scanner read, relative to the snapshot; its stderr without the listing). Read: named
    by `Using streaming scanner` and not by a `[secret]` error (a read that failed halfway)."""
    read: set[str] = set()
    failed: set[str] = set()
    rest: list[str] = []
    for line in (stderr or "").splitlines(keepends=True):
        match = _TRIVY_RECORD.match(line.rstrip("\r\n"))
        if not match or not _trivy_listing(match.group("level"), match.group("message")):
            rest.append(line)
            continue
        found = _TRIVY_PATH.search(match.group("message"))
        path = _value(found.group("path")) if found else None
        if path is None:
            continue
        path = path.removeprefix("/src/").removeprefix("./")
        (read if match.group("level") == "DEBUG" else failed).add(path)
    return read - failed, "".join(rest)


def committed(root: Path) -> list[str]:
    """Every file of a snapshot (or of the copy only the secret scanners read), relative to it."""
    if not root.is_dir():
        return []
    return sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file() and not path.is_symlink())


def unread(files: Iterable[str], read: set[str], *, allowed: Callable[[str], bool] | None = None) -> dict[str, str]:
    """Every file of `files` the engine didn't read, with why: in a path our own allowlist names (`allowlisted`, a
    setting, reported as such) or passed over by the engine (`skipped_by_engine`), whatever the reason it had."""
    return {path: "allowlisted" if allowed and allowed(path) else "skipped_by_engine" for path in files if path not in read}


def unreadable(root: Path, files: Iterable[str]) -> dict[str, str]:
    """The files among `files` whose bytes an engine that matches bytes can't read as the text they are (not UTF-8, or
    holding zero bytes: shared/encodings), as `encoding` gaps. Its log naming such a file as read says it opened it,
    not that a token written there was where its patterns look: a property of the bytes, whatever the file is called."""
    found: dict[str, str] = {}
    for path in files:
        try:
            data = (root / path).read_bytes()
        except OSError:
            found[path] = "unreadable"
            continue
        if data and not encodings.readable(data):
            found[path] = "encoding"
    return found


def declared(files: Iterable[str], gaps: dict[str, str], limit: int = LISTED_MAX) -> dict[str, str]:
    """`gaps` as few units as says exactly the same (coverage_units.compact): a folder all of whose files are unexamined
    for the same reason is declared as the folder (`dist/`). Longer than `limit`, coarser, which leaves more unexamined,
    never less."""
    return coverage_units.compact(files, gaps, limit, mixed="skipped_by_engine")
