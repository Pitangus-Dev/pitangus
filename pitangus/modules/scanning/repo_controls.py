"""What a scanned repository says about its own results: comments and files that make an engine report less.

An owner can suppress a result in the code (`gitleaks:allow`, `# zizmor: ignore[…]`, `trivy:ignore:…`, `checkov:skip=…`,
a `checkov.io/skip…` annotation, `nosemgrep`) or in a file an engine would load (`.gitleaksignore`, `.betterleaksignore`,
`.github/zizmor.yml`, `.trivyignore`, `.trivyignore.yaml`, `.checkov.yaml`, `osv-scanner.toml`). Pitangus honours them,
and never silently: every result one suppresses is excluded and declared with its rule, its file and line and the
comment or file that suppressed it (never the code), and it is never taken as fixed. With
PITANGUS_IGNORE_REPO_SUPPRESSIONS they suppress nothing.

An engine that doesn't say what it suppressed runs once more without them (on a `view` of the snapshot: the control
files left out, the comments made inert), and what only that run reports is what they suppressed. A file an engine would
load on its own whatever its flags (Checkov's `.checkov.yaml`) never reaches it: Pitangus applies its suppressions itself.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

from pitangus.shared import settings

READ_MAX = 2_000_000        # bytes of a file looked at for comments (the snapshot keeps nothing bigger for the engines)


def ignored() -> bool:
    """Whether the repository's own suppressions suppress nothing (PITANGUS_IGNORE_REPO_SUPPRESSIONS, or its name before
    0.14.1)."""
    return settings.flag("PITANGUS_IGNORE_REPO_SUPPRESSIONS") or settings.flag("PITANGUS_SECRETS_IGNORE_INLINE_ALLOW")


def files(snapshot: Path, wanted: Callable[[str], bool]) -> Iterator[str]:
    """The snapshot's regular files (relative, POSIX) whose path `wanted` takes; links are never followed."""
    for directory, folders, names in os.walk(snapshot):
        folders[:] = [name for name in folders if name != ".git" and not (Path(directory) / name).is_symlink()]
        relative = Path(directory).relative_to(snapshot)
        for name in names:
            path = (relative / name).as_posix()
            if wanted(path) and not (Path(directory) / name).is_symlink():
                yield path


def marked(snapshot: Path, markers: tuple[bytes, ...], paths: Iterable[str]) -> dict[str, list[int]]:
    """Of `paths`, the files holding one of `markers`, with the lines (1-based) where they do. Only the markers are
    looked for: nothing else of the file is kept."""
    found: dict[str, list[int]] = {}
    for path in paths:
        target = snapshot / path
        try:
            if target.is_symlink() or not target.is_file() or target.stat().st_size > READ_MAX:
                continue
            data = target.read_bytes()
        except OSError:
            continue
        if any(marker in data for marker in markers):
            found[path] = [number for number, line in enumerate(data.split(b"\n"), 1) if any(marker in line for marker in markers)]
    return found


def inert(data: bytes, replacements: dict[bytes, bytes]) -> bytes:
    """`data` with each marker replaced by text of the same length the engine doesn't read: lines and columns stay."""
    for marker, replacement in replacements.items():
        assert len(marker) == len(replacement)
        data = data.replace(marker, replacement)
    return data


@contextmanager
def view(snapshot: Path, *, drop: Iterable[str] = (), rewrite: dict[str, bytes] | None = None) -> Iterator[Path]:
    """A copy of the snapshot (hard links where the filesystem allows, so it costs no space) without the files `drop`
    and with the files of `rewrite` holding new content, next to it so the engine's container can mount it; removed
    when done. The snapshot itself is never written: a rewritten file is unlinked from it first."""
    folder = Path(tempfile.mkdtemp(prefix="controls-", dir=snapshot.parent))
    try:
        copy = folder / snapshot.name

        def link(source: str, target: str) -> None:
            try:
                os.link(source, target)
            except OSError:
                shutil.copy2(source, target)
        shutil.copytree(snapshot, copy, symlinks=True, copy_function=link)
        for path in [*drop, *(rewrite or {})]:
            (copy / path).unlink(missing_ok=True)
        for path, content in (rewrite or {}).items():
            (copy / path).write_bytes(content)
        yield copy
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def split(full: list[dict], honoured: list[dict], key: Callable[[dict], object]) -> tuple[list[dict], list[dict], list[dict]]:
    """(what the run without the repository's suppressions reports that the run with them also does, what only it
    reports: the suppressed ones, what only the run with them reports: a configuration that asked for more). Matched by
    `key` (where each result is), never by fingerprint: a result's order among identical ones may differ between runs."""
    present: dict[object, int] = {}
    for item in honoured:
        present[key(item)] = present.get(key(item), 0) + 1
    kept, suppressed = [], []
    for item in full:
        if present.get(key(item), 0) > 0:
            present[key(item)] -= 1
            kept.append(item)
        else:
            suppressed.append(item)
    keys = {key(item) for item in full}
    return kept, suppressed, [item for item in honoured if key(item) not in keys]
