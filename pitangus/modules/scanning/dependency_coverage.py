"""What a dependency engine didn't examine although its run says nothing about it (engine_contract.coverage):

- a manifest that isn't empty with no lockfile the engine reads beside it (`build.gradle` without `gradle.lockfile`,
  `package.json` with no lock or only `bun.lockb`, `Pipfile` without `Pipfile.lock`…): its project (the manifest and its
  lockfile, shared/coverage_units.py) wasn't resolved, whatever the manifest declares;
- a manifest whose packages were left without a resolved version: Trivy keeps them with an empty version when a parent
  POM or a property doesn't resolve (404, 5xx or no network, still exit 0), OSV-Scanner lists them with an empty one,
  and both leave a requirement without an exact pin out of what they check;
- a file in an encoding the engine doesn't decode (UTF-16 or bytes that aren't UTF-8), which it skips without a word.

Each is unexamined for the dependency scanner, never "examined": nothing it held before is taken as fixed.
"""

from __future__ import annotations

import fnmatch
import json
import re
import tomllib
from collections.abc import Callable, Iterable
from pathlib import Path

from pitangus.shared import coverage_units, encodings
from pitangus.shared.i18n import msg
from pitangus.shared.model import Message

NO_LOCKFILE, EMPTY_LOCKFILE, WORKSPACE, UNVERSIONED, ENCODING = "no_lockfile", "empty_lockfile", "workspace", "unresolved_versions", "encoding"
LISTED = 10  # manifests a step names in one sentence

def encoding(data: bytes) -> str | None:
    """The codec of a file's bytes (shared/encodings.codec)."""
    return encodings.codec(data)


def read(path: Path) -> tuple[str, bool] | None:
    """A file's text, whatever its encoding, and whether the engines can read it (UTF-8); None when it can't be opened."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    codec = encoding(data)
    return data.decode(codec or "utf-8", errors="replace"), codec in ("utf-8", "utf-8-sig")


def readable(path: Path) -> bool:
    found = read(path)
    return found is None or found[1]


# --- Manifests without their lockfile ------------------------------------------------------------------------------

def _json(text: str) -> dict:
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _toml(text: str) -> dict:
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return {}


def _npm_workspace(text: str, member: str) -> bool:
    """Whether a package.json's `workspaces` (a list of globs, or Yarn's {"packages": [...]}) gathers folder `member`."""
    workspaces = _json(text).get("workspaces")
    patterns = workspaces.get("packages") if isinstance(workspaces, dict) else workspaces
    return isinstance(patterns, list) and any(isinstance(pattern, str) and fnmatch.fnmatch(member, pattern.strip("./").rstrip("/") or "*")
                                              for pattern in patterns)


# Ecosystems with workspaces: (the manifest above that gathers members, whether its text gathers folder `member`). Only
# to say why a member's own unit has no lockfile (`WORKSPACE`): it never makes a unit examined.
WORKSPACES: dict[str, tuple[str, Callable[[str, str], bool]]] = {
    "npm": ("package.json", _npm_workspace),
    "python": ("pyproject.toml", lambda text, _: bool(((_toml(text).get("tool") or {}).get("uv") or {}).get("workspace"))),
    "cargo": ("Cargo.toml", lambda text, _: "workspace" in _toml(text)),
    "mix": ("mix.exs", lambda text, _: "apps_path" in text),
}


def _lockfile(path: Path) -> bool:
    """A lockfile that is there: anything but an empty file (an emptied lockfile resolves nothing)."""
    found = read(path)
    return found is not None and (not found[1] or bool(found[0].strip()))


def _gathered(path: Path, root: Path, ecosystem: str, wanted: frozenset[str], locks: dict[Path, set[str]],
              names: dict[Path, set[str]]) -> bool:
    """Whether a lockfile in a folder above, whose manifest gathers this one's folder as a workspace member, resolves it."""
    if ecosystem not in WORKSPACES:
        return False
    workspace_file, gathers = WORKSPACES[ecosystem]
    folder = path.parent
    while folder != root and root in folder.parents:
        folder = folder.parent
        if not locks.get(folder, set()) & wanted:
            continue
        if ecosystem == "npm" and "pnpm-workspace.yaml" in names.get(folder, set()):
            return True
        text = read(folder / workspace_file)
        return text is not None and gathers(text[0], path.parent.relative_to(folder).as_posix())
    return False


def without_lockfile(root: Path, inventoried: Iterable[str] | None = None) -> dict[str, str]:
    """The manifests under `root` whose project (coverage_units) wasn't resolved: unexamined, whatever they declare.
    Whether a manifest declares dependencies, or what its lockfile holds, is never read: a manifest that isn't empty, of
    an ecosystem whose manifests need a lockfile, leaves its project unexamined unless a lockfile of its own beside it
    gave the engine at least one package in this run (`inventoried`: the lockfiles, by relative path, the engine's own
    output listed packages for; without it, any lockfile that isn't empty counts). So an advisory reported in a lockfile
    that was deleted, emptied or replaced by one that lists nothing is never taken as fixed. `NO_LOCKFILE` when there is
    no lockfile, `EMPTY_LOCKFILE` when there is one the engine inventoried nothing from, `WORKSPACE` for a member that a
    workspace's lockfile above resolves (its dependencies were read there)."""
    listed = None if inventoried is None else set(inventoried)
    files = [path for path in root.rglob("*") if path.is_file() and not path.is_symlink()]
    names: dict[Path, set[str]] = {}
    locks: dict[Path, set[str]] = {}      # lockfiles that resolved something
    present: dict[Path, set[str]] = {}    # lockfiles on disk
    for path in files:
        name = path.name.lower()
        names.setdefault(path.parent, set()).add(name)
        if name not in coverage_units.LOCKFILES:
            continue
        present.setdefault(path.parent, set()).add(name)
        if (path.relative_to(root).as_posix() in listed) if listed is not None else _lockfile(path):
            locks.setdefault(path.parent, set()).add(name)
    found: dict[str, str] = {}
    for path in files:
        kind = coverage_units.manifest(path.name)
        if kind is None or locks.get(path.parent, set()) & kind[1]:
            continue
        text = read(path)
        if text is None or (text[1] and not text[0].strip()):
            continue
        reason = EMPTY_LOCKFILE if present.get(path.parent, set()) & kind[1] else NO_LOCKFILE
        found[path.relative_to(root).as_posix()] = WORKSPACE if _gathered(path, root, kind[0], kind[1], locks, names) else reason
    return found


# --- Packages without a resolved version ---------------------------------------------------------------------------

REQUIREMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
PINNED = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\s*(?:\[[^\]]*\])?\s*==\s*[^\s=<>!~,*;]+")


def unpinned_requirements(text: str) -> list[str]:
    """The requirements of a pip requirements file without an exact pin (`name==version`): Trivy leaves them out and
    OSV-Scanner guesses from their range. Options (`-r`, `-e`, `--hash`), URLs and local paths name no registry version."""
    found = []
    for line in re.sub(r"\\\r?\n", " ", text).splitlines():
        line = re.sub(r"(?:^|\s)#.*", "", line).split(";", 1)[0].strip()
        line = re.sub(r"\s--hash[= ]\S+", "", line).strip()
        if not line or line.startswith(("-", ".", "/")) or "@" in line or "://" in line:
            continue
        if not PINNED.fullmatch(line) and (name := REQUIREMENT.match(line)):
            found.append(name.group(0))
    return sorted(set(found))


def requirements_file(name: str) -> bool:
    lowered = name.lower()
    return lowered.endswith(".txt") and "requirements" in lowered


def unversioned(packages: Iterable[tuple[str, str, bool]]) -> list[str]:
    """The packages of one result left without a version (`packages`: name, version, local). A local one (the project
    itself, a workspace, a path) has no registry version to resolve, nor has a link to a package the result also lists
    with its version."""
    entries = list(packages)
    versioned = {name for name, version, _ in entries if version}
    return sorted({name for name, version, local in entries if name and not version and not local and name not in versioned})


def local_name(name: str) -> bool:
    return name.startswith((".", "/"))


def inventoried(listing: dict[str, list[tuple[str, bool]]]) -> set[str]:
    """The files an engine's own output listed at least one package for ({path: [(name, local)]}): the project itself,
    a workspace or a path dependency isn't one."""
    return {path for path, packages in listing.items() if any(name and not local for name, local in packages)}


# --- What an engine inventoried, by folder ------------------------------------------------------------------------

def folders(root: Path, inventoried: Iterable[str]) -> dict[str, list[str]]:
    """What a dependency engine examined in a run, by project folder (shared/coverage_units.dependency_unexamined):
    `inventoried`, the files under `root` it listed at least one package from; `uninventoried`, every folder of `root`
    it listed none from (`.` for the root), each by itself: a folder that isn't there any more must never match one. A
    long list is kept as digests (coverage_units.folder_digest). No file name nor package manager decides anything: a
    folder whose lockfile was deleted, emptied, replaced or written in a format nobody lists is a folder nothing was
    inventoried from."""
    files = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file() and not path.is_symlink())
    listed = sorted(set(inventoried) & set(files))
    present: set[str] = set()
    for path in files:
        parts = path.split("/")[:-1]
        present.add(coverage_units.ROOT)
        present.update("/".join(parts[:end]) for end in range(1, len(parts) + 1))
    direct = {coverage_units.folder_of(path) for path in listed}
    return {"inventoried": listed, **coverage_units.folder_list(sorted(present - direct))}


# --- What the step says ----------------------------------------------------------------------------------------------

def _listed(units: Iterable[str]) -> str:
    ordered = sorted(units)
    return ", ".join(ordered[:LISTED]) + ("…" if len(ordered) > LISTED else "")


def gaps_detail(reasons: dict[str, str], unresolved: dict[str, list[str]]) -> list[Message]:
    """One sentence for each kind of gap among `reasons` ({unit: reason}): the manifests without a lockfile, those with
    packages left without a version (`unresolved`: their names, counted), the files in an encoding the engine skips."""
    def having(code: str) -> list[str]:
        return [unit for unit, why in reasons.items() if why == code]
    sentences: list[Message] = []   # a workspace member's dependencies were read in the workspace's lockfile: no gap to say
    if units := having(NO_LOCKFILE):
        sentences.append(msg("scanning.dependency_coverage.no_lockfile", count=len(units), manifests=_listed(units)))
    if units := having(EMPTY_LOCKFILE):
        sentences.append(msg("scanning.dependency_coverage.empty_lockfile", count=len(units), manifests=_listed(units)))
    if units := having(UNVERSIONED):
        sentences.append(msg("scanning.dependency_coverage.unversioned", count=len(units), manifests=_listed(units),
                             packages=sum(len(unresolved.get(unit) or ()) for unit in units)))
    if units := having(ENCODING):
        sentences.append(msg("scanning.dependency_coverage.encoding", count=len(units), files=_listed(units)))
    return sentences
