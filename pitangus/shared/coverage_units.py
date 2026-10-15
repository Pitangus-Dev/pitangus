"""Coverage units: what a finding's absence is proven over, and what an engine's coverage names.

A finding is proven gone only when every engine that saw it examined the unit it lives in (findings/registry.py). The
unit is declared with the finding (`units`) and compared with the units an engine's coverage lists as unexamined, never
the finding's path with the coverage's paths:

- a code, secret or configuration finding lives in its file (`app/settings.py`);
- a dependency finding lives in the project folder of the file its engine attributes it to (`project://crates/api` for
  `crates/api/Cargo.lock`), and in that of every other file it was seen in (`package.also_in`). No list of package
  managers decides it: whatever the folder holds, an engine examined it in a run only if it inventoried at least one
  package from a file in it (`dependencies` in the engine's coverage, scanning/dependency_coverage.folders), and a folder
  it inventoried something from proves gone only what came from a file it inventoried there (`dependency_unexamined`).
  A folder no longer in the repository at all holds nothing: what came from it is gone;
- a folder listed with its trailing slash (`dist/`) holds every unit under it.

ECOSYSTEMS is metadata of the package managers (which manifest each lockfile resolves), for the messages only (`no
lockfile` or `lockfile without packages`): never a condition for what was examined.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from typing import Any

PROJECT_PREFIX = "project://"   # a normalized relative path never holds "//", and a page's URL is http(s)://
ROOT = "."                      # the repository's root folder, as a project's folder
# The units 0.14 declared before (`deps://<ecosystem>/<folder>`): derived again from the finding's paths when read.
LEGACY_PREFIX = "deps://"
DEPENDENCY_PREFIX = PROJECT_PREFIX

# Ecosystem → {manifest name (lowercase) or ".suffix": the lockfiles that resolve it}, for the messages that say why a
# project went unexamined (scanning/dependency_coverage.without_lockfile). Never what decides it: a package manager
# missing here is examined, or not, exactly like the ones listed.
NPM_LOCKS = frozenset({"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"})
ECOSYSTEMS: dict[str, dict[str, frozenset[str]]] = {
    "npm": {"package.json": NPM_LOCKS},
    "pipenv": {"pipfile": frozenset({"pipfile.lock"})},
    "python": {"pyproject.toml": frozenset({"poetry.lock", "uv.lock", "pdm.lock"})},
    "composer": {"composer.json": frozenset({"composer.lock"})},
    "cargo": {"cargo.toml": frozenset({"cargo.lock"})},
    "gradle": {"build.gradle": frozenset({"gradle.lockfile"}), "build.gradle.kts": frozenset({"gradle.lockfile"})},
    "bundler": {"gemfile": frozenset({"gemfile.lock"}), "gems.rb": frozenset({"gems.locked"})},
    "nuget": {suffix: frozenset({"packages.lock.json"}) for suffix in (".csproj", ".fsproj", ".vbproj")},
    "swift": {"package.swift": frozenset({"package.resolved"})},
    "mix": {"mix.exs": frozenset({"mix.lock"})},
    "pub": {"pubspec.yaml": frozenset({"pubspec.lock"})},
    "cocoapods": {"podfile": frozenset({"podfile.lock"})},
}
LOCKFILES = frozenset(lock for manifests in ECOSYSTEMS.values() for locks in manifests.values() for lock in locks)
# Files of a project no engine reads that still belong to it (Bun's binary lockfile).
MEMBERS: dict[str, frozenset[str]] = {"npm": frozenset({"bun.lockb"})}


def _suffix(name: str) -> str:
    return name[name.rfind("."):] if "." in name else ""


def manifest(name: str) -> tuple[str, frozenset[str]] | None:
    """(ecosystem, the lockfiles that resolve it) when a file by this name is a manifest that needs a lockfile."""
    lowered = name.lower()
    for ecosystem, manifests in ECOSYSTEMS.items():
        if lowered in manifests:
            return ecosystem, manifests[lowered]
        if (suffix := _suffix(lowered)) and suffix in manifests:
            return ecosystem, manifests[suffix]
    return None


def ecosystem(name: str) -> str | None:
    """The ecosystem whose project a file by this name belongs to (its manifest, a lockfile of it), or None."""
    lowered = name.lower()
    if found := manifest(lowered):
        return found[0]
    for key, manifests in ECOSYSTEMS.items():
        if any(lowered in locks for locks in manifests.values()) or lowered in MEMBERS.get(key, ()):
            return key
    return None


def normal(path: str) -> str:
    path = str(path or "").strip().replace("\\", "/")
    if "://" in path:
        return path
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


def folder_of(path: str) -> str:
    """The folder a file is in, `ROOT` for the repository's root."""
    folder = normal(path).rpartition("/")[0]
    return folder or ROOT


def unit(path: str, scanner: str = "") -> str:
    """The unit `path` stands for to a scanner: a dependency scanner's project folder (`project://<folder>`) for a
    file, else the file, folder or page itself."""
    path = normal(path)
    if scanner != "sca" or "://" in path or path.endswith("/"):
        return path
    return f"{PROJECT_PREFIX}{folder_of(path)}"


def location(value: str) -> tuple[str, bool]:
    """(where a unit is, whether that is a folder): a project's folder, a file's path."""
    if value.startswith(PROJECT_PREFIX):
        return value[len(PROJECT_PREFIX):], True
    return value, False


def sources(finding: Mapping[str, Any]) -> list[str]:
    """Every file `finding` was seen in: its path, the other places it was seen and, for a dependency, each other file."""
    paths = [str(finding.get("path") or "")]
    paths += [str(item.get("path")) for key in ("instances", "also_at") for item in finding.get(key) or []
              if isinstance(item, dict) and item.get("path")]
    if str(finding.get("scanner") or "") == "sca":
        paths += [str(item) for item in ((finding.get("package") or {}).get("also_in") or []) if isinstance(item, str)]
    return [normal(path) for path in paths if path]


def of_finding(finding: Mapping[str, Any]) -> list[str]:
    """Every unit `finding` lives in: the ones it declares and the ones its paths stand for (its path, the other places
    it was seen and, for a dependency, each other file). A declared unit never replaces one its paths give: both count.
    One in the form 0.14 declared before (`deps://`) is derived again from the paths."""
    scanner = str(finding.get("scanner") or "")
    declared = finding.get("units")
    found = {unit(path, scanner) for path in sources(finding)}
    found |= {str(item) for item in (declared if isinstance(declared, list) else [])
              if isinstance(item, str) and item and not item.startswith(LEGACY_PREFIX)}
    return sorted(found)


def declare(finding: dict) -> dict:
    """`finding` with its units declared (`units`), for the run and the registry to store."""
    finding["units"] = of_finding(finding)
    return finding


def inside(value: str, entries: Iterable[str] | Mapping[str, Any], scanner: str = "") -> bool:
    """Whether the unit `value` is among the units `entries` (paths an engine's coverage lists, as that scanner reads
    them) stand for: one of them, or under a folder among them (`dist/`). A page is only ever itself."""
    raw = [str(entry) for entry in entries]
    listed = {normal(entry) for entry in raw}
    if not listed:
        return False
    whole = f"{ROOT}/" in raw   # the whole repository (a tree its provider didn't list)
    if value in listed or normal(value) in listed or value in {unit(entry, scanner) for entry in listed}:
        return True
    place, folder = location(value)
    if "://" in normal(place):
        return False
    if whole:
        return True
    listed |= set(raw)
    # As written and as normalized (a backslash is a separator to `normal`, a character to git): either form counts.
    for form in {place, normal(place)}:
        for parts in (form.split("/"), [part for part in form.split("/") if part]):
            if any("/".join(parts[:end]) + "/" in listed for end in range(1, len(parts) + (1 if folder else 0))):
                return True
    return False


FOLDERS_LISTED = 2_000   # folders an engine's inventory names by path; beyond it, by digest


def folder_digest(folder: str) -> str:
    """A folder's short digest: two folders that share one are both taken as uninventoried, never as examined."""
    return hashlib.sha256(folder.encode("utf-8", "surrogateescape")).hexdigest()[:12]


def folder_list(folders: list[str]) -> dict[str, list[str]]:
    """`uninventoried` folders as a coverage stores them: by path, or by digest when there are many."""
    if len(folders) <= FOLDERS_LISTED:
        return {"uninventoried": folders}
    return {"uninventoried_digests": sorted({folder_digest(folder) for folder in folders})}


def dependency_unexamined(finding: Mapping[str, Any], spec: Mapping[str, Any] | None) -> bool:
    """Whether an engine's inventory in a run (`spec`: {"inventoried": files it listed packages from, "uninventoried":
    folders of the repository it listed none from}) leaves a dependency finding unproven. For every file the finding
    came from: its folder is in the repository and nothing was inventoried from it, or something was but not from that
    file (deleted, emptied, unreadable, replaced). A folder that isn't in the repository any more proves the finding
    gone. No `spec` (a run before it existed): the coverage's other entries decide."""
    if not isinstance(spec, Mapping):
        return False
    inventoried = {normal(item) for item in spec.get("inventoried") or () if isinstance(item, str)}
    uninventoried = {str(item) for item in spec.get("uninventoried") or () if isinstance(item, str)}
    digests = {str(item) for item in spec.get("uninventoried_digests") or () if isinstance(item, str)}
    folders = {folder_of(item) for item in inventoried}
    for path in sources(finding):
        folder = folder_of(path)
        if folder in uninventoried or (digests and folder_digest(folder) in digests) or (folder in folders and path not in inventoried):
            return True
    return False


def compact(files: Iterable[str], gaps: Mapping[str, str], limit: int, mixed: str = "left_out") -> dict[str, str]:
    """`gaps` ({path: why}, paths among `files`) as few units as says exactly the same (`inside`): a folder all of whose
    files are gaps for the same reason is declared as the folder (`dist/`). Longer than `limit`, coarser, one level of
    folders at a time, up to the top folders and the root files that hold a gap: that leaves more unexamined, never less,
    and nothing is ever dropped. A coarser unit whose files had different reasons takes `mixed`."""
    if not gaps:
        return {}
    totals: dict[str, int] = {}
    reasons: dict[str, dict[str, int]] = {}
    for path in {*files, *gaps}:
        parts = path.split("/")
        for end in range(1, len(parts)):
            folder = "/".join(parts[:end]) + "/"
            totals[folder] = totals.get(folder, 0) + 1
            if path in gaps:
                tally = reasons.setdefault(folder, {})
                tally[gaps[path]] = tally.get(gaps[path], 0) + 1
    whole = {folder: next(iter(tally)) for folder, tally in reasons.items() if len(tally) == 1 and sum(tally.values()) == totals[folder]}
    result: dict[str, str] = {}
    for path, why in gaps.items():
        parts = path.split("/")
        outer = next(("/".join(parts[:end]) + "/" for end in range(1, len(parts)) if "/".join(parts[:end]) + "/" in whole), None)
        if outer is None:
            result[path] = why
        else:
            result[outer] = whole[outer]
    depth = max((unit.rstrip("/").count("/") for unit in result), default=0)
    while len(result) > limit and depth > 0:
        coarse: dict[str, str] = {}
        for unit, why in result.items():
            parts = unit.rstrip("/").split("/")
            key = "/".join(parts[:depth]) + "/" if len(parts) > depth else unit
            coarse[key] = why if coarse.get(key, why) == why else mixed
        result, depth = coarse, depth - 1
    return dict(sorted(result.items()))
