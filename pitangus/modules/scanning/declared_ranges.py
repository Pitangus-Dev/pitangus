"""The version ranges a lockfile and its manifest declare, read while the snapshot exists.

The dependency graph Trivy resolves (dependency_graph.py) says who brings a vulnerable package in, in any ecosystem.
It doesn't say with which range: "update starlette" is a no-op when FastAPI 0.110.1 only accepts
`starlette>=0.37.2,<0.38.0`, and the fix guide must say so and name what has to move first. Some lockfiles keep the
range each package declares for what it requires (poetry.lock, package-lock.json, yarn.lock, Gemfile.lock) and the
manifest next to them keeps the project's own ranges (pyproject.toml, package.json, Gemfile.lock's DEPENDENCIES). Where
they don't (Cargo.lock, pnpm-lock.yaml, uv.lock, go.sum…), the range is unknown and the guide says what it can without it.

Never fails a scan: a file it can't read (too big, a symlink, outside the snapshot, malformed) just adds nothing.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path, PurePosixPath

from pitangus.modules.intel.version_ranges import MAX_RANGE, bounded

MAX_BYTES = 30_000_000
MAX_LINE = 2_000  # no lockfile line that names a package and its range is longer; longer ones are skipped unread
PYTHON_NAME = re.compile(r"[-_.]+")
PLATFORM = ("x86", "arm", "aarch", "universal", "java", "mingw", "mswin", "darwin", "x64")


class Ranges:
    """One lockfile's declared ranges: what each `name@version` requires and with which range, and what the project
    declares for its direct dependencies."""

    def __init__(self, syntax: str):
        self.syntax = syntax  # version_ranges.allows syntax: pep440, npm, gem
        self.requires: dict[tuple[str, str], dict[str, str]] = {}
        self.roots: dict[str, str] = {}

    def key(self, name: str) -> str:
        return PYTHON_NAME.sub("-", name).casefold() if self.syntax == "pep440" else name

    def add(self, parent: str, version: str, child: str, requirement) -> None:
        requirement = bounded(requirement)
        if requirement:
            self.requires.setdefault((self.key(parent), version), {})[self.key(child)] = requirement

    def root(self, name: str, requirement) -> None:
        requirement = bounded(requirement)
        if requirement:
            self.roots.setdefault(self.key(name), requirement)

    def of(self, parent: str, version: str, child: str) -> str | None:
        """The range `parent` `version` declares for `child` (None: the lockfile doesn't say)."""
        return (self.requires.get((self.key(parent), version)) or {}).get(self.key(child))

    def declared(self, name: str) -> str | None:
        """The range the project declares for its direct dependency `name`."""
        return self.roots.get(self.key(name))


def _read(path: Path) -> str | None:
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_BYTES:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None


def _poetry_spec(value) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("version") if isinstance(value.get("version"), str) else None
    if isinstance(value, list):  # one entry per marker: only a single shared range is a range
        versions = {item.get("version") for item in value if isinstance(item, dict)}
        return versions.pop() if len(versions) == 1 and isinstance(next(iter(versions)), str) else None
    return None


def _pep508(line) -> tuple[str, str] | None:
    """`fastapi[all]>=0.110,<1; python_version>='3.9'` → ("fastapi", ">=0.110,<1")."""
    match = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)", str(line).split(";", 1)[0].strip())
    if not match or match[3].strip().startswith("@"):
        return None
    return match[1], match[3].strip("() ") or "*"


def _pyproject(ranges: Ranges, path: Path) -> None:
    text = _read(path)
    if text is None:
        return
    data = tomllib.loads(text)
    poetry = (data.get("tool") or {}).get("poetry") or {}
    sections = [poetry.get("dependencies"), poetry.get("dev-dependencies")]
    sections += [(group or {}).get("dependencies") for group in (poetry.get("group") or {}).values() if isinstance(group, dict)]
    for section in sections:
        if isinstance(section, dict):
            for name, value in section.items():
                if name.lower() != "python":
                    ranges.root(name, _poetry_spec(value))
    project = data.get("project") or {}
    lines = list(project.get("dependencies") or [])
    lines += [line for group in (project.get("optional-dependencies") or {}).values() for line in group or []]
    lines += [line for group in (data.get("dependency-groups") or {}).values() for line in group or [] if isinstance(line, str)]
    for line in lines:
        parsed = _pep508(line)
        if parsed:
            ranges.root(*parsed)


def poetry(path: Path) -> Ranges | None:
    text = _read(path)
    if text is None:
        return None
    ranges = Ranges("pep440")
    for item in tomllib.loads(text).get("package") or []:
        if isinstance(item, dict) and item.get("name") and item.get("version"):
            for name, value in (item.get("dependencies") or {}).items():
                ranges.add(str(item["name"]), str(item["version"]), name, _poetry_spec(value))
    _pyproject(ranges, path.with_name("pyproject.toml"))
    return ranges


def _package_json(ranges: Ranges, path: Path) -> None:
    try:
        data = json.loads(_read(path.with_name("package.json")) or "{}")
    except ValueError:
        return
    if isinstance(data, dict):
        for section in ("dependencies", "optionalDependencies", "devDependencies"):
            for name, requirement in (data.get(section) or {}).items():
                ranges.root(name, requirement)


def npm(path: Path) -> Ranges | None:
    text = _read(path)
    if text is None:
        return None
    data = json.loads(text)
    ranges = Ranges("npm")
    packages = data.get("packages") if isinstance(data.get("packages"), dict) else {}
    for location, meta in packages.items():
        if not isinstance(meta, dict) or meta.get("link"):
            continue
        sections = ("dependencies", "optionalDependencies", "peerDependencies")
        if "node_modules/" not in location:  # the project or one of its workspaces
            for section in (*sections, "devDependencies"):
                for name, requirement in (meta.get(section) or {}).items():
                    ranges.root(name, requirement)
            continue
        name, version = str(meta.get("name") or location.rsplit("node_modules/", 1)[1]), str(meta.get("version") or "")
        for section in sections:
            for child, requirement in (meta.get(section) or {}).items():
                ranges.add(name, version, child, requirement)
    if not packages:  # lockfile v1: a nested tree with `requires`
        pending = [data.get("dependencies") or {}]
        while pending and len(ranges.requires) < 50_000:
            for name, meta in pending.pop().items():
                if isinstance(meta, dict):
                    for child, requirement in (meta.get("requires") or {}).items():
                        ranges.add(name, str(meta.get("version") or ""), child, requirement)
                    if isinstance(meta.get("dependencies"), dict):
                        pending.append(meta["dependencies"])
    if not ranges.roots:
        _package_json(ranges, path)
    return ranges


def _descriptor(text: str) -> tuple[str, str] | None:
    text = text.strip().strip('"')
    at = text.find("@", 1)
    return (text[:at], text[at + 1:]) if at > 0 else None


def _npm_spec(spec: str) -> str:
    return spec[4:] if spec.startswith("npm:") else spec


def _pair(line: str, berry: bool) -> tuple[str, str] | None:
    """A yarn.lock `key value` line (berry: `key: value`), the key quoted or not. Parsed by hand: a regex with a lazy
    key backtracks quadratically on a long line."""
    line = line.strip()
    if line.startswith('"'):
        end = line.find('"', 1)
        if end > 1:
            key, rest = line[1:end], line[end + 1:]
            if berry and rest.startswith(":"):
                return key, rest[1:].strip()
            if not berry and rest[:1].isspace():
                return key, rest.strip()
    if berry:
        key, colon, value = line.partition(":")
        return (key, value.strip()) if colon and key else None
    parts = line.split(None, 1)
    return (parts[0], parts[1].strip()) if len(parts) == 2 else None


def yarn(path: Path) -> Ranges | None:
    text = _read(path)
    if text is None:
        return None
    berry = "__metadata:" in text
    ranges = Ranges("npm")
    block: dict | None = None
    blocks: list[dict] = []
    section = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#") or len(line) > MAX_LINE:
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            block = None
            if line.endswith(":"):
                descriptors = [found for found in (_descriptor(item) for item in line.rstrip(":").split(",")) if found]
                block = {"descriptors": descriptors, "version": "", "dependencies": []}
                blocks.append(block)
            section = None
        elif block is None:
            continue
        elif indent == 2:
            section = line.strip().rstrip(":") if line.rstrip().endswith(":") else None
            pair = _pair(line, berry)
            if pair and pair[0] == "version":
                block["version"] = pair[1].strip('"')
        elif indent >= 4 and section in ("dependencies", "optionalDependencies"):
            pair = _pair(line, berry)
            if pair:
                block["dependencies"].append((pair[0], _npm_spec(pair[1].strip('"'))))
    for item in blocks:
        if not item["descriptors"]:
            continue
        name = item["descriptors"][0][0]
        if any(spec.startswith("workspace:") for _, spec in item["descriptors"]):  # berry: the project itself
            for child, spec in item["dependencies"]:
                ranges.root(child, spec)
            continue
        for child, spec in item["dependencies"]:
            ranges.add(name, item["version"], child, spec)
    _package_json(ranges, path)
    return ranges


def bundler(path: Path) -> Ranges | None:
    text = _read(path)
    if text is None:
        return None
    ranges = Ranges("gem")
    spec = re.compile(r"(\s+)([A-Za-z0-9][A-Za-z0-9._-]*)(?: \(([^)]*)\))?!?$")
    section, parent = None, None
    for line in text.splitlines():
        if len(line) > MAX_LINE:
            continue
        if line and not line.startswith(" "):
            section, parent = line.strip(), None
            continue
        match = spec.fullmatch(line)
        if not match:
            continue
        indent, name, detail = len(match[1]), match[2], match[3]
        if section == "DEPENDENCIES" and indent == 2:
            ranges.root(name, detail)
        elif section in ("GEM", "GIT", "PATH") and indent == 4 and detail:
            parent = (name, _gem_version(detail)) if len(detail) <= MAX_RANGE else None
        elif section in ("GEM", "GIT", "PATH") and indent == 6 and parent:
            ranges.add(parent[0], parent[1], name, detail)
    return ranges


def _gem_version(detail: str) -> str:
    """Platform gems carry the platform after the version: nokogiri (1.16.0-x86_64-linux) → 1.16.0."""
    start = len(detail)  # the platform runs to the end in word characters and dashes
    while start and (detail[start - 1].isalnum() or detail[start - 1] in "_-"):
        start -= 1
    index = detail.find("-", start)
    while index != -1 and not detail.startswith(PLATFORM, index + 1):
        index = detail.find("-", index + 1)
    return detail if index == -1 else detail[:index]


READERS = {"poetry.lock": poetry, "package-lock.json": npm, "npm-shrinkwrap.json": npm, "yarn.lock": yarn, "gemfile.lock": bundler}


def reader(root: Path):
    """A function `lockfile path (relative to the snapshot) → Ranges | None`, each file read once."""
    base = root.resolve()
    cache: dict[str, Ranges | None] = {}

    def read(path: str) -> Ranges | None:
        if path not in cache:
            cache[path] = None
            parse = READERS.get(PurePosixPath(path).name.lower())
            try:
                # RuntimeError: a symlink loop; MemoryError: a lockfile under MAX_BYTES that still doesn't fit.
                if parse is not None and base in (base / path).resolve().parents and not (base / path).is_symlink():
                    cache[path] = parse(base / path)
            except (ValueError, KeyError, TypeError, AttributeError, RecursionError, RuntimeError, OSError, MemoryError,
                    tomllib.TOMLDecodeError):
                cache[path] = None
        return cache[path]
    return read
