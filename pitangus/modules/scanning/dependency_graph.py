"""Who brings in each dependency, from the graph Trivy resolves out of the lockfiles.

Trivy runs with `--list-all-pkgs`: every package of a lockfile comes with its `Relationship` (root, workspace, direct,
indirect) and `DependsOn` (the IDs of what it requires). That graph is the same for every ecosystem Trivy reads (npm,
yarn, pnpm, Poetry, uv, pip, Pipenv, Cargo, Go, Composer, NuGet, Gradle, Bundler…), so the fix guide never depends on
parsing each lockfile format ourselves. A lockfile Trivy reads without a graph simply adds nothing.

The graph has no version ranges: where the lockfile keeps them, declared_ranges.py adds the range each parent declares
for the package and the one the project declares for the direct dependency, so the guide can tell whether updating the
package alone can work. The result is stored on each dependency finding as data (`package.introduced_by`,
`package.direct`): the guide turns it into text when the finding is served.
"""

from __future__ import annotations

import re
from collections import deque

from pitangus.modules.intel.version_ranges import allows
from pitangus.shared.model import DependencyPath, Finding, Package

TOP = ("root", "workspace")   # the project itself: whatever it requires is a direct dependency
MAX_ENTRIES = 3
MAX_PARENTS = 200
MAX_VISITED = 50_000
PYTHON = ("pip", "pipenv", "poetry", "uv", "pdm", "python-pkg")


class Graph:
    """One lockfile's packages: name and version by ID, with the IDs that require each one."""

    def __init__(self, ecosystem: str, packages: list[dict]):
        self.ecosystem = ecosystem
        self.nodes: dict[str, dict] = {}
        self.parents: dict[str, list[str]] = {}
        self.by_name: dict[tuple[str, str], list[str]] = {}
        for item in packages:
            identifier, name, version = item.get("ID"), item.get("Name"), item.get("Version")
            if not isinstance(identifier, str) or not isinstance(name, str):
                continue
            self.nodes[identifier] = {"name": name, "version": str(version or ""), "relationship": item.get("Relationship"),
                                      "dev": bool(item.get("Dev"))}
            self.by_name.setdefault((self.key(name), str(version or "")), []).append(identifier)
        for item in packages:
            for child in item.get("DependsOn") or []:
                if child in self.nodes and item.get("ID") in self.nodes and child != item["ID"]:
                    self.parents.setdefault(child, []).append(item["ID"])

    def key(self, name: str) -> str:
        """Names as the ecosystem compares them (Python: case and `-_.` don't matter)."""
        return re.sub(r"[-_.]+", "-", name).casefold() if self.ecosystem in PYTHON else name

    def is_direct(self, identifier: str) -> bool:
        node = self.nodes[identifier]
        return node["relationship"] == "direct" or any(self.nodes[parent]["relationship"] in TOP for parent in self.parents.get(identifier, []))

    def chain(self, start: str) -> list[str] | None:
        """The shortest path from a direct dependency down to `start` (both included)."""
        previous: dict[str, str | None] = {start: None}
        pending = deque([start])
        while pending and len(previous) < MAX_VISITED:
            current = pending.popleft()
            if self.is_direct(current):
                path = [current]
                while (step := previous[path[-1]]) is not None:
                    path.append(step)
                return path
            for parent in self.parents.get(current, []):
                if parent not in previous and self.nodes[parent]["relationship"] not in TOP:
                    previous[parent] = current
                    pending.append(parent)
        return None


def graphs(results: list[dict], relative) -> dict[str, Graph]:
    """{lockfile path: Graph} for the Trivy results that carry a dependency graph."""
    found = {}
    for result in results:
        packages = result.get("Packages") or []
        if result.get("Class") == "lang-pkgs" and any(item.get("DependsOn") for item in packages):
            found[relative(str(result.get("Target") or ""))] = Graph(str(result.get("Type") or "").lower(), packages)
    return found


def introduced_by(graph: Graph, name: str, version: str, limit: int = MAX_ENTRIES) -> tuple[list[DependencyPath], bool | None]:
    """Who requires `name` `version` and the direct dependency above each of them, the shortest chains first; and
    whether the project declares it itself (None when the lockfile doesn't have it)."""
    targets = graph.by_name.get((graph.key(name), version)) or []
    if not targets:
        return [], None
    entries: list[DependencyPath] = []
    seen: set[str] = set()
    for target in targets:
        for parent in graph.parents.get(target, []):
            chain = None if graph.nodes[parent]["relationship"] in TOP or parent in seen else graph.chain(parent)
            if chain is None:
                continue
            seen.add(parent)
            if len(seen) > MAX_PARENTS:
                break
            top, node = graph.nodes[chain[0]], graph.nodes[parent]
            entries.append({"name": node["name"], "version": node["version"], "direct": top["name"], "direct_version": top["version"],
                            "chain": [graph.nodes[item]["name"] for item in chain], **({"direct_dev": True} if top["dev"] else {})})
    entries.sort(key=lambda entry: len(entry["chain"]))
    return entries[:limit], any(graph.is_direct(target) for target in targets)


def _with_ranges(entries: list[DependencyPath], package: Package, ranges) -> None:
    """Adds the declared ranges and puts first the parents whose range rejects the fixed version (then the ones whose
    range is unknown): those decide what has to move first."""
    for entry in entries:
        requires = ranges.of(entry["name"], entry["version"], str(package["name"]))
        declared = ranges.declared(entry["direct"])
        entry.update({**({"requires": requires} if requires else {}), **({"direct_requires": declared} if declared else {})})
    fixed = str(package.get("fixed_version") or "")
    order = {False: 0, None: 1, True: 2}
    entries.sort(key=lambda entry: (order[allows(ranges.syntax, entry.get("requires"), fixed)], len(entry["chain"])))


def annotate(findings: list[Finding], found: dict[str, Graph], ranges=None) -> None:
    """Adds who brings it in (and whether it is direct, when no engine said) to each dependency finding whose lockfile
    Trivy resolved, whichever engine reported it. `ranges`: lockfile path → declared_ranges.Ranges | None."""
    for finding in findings:
        package = finding.get("package") or {}
        path = str(finding.get("path") or "")
        graph = found.get(path)
        if graph is None or finding.get("scanner") != "sca" or not package.get("name") or finding.get("malicious"):
            continue
        entries, direct = introduced_by(graph, str(package["name"]), str(package.get("version") or ""), limit=MAX_PARENTS)
        if entries and direct is False:
            declared = ranges(path) if ranges else None
            if declared is not None:
                _with_ranges(entries, package, declared)
            package["introduced_by"] = entries[:MAX_ENTRIES]
            if len(entries) > MAX_ENTRIES:
                package["introduced_by_more"] = True  # others bring it in too: "updating it alone is enough" can't be said
        if package.get("direct") is None and direct is not None:
            package["direct"] = direct
