"""One dependency advisory, one finding: even when several engines detect it and each names it differently.

Trivy usually identifies an advisory by its CVE; OSV-Scanner by its GHSA or PYSEC, with the CVE as an
alias. And each writes the ecosystem its own way (`pip`, `poetry`, `PyPI`…). This normalizes all of
that to recognize the same advisory on the same package and the same version.
"""

from __future__ import annotations

from collections.abc import Callable, Hashable
from urllib.parse import quote

from pitangus.modules.intel.packages import FAMILY, canonical_id, dependency_fingerprint, family, normalized_version, package_name  # noqa: F401  (re-exported)
from pitangus.modules.scanning.folding import absorbed


# Package family → purl type (https://github.com/package-url/purl-spec).
PURL_TYPE = {"npm": "npm", "pypi": "pypi", "go": "golang", "cargo": "cargo", "composer": "composer",
             "rubygems": "gem", "maven": "maven", "nuget": "nuget", "pub": "pub", "hex": "hex"}


def purl(dependency: dict) -> str | None:
    kind = PURL_TYPE.get(family(dependency.get("ecosystem") or ""))
    name, version = str(dependency.get("name") or ""), str(dependency.get("version") or "")
    if not kind or not name or not version:
        return None
    if kind == "maven" and ":" in name:
        group, artifact = name.split(":", 1)
        path = f"{quote(group, safe='')}/{quote(artifact, safe='')}"
    elif kind in ("npm", "composer", "golang") and "/" in name:
        # Scoped npm (@org/name), composer (vendor/name) and Go modules keep their segments.
        path = "/".join(quote(part, safe="") for part in name.split("/"))
    else:
        path = quote(name, safe="")
    return f"pkg:{kind}/{path}@{quote(version, safe='')}"


def identifiers(finding: dict) -> set[str]:
    advisory = finding.get("advisory") or {}
    return {item for item in (finding.get("rule_id"), advisory.get("id"), *(advisory.get("aliases") or []),
                              *(finding.get("cve") or []), *(finding.get("ghsa") or [])) if item}


def stable_fingerprint(identifier: str, aliases: set[str], ecosystem: str, name: str, version: str) -> str:
    return dependency_fingerprint(aliases, identifier, ecosystem, name, version)


def _key(finding: dict) -> tuple[str, str, str]:
    package = finding.get("package") or {}
    ecosystem = package.get("ecosystem") or ""
    return family(ecosystem), package_name(ecosystem, package.get("name") or ""), normalized_version(ecosystem, str(package.get("version") or ""))


def note_location(kept: dict, other: dict) -> None:
    """`other` is the same dependency finding as `kept` in another file (a monorepo's second lockfile): the fingerprint
    doesn't depend on the path, so it stays one finding and lists that file in `package.also_in`."""
    path = other.get("path")
    if kept.get("scanner") != "sca":
        # Anything else with one fingerprint in two places (two resources a config engine gives no address for): one
        # finding, the other place kept among its instances (findings/canonical.py counts them).
        place = {"path": str(path or ""), "line": int(other.get("line") or 0)}
        if (place["path"], place["line"]) != (kept.get("path"), kept.get("line")) and place not in kept.setdefault("also_at", []) \
                and len(kept["also_at"]) < 100:
            kept["also_at"].append(place)
        return
    if not path or path == kept.get("path"):
        return
    also = kept.setdefault("package", {}).setdefault("also_in", [])
    if path not in also:
        also.append(path)
        also.sort()


def unique_by_fingerprint(findings: list[dict]) -> list[dict]:
    """One finding per fingerprint (the registry's invariant), keeping where else it appears and a malicious verdict."""
    kept: dict[str, dict] = {}
    for finding in findings:
        first = kept.setdefault(finding["fingerprint"], finding)
        if first is not finding:
            note_location(first, finding)
            if first.get("scanner") == "sca":
                join_names(first, finding)
                malicious_if_any(first, [(0, finding)])
    return list(kept.values())


def join_names(kept: dict, other: dict) -> None:
    """`other`'s names (CVE, GHSA, its advisory's id and aliases) as `kept`'s too: they are one advisory."""
    names = identifiers(other)
    kept["cve"] = sorted(set(kept.get("cve") or []) | set(other.get("cve") or []))
    kept["ghsa"] = sorted(set(kept.get("ghsa") or []) | set(other.get("ghsa") or []))
    advisory = kept.get("advisory")
    if isinstance(advisory, dict):
        advisory["aliases"] = sorted((set(advisory.get("aliases") or []) | names) - {advisory.get("id")})


def advisory_groups(sources: list[list[dict]], key: Callable[[dict], Hashable] = _key) -> list[list[tuple[int, dict]]]:
    """The findings of every source grouped into one advisory each: the same package version (`key`) and a chain of
    shared identifiers (a PYSEC that aliases a GHSA that aliases a CVE is one advisory, whichever engine named which);
    and when any of them is malicious, every advisory on that package version: the package is removed, not upgraded,
    so they are one finding with all their names.

    Each group lists (source index, finding), the one to keep first: from the earliest source (its fingerprints hold the
    triage already done), then a malicious one, then the lowest fingerprint. Neither the groups nor what is kept depend
    on the order of the findings within a source. Groups come in the order of their kept finding."""
    buckets: dict[Hashable, list[tuple[int, int, dict]]] = {}
    for source, findings in enumerate(sources):
        for position, finding in enumerate(findings):
            buckets.setdefault(key(finding), []).append((source, position, finding))
    groups = [sorted(group, key=lambda member: (member[0], not member[2].get("malicious"), str(member[2].get("fingerprint") or ""),
                                          str(member[2].get("path") or ""), member[1]))
              for members in buckets.values() for group in _components(members)]
    groups.sort(key=lambda group: group[0][:2])
    return [[(source, finding) for source, _, finding in group] for group in groups]


def _components(members: list[tuple[int, int, dict]]) -> list[list[tuple[int, int, dict]]]:
    """The connected components of findings joined by a shared identifier (union-find), or all of them as one when any
    is malicious."""
    parent = list(range(len(members)))

    def root(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    owner: dict[str, int] = {}
    for index, (_, _, finding) in enumerate(members):
        for name in identifiers(finding):
            parent[root(index)] = root(owner.setdefault(name, index))
    if any(finding.get("malicious") for _, _, finding in members):
        for index in range(len(members)):
            parent[root(index)] = root(0)
    joined: dict[int, list[tuple[int, int, dict]]] = {}
    for index, member in enumerate(members):
        joined.setdefault(root(index), []).append(member)
    return list(joined.values())


def merge_dependencies(primary: list[dict], *others: tuple[str, list[dict]]) -> tuple[list[dict], dict]:
    """Merges the dependency advisories of several engines without repeating any (advisory_groups).

    `primary` wins (its fingerprints don't change, and with them the triage and tickets already created).
    Each engine in `others` adds what the previous ones didn't see and, where they match, is recorded
    in `also_detected_by`, fills in identifiers and supplies the fixed version if it was missing.
    """
    tools = [None, *(tool for tool, _ in others)]
    merged, stats = [], {"joined": 0, "new": 0}
    for group in advisory_groups([list(primary), *(findings for _, findings in others)]):
        (source, twin), rest = group[0], group[1:]
        stats["new"] += source > 0
        for index, finding in rest:
            tool = tools[index] or finding.get("tool")
            note_location(twin, finding)
            if tool != twin.get("tool") and tool not in twin.get("also_detected_by", []):
                twin["confidence"] = min(10, int(twin.get("confidence") or 6) + 1)
                stats["joined"] += 1
            absorbed(twin, {**finding, "tool": tool})
            join_names(twin, finding)
            if not twin.get("source") and finding.get("source"):
                twin["source"] = finding["source"]
            package, other = twin.get("package") or {}, finding.get("package") or {}
            if not package.get("fixed_version") and other.get("fixed_version"):
                package["fixed_version"] = other["fixed_version"]
        merged.append(malicious_if_any(twin, group))
    return merged, stats


def malicious_if_any(kept: dict, group: list[tuple[int, dict]]) -> dict:
    """`kept` as a malicious package when any finding of its group says so: removed, never upgraded (no fixed version
    survives the merge)."""
    if any(finding.get("malicious") for _, finding in group):
        from pitangus.modules.intel.advisories import mark_malicious
        mark_malicious(kept)
    return kept
