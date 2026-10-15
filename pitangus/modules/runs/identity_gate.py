"""The upgrade gate for the canonical identity (findings/canonical.py): the same commit scanned twice opens nothing and
fixes nothing, keyed by fingerprints (v1) and by identities (v2). `pitangus identity-gate` runs it over the last two
full scans of each repository. PITANGUS_IDENTITY_MODE is v2 by default; a repository scanned twice on one commit that
doesn't give 0/0 is a reason to set it back to shadow until it does.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from pitangus.modules.findings import canonical, registry
from pitangus.modules.findings.identity import formers
from pitangus.modules.runs import store
from pitangus.shared.model import Finding


def _families(findings: list[Finding]) -> dict[str, int]:
    """Each family's count: a run stored in v2 already holds them; an earlier one is grouped here."""
    if findings and all(item.get("identity_version") == canonical.VERSION for item in findings):
        return {item["fingerprint"]: int(item.get("count") or 1) for item in findings}
    return {item["fingerprint"]: int(item["count"]) for item in canonical.collapse(findings)}


def compare(previous: list[Finding], current: list[Finding]) -> dict:
    """What `current` opens and leaves out against `previous`, by fingerprint (a former name counts as the same) and
    by family, with the families whose count moved."""
    before = {item["fingerprint"] for item in previous}
    before_names = before | {name for item in previous for name in formers(item)}
    now = {item["fingerprint"] for item in current}
    now_names = now | {name for item in current for name in formers(item)}
    opened = [item["fingerprint"] for item in current if item["fingerprint"] not in before_names and not set(formers(item)) & before]
    gone = sorted(before - now_names)
    old, new = _families(previous), _families(current)
    return {"v1_opened": len(opened), "v1_gone": len(gone), "v2_opened": len(set(new) - set(old)), "v2_gone": len(set(old) - set(new)),
            "recounted": sum(1 for identity in set(old) & set(new) if old[identity] != new[identity]),
            "findings": len(current), "families": len(new)}


def report(data_dir: Path, keys: Iterable[str] | None = None) -> list[dict]:
    """One row per repository: its last two full scans compared, and whether both were of the same commit."""
    rows = []
    for key in keys or registry.asset_keys(data_dir):
        latest = [item for item in store.page_runs(data_dir, asset=key, kind="repository_scan", limit=10)["items"]
                  if item.get("status") in ("completed", "incomplete")][:2]
        if len(latest) < 2:
            rows.append({"asset": key, "name": latest[0].get("target") if latest else key, "scans": len(latest)})
            continue
        current, previous = (store.load_run(data_dir, item["id"]) for item in latest)
        commits = [str((record.get("source") or {}).get("commit") or "") for record in (previous, current)]
        rows.append({"asset": key, "name": current.get("target") or key, "scans": 2, "commit": commits[1][:12],
                     "same_commit": bool(commits[0]) and commits[0] == commits[1],
                     # Excluded findings too: their identity carries their exclusion and its reason.
                     **compare([*(previous.get("findings") or []), *(previous.get("excluded_findings") or [])],
                               [*(current.get("findings") or []), *(current.get("excluded_findings") or [])])})
    return rows


def passed(rows: list[dict]) -> bool:
    """At least one repository scanned twice on one commit, and every such one 0/0 both ways."""
    same = [row for row in rows if row.get("same_commit")]
    return bool(same) and all(row[field] == 0 for row in same for field in ("v1_opened", "v1_gone", "v2_opened", "v2_gone", "recounted"))


def scan_twice(path: Path, data_dir: Path, progress=None) -> dict:
    """The gate on a working tree, for CI: the same commit scanned twice with this code, compared by fingerprint and
    by identity (excluded findings included). `passed` only with two complete scans and 0/0 both ways."""
    from pitangus.modules.runs.local import run
    scans = [run(path, data_dir=data_dir, fail_on="never", progress=progress)["scan"] for _ in range(2)]
    every = [[*(scan.get("findings") or []), *(scan.get("excluded_findings") or [])] for scan in scans]
    result = compare(every[0], every[1])
    complete = all(scan.get("status") == "completed" for scan in scans)
    return {**result, "complete": complete,
            "passed": complete and all(result[field] == 0 for field in ("v1_opened", "v1_gone", "v2_opened", "v2_gone", "recounted"))}

