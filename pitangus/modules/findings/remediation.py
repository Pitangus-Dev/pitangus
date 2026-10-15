"""Group findings by fix: what a development team does, not what an engine reports.

Advisories of the same package (same manifest and version) are closed by a single upgrade: the
highest of the versions that fix each advisory. Code, secrets and infrastructure are handled one by
one, but the same rule repeated across several files is a single pattern to fix. A web problem (the same rule and
title) found on several URLs is one fix too: one entry that lists its URLs, while each URL stays a finding of its own.
"""

from __future__ import annotations

import re

from typing import cast

from pitangus.modules.findings.fix_guide import guide
from pitangus.modules.intel.advisories import compare_versions
from pitangus.shared.i18n import t, text
from pitangus.shared.model import Finding

ORDER = {level: index for index, level in enumerate(("critical", "high", "medium", "low", "info"))}


def _worst(items: list[dict]) -> str:
    return min((item.get("severity") or "info" for item in items), key=lambda level: ORDER.get(level, 9))


def _counts(items: list[dict]) -> dict[str, int]:
    return {level: sum(1 for item in items if item.get("severity") == level) for level in ORDER if any(item.get("severity") == level for item in items)}


def _web_key(item: dict) -> tuple[str, str, str] | None:
    """A web problem: the same rule with the same title, wherever it was seen."""
    if item.get("scanner") != "dast" or not item.get("rule_id"):
        return None
    return ("web", str(item["rule_id"]), text(item.get("title")) if isinstance(item.get("title"), dict) else str(item.get("title") or ""))


def problems(findings: list[dict]) -> list[list[dict]]:
    """The findings in their order, one list per report row: a web problem's URLs together (at its first place),
    anything else alone."""
    rows: list[list[dict]] = []
    seen: dict[tuple, list[dict]] = {}
    for item in findings:
        key = _web_key(item)
        if key is None:
            rows.append([item])
        elif key in seen:
            seen[key].append(item)
        else:
            seen[key] = [item]
            rows.append(seen[key])
    return rows


def _ids(items: list[dict]) -> list[str]:
    ids = []
    for item in items:
        ids += (item.get("cve") or [])[:1] or (item.get("ghsa") or [])[:1] or ([item["rule_id"]] if item.get("rule_id") else [])
    return list(dict.fromkeys(ids))


def fix_groups(findings: list[dict], *, by_rule: bool = False, by_problem: bool = False) -> list[dict]:
    """One entry per fix, in priority order (active exploitation, severity, scope).

    Each entry: kind ("package" or "finding"), severity (the worst), items, counts, ids, kev, epss,
    and for packages name, version, path, target (the version that closes them all) and complete (all have a fix).
    With by_rule, code findings of the same rule are grouped together (kind "rule"); with by_problem, a web problem
    on several URLs is one entry (kind "web", with its `urls`)."""
    groups: dict[tuple, list[dict]] = {}
    for item in findings:
        package = item.get("package") or {}
        if item.get("scanner") == "sca" and package.get("name"):
            key = ("package", item.get("path") or "", package["name"], package.get("version") or "")
        elif by_rule and item.get("rule_id"):
            key = ("rule", item.get("scanner") or "", item["rule_id"])
        elif by_problem and (web := _web_key(item)) is not None:
            key = web
        else:
            key = ("finding", item.get("fingerprint") or id(item))
        groups.setdefault(key, []).append(item)
    result = []
    for key, items in groups.items():
        entry = {"kind": key[0], "severity": _worst(items), "items": items, "counts": _counts(items), "ids": _ids(items),
                 "kev": any(item.get("kev") for item in items), "malicious": any(item.get("malicious") for item in items),
                 "epss": max(((item.get("epss") or {}).get("score") or 0 for item in items), default=0)}
        if key[0] == "package":
            fixes = [item["package"]["fixed_version"] for item in items if item["package"].get("fixed_version")]
            target = None
            for fix in fixes:
                target = fix if target is None or compare_versions(fix, target) > 0 else target
            entry.update(path=key[1], name=key[2], version=key[3], target=target, complete=bool(fixes) and len(fixes) == len(items),
                         ecosystem=(items[0]["package"].get("ecosystem") or ""))
        elif key[0] == "rule":
            entry.update(rule=key[2], title=items[0].get("title") or key[2])
        elif key[0] == "web":
            entry.update(rule=key[1], title=items[0].get("title") or key[1], urls=[str(item.get("path") or "") for item in items])
        result.append(entry)
    # Malicious and actively exploited first.
    return sorted(result, key=lambda entry: (not entry["malicious"], not entry["kev"], ORDER.get(entry["severity"], 9), -len(entry["items"]), -entry["epss"],
                                             entry.get("path") or entry["items"][0].get("path") or ""))


def action(entry: dict, *, short: bool = False, locale: str | None = None) -> str:
    """What to do, in one sentence. `short`: for a table cell (the detail carries the full guide)."""
    if entry.get("malicious"):
        # Hostile code: no version "fixes" it, it gets removed (same criterion as the panel's fix guide).
        version = entry.get("version") or ""
        sentence = (t("findings.remediation.remove_malicious", locale, package=entry["name"], version=version) if entry.get("name")
                    else t("findings.remediation.remove_malicious_unnamed", locale, version=version))
        return sentence.replace("  ", " ")
    if entry["kind"] == "package":
        # A parent whose range rejects the fixed version moves first: the guide says which (same text as the panel).
        first = guide(cast(Finding, entry["items"][0]), target=entry["target"]) if entry["target"] else None
        if first and first.get("action"):
            return text(first["action"], locale)
        name, count = entry["name"], len(entry["items"])
        fixed = sum(1 for item in entry["items"] if item["package"].get("fixed_version"))
        if entry["target"] and entry["complete"]:
            return t("findings.remediation.update_all" if count > 1 else "findings.remediation.update", locale,
                     package=name, version=entry["target"], total=count)
        if entry["target"]:
            return t("findings.remediation.update_partial", locale, package=name, version=entry["target"], fixed=fixed, total=count)
        return t("findings.remediation.no_fix_short", locale) if short else t("findings.remediation.no_fix", locale, package=name)
    guidance = text(entry["items"][0].get("remediation"), locale) or t("findings.remediation.review", locale)
    if short:
        first = re.split(r"(?<=[.;])\s", guidance, maxsplit=1)[0]
        return first if len(first) <= 110 else first[:110].rsplit(" ", 1)[0] + "…"
    return guidance


SEVERITY_COUNT = {"critical": "findings.remediation.severity_count.critical", "high": "findings.remediation.severity_count.high",
                  "medium": "findings.remediation.severity_count.medium", "low": "findings.remediation.severity_count.low",
                  "info": "findings.remediation.severity_count.info"}


def counts_text(counts: dict[str, int], *, locale: str | None = None) -> str:
    return ", ".join(t(SEVERITY_COUNT[level], locale, count=value) for level, value in counts.items())
