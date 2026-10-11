"""The OWASP pages that explain a finding: cheat sheets, the Top 10:2025 category, the API Security Top 10 and the
Web Security Testing Guide, from the curated mapping in `references.yaml`.

Pitangus doesn't write remediation of its own for third-party rules (the fix may live in a WAF, a CDN or the platform,
not in the code): the tool's guidance is shown as published and these links come after its own references. Links
only, never the pages' text. Computed when a finding is served, so a better mapping reaches old runs too.
"""

from __future__ import annotations

import re
from functools import cache
from pathlib import Path
from typing import Any, TypedDict

import yaml

from pitangus.shared.model import Finding

MAPPING = Path(__file__).with_name("references.yaml")
KINDS = ("cheatsheet", "top10", "api_top10", "wstg")
APP_KINDS = frozenset(("api_top10", "wstg"))  # only for code and web findings
APP_SCANNERS = frozenset(("sast", "dast"))
LIMIT = 6  # links before the Top 10 category
TOP10 = re.compile(r"A(\d{2}):2025")


class Guidance(TypedDict):
    title: str
    url: str
    kind: str


@cache
def mapping() -> dict[str, Any]:
    return yaml.safe_load(MAPPING.read_text(encoding="utf-8"))


@cache
def _top10_of() -> dict[int, str]:
    return {cwe: category for category, entry in mapping()["top10"].items() for cwe in entry["cwe"]}


def top10(cwes: list[int]) -> list[str]:
    """The Top 10:2025 categories of these CWEs, by OWASP's own mapping, as `A05:2025`."""
    found = {_top10_of().get(cwe) for cwe in cwes}
    return sorted(f"{category}:2025" for category in found if category)


def owasp_of(finding: Finding) -> list[str]:
    """The finding's OWASP Top 10 categories: its engine's (any edition an imported SARIF named), or, when the engine
    set none, the Top 10:2025 categories of its CWEs."""
    stated = [str(item) for item in finding.get("owasp") or [] if str(item).strip()]
    return stated or top10([cwe for cwe in finding.get("cwe") or [] if isinstance(cwe, int)])


def _rule_pages(tool: str, rule: str) -> list[str]:
    rules = mapping()["rules"].get(tool)
    if not rules or not rule:
        return []
    candidates = [rule]
    if ":" in rule:
        candidates.append(rule.split(":", 1)[0])
    if tool == "zap" and "-" in rule:  # an alert's variant (10035-1) of its rule
        candidates.append(rule.split("-", 1)[0])
    for candidate in candidates:
        if candidate in rules:
            return rules[candidate]
    for pattern, pages in rules.items():
        if pattern.endswith("*") and rule.startswith(pattern[:-1]):
            return pages
    return rules.get("_default") or []


def _page(key: str) -> Guidance:
    page = mapping()["pages"][key]
    return {"title": page["title"], "url": page["url"], "kind": page["kind"]}


def guidance(finding: Finding) -> list[Guidance]:
    """Links to the OWASP pages for this finding, most specific first, the Top 10 category last."""
    data = mapping()
    scanner = str(finding.get("scanner") or "")
    tool = str(finding.get("tool") or "").lower()
    path = str(finding.get("path") or "")
    keys = list(_rule_pages(tool, str(finding.get("rule_id") or "")))
    keys += data["frameworks"].get(str(finding.get("framework") or ""), [])
    if scanner in ("iac", "cicd"):
        keys += [page for entry in data["paths"] if re.search(entry["pattern"], path) for page in entry["pages"]]
    fallback = data["scanners"].get(scanner) or {"cwe": True, "pages": []}
    if fallback["cwe"] and not keys:  # a rule we know says more than its CWE
        keys += [page for cwe in finding.get("cwe") or [] for page in data["cwe"].get(cwe, [])]
    if not keys or scanner in ("secrets", "sca"):
        keys += fallback["pages"]
    if scanner not in APP_SCANNERS:
        keys = [key for key in keys if data["pages"][key]["kind"] not in APP_KINDS]
    links = [_page(key) for key in dict.fromkeys(keys)][:LIMIT]
    for category in owasp_of(finding):
        entry = data["top10"].get(category[:3]) if TOP10.fullmatch(category) else None
        if entry:
            links.append({"title": entry["title"], "url": entry["url"], "kind": "top10"})
    return links


def brief(links: list) -> list:
    """What a report prints per finding: the three most specific pages and the Top 10 category."""
    return [link for link in links if link["kind"] != "top10"][:3] + [link for link in links if link["kind"] == "top10"][:1]


def annotate(findings: list[Finding]) -> list[Finding]:
    """Adds `guidance` and fills `owasp` from the CWEs where the engine left it empty."""
    for finding in findings:
        finding["owasp"] = owasp_of(finding)
        finding["guidance"] = [dict(link) for link in guidance(finding)]
    return findings
