"""Third-party SAST rules (GitLab's sast-rules, PITANGUS_THIRD_PARTY_RULES) next to Pitangus' own, without repeating them.

When one of ours and a third-party rule report the same problem on the same line, one finding remains: ours, untouched
(its rule, texts, severity and identity), with the other rule in `related_rules` and its fingerprint among the former
names, so an entry the third-party finding had moves to ours instead of looking fixed. The same problem means the same
weakness class: the CWEs of both share one, counting the close siblings below as one (OS command injection is CWE-78 for
one rule set and CWE-77 for another). A third-party finding with no twin of ours stays as it is; two of ours are never
joined.
"""

from __future__ import annotations

import copy

from pitangus.modules.scanning.folding import absorbed

OWN_PREFIX = "appsec."
# Weakness classes rule sets file under neighbouring CWEs.
SIBLINGS = ({77, 78, 88}, {89, 564, 943}, {22, 23, 36, 73}, {79, 80, 83, 87}, {94, 95, 96}, {326, 327, 328, 916},
            {295, 297}, {259, 321, 798}, {502}, {611, 776}, {918}, {601}, {1333, 400}, {330, 338})
_CLASS = {cwe: min(group) for group in SIBLINGS for cwe in group}


def own(finding: dict) -> bool:
    return str(finding.get("rule_id") or "").startswith(OWN_PREFIX)


def weakness(finding: dict) -> set[int]:
    return {_CLASS.get(cwe, cwe) for cwe in finding.get("cwe") or [] if isinstance(cwe, int)}


def twins(finding: dict, candidate: dict) -> bool:
    return (finding.get("path"), finding.get("line")) == (candidate.get("path"), candidate.get("line")) \
        and bool(weakness(finding) & weakness(candidate))


def merge(findings: list) -> list:
    """Ours, each with the third-party rules that saw the same problem folded in, then the third-party ones left over.
    Idempotent, and independent of the order the engine reported them in."""
    ours = [copy.deepcopy(item) for item in findings if own(item)]
    by_place: dict[tuple, list[dict]] = {}
    for item in ours:
        by_place.setdefault((item.get("path"), item.get("line")), []).append(item)
    left = []
    for item in sorted((item for item in findings if not own(item)),
                       key=lambda item: (str(item.get("path")), int(item.get("line") or 0), str(item.get("rule_id")), str(item.get("fingerprint")))):
        matched = [candidate for candidate in by_place.get((item.get("path"), item.get("line")), []) if twins(item, candidate)]
        if not matched:
            left.append(item)
            continue
        for twin in matched:
            absorbed(twin, item)
            rules = twin.setdefault("related_rules", [])
            for rule in [item.get("rule_id"), *(item.get("related_rules") or [])]:
                if isinstance(rule, str) and rule and rule not in rules:
                    rules.append(rule)
    return ours + left
