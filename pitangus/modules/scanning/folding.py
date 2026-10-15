"""Folding one engine's report into another's: what the folded one was known by is never lost."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

FORMERS_MAX = 500


def absorbed(kept: Any, other: Mapping[str, Any]) -> None:
    """`other`, the same problem reported by another engine, folded into `kept`: noted among its engines, and its
    fingerprints among `kept`'s former names, so the entry it may have had moves to `kept` instead of looking fixed."""
    if other.get("tool") and other["tool"] != kept.get("tool") and other["tool"] not in kept.setdefault("also_detected_by", []):
        kept["also_detected_by"].append(other["tool"])
    if other.get("malicious") and not kept.get("malicious"):  # the strongest verdict survives the merge
        from pitangus.modules.intel.advisories import mark_malicious
        mark_malicious(kept)
    names = kept.setdefault("previous_fingerprints", [])
    for name in [other.get("fingerprint"), other.get("previous_fingerprint"), *(other.get("previous_fingerprints") or [])]:
        if isinstance(name, str) and name and name != kept.get("fingerprint") and name not in names and len(names) < FORMERS_MAX:
            names.append(name)
    # The same value, named by both: what each knew it by is still a name of that value.
    if isinstance(kept.get("value_formers"), list) and isinstance(other.get("value_formers"), list):
        kept["value_formers"] = list(dict.fromkeys(name for name in [*kept["value_formers"], *other["value_formers"]]
                                                   if name != kept.get("identity")))[:FORMERS_MAX]


def known_as(finding: Any, *names: str | None) -> None:
    """Names an earlier formula gave `finding`, among its former names, so the entry stored under any of them moves to
    it with its triage and issue (findings/registry._rekey) instead of looking fixed while the finding looks new. For
    what can't be recomputed from what is stored (a secret's identity: its value is never stored), the scans of one
    release compute the earlier formula next to the current one."""
    formers = finding.setdefault("previous_fingerprints", [])
    for name in names:
        if isinstance(name, str) and name and name not in (finding.get("fingerprint"), finding.get("identity")) \
                and name not in formers and len(formers) < FORMERS_MAX:
            formers.append(name)
    if not formers:
        finding.pop("previous_fingerprints")
