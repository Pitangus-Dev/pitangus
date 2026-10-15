"""The fingerprints a finding was known by before, so its state, triage and issue follow it.

A fingerprint is stable by design, but some change for reasons that aren't the finding's: a formula that improves (a
zizmor finding keyed by its step instead of its line, an image history step by its command instead of its position),
an advisory that gets a CVE after being known by its GHSA, or two engines' reports of the same package folded into one
(Trivy's and Grype's names for a Java package). The finding carries what it was (`previous_fingerprint`,
`previous_fingerprints`) and its advisory's other names, and the registry, a PR review and a fix comparison treat any
of those as the same finding.

A secret is named by its value (`of_value`: the keyed HMAC of the value, scanning/secret_identity.py), and then only
names computed from that value are its former names (`value_formers`: its identity under the key before a rotation, or
by an earlier formula). Its engine's fingerprint (the rule, the file, what precedes it on its line) is the same for any
value in that place, so it never links a value to another: changing `TOKEN = "A"` to `TOKEN = "B"` is A fixed and B new,
whatever else they share. Such a name (`legacy_formers`) only hands over what was stored before secrets had a value's
identity (0.13), which has no value to compare with: on the first scan that reads the value, once.

A secret whose value couldn't be read for sure is `unlinkable` (scanning/secret_location.py): named by its rule, its
file and the content of its lines, it has no former names, is no other finding's former name and takes no entry but
its own, so it never inherits another's triage, issue or state, nor hands over its own.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from pitangus.modules.intel.packages import alias_fingerprints


def of_value(finding: Mapping[str, Any]) -> bool:
    """Whether `finding`'s identity is its value's (a secret's): it then carries `value_formers`, even empty."""
    return isinstance(finding.get("value_formers"), list) and not unlinkable(finding)


def unlinkable(finding: Mapping[str, Any]) -> bool:
    """Whether `finding` is a secret whose value couldn't be read for sure: its identity is its own only."""
    return finding.get("unlinkable") is True


def _names(items: Iterable[Any], *without: Any) -> list[str]:
    return list(dict.fromkeys(item for item in items if isinstance(item, str) and item and item not in without))


def formers(finding: Mapping[str, Any]) -> list[str]:
    """The other fingerprints of `finding`, most specific first, without its own. For a finding named by its value
    (`of_value`), only names of that value: its identity when it isn't its fingerprint (`PITANGUS_IDENTITY_MODE=v1`),
    and its `value_formers`. An unlinkable one, none."""
    if unlinkable(finding):
        return []
    if of_value(finding):
        return _names([finding.get("identity"), *finding["value_formers"]], finding.get("fingerprint"))
    found = [finding.get("previous_fingerprint"), *(finding.get("previous_fingerprints") or [])]
    package = finding.get("package") or {}
    if finding.get("scanner") == "sca" and package.get("name") and finding.get("rule_id"):
        rule = str(finding["rule_id"])
        found += alias_fingerprints({rule, *(finding.get("cve") or []), *(finding.get("ghsa") or [])}, rule,
                                    str(package.get("ecosystem") or ""), str(package["name"]), str(package.get("version") or ""))
    return list(dict.fromkeys(item for item in found if isinstance(item, str) and item and item != finding.get("fingerprint")))


def legacy_formers(finding: Mapping[str, Any]) -> list[str]:
    """The names of a finding named by its value that aren't its value's: its engine's fingerprints. They only ever
    reach something stored without a value's identity (`may_take`); [] for any other finding."""
    if not of_value(finding):
        return []
    found = [finding.get("fingerprint"), finding.get("previous_fingerprint"), *(finding.get("previous_fingerprints") or [])]
    return _names(found, finding.get("identity"), *finding["value_formers"])


def own_names(finding: Mapping[str, Any]) -> list[str]:
    """Every name that is certainly `finding`: its fingerprint (its identity, when it is named by its value or
    unlinkable) and its `formers`."""
    first = finding.get("identity") if of_value(finding) or unlinkable(finding) else finding.get("fingerprint")
    return _names([first, *formers(finding)])


def may_take(finding: Mapping[str, Any], earlier: Mapping[str, Any], legacy: bool = False) -> bool:
    """Whether `finding` may be what `earlier` (a stored finding, a base's report) was, through one of its own names, or
    one of its `legacy_formers` (`legacy`). A value is only ever its own: a finding named by its value takes another
    named by a value only through that value's names, and something stored without one (0.13) through any; a finding
    whose value couldn't be read never takes one that has it (it could be any value). An unlinkable finding takes nothing
    and nothing takes it."""
    if unlinkable(finding) or unlinkable(earlier):
        return False
    if of_value(finding):
        return not (legacy and of_value(earlier))
    return not legacy and not of_value(earlier)


def family_of(finding: Mapping[str, Any]) -> str:
    """The identity a finding shares with its identical copies (the same line pasted twice, the same secret twice in a
    file): its fingerprint without the copy's order. Engines that tell copies apart set `family`; for the rest the
    fingerprint is already the family."""
    return str(finding.get("family") or finding["fingerprint"])


def family_counts(findings: Iterable[Mapping[str, Any]]) -> Counter[str]:
    """How many instances of each family a scan has: copies are counted, never collapsed (a PR that pastes an existing
    problem once more adds one)."""
    return Counter(family_of(finding) for finding in findings)
