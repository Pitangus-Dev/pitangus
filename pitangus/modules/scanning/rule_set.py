"""What a scan ran with: which engines were on and which rules each applied, recorded on the run (`configuration`).

Turning a rule or an engine off, or updating a rule, makes findings disappear that are still in the code. The registry
reads this record to tell those apart from fixes (findings/registry.configuration_cause): a finding is fixed only by a
run whose engine was on and whose rule was active, unchanged since the finding was last seen.

Per engine, `{"off": true}` when the operator turned it off, or:

* `rules`: {rule id: digest of what it matches} for the rules this run enumerates ("" when the digest is unknown);
* `enumerated`: id prefixes whose rules are all in `rules` (one missing from it didn't run);
* `others`: the digest of every other rule (the engine's built-in set, the third-party rules), when they ran;
* `inactive`: rule ids that didn't run although `others` would cover them;
* `scanners`: {scanner: digest} for the rules of one of the engine's scanners that `others` doesn't describe.

A rule's digest changes when what it matches does (`rule_digests` leaves its wording out), or for the secret engines'
built-in rules when Pitangus changes how it filters them (SECRET_FILTERS, SECRET_REVISIONS).

An engine left out declares nothing: the coverage rules alone decide for it. Allowlists and disabled built-in rules are
not here: their secrets are recorded as excluded by the unfiltered reference run (secret_rules.withheld).
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

import yaml

from pitangus.modules.scanning import secret_identity, secret_rules
from pitangus.modules.scanning.engines import RULES_DIR, THIRD_PARTY_RULES_DIR, enabled
from pitangus.modules.scanning.secret_builtin_rules import OPT_IN_RULES
from pitangus.shared import settings

BASELINE = Path(__file__).with_name("rule_baseline.json")
# How Pitangus filters what the secret engines' built-in rules report (their definitions come with the pinned engine).
# Bump SECRET_FILTERS when that changes for every rule, or a rule's SECRET_REVISIONS entry when it changes for it alone:
# a finding seen before that stops appearing is then "not checked (configuration)", never fixed.
# 2: the post-filter that sets aside what can't be a secret (scanning/secret_filter), on every rule of both engines.
# 3: a Betterleaks secret's identity is its value's, not its whole match's: an entry the former name doesn't carry over
#    (scanning/folding.known_as) stays "not checked", never fixed.
SECRET_FILTERS = "3"
SECRET_REVISIONS: dict[str, str] = {}
OWN_PREFIX = "appsec."   # every rule of ours (engines._rule_id); anything else Opengrep reports is third-party
# What a rule says about its matches, not what it matches: changing it changes no finding.
WORDING = ("metadata", "message", "severity", "fix")


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()[:16]


def rule_digests(documents: list[str]) -> dict[str, str]:
    """{id: digest of its matching part} for the Opengrep rules in these YAML documents."""
    found: dict[str, str] = {}
    for document in documents:
        for rule in (yaml.safe_load(document) or {}).get("rules") or []:
            if isinstance(rule, dict) and rule.get("id"):
                found[str(rule["id"])] = _digest({key: value for key, value in rule.items() if key not in WORDING})
    return found


@lru_cache(maxsize=1)
def own_rules() -> dict[str, str]:
    """Pitangus's Opengrep rules, by id, with their digests."""
    return rule_digests([path.read_text(encoding="utf-8") for path in sorted(RULES_DIR.glob("*.yml"))])


@lru_cache(maxsize=1)
def opt_in_rules() -> tuple[str, ...]:
    """Pitangus's Opengrep rules that start off (`metadata.opt_in`): measured too noisy to be on by default."""
    found = [str(rule["id"]) for path in sorted(RULES_DIR.glob("*.yml"))
             for rule in (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("rules") or []
             if isinstance(rule, dict) and (rule.get("metadata") or {}).get("opt_in")]
    return tuple(sorted(found))


def dormant_rules() -> list[str]:
    """The opt-in rules a scan leaves off: all of them but those PITANGUS_SAST_OPT_IN_RULES turns on. A finding one of
    them reported before is then "not checked (rule off)", never fixed."""
    turned_on = set(settings.items("PITANGUS_SAST_OPT_IN_RULES"))
    return [rule for rule in opt_in_rules() if rule not in turned_on]


def builtin(rule: str | None = None) -> str:
    """The digest of a secret engine's built-in rule as Pitangus filters it."""
    return f"builtin-{SECRET_FILTERS}" + (f".{SECRET_REVISIONS[rule]}" if rule in SECRET_REVISIONS else "")


@lru_cache(maxsize=1)
def baseline() -> dict:
    """The digests findings stored before runs recorded their configuration were seen with (`rule_baseline.json`: the
    rules of 0.13.1, the last release without it), stamped on them once (app/data_migrations)."""
    return json.loads(BASELINE.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def third_party_digest() -> str:
    """One digest for the vendored third-party rules: they change together, when the vendored copy is updated."""
    digest = hashlib.sha256()
    for path in sorted(THIRD_PARTY_RULES_DIR.rglob("*.yml")):
        digest.update(path.relative_to(THIRD_PARTY_RULES_DIR).as_posix().encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()[:16]


def _custom(secret_settings: dict | None) -> dict[str, str]:
    return {secret_rules.engine_id(rule["id"]): _digest([rule["regex"], sorted(rule.get("keywords") or [])])
            for rule in (secret_settings or {}).get("rules") or []}


def _optional(key: str) -> dict:
    return {"others": ""} if enabled(key) else {"off": True}


def code(secret_settings: dict | None) -> dict:
    """A repository scan's configuration, with the secret detection settings it applied and the ids of the keys its
    secrets' identities were computed with (`identity_keys`: a secret named under another key can't be told gone)."""
    custom = _custom(secret_settings)
    third_party = settings.flag("PITANGUS_THIRD_PARTY_RULES") and THIRD_PARTY_RULES_DIR.is_dir()
    # Opt-in rules stay off unless turned on, in the scan and in its unfiltered reference run alike.
    dormant = sorted(set(OPT_IN_RULES) - set((secret_settings or {}).get("enabled_rules") or []))
    revised = {rule: builtin(rule) for rule in SECRET_REVISIONS}
    return {"engines": {
        "opengrep": {"rules": own_rules(), "enumerated": [OWN_PREFIX], **({"inactive": sast_dormant} if (sast_dormant := dormant_rules()) else {}),
                     **({"others": third_party_digest()} if third_party else {})},
        "betterleaks": {"rules": {**revised, **custom}, "enumerated": [secret_rules.ENGINE_PREFIX], "others": builtin(),
                        **({"inactive": dormant} if dormant else {})},
        # Trivy's built-in rules are also its dependency advisories and configuration checks: no digest to compare, but
        # its secret rules go through the same filter as Betterleaks'.
        "trivy": {"rules": custom, "enumerated": [secret_rules.ENGINE_PREFIX], "others": "", "scanners": {"secrets": builtin()}},
        "checkov": _optional("checkov"),
    }, "identity_keys": secret_identity.key_ids()}


def image() -> dict:
    """An image scan's configuration: its optional engines."""
    return {"engines": {"grype": _optional("grype"), "checkov": _optional("checkov")}}
