"""Findings registry per repository: the current state and its lifecycle.

A run is a snapshot; the registry is the film. Each finding (by its stable fingerprint)
lives here with its origin, when it was first and last seen, and whether it is still
open. It is updated only when a run finishes:

* **Full scan** (main branch): what shows up stays open (and reopens if it had been
  fixed); what was open from the main branch and no longer shows up is **fixed
  automatically**. Only if the scan finished entirely: in an **incomplete** one (an
  engine didn't run, truncated snapshot) not showing up proves nothing, so it opens and
  updates but never fixes. Nor does a complete one fix a finding that only engines which
  failed in it see (an optional engine such as Checkov or zizmor can fail without making
  the scan incomplete): they didn't look, so its absence proves nothing either. The same
  goes for a finding whose file this scan didn't analyze (left out of the snapshot for its
  size, or skipped by the engine that reports it: `unexamined`).
* **Configuration never fixes.** Each run records which engines were on and which rules each applied (scanning/rule_set).
  A finding whose engine was off, whose rule didn't run, or whose rule changed since it was last seen (`rule_digest`)
  is not proven gone: it stays open, unseen with reason "configuration", in every coverage mode.
* **Excluded paths** (`exclusions`): whatever falls under them is **excluded**, neither open
  nor fixed. If the path stops being excluded, the next scan reopens it.
* **Secrets withheld by the secret detection settings** (allowlist, disabled rule), and **SAST matches silenced with a
  `nosemgrep` comment**: excluded with the reason, never fixed. They reopen when the settings stop withholding them (or
  the comment goes away), and are fixed only once a complete scan no longer sees them even without the filters.
* **A finding known by another fingerprint** (an earlier formula, an advisory's GHSA before its CVE, a report folded
  into another one: `identity.formers`) keeps its entry, triage and issue under the current fingerprint; only within
  its lane (`lane`: the same tool for imports, the same kind of web scan), never taking another kind's entry.
* **PR review**: what the PR introduces stays open with origin "PR #n"; what that same
  PR had introduced and is no longer in its new commit is fixed. A PR closed without
  merging withdraws its findings; a merged one leaves them waiting for the next full
  scan, which confirms whether they reached the main branch.
* **Imports** (`sarif_import`, findings from another tool): what shows up opens with origin
  "import" and the tool's name. Only a later complete import of the **same tool** (and the same
  category, when the SARIF has one: CodeQL uploads one file per language) with scope "full" fixes
  what that tool no longer reports; a partial import (some files, one module) only
  opens and updates. Pitangus's own scans and PR reviews never fix an imported finding, nor
  does an import fix theirs: each tool vouches only for what it looks at.

Manual remediation is a triage decision with a mandatory justification; if the finding
reappears in a later run, it reopens on its own.
"""

from __future__ import annotations

from collections.abc import Collection
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert

from pitangus.modules.findings.tables import registry_assets, registry_findings
from pitangus.shared import db
from pitangus.shared.db import TENANT

from pitangus.modules.findings.kinds import FINDING_RUNS, FULL_SCANS, IMPORT_RUNS
from pitangus.shared import log as logging_setup
from pitangus.shared.i18n import msg, text
from pitangus.modules.findings import sla
from pitangus.modules.findings import kpis, triage
from pitangus.modules.findings.identity import legacy_formers, may_take, of_value, own_names, unlinkable
from pitangus.modules.sources.assets import asset_key
from pitangus.shared import coverage_units, settings, web_keys
from pitangus.shared.render import PLACEHOLDER
from pitangus.shared.model import Finding, Message, RunRecord

_log = logging_setup.get("findings")
VIEW_PREFIX = "asset:"
# An engine replaced by its successor (same rules, same findings): what the old one reported is the new one's to prove gone.
SUCCESSORS = {"gitleaks": "betterleaks"}


def owner_of(finding: dict) -> str:
    """The engine that vouches for `finding` today: the one whose fingerprint it carries, or its successor."""
    tool = str(finding.get("tool") or "").lower()
    return SUCCESSORS.get(tool, tool)


def _cves(entry: dict) -> list[str]:
    return [item for item in ((entry.get("finding") or {}).get("cve") or []) if isinstance(item, str)]


def load(data_dir: Path, key: str) -> dict:
    """An asset's state: {"asset", "name", "findings": {fingerprint: entry}, "applied": [runs]}."""
    with db.transaction(data_dir) as connection:
        head = connection.execute(select(registry_assets.c.name, registry_assets.c.applied, registry_assets.c.control)
                                  .where(registry_assets.c.tenant_id == TENANT, registry_assets.c.asset_key == key)).first()
        entries = dict(connection.execute(
            select(registry_findings.c.fingerprint, registry_findings.c.entry)
            .where(registry_findings.c.tenant_id == TENANT, registry_findings.c.asset_key == key)).all())
    return {"asset": key, "name": head.name if head else None, "findings": entries, "applied": list(head.applied) if head else [],
            "control": dict(head.control or {}) if head else {}}


def _save(data_dir: Path, payload: dict, gone: set[str] = frozenset()) -> None:
    """`gone`: fingerprints whose rows go away (the entry moved to a new fingerprint)."""
    key = payload["asset"]
    head = insert(registry_assets).values(tenant_id=TENANT, asset_key=key, name=payload.get("name"), applied=payload.get("applied") or [],
                                          control=payload.get("control") or {})
    rows = [{"tenant_id": TENANT, "asset_key": key, "fingerprint": digest, "status": entry.get("status") or "open",
             "cves": _cves(entry), "entry": entry} for digest, entry in (payload.get("findings") or {}).items()]
    with db.transaction(data_dir) as connection:
        connection.execute(head.on_conflict_do_update(index_elements=[registry_assets.c.tenant_id, registry_assets.c.asset_key],
                                                      set_={"name": head.excluded.name, "applied": head.excluded.applied,
                                                            "control": head.excluded.control}))
        if rows:
            statement = insert(registry_findings)
            connection.execute(statement.on_conflict_do_update(
                index_elements=[registry_findings.c.tenant_id, registry_findings.c.asset_key, registry_findings.c.fingerprint],
                set_={"status": statement.excluded.status, "cves": statement.excluded.cves, "entry": statement.excluded.entry,
                      "updated_at": func.now()}), rows)
        if gone:
            connection.execute(delete(registry_findings).where(registry_findings.c.tenant_id == TENANT, registry_findings.c.asset_key == key,
                                                               registry_findings.c.fingerprint.in_(sorted(gone))))


@contextmanager
def _locked(data_dir: Path, key: str):
    """Read-modify-write an asset's state in a locked transaction (across processes, not just threads)."""
    with db.transaction(data_dir) as connection:
        db.lock(connection, "registry", key)
        yield load(data_dir, key)


def asset_keys(data_dir: Path) -> list[str]:
    with db.transaction(data_dir) as connection:
        return [row.asset_key for row in connection.execute(select(registry_assets.c.asset_key).where(registry_assets.c.tenant_id == TENANT)
                                                            .order_by(registry_assets.c.asset_key))]


def find_assets(data_dir: Path, wanted: str) -> list[dict]:
    """Assets whose key is `wanted`, or else whose name is (ignoring case): [{"asset", "name"}]."""
    with db.transaction(data_dir) as connection:
        rows = connection.execute(select(registry_assets.c.asset_key, registry_assets.c.name)
                                  .where(registry_assets.c.tenant_id == TENANT, registry_assets.c.asset_key == wanted)).all() \
            or connection.execute(select(registry_assets.c.asset_key, registry_assets.c.name)
                                  .where(registry_assets.c.tenant_id == TENANT, func.lower(registry_assets.c.name) == wanted.lower())
                                  .order_by(registry_assets.c.asset_key)).all()
    return [{"asset": row.asset_key, "name": row.name} for row in rows]


def forget_asset(data_dir: Path, key: str) -> None:
    with db.transaction(data_dir) as connection:
        connection.execute(delete(registry_findings).where(registry_findings.c.tenant_id == TENANT, registry_findings.c.asset_key == key))
        connection.execute(delete(registry_assets).where(registry_assets.c.tenant_id == TENANT, registry_assets.c.asset_key == key))


def _requestable(item: dict) -> str:
    """A stored web place as a URL that can be requested again: its scheme, host and port from its key, its path as
    shown when the renderer kept all of it (then it is the path as it was); "" when it didn't."""
    found = web_keys.of_instance(item)
    if not found:
        return ""
    try:
        path = urlsplit(str(item.get("path") or "")).path
    except ValueError:
        return ""
    if PLACEHOLDER in path:
        return ""
    authority = web_keys.bare(found).partition("://")[2].partition("/")[0].partition("?")[0]
    return f"{web_keys.bare(found).partition('://')[0]}://{authority}{path or '/'}"


def web_instances(data_dir: Path, key: str, limit: int = 5_000) -> list[str]:
    """The pages the asset's web findings were seen on (each family's instances) that can be requested again
    (`_requestable`): a place whose path the renderer replaced in part isn't asked for, and stays unproven."""
    urls: list[str] = []
    for entry in load(data_dir, key)["findings"].values():
        finding = entry.get("finding") or {}
        if finding.get("scanner") == "dast":
            places = [item for item in finding.get("instances") or [] if isinstance(item, dict) and item.get("path")] \
                or [{"path": finding.get("path"), "key": finding.get("web_key")}]
            urls += [_requestable(item) for item in places]
        if len(urls) >= limit:
            break
    return [url for url in urls if url][:limit]


def web_known(data_dir: Path, key: str, limit: int = 5_000) -> list[tuple[str, str, str, str]]:
    """(tool, rule, key, kind of scan) for each instance of the asset's web findings (its key: shared/web_keys.py,
    never the URL shown): the URLs a rule was seen on in earlier scans of each kind, so its path template spans scans
    (`canonical.collapse`), never mixing one rule's URLs into another's, nor one kind of scan's into another's."""
    from pitangus.modules.findings.canonical import web_kind
    known: list[tuple[str, str, str, str]] = []
    for entry in load(data_dir, key)["findings"].values():
        finding = entry.get("finding") or {}
        if finding.get("scanner") == "dast":
            tool, rule, kind = str(finding.get("tool") or "").lower(), str(finding.get("rule_id") or ""), web_kind(finding)
            places = [item for item in finding.get("instances") or [] if isinstance(item, dict) and item.get("path")] \
                or [{"path": finding.get("path"), "key": finding.get("web_key")}]
            known += [(tool, rule, found, kind) for item in places if (found := web_keys.of_instance(item))]
        if len(known) >= limit:
            break
    return known[:limit]


def is_empty(data_dir: Path) -> bool:
    with db.transaction(data_dir) as connection:
        return connection.execute(select(registry_assets.c.asset_key).where(registry_assets.c.tenant_id == TENANT).limit(1)).first() is None


def blind_engines(scan: dict) -> set[str]:
    """The engines that didn't look in a scan (failed, `inconclusive`, or didn't run, `not_tested`): what they report
    can't have gone away."""
    tools = (scan.get("summary") or {}).get("tools") or []
    return {str(tool.get("name") or "").lower() for tool in tools if tool.get("status") in ("inconclusive", "not_tested")}


def unseen(finding: dict, blind: set[str], engines=()) -> bool:
    """Not finding `finding` proves nothing: an engine that saw it (the one it is keyed by, those it was also detected
    by, those that saw it before: `engines`) was blind."""
    return any(engine in blind for engine in detected_by(finding, engines))


def other_kind(scan: dict, finding: dict) -> bool:
    """Whether `finding` belongs to another kind of web scan than `scan` (`web.coverage`: an exposure check, an
    anonymous crawl, one with saved headers, one API definition): that scan neither fixes it nor marks it unseen."""
    if scan.get("type") != "dast_scan" or finding.get("scanner") != "dast":
        return False
    return ((finding.get("web") or {}).get("coverage") or "baseline") != ((scan.get("scope") or {}).get("coverage") or "baseline")


def units_of(finding: dict) -> list[str]:
    """The units `finding` lives in (shared/coverage_units): a web finding's page; a code finding's file, or, a
    dependency's, the project of each lockfile it was seen in, with whatever units it declares."""
    if finding.get("scanner") == "dast":
        found = web_keys.of_finding(finding)
        return [web_keys.as_page(found) if found else str(finding.get("path") or "")]
    return coverage_units.of_finding(finding)


def _outside(finding: dict, entries) -> bool:
    """Whether any unit of `finding` is among the units `entries` name (unexamined files, folders, projects, pages)."""
    scanner = str(finding.get("scanner") or "")
    return bool(entries) and any(coverage_units.inside(unit, entries, scanner) for unit in units_of(finding))


def detected_by(finding: dict, engines=()) -> list[str]:
    """Every engine that saw `finding`: the one that owns it, those it was also detected by and, from the registry,
    those that saw it in an earlier run (`engines`), each by its current name."""
    others = [*(finding.get("also_detected_by") or []), *(engines or [])]
    return list(dict.fromkeys([owner_of(finding), *(SUCCESSORS.get(str(item).lower(), str(item).lower()) for item in others if item)]))


def covers(scan: dict, finding: dict, engines=()) -> bool:
    """Whether the scan looked where `finding` was seen. A code scan: unless its file was left out of the snapshot (too
    large, not in the provider's archive…) or skipped by an engine that saw it (`unexamined`; `engines`: those that
    saw it before, beyond its own). A web scan: the same kind of scan (anonymous crawl, crawl with saved headers, or one
    API definition: `web.coverage`) on a host of its scope."""
    if scan.get("type") != "dast_scan":
        unexamined, scanner = scan.get("unexamined") or {}, finding.get("scanner")
        # `engine:scanner`: a unit only one of the engine's scanners skipped (engine_contract.coverage's `by_scanner`).
        keys = ["*", *(key for engine in detected_by(finding, engines) for key in (engine, f"{engine}:{scanner}"))]
        return not any(_outside(finding, unexamined.get(key) or ()) for key in keys)
    scope = web_keys.keyed(scan).get("scope") or {}   # pages compared by their keys, never as shown
    coverage = (finding.get("web") or {}).get("coverage") or "baseline"
    if coverage != (scope.get("coverage") or "baseline"):
        return False
    # Saved headers whose session nobody checked may have stopped signing in: what was behind the login proves nothing.
    # (Scans stored before the check existed don't say, and keep their rule.)
    if "+headers" in coverage and scope.get("session_checked") is False:
        return False
    hosts = scope.get("hosts")
    found = web_keys.of_finding(finding)
    if hosts:
        host = web_keys.host(found) if found else ""
        if not (host in hosts or any(host.endswith(pattern[1:]) for pattern in scope.get("wildcards") or [])):
            return False
    # ZAP's findings come from its bounded crawl: only a page this scan reached vouches for it (scans stored before the
    # list existed keep the host rule). nuclei probes each host's root on every run, and the pages of its page pass:
    # a page-level finding only on a page that pass requested. testssl and httpx look at hosts only.
    tool = str(finding.get("tool") or "").lower()
    page = web_keys.as_page(found) if found and web_keys.bare(found).startswith(("http://", "https://")) else None
    reached = scope.get("reached")
    if reached is not None and tool == "zap":
        return page in set(reached)
    probed = scope.get("probed")
    if probed is not None and tool == "nuclei" and page is not None and urlsplit(web_keys.bare(page)).path != "/":
        return page in set(probed)
    return True


def _rule(record: dict, finding: dict) -> tuple[str | None, str]:
    """(why the rule that reported `finding` didn't run in this run, or None; its digest, "" if unknown), from the run's
    configuration (scanning/rule_set). ("", "") when the run declares none for the finding's engine."""
    configuration = record.get("configuration")
    engines = configuration.get("engines") if isinstance(configuration, dict) else None
    spec = engines.get(owner_of(finding)) if isinstance(engines, dict) else None
    if not isinstance(spec, dict):
        return "", ""
    if spec.get("off"):
        return "engine_off", ""
    rule, rules = str(finding.get("rule_id") or ""), spec.get("rules") or {}
    if rule in rules and rule not in (spec.get("inactive") or ()):
        return None, str(rules[rule] or "")
    if rule in (spec.get("inactive") or ()) or any(rule.startswith(prefix) for prefix in spec.get("enumerated") or ()) \
            or "others" not in spec:
        return "rule_off", ""
    return None, str((spec.get("scanners") or {}).get(str(finding.get("scanner") or ""), spec["others"]) or "")


def rule_digest(record: dict, finding: dict) -> str | None:
    """The digest of the rule that reported `finding` as this run applied it, or None (unknown, or it didn't run)."""
    off, digest = _rule(record, finding)
    return (digest or None) if off is None else None


def configuration_cause(record: dict, finding: dict, seen: str | None = None) -> str | None:
    """Why this run's configuration can't tell whether `finding` is gone (None when it can): its engine was turned off
    (`engine_off`), the rule that reported it didn't run (`rule_off`: disabled, opt-in, dropped from the rule set), or
    it changed since the finding was last seen (`rule_changed`; `seen`: its digest then). A run that declares no
    configuration for the engine (older runs, imports, engines nobody can turn off) leaves it to the coverage rules.
    A secret named by its value under a key the run didn't compute identities with (`identity_key`: the master key
    changed and PITANGUS_PREVIOUS_MASTER_KEY doesn't name the one before) can't be told gone either."""
    keys = (record.get("configuration") or {}).get("identity_keys") if isinstance(record.get("configuration"), dict) else None
    if isinstance(keys, list) and (of_value(finding) or unlinkable(finding)) \
            and not any(str(finding.get("identity") or "").startswith(str(kid)) for kid in keys if kid):
        return "identity_key"
    off, digest = _rule(record, finding)
    if off:
        return off
    return "rule_changed" if off is None and seen and digest and digest != seen else None


def indistinct(record: dict, finding: dict, engines=()) -> bool:
    """Whether `record` reports, in `finding`'s file, a secret that can't be told apart from it: one whose value couldn't
    be read (unlinkable), or any when `finding` itself isn't named by a value (unlinkable, or stored before values were
    read); by its engine under its rule, or by any other engine that saw it (`detected_by`, with `engines`) under any
    of its rules, since every one of them must vouch for its absence. Only two values tell two secrets apart, so its
    absence proves nothing then."""
    if finding.get("scanner") != "secrets" or not finding.get("path"):
        return False
    named, owner, rule, path = of_value(finding), owner_of(finding), str(finding.get("rule_id") or ""), str(finding.get("path"))
    others = set(detected_by(finding, engines)) - {owner}
    for item in record.get("findings") or []:
        if item.get("scanner") != "secrets" or str(item.get("path") or "") != path or (named and not unlinkable(item)):
            continue
        if (owner_of(item) == owner and str(item.get("rule_id") or "") == rule) or set(detected_by(item)) & others:
            return True
    return False


def blind_tool(tool: dict, coverage: dict | None) -> bool:
    """Whether an engine is blind as a whole in a run: it failed, didn't run or broke its contract. One that ended
    `partial` looked at some units and is blind only if it doesn't say which: its per-unit coverage decides the rest."""
    if (tool.get("contract") or {}).get("blind"):
        return True
    status = tool.get("status")
    return status != "completed" and not (status == "partial" and coverage is not None)


def _engine_unproven(record: dict, finding: dict, engine: str, tools: dict[str, dict], owner: bool) -> str | None:
    """Why one engine that saw `finding` doesn't vouch for its absence in this run, or None when it does."""
    tool, coverage = tools.get(engine), (record.get("coverage") or {}).get(engine)
    if tool is not None and blind_tool(tool, coverage):
        return "engine_blind"
    if tool is None and not owner and tools and record.get("type") != "dast_scan":
        return "engine_blind"   # it saw it before, and didn't run now
    if coverage is None:
        return "engine_blind" if engine in blind_engines(record) else None
    scanner = str(finding.get("scanner") or "")
    if _outside(finding, coverage.get("unexamined") or {}) or _outside(finding, (coverage.get("by_scanner") or {}).get(scanner) or {}):
        return "unexamined"
    if scanner == "sca" and coverage_units.dependency_unexamined(finding, coverage.get("dependencies")):
        return "unexamined"
    examined = coverage.get("examined")
    if examined != "*":
        named = {coverage_units.unit(item, scanner) for item in examined or ()}
        if not all(unit in named for unit in units_of(finding)):
            return "unexamined"
    return None


def unproven_reason(record: dict, finding: dict, seen: str | None = None, engines=()) -> str | None:
    """Why this run doesn't prove `finding` gone (None when it does): the run is incomplete, its configuration doesn't
    say (`configuration_cause`; `seen`: the rule's digest when the finding was last seen), or an engine that saw it (the
    one that owns it, those it was also detected by, and those that saw it before: `engines`) failed, broke its
    contract (engine_contract), didn't run, declared the finding's file, page or project unexamined, or didn't list it
    among those it examined: every one of them must have looked. An engine that ended `partial` vouches for the units it
    declares examined (`blind_tool`). An engine that declares no coverage (an import, testssl.sh, httpx, our own image
    rules) keeps the rules before the contract: host, kind of scan and blind engines."""
    if record.get("status") != "completed":
        return "incomplete"
    record = cast(dict, web_keys.keyed(record))
    if configuration_cause(record, finding, seen):
        return "configuration"
    tools = {str(tool.get("name") or "").lower(): tool for tool in (record.get("summary") or {}).get("tools") or []}
    owner, everyone = owner_of(finding), detected_by(finding, engines)
    blind = _engine_unproven(record, finding, owner, tools, True)
    if blind == "engine_blind":
        return blind
    if not covers(record, finding, engines):
        return "not_covered"
    if indistinct(record, finding, engines):
        return "unidentified"
    for engine in everyone:
        if reason := (blind if engine == owner else _engine_unproven(record, finding, engine, tools, False)):
            return reason
    return None


def _would_hold(count: int, entries: dict) -> bool:
    """Whether fixing `count` findings at once trips the fix hold: at least PITANGUS_FIX_HOLD_MINIMUM of them and at
    least PITANGUS_FIX_HOLD_PERCENT of the asset's open findings."""
    opened = sum(1 for entry in entries.values() if entry.get("status") == "open")
    return count >= settings.integer("PITANGUS_FIX_HOLD_MINIMUM") and count * 100 >= settings.integer("PITANGUS_FIX_HOLD_PERCENT") * max(opened, 1)


def _held_or_released(control: dict, record: dict, stamp: str, proven: list[str], entries: dict, present: set[str]) -> list[str]:
    """What this run fixes once the fix hold had its say, finding by finding. A held finding is fixed when the next
    complete, covered scan proves it gone again (confirmed); one this run couldn't check keeps waiting; one that came
    back leaves the hold. What this run proves gone for the first time is fixed at once, unless it is too much
    (`_would_hold`): then it joins the hold, which keeps why (the latest run that tripped it: how many it would have fixed
    out of how many open, against which thresholds). The hold is said once, when it starts. Openings are never held."""
    held = control.get("hold") or {}
    waiting = set(held.get("digests") or [])
    confirmed = sorted(waiting & set(proven))
    fresh = [digest for digest in proven if digest not in waiting]
    waiting = waiting - set(proven) - present
    chosen = list(confirmed)
    reason = held.get("reason")
    if fresh and _would_hold(len(fresh), entries):
        waiting |= set(fresh)
        reason = {"kind": "too_many", "run": record["id"], "at": stamp, "count": len(fresh),
                  "open": sum(1 for entry in entries.values() if entry.get("status") == "open"),
                  "minimum": settings.integer("PITANGUS_FIX_HOLD_MINIMUM"), "percent": settings.integer("PITANGUS_FIX_HOLD_PERCENT")}
        if not held:
            _log.warning("registry_fixes_held", extra={"run_id": record["id"], "reason": f"{record.get('source', {}).get('name')}: {len(fresh)}"})
    else:
        chosen += fresh
    if confirmed:
        control["released"] = {"run": record["id"], "at": stamp, "count": len(confirmed), "by": "scan"}
    if waiting:
        control["hold"] = {"run": held.get("run") or record["id"], "at": held.get("at") or stamp, "digests": sorted(waiting), "warned": True,
                           **({"reason": reason} if reason else {})}
    else:
        control.pop("hold", None)
    return sorted(chosen)


def _mark_unseen(entries: dict, unproven: dict[str, str], present: dict, stamp: str, causes: dict[str, dict] | None = None) -> None:
    """An open finding a run couldn't check stays open, marked unseen since the first such run, never fixed; seeing it
    again clears the mark. `causes`: for those the configuration left unchecked, what changed (rule or engine off, rule
    changed) and which rule and engine."""
    for digest, entry in entries.items():
        if digest in present:
            entry.pop("unseen", None)
        elif digest in unproven:
            previous = entry.get("unseen") or {}
            entry["unseen"] = {"since": previous.get("since") or stamp, "scans": int(previous.get("scans") or 0) + 1, "reason": unproven[digest],
                               **((causes or {}).get(digest) or {})}


def control_of(data_dir: Path, key: str) -> dict:
    """What the panel shows about how the asset's findings get fixed: the fixes held back (count, since, by which run)
    and the last release."""
    control = load(data_dir, key).get("control") or {}
    held = control.get("hold")
    return {"mode": settings.text("PITANGUS_COVERAGE_MODE"),
            "hold": {"count": len(held["digests"]), "at": held["at"], "run": held["run"], "reason": held.get("reason")} if held else None,
            "released": control.get("released"), "unseen_warn_scans": settings.integer("PITANGUS_UNSEEN_WARN_SCANS")}


HEALTH_RUNS = 20          # full scans per asset the fix spike metric looks back over
REOPENED_DAYS = 30        # a finding back within this many days of being fixed was likely never gone


def _days_between(start: str | None, end: str) -> float | None:
    try:
        return round((datetime.fromisoformat(end) - datetime.fromisoformat(str(start))).total_seconds() / 86400, 1)
    except (TypeError, ValueError):
        return None


def health(data_dir: Path, keys: list[str]) -> dict:
    """How trustworthy the registry's fixes look across `keys`, to notice a kind of failure nobody thought of: findings
    back within REOPENED_DAYS of being fixed, scans that fixed far more than usual (a spike: over three times an asset's
    median and at least PITANGUS_FIX_HOLD_MINIMUM), open findings several engines report apart (same file, line and
    CVEs), unverified ones, and the share of engines that were blind in each asset's last scan."""
    reopened = spikes = duplicates = unverified = blind = engines = 0
    minimum = settings.integer("PITANGUS_FIX_HOLD_MINIMUM")
    for key in keys:
        state = load(data_dir, key)
        entries = state["findings"].values()
        reopened += sum(1 for entry in entries if entry.get("status") == "open" and entry.get("fixed_for_days") is not None
                        and entry["fixed_for_days"] <= REOPENED_DAYS)
        unverified += sum(1 for entry in entries if entry.get("status") == "open" and entry.get("unseen"))
        counts = sorted(item["count"] for item in (state.get("control") or {}).get("fixes", []))
        median = counts[len(counts) // 2] if counts else 0
        spikes += sum(1 for count in counts if count >= minimum and count > 3 * max(median, 1))
        groups: dict[tuple, set[str]] = {}
        for entry in entries:
            finding = entry.get("finding") or {}
            if entry.get("status") == "open":
                groups.setdefault((finding.get("path"), finding.get("line"), tuple(sorted(finding.get("cve") or []))), set()).add(str(finding.get("tool")))
        duplicates += sum(1 for tools in groups.values() if len(tools) > 1)
        last = (state.get("control") or {}).get("last_tools") or []
        engines += len(last)
        blind += sum(1 for tool in last if tool.get("blind"))
    return {"assets": len(keys), "reopened_soon": reopened, "reopened_days": REOPENED_DAYS, "fix_spikes": spikes,
            "duplicates": duplicates, "unverified": unverified, "blind_engines": blind, "engines": engines,
            "blind_share": round(100 * blind / engines, 1) if engines else 0.0}


def release_hold(data_dir: Path, key: str, *, user: str) -> int:
    """Fixes what the fix hold kept back, at an administrator's word (the scan that would confirm it hasn't run).
    Returns how many were fixed: only those still open."""
    stamp = datetime.now(timezone.utc).isoformat()
    with _locked(data_dir, key) as state:
        control = state.setdefault("control", {})
        held = control.pop("hold", None)
        if not held:
            return 0
        released = [digest for digest in held["digests"] if (state["findings"].get(digest) or {}).get("status") == "open"]
        for digest in released:
            state["findings"][digest].update(status="fixed", fixed={"at": stamp, "run_id": held["run"], "auto": False,
                                                                     "how": msg("findings.registry.released", user=user, date=stamp[:10])})
            state["findings"][digest].pop("unseen", None)
        control["released"] = {"run": held["run"], "at": stamp, "count": len(released), "by": user}
        _save(data_dir, state)
    _log.warning("registry_hold_released", extra={"user": user, "reason": f"{key}: {len(released)}"})
    return len(released)


def _clean(finding: dict) -> dict:
    """What the registry stores of a finding: with the units it lives in declared (shared/coverage_units)."""
    kept = {key: value for key, value in finding.items() if key not in ("triage", "ticket", "lifecycle", "excluded_by", "excluded_reason")}
    return kept if kept.get("scanner") == "dast" else coverage_units.declare(kept)


def _exclusion(finding: dict, stamp: str) -> dict:
    reason = finding.get("excluded_reason")
    return {"pattern": finding.get("excluded_by"), "at": stamp, **({"reason": reason} if reason else {})}


def _withheld(entry: dict) -> bool:
    """Excluded by the secret detection settings or a nosemgrep comment (it carries the reason), not by an excluded path."""
    return entry.get("status") == "excluded" and bool((entry.get("excluded") or {}).get("reason"))


def _reopen_manual(data_dir: Path, record: dict, fingerprints: set[str]) -> None:
    """A manual fix that reappears wasn't one: it reopens and stays in the history."""
    decisions = triage.load(data_dir).get(asset_key(record), {})
    stamp = record.get("finished_at") or record["created_at"]
    # Only counts if the fix predates this run (a rebuild reprocesses old runs).
    back = [digest for digest in fingerprints if (decisions.get(digest) or {}).get("status") == "fixed"
            and (decisions[digest].get("at") or "") < stamp]
    if back:
        triage.decide(data_dir, record, back, "open", system_note=msg("findings.registry.reappeared", run=record["id"][:12]),
                      user={"username": "sistema", "role": "admin"})


def _identities(entries: dict) -> dict[str, str]:
    """Each entry's canonical identity (stored with its finding, else computed from it) and its status."""
    from pitangus.modules.findings.canonical import identity_of
    found: dict[str, str] = {}
    for entry in entries.values():
        finding = entry.get("finding") or {}
        if finding.get("fingerprint") or finding.get("identity"):
            found[identity_of(finding)] = entry.get("status") or "open"
    return found


ONE_PLACE = ("units", "instances", "also_at")   # what a probe of one instance leaves out: the family's other places


def _place(item: dict) -> tuple[str, Any]:
    """One instance of a family: a web page by its key (two pages may be shown alike), anything else by its path."""
    return (str(item["key"]) if web_keys.is_key(item.get("key")) else str(item.get("path") or "")), item.get("line")


def _counted(entry: dict, finding: Finding, record: RunRecord, stamp: str, rising: dict[str, int]) -> Finding:
    """A family's count against the one stored (PITANGUS_IDENTITY_MODE=v2). An instance this run couldn't check (its
    file or page not examined, an engine down) stays, marked unseen: only instances proven gone lower the count, and a
    drop is a partial fix recorded on the entry. A rise is noted for `_reopen_new_copies`."""
    before = entry.get("finding") or {}
    if entry.get("status") != "open" or "count" not in before:
        entry.pop("partial", None)
        return finding
    places = {_place(item) for item in finding.get("instances") or []}
    kept = [{**item, "unseen": True} for item in before.get("instances") or []
            if _place(item) not in places and unproven_reason(record, {**{key: value for key, value in finding.items() if key not in ONE_PLACE},
                                                                       "path": item.get("path"), "web_key": item.get("key")}) is not None]
    counted = {**finding, "count": int(finding["count"]) + len(kept), "instances": [*(finding.get("instances") or []), *kept][:100]} if kept else finding
    previous, now = int(before.get("count") or 1), int(counted["count"])
    if now < previous:
        entry["partial"] = {"at": stamp, "run_id": record["id"], "from": previous, "to": now}
    elif now > previous:
        rising[finding["fingerprint"]] = now
    return counted


def _reopen_new_copies(data_dir: Path, record: dict, rising: dict[str, int]) -> None:
    """A triage decision covers the copies there were when it was taken: one more copy puts the finding back to open,
    with a note, whatever was decided."""
    if not rising:
        return
    decisions = triage.load(data_dir).get(asset_key(record), {})
    back = {digest: count for digest, count in rising.items() if (decisions.get(digest) or {}).get("status") not in (None, "open")
            and int((decisions[digest].get("count") or 1)) < count}
    for digest, count in back.items():
        triage.decide(data_dir, record, [digest], "open", user={"username": "sistema", "role": "admin"},
                      system_note=msg("findings.registry.new_copy", run=record["id"][:12], count=count,
                                      before=int(decisions[digest].get("count") or 1)))


def lane(origin: dict | None, finding: dict) -> tuple[str, ...]:
    """Who vouches for a finding and what kind of look saw it: an import's tool (and category) or Pitangus's own runs,
    and a web finding's kind of scan (`web.coverage`). An entry only ever moves or folds within its lane: a scan of
    one kind can't tell what another kind saw, nor can one tool speak for another's findings."""
    from pitangus.modules.findings.canonical import kind_of
    origin = origin or {}
    owner = ("import", str(origin.get("tool") or "").lower(), str(origin.get("category") or "")) if origin.get("kind") == "import" else ("pitangus",)
    return (*owner, kind_of(finding))


def _rekey(entries: dict, findings: list[Finding], origin: dict | None = None) -> dict[str, str]:
    """A finding known by another fingerprint before (`identity.formers`) keeps its entry: it moves to the current
    fingerprint. An entry is found by its own fingerprint or by a name its finding carried. When both exist (the two
    were the same finding all along), the former folds into the current one, whose own triage wins. Only within the
    finding's lane (`lane`; `origin`: the run's, `_origin`): an engine fingerprint two kinds of web scan share never
    hands one kind's entry, nor its first run, to the other. A secret named by its value takes an entry named by a
    value only through that value's names (a master key rotation, a formula that changed: `identity.may_take`), never
    through its engine's fingerprint, which any value in that place has. Returns {former: current}."""
    moved = {}
    present = {finding["fingerprint"] for finding in findings}
    lanes = {digest: lane(entry.get("origin"), entry.get("finding") or {}) for digest, entry in entries.items()}
    known: dict[tuple, list[str]] = {}     # every entry known by a name (copies stored apart may share one)
    for digest, entry in entries.items():
        for name in own_names(entry.get("finding") or {}):
            if name != digest:
                known.setdefault((lanes[digest], name), []).append(digest)
    for finding in findings:
        digest, mine = finding["fingerprint"], lane(origin, finding)
        if digest in entries and lanes[digest] != mine:
            continue
        # A value's own identity too: an entry stored under another fingerprint may know the value by it (v1).
        names = [(name, False) for name in own_names(finding) if of_value(finding) or name != digest]
        for former, legacy in [*names, *((name, True) for name in legacy_formers(finding))]:
            direct = [former] if former != digest and former in entries and lanes[former] == mine else []
            for target in direct or known.get((mine, former), []):
                # A fingerprint this same run reports is a finding of its own, never a former name of another.
                if target == digest or target in moved or target in present or target not in entries \
                        or not may_take(finding, entries[target].get("finding") or {}, legacy):
                    continue
                if digest in entries:
                    entries.pop(target)
                else:
                    entries[digest] = entries.pop(target)
                    lanes[digest] = mine
                moved[target] = digest
    return moved


def carry_over(data_dir: Path, key: str, moved: dict[str, str], kept: Collection[str] = ()) -> None:
    """What hangs off a finding's former fingerprint (triage, Jira issue, requested verification) also answers to
    the new one. Copied, not moved: older runs still show the former fingerprint. Several folded into one never relax
    its triage (`triage.fold`) nor drop an issue. `kept`: new fingerprints that already had an entry of their own."""
    if not moved:
        return
    from pitangus.modules.findings import tickets, verifications
    triage.carry_over(data_dir, key, moved, kept)
    tickets.carry_over(data_dir, key, moved)
    verifications.carry_over(data_dir, key, moved)
    _log.info("registry_rekeyed", extra={"reason": f"{key}: {len(moved)}"})


def _own_pr(entry: dict, pull: dict) -> bool:
    origin = entry.get("origin") or {}
    return origin.get("kind") == "pr" and origin.get("pr") == pull.get("number") and not origin.get("merged")


def _origin(record: RunRecord, imported: dict | None) -> dict:
    if imported is not None:
        return {"kind": "import", "tool": imported.get("tool"), **({"category": imported["category"]} if imported.get("category") else {})}
    if record["type"] == "pr_review":
        pull = record.get("pull_request") or {}
        return {"kind": "pr", "pr": pull.get("number"), "branch": pull.get("head_ref")}
    return {"kind": "advisory"} if record["type"] == "advisory_watch" else {"kind": "scan"}


def apply(data_dir: Path, record: RunRecord) -> dict:
    """Adds a finished run to its repository's registry. Idempotent per run."""
    if record.get("type") not in FINDING_RUNS or record.get("status") not in ("completed", "incomplete"):
        return {}
    record = cast(RunRecord, web_keys.keyed(record))   # a web scan's pages by their keys (shared/web_keys.py), once
    key = asset_key(record)
    stamp = record.get("finished_at") or record["created_at"]
    pull = record.get("pull_request") or {}
    kind = record["type"]
    imported = (record.get("trigger") or {}) if kind in IMPORT_RUNS else None
    with _locked(data_dir, key) as state:
        if record["id"] in state.setdefault("applied", []):
            return {"opened": 0, "fixed": 0}
        state["name"] = (record.get("source") or {}).get("name") or state.get("name")
        entries = state["findings"]
        had = set(entries)
        if kind == "pr_review":
            # A PR review records what the PR brings: the main branch's entries, their families and counts, are only
            # the full scans' to change (the PR's own entries, from an earlier review of it, are its to update).
            own = {digest: entry for digest, entry in entries.items() if _own_pr(entry, pull)}
            mine = [item for item in record.get("findings", []) if item["fingerprint"] not in had or item["fingerprint"] in own]
            moved = _rekey(own, mine, _origin(record, imported))
            for digest in moved:
                entries.pop(digest, None)
            entries.update(own)
            present = {item["fingerprint"]: item for item in mine}
        else:
            moved = _rekey(entries, [*record.get("findings", []), *(record.get("excluded_findings") or [])], _origin(record, imported))
            present = {item["fingerprint"]: item for item in record.get("findings", [])}
        kept = {digest for digest in moved.values() if digest in had}
        identities_before = _identities(entries)
        rising: dict[str, int] = {}
        opened = fixed = 0
        new: list[str] = []
        reopened: list[str] = []
        fixed_now: list[str] = []
        for digest, finding in present.items():
            entry = entries.get(digest)
            if entry is None:
                entry = entries[digest] = {"first_seen": stamp, "first_run": record["id"], "origin": _origin(record, imported)}
                opened += 1
                new.append(digest)
            elif entry["status"] == "fixed":
                opened += 1
                new.append(digest)
                reopened.append(digest)
                entry["reopened_at"] = stamp
                # How long it stayed fixed: a finding that comes back within days was likely never gone (health()).
                entry["fixed_for_days"] = _days_between((entry.get("fixed") or {}).get("at"), stamp)
            if record["type"] in FULL_SCANS:
                entry["origin"] = {"kind": "scan"}  # already on the main branch
            if "count" in finding:
                finding = _counted(entry, finding, record, stamp, rising)
            entry.update(status="open", finding=_clean(finding), last_seen=stamp, last_run=record["id"])
            # Every engine that ever saw it: each one must look again before its absence proves anything.
            entry["detected_by"] = sorted({*(entry.get("detected_by") or []), *detected_by(finding)})
            entry.pop("fixed", None)
            entry.pop("excluded", None)
            if digest_now := rule_digest(record, finding):
                entry["rule_digest"] = digest_now  # a later run with the rule changed proves nothing (configuration_cause)
        excluded_now = set()
        if record["type"] in FULL_SCANS or imported is not None:
            for finding in record.get("excluded_findings") or []:
                digest = finding["fingerprint"]
                if digest in present:
                    continue
                excluded_now.add(digest)
                entry = entries.setdefault(digest, {"first_seen": stamp, "first_run": record["id"], "origin": _origin(record, imported)})
                entry.update(status="excluded", finding=_clean(finding), excluded=_exclusion(finding, stamp),
                             last_seen=stamp, last_run=record["id"])
                if digest_now := rule_digest(record, finding):
                    entry["rule_digest"] = digest_now
        # An incomplete scan can't prove something disappeared: it fixes nothing.
        complete = record.get("status") == "completed"
        blind = blind_engines(record)
        mode = settings.text("PITANGUS_COVERAGE_MODE")
        candidates: dict[str, Message] = {}      # what this run would fix, and how
        legacy: set[str] = set()                 # what the rules before the coverage contract fix
        proven: set[str] = set()                 # what the owner engine proved gone (coverage contract)
        unproven: dict[str, str] = {}            # open findings absent but not proven gone, and why
        causes: dict[str, dict] = {}             # of those, the ones the run's configuration left unchecked: what changed
        for digest, entry in entries.items():
            if digest in present:
                continue
            # A withheld secret that a complete scan no longer sees, even without the filters, is gone.
            if entry["status"] != "open" and not (record["type"] in FULL_SCANS and _withheld(entry) and digest not in excluded_now):
                continue
            origin = entry.get("origin") or {}
            # A new advisory affects the main branch: the next full scan without it marks it fixed.
            if record["type"] in FULL_SCANS and (origin.get("kind") in ("scan", "advisory") or origin.get("merged")):
                how = msg("findings.registry.gone_from_scan", date=stamp[:10])
            elif record["type"] == "pr_review" and origin.get("kind") == "pr" and origin.get("pr") == pull.get("number"):
                how = msg("findings.registry.fixed_in_pr", commit=str(pull.get("head_sha") or "")[:7], number=pull.get("number"))
            elif imported is not None and imported.get("scope") == "full" and origin.get("kind") == "import" \
                    and str(origin.get("tool") or "").lower() == str(imported.get("tool") or "").lower() \
                    and (origin.get("category") or None) == (imported.get("category") or None):
                how = msg("findings.registry.gone_from_import", tool=imported.get("tool"), date=stamp[:10])
            else:
                continue
            finding, seen = entry.get("finding") or {}, entry.get("rule_digest")
            if other_kind(record, finding):
                continue
            # Turning a rule or an engine off, or changing a rule, proves nothing gone: in every mode.
            engines_ = entry.get("detected_by") or ()
            if complete and not unseen(finding, blind, engines_) and covers(record, finding, engines_) and configuration_cause(record, finding, seen) is None \
                    and not indistinct(record, finding, engines_):
                legacy.add(digest)
            reason = unproven_reason(record, finding, seen, engines_)
            if reason is None:
                proven.add(digest)
            elif entry["status"] == "open":
                unproven[digest] = reason
                if reason == "configuration":
                    causes[digest] = {"cause": configuration_cause(record, finding, seen), "rule": finding.get("rule_id"),
                                      "engine": owner_of(finding)}
            candidates[digest] = how
        control = state.setdefault("control", {})
        # The engines of the asset's last scan, and whether each was blind (health()).
        control["last_tools"] = [{"name": tool.get("name"), "blind": blind_tool(tool, (record.get("coverage") or {}).get(str(tool.get("name") or "").lower()))}
                                 for tool in (record.get("summary") or {}).get("tools") or []]
        if mode == "on":
            chosen = _held_or_released(control, record, stamp, sorted(proven), entries, set(present))
            _mark_unseen(entries, unproven, present, stamp, causes)
        else:
            chosen = sorted(legacy)
            # Without the coverage contract only what the configuration left unchecked is said: it is never fixed either.
            _mark_unseen(entries, dict.fromkeys(causes, "configuration"), present, stamp, causes)
            if mode == "shadow":  # what the coverage contract would have done, for the upgrade gate
                control["shadow"] = {"run": record["id"], "at": stamp, "legacy": len(legacy), "proven": len(proven),
                                     "legacy_only": sorted(legacy - proven)[:50], "proven_only": sorted(proven - legacy)[:50],
                                     "unseen": len(unproven), "would_hold": _would_hold(len(proven), entries)}
        for digest in chosen:
            entry = entries[digest]
            entry.update(status="fixed", fixed={"at": stamp, "run_id": record["id"], "how": candidates[digest], "auto": True})
            entry.pop("excluded", None)
            entry.pop("unseen", None)
            fixed += 1
            fixed_now.append(digest)
        if settings.text("PITANGUS_IDENTITY_MODE") == "shadow":
            # What one identity per problem would have opened and found gone, next to what this run did (upgrade gate).
            now = {str(item.get("identity")) for item in present.values() if item.get("identity")}
            before_open = {identity for identity, status in identities_before.items() if status == "open"}
            control["identity_shadow"] = {"run": record["id"], "at": stamp, "opened": opened, "fixed": len(chosen),
                                          "v2_opened": len(now - set(identities_before)), "v2_gone": len(before_open - now),
                                          "families": len(now)}
        if record["type"] in FULL_SCANS:  # each full scan's fixes, for the spike metric (health())
            control["fixes"] = [*control.get("fixes", [])[-(HEALTH_RUNS - 1):], {"run": record["id"], "at": stamp, "count": fixed}]
        state["applied"] = state["applied"][-500:] + [record["id"]]
        _save(data_dir, state, set(moved))
    carry_over(data_dir, key, moved, kept)
    _reopen_manual(data_dir, record, set(present))
    _reopen_new_copies(data_dir, record, rising)
    if opened or fixed:
        _log.info("registry_updated", extra={"run_id": record["id"], "reason": f"{key}: {opened} abiertos, {fixed} remediados"})
    return {"opened": opened, "fixed": fixed, "new": new, "reopened": reopened, "fixed_now": fixed_now}


def _exclusion_moves(state: dict, active: list[str]) -> list[tuple[dict, str | None]]:
    """The findings a set of excluded paths moves: (entry, the pattern that excludes it), or (entry, None) for an
    excluded one that no longer is under any of them and reopens."""
    from pitangus.modules.findings.exclusions import excluded
    moves: list[tuple[dict, str | None]] = []
    for entry in state["findings"].values():
        pattern = excluded((entry.get("finding") or {}).get("path", ""), active)
        if entry.get("status") == "open" and pattern:
            moves.append((entry, pattern))
        elif entry.get("status") == "excluded" and not pattern and not _withheld(entry):
            moves.append((entry, None))
    return moves


def apply_exclusions(data_dir: Path, key: str, active: list[str], *, when: str) -> dict:
    """Excluded paths changed: open findings under them become excluded; excluded ones no longer under them reopen."""
    moved = {"excluded": 0, "reopened": 0}
    with _locked(data_dir, key) as state:
        for entry, pattern in _exclusion_moves(state, active):
            if pattern:
                entry.update(status="excluded", excluded={"pattern": pattern, "at": when})
                moved["excluded"] += 1
            else:
                entry["status"] = "open"
                entry.pop("excluded", None)
                moved["reopened"] += 1
        if moved["excluded"] or moved["reopened"]:
            _save(data_dir, state)
    return moved


PREVIEW_PATHS = 5


def preview_exclusions(data_dir: Path, key: str, active: list[str]) -> dict:
    """What `apply_exclusions` would move, without moving anything: how many findings, how many distinct paths they are
    in and the first few of those paths."""
    moves = _exclusion_moves(load(data_dir, key), active)

    def paths(reopening: bool) -> list[str]:
        return sorted({path for entry, pattern in moves if (pattern is None) == reopening and (path := str((entry.get("finding") or {}).get("path") or ""))})
    excluded, reopened = paths(False), paths(True)
    return {"excluded": sum(1 for _, pattern in moves if pattern), "reopened": sum(1 for _, pattern in moves if pattern is None),
            "excluded_paths": excluded[:PREVIEW_PATHS], "reopened_paths": reopened[:PREVIEW_PATHS],
            "excluded_path_count": len(excluded), "reopened_path_count": len(reopened)}


def pull_closed(data_dir: Path, key: str, number: int, *, merged: bool, when: str) -> int:
    """PR closed: unmerged, its findings are withdrawn; merged, they wait for the full scan."""
    changed = 0
    with _locked(data_dir, key) as state:
        for entry in state["findings"].values():
            origin = entry.get("origin") or {}
            if entry["status"] != "open" or origin.get("kind") != "pr" or origin.get("pr") != number:
                continue
            if merged:
                origin["merged"] = True
            else:
                entry.update(status="fixed", fixed={"at": when, "run_id": None, "how": msg("findings.registry.pr_closed", number=number), "auto": True})
            changed += 1
        if changed:
            _save(data_dir, state)
    return changed


def reset(data_dir: Path) -> None:
    """Empties every asset's registry, before rebuilding it from the runs (`runs/registry.py`)."""
    with db.transaction(data_dir) as connection:
        connection.execute(delete(registry_findings).where(registry_findings.c.tenant_id == TENANT))
        connection.execute(delete(registry_assets).where(registry_assets.c.tenant_id == TENANT))


LIFECYCLE_FIELDS = ("status", "origin", "first_seen", "last_seen", "first_run", "last_run", "fixed", "reopened_at", "excluded", "unseen")


def _record(key: str, name: str | None, entries: dict) -> dict:
    """An asset's registry entries shaped like a run."""
    items = [{**entry["finding"], "lifecycle": {field: entry.get(field) for field in LIFECYCLE_FIELDS}} for entry in entries.values()]
    return {"id": f"{VIEW_PREFIX}{key}", "type": "repository_scan", "status": "completed",
            "created_at": max([entry.get("last_seen") or "" for entry in entries.values()] or [""]),
            "source": {"uid": key if key.startswith("github#") else None, "id": key, "name": name or key},
            "findings": items, "summary": {}, "steps": [], "owasp_coverage": [], "limitations": []}


def _bucket(item: dict) -> str:
    """The Findings tab an annotated finding falls under: open (including what triage dismissed), fixed or excluded."""
    if item["lifecycle"]["status"] == "excluded":
        return "excluded"
    return "fixed" if item["lifecycle"]["status"] == "fixed" or item["triage"]["status"] == "fixed" else "open"


def view(data_dir: Path, key: str, *, status: str = "open") -> dict:
    """The repository's state shaped like a run, so it is viewed, triaged and exported the same way.

    `open`: what is still there (including what triage dismissed, which the table filters separately);
    `fixed`: fixed, automatically or by hand; `excluded`: under excluded paths; `all`: everything.
    """
    state = load(data_dir, key)
    annotated = triage.annotate(data_dir, _record(key, state.get("name"), state["findings"]))
    days = sla.policy(data_dir)["days"]
    sla.annotate(annotated["findings"], days)
    # An unverified finding (`unseen`) counts in no deadline or indicator: nobody can say it's still there.
    deadlines = {**sla.counts([item for item in annotated["findings"] if not item["lifecycle"].get("unseen")]), "days": days}
    if status != "all":
        annotated["findings"] = [item for item in annotated["findings"] if _bucket(item) == status]
    return {**annotated, "type": "asset_state", "control": control_of(data_dir, key),
            "summary": {**annotated["summary"], "lifecycle": summarize(data_dir, key), "candidates": len(annotated["findings"]),
                        "kpis": kpis.count([item for item in annotated["findings"] if not item["lifecycle"].get("unseen")]), "sla": deadlines}}


def summarize(data_dir: Path, key: str) -> dict:
    """Open (really pending), fixed and dismissed, taking triage into account."""
    return _summarize(load(data_dir, key)["findings"], triage.load_asset(data_dir, key))


def _summarize(entries: dict, decisions: dict) -> dict:
    """The asset's counts. An open finding no scan could check lately (`unseen`) is `unverified`, apart from `open` and
    its severities: neither still there nor gone as far as anyone can prove. `unverified_stale`: those unseen for
    PITANGUS_UNSEEN_WARN_SCANS scans or more, which the panel warns about; `unverified_configuration`: those the scan's
    configuration left unchecked (a rule or an engine off, a rule changed), warned about at once and apart."""
    counts = {"open": 0, "fixed": 0, "suppressed": 0, "excluded": 0, "unverified": 0, "unverified_stale": 0, "unverified_configuration": 0,
              "by_severity": dict.fromkeys(("critical", "high", "medium", "low"), 0), "from_pr": 0}
    stale = settings.integer("PITANGUS_UNSEEN_WARN_SCANS")
    for digest, entry in entries.items():
        manual = (triage.effective(decisions.get(digest)) or {}).get("status", "open")
        if entry["status"] == "excluded":
            counts["excluded"] += 1
        elif entry["status"] == "fixed" or manual == "fixed":
            counts["fixed"] += 1
        elif manual in triage.SUPPRESSED:
            counts["suppressed"] += 1
        elif entry.get("unseen"):
            counts["unverified"] += 1
            configured = entry["unseen"].get("reason") == "configuration"
            counts["unverified_configuration"] += configured
            counts["unverified_stale"] += not configured and int(entry["unseen"].get("scans") or 0) >= stale
        else:
            counts["open"] += 1
            severity = entry["finding"].get("severity")
            if severity in counts["by_severity"]:
                counts["by_severity"][severity] += 1
            if (entry.get("origin") or {}).get("kind") == "pr":
                counts["from_pr"] += 1
    return counts


# Findings one scoped view serves at most: the most urgent first; the counts always cover the whole scope.
SCOPE_FINDINGS_MAX = 10_000
_ACTION_RANK = {"act": 0, "attend": 1, "track": 2}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def scoped_view(data_dir: Path, assets: list[dict], *, status: str = "open", limit: int = SCOPE_FINDINGS_MAX) -> dict:
    """Several assets' states in one view (`assets`: [{"key", "name", "kind"}], e.g. a portfolio scope), each finding
    tagged with its `asset`. Like `view`, plus `by_asset` (each asset's counts) and, past `limit`, only the most urgent
    findings with `truncated` set: the counts (`summary.lifecycle`, `summary.kpis`, `by_asset`, `total`) always cover
    everything. The registry, triage, verifications and Jira links are read once for the whole scope, and only the
    findings served get their fix guides and verifications."""
    from pitangus.modules.findings import tickets, verifications
    keys = list(dict.fromkeys(row["key"] for row in assets))
    entries: dict[str, dict] = {key: {} for key in keys}
    names: dict[str, str] = {}
    if keys:
        with db.transaction(data_dir) as connection:
            names = dict(connection.execute(select(registry_assets.c.asset_key, registry_assets.c.name)
                                            .where(registry_assets.c.tenant_id == TENANT, registry_assets.c.asset_key.in_(keys))).all())
            for key, digest, entry in connection.execute(
                    select(registry_findings.c.asset_key, registry_findings.c.fingerprint, registry_findings.c.entry)
                    .where(registry_findings.c.tenant_id == TENANT, registry_findings.c.asset_key.in_(keys))):
                entries[key][digest] = entry
    decisions, links = triage.load(data_dir), tickets.load_links(data_dir)
    days = sla.policy(data_dir)["days"]
    rows = {row["key"]: row for row in assets}
    lifecycle = {"open": 0, "fixed": 0, "suppressed": 0, "excluded": 0, "by_severity": dict.fromkeys(("critical", "high", "medium", "low"), 0), "from_pr": 0}
    every: list[dict] = []
    by_asset: list[dict] = []
    whole: dict[str, list[dict]] = {}  # each asset's findings, every tab: what its fix guides look at
    for key in keys:
        name = rows[key].get("name") or names.get(key) or key
        kind = rows[key].get("kind") or ("image" if key.startswith("image:") else "domain" if key.startswith("domain:") else "repository")
        found = sla.annotate(triage.annotate(data_dir, _record(key, name, entries[key]), decisions, guides=False)["findings"], days)
        whole[key] = found
        ticketed = links.get(key) or {}
        shown = [{**item, "asset": {"key": key, "name": name, "kind": kind},
                  **({"ticket": ticketed[item["fingerprint"]]} if item["fingerprint"] in ticketed else {})}
                 for item in found if status == "all" or _bucket(item) == status]
        every.extend(shown)
        counts = _summarize(entries[key], decisions.get(key) or {})
        for field in ("open", "fixed", "suppressed", "excluded", "from_pr"):
            lifecycle[field] += counts[field]
        for level, value in counts["by_severity"].items():
            lifecycle["by_severity"][level] += value
        by_asset.append({"key": key, "name": name, "kind": kind, "open": counts["open"], "critical": counts["by_severity"]["critical"],
                         "high": counts["by_severity"]["high"], "fixed": counts["fixed"], "suppressed": counts["suppressed"],
                         "excluded": counts["excluded"], "shown": len(shown)})
    by_asset.sort(key=lambda row: (-row["critical"], -row["open"], str(row["name"]).casefold()))
    every.sort(key=lambda item: (_ACTION_RANK.get((item.get("priority") or {}).get("action"), 3), _SEVERITY_RANK.get(item.get("severity"), 5),
                                 str(item["asset"]["name"]).casefold(), item["fingerprint"]))
    served = every[:limit]
    requested: dict = verifications.load(data_dir) if served else {}
    for key in dict.fromkeys(item["asset"]["key"] for item in served):  # in place: `served` keeps its order
        triage.enrich(data_dir, key, [item for item in served if item["asset"]["key"] == key], among=whole[key],
                      requested=requested.get(key) or {}, entries=entries[key])
    return {"id": "scope", "type": "asset_scope", "status": "completed",
            "created_at": max([str(item["lifecycle"].get("last_seen") or "") for item in every] or [""]),
            "findings": served, "total": len(every), "truncated": len(every) > limit, "by_asset": by_asset,
            "summary": {"lifecycle": lifecycle, "candidates": len(every), "kpis": kpis.count(every), "sla": {**sla.counts(every), "days": days}},
            "steps": [], "owasp_coverage": [], "limitations": []}


PACKAGES_SHOWN = 5  # per affected repository in the CVE tracker


def assets_with_cve(data_dir: Path, cve: str, *, limit: int, offset: int) -> dict:
    """Repositories with a finding that cites this CVE, to answer "does it affect me?" from the tracker (GIN index).

    One page of repositories, ordered by key: `{items, total, limit, offset}`."""
    cites = (registry_findings.c.tenant_id == TENANT, registry_findings.c.cves.any_() == cve)
    with db.transaction(data_dir) as connection:
        total = connection.execute(select(func.count(func.distinct(registry_findings.c.asset_key))).where(*cites)).scalar_one()
        keys = list(connection.execute(select(registry_findings.c.asset_key).where(*cites).group_by(registry_findings.c.asset_key)
                                       .order_by(registry_findings.c.asset_key).limit(limit).offset(offset)).scalars())
        by_asset: dict[str, list[dict]] = {key: [] for key in keys}
        for key, entry in connection.execute(select(registry_findings.c.asset_key, registry_findings.c.entry)
                                             .where(*cites, registry_findings.c.asset_key.in_(keys))):
            by_asset[key].append(entry)
        names = dict(connection.execute(select(registry_assets.c.asset_key, registry_assets.c.name)
                                        .where(registry_assets.c.tenant_id == TENANT, registry_assets.c.asset_key.in_(keys))).all())

    def packages(hits: list[dict]) -> list:
        # Titles may be messages: dedup and sort by their text, return the values as stored (rendered by the reader).
        labels = {}
        for entry in hits:
            value = (entry["finding"].get("package") or {}).get("name") or entry["finding"].get("title", "")
            labels.setdefault(text(value, "en"), value)
        return [labels[label] for label in sorted(labels)][:PACKAGES_SHOWN]
    items = [{"asset": key, "name": names.get(key) or key,
              "open": sum(1 for entry in hits if entry.get("status") == "open"),
              "fixed": sum(1 for entry in hits if entry.get("status") == "fixed"),
              "packages": packages(hits)}
             for key, hits in by_asset.items()]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


def open_cves(data_dir: Path) -> frozenset[str]:
    """CVEs still open in some asset (minus what triage dismissed), for "only mine" in the tracker."""
    decisions = triage.load(data_dir)
    found: set[str] = set()
    with db.transaction(data_dir) as connection:
        for key, digest, cves in connection.execute(select(registry_findings.c.asset_key, registry_findings.c.fingerprint, registry_findings.c.cves)
                                                    .where(registry_findings.c.tenant_id == TENANT, registry_findings.c.status == "open",
                                                           func.cardinality(registry_findings.c.cves) > 0)):
            if (triage.effective((decisions.get(key) or {}).get(digest)) or {}).get("status", "open") in triage.SUPPRESSED:
                continue
            found.update(cve for cve in cves if cve.startswith("CVE-"))
    return frozenset(found)
