"""Data format version and ordered data migrations at start-up.

The version lives in PostgreSQL (document `data-version`): a restored database carries its own version, and no process
needs a shared disk to know it. A `data-version.json` left on disk by earlier versions is adopted once.

Rules for whoever changes the format of stored data (see docs/development.md):
1. Readers tolerate the old format (missing fields, old types): reading never breaks.
2. Rewriting data takes a migration appended to MIGRATIONS: idempotent, declaring the data/ paths it touches (they are
   copied first), with a test on old data.
3. A published migration is never reordered or deleted: the version is its position.

A new install starts at the latest version without migrating. Data from a newer version than the code (a rollback)
refuses to start: writing it with the old format could damage it.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from sqlalchemy import select, text as sql

from pitangus.shared import db, documents
from pitangus.shared import log as logging_setup
from pitangus.shared.i18n import msg, text

_log = logging_setup.get("migrations")
VERSION_DOCUMENT = "data-version"
VERSION_FILE = "data-version.json"  # earlier versions kept it on disk: adopted once
BACKUPS = "backups"
KEEP_BACKUPS = 5


@dataclass(frozen=True)
class Migration:
    name: str
    touches: tuple[str, ...]  # paths relative to data/, copied before migrating
    apply: Callable[[Path], object]


# Data migrations (in order; a published one is never reordered or deleted). Alembic migrations own the table
# schema; this is for data transformations that are not just schema. The list starts empty with the first public
# release (PostgreSQL): there are no earlier installs to convert.


def _cra_opt_in(data_dir: Path) -> int:
    """The CRA kit became opt-in (off by default): a workspace that already marked products keeps it on, with a
    history entry that says why. Events need no rewrite: their readers treat a missing assessment as `to_assess`."""
    from pitangus.shared import documents
    with documents.lock(data_dir, "cra"):
        state = documents.load(data_dir, "cra", {})
        if not isinstance(state, dict) or "policy" in state or not isinstance(state.get("products"), dict) or not state["products"]:
            return 0
        entry = {"enabled": True, "by": "pitangus", "at": datetime.now(timezone.utc).isoformat(), "reason": msg("compliance.cra.policy.migrated")}
        documents.save(data_dir, "cra", {**state, "policy": {**entry, "history": [entry]}})
    return 1


def _seal_totp_seeds(data_dir: Path) -> int:
    """TOTP seeds were stored in the clear; they are sealed with the master key."""
    from pitangus.modules.identity.auth import Users
    return Users(data_dir).seal_clear_totp()


def _vault_to_database(data_dir: Path) -> int:
    """The secrets vault moved from config/secrets.vault to the database; the session key, from data/auth/."""
    from pitangus.modules.identity.auth import import_session_key
    from pitangus.shared import vault
    return vault.import_file() + import_session_key(data_dir)


def _cve_copy_to_database(data_dir: Path) -> int:
    """The local NVD copy moved from data/feeds/cves.sqlite to the database."""
    from pitangus.modules.intel import cve_db
    return cve_db.import_sqlite(data_dir)


def _watch_and_registry_to_tables(data_dir: Path) -> int:
    """The `pr-watch` and `repo-registry` documents became tables: one row per repository and per reviewed PR."""
    from pitangus.modules.pullrequests import watch
    from pitangus.modules.sources import assets
    moved = assets.import_document(data_dir)
    payload = documents.load(data_dir, "pr-watch", None)
    if isinstance(payload, dict):
        watch._save(data_dir, {section: payload.get(section) if isinstance(payload.get(section), dict) else {}
                               for section in ("repositories", "reviewed", "branches")})
        documents.delete(data_dir, "pr-watch")
        moved += 1
    return moved


def _jira_routing(data_dir: Path) -> int:
    """The single Jira project and issue type became a destination and the default rule (manual); the credential stays
    in the vault as it was."""
    from pitangus.modules.integrations import jira_routing
    from pitangus.shared.vault import VaultError, get
    try:
        stored = get("jira")
    except VaultError:
        return 0
    if not isinstance(stored, dict) or not isinstance(stored.get("project"), str) or not stored["project"]:
        return 0
    return int(jira_routing.adopt_legacy(data_dir, {"key": stored["project"], "name": stored.get("project_name")},
                                         {"name": stored.get("issue_type") or "Task"}, by=stored.get("saved_by") or "pitangus"))


def _brand_rename(data_dir: Path) -> int:
    """Tamandua became Pitangus: Jira field mappings saved with the old variable source keep working."""
    if not isinstance(documents.load(data_dir, "jira-routing"), dict):
        return 0
    renamed = 0
    with documents.edit(data_dir, "jira-routing", {}) as stored:
        for destination in stored.get("destinations") or []:
            mapping = destination.get("mapping") if isinstance(destination, dict) else None
            for spec in mapping.values() if isinstance(mapping, dict) else []:
                if isinstance(spec, dict) and spec.get("source") == "tamandua":
                    spec["source"] = "pitangus"
                    renamed += 1
    return renamed


def _domains_to_table(data_dir: Path) -> int:
    """The `domains` document became a table, with how long each TXT proof counts."""
    from pitangus.modules.sources import domains
    return domains.import_document(data_dir)


def _scan_schedule_rules(data_dir: Path) -> int:
    """A domain's weekly scan became a rule (daily, weekdays or days of the month, at a time in a timezone): the
    existing ones keep their weekday and time, in UTC."""
    from pitangus.modules.sources import domains
    return domains.adopt_schedule_rules(data_dir)


def _registry_identities(data_dir: Path) -> int:
    """Registry entries get their canonical identity (findings/canonical.py) where the stored finding holds all it needs:
    a dependency advisory (its package and advisory). Others wait for their next scan, which carries what the identity
    reads (the code, the resource's address, the secret's HMAC) and moves the entry by its former fingerprints."""
    from sqlalchemy import update
    from pitangus.modules.findings.canonical import identity_of
    from pitangus.modules.findings.tables import registry_findings
    changed = 0
    with db.transaction(data_dir) as connection:
        rows = connection.execute(select(registry_findings.c.asset_key, registry_findings.c.fingerprint, registry_findings.c.entry)
                                  .where(registry_findings.c.tenant_id == db.TENANT)).all()
        for row in rows:
            entry = row.entry if isinstance(row.entry, dict) else {}
            finding = entry.get("finding") if isinstance(entry.get("finding"), dict) else None
            if not finding or finding.get("identity") or finding.get("scanner") != "sca" or not (finding.get("package") or {}).get("name"):
                continue
            entry = {**entry, "finding": {**finding, "identity": identity_of(finding)}}
            connection.execute(update(registry_findings).where(registry_findings.c.tenant_id == db.TENANT, registry_findings.c.asset_key == row.asset_key,
                                                               registry_findings.c.fingerprint == row.fingerprint).values(entry=entry))
            changed += 1
    return changed


def _registry_rule_baseline(data_dir: Path) -> int:
    """Runs record the rules they applied, and each registry entry the digest of the rule it was last seen with, so a
    rule that changes never fixes what it stops reporting (findings/registry.configuration_cause). Entries stored before
    get the digests of the rules they were seen with: those of 0.13.1 (scanning/rule_set.baseline). A rule without one
    (added since, or a custom one) leaves its entries unstamped until their next scan."""
    from sqlalchemy import update
    from pitangus.modules.findings.registry import owner_of
    from pitangus.modules.findings.tables import registry_findings
    from pitangus.modules.scanning import rule_set, secret_rules
    known = rule_set.baseline()
    changed = 0
    with db.transaction(data_dir) as connection:
        rows = connection.execute(select(registry_findings.c.asset_key, registry_findings.c.fingerprint, registry_findings.c.entry)
                                  .where(registry_findings.c.tenant_id == db.TENANT)).all()
        for row in rows:
            entry = row.entry if isinstance(row.entry, dict) else {}
            finding = entry.get("finding") if isinstance(entry.get("finding"), dict) else None
            if not finding or entry.get("rule_digest"):
                continue
            owner, rule = owner_of(finding), str(finding.get("rule_id") or "")
            built_in_secret = (owner == "betterleaks" or (owner == "trivy" and finding.get("scanner") == "secrets")) \
                and not rule.startswith(secret_rules.ENGINE_PREFIX)
            digest = known["opengrep"].get(rule) if owner == "opengrep" else known["secrets"] if built_in_secret else None
            if not digest:
                continue
            connection.execute(update(registry_findings).where(registry_findings.c.tenant_id == db.TENANT, registry_findings.c.asset_key == row.asset_key,
                                                               registry_findings.c.fingerprint == row.fingerprint)
                               .values(entry={**entry, "rule_digest": digest}))
            changed += 1
    return changed


def _mask_stored_secrets(data_dir: Path) -> int:
    """No value in what is already stored (shared/masking.py, shared/render.py as of today): every finding of every run
    (its excluded ones too) and of the registry sanitized again, every other text of a run rendered, and a code finding
    whose snippet changes keeps the identity (and the identity anywhere) its code had. The run's report and SARIF are
    rendered again from the sanitized run; pending notifications have their texts rendered and their URLs too."""
    from sqlalchemy import update
    from pitangus.modules.findings.tables import registry_findings
    from pitangus.modules.integrations.tables import outbox
    from pitangus.modules.runs.store import _row, render_repository_report, render_repository_sarif
    from pitangus.modules.runs.tables import runs
    from pitangus.shared.masking import mask, mask_url, sanitize_findings, sanitize_record
    from pitangus.shared.render import URL_IN_TEXT

    def urls(value, key=""):
        """A pending notification as written before: what it says rendered as text, its format (block types, URLs) kept."""
        if isinstance(value, str):
            return mask(value) if key in ("text", "title", "message", "body", "summary", "fallback", "description") \
                else URL_IN_TEXT.sub(lambda found: mask_url(found.group(0)), value)
        if isinstance(value, list):
            return [urls(item, key) for item in value]
        if isinstance(value, dict):
            return {name: urls(item, name) for name, item in value.items()}
        return value

    changed = 0
    with db.transaction(data_dir) as connection:
        for row in connection.execute(select(runs.c.id, runs.c.record, runs.c.report, runs.c.sarif).where(runs.c.tenant_id == db.TENANT)).all():
            if not isinstance(row.record, dict):
                continue
            record = sanitize_record(_web_identities(row.record))
            if record == row.record:
                continue
            values: dict = {"record": record, "row": _row(record)}
            if row.report is not None:
                try:
                    values["report"] = render_repository_report(record)
                except Exception:  # noqa: BLE001 - a record today's renderer can't read keeps its text, rendered
                    values["report"] = "\n".join(mask(line) for line in row.report.split("\n"))
            if row.sarif is not None:
                try:
                    values["sarif"] = render_repository_sarif(record)
                except Exception:  # noqa: BLE001
                    values["sarif"] = None
            connection.execute(update(runs).where(runs.c.tenant_id == db.TENANT, runs.c.id == row.id).values(**values))
            changed += 1
        rows = connection.execute(select(registry_findings.c.asset_key, registry_findings.c.fingerprint, registry_findings.c.entry)
                                  .where(registry_findings.c.tenant_id == db.TENANT)).all()
        assets: dict[str, list] = {}
        for row in rows:
            if isinstance(row.entry, dict) and isinstance(row.entry.get("finding"), dict):
                assets.setdefault(row.asset_key, []).append(row)
        for key, members in assets.items():
            stored = [_web_identity(row.entry["finding"]) for row in members]
            for row, finding in zip(members, sanitize_findings(stored)):
                if finding != row.entry["finding"]:
                    connection.execute(update(registry_findings).where(
                        registry_findings.c.tenant_id == db.TENANT, registry_findings.c.asset_key == key,
                        registry_findings.c.fingerprint == row.fingerprint).values(entry={**row.entry, "finding": finding}))
                    changed += 1
        for row in connection.execute(select(outbox.c.id, outbox.c.payload).where(outbox.c.tenant_id == db.TENANT, outbox.c.status == "pending")).all():
            payload = urls(row.payload)
            if payload != row.payload:
                connection.execute(update(outbox).where(outbox.c.tenant_id == db.TENANT, outbox.c.id == row.id).values(payload=payload))
                changed += 1
    return changed


def _web_identity(finding: dict) -> dict:
    """A web finding stored without its identity (0.13, `v1`) gets the one it has now, before its evidence is rendered:
    a web finding's identity reads its evidence."""
    if finding.get("scanner") != "dast" or finding.get("identity"):
        return finding
    from pitangus.modules.findings.canonical import identity_of
    return {**finding, "identity": identity_of(finding)}


def _web_identities(record: dict) -> dict:
    return {**record, **{key: [_web_identity(item) if isinstance(item, dict) else item for item in record[key]]
                         for key in ("findings", "excluded_findings") if isinstance(record.get(key), list)}}


def _mask_stored_credentials(data_dir: Path) -> int:
    """No credential value in what is stored, however it was written (shared/masking.py as of 0.14): what
    `mask_stored_secrets` masks, now also unquoted values of credential-named keys (`password: v`, `DB_PASSWORD=v`), the
    string arguments of calls that open a connection or log in, what URLs carry (token-shaped path segments, matrix
    parameters, credential query and fragment values; a web finding's location too, whose identity reads it masked),
    every text of a run whatever its key (steps, progress, limitations, details, the causes an engine's stderr went
    into) and of pending notifications; a secret or a hard-coded credential loses its snippet. Every finding keeps its
    identity: a code finding's is pinned before its snippet changes, a web finding's reads its URL masked."""
    return _mask_stored_secrets(data_dir)


def _web_location_keys(data_dir: Path) -> int:
    """Every URL stored is rendered like any other (0.14, shared/render.py `url`), a web finding's location, its
    instances, a run's target and the pages and units a web scan lists too, and the runs' listing rows with them. What
    a web finding's identity and coverage read of its URLs is pinned first, from the location form they were stored in
    (shared/web_keys.py, which reads that form as it read the URL in clear): its key, its instances' keys and its
    identity, and a web scan's page keys. So every identity, template and coverage stays what it was."""
    return _mask_stored_secrets(data_dir)


def _render_stored_texts(data_dir: Path) -> int:
    """Structure, never values, in what is stored (0.14, shared/render.py): every snippet, message, detail, cause and
    other text of every run and of the registry rendered again by the one renderer, which keeps punctuation and the
    words of its lexicon and nothing for its position; an imported SARIF's rule texts too; zizmor's snippets (the
    workflow's YAML) become their route of keys; reports and SARIF rendered again from the runs. Every finding keeps
    its identity: a code finding's, and its identity anywhere in the repository, are pinned from the snippet as it
    was stored before it changes; a web finding's reads its location, which keeps its form. Run again by
    `render_stored_texts_lexicon` when the renderer changed what it keeps."""
    from sqlalchemy import update
    from pitangus.modules.findings.tables import registry_findings
    from pitangus.modules.runs.tables import runs
    changed = 0
    with db.transaction(data_dir) as connection:
        for row in connection.execute(select(runs.c.id, runs.c.record).where(runs.c.tenant_id == db.TENANT)).all():
            if isinstance(row.record, dict):
                record = _zizmor_routes(row.record)
                if record != row.record:
                    connection.execute(update(runs).where(runs.c.tenant_id == db.TENANT, runs.c.id == row.id).values(record=record))
        for row in connection.execute(select(registry_findings.c.asset_key, registry_findings.c.fingerprint, registry_findings.c.entry)
                                      .where(registry_findings.c.tenant_id == db.TENANT)).all():
            if isinstance(row.entry, dict) and isinstance(row.entry.get("finding"), dict):
                finding = _zizmor_route(row.entry["finding"])
                if finding is not row.entry["finding"]:
                    connection.execute(update(registry_findings).where(
                        registry_findings.c.tenant_id == db.TENANT, registry_findings.c.asset_key == row.asset_key,
                        registry_findings.c.fingerprint == row.fingerprint).values(entry={**row.entry, "finding": finding}))
    changed += _mask_stored_secrets(data_dir)
    return changed


def _zizmor_route(finding: dict) -> dict:
    """A zizmor finding stored with the YAML it pointed at as its snippet (before 0.14): the identities pinned from it
    and the snippet reduced to zizmor's note (its route was never stored). Any other finding as it is (the same object)."""
    from pitangus.shared.code_identity import anywhere_identity, content_identity
    snippet = finding.get("snippet")
    if str(finding.get("tool") or "").lower() != "zizmor" or not isinstance(snippet, str) or not snippet:
        return finding
    # A route of keys already (`jobs:` / `build:`), with or without zizmor's note (`# …`), or the note alone: as stored
    # since 0.14, or by this migration.
    if all(line.rstrip().endswith(":") or line.lstrip().startswith("#") for line in snippet.split("\n") if line.strip()):
        return finding
    _, _, note = snippet.partition("\n")
    pinned = {**finding, **({} if finding.get("identity") else {"identity": content_identity(finding)}),
              **({} if "anywhere" in finding else {"anywhere": anywhere_identity(finding)})}
    if note.strip():
        pinned["snippet"] = f"# {note.strip()}"
    else:
        del pinned["snippet"]
    return pinned


def _zizmor_routes(record: dict) -> dict:
    changed = False
    lists = {}
    for key in ("findings", "excluded_findings"):
        items = record.get(key)
        if isinstance(items, list):
            updated = [_zizmor_route(item) if isinstance(item, dict) else item for item in items]
            if any(new is not old for new, old in zip(updated, items)):
                lists[key], changed = updated, True
    return {**record, **lists} if changed else record


CREDENTIAL_CWES = frozenset({798, 259, 321, 522})


def _named_by_value(finding: object, keys: list[str]) -> object:
    """`finding` marked as named by its value (`value_formers`, findings/identity.py) when its identity is a secret's
    keyed HMAC made with one of `keys` (it starts with the key's id); anything else as it is."""
    if not isinstance(finding, dict) or isinstance(finding.get("value_formers"), list) or finding.get("unlinkable"):
        return finding
    identity, cwe = str(finding.get("identity") or ""), finding.get("cwe")
    cwes = cwe if isinstance(cwe, list) else []
    secret = finding.get("scanner") == "secrets" or bool(CREDENTIAL_CWES & {item for item in cwes if isinstance(item, int)})
    return {**finding, "value_formers": []} if secret and len(identity) == 64 and any(identity.startswith(kid) for kid in keys) else finding


def _secret_value_identities(data_dir: Path) -> int:
    """Secrets named by their value since 0.14 say so (`value_formers`), in the registry and in stored runs (a PR's
    baseline, the dashboard's history): only their value's names link them from now on, never their engine's
    fingerprint, which another value in the same place shares (findings/identity.may_take). Recognised by the id of the
    key that made the identity, the current one or PITANGUS_PREVIOUS_MASTER_KEY's; one made with another key is left
    as stored before values were read, which the next scan that reads its value adopts once."""
    from sqlalchemy import update
    from pitangus.modules.findings.tables import registry_findings
    from pitangus.modules.runs.tables import runs
    from pitangus.modules.scanning import secret_identity
    keys = secret_identity.key_ids()
    if not keys:
        return 0
    changed = 0
    with db.transaction(data_dir) as connection:
        for row in connection.execute(select(runs.c.id, runs.c.record).where(runs.c.tenant_id == db.TENANT)).all():
            if not isinstance(row.record, dict):
                continue
            record = {**row.record, **{field: [_named_by_value(item, keys) for item in row.record[field]]
                                       for field in ("findings", "excluded_findings") if isinstance(row.record.get(field), list)}}
            if record != row.record:
                connection.execute(update(runs).where(runs.c.tenant_id == db.TENANT, runs.c.id == row.id).values(record=record))
                changed += 1
        for row in connection.execute(select(registry_findings.c.asset_key, registry_findings.c.fingerprint, registry_findings.c.entry)
                                      .where(registry_findings.c.tenant_id == db.TENANT)).all():
            entry = row.entry if isinstance(row.entry, dict) else {}
            finding = _named_by_value(entry.get("finding"), keys)
            if finding is not entry.get("finding"):
                connection.execute(update(registry_findings).where(registry_findings.c.tenant_id == db.TENANT, registry_findings.c.asset_key == row.asset_key,
                                                                   registry_findings.c.fingerprint == row.fingerprint).values(entry={**entry, "finding": finding}))
                changed += 1
    return changed


def _registry_coverage_units(data_dir: Path) -> int:
    """Each registry entry's finding declares the coverage units it lives in (shared/coverage_units): stored before,
    they are derived from its path, conservatively: a dependency's from the path of every lockfile it was seen in (its
    project, manifest and lockfile together), anything else's from its file. A web finding keeps its page. The registry
    also derives them from the path whenever it reads one, so an entry this misses still compares by unit."""
    from sqlalchemy import update
    from pitangus.modules.findings.tables import registry_findings
    from pitangus.shared import coverage_units
    changed = 0
    with db.transaction(data_dir) as connection:
        rows = connection.execute(select(registry_findings.c.asset_key, registry_findings.c.fingerprint, registry_findings.c.entry)
                                  .where(registry_findings.c.tenant_id == db.TENANT)).all()
        for row in rows:
            entry = row.entry if isinstance(row.entry, dict) else {}
            finding = entry.get("finding") if isinstance(entry.get("finding"), dict) else None
            if not finding or finding.get("scanner") == "dast" or not finding.get("path"):
                continue
            units = coverage_units.of_finding(finding)
            if units == finding.get("units"):
                continue
            connection.execute(update(registry_findings).where(registry_findings.c.tenant_id == db.TENANT, registry_findings.c.asset_key == row.asset_key,
                                                               registry_findings.c.fingerprint == row.fingerprint)
                               .values(entry={**entry, "finding": {**finding, "units": units}}))
            changed += 1
    return changed


def _project_units(finding: object) -> object:
    """A finding with its units as 0.14 declares them now: a dependency's, the project folder of each file it was seen
    in (`project://<folder>`), whatever package manager the folder holds; `deps://<ecosystem>/<folder>` is gone. The
    same object when nothing changes."""
    from pitangus.shared import coverage_units
    if not isinstance(finding, dict) or finding.get("scanner") == "dast" or "units" not in finding:
        return finding
    units = coverage_units.of_finding(finding)
    return finding if units == finding.get("units") else {**finding, "units": units}


def _dependency_project_units(data_dir: Path) -> int:
    """Stored findings (the registry's and the runs') declare a dependency's unit as its project folder, read from its
    paths: what deleting any of its files proves is decided by what the engines inventoried there
    (coverage_units.dependency_unexamined), never by a list of package managers."""
    from sqlalchemy import update
    from pitangus.modules.findings.tables import registry_findings
    from pitangus.modules.runs.tables import runs
    changed = 0
    with db.transaction(data_dir) as connection:
        for row in connection.execute(select(runs.c.id, runs.c.record).where(runs.c.tenant_id == db.TENANT)).all():
            if not isinstance(row.record, dict):
                continue
            record = {**row.record, **{field: [_project_units(item) for item in row.record[field]]
                                       for field in ("findings", "excluded_findings") if isinstance(row.record.get(field), list)}}
            if record != row.record:
                connection.execute(update(runs).where(runs.c.tenant_id == db.TENANT, runs.c.id == row.id).values(record=record))
                changed += 1
        for row in connection.execute(select(registry_findings.c.asset_key, registry_findings.c.fingerprint, registry_findings.c.entry)
                                      .where(registry_findings.c.tenant_id == db.TENANT)).all():
            entry = row.entry if isinstance(row.entry, dict) else {}
            finding = _project_units(entry.get("finding"))
            if finding is not entry.get("finding"):
                connection.execute(update(registry_findings).where(registry_findings.c.tenant_id == db.TENANT, registry_findings.c.asset_key == row.asset_key,
                                                                   registry_findings.c.fingerprint == row.fingerprint).values(entry={**entry, "finding": finding}))
                changed += 1
    return changed


MIGRATIONS: tuple[Migration, ...] = (
    Migration("cra_opt_in", (), _cra_opt_in),
    Migration("seal_totp_seeds", (), _seal_totp_seeds),
    Migration("vault_to_database", (), _vault_to_database),
    Migration("cve_copy_to_database", (), _cve_copy_to_database),
    Migration("watch_and_registry_to_tables", (), _watch_and_registry_to_tables),
    Migration("jira_routing", (), _jira_routing),
    Migration("brand_rename", (), _brand_rename),
    Migration("domains_to_table", (), _domains_to_table),
    Migration("scan_schedule_rules", (), _scan_schedule_rules),
    Migration("registry_identities", (), _registry_identities),
    Migration("registry_rule_baseline", (), _registry_rule_baseline),
    Migration("mask_stored_secrets", (), _mask_stored_secrets),
    Migration("mask_stored_credentials", (), _mask_stored_credentials),
    Migration("secret_value_identities", (), _secret_value_identities),
    Migration("registry_coverage_units", (), _registry_coverage_units),
    Migration("dependency_project_units", (), _dependency_project_units),
    # Last, as in a scan: identities and units are read from what was stored, then every text is rendered.
    Migration("render_stored_texts", (), _render_stored_texts),
    # The renderer keeps a word only when it is a common word (0.14): what the one before kept for its position goes.
    Migration("render_stored_texts_lexicon", (), _render_stored_texts),
    # Locations are rendered like any URL: what the web identity and coverage read is pinned from them first.
    Migration("web_location_keys", (), _web_location_keys),
)
LATEST = len(MIGRATIONS)


class DataTooNew(RuntimeError):
    """`message` is what people read; str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


def _legacy_version(data_dir: Path) -> int | None:
    try:
        return int(json.loads((data_dir / VERSION_FILE).read_text(encoding="utf-8"))["version"])
    except FileNotFoundError:
        return None
    except (OSError, ValueError, KeyError, TypeError):
        return 0  # unreadable: assume the oldest; migrations are idempotent


def _state(data_dir: Path) -> dict | None:
    state = documents.load(data_dir, VERSION_DOCUMENT)
    return state if isinstance(state, dict) and isinstance(state.get("version"), int) else None


def current(data_dir: Path) -> int | None:
    """The stored version; None on a new install (no version anywhere)."""
    state = _state(data_dir)
    return state["version"] if state else _legacy_version(data_dir)


def _has_data(data_dir: Path) -> bool:
    from pitangus.modules.identity.tables import users
    from pitangus.modules.runs.tables import runs
    with db.transaction(data_dir) as connection:
        return any(connection.execute(select(table.c.tenant_id).where(table.c.tenant_id == db.TENANT).limit(1)).first()
                   for table in (users, runs, documents.documents))


def _write(data_dir: Path, version: int, history: list[dict]) -> None:
    documents.save(data_dir, VERSION_DOCUMENT, {"version": version, "history": history[-50:]})


def _history(data_dir: Path) -> list[dict]:
    state = _state(data_dir)
    if state:
        return list(state.get("history") or [])
    try:
        return list(json.loads((data_dir / VERSION_FILE).read_text(encoding="utf-8")).get("history") or [])
    except (OSError, ValueError, AttributeError):
        return []


@contextmanager
def _locked(data_dir: Path):
    """The API, the workers and a CLI command can start at once: one migrates, the rest wait. A session-level lock
    on its own connection, so each migration still commits on its own and a failure resumes from there."""
    key = int.from_bytes(hashlib.sha256(f"{db.TENANT}\x1fdata-migrations\x1f{db.schema_for(data_dir)}".encode()).digest()[:8],
                         "big", signed=True)
    connection = db.engine().connect()
    try:
        connection.execute(sql("SELECT pg_advisory_lock(:key)"), {"key": key})
        connection.commit()
        yield
    finally:
        connection.execute(sql("SELECT pg_advisory_unlock(:key)"), {"key": key})
        connection.commit()
        connection.close()


def _backup(data_dir: Path, pending: list[tuple[int, Migration]]) -> Path | None:
    """Copies what the pending migrations will touch. Only that: runs/ or the CVE database can weigh gigabytes."""
    paths = sorted({path for _, migration in pending for path in migration.touches if (data_dir / path).exists()})
    if not paths:
        return None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = data_dir / BACKUPS / f"antes-de-v{pending[-1][0]}-{stamp}"
    for relative in paths:
        source, destination = data_dir / relative, target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, destination, symlinks=True)
        else:
            shutil.copy2(source, destination)
    old = sorted(path for path in (data_dir / BACKUPS).iterdir() if path.is_dir() and path.name.startswith("antes-de-v"))
    for path in old[:-KEEP_BACKUPS]:
        shutil.rmtree(path, ignore_errors=True)
    return target


def upgrade(data_dir: Path) -> list[str]:
    """Brings the database (Alembic schema) and data/ to the latest version; returns the data/ migrations it ran."""
    from pitangus.app import database
    database.upgrade()  # first of all: data migrations and the application read from these tables
    data_dir.mkdir(parents=True, exist_ok=True)
    state = _state(data_dir)
    if state and state["version"] == LATEST:
        return []
    with _locked(data_dir):
        version = current(data_dir)  # another process may have migrated while this one waited for the lock
        if _state(data_dir) is None and version is not None:
            _write(data_dir, version, _history(data_dir))  # adopt the on-disk version of earlier releases
        if version is None and not _has_data(data_dir):
            _write(data_dir, LATEST, [{"version": LATEST, "at": datetime.now(timezone.utc).isoformat(), "name": "fresh install"}])
            return []
        version = version or 0
        if version > LATEST:
            raise DataTooNew(msg("cli.migrations.data_too_new", path=str(data_dir), version=version, latest=LATEST))
        pending = [(number, migration) for number, migration in enumerate(MIGRATIONS, start=1) if number > version]
        if not pending:
            return []
        backup = _backup(data_dir, pending)
        history = _history(data_dir)
        done = []
        for number, migration in pending:
            result = migration.apply(data_dir)
            history.append({"version": number, "name": migration.name, "at": datetime.now(timezone.utc).isoformat(),
                            "result": result if isinstance(result, (int, str)) else None,
                            "backup": str(backup.relative_to(data_dir)) if backup else None})
            _write(data_dir, number, history)  # after each step: if something fails, it resumes from there
            done.append(migration.name)
        _log.warning("data_migrated", extra={"reason": f"datos migrados al formato {LATEST}: {', '.join(done)}"
                                                        + (f" (copia previa en {backup})" if backup else "")})
        return done
