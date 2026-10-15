"""The four 0.14 contracts together, where each one's output is the next one's input.

- Structure, never values (shared/render.py) over what the others now write: the files the secret engines newly read,
  the matches an inline comment allowed (`suppressed_inline`, `places`), the units findings declare (`units`, a
  dependency project's `project://` unit), the value identities (`value_formers`) and the coverage reasons. Rendering a
  stored run again changes nothing: no field is handled twice into something else.
- Value identity (findings/identity.may_take) with the files the secret engines didn't read before (committed
  dependencies, hidden folders): a secret found there for the first time is new; it never takes an earlier entry.
- Coverage units (shared/coverage_units) with the files a secret engine passed over: an unexamined file never fixes
  what was found in it, whichever list made the engine pass over it.
- The data migrations of all three in sequence, in any order, on a registry with entries of 0.13 and of 0.14 before
  them: each idempotent, the result the same whatever the order.
- A secret nobody could read (unlinkable) with every engine that saw it: fixed only when all of them looked again and
  none reports one like it in its place. The secret filter with value identity: a value set aside names, links and
  inherits nothing. The secret filter with coverage: setting a value aside never changes what an engine examined.
"""

import base64
import hashlib
import itertools
import json
import os
import tempfile
import unittest
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from hypothesis import HealthCheck, example, given, settings, strategies as st

from pitangus.app import data_migrations as migrations
from pitangus.modules.findings import canonical, registry, triage
from pitangus.modules.findings.identity import of_value, unlinkable
from pitangus.modules.runs.local import render_prompt
from pitangus.modules.runs.store import load_run, render_repository_report, render_repository_sarif, save_and_apply
from pitangus.modules.scanning import engine_contract, engines, secret_identity
from pitangus.modules.scanning.secret_filter import outside_code, verdict
from pitangus.modules.scanning.secret_location import entropy
from pitangus.shared import coverage_units, documents
from pitangus.shared.i18n import text
from pitangus.shared.masking import sanitize_record
from test_secret_filter import ANY_PATHS, PASSWORD as GENERIC_PASSWORD, SECRET_KEYS, SECRET_LAYOUTS, benign, shaped_secrets
from test_secret_pass_coverage import SCALE, TOKEN, TOKEN_SHAPE, SecretEngines as Engines, _mounted, _token, committed_path, scan, unproven
from value_oracle import leaked

ADMIN = {"username": "ana", "role": "admin"}
MODES = {"PITANGUS_IDENTITY_MODE": "v2", "PITANGUS_COVERAGE_MODE": "on", "PITANGUS_FIX_HOLD_MINIMUM": "1000"}
TOKENS = [_token(0, seed) for seed in (11, 12, 13)]   # sk_live_…, built at run time


class SecretEngines(Engines):
    """As in test_secret_pass_coverage, with Trivy's `Match` and `Offset` as Trivy writes them (one `*` per byte of the
    value, the offset in bytes), so its secrets are named by their value too."""

    def __call__(self, key, arguments, snapshot=None, **options):
        done = super().__call__(key, arguments, snapshot, **options)
        if key != "trivy" or not done.stdout:
            return done
        payload = json.loads(done.stdout)
        for result in payload["Results"]:
            data = (snapshot / result["Target"]).read_bytes().decode("utf-8", "surrogateescape")
            for secret in result["Secrets"]:
                lines = data.splitlines(keepends=True)
                line = lines[secret["StartLine"] - 1].rstrip("\n")
                found = TOKEN_SHAPE.search(line)
                before = "".join(lines[:secret["StartLine"] - 1]) + line[:found.start()]
                secret.update({"Offset": len(before.encode("utf-8", "surrogateescape")),
                               "Match": line[:found.start()] + "*" * len(found.group(0).encode()) + line[found.end():]})
        return done.__class__(done.args, done.returncode, json.dumps(payload), done.stderr)


def _files(app: str, dependency: str, lambda_: str) -> dict[str, bytes]:
    return {"src/app.js": f'const stripe = "{app}";\n'.encode(),
            "node_modules/@acme/internal/index.js": f'const stripe = "{dependency}";\n'.encode(),
            "deploy/lambda/node_modules/@acme/internal/index.js": f'const stripe = "{lambda_}";\n'.encode(),
            "src/keys.js": f'const a = 1;\nconst stripe = "{TOKENS[0]}"; // gitleaks:allow\n'.encode(),
            "web/package.json": b'{"dependencies": {"left-pad": "1.3.0"}}\n', "README.md": b"# app\n"}


def _secrets(record: dict, path: str) -> list[str]:
    return sorted({item["fingerprint"] for item in record["findings"] if item["scanner"] == "secrets" and item["path"] == path})


class Registry(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name) / "data"
        self.data_dir.mkdir()
        self.clock = datetime.now(timezone.utc)
        modes = patch.dict(os.environ, MODES)
        modes.start()
        self.addCleanup(modes.stop)

    def save(self, record: dict, mode: str = "v2") -> tuple[dict, dict]:
        self.clock += timedelta(hours=1)
        with patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": mode}):
            return save_and_apply(self.data_dir, {**record, "finished_at": self.clock.isoformat()}, created_at=self.clock.isoformat(), quiet=True)


class NewlyReadFilesTests(Registry):
    """R2 × R4: the secret engines now read committed dependencies. What they find there for the first time opens as
    new and never takes an entry stored before (0.13's, adopted once by its engine fingerprint, is another file's)."""

    def test_a_secret_first_read_in_a_committed_dependency_is_new_and_takes_nothing(self):
        app, dependency, lambda_ = TOKENS[1], TOKENS[2], _token(1, 99)
        files = _files(app, dependency, lambda_)
        # As 0.13 stored it: its engines passed over node_modules, and its secrets carried no value identity.
        before = scan(files, SecretEngines(hidden={"betterleaks": frozenset({"node_modules"}), "trivy": frozenset({"node_modules"})}))
        self.assertEqual(_secrets(before, "node_modules/@acme/internal/index.js"), [])
        legacy = {**before, "findings": [{key: value for key, value in item.items() if key not in ("identity", "value_formers", "units")}
                                         for item in before["findings"]]}
        saved, _ = self.save(legacy, "v1")
        (stored,) = _secrets(saved, "src/app.js")
        triage.decide(self.data_dir, saved, [stored], "accepted", reason="Rotation planned for the next release", user=ADMIN)

        now = scan(files, SecretEngines())
        saved, changes = self.save(now)
        read = _secrets(saved, "node_modules/@acme/internal/index.js") + _secrets(saved, "deploy/lambda/node_modules/@acme/internal/index.js")
        self.assertEqual(len(read), 2, saved["findings"])
        self.assertEqual(sorted(changes["new"]), sorted(read))
        self.assertEqual(changes["fixed_now"], [])
        (app_now,) = _secrets(saved, "src/app.js")
        key = next(iter(registry.asset_keys(self.data_dir)))
        self.assertEqual((triage.load(self.data_dir).get(key) or {}).get(app_now, {}).get("status"), "accepted")
        for fingerprint in read:
            self.assertIsNone((triage.load(self.data_dir).get(key) or {}).get(fingerprint))
            self.assertTrue(of_value(registry.load(self.data_dir, key)["findings"][fingerprint]["finding"]))

    def test_the_same_value_in_a_dependency_is_the_same_secret_a_different_one_never_is(self):
        """A value is one secret wherever it is: the copy in node_modules is another place of it, not a new one; a
        different value there is new even when everything around it is the same."""
        app = TOKENS[1]
        saved, _ = self.save(scan(_files(app, app, TOKENS[2]), SecretEngines()))
        identities = {item["path"]: canonical.identity_of(item) for item in saved["findings"] if item["scanner"] == "secrets"}
        if "node_modules/@acme/internal/index.js" in identities:   # folded into the src/app.js finding otherwise
            self.assertEqual(identities["node_modules/@acme/internal/index.js"], identities["src/app.js"])
        self.assertNotEqual(identities.get("deploy/lambda/node_modules/@acme/internal/index.js"), identities["src/app.js"])


class UnexaminedNeverFixesTests(Registry):
    """R3 × R4: a secret's unit is its file. When a secret engine passes over that file (by any list of its own, which
    Pitangus never sees), the file is unexamined for it and nothing it or another engine found there is fixed, whether
    it is still there: every engine that saw a finding must have looked again."""

    @settings(max_examples=8 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
    @given(TOKEN, committed_path, st.booleans(), st.sampled_from(["betterleaks", "trivy", "both"]))
    @example(TOKENS[1], "node_modules/@acme/internal/index.js", False, "both")
    @example(TOKENS[1], "deploy/lambda/node_modules/@acme/internal/index.js", True, "trivy")
    def test_a_file_an_engine_passed_over_never_fixes_its_secret(self, token, path, kept, skipping):
        self.setUp()
        files = {path: f'k = "{token}"\n'.encode(), "app.py": b"x = 1\n"}
        first, _ = self.save(scan(files, SecretEngines()))
        found = _secrets(first, path)
        self.assertTrue(found, (path, first["steps"]))
        marker = path.rsplit("/", 1)[-1]
        hidden = {engine: frozenset({marker}) for engine in ("betterleaks", "trivy") if skipping in (engine, "both")}
        then = {**files, path: f'k = "{token}"\n'.encode() if kept else b"k = 1\n"}
        _, changes = self.save(scan(then, SecretEngines(hidden=hidden)))
        # An engine that saw a finding (its owner, or one it was also detected by) passed over its file: never fixed.
        # A finding every engine that saw it read again without the secret: fixed.
        for item in first["findings"]:
            if item["fingerprint"] in found and set(registry.detected_by(item)) & set(hidden):
                self.assertNotIn(item["fingerprint"], changes["fixed_now"], (path, hidden, item["tool"]))
            elif item["fingerprint"] in found and not kept:
                self.assertIn(item["fingerprint"], changes["fixed_now"], (path, hidden, item["tool"]))

    def test_a_file_read_again_and_without_its_secret_does_fix_it(self):
        path = "node_modules/@acme/internal/index.js"
        first, _ = self.save(scan({path: f'k = "{TOKENS[1]}"\n'.encode(), "app.py": b"x = 1\n"}, SecretEngines()))
        _, changes = self.save(scan({path: b"k = 1\n", "app.py": b"x = 1\n"}, SecretEngines()))
        self.assertTrue(set(_secrets(first, path)) <= set(changes["fixed_now"]), changes)


class RenderedOnceTests(Registry):
    """R1 over R2, R3 and R4: no value in anything the run stores or prints, the structure they added intact, and a
    stored run rendered again is the same run."""

    def test_what_the_other_contracts_write_is_rendered_as_structure_and_only_once(self):
        app, dependency, lambda_ = TOKENS[1], TOKENS[2], _token(3, 7)
        record = scan(_files(app, dependency, lambda_), SecretEngines())
        saved, _ = self.save(record)
        stored = load_run(self.data_dir, saved["id"])
        outputs = [json.dumps(stored, ensure_ascii=False), render_repository_report(stored), render_repository_sarif(stored),
                   render_prompt({"findings": [], "comparison": None, "scan": stored}, locale="en"),
                   json.dumps(registry.load(self.data_dir, next(iter(registry.asset_keys(self.data_dir)))), ensure_ascii=False)]
        for output in (item if isinstance(item, str) else json.dumps(item, ensure_ascii=False) for item in outputs):
            for value in (app, dependency, lambda_, TOKENS[0]):
                self.assertNotIn(value, output)
                self.assertEqual(leaked(value, output, numbers=8), [], value)   # no fragment of it either
        # R4: the inline comment's places, by file and line, in the limitations and the coverage.
        self.assertTrue(any("src/keys.js:2" in text(item, "en") for item in stored["limitations"]), stored["limitations"])
        self.assertIn("src/keys.js:2", stored["coverage"]["betterleaks"]["suppressed_inline"])
        # R3: the manifest left without its lockfile is named, not rendered away.
        self.assertTrue(any("web/package.json" in text(step.get("detail"), "en") for step in stored["steps"] if step.get("detail")),
                        [step.get("detail") for step in stored["steps"]])
        # R2 and R3: what the registry reads, as the scan declared it.
        for item in stored["findings"]:
            self.assertEqual(item["units"], coverage_units.of_finding({key: value for key, value in item.items() if key != "units"}), item)
            if item["scanner"] == "secrets":
                self.assertIsInstance(item.get("value_formers"), list, item)
        # Rendering again changes nothing.
        self.assertEqual(sanitize_record(stored), stored)

    @settings(max_examples=20 * SCALE, deadline=None)
    @given(st.from_regex(r"[A-Za-z0-9]{8,32}", fullmatch=True), st.sampled_from(["en", "es"]))
    @example("a8F3kQ9zL2xW7pR4tY6uHj", "en")
    def test_what_the_other_rounds_added_is_structure_or_reads_as_said(self, folder, locale):
        """The lexicon renderer over what R2, R3, R4 and the secret filter now write: an unlinkable secret's marks, a
        project's unit, every engine's inventory by folder, the reasons a committed entry wasn't held and the filter's
        reasons are kept as written; the messages that carry them read in either language with their paths whole."""
        from pitangus.modules.scanning.engines import screened_detail
        from pitangus.shared.i18n import msg
        lock, entry = f"svc/{folder}/Cargo.lock", f"assets/{folder}.bin"
        finding = {"fingerprint": "b" * 64, "finding_id": "b" * 16, "scanner": "secrets", "tool": "betterleaks", "rule_id": "generic-api-key",
                   "path": f"svc/{folder}/.env", "line": 1, "identity": "k1" + "c" * 62, "unlinkable": True, "units": [f"svc/{folder}/.env"],
                   "also_detected_by": ["trivy"]}
        dependency = {"fingerprint": "d" * 64, "finding_id": "d" * 16, "scanner": "sca", "tool": "trivy", "rule_id": "CVE-2021-44228",
                      "path": lock, "line": 1, "units": [f"project://svc/{folder}"]}
        record = {"type": "repository_scan", "status": "completed", "findings": [finding, dependency],
                  "source": {"id": "github:org/app", "snapshot": {"committed": {"lfs_object": 1, "submodule": 1}}},
                  "coverage": {"trivy": {"examined": "*", "unexamined": {entry: "lfs_object", f"vendor/{folder}": "submodule"},
                                         "dependencies": {"inventoried": [f"svc/{folder}"], "uninventoried": [f"tools/{folder}"]}}},
                  "steps": [{"name": "Betterleaks 1.9.0", "status": "completed", "detail": screened_detail(Counter({"checksum": 2, "link": 1, "keyless": 1}))},
                            {"name": "snapshot", "status": "completed",
                             "detail": msg("scanning.repository.snapshot.not_held", detail="", count=2, paths=f"{entry}, vendor/{folder}")}]}
        rendered = sanitize_record(record)
        self.assertEqual(rendered["findings"], record["findings"])
        self.assertEqual((rendered["coverage"], rendered["source"]), (record["coverage"], record["source"]))
        self.assertEqual(sanitize_record(rendered), rendered)
        said = text(rendered["steps"][1]["detail"], locale)
        self.assertIn(entry, said)
        self.assertIn(f"vendor/{folder}", said)
        self.assertEqual(text(rendered["steps"][0]["detail"], locale), text(record["steps"][0]["detail"], locale))
        self.assertNotIn("***", text(rendered["steps"][0]["detail"], locale))

    @settings(max_examples=20 * SCALE, deadline=None)
    @given(st.sampled_from(sorted(coverage_units.ECOSYSTEMS)), st.from_regex(r"[A-Za-z0-9]{8,32}", fullmatch=True))
    @example("cargo", "a8F3kQ9zL2xW7pR4tY6uHj")
    def test_a_dependency_projects_unit_is_kept_whatever_its_folder_is_called(self, ecosystem, folder):
        """A folder name that looks random is still a folder: the unit keeps it, so the registry finds it examined."""
        manifest, locks = next(iter(coverage_units.ECOSYSTEMS[ecosystem].items()))
        name = f"app{manifest}" if manifest.startswith(".") else manifest
        lock = f"crates/{folder}/{sorted(locks)[0]}"
        finding = {"fingerprint": "a" * 64, "scanner": "sca", "tool": "trivy", "rule_id": "CVE-2021-44228", "path": lock}
        rendered = sanitize_record({"findings": [coverage_units.declare(dict(finding))]})["findings"][0]
        self.assertEqual(rendered["units"], [f"project://crates/{folder}"])
        record = {"type": "repository_scan", "status": "completed", "summary": {"tools": [{"name": "trivy", "status": "completed"}]},
                  "coverage": {"trivy": engine_contract.coverage([lock, f"crates/{folder}/{name}"])}}
        self.assertIsNone(registry.unproven_reason(record, rendered))


SECRET = "xoxb-" + "2339545089-2835763688579-cpP7BEXvfqZgimdS7jnqFCiI"
PASSWORD = "Mx7Lq2Wz9Rt"
NEW_STEPS = ("secret_value_identities", "registry_coverage_units", "dependency_project_units", "render_stored_texts", "web_location_keys")


def _stored(data_dir: Path) -> tuple[dict, dict]:
    """What the registry and the runs hold, comparable across data folders."""
    from sqlalchemy import select
    from pitangus.modules.findings.tables import registry_findings
    from pitangus.modules.runs.tables import runs
    from pitangus.shared import db
    with db.transaction(data_dir) as connection:
        entries = {row.fingerprint: row.entry for row in connection.execute(select(registry_findings.c.fingerprint, registry_findings.c.entry)
                                                                            .where(registry_findings.c.tenant_id == db.TENANT))}
        records = {row.id: row.record for row in connection.execute(select(runs.c.id, runs.c.record).where(runs.c.tenant_id == db.TENANT))}
    return entries, records


class MigrationSequenceTests(unittest.TestCase):
    """The 0.14 data migrations, on a registry holding what 0.13 stored (a secret under its engine fingerprint,
    zizmor's YAML, a multi-line fragment, a dependency in a lockfile) and what 0.14 stored before them (a secret with
    its value's identity, unmarked; a secret whose value couldn't be read, unlinkable)."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        modes = patch.dict(os.environ, {**MODES, "PITANGUS_MASTER_KEY": base64.b64encode(hashlib.sha256(b"ronda 3").digest()).decode()})
        modes.start()
        self.addCleanup(modes.stop)
        secret_identity._key.cache_clear()
        self.addCleanup(secret_identity._key.cache_clear)

    def prepared(self, name: str) -> Path:
        data_dir = Path(self.directory.name) / name
        data_dir.mkdir()
        position = [migration.name for migration in migrations.MIGRATIONS].index(NEW_STEPS[0])
        documents.save(data_dir, migrations.VERSION_DOCUMENT, {"version": position, "history": []})
        base = {"title": "A finding", "confidence": 8, "cwe": [], "owasp": [], "cve": [], "ghsa": [], "verdict": "candidate",
                "priority": {"action": "attend", "factors": []}, "remediation": "Fix it.", "package": None, "advisory": None, "reason": "Why."}
        value_identity = secret_identity.names(SECRET)
        stored = [
            {**base, "fingerprint": "1" * 64, "finding_id": "1" * 16, "scanner": "secrets", "tool": "betterleaks", "rule_id": "slack-bot-token",
             "path": "config/slack.env", "line": 3, "severity": "critical", "cwe": [798]},                           # 0.13
            {**base, "fingerprint": "2" * 64, "finding_id": "2" * 16, "scanner": "secrets", "tool": "betterleaks", "rule_id": "slack-bot-token",
             "path": "config/other.env", "line": 1, "severity": "critical", "cwe": [798], "identity": value_identity[0]},  # 0.14 unmarked
            {**base, "fingerprint": "3" * 64, "finding_id": "3" * 16, "scanner": "cicd", "tool": "zizmor", "rule_id": "excessive-permissions",
             "path": ".github/workflows/ci.yml", "line": 4, "severity": "medium",
             "snippet": f"build: steps: - run: docker login -u x -p {PASSWORD}\nthis job uses write-all permissions"},
            {**base, "fingerprint": "4" * 64, "finding_id": "4" * 16, "scanner": "sast", "tool": "opengrep", "rule_id": "x.y",
             "path": "config.json", "line": 2, "severity": "high", "snippet": f'{{\n  "contrasenia": "{PASSWORD}"\n}}'},
            {**base, "fingerprint": "5" * 64, "finding_id": "5" * 16, "scanner": "sca", "tool": "trivy", "rule_id": "CVE-2021-44228",
             "path": "services/a8F3kQ9zL2xW7pR4tY6uHj/gradle.lockfile", "line": 1, "severity": "critical",
             "package": {"name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1", "also_in": ["web/yarn.lock"]}},
            {**base, "fingerprint": "6" * 64, "finding_id": "6" * 16, "scanner": "secrets", "tool": "betterleaks", "rule_id": "slack-bot-token",
             "path": "config/third.env", "line": 2, "severity": "critical", "cwe": [798], "unlinkable": True,
             "identity": secret_identity.unlinkable("slack-bot-token", "config/third.env", b"SLACK=REDACTED")},  # 0.14 unlinkable
        ]
        record = {"schema_version": "0.3.0", "id": "f" * 32, "created_at": datetime.now(timezone.utc).isoformat(), "type": "repository_scan",
                  "status": "completed", "target": "org/api", "source": {"id": "github:org/api", "uid": "github#1", "name": "org/api", "provider": "github"},
                  "findings": stored, "steps": [], "owasp_coverage": [], "limitations": [f"engine said: password {PASSWORD}"], "context": "",
                  "summary": {"files": 5, "dependencies": 1, "candidates": 5, "severities": {}, "priorities": {}, "kev": 0, "fixable": 0, "tools": []}}
        from pitangus.modules.runs.store import _persist
        _persist(data_dir, record, render_repository_report(record), render_repository_sarif(record))
        registry._save(data_dir, {"asset": "github#1", "name": "org/api", "applied": [], "findings": {
            item["fingerprint"]: {"status": "open", "finding": item} for item in stored}})
        return data_dir

    def test_in_sequence_each_is_idempotent_and_together_they_keep_every_identity(self):
        data_dir = self.prepared("upgrade")
        before = {fingerprint: canonical.identity_of(entry["finding"]) for fingerprint, entry in _stored(data_dir)[0].items()}
        done = migrations.upgrade(data_dir)
        self.assertEqual([name for name in done if name in NEW_STEPS], list(NEW_STEPS))
        # The lexicon, then URLs like any, then no code at all.
        self.assertEqual(done[-3:], ["render_stored_texts_lexicon", "web_location_keys", "drop_stored_code"])
        entries, records = _stored(data_dir)
        for name in (*NEW_STEPS, "drop_stored_code"):
            self.assertEqual(getattr(migrations, f"_{name}")(data_dir), 0, name)
        self.assertNotIn('"snippet"', json.dumps([entries, records]))
        self.assertEqual(_stored(data_dir), (entries, records))
        self.assertEqual(migrations.upgrade(data_dir), [])
        findings = {fingerprint: entry["finding"] for fingerprint, entry in entries.items()}
        self.assertEqual({fingerprint: canonical.identity_of(item) for fingerprint, item in findings.items()}, before)
        self.assertEqual({fingerprint: entry["status"] for fingerprint, entry in entries.items()}, dict.fromkeys(before, "open"))
        # 0.13's secret is adopted once by the next scan that reads its value; 0.14's is its value's alone.
        self.assertFalse(of_value(findings["1" * 64]))
        self.assertTrue(of_value(findings["2" * 64]))
        # One whose value couldn't be read stays its own: never adopted as a value's, never a former name.
        self.assertFalse(of_value(findings["6" * 64]))
        self.assertTrue(findings["6" * 64]["unlinkable"])
        self.assertNotIn("value_formers", findings["6" * 64])
        self.assertEqual(findings["5" * 64]["units"], ["project://services/a8F3kQ9zL2xW7pR4tY6uHj", "project://web"])
        self.assertEqual(findings["3" * 64]["units"], [".github/workflows/ci.yml"])
        for value in (PASSWORD, SECRET):
            self.assertNotIn(value, json.dumps([entries, records]))
            self.assertEqual(leaked(value, json.dumps([entries, records]), numbers=8), [], value)

    def test_the_order_doesnt_change_the_result(self):
        results = []
        for number, order in enumerate(itertools.permutations(NEW_STEPS)):
            data_dir = self.prepared(f"order-{number}")
            for name in order:
                getattr(migrations, f"_{name}")(data_dir)
            entries, records = _stored(data_dir)
            results.append((order, entries, {key: {field: value for field, value in record.items() if field not in ("created_at",)}
                                             for key, record in records.items()}))
        for order, entries, records in results[1:]:
            self.assertEqual(entries, results[0][1], order)
            self.assertEqual(records, results[0][2], order)


class Reporting(SecretEngines):
    """As SecretEngines, but each engine may fail to say a value it found the way the value can be read back
    (`unreadable`: Betterleaks' entropy off, Trivy's offset missing), and Betterleaks also flags every place of the
    values in `flagged` (a lockfile digest, a placeholder…) under a generic rule, said so that their value is read."""

    def __init__(self, hidden=None, *, unreadable: frozenset[str] = frozenset(), flagged: tuple[str, ...] = ()):
        super().__init__(hidden)
        self.unreadable, self.flagged = unreadable, flagged

    def __call__(self, key, arguments, snapshot=None, **options):
        if key == "trivy" and "trivy" in self.unreadable:
            return Engines.__call__(self, key, arguments, snapshot, **options)
        done = super().__call__(key, arguments, snapshot, **options)
        if key != "betterleaks":
            return done
        out = _mounted(list(options.get("mounts") or []))["/out"] / "report.json"
        report = json.loads(out.read_text())
        inside = "files/" if snapshot.name.endswith(".credentials") else ""   # the secret-only copy, one folder down
        for path in sorted(path for path in self.read["betterleaks"] if (snapshot / inside / path).is_file()):   # this pass's copy
            text_ = (snapshot / inside / path).read_bytes().decode("utf-8", "surrogateescape")
            for number, line in enumerate(text_.splitlines(), 1):
                for value in self.flagged:
                    if value and value in line:
                        end = line.index(value) + len(value)
                        report.append({"RuleID": "generic-api-key", "File": f"/src/{inside}{path}", "StartLine": number, "EndLine": number,
                                       "StartColumn": 1, "EndColumn": len(line[:end].encode("utf-8", "surrogateescape")),
                                       "Match": line[:end].replace(value, "REDACTED"), "Secret": "REDACTED", "Entropy": entropy(value)})
        if "betterleaks" in self.unreadable:
            for item in report:
                item["Entropy"] = float(item["Entropy"]) + 0.5
        out.write_text(json.dumps(report))
        return done


def looked(record: dict, engine: str, path: str) -> bool:
    """Whether `engine` declares it examined `path` in `record` (a lockfile Trivy didn't parse, for one, it didn't)."""
    coverage = (record.get("coverage") or {}).get(engine) or {}
    return path not in (coverage.get("unexamined") or {}) and path not in ((coverage.get("by_scanner") or {}).get("secrets") or {})


ENGINE_SETS = st.sampled_from([frozenset(), frozenset({"betterleaks"}), frozenset({"trivy"}), frozenset({"betterleaks", "trivy"})])


class UnlinkableEveryEngineTests(Registry):
    """R2 (a secret whose value can't be read is unlinkable) × R3 (every engine that saw a finding must look again): a
    secret is fixed only when every engine that saw it read its file again, and, when it or what is reported in its
    place is unlinkable, only when none of them reports one there (its own engine, by its rule): two secrets that can't
    be told apart are indistinguishable, so one going proves nothing while the other stays."""

    @settings(max_examples=6 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
    @given(TOKEN, TOKEN, committed_path, ENGINE_SETS, ENGINE_SETS, ENGINE_SETS, st.sampled_from(["replaced", "removed"]))
    @example(TOKENS[1], TOKENS[2], "config/app.js", frozenset({"betterleaks", "trivy"}), frozenset({"betterleaks", "trivy"}), frozenset(), "replaced")
    @example(TOKENS[1], TOKENS[2], "config/app.js", frozenset(), frozenset({"betterleaks"}), frozenset(), "replaced")
    @example(TOKENS[1], TOKENS[2], "config/app.js", frozenset(), frozenset({"trivy"}), frozenset(), "replaced")   # the other engine can't tell
    @example(TOKENS[1], TOKENS[2], "config/app.js", frozenset({"trivy"}), frozenset(), frozenset({"trivy"}), "removed")
    @example(TOKENS[1], TOKENS[2], "node_modules/@acme/internal/index.js", frozenset({"betterleaks"}), frozenset(), frozenset(), "removed")
    def test_an_unlinkable_secret_is_fixed_only_when_nothing_like_it_is_left_and_every_engine_looked(
            self, a, b, path, first_unreadable, then_unreadable, skipping, change):
        self.setUp()
        if a == b:
            return
        files = {path: f'k = "{a}"\n'.encode(), "app.py": b"x = 1\n"}
        first, _ = self.save(scan(files, Reporting(unreadable=first_unreadable)))
        found = {item["fingerprint"]: item for item in first["findings"] if item["scanner"] == "secrets" and item["path"] == path}
        self.assertTrue(found, (path, first["steps"]))
        key = next(iter(registry.asset_keys(self.data_dir)))
        seen_by = {fingerprint: set(registry.detected_by(item, registry.load(self.data_dir, key)["findings"][fingerprint].get("detected_by") or ()))
                   for fingerprint, item in found.items()}
        marker = path.rsplit("/", 1)[-1]
        hidden = {engine: frozenset({marker}) for engine in skipping}
        then = {**files, path: f'k = "{b}"\n'.encode() if change == "replaced" else b"k = 1\n"}
        second, changes = self.save(scan(then, Reporting(hidden, unreadable=then_unreadable)))
        left = [item for item in second["findings"] if item["scanner"] == "secrets" and item["path"] == path]
        for fingerprint, item in found.items():
            passed_over = seen_by[fingerprint] & ({*skipping} | {engine for engine in seen_by[fingerprint] if not looked(second, engine, path)})
            # Reported in its place by its engine under its rule, or by any other engine that saw it, under any rule.
            alike = [other for other in left if (unlinkable(item) or unlinkable(other))
                     and ((registry.owner_of(other), other["rule_id"]) == (registry.owner_of(item), item["rule_id"])
                          or set(registry.detected_by(other)) & (seen_by[fingerprint] - {registry.owner_of(item)}))]
            if passed_over or alike:
                self.assertNotIn(fingerprint, changes["fixed_now"], (item["tool"], unlinkable(item), passed_over, alike))
                if alike and not passed_over:
                    self.assertEqual(registry.unproven_reason(second, item, None, seen_by[fingerprint]), "unidentified")
            else:
                self.assertIn(fingerprint, changes["fixed_now"], (item["tool"], unlinkable(item), changes))
            # Never linked to what replaced it: B is another secret, whether anyone could read it or not.
            for other in left:
                self.assertNotEqual(canonical.identity_of(other), canonical.identity_of(item))
        if change == "replaced":
            self.assertTrue({item["fingerprint"] for item in left} <= set(changes["new"]), (left, changes))
        # Whatever was read or left unlinkable, no fragment of either value is stored or shown.
        stored = json.dumps([load_run(self.data_dir, run["id"]) for run in (first, second)] + [registry.load(self.data_dir, key)], ensure_ascii=False)
        outputs = [stored, render_repository_report(load_run(self.data_dir, second["id"])), render_repository_sarif(load_run(self.data_dir, second["id"]))]
        for output in (item if isinstance(item, str) else json.dumps(item, ensure_ascii=False) for item in outputs):
            for value in (a, b):
                self.assertEqual(leaked(value, output, numbers=8), [], value)


class FilteredNeverLinkedTests(Registry):
    """R2 (only a value names a secret) × the secret filter (what a file shows in plain sight is judged by its value):
    a value the filter sets aside names nothing, links nothing and inherits nothing; a secret replaced by one is gone."""

    @settings(max_examples=40 * SCALE, deadline=None)
    @given(st.lists(benign(), min_size=1, max_size=12), shaped_secrets, st.sampled_from(SECRET_LAYOUTS), st.sampled_from(SECRET_KEYS),
           ANY_PATHS, st.data())
    def test_a_set_aside_value_has_no_identity_and_no_former_name(self, items, shaped, layout, key, path, data):
        rule, secret = shaped
        if rule == GENERIC_PASSWORD and outside_code(path):
            rule = "generic-api-key"
        at = data.draw(st.integers(0, len(items)), label="where")
        rows = [(line, value) for _, line, value in items]
        line = layout.format(key=key, value=secret)
        rows.insert(at, (line[:line.index(secret) + len(secret)], secret))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text("\n".join(text_ for text_, _ in rows) + "\n", encoding="utf-8")
            entries = []
            for number, (text_, value) in enumerate(rows, 1):
                end = text_.rindex(value) + len(value)
                entries.append({"RuleID": rule if number == at + 1 else "generic-api-key", "File": f"/src/{path}", "StartLine": number,
                                "EndLine": number, "StartColumn": 1, "EndColumn": end, "Match": text_[:end].replace(value, "REDACTED"),
                                "Entropy": entropy(value)})
            found = engines.parse_betterleaks(entries, None, root, Counter())
        apart = {value for _, _, value in items} - {secret}
        names_apart = {name for value in apart for name in ((secret_identity.names(value) or secret_identity.Names("", []))[0],
                                                             *(secret_identity.names(value) or secret_identity.Names("", []))[1]) if name}
        for item in found:
            self.assertNotIn(item.get("identity"), names_apart, item)
            self.assertFalse(set(item.get("value_formers") or ()) & names_apart, item)
            if of_value(item):
                self.assertEqual(item["identity"], secret_identity.identity(secret))

    @settings(max_examples=6 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
    @given(TOKEN, benign(), committed_path, ENGINE_SETS)
    @example(TOKENS[1], ("checksum", "github.com/acme/auth v1.2.3 h1:" + base64.b64encode(hashlib.sha256(b"go.sum").digest()).decode(),
                         base64.b64encode(hashlib.sha256(b"go.sum").digest()).decode()), "go.sum", frozenset())
    @example(TOKENS[2], ("checksum", "github.com/acme/auth v1.2.3 h1:" + base64.b64encode(hashlib.sha256(b"go.sum").digest()).decode(),
                         base64.b64encode(hashlib.sha256(b"go.sum").digest()).decode()), "go.sum", frozenset({"trivy"}))
    def test_a_secret_replaced_by_a_set_aside_value_is_gone_and_the_value_takes_nothing(self, token, item, path, skipping):
        """The secret's line becomes what a lockfile or a test shows in plain sight: the secret is fixed when every
        engine that saw it read the file again; the value the filter sets aside is no entry and no name of any."""
        self.setUp()
        _, line, value = item
        files = {path: f'api_key = "{token}"\n'.encode(), "app.py": b"x = 1\n"}
        first, _ = self.save(scan(files, Reporting(flagged=(value,))))
        found = {item_["fingerprint"]: item_ for item_ in first["findings"] if item_["scanner"] == "secrets" and item_["path"] == path}
        self.assertTrue(found, first["steps"])
        key = next(iter(registry.asset_keys(self.data_dir)))
        seen_by = {fingerprint: set(registry.detected_by(item_, registry.load(self.data_dir, key)["findings"][fingerprint].get("detected_by") or ()))
                   for fingerprint, item_ in found.items()}
        marker = path.rsplit("/", 1)[-1]
        hidden = {engine: frozenset({marker}) for engine in skipping}
        second, changes = self.save(scan({**files, path: f"{line}\n".encode()}, Reporting(hidden, flagged=(value,))))
        apart = secret_identity.names(value)
        set_aside = verdict("generic-api-key", path, line[:line.rindex(value) + len(value)], value) is not None
        entries = registry.load(self.data_dir, key)["findings"]
        for entry in entries.values():
            if set_aside and apart:
                self.assertNotEqual(entry["finding"].get("identity"), apart.identity, entry)
                self.assertFalse(set(entry["finding"].get("value_formers") or ()) & {apart.identity, *apart.formers}, entry)
        for fingerprint, item_ in found.items():
            self.assertEqual(canonical.identity_of(entries[fingerprint]["finding"]), canonical.identity_of(item_))   # it kept its own name
            if seen_by[fingerprint] & ({*skipping} | {engine for engine in seen_by[fingerprint] if not looked(second, engine, path)}):
                self.assertNotIn(fingerprint, changes["fixed_now"], (skipping, seen_by[fingerprint]))
            else:
                self.assertIn(fingerprint, changes["fixed_now"], (seen_by[fingerprint], changes))
        stored = json.dumps([load_run(self.data_dir, run["id"]) for run in (first, second)] + [entries], ensure_ascii=False)
        self.assertEqual(leaked(token, stored, numbers=8), [], token)


class FilterNeverHidesTests(Registry):
    """R3/R4 (what each engine examined, file by file) × the secret filter: setting a value aside never changes what an
    engine examined. A file whose only matches are set aside is examined; one an engine passed over stays unexamined,
    whatever the filter did with its matches."""

    @settings(max_examples=6 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
    @given(st.lists(benign(), min_size=1, max_size=4), committed_path, committed_path, ENGINE_SETS)
    @example([("checksum", "", base64.b64encode(hashlib.sha256(b"go.sum").digest()).decode())], "go.sum", "node_modules/x/index.js", frozenset({"trivy"}))
    def test_the_coverage_is_the_same_with_or_without_values_set_aside(self, items, apart_path, token_path, skipping):
        if apart_path == token_path:
            return
        values = tuple(value for _, _, value in items)
        marker = apart_path.rsplit("/", 1)[-1]
        hidden = {engine: frozenset({marker}) for engine in skipping}
        plain = {apart_path: b"x = 1\n", token_path: f'k = "{TOKENS[1]}"\n'.encode(), "app.py": b"x = 1\n"}
        flagged = {**plain, apart_path: "".join(f'key{index} = "{value}"\n' for index, value in enumerate(values)).encode()}
        without = scan(plain, Reporting(hidden))
        with_ = scan(flagged, Reporting(hidden, flagged=values))
        for engine in ("betterleaks", "trivy"):
            self.assertEqual(with_["coverage"].get(engine), without["coverage"].get(engine), engine)
            reason = unproven(with_, engine, apart_path)
            self.assertEqual(reason, unproven(without, engine, apart_path), engine)
            if engine in skipping:
                self.assertIn(reason, ("unexamined", "not_covered"), engine)
        # What it did keep there is what the filter keeps, by value: nothing else, nothing less.
        kept_ = {secret_identity.identity(value) for index, value in enumerate(values)
                 if verdict("generic-api-key", apart_path, f'key{index} = "{value}', value) is None}
        if "betterleaks" not in skipping:
            self.assertEqual({item["identity"] for item in with_["findings"] if item["path"] == apart_path and item["scanner"] == "secrets"}, kept_)


if __name__ == "__main__":
    unittest.main()
