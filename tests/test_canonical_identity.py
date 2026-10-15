"""Canonical identity in the registry (PITANGUS_IDENTITY_MODE): families with a count, triage that covers the copies it
saw, partial fixes, the shadow comparison and the move from fingerprints to identities."""

import hashlib
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from pitangus.modules.scanning.secret_location import entropy
from pitangus.modules.findings import canonical, registry, triage
from pitangus.modules.runs.store import save_repository_scan
from pitangus.shared.i18n import text
from test_dashboard import _scan

KEY = "github#31"
ADMIN = {"username": "ana", "role": "admin"}


def code(line: int, snippet: str = "eval(user)", path: str = "app.py") -> dict:
    """An Opengrep report as its adapter writes it: the fingerprint of its first copy, the snippet the identity reads."""
    digest = hashlib.sha256(f"{path}|{snippet}|{line}".encode()).hexdigest()
    return {"finding_id": digest[:16], "fingerprint": digest, "scanner": "sast", "tool": "opengrep", "rule_id": "appsec.py.eval",
            "title": "eval", "path": path, "line": line, "severity": "high", "confidence": 8, "verdict": "candidate", "cwe": [95],
            "owasp": ["A05:2025"], "cve": [], "ghsa": [], "package": None, "advisory": None, "kev": None, "epss": None,
            "priority": {"action": "attend", "factors": []}, "reason": "", "remediation": "", "snippet": snippet}


class FamilyRegistryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.clock = datetime.now(timezone.utc)
        mode = patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": "v2", "PITANGUS_COVERAGE_MODE": "on", "PITANGUS_FIX_HOLD_MINIMUM": "1000"})
        mode.start()
        self.addCleanup(mode.stop)

    def run_(self, findings, *, status="completed", coverage=None):
        self.clock += timedelta(hours=1)
        record = {**_scan("org/api", findings, self.clock.isoformat()), "status": status, "finished_at": self.clock.isoformat(),
                  "coverage": coverage or {"opengrep": {"examined": "*", "unexamined": {}}}}
        record["summary"]["tools"] = [{"name": "opengrep", "version": "1", "status": "completed"}]
        record["source"]["uid"] = KEY
        return save_repository_scan(self.data_dir, record, created_at=self.clock.isoformat())

    def entries(self):
        return registry.load(self.data_dir, KEY)["findings"]

    def test_copies_are_one_family_with_its_count_and_each_copy_moves_it(self):
        saved = self.run_([code(10), code(40), code(70)])
        (family,) = saved["findings"]
        self.assertEqual((family["count"], [item["line"] for item in family["instances"]]), (3, [10, 40, 70]))
        # One copy removed: a partial fix on the same entry, still open.
        self.run_([code(10), code(70)])
        (entry,) = self.entries().values()
        self.assertEqual((entry["status"], entry["finding"]["count"], entry["partial"]["from"], entry["partial"]["to"]), ("open", 2, 3, 2))
        # The last ones removed: fixed.
        self.run_([])
        self.assertEqual([entry["status"] for entry in self.entries().values()], ["fixed"])

    def test_a_triage_decision_covers_the_copies_it_saw_and_one_more_reopens_it(self):
        saved = self.run_([code(10), code(40)])
        digest = saved["findings"][0]["fingerprint"]
        triage.decide(self.data_dir, saved, [digest], "false_positive", reason="Sandboxed evaluator, input is a constant", user=ADMIN)
        self.assertEqual(triage.load(self.data_dir)[KEY][digest]["count"], 2)
        self.run_([code(10), code(40)])  # the same two: the decision stands
        self.assertEqual(triage.load(self.data_dir)[KEY][digest]["status"], "false_positive")
        self.run_([code(10), code(40), code(90)])  # a new copy
        decision = triage.load(self.data_dir)[KEY][digest]
        self.assertEqual(decision["status"], "open")
        self.assertIn("ahora hay 3, había 2", text(decision["note"]))

    def test_a_family_in_a_file_the_scan_left_out_is_unseen_not_fixed(self):
        self.run_([code(10), code(5, path="big.py")])
        self.run_([code(10)], coverage={"opengrep": {"examined": "*", "unexamined": {"big.py": "too_large"}}})
        statuses = sorted((entry["finding"]["path"], entry["status"], bool(entry.get("unseen"))) for entry in self.entries().values())
        self.assertEqual(statuses, [("app.py", "open", False), ("big.py", "open", True)])
        self.run_([code(10)])
        self.assertEqual(sorted((entry["finding"]["path"], entry["status"]) for entry in self.entries().values()),
                         [("app.py", "open"), ("big.py", "fixed")])

    def test_a_copy_the_scan_could_not_check_keeps_the_count(self):
        """One rule timed out on a.py: the copy it didn't report stays counted, marked unseen, and nothing is partial."""
        self.run_([code(1, path="a.py"), code(2, path="a.py")])
        self.run_([code(1, path="a.py")], coverage={"opengrep": {"examined": "*", "unexamined": {"a.py": "timeout"}}})
        (entry,) = self.entries().values()
        self.assertEqual((entry["finding"]["count"], "partial" in entry), (2, False))
        self.assertEqual([item.get("unseen", False) for item in entry["finding"]["instances"]], [False, True])


class TransitionTests(unittest.TestCase):
    """The same commit scanned before and after switching to v2: nothing opens and nothing is fixed."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.clock = datetime.now(timezone.utc)

    def run_(self, findings, mode):
        self.clock += timedelta(hours=1)
        record = {**_scan("org/api", findings, self.clock.isoformat()), "finished_at": self.clock.isoformat()}
        record["summary"]["tools"] = [{"name": "opengrep", "version": "1", "status": "completed"}]
        record["source"]["uid"] = KEY
        with patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": mode}):
            return save_repository_scan(self.data_dir, record, created_at=self.clock.isoformat())

    def test_switching_identity_modes_on_the_same_commit_changes_nothing(self):
        copies = [code(10), {**code(40), "fingerprint": "f" * 64, "finding_id": "f" * 16, "family": code(10)["fingerprint"]}, code(5, "os.system(cmd)")]
        self.run_(copies, "v1")
        triage.decide(self.data_dir, {**_scan("org/api", copies, ""), "id": "x" * 32, "source": {"id": "github:org/api", "uid": KEY, "name": "org/api"}},
                      [copies[2]["fingerprint"]], "accepted", reason="Runs only in the build container", user=ADMIN)
        shadow = self.run_(copies, "shadow")
        control = registry.load(self.data_dir, KEY)["control"]["identity_shadow"]
        self.assertEqual((control["opened"], control["fixed"]), (0, 0))
        self.assertEqual(shadow["identity_shadow"]["families"], 2)
        second = self.run_(copies, "shadow")
        control = registry.load(self.data_dir, KEY)["control"]["identity_shadow"]
        self.assertEqual((control["v2_opened"], control["v2_gone"]), (0, 0), second["id"])
        self.run_(copies, "v2")
        entries = registry.load(self.data_dir, KEY)["findings"]
        self.assertEqual(sorted((entry["status"], entry["finding"].get("count")) for entry in entries.values()), [("open", 1), ("open", 2)])
        # The triage moved with the entry to its family.
        accepted = canonical.identity_of(copies[2])
        self.assertEqual(triage.load(self.data_dir)[KEY][accepted]["status"], "accepted")


class GateTests(TransitionTests):
    mode = "shadow"   # the gate on runs stored before the switch to v2

    def scan_commit(self, findings, commit):
        self.clock += timedelta(hours=1)
        record = {**_scan("org/api", findings, self.clock.isoformat()), "finished_at": self.clock.isoformat()}
        record["source"].update(uid=KEY, commit=commit)
        record["summary"]["tools"] = [{"name": "opengrep", "version": "1", "status": "completed"}]
        with patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": self.mode}):
            return save_repository_scan(self.data_dir, record, created_at=self.clock.isoformat())

    def test_on_runs_stored_in_v2_the_same_commit_passes_and_a_new_copy_does_not(self):
        """With v2 (the default) a stored run already holds families: the gate compares them as they are."""
        from pitangus.modules.runs import identity_gate
        self.mode = "v2"
        self.scan_commit([code(10), code(40)], "a" * 40)
        self.scan_commit([code(10), code(40)], "a" * 40)
        (row,) = identity_gate.report(self.data_dir)
        self.assertTrue(row["same_commit"] and identity_gate.passed([row]), row)
        self.assertEqual((row["findings"], row["families"]), (1, 1))
        self.scan_commit([code(10), code(40), code(70)], "a" * 40)
        (row,) = identity_gate.report(self.data_dir)
        self.assertEqual((row["v1_opened"], row["v2_opened"], row["recounted"]), (0, 0, 1))
        self.assertFalse(identity_gate.passed([row]))

    def test_the_same_commit_twice_passes_and_a_new_copy_does_not(self):
        from pitangus.modules.runs import identity_gate
        self.scan_commit([code(10), code(40)], "a" * 40)
        self.scan_commit([code(10), code(40)], "a" * 40)
        (row,) = identity_gate.report(self.data_dir)
        self.assertTrue(row["same_commit"] and identity_gate.passed([row]), row)
        self.assertEqual((row["findings"], row["families"]), (2, 1))
        self.scan_commit([code(10), code(40), code(70)], "a" * 40)
        (row,) = identity_gate.report(self.data_dir)
        self.assertEqual((row["v1_opened"], row["v2_opened"], row["recounted"]), (1, 0, 1))
        self.assertFalse(identity_gate.passed([row]))
        self.scan_commit([code(10)], "b" * 40)
        self.assertFalse(identity_gate.passed(identity_gate.report(self.data_dir)))  # no repository on one commit


class PrepareTests(unittest.TestCase):
    def test_shadow_writes_identities_and_changes_nothing_else(self):
        record = {"type": "repository_scan", "findings": [code(10), code(40)], "summary": {"candidates": 2}}
        with patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": "shadow"}):
            prepared = canonical.prepare(record)
        self.assertEqual([item["fingerprint"] for item in prepared["findings"]], [item["fingerprint"] for item in record["findings"]])
        self.assertEqual(len({item["identity"] for item in prepared["findings"]}), 1)
        self.assertEqual(prepared["identity_shadow"], {"version": 2, "findings": 2, "families": 1, "grouped": 1})
        excluded = canonical.prepare({**record, "excluded_findings": [code(5, path="fixtures/x.py")]})
        self.assertTrue(excluded["excluded_findings"][0]["identity"])

    def test_v1_leaves_the_record_alone(self):
        record = {"type": "repository_scan", "findings": [code(10)]}
        with patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": "v1"}):
            self.assertIs(canonical.prepare(record), record)


if __name__ == "__main__":
    unittest.main()


class SecretMigrationTests(unittest.TestCase):
    """Secrets on the first scan after upgrading: their entries, triage included, move to the value's HMAC identity;
    nothing opens and nothing is fixed. Nor when the master key rotates and every identity changes."""

    TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

    def setUp(self):
        import tempfile as _tempfile
        self.directory = _tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.snapshot = self.data_dir / "snapshot"
        self.snapshot.mkdir()
        (self.snapshot / "config.py").write_text(f'x = 1\nGITHUB_TOKEN = "{self.TOKEN}"\n')
        self.clock = datetime.now(timezone.utc)

    def secret(self, *, with_identity=True):
        from pitangus.modules.scanning import engines
        entry = {"RuleID": "github-pat", "File": "/src/config.py", "StartLine": 2, "EndLine": 2, "StartColumn": 17, "EndColumn": 56,
                 "Match": "REDACTED", "Entropy": entropy(self.TOKEN)}
        finding = engines.parse_betterleaks([entry], None, self.snapshot)[0]
        if not with_identity:  # stored before the HMAC identity existed
            finding.pop("identity", None)
        return finding

    def scan(self, findings, mode):
        from pitangus.modules.runs.store import save_and_apply
        self.clock += timedelta(hours=1)
        record = {**_scan("org/api", findings, self.clock.isoformat()), "finished_at": self.clock.isoformat()}
        record["summary"]["tools"] = [{"name": "betterleaks", "version": "1", "status": "completed"}]
        record["source"]["uid"] = KEY
        from pitangus.modules.scanning import secret_identity
        record["configuration"] = {"identity_keys": secret_identity.key_ids()}   # as rule_set.code records it
        with patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": mode}):
            return save_and_apply(self.data_dir, record, created_at=self.clock.isoformat())

    def entries(self):
        return registry.load(self.data_dir, KEY)["findings"]

    def test_the_first_v2_scan_moves_each_secret_and_its_triage(self):
        for stored_with_identity in (True, False):
            with self.subTest(stored_with_identity=stored_with_identity):
                registry.forget_asset(self.data_dir, KEY)
                saved, _ = self.scan([self.secret(with_identity=stored_with_identity)], "v1")
                v1 = saved["findings"][0]["fingerprint"]
                triage.decide(self.data_dir, saved, [v1], "accepted", reason="Rotation planned for the next release", user=ADMIN)
                saved, changes = self.scan([self.secret()], "v2")
                self.assertEqual((changes["new"], changes["fixed_now"]), ([], []))
                identity = saved["findings"][0]["fingerprint"]
                self.assertNotEqual(identity, v1)
                self.assertEqual([(digest, entry["status"]) for digest, entry in self.entries().items()], [(identity, "open")])
                self.assertEqual(triage.load(self.data_dir)[KEY][identity]["status"], "accepted")

    def test_a_master_key_rotation_with_the_key_before_moves_every_secret_and_fixes_nothing(self):
        """R2: the scan computes each value's identity with PITANGUS_PREVIOUS_MASTER_KEY too, a name of that value: the
        entry and its triage move. Without it nothing links the two identities (the engine fingerprint never does): the
        new one opens and the old one stays open, unverified (its key isn't one the scan knew), never fixed."""
        import base64
        from pitangus.modules.scanning import secret_identity
        old, new = (base64.b64encode(byte * 32).decode() for byte in (b"\x05", b"\x06"))
        for previous in (old, ""):
            with self.subTest(previous=bool(previous)):
                self.data_dir = Path(tempfile.mkdtemp(dir=self.directory.name))
                with patch.dict(os.environ, {"PITANGUS_MASTER_KEY": old, "PITANGUS_PREVIOUS_MASTER_KEY": ""}):
                    secret_identity._key.cache_clear()
                    saved, _ = self.scan([self.secret()], "v2")
                    before = saved["findings"][0]["fingerprint"]
                    triage.decide(self.data_dir, saved, [before], "accepted", reason="Rotation planned for the next release", user=ADMIN)
                with patch.dict(os.environ, {"PITANGUS_MASTER_KEY": new, "PITANGUS_PREVIOUS_MASTER_KEY": previous}):
                    secret_identity._key.cache_clear()
                    saved, changes = self.scan([self.secret()], "v2")
                after = saved["findings"][0]["fingerprint"]
                self.assertNotEqual(before[:8], after[:8])
                if previous:
                    self.assertEqual((changes["new"], changes["fixed_now"]), ([], []))
                    self.assertEqual([(digest, entry["status"]) for digest, entry in self.entries().items()], [(after, "open")])
                    self.assertEqual(triage.load(self.data_dir)[KEY][after]["status"], "accepted")
                else:
                    self.assertEqual((changes["new"], changes["fixed_now"]), ([after], []))
                    entries = self.entries()
                    self.assertEqual((entries[before]["status"], entries[before]["unseen"]["cause"]), ("open", "identity_key"))
                    self.assertNotIn(after, triage.load(self.data_dir).get(KEY, {}))
        secret_identity._key.cache_clear()

    def test_an_entry_under_the_whole_match_identity_moves_by_that_name_alone(self):
        """F3: the identity was the whole match (`API_KEY = "…"`), now it is the value's. The scan records the identity
        before as a former name: the entry moves even when nothing else it was known by is left (here the text before the
        key changed and the line moved in the same commit). Without that name it would look fixed, and the secret new."""
        from pitangus.modules.scanning import engines, secret_identity
        token = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"  # gitleaks:allow
        current = engines._betterleaks_identities

        def findings(prefix, line, formula):
            (self.snapshot / "config.py").write_text(f'x = 1\n{"y = 2\n" * (line - 2)}{prefix}API_KEY = "{token}"\n')
            start = len(prefix.encode()) + 1
            entry = {"RuleID": "generic-api-key", "File": "/src/config.py", "StartLine": line, "EndLine": line, "StartColumn": start,
                     "EndColumn": start + len(f'API_KEY = "{token}"') - 1, "Match": 'API_KEY = "REDACTED"', "Entropy": entropy(token)}
            with patch.object(engines, "_betterleaks_identities", side_effect=formula):
                return engines.parse_betterleaks([entry], None, self.snapshot)

        for formula, outcome in ((current, "moved"), (lambda *args: (current(*args)[0], None), "fixed and new")):
            with self.subTest(outcome):
                registry.forget_asset(self.data_dir, KEY)
                saved, _ = self.scan(findings("cfg ; ", 2, lambda *args: (secret_identity.Names(current(*args)[1], []), None)), "v2")
                stored = saved["findings"][0]["fingerprint"]
                triage.decide(self.data_dir, saved, [stored], "accepted", reason="Rotation planned for the next release", user=ADMIN)
                saved, changes = self.scan(findings("", 3, formula), "v2")
                identity = saved["findings"][0]["fingerprint"]
                self.assertNotEqual(identity, stored)
                if outcome == "moved":
                    self.assertEqual((changes["new"], changes["fixed_now"]), ([], []))
                    self.assertEqual(triage.load(self.data_dir)[KEY][identity]["status"], "accepted")
                else:
                    self.assertEqual((changes["new"], changes["fixed_now"]), ([identity], [stored]))

class ScanTwiceTests(unittest.TestCase):
    """identity-gate --scan, the CI gate: two scans of one tree with this code, compared both ways."""

    def outcome(self, scans):
        from pitangus.modules.runs import identity_gate
        results = iter([{"scan": scan} for scan in scans])
        with patch("pitangus.modules.runs.local.run", side_effect=lambda *args, **kwargs: next(results)):
            return identity_gate.scan_twice(Path("."), Path("."))

    def test_the_same_findings_twice_pass_and_any_change_or_an_incomplete_scan_fails(self):
        same = {"status": "completed", "findings": [code(10), code(40)], "excluded_findings": [code(5, path="fixtures/x.py")]}
        self.assertTrue(self.outcome([same, same])["passed"])
        moved = {**same, "findings": [code(10)]}
        failed = self.outcome([same, moved])
        self.assertEqual((failed["passed"], failed["recounted"]), (False, 1))
        self.assertFalse(self.outcome([same, {**same, "status": "incomplete"}])["passed"])

    def test_the_command_needs_no_database_like_scan(self):
        """CI runs it in the published image with no PostgreSQL: it must not migrate anything first."""
        from pitangus.cli import main as cli
        from pitangus.modules.runs import identity_gate
        outcome = {"v1_opened": 0, "v1_gone": 0, "v2_opened": 0, "v2_gone": 0, "recounted": 0, "findings": 2, "families": 2,
                   "complete": True, "passed": True}
        with tempfile.TemporaryDirectory() as folder, patch.object(identity_gate, "scan_twice", return_value=outcome) as twice, \
                patch.object(cli, "upgrade_data", side_effect=AssertionError("migrated")), redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["--data-dir", folder, "identity-gate", "--scan", folder]), 0)
            twice.return_value = {**outcome, "v2_opened": 1, "passed": False}
            self.assertEqual(cli.main(["--data-dir", folder, "identity-gate", "--scan", folder]), 3)
        self.assertEqual(twice.call_args.args, (Path(folder), Path(folder)))
        self.assertTrue(callable(twice.call_args.kwargs["progress"]))
