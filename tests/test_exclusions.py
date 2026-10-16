"""Excluded paths per repository: patterns, effect on runs and the registry, and who can change them."""

import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pitangus.modules.findings import exclusions
from pitangus.modules.findings import registry as findings_registry
from pitangus.modules.identity.auth import Users
from pitangus.modules.runs.store import save_repository_scan
from test_auth import PASSWORD, HttpCase
from test_dashboard import _finding, _scan
from pitangus.shared.i18n import localize

ADMIN = {"username": "operadora", "role": "admin"}
KEY = "github#7"
QUERY_KEY = "github%237"  # "#" would start the URL fragment


def located(fingerprint, path, severity="high"):
    return {**_finding(fingerprint, severity), "path": path, "scanner": "sast"}


def scan(findings, when):
    record = _scan("org/app", findings, when)
    record["source"].update(uid=KEY)
    record["summary"]["sast"] = len(findings)
    return record


class PatternTests(unittest.TestCase):
    def test_hostile_or_overbroad_patterns_are_rejected(self):
        for bad in (["../etc"], ["/abs"], ["**"], ["*"], ["*/**"], ["?*"], ["**/*"], ["*?"], ["a;b"], ["x" * 300], ["fixtures", 3], "fixtures/**",
                    ["./a"], [f"d{index}/**" for index in range(51)]):
            with self.subTest(bad=bad), self.assertRaises(exclusions.ExclusionError):
                exclusions.normalize(bad)
        self.assertEqual(exclusions.normalize(["fixtures/", " docs/*.md ", "fixtures/**", ""]), ["fixtures/**", "docs/*.md"])
        self.assertEqual(exclusions.normalize(["a/**/**/**/b", "c/****"]), ["a/**/b", "c/**"])

    def test_glob_semantics(self):
        active = ["fixtures/**", "docs/*.md", "**/testdata/**"]
        self.assertEqual(exclusions.excluded("fixtures/sast-samples/app.py", active), "fixtures/**")
        self.assertEqual(exclusions.excluded("docs/intro.md", active), "docs/*.md")
        self.assertIsNone(exclusions.excluded("docs/deep/intro.md", active))  # "*" doesn't cross "/"
        self.assertEqual(exclusions.excluded("pkg/api/testdata/x.json", active), "**/testdata/**")
        self.assertEqual(exclusions.excluded("testdata/x.json", active), "**/testdata/**")
        self.assertIsNone(exclusions.excluded("src/fixtures/app.py", active))
        self.assertEqual(exclusions.excluded(".github/workflows/ci.yml", [".github/**"]), ".github/**")
        # As in .gitignore: if the pattern matches a folder, everything inside it is excluded.
        for pattern in ("fixtures/*", "fixtures", "fixtures/sast-*"):
            self.assertEqual(exclusions.excluded("fixtures/sast-samples/index.php", [pattern]), pattern)
        self.assertIsNone(exclusions.excluded("src/fixtures/app.py", ["fixtures/*"]))
        self.assertIsNone(exclusions.excluded("docs/deep/intro.md", ["docs/*.md"]))

    def test_matching_takes_linear_time_whatever_the_wildcards(self):
        # As a regex, `*a*a*a*a*a*a*b` against a 100-character name backtracked for ~30 s. Generous bound: CI is slower.
        hostile = exclusions.normalize(["*a*a*a*a*a*a*b/**", "**/*a*a*a*a*a*a*a*a*b*"])
        started = time.process_time()
        for path in ("a" * 100, "src/" + "a" * 2_000 + "/x.py", "a/" * 500 + "c"):
            self.assertIsNone(exclusions.excluded(path, hostile))
        self.assertLess(time.process_time() - started, 2.0)
        self.assertEqual(exclusions.excluded("aaaaaab/x.py", hostile), hostile[0])

    def test_a_pattern_can_be_limited_to_one_rule(self):
        """A known false positive: one rule in one place. Everything else there still counts."""
        self.assertEqual(exclusions.normalize(["tests/fixtures/  generic-api-key", "** python.lang.eval-detected", "tests/fixtures/**"]),
                         ["tests/fixtures/** generic-api-key", "** python.lang.eval-detected", "tests/fixtures/**"])
        for bad in (["tests a b"], ["tests rule;drop"], ["tests " + "r" * 200], ["../tests rule"]):
            with self.subTest(bad=bad), self.assertRaises(exclusions.ExclusionError):
                exclusions.normalize(bad)
        active = ["tests/** generic-api-key"]
        key = {"path": "tests/fixtures/settings.py", "rule_id": "generic-api-key"}
        self.assertEqual(exclusions.excludes(key, active), "tests/** generic-api-key")
        self.assertIsNone(exclusions.excludes({**key, "rule_id": "aws-access-token"}, active))
        self.assertIsNone(exclusions.excludes({**key, "path": "app/settings.py"}, active))
        # A finding two engines reported answers to either engine's rule.
        self.assertEqual(exclusions.excludes({**key, "rule_id": "CKV_SECRET_6", "related_rules": ["generic-api-key"]}, active), active[0])
        self.assertIsNone(exclusions.excluded("tests/fixtures/settings.py", active))  # by path alone, never

    def test_reason_is_mandatory_and_history_is_kept(self):
        with tempfile.TemporaryDirectory() as folder:
            data_dir = Path(folder)
            with self.assertRaises(exclusions.ExclusionError):
                exclusions.save(data_dir, KEY, ["fixtures/**"], reason="", user=ADMIN)
            exclusions.save(data_dir, KEY, ["fixtures/**"], reason="Ejemplos vulnerables a propósito", user=ADMIN)
            saved = exclusions.save(data_dir, KEY, [], reason=None, user=ADMIN)
            self.assertEqual(saved["patterns"], [])
            self.assertEqual([item["patterns"] for item in saved["history"]], [["fixtures/**"], []])


class RecordAndRegistryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        self.now = datetime.now(timezone.utc)
        self.findings = [located("a" * 64, "fixtures/vuln.py", "critical"), located("b" * 64, "app/main.py")]

    def tearDown(self):
        self.directory.cleanup()

    def save(self, minutes):
        return save_repository_scan(self.data_dir, scan([dict(item) for item in self.findings], self.now.isoformat()),
                                    created_at=(self.now + timedelta(minutes=minutes)).isoformat())

    def test_excluded_paths_leave_the_run_but_are_counted(self):
        exclusions.save(self.data_dir, KEY, ["fixtures/**"], reason="Ejemplos vulnerables a propósito", user=ADMIN)
        record = self.save(0)
        self.assertEqual([item["path"] for item in record["findings"]], ["app/main.py"])
        self.assertEqual((record["summary"]["candidates"], record["summary"]["excluded"], record["summary"]["severities"]["critical"]), (1, 1, 0))
        self.assertEqual(record["excluded"]["by_pattern"], {"fixtures/**": 1})
        self.assertTrue(any("fixtures/**" in line for line in localize(record["limitations"])))
        state = findings_registry.summarize(self.data_dir, KEY)
        self.assertEqual((state["open"], state["excluded"], state["fixed"]), (1, 1, 0))
        view = findings_registry.view(self.data_dir, KEY, status="excluded")
        self.assertEqual([item["path"] for item in view["findings"]], ["fixtures/vuln.py"])

    def test_excluding_later_is_not_a_fix_and_including_again_reopens(self):
        self.save(0)
        self.assertEqual(findings_registry.summarize(self.data_dir, KEY)["open"], 2)
        saved = exclusions.save(self.data_dir, KEY, ["fixtures/**"], reason="Ejemplos vulnerables a propósito", user=ADMIN)
        moved = findings_registry.apply_exclusions(self.data_dir, KEY, saved["patterns"], when=saved["at"])
        self.assertEqual(moved, {"excluded": 1, "reopened": 0})
        self.save(5)  # the next scan doesn't take it as remediated
        state = findings_registry.summarize(self.data_dir, KEY)
        self.assertEqual((state["open"], state["excluded"], state["fixed"]), (1, 1, 0))
        exclusions.save(self.data_dir, KEY, [], reason=None, user=ADMIN)
        self.save(10)
        state = findings_registry.summarize(self.data_dir, KEY)
        self.assertEqual((state["open"], state["excluded"], state["fixed"]), (2, 0, 0))

    def test_a_rule_limited_pattern_moves_only_that_rule_and_the_preview_says_so(self):
        self.findings = [{**located("a" * 64, "tests/settings.py", "critical"), "rule_id": "generic-api-key"},
                         {**located("c" * 64, "tests/test_api.py"), "rule_id": "python.lang.eval-detected"}, located("b" * 64, "app/main.py")]
        self.save(0)
        active = exclusions.normalize(["tests/** generic-api-key"])
        preview = findings_registry.preview_exclusions(self.data_dir, KEY, active)
        self.assertEqual((preview["excluded"], preview["excluded_paths"]), (1, ["tests/settings.py"]))
        findings_registry.apply_exclusions(self.data_dir, KEY, active, when=self.now.isoformat())
        exclusions.save(self.data_dir, KEY, active, reason="Clave de ejemplo de los tests", user=ADMIN)
        record = self.save(5)
        self.assertEqual(sorted(item["path"] for item in record["findings"]), ["app/main.py", "tests/test_api.py"])
        self.assertEqual(record["excluded"]["by_pattern"], {"tests/** generic-api-key": 1})
        state = findings_registry.summarize(self.data_dir, KEY)
        self.assertEqual((state["open"], state["excluded"], state["fixed"]), (2, 1, 0))
        listed = findings_registry.view(self.data_dir, KEY, status="excluded")["findings"]
        self.assertEqual([(item["path"], item["lifecycle"]["excluded"]["pattern"]) for item in listed], [("tests/settings.py", "tests/** generic-api-key")])

    def test_applying_twice_changes_nothing(self):
        exclusions.save(self.data_dir, KEY, ["fixtures/**"], reason="Ejemplos vulnerables a propósito", user=ADMIN)
        once = exclusions.apply_to_record(self.data_dir, scan(self.findings, self.now.isoformat()), KEY)
        self.assertIs(exclusions.apply_to_record(self.data_dir, once, KEY), once)


class ExclusionApiTests(HttpCase):
    def setUp(self):
        super().setUp()
        Users(self.data_dir).create("operadora", PASSWORD, role="admin")
        Users(self.data_dir).create("analista", PASSWORD)
        save_repository_scan(self.data_dir, scan([located("a" * 64, "fixtures/vuln.py"), located("b" * 64, "app/main.py")],
                                                 datetime.now(timezone.utc).isoformat()))

    def cookie(self, username):
        _, _, cookies = self.post("/api/auth/login", "login", {"username": username, "password": PASSWORD})
        return cookies[0].split("; ")[0]

    def test_only_admins_change_exclusions_and_only_for_real_assets(self):
        body = {"key": KEY, "patterns": ["fixtures/**"], "reason": "Ejemplos vulnerables a propósito"}
        member = self.cookie("analista")
        self.assertEqual(self.post("/api/assets/exclusions", "save-exclusions", body, member)[0], 403)
        self.assertEqual(self.call("GET", f"/api/assets/exclusions?key={QUERY_KEY}", headers={"Cookie": member})[0], 200)
        admin = self.cookie("operadora")
        self.assertEqual(self.post("/api/assets/exclusions", "wrong-action", body, admin)[0], 403)
        self.assertEqual(self.post("/api/assets/exclusions", "save-exclusions", {**body, "key": "github#999"}, admin)[0], 404)
        self.assertEqual(self.post("/api/assets/exclusions", "save-exclusions", {**body, "patterns": ["**"]}, admin)[0], 400)
        self.assertEqual(self.post("/api/assets/exclusions", "save-exclusions", {**body, "extra": 1}, admin)[0], 400)
        self.assertEqual(self.post("/api/assets/exclusions", "save-exclusions", {**body, "key": "github#7\nfalso log"}, admin)[0], 400)
        status, saved, _ = self.post("/api/assets/exclusions", "save-exclusions", body, admin)
        self.assertEqual((status, saved["patterns"], saved["moved"]), (200, ["fixtures/**"], {"excluded": 1, "reopened": 0}))
        status, view, _ = self.call("GET", f"/api/assets/state?key={QUERY_KEY}&status=excluded", headers={"Cookie": admin})
        self.assertEqual((status, len(view["findings"]), view["summary"]["lifecycle"]["excluded"]), (200, 1, 1))


    def test_the_preview_says_what_would_move_and_saves_nothing(self):
        admin, member = self.cookie("operadora"), self.cookie("analista")
        body = {"key": KEY, "patterns": ["fixtures"]}
        self.assertEqual(self.post("/api/assets/exclusions/preview", "preview-exclusions", body, member)[0], 403)
        status, preview, _ = self.post("/api/assets/exclusions/preview", "preview-exclusions", body, admin)
        self.assertEqual((status, preview), (200, {"excluded": 1, "reopened": 0, "excluded_paths": ["fixtures/vuln.py"], "reopened_paths": [],
                                                   "excluded_path_count": 1, "reopened_path_count": 0}))
        self.assertEqual(self.call("GET", f"/api/assets/exclusions?key={QUERY_KEY}", headers={"Cookie": admin})[1]["patterns"], [])
        # The same checks as saving, before saving.
        status, refused, _ = self.post("/api/assets/exclusions/preview", "preview-exclusions", {**body, "patterns": ["**"]}, admin)
        self.assertEqual(status, 400)
        self.assertIn("**", refused["error"])
        # Once saved, dropping the path previews the finding going back to open.
        self.post("/api/assets/exclusions", "save-exclusions", {**body, "reason": "Ejemplos vulnerables a propósito"}, admin)
        status, preview, _ = self.post("/api/assets/exclusions/preview", "preview-exclusions", {**body, "patterns": []}, admin)
        self.assertEqual((preview["excluded"], preview["reopened"], preview["reopened_paths"]), (0, 1, ["fixtures/vuln.py"]))

    def test_only_admins_release_a_fix_hold_and_the_asset_shows_it(self):
        import os
        from unittest.mock import patch
        member, admin = self.cookie("analista"), self.cookie("operadora")
        with patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "on", "PITANGUS_FIX_HOLD_MINIMUM": "2"}):
            held = scan([], (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
            held["summary"]["tools"] = [{"name": "opengrep", "version": "1", "status": "completed"}]
            save_repository_scan(self.data_dir, held)
            status, view, _ = self.call("GET", f"/api/assets/state?key={QUERY_KEY}", headers={"Cookie": member})
            self.assertEqual((status, view["control"]["hold"]["count"], view["control"]["mode"]), (200, 2, "on"))
            self.assertEqual(self.post("/api/assets/fix-hold", "release-fix-hold", {"asset": KEY}, member)[0], 403)
            self.assertEqual(self.post("/api/assets/fix-hold", "release-fix-hold", {"asset": "github#999"}, admin)[0], 404)
            status, released, _ = self.post("/api/assets/fix-hold", "release-fix-hold", {"asset": KEY}, admin)
            self.assertEqual((status, released), (200, {"released": 2}))
            status, health, _ = self.call("GET", "/api/findings/health", headers={"Cookie": member})
            self.assertEqual((status, health["assets"], health["engines"], health["blind_engines"]), (200, 1, 1, 0))


if __name__ == "__main__":
    unittest.main()
