"""Finding lifecycle: open, remediated on their own, reopened, PRs and manual remediation."""

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from pitangus.modules.findings import registry
from pitangus.modules.findings import triage
from pitangus.modules.runs import registry as run_registry
from pitangus.modules.runs.store import save_repository_scan
from test_dashboard import _finding, _scan
from pitangus.shared.i18n import text

KEY = "github#7"
A, B, C = "a" * 64, "b" * 64, "c" * 64
USER = {"username": "ana", "role": "member"}


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        self.clock = datetime.now(timezone.utc)

    def tearDown(self):
        self.directory.cleanup()

    def run_(self, findings, *, pr=None, head="1" * 40, status="completed", tools=(), unexamined=None, coverage=None, configuration=None):
        self.clock += timedelta(hours=1)
        record = {**_scan("org/api", findings, self.clock.isoformat()), "status": status,
                  **({"unexamined": unexamined} if unexamined else {}), **({"coverage": coverage} if coverage else {}),
                  **({"configuration": configuration} if configuration else {})}
        record["summary"]["tools"] = [{"name": name, "version": "1", "status": state} for name, state in tools]
        record["source"]["uid"] = KEY
        record["finished_at"] = self.clock.isoformat()
        if pr:
            record.update(type="pr_review", pull_request={"number": pr, "head_sha": head, "head_ref": "feat"})
        return save_repository_scan(self.data_dir, record, created_at=self.clock.isoformat())

    def status(self):
        return {digest: entry["status"] for digest, entry in registry.load(self.data_dir, KEY)["findings"].items()}

    def test_full_scans_open_fix_and_reopen(self):
        self.run_([_finding(A), _finding(B)])
        self.run_([_finding(A)])
        self.assertEqual(self.status(), {A: "open", B: "fixed"})
        fixed = registry.load(self.data_dir, KEY)["findings"][B]["fixed"]
        self.assertTrue(fixed["auto"] and "escaneo completo" in text(fixed["how"]))
        self.run_([_finding(A), _finding(B)])
        self.assertEqual(self.status(), {A: "open", B: "open"})
        self.assertEqual(registry.summarize(self.data_dir, KEY)["open"], 2)

    def test_an_incomplete_scan_never_fixes_anything(self):
        """If an engine didn't run (Docker, images, network), a missing finding doesn't prove it was fixed."""
        self.run_([_finding(A), _finding(B)])
        self.run_([], status="incomplete")
        self.assertEqual(self.status(), {A: "open", B: "open"})
        # What an incomplete scan does see is still opened.
        C = "c" * 64
        self.run_([_finding(C)], status="incomplete")
        self.assertEqual(self.status(), {A: "open", B: "open", C: "open"})
        # The next complete scan does remediate what is gone.
        self.run_([_finding(A)])
        self.assertEqual(self.status(), {A: "open", B: "fixed", C: "fixed"})

    def test_a_finding_only_failed_engines_see_is_not_fixed(self):
        """An optional engine (Checkov, zizmor) can fail without making the scan incomplete: what it sees didn't go away,
        it just wasn't looked at, also when another engine sees it too: every engine that saw a finding must look again."""
        iac = {**_finding(A), "scanner": "iac", "tool": "checkov"}
        both = {**_finding(B), "scanner": "iac", "tool": "trivy", "also_detected_by": ["checkov"]}
        self.run_([iac, both])
        self.run_([], tools=[("checkov", "inconclusive"), ("trivy", "completed")])
        self.assertEqual(self.status(), {A: "open", B: "open"})
        # Once Checkov runs and no longer reports it, it is fixed.
        self.run_([], tools=[("checkov", "completed"), ("trivy", "completed")])
        self.assertEqual(self.status(), {A: "fixed", B: "fixed"})

    def test_the_dashboard_ignores_incomplete_scans(self):
        from pitangus.modules.reporting import dashboard
        self.run_([_finding(A), _finding(B)])
        self.run_([], status="incomplete")
        data = dashboard.compute(self.data_dir)
        asset = next(row for row in data["top_assets"] if row["name"] == "org/api")
        self.assertEqual(asset["open"], 2)

    def test_pull_request_findings_live_and_die_with_the_pr(self):
        self.run_([_finding(A)])
        self.run_([_finding(C)], pr=4)
        entry = registry.load(self.data_dir, KEY)["findings"][C]
        self.assertEqual((entry["status"], entry["origin"]["kind"], entry["origin"]["pr"]), ("open", "pr", 4))
        self.run_([_finding(A)])                   # a main scan doesn't clear what lives on the PR branch
        self.assertEqual(self.status()[C], "open")
        self.run_([], pr=4, head="2" * 40)         # new PR commit without the finding
        self.assertEqual(self.status()[C], "fixed")
        self.assertIn("2222222", text(registry.load(self.data_dir, KEY)["findings"][C]["fixed"]["how"]))

    def test_closed_and_merged_pull_requests(self):
        self.run_([_finding(B)], pr=5)
        self.run_([_finding(C)], pr=6)
        registry.pull_closed(self.data_dir, KEY, 5, merged=False, when="2026-09-02")
        registry.pull_closed(self.data_dir, KEY, 6, merged=True, when="2026-09-02")
        self.assertEqual(self.status(), {B: "fixed", C: "open"})
        self.run_([])                              # the main scan after the merge no longer sees it
        self.assertEqual(self.status()[C], "fixed")

    def test_manual_fix_needs_a_reason_and_reopens_if_it_comes_back(self):
        self.run_([_finding(A)])
        state = registry.view(self.data_dir, KEY, status="all")
        with self.assertRaises(triage.TriageError):
            triage.decide(self.data_dir, state, [A], "fixed", reason="", user=USER)
        triage.decide(self.data_dir, state, [A], "fixed", reason="Parche aplicado en producción, pendiente de desplegar", user=USER)
        self.assertEqual([item["fingerprint"] for item in registry.view(self.data_dir, KEY, status="fixed")["findings"]], [A])
        self.assertEqual(registry.view(self.data_dir, KEY, status="open")["findings"], [])
        self.run_([_finding(A)])                   # it shows up again: it wasn't remediated
        self.assertEqual(triage.effective(triage.load(self.data_dir)[KEY][A])["status"], "open")
        self.assertEqual(len(registry.view(self.data_dir, KEY, status="open")["findings"]), 1)

    def test_each_tab_lists_what_its_count_says(self):
        """The asset's tabs (open, fixed, excluded, all) hold exactly what the summary counts: fixed by a scan or by
        hand, dismissed in triage (in the open tab, counted apart) and under excluded paths."""
        D, E = "d" * 64, "e" * 64
        vendored = {**_finding(E), "path": "vendor/package-lock.json"}
        self.run_([_finding(A), _finding(B), _finding(C), _finding(D), vendored])
        self.run_([_finding(A), _finding(C), _finding(D), vendored])  # B: fixed by the scan
        state = registry.view(self.data_dir, KEY, status="all")
        triage.decide(self.data_dir, state, [C], "fixed", reason="Parche aplicado fuera de la rama principal", user=USER)
        triage.decide(self.data_dir, state, [D], "false_positive", reason="Solo en pruebas", user=USER)
        registry.apply_exclusions(self.data_dir, KEY, ["vendor/**"], when="2026-10-01")
        counts = registry.summarize(self.data_dir, KEY)
        self.assertEqual({field: counts[field] for field in ("open", "fixed", "suppressed", "excluded")},
                         {"open": 1, "fixed": 2, "suppressed": 1, "excluded": 1})
        listed = {tab: sorted(item["fingerprint"] for item in registry.view(self.data_dir, KEY, status=tab)["findings"])
                  for tab in ("open", "fixed", "excluded", "all")}
        self.assertEqual(listed, {"open": [A, D], "fixed": [B, C], "excluded": [E], "all": [A, B, C, D, E]})
        self.assertEqual(len(listed["open"]), counts["open"] + counts["suppressed"])
        for tab in ("open", "fixed", "excluded", "all"):  # every tab carries the asset's counts, not the tab's
            self.assertEqual(registry.view(self.data_dir, KEY, status=tab)["summary"]["lifecycle"], counts)

    def test_a_file_the_scan_didnt_analyze_proves_nothing(self):
        """Left out of the snapshot (too large) or skipped by the engine that reports it: not fixed. Another engine's
        finding in a file only Opengrep skipped is."""
        bundle = {**_finding(A), "scanner": "sast", "tool": "opengrep", "path": "web/bundle.js"}
        dump = {**_finding(B), "scanner": "secrets", "tool": "betterleaks", "path": "db/dump.sql"}
        key = {**_finding(C), "scanner": "secrets", "tool": "betterleaks", "path": "web/bundle.js"}
        self.run_([bundle, dump, key])
        self.run_([], unexamined={"*": ["db/dump.sql"], "opengrep": ["web/bundle.js"]})
        self.assertEqual(self.status(), {A: "open", B: "open", C: "fixed"})
        self.run_([])  # read whole again: what isn't there any more is gone
        self.assertEqual(self.status(), {A: "fixed", B: "fixed", C: "fixed"})

    def test_what_a_blind_engine_reports_is_never_closed(self):
        """An engine that failed or didn't run proves nothing, even when another engine saw the same problem: every
        engine that saw it must have looked."""
        scan = {"summary": {"tools": [{"name": "Trivy", "status": "inconclusive"}, {"name": "Checkov", "status": "not_tested"},
                                      {"name": "Betterleaks", "status": "completed"}]}}
        blind = registry.blind_engines(scan)
        self.assertEqual(blind, {"trivy", "checkov"})
        self.assertTrue(registry.unseen({"tool": "trivy", "also_detected_by": ["betterleaks"]}, blind))
        self.assertTrue(registry.unseen({"tool": "checkov"}, blind))
        self.assertTrue(registry.unseen({"tool": "betterleaks", "also_detected_by": ["trivy"]}, blind))
        self.assertFalse(registry.unseen({"tool": "betterleaks"}, blind))
        self.assertTrue(registry.unseen({"tool": "betterleaks"}, blind, ["trivy"]))   # it saw it in an earlier run

    def test_rebuild_matches_incremental(self):
        self.run_([_finding(A), _finding(B)])
        self.run_([_finding(A)])
        before = self.status()
        run_registry.rebuild(self.data_dir)
        self.assertEqual(self.status(), before)


if __name__ == "__main__":
    unittest.main()


class RulesBeforeTheContractTests(RegistryTests):
    """The lifecycle above with the modes an operator can still choose: the fixing rules before the coverage contract
    (PITANGUS_COVERAGE_MODE=shadow) and the engines' fingerprints (PITANGUS_IDENTITY_MODE=shadow)."""

    def setUp(self):
        super().setUp()
        mode = patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "shadow", "PITANGUS_IDENTITY_MODE": "shadow"})
        mode.start()
        self.addCleanup(mode.stop)


class CoverageContractTests(RegistryTests):
    """PITANGUS_COVERAGE_MODE=on: only what the owner engine proved gone is fixed; the rest is unseen, never fixed; a
    run that would fix too much at once holds its fixes until the next one confirms them. It inherits every lifecycle
    test above, so they hold with the contract on too."""

    def setUp(self):
        super().setUp()
        mode = patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "on", "PITANGUS_FIX_HOLD_MINIMUM": "3", "PITANGUS_FIX_HOLD_PERCENT": "30"})
        mode.start()
        self.addCleanup(mode.stop)

    def finding(self, digest, path="app.py"):
        return {**_finding(digest), "scanner": "sast", "tool": "opengrep", "path": path}

    def entries(self):
        return registry.load(self.data_dir, KEY)["findings"]

    def test_a_finding_its_engine_couldnt_read_is_unseen_never_fixed_and_seeing_it_clears_the_mark(self):
        self.run_([self.finding(A), self.finding(B, "lib.py")])
        skipped = {"opengrep": {"examined": "*", "unexamined": {"app.py": "timeout"}}}
        self.run_([], tools=[("opengrep", "completed")], coverage=skipped)
        entries = self.entries()
        self.assertEqual((entries[A]["status"], entries[A]["unseen"]["scans"], entries[A]["unseen"]["reason"]), ("open", 1, "unexamined"))
        self.assertEqual(entries[B]["status"], "fixed")  # lib.py was read: its absence is proof
        self.run_([], tools=[("opengrep", "completed")], coverage=skipped)
        self.assertEqual(self.entries()[A]["unseen"]["scans"], 2)
        self.assertEqual(self.entries()[A]["unseen"]["since"], entries[A]["unseen"]["since"])
        self.run_([self.finding(A)], tools=[("opengrep", "completed")], coverage={"opengrep": {"examined": "*", "unexamined": {}}})
        self.assertNotIn("unseen", self.entries()[A])

    def test_an_engine_that_broke_its_contract_proves_nothing(self):
        self.run_([self.finding(A)])
        record_tools = [("opengrep", "completed")]
        self.clock += timedelta(hours=1)
        record = {**_scan("org/api", [], self.clock.isoformat()), "status": "completed", "coverage": {"opengrep": {"examined": "*", "unexamined": {}}}}
        record["summary"]["tools"] = [{"name": name, "version": "1", "status": state, "contract": {"blind": True, "cause": "empty"}} for name, state in record_tools]
        record["source"]["uid"], record["finished_at"] = KEY, self.clock.isoformat()
        save_repository_scan(self.data_dir, record, created_at=self.clock.isoformat())
        self.assertEqual((self.entries()[A]["status"], self.entries()[A]["unseen"]["reason"]), ("open", "engine_blind"))

    def test_too_many_fixes_at_once_wait_for_the_next_scan_to_confirm_them(self):
        digests = [character * 64 for character in "defgh"]
        self.run_([self.finding(digest, f"f{index}.py") for index, digest in enumerate(digests)])
        clean = {"opengrep": {"examined": "*", "unexamined": {}}}
        self.run_([], tools=[("opengrep", "completed")], coverage=clean)
        self.assertEqual(set(self.status().values()), {"open"})  # held: 5 of 5 open, over 30% and at least 3
        held = registry.load(self.data_dir, KEY)["control"]["hold"]
        self.assertEqual(sorted(held["digests"]), sorted(digests))
        self.run_([], tools=[("opengrep", "completed")], coverage=clean)  # the next complete scan confirms the same absences
        self.assertEqual(set(self.status().values()), {"fixed"})
        control = registry.load(self.data_dir, KEY)["control"]
        self.assertNotIn("hold", control)
        self.assertEqual((control["released"]["count"], control["released"]["by"]), (5, "scan"))

    def test_a_rule_updated_since_its_finding_was_seen_or_an_engine_turned_off_proves_nothing(self):
        """What changed is kept with the mark (scanning/rule_set declares it on every run), and the panel says it."""
        clean = {"opengrep": {"examined": "*", "unexamined": {}}, "checkov": {"examined": "*", "unexamined": {}}}
        iac = {**_finding(B), "scanner": "iac", "tool": "checkov", "rule_id": "CKV_AWS_20", "path": "main.tf"}
        rules = {"opengrep": {"rules": {"appsec.py.eval": "v1"}, "enumerated": ["appsec."]}, "checkov": {"others": ""}}
        self.run_([{**self.finding(A), "rule_id": "appsec.py.eval"}, iac], tools=[("opengrep", "completed"), ("checkov", "completed")], coverage=clean,
                  configuration={"engines": rules})
        self.assertEqual(self.entries()[A]["rule_digest"], "v1")
        changed = {"engines": {"opengrep": {**rules["opengrep"], "rules": {"appsec.py.eval": "v2"}}, "checkov": {"off": True}}}
        self.run_([], tools=[("opengrep", "completed"), ("checkov", "not_tested")], coverage={"opengrep": clean["opengrep"]}, configuration=changed)
        entries = self.entries()
        self.assertEqual([(entries[digest]["status"], entries[digest]["unseen"]["reason"], entries[digest]["unseen"]["cause"]) for digest in (A, B)],
                         [("open", "configuration", "rule_changed"), ("open", "configuration", "engine_off")])
        self.assertEqual((entries[A]["unseen"]["rule"], entries[B]["unseen"]["engine"]), ("appsec.py.eval", "checkov"))
        counts = registry.summarize(self.data_dir, KEY)
        self.assertEqual((counts["unverified"], counts["unverified_configuration"], counts["open"]), (2, 2, 0))
        # The same rule again and the engine back on: their absence is proof now.
        self.run_([], tools=[("opengrep", "completed"), ("checkov", "completed")], coverage=clean,
                  configuration={"engines": {**rules, "opengrep": changed["engines"]["opengrep"]}})
        self.assertEqual(self.status(), {A: "open", B: "fixed"})  # A was last seen under v1: v2 never proves it gone

    def test_an_administrator_can_release_a_hold(self):
        digests = [character * 64 for character in "defg"]
        self.run_([self.finding(digest, f"f{index}.py") for index, digest in enumerate(digests)])
        self.run_([self.finding(digests[0], "f0.py")], tools=[("opengrep", "completed")], coverage={"opengrep": {"examined": "*", "unexamined": {}}})
        self.assertEqual(registry.release_hold(self.data_dir, KEY, user="ana"), 3)
        self.assertEqual(sorted(self.status().values()), ["fixed", "fixed", "fixed", "open"])
        self.assertEqual(registry.release_hold(self.data_dir, KEY, user="ana"), 0)  # nothing held any more


class FixHoldTests(RegistryTests):
    """The circuit breaker with its real defaults (30% and at least 10, PITANGUS_FIX_HOLD_*): released only by the next
    complete, covered scan that proves the same findings gone; openings never wait; it says so once."""

    def setUp(self):
        super().setUp()
        mode = patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "on", "PITANGUS_FIX_HOLD_MINIMUM": "", "PITANGUS_FIX_HOLD_PERCENT": ""})
        mode.start()
        self.addCleanup(mode.stop)

    CLEAN = {"opengrep": {"examined": "*", "unexamined": {}}}

    def finding(self, index: int):
        digest = f"{index:064x}"
        return {**_finding(digest), "scanner": "sast", "tool": "opengrep", "path": f"f{index}.py"}

    def scan(self, findings, **options):
        return self.run_(findings, tools=[("opengrep", "completed")], coverage=options.pop("coverage", self.CLEAN), **options)

    def fixed(self):
        return sorted(digest for digest, status in self.status().items() if status == "fixed")

    def test_the_defaults_are_thirty_percent_and_at_least_ten(self):
        self.scan([self.finding(index) for index in range(40)])
        self.scan([self.finding(index) for index in range(31)])        # 9 gone: under the minimum, fixed at once
        self.assertEqual(len(self.fixed()), 9)
        self.scan([self.finding(index) for index in range(21)])        # 10 of 31 open (32%): held
        self.assertEqual(len(self.fixed()), 9)
        self.assertEqual(len(registry.load(self.data_dir, KEY)["control"]["hold"]["digests"]), 10)

    def test_the_hold_keeps_why_and_the_asset_view_says_it(self):
        self.scan([self.finding(index) for index in range(40)])
        self.scan([self.finding(index) for index in range(28)])        # 12 of 40 (30%): held
        hold = registry.control_of(self.data_dir, KEY)["hold"]
        self.assertEqual({key: hold["reason"][key] for key in ("kind", "count", "open", "minimum", "percent")},
                         {"kind": "too_many", "count": 12, "open": 40, "minimum": 10, "percent": 30})
        self.assertEqual(hold["count"], 12)

    def test_ten_that_are_under_thirty_percent_are_fixed_at_once(self):
        self.scan([self.finding(index) for index in range(50)])
        self.scan([self.finding(index) for index in range(40)])        # 10 of 50 (20%)
        self.assertEqual(len(self.fixed()), 10)

    def test_the_thresholds_are_configurable(self):
        with patch.dict(os.environ, {"PITANGUS_FIX_HOLD_MINIMUM": "2", "PITANGUS_FIX_HOLD_PERCENT": "60"}):
            self.scan([self.finding(index) for index in range(5)])
            self.scan([self.finding(index) for index in range(3)])    # 2 of 5 (40%): under 60%
            self.assertEqual(len(self.fixed()), 2)
            self.scan([])                                              # 3 of 3 (100%), at least 2: held
            self.assertEqual(len(self.fixed()), 2)

    def test_only_a_complete_covered_scan_proving_the_same_absences_releases_it_and_openings_never_wait(self):
        self.scan([self.finding(index) for index in range(12)])
        with patch.object(registry._log, "warning") as warned:
            self.scan([])                                                # 12 of 12 gone at once: held
            self.assertEqual((len(registry.load(self.data_dir, KEY)["control"]["hold"]["digests"]), self.fixed()), (12, []))
            self.scan([], status="incomplete")                           # incomplete: proves nothing, the hold stays
            self.assertEqual((len(registry.load(self.data_dir, KEY)["control"]["hold"]["digests"]), self.fixed()), (12, []))
            # f0.py not examined this time: the other 11 are confirmed gone, f0 keeps waiting.
            self.scan([], coverage={"opengrep": {"examined": "*", "unexamined": {"f0.py": "timeout"}}})
            self.assertEqual(len(self.fixed()), 11)
            self.assertEqual(registry.load(self.data_dir, KEY)["control"]["hold"]["digests"], [self.finding(0)["fingerprint"]])
            new = {**self.finding(99), "path": "new.py"}
            self.scan([new])                                             # an opening during the hold: opened at once
            self.assertEqual(self.status()[new["fingerprint"]], "open")
        self.assertEqual(len(self.fixed()), 12)                         # and that scan confirmed f0
        self.assertNotIn("hold", registry.load(self.data_dir, KEY)["control"])
        self.assertEqual(warned.call_count, 1)                          # said once, when it started

    def test_one_coming_back_leaves_the_hold_and_the_rest_wait_for_their_confirmation(self):
        self.scan([self.finding(index) for index in range(12)])
        self.scan([])                                                    # held
        self.scan([self.finding(0)])                                    # 11 gone again (confirmed), one back
        self.assertEqual(len(self.fixed()), 11)
        self.assertEqual(self.status()[self.finding(0)["fingerprint"]], "open")
        self.assertNotIn("hold", registry.load(self.data_dir, KEY)["control"])


class ShadowTests(unittest.TestCase):
    setUp, tearDown, run_, status = RegistryTests.setUp, RegistryTests.tearDown, RegistryTests.run_, RegistryTests.status

    def test_shadow_mode_fixes_as_before_and_records_what_the_contract_would_do(self):
        with patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "shadow"}):
            finding = {**_finding(A), "scanner": "sast", "tool": "opengrep", "path": "app.py"}
            self.run_([finding])
            self.run_([], tools=[("opengrep", "completed")], coverage={"opengrep": {"examined": "*", "unexamined": {"app.py": "timeout"}}})
        self.assertEqual(self.status()[A], "fixed")  # as before the contract
        shadow = registry.load(self.data_dir, KEY)["control"]["shadow"]
        self.assertEqual((shadow["legacy"], shadow["proven"], shadow["legacy_only"], shadow["unseen"]), (1, 0, [A], 1))


class HealthTests(unittest.TestCase):
    setUp, tearDown, run_, status = RegistryTests.setUp, RegistryTests.tearDown, RegistryTests.run_, RegistryTests.status

    def test_health_counts_what_makes_fixes_look_doubtful(self):
        trivy = {**_finding(A), "tool": "trivy", "path": "package-lock.json", "line": 1, "cve": ["CVE-2026-1"]}
        osv = {**_finding(B), "tool": "osv-scanner", "path": "package-lock.json", "line": 1, "cve": ["CVE-2026-1"]}  # the same, apart
        self.run_([trivy, osv, _finding(C)])
        self.run_([trivy, osv])                       # C fixed
        self.run_([trivy, osv, _finding(C)], tools=[("trivy", "completed"), ("checkov", "inconclusive")])  # back an hour later
        health = registry.health(self.data_dir, [KEY])
        self.assertEqual((health["reopened_soon"], health["duplicates"], health["engines"], health["blind_engines"], health["blind_share"]),
                         (1, 1, 2, 1, 50.0))
