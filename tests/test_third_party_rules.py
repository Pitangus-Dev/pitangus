"""Third-party Opengrep rules (third_party/gitlab-sast-rules): pinned file by file, licensed apart from ours, off unless
turned on, and read like ours when they are."""

import copy
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hypothesis import given, settings, strategies as st

from pitangus.modules.scanning import engines, sast_merge
from pitangus.shared import paths

PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

FOLDER = paths.THIRD_PARTY_RULES_DIR.parent


class PinnedTests(unittest.TestCase):
    def test_every_rule_file_is_the_pinned_one_and_carries_a_permissive_license(self):
        pinned = dict(reversed(line.split("  ", 1)) for line in (FOLDER / "SHA256SUMS").read_text().splitlines())
        files = sorted(path.relative_to(FOLDER).as_posix() for path in paths.THIRD_PARTY_RULES_DIR.rglob("*.yml"))
        self.assertEqual(sorted(pinned), files)  # nothing added or removed without updating the pins
        for name in files:
            content = (FOLDER / name).read_bytes()
            self.assertEqual(hashlib.sha256(content).hexdigest(), pinned[name], name)
            header = content.decode()[:300]
            self.assertRegex(header, r"License: (MIT \(c\) GitLab Inc\.|Apache 2\.0 \(c\) gosec)", name)
        self.assertTrue((FOLDER / "LICENSE").is_file() and (FOLDER / "LICENSE-APACHE-2.0").is_file() and (FOLDER / "NOTICE").is_file())

    def test_they_never_sit_with_pitangus_own_rules(self):
        self.assertFalse(any(paths.RULES_DIR.rglob("*sast-rules*")))
        self.assertNotIn(paths.RULES_DIR, paths.THIRD_PARTY_RULES_DIR.parents)


class SwitchTests(unittest.TestCase):
    def test_off_by_default_and_on_both_sets_go_to_the_engine_apart(self):
        with tempfile.TemporaryDirectory() as folder:
            snapshot = Path(folder) / "snapshot"
            snapshot.mkdir()
            with patch.dict(os.environ, {"PITANGUS_THIRD_PARTY_RULES": ""}), patch.object(engines, "in_container", return_value=False):
                self.assertEqual(engines._rules_for(snapshot), engines.RULES_DIR)
            with patch.dict(os.environ, {"PITANGUS_THIRD_PARTY_RULES": "1"}):
                combined = engines._rules_for(snapshot)
            self.assertEqual(sorted(path.name for path in (combined / "pitangus").glob("*.yml")),
                             sorted(path.name for path in engines.RULES_DIR.glob("*.yml")))
            self.assertEqual(len(list((combined / "gitlab").rglob("*.yml"))), len(list(paths.THIRD_PARTY_RULES_DIR.rglob("*.yml"))))

    def test_their_findings_read_like_ours(self):
        report = {"results": [{"check_id": "rules.gitlab.python.exec.python_exec_rule-subprocess-popen-shell-true", "path": "/src/app.py",
                               "start": {"line": 3}, "extra": {"lines": "subprocess.call(cmd, shell=True)", "severity": "ERROR", "message": "Shell",
                                                               "metadata": {"cwe": "CWE-78", "owasp": ["A1:2017-Injection", "A03:2021-Injection"],
                                                                            "shortDescription": "Command injection with shell=True",
                                                                            "category": "security"}}}]}
        (finding,) = engines.parse_opengrep(report)
        self.assertEqual((finding["rule_id"], finding["cwe"], finding["owasp"], finding["title"]),
                         ("gitlab.python.exec.python_exec_rule-subprocess-popen-shell-true", [78], ["A03:2021"], "Command injection with shell=True"))


def _finding(index: int, own: bool, path: str, line: int, cwe: list[int], severity: str) -> dict:
    rule = f"appsec.js.rule-{index % 3}" if own else f"gitlab.javascript.rule-{index % 4}"
    return {"scanner": "sast", "tool": "opengrep", "rule_id": rule, "path": path, "line": line, "cwe": cwe, "severity": severity,
            "title": f"title of {rule}", "remediation": f"fix for {rule}", "fingerprint": f"fp-{index}", "confidence": 6}


# Overlapping sets: few places, few weakness classes (siblings included), so twins are common.
findings = st.lists(st.tuples(st.booleans(), st.sampled_from(["a.js", "b.js"]), st.integers(1, 3),
                              st.lists(st.sampled_from([77, 78, 79, 80, 89, 943, 22, 327]), min_size=1, max_size=2, unique=True),
                              st.sampled_from(["low", "medium", "high"])), max_size=14).map(
    lambda rows: [_finding(index, *row) for index, row in enumerate(rows)])


class MergeTests(unittest.TestCase):
    """Turned on, a GitLab rule that sees what one of ours sees on the same line adds nothing but its rule id."""

    @settings(max_examples=200 * SCALE)
    @given(findings)
    def test_merging_is_idempotent(self, found):
        once = sast_merge.merge(found)
        self.assertEqual(sast_merge.merge(once), once)

    @settings(max_examples=200 * SCALE)
    @given(findings)
    def test_no_distinct_problem_is_lost_and_ours_keep_their_metadata(self, found):
        before = copy.deepcopy(found)
        merged = sast_merge.merge(found)
        self.assertEqual(found, before)  # the engine's list is left as it was
        by_fingerprint = {item["fingerprint"]: item for item in merged}
        for item in found:
            if sast_merge.own(item):  # every one of ours, unchanged but for what it absorbed
                kept = by_fingerprint[item["fingerprint"]]
                self.assertEqual({key: value for key, value in kept.items() if key not in ("related_rules", "previous_fingerprints")}, item)
            elif item["fingerprint"] not in by_fingerprint:  # a third-party one only goes into a twin of ours, which names it
                hosts = [other for other in merged if sast_merge.own(other) and sast_merge.twins(item, other)]
                self.assertTrue(hosts, item)
                for host in hosts:
                    self.assertIn(item["rule_id"], host["related_rules"])
                    self.assertIn(item["fingerprint"], host["previous_fingerprints"])
            else:  # and stays whenever none of ours saw that problem there
                self.assertFalse(any(sast_merge.own(other) and sast_merge.twins(item, other) for other in found))
        self.assertEqual(sum(map(sast_merge.own, merged)), sum(map(sast_merge.own, found)))  # ours are never joined

    @settings(max_examples=100 * SCALE)
    @given(findings, st.randoms(use_true_random=False))
    def test_the_order_the_engine_reports_them_in_changes_nothing(self, found, random):
        shuffled = random.sample(found, len(found))
        key = lambda items: sorted(items, key=lambda item: item["fingerprint"])  # noqa: E731
        self.assertEqual(key(sast_merge.merge(shuffled)), key(sast_merge.merge(found)))

    def test_siblings_count_as_one_weakness_and_others_do_not(self):
        ours = _finding(0, True, "a.js", 3, [78], "high")
        self.assertTrue(sast_merge.twins(_finding(1, False, "a.js", 3, [77], "low"), ours))
        self.assertFalse(sast_merge.twins(_finding(1, False, "a.js", 3, [79], "low"), ours))
        self.assertFalse(sast_merge.twins(_finding(1, False, "a.js", 4, [78], "low"), ours))

    def test_opengrep_reports_one_finding_with_both_rule_ids(self):
        def match(rule, cwe):
            return {"check_id": rule, "path": "/src/app.js", "start": {"line": 4},
                    "extra": {"lines": "el.innerHTML = html;", "severity": "WARNING", "message": "XSS", "metadata": {"cwe": cwe}}}
        payload = {"results": [match("rules.pitangus.appsec.js.dom-xss-sink", [79]),
                               match("rules.gitlab.javascript.xss.rule-xss", "CWE-79: Cross-site Scripting")], "paths": {}}

        def run(key, arguments, snapshot, **options):
            return subprocess.CompletedProcess(arguments, 0, json.dumps(payload), "")

        def scan(turned_on: str) -> list[dict]:
            with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"PITANGUS_SAST_OPT_IN_RULES": turned_on}), \
                    patch.object(engines, "runner", return_value="docker"), patch.object(engines, "docker_available", return_value=True), \
                    patch.object(engines, "image_available", return_value=True), patch.object(engines, "_run", side_effect=run):
                (Path(folder) / "app.js").write_text("el.innerHTML = html;\n" * 4)
                return engines.run_opengrep(Path(folder))["findings"]
        (finding,) = scan("appsec.js.dom-xss-sink")
        self.assertEqual((finding["rule_id"], finding["related_rules"]), ("appsec.js.dom-xss-sink", ["gitlab.javascript.xss.rule-xss"]))
        # Ours off by default (rule_set.opt_in_rules): the third-party match stands on its own.
        self.assertEqual([item["rule_id"] for item in scan("")], ["gitlab.javascript.xss.rule-xss"])


if __name__ == "__main__":
    unittest.main()
