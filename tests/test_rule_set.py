"""What a scan records about its configuration (scanning/rule_set), which the registry reads so that a configuration
change never fixes (tests/test_invariants.py, I8)."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hypothesis import given, strategies as st

from pitangus.modules.findings import registry
from pitangus.modules.scanning import engines as engine_runs, rule_set, secret_rules
from pitangus.modules.scanning.secret_builtin_rules import OPT_IN_RULES


def _settings(**overrides) -> dict:
    return {**secret_rules.empty(), "origins": {}, **overrides}


class RuleSetTests(unittest.TestCase):
    def test_the_defaults_leave_the_opt_in_rules_third_party_rules_and_optional_engines_off(self):
        with patch.dict(os.environ, {"PITANGUS_THIRD_PARTY_RULES": "", "PITANGUS_CHECKOV_ENABLED": ""}):
            engines = rule_set.code(None)["engines"]
        self.assertEqual(engines["opengrep"]["rules"], rule_set.own_rules())
        self.assertNotIn("others", engines["opengrep"])
        self.assertEqual(engines["betterleaks"]["inactive"], sorted(OPT_IN_RULES))
        self.assertEqual(engines["checkov"], {"off": True})
        record = {"configuration": {"engines": engines}}
        for finding, cause in (({"tool": "betterleaks", "rule_id": "generic-credential-uri"}, "rule_off"),
                               ({"tool": "gitleaks", "rule_id": "generic-credential-uri"}, "rule_off"),   # Betterleaks vouches for Gitleaks' findings
                               ({"tool": "betterleaks", "rule_id": "generic-password"}, None),            # on by default since 0.14, filtered
                               ({"tool": "betterleaks", "rule_id": "github-pat"}, None),
                               ({"tool": "betterleaks", "rule_id": "pitangus-gone"}, "rule_off"),  # a custom rule no longer there
                               ({"tool": "opengrep", "rule_id": "appsec.py.gone"}, "rule_off"),    # dropped from our rules
                               ({"tool": "opengrep", "rule_id": "gitlab.python.exec.x"}, "rule_off"),
                               ({"tool": "checkov", "rule_id": "CKV_AWS_20"}, "engine_off"),
                               ({"tool": "trivy", "rule_id": "CVE-2026-1"}, None),
                               ({"tool": "osv-scanner", "rule_id": "GHSA-x"}, None)):           # declares nothing: coverage decides
            with self.subTest(finding=finding):
                self.assertEqual(registry.configuration_cause(record, finding), cause)

    def test_turning_things_on_is_recorded(self):
        custom = {"id": "internal-token", "description": "Internal", "regex": "tok_[a-z]{8}", "keywords": []}
        with patch.dict(os.environ, {"PITANGUS_THIRD_PARTY_RULES": "1", "PITANGUS_CHECKOV_ENABLED": "1"}):
            engines = rule_set.code(_settings(enabled_rules=["generic-password"], rules=[custom]))["engines"]
        self.assertEqual(engines["opengrep"]["others"], rule_set.third_party_digest())
        self.assertEqual(engines["betterleaks"]["inactive"], sorted(set(OPT_IN_RULES) - {"generic-password"}))
        self.assertIn("pitangus-internal-token", engines["betterleaks"]["rules"])
        self.assertEqual(engines["checkov"], {"others": ""})
        self.assertIsNone(registry.configuration_cause({"configuration": {"engines": engines}}, {"tool": "opengrep", "rule_id": "gitlab.python.exec.x"}))

    def test_a_rule_digest_follows_what_it_matches_not_its_wording(self):
        rule = "rules:\n  - id: appsec.py.x\n    languages: [python]\n    severity: ERROR\n    message: m\n    pattern: eval($X)\n"
        base = rule_set.rule_digests([rule])["appsec.py.x"]
        self.assertEqual(rule_set.rule_digests([rule.replace("message: m", "message: other").replace("ERROR", "WARNING")])["appsec.py.x"], base)
        self.assertNotEqual(rule_set.rule_digests([rule.replace("eval($X)", "exec($X)")])["appsec.py.x"], base)
        first = rule_set.code(_settings(rules=[{"id": "t", "description": "T", "regex": "a+", "keywords": []}]))["engines"]["betterleaks"]["rules"]
        second = rule_set.code(_settings(rules=[{"id": "t", "description": "Other", "regex": "a+b", "keywords": []}]))["engines"]["betterleaks"]["rules"]
        self.assertNotEqual(first["pitangus-t"], second["pitangus-t"])

    def test_filtering_the_built_in_secret_rules_differently_changes_their_digest(self):
        record = {"configuration": rule_set.code(None)}
        seen = registry.rule_digest(record, {"tool": "betterleaks", "rule_id": "github-pat"})
        with patch.object(rule_set, "SECRET_REVISIONS", {"github-pat": "2"}):
            revised = {"configuration": rule_set.code(None)}
        self.assertEqual(registry.configuration_cause(revised, {"tool": "betterleaks", "rule_id": "github-pat"}, seen), "rule_changed")
        self.assertIsNone(registry.configuration_cause(revised, {"tool": "betterleaks", "rule_id": "generic-api-key"}, seen))
        self.assertNotEqual(rule_set.baseline()["secrets"], seen)  # 0.14 filters them (secret_filter): see below

    @given(rule=st.from_regex(r"[a-z][a-z0-9-]{2,30}", fullmatch=True), tool=st.sampled_from(["betterleaks", "gitleaks", "trivy"]))
    def test_a_secret_the_filter_sets_aside_after_upgrading_is_not_checked_never_fixed(self, rule, tool):
        """0.14 screens what every built-in secret rule of both engines reports (B1/B2): a secret seen before it, with
        the 0.13.1 stamp, that stops appearing is "not checked (configuration)"; a dependency or a custom rule isn't."""
        record, before = {"configuration": rule_set.code(None)}, rule_set.baseline()["secrets"]
        secret = {"tool": tool, "rule_id": rule, "scanner": "secrets"}
        self.assertEqual(registry.configuration_cause(record, secret, before), "rule_changed")
        self.assertEqual(registry.unproven_reason({**record, "status": "completed"}, secret, before), "configuration")
        self.assertIsNone(registry.configuration_cause(record, {"tool": "trivy", "rule_id": rule.upper(), "scanner": "sca"}, before))
        custom = {"tool": tool, "rule_id": secret_rules.engine_id(rule), "scanner": "secrets"}
        self.assertNotEqual(registry.configuration_cause(record, custom, before), "rule_changed")


class SastOptInTests(unittest.TestCase):
    """A rule measured too noisy starts off (`opt_in` in rules/*.yml): it reports nothing, the run records it as off, so
    what it found before is "not checked (rule off)", never fixed; PITANGUS_SAST_OPT_IN_RULES turns it back on."""

    def test_the_measured_rules(self):
        self.assertIn("appsec.js.dom-xss-sink", rule_set.opt_in_rules())        # 3 of 18 on the corpus
        self.assertNotIn("appsec.java.hardcoded-password", rule_set.opt_in_rules())  # sharpened instead
        self.assertTrue(set(rule_set.opt_in_rules()) <= set(rule_set.own_rules()))

    @given(st.sets(st.sampled_from([*rule_set.opt_in_rules(), "appsec.py.unknown", "appsec.java.hardcoded-password"])))
    def test_an_opt_in_rule_is_off_unless_turned_on_and_off_never_fixes(self, turned_on):
        with patch.dict(os.environ, {"PITANGUS_SAST_OPT_IN_RULES": ", ".join(sorted(turned_on))}):
            record = {"configuration": rule_set.code(None), "status": "completed", "type": "repository_scan"}
        for rule in [*rule_set.opt_in_rules(), "appsec.java.hardcoded-password"]:
            finding = {"tool": "opengrep", "rule_id": rule, "scanner": "sast", "path": "app.js"}
            off = rule in rule_set.opt_in_rules() and rule not in turned_on
            self.assertEqual(registry.configuration_cause(record, finding), "rule_off" if off else None)
            if off:
                self.assertEqual(registry.unproven_reason(record, finding), "configuration")

    def test_an_opt_in_rule_reports_nothing_until_turned_on(self):
        def result(rule: str, line: int, silenced: bool = False) -> dict:
            return {"check_id": f"rules.{rule}", "path": "/src/app.js", "start": {"line": line},
                    "extra": {"lines": "el.innerHTML = html; // nosemgrep" if silenced else "el.innerHTML = html;", "severity": "WARNING",
                              "message": "m", "metadata": {"cwe": [79]}, **({"is_ignored": True} if silenced else {})}}
        payload = {"results": [result("appsec.js.dom-xss-sink", 3), result("appsec.js.dom-xss-sink", 5, silenced=True),
                               result("appsec.js.eval-non-literal", 7)], "paths": {}}

        def run(key, arguments, snapshot, **options):
            return subprocess.CompletedProcess(arguments, 1, json.dumps(payload), "")

        def scan(turned_on: str) -> dict:
            with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"PITANGUS_SAST_OPT_IN_RULES": turned_on}), \
                    patch.object(engine_runs, "runner", return_value="docker"), patch.object(engine_runs, "docker_available", return_value=True), \
                    patch.object(engine_runs, "image_available", return_value=True), patch.object(engine_runs, "_run", side_effect=run):
                (Path(folder) / "app.js").write_text("el.innerHTML = html;\n" * 8)
                return engine_runs.run_opengrep(Path(folder))
        rules = lambda items: sorted(item["rule_id"] for item in items)  # noqa: E731
        off = scan("")
        self.assertEqual((rules(off["findings"]), rules(off["silenced"]), rules(off["vendored"])), (["appsec.js.eval-non-literal"], [], []))
        on = scan("appsec.js.dom-xss-sink")
        self.assertEqual((rules(on["findings"]), rules(on["silenced"])), (["appsec.js.dom-xss-sink", "appsec.js.eval-non-literal"], ["appsec.js.dom-xss-sink"]))


if __name__ == "__main__":
    unittest.main()
