"""Contract of the containerised engines: parsers against real outputs, no secrets and no faking."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import testenv

from pitangus.modules.scanning import engines as scanners
from pitangus.modules.scanning.engines import _pick_fixed, merge_secrets, parse_betterleaks, parse_opengrep, parse_trivy
from pitangus.shared.i18n import text

FIXTURES = Path(__file__).parent / "fixtures"


class TrivyParserTests(unittest.TestCase):
    def setUp(self):
        self.payload = json.loads((FIXTURES / "trivy.json").read_text(encoding="utf-8"))

    def test_three_fronts_from_one_run(self):
        findings = parse_trivy(self.payload, {"kev": {}, "epss": {}})
        kinds = {kind: sum(1 for item in findings if item["scanner"] == kind) for kind in ("sca", "iac", "secrets")}
        self.assertEqual(kinds, {"sca": 9, "iac": 5, "secrets": 1})
        self.assertTrue(all(item["tool"] == "trivy" for item in findings))

    def test_dependency_finding_carries_fix_cvss_and_stable_fingerprint(self):
        lodash = next(item for item in parse_trivy(self.payload, {"kev": {}, "epss": {}})
                      if item["package"] and item["package"]["name"] == "lodash" and item["rule_id"] == "CVE-2021-23337")
        self.assertEqual(lodash["package"]["fixed_version"], "4.17.21")
        self.assertEqual(lodash["advisory"]["cvss_score"], 7.2)
        self.assertEqual(lodash["severity"], "high")
        self.assertIn("de 4.17.20 a 4.17.21", text(lodash["remediation"]))
        self.assertEqual(lodash["cve"], ["CVE-2021-23337"])
        # Same fingerprint the OSV path would produce for the same advisory: no duplicate tickets across engines.
        from pitangus.modules.intel.advisories import fingerprint
        self.assertEqual(lodash["fingerprint"], fingerprint("sca", "CVE-2021-23337", "npm", "lodash", "4.17.20"))

    def test_kev_and_epss_enrich_priority(self):
        feeds = {"kev": {"CVE-2021-23337": {"date_added": "2021-12-01", "ransomware": False}}, "epss": {"CVE-2021-23337": (0.42, 0.97)}}
        lodash = next(item for item in parse_trivy(self.payload, feeds) if item["rule_id"] == "CVE-2021-23337")
        self.assertEqual(lodash["priority"]["action"], "act")
        self.assertEqual(lodash["epss"], {"score": 0.42, "percentile": 0.97})

    def test_misconfiguration_has_line_and_resolution(self):
        latest = next(item for item in parse_trivy(self.payload, {}) if item["scanner"] == "iac" and item["rule_id"] == "DS-0001")
        self.assertEqual(latest["path"], "Dockerfile")
        self.assertEqual(latest["line"], 1)
        self.assertIn("tag", latest["remediation"].lower())
        self.assertEqual(latest["owasp"], ["A02:2025"])

    def test_secret_value_is_never_stored(self):
        secret = next(item for item in parse_trivy(self.payload, {}) if item["scanner"] == "secrets")
        serialized = json.dumps(secret)
        self.assertNotIn("ghp_", serialized)
        self.assertNotIn("Match", serialized)
        self.assertEqual(secret["path"], "config.py")
        self.assertEqual(secret["cwe"], [798])

    def test_pick_fixed_chooses_the_next_version_above_installed(self):
        self.assertEqual(_pick_fixed("1.16.0, 0.30.2", "1.9.0"), "1.16.0")
        self.assertEqual(_pick_fixed("4.17.21", "4.17.20"), "4.17.21")
        self.assertIsNone(_pick_fixed("", "1.0.0"))
        # By version order, the nearest: not a major jump because "10" sorts before "9" as text.
        self.assertEqual(_pick_fixed("10.1.25, 9.0.90", "9.0.80"), "9.0.90")


class BetterleaksParserTests(unittest.TestCase):
    def test_finding_keeps_location_and_drops_the_value(self):
        payload = json.loads((FIXTURES / "betterleaks.json").read_text(encoding="utf-8"))
        findings = parse_betterleaks(payload)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual((finding["rule_id"], finding["path"], finding["line"]), ("slack-bot-token", "config.py", 4))
        self.assertEqual(finding["severity"], "critical")
        # The value never travels: neither betterleaks' raw keys nor the token, not even redacted.
        self.assertFalse({"Secret", "Match", "Fingerprint"} & set(finding))
        serialized = json.dumps(finding)
        for forbidden in ("REDACTED", "xoxb"):
            self.assertNotIn(forbidden, serialized)

    def test_same_secret_from_two_engines_is_one_finding(self):
        """Both engines read one value, so both carry its identity: one finding in every identity mode."""
        # As read from the file (parsed here without it: unlinkable, so given the value's identity by hand).
        a = [{**parse_betterleaks(json.loads((FIXTURES / "betterleaks.json").read_text(encoding="utf-8")))[0], "identity": "i" * 64,
              "unlinkable": False, "value_formers": []}]
        b = [{**a[0], "tool": "trivy", "fingerprint": "otra"}]
        for mode in ("v1", "shadow", "v2"):
            with self.subTest(mode=mode), patch.dict("os.environ", {"PITANGUS_IDENTITY_MODE": mode}):
                merged = merge_secrets(a, b)
                self.assertEqual(len(merged), 1)
                self.assertEqual(merged[0]["also_detected_by"], ["trivy"])
                # Another value on the same line is another secret, whatever the rules say.
                self.assertEqual(len(merge_secrets(a, [{**b[0], "identity": "j" * 64}])), 2)

    def test_without_an_identity_two_engines_are_never_joined_in_v2(self):
        """A secret whose value couldn't be read (unlinkable: scanning/secret_location.py) keeps its engine's report: v2 never joins
        two by guess, the modes before it do on the same line (test_different_secrets_on_one_line_are_never_merged)."""
        a = parse_betterleaks(json.loads((FIXTURES / "betterleaks.json").read_text(encoding="utf-8")))
        b = [{**a[0], "tool": "trivy", "fingerprint": "otra"}]
        with patch.dict("os.environ", {"PITANGUS_IDENTITY_MODE": "v2"}):
            self.assertEqual(len(merge_secrets(a, b)), 2)
        with patch.dict("os.environ", {"PITANGUS_IDENTITY_MODE": "shadow"}):
            self.assertEqual(len(merge_secrets(a, b)), 1)

    def test_different_secrets_on_one_line_are_never_merged_by_their_identities(self):
        """The same minified line in v2 (the default): each value its identity; Trivy's report of the Slack token reads
        the Slack token's value."""
        base = {"scanner": "secrets", "path": "config.json", "line": 1, "severity": "critical"}
        rules = ("github-pat", "slack-bot-token", "stripe-access-token")
        betterleaks = [{**base, "tool": "betterleaks", "rule_id": rule, "fingerprint": rule, "identity": str(index) * 64} for index, rule in enumerate(rules)]
        slack = {**base, "tool": "trivy", "rule_id": "slack-access-token", "fingerprint": "t", "identity": "1" * 64}
        with patch.dict("os.environ", {"PITANGUS_IDENTITY_MODE": "v2"}):
            merged = merge_secrets(betterleaks, [slack])
            self.assertEqual([item.get("also_detected_by") for item in merged], [None, ["trivy"], None])
            self.assertEqual(len(merge_secrets(betterleaks, [{**slack, "rule_id": "private-key", "identity": "9" * 64}])), 4)

    @patch.dict("os.environ", {"PITANGUS_IDENTITY_MODE": "shadow"})
    def test_different_secrets_on_one_line_are_never_merged(self):
        """A minified config with a GitHub token, a Slack token and a Stripe key on one line: three findings. Without
        the values' identities, as the modes before v2 join them (by rule, on the same line)."""
        base = {"scanner": "secrets", "path": "config.json", "line": 1, "severity": "critical"}
        betterleaks = [{**base, "tool": "betterleaks", "rule_id": rule, "fingerprint": rule} for rule in ("github-pat", "slack-bot-token", "stripe-access-token")]
        # Trivy names a Slack bot token slack-access-token (its rule covers every xox… token): the same secret.
        merged = merge_secrets(betterleaks, [{**base, "tool": "trivy", "rule_id": "slack-access-token", "fingerprint": "t"}])
        self.assertEqual([item["rule_id"] for item in merged], ["github-pat", "slack-bot-token", "stripe-access-token"])
        self.assertEqual([item.get("also_detected_by") for item in merged], [None, ["trivy"], None])
        # Equal for merging only: turning Betterleaks' bot-token rule off doesn't turn Trivy's broader rule off.
        from pitangus.modules.scanning.secret_builtin_rules import TRIVY_EQUIVALENTS
        self.assertNotIn("slack-bot-token", TRIVY_EQUIVALENTS)
        # Another engine's secret on that line that matches none of them is a finding of its own.
        merged = merge_secrets(betterleaks, [{**base, "tool": "trivy", "rule_id": "private-key", "fingerprint": "k"}])
        self.assertEqual(len(merged), 4)


class OpengrepParserTests(unittest.TestCase):
    def setUp(self):
        self.payload = json.loads((FIXTURES / "opengrep.json").read_text(encoding="utf-8"))

    def test_all_seven_languages_yield_findings_with_metadata(self):
        findings = parse_opengrep(self.payload)
        languages = {item["rule_id"].split(".")[1] for item in findings}
        self.assertEqual(languages, {"js", "py", "java", "go", "php", "rb", "cs"})
        self.assertTrue(all(item["rule_id"].startswith("appsec.") for item in findings))
        self.assertTrue(all(item["cwe"] for item in findings), "toda regla propia declara CWE")

    def test_severity_mapping_and_critical_override(self):
        findings = parse_opengrep(self.payload)
        eval_js = next(item for item in findings if item["rule_id"] == "appsec.js.eval-non-literal")
        self.assertEqual(eval_js["severity"], "critical")
        self.assertEqual(eval_js["priority"]["action"], "act")
        weak = next(item for item in findings if item["rule_id"] == "appsec.js.weak-hash")
        self.assertEqual(weak["severity"], "low")
        self.assertEqual(eval_js["path"], "app.js")

    def test_fingerprint_follows_the_snippet_not_the_line(self):
        result = next(item for item in self.payload["results"] if item["check_id"].endswith("js.eval-non-literal"))
        moved = {**result, "start": {**result["start"], "line": result["start"]["line"] + 40}}
        original = parse_opengrep({"results": [result]})[0]["fingerprint"]
        shifted = parse_opengrep({"results": [moved]})[0]["fingerprint"]
        self.assertEqual(original, shifted)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        testenv.docker_runner(self)

    def test_without_docker_each_engine_declares_not_tested_and_never_runs(self):
        with patch.dict(scanners._docker_state, {"ok": False}, clear=True), \
                patch("pitangus.modules.scanning.engines._run", side_effect=AssertionError("lanzó un contenedor")):
            for runner in (lambda: scanners.run_opengrep(Path(".")), lambda: scanners.run_betterleaks(Path(".")),
                           lambda: scanners.run_trivy(Path("."), Path("/tmp/x"), {})):
                result = runner()
                self.assertEqual(result["status"], "not_tested")
                self.assertIn("Docker", text(result["detail"]))
                self.assertEqual(result["findings"], [])

    def test_a_timed_out_engine_container_is_removed(self):
        import subprocess
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            if command[1] == "run":
                raise subprocess.TimeoutExpired(command, kwargs.get("timeout"))
            return subprocess.CompletedProcess(command, 0, "", "")
        with patch("pitangus.modules.scanning.engines.shutil.which", return_value="docker"), \
                patch("pitangus.modules.scanning.engines.subprocess.run", side_effect=run):
            with self.assertRaises(subprocess.TimeoutExpired):
                scanners._run("betterleaks", ["version"], None, timeout=1)
        name = calls[0][calls[0].index("--name") + 1]
        self.assertEqual(calls[1], ["docker", "rm", "--force", name])


if __name__ == "__main__":
    unittest.main()


class DevDependencyTests(unittest.TestCase):
    def test_dev_dependencies_are_included_marked_and_deprioritized(self):
        from pitangus.modules.scanning.engines import parse_trivy
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        def vuln(name, pkg_id):
            return {"VulnerabilityID": f"CVE-2026-{len(name)}000", "PkgID": pkg_id, "PkgName": name, "InstalledVersion": "1.0.0",
                    "FixedVersion": "1.0.1", "Severity": "CRITICAL", "CVSS": {"nvd": {"V3Vector": vector}}, "Title": name}
        payload = {"Results": [{"Target": "pnpm-lock.yaml", "Type": "pnpm", "Class": "lang-pkgs",
                                "Packages": [{"ID": "postcss@1.0.0", "Name": "postcss", "Dev": True, "Relationship": "indirect"},
                                             {"ID": "express@1.0.0", "Name": "express", "Relationship": "direct"}],
                                "Vulnerabilities": [vuln("postcss", "postcss@1.0.0"), vuln("express", "express@1.0.0")]}]}
        by_name = {item["package"]["name"]: item for item in parse_trivy(payload, {})}
        self.assertTrue(by_name["postcss"]["package"]["dev"])
        # Critical without KEV or high EPSS: «attend» in production, one level lower for a dev dependency.
        self.assertEqual((by_name["express"]["priority"]["action"], by_name["postcss"]["priority"]["action"]), ("attend", "track"))
        self.assertIn("desarrollo", " ".join(text(item) for item in by_name["postcss"]["priority"]["factors"]))
        self.assertFalse(by_name["express"]["package"]["dev"])
        self.assertTrue(by_name["express"]["package"]["direct"])
        # With high EPSS, «act» drops to «attend»; in CISA KEV it is not lowered even for a dev dependency.
        epss = {"epss": {"CVE-2026-7000": (0.5, 0.99)}}
        self.assertEqual({item["package"]["name"]: item for item in parse_trivy(payload, epss)}["postcss"]["priority"]["action"], "attend")
        kev = {"kev": {"CVE-2026-7000": {"date_added": "2026-09-01"}}}
        self.assertEqual({item["package"]["name"]: item for item in parse_trivy(payload, kev)}["postcss"]["priority"]["action"], "act")


class TrivyDatabaseTests(unittest.TestCase):
    """Trivy's databases are refreshed once, before the scans, which never update the shared cache themselves; a
    refresh lands in a folder of its own and replaces the live database only when it arrived whole."""

    def setUp(self):
        import tempfile
        self.cache = Path(tempfile.mkdtemp())

    @staticmethod
    def stamp(hours):
        from datetime import datetime, timedelta, timezone
        return (datetime.now(timezone.utc) + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.123456789Z")  # Trivy's nanoseconds

    def database(self, root, folder, *, next_update=None, downloaded=None, content=b"bolt"):
        (root / folder).mkdir(parents=True, exist_ok=True)
        metadata = {"NextUpdate": next_update} if next_update else {"DownloadedAt": downloaded, "MajorVersion": 2}
        (root / folder / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
        if content is not None:
            (root / folder / "data.db").write_bytes(content)

    def meta(self, folder, hours):
        self.database(self.cache, folder, next_update=self.stamp(hours))

    def checks(self, hours):
        """The checks bundle's metadata: Trivy writes when it downloaded it and fetches it again a day later."""
        self.database(self.cache, "policy", downloaded=self.stamp(-hours))

    def refresh(self, *, outcome="ok"):
        """Runs the refresh with a fake Trivy that downloads into the folder it was given (`outcome`: ok, exit, empty)."""
        from unittest.mock import patch
        calls = []

        def download(key, arguments, *rest, mounts=(), env=None, **options):
            calls.append(arguments[1])
            staging = Path(mounts[1].split(":")[0])
            self.assertEqual(env, {"TMPDIR": "/cache/tmp"})  # temporary files on the disk, never the in-memory /tmp
            self.assertTrue((staging / "tmp").is_dir())
            folder = "policy" if arguments[0] == "config" else "db" if arguments[1] == "--download-db-only" else "java-db"
            if outcome == "empty":  # metadata written, the database cut short
                self.database(staging, folder, next_update=self.stamp(24), downloaded=self.stamp(0), content=None)
            elif outcome == "ok":
                self.database(staging, folder, next_update=None if folder == "policy" else self.stamp(24),
                              downloaded=self.stamp(0), content=b"new")
            return subprocess.CompletedProcess(arguments, 1 if outcome == "exit" else 0, "", "no space left on device" if outcome == "exit" else "")

        with patch.object(scanners, "_run", side_effect=download):
            flags = scanners.trivy_databases(self.cache, None)
        return calls, flags

    def test_a_fresh_database_isnt_downloaded_and_the_scan_skips_updating_it(self):
        self.meta("db", 5)
        self.checks(hours=3)
        self.assertEqual(self.refresh(), ([], ["--skip-db-update", "--skip-check-update"]))

    def test_a_due_or_missing_database_is_downloaded_once_and_java_only_when_trivy_has_it(self):
        target = "/cache/" + scanners.CHECKS_TARGET
        self.assertEqual(self.refresh(), (["--download-db-only", target], ["--skip-db-update", "--skip-check-update"]))
        self.meta("db", -1)
        self.meta("java-db", -1)
        self.checks(hours=25)  # a checks bundle older than a day is due, as Trivy would see it
        self.assertEqual(self.refresh(), (["--download-db-only", "--download-java-db-only", target],
                                          ["--skip-db-update", "--skip-java-db-update", "--skip-check-update"]))
        self.assertEqual((self.cache / "java-db" / "data.db").read_bytes(), b"new")  # swapped in
        self.assertEqual(sorted(path.name for path in self.cache.iterdir()), ["db", "java-db", "policy"])  # nothing left over

    def test_a_refresh_that_fails_never_touches_the_database_in_use(self):
        for outcome in ("exit", "empty"):
            with self.subTest(outcome=outcome):
                self.meta("java-db", -1)
                (self.cache / "java-db" / "data.db").write_bytes(b"old")
                self.meta("db", 5)
                self.checks(hours=3)
                calls, flags = self.refresh(outcome=outcome)
                self.assertEqual(calls, ["--download-java-db-only"])
                self.assertEqual((self.cache / "java-db" / "data.db").read_bytes(), b"old")
                self.assertIn("--skip-java-db-update", flags)  # the stale one still serves, the scan never replaces it
                self.assertFalse((self.cache / scanners.REFRESH_DIR).exists() and any((self.cache / scanners.REFRESH_DIR).iterdir()))

class SystemPackageSeverityTests(unittest.TestCase):
    def test_an_image_system_package_takes_the_distribution_rating_not_nvd(self):
        entry = {"VulnerabilityID": "CVE-2026-1000", "PkgName": "openssl", "InstalledVersion": "3.0.11-1", "FixedVersion": "3.0.13-1",
                 "Severity": "LOW", "CVSS": {"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}}
        payload = {"Results": [{"Target": "debian 12", "Class": "os-pkgs", "Type": "debian", "Vulnerabilities": [entry]},
                               {"Target": "/src/requirements.txt", "Class": "lang-pkgs", "Type": "pip", "Vulnerabilities": [{**entry, "PkgName": "lib"}]}]}
        system, library = parse_trivy(payload, {"kev": {}, "epss": {}})
        self.assertEqual((system["severity"], library["severity"]), ("low", "critical"))  # a library keeps the CVSS score


class MonorepoTests(unittest.TestCase):
    def test_one_version_in_two_lockfiles_is_one_finding_that_names_both(self):
        from pitangus.modules.findings import fix_guide
        from pitangus.shared.i18n import localize
        entry = {"VulnerabilityID": "CVE-2026-2000", "PkgName": "lodash", "InstalledVersion": "4.17.20", "FixedVersion": "4.17.21", "Severity": "HIGH"}
        payload = {"Results": [{"Target": f"/src/{folder}/package-lock.json", "Class": "lang-pkgs", "Type": "npm", "Vulnerabilities": [entry]}
                               for folder in ("web", "api", "admin")]}
        findings = parse_trivy(payload, {"kev": {}, "epss": {}})
        self.assertEqual(len(findings), 1)
        self.assertEqual((findings[0]["path"], findings[0]["package"]["also_in"]), ("web/package-lock.json", ["admin/package-lock.json", "api/package-lock.json"]))
        steps = localize(fix_guide.guide(findings[0]), "en")["steps"]
        self.assertIn("lodash 4.17.20 is also in admin/package-lock.json, api/package-lock.json", " ".join(steps))


class IdenticalLinesTests(unittest.TestCase):
    def test_the_same_line_twice_in_a_file_is_two_findings_and_the_first_keeps_its_fingerprint(self):
        def match(line, column=1):
            return {"check_id": "rules.appsec.py.eval-input", "path": "/src/app.py", "start": {"line": line, "col": column},
                    "extra": {"lines": "eval(request.args['x'])", "message": "eval", "severity": "ERROR", "metadata": {}}}
        alone = parse_opengrep({"results": [match(3)]})
        twice = parse_opengrep({"results": [match(9), match(3), match(3, 12)]})  # a second match on line 3 is the same finding
        self.assertEqual(len(twice), 2)
        self.assertEqual(twice[0]["fingerprint"], alone[0]["fingerprint"])  # line 3, the first: unchanged
        self.assertEqual(twice[1]["line"], 9)
        self.assertNotEqual(twice[1]["fingerprint"], twice[0]["fingerprint"])


class NosemgrepTests(unittest.TestCase):
    """A match silenced with a nosemgrep comment is reported as excluded with why, under the same fingerprint it had."""

    def match(self, lines, ignored):
        return {"check_id": "rules.appsec.py.eval-exec-non-literal", "path": "/src/app.py", "start": {"line": 4},
                "extra": {"lines": lines, "message": "eval", "severity": "ERROR", "metadata": {}, "is_ignored": ignored}}

    def test_silenced_matches_are_kept_apart_and_keep_their_identity(self):
        before = parse_opengrep({"results": [self.match("    return eval(user)", False)]})
        payload = {"results": [self.match("    return eval(user)  # nosemgrep: appsec.py.eval-exec-non-literal", True)]}
        self.assertEqual(parse_opengrep(payload), [])
        (silenced,) = parse_opengrep(payload, silenced=True)
        self.assertEqual(silenced["fingerprint"], before[0]["fingerprint"])  # adding the comment doesn't make it another finding
        for comment in ("// nosemgrep", "/* nosemgrep */", "-- nosemgrep", "# NOSEMGREP"):
            self.assertEqual(scanners.NOSEM_COMMENT.sub("", f"x = run(y)  {comment}"), "x = run(y)", comment)

    def test_opengrep_runs_without_honouring_them_and_lists_them_as_excluded(self):
        payload = {"results": [self.match("eval(user)  # nosemgrep", True), {**self.match("eval(other)", False), "start": {"line": 9}}],
                   "paths": {"skipped": [{"path": "/src/huge.py", "reason": "exceeded_size_limit"},
                                         {"path": "/src/tests/x.py", "reason": "cli_exclude_flags_match"}]},
                   # As Opengrep 1.30.0 reports a rule that ran out of time on a file (recorded on a 1.5 MB file).
                   "errors": [{"code": 2, "level": "warn", "type": "Timeout", "rule_id": "rules.appsec.py.shell-command-non-literal",
                               "message": "Timeout when running rules.appsec.py.shell-command-non-literal on /src/big.py:\n ",
                               "path": "/src/big.py"}]}
        calls = []

        def run(key, arguments, snapshot, **options):
            calls.append(arguments)
            return subprocess.CompletedProcess(arguments, 0, json.dumps(payload), "")

        with tempfile.TemporaryDirectory() as folder, patch.object(scanners, "runner", return_value="docker"), \
                patch.object(scanners, "docker_available", return_value=True), patch.object(scanners, "image_available", return_value=True), \
                patch.object(scanners, "_run", side_effect=run):
            result = scanners.run_opengrep(Path(folder))
        self.assertIn("--disable-nosem", calls[0])
        self.assertEqual([item["line"] for item in result["findings"]], [9])
        self.assertEqual(text(result["silenced"][0]["excluded_reason"], "en")[:25], "Silenced in the code with")
        # What it skipped on its own or didn't finish reading; a deliberate exclusion isn't.
        self.assertEqual(result["unexamined"], ["big.py", "huge.py"])

    def test_a_scan_lists_them_as_excluded_and_the_registry_never_takes_them_as_fixed(self):
        from pitangus.modules.findings import registry
        from pitangus.modules.scanning import repository
        from pitangus.modules.runs.store import save_repository_scan
        payloads = iter([{"results": [self.match("return eval(user)", False)]},
                         {"results": [self.match("return eval(user)  # nosemgrep", True)]}])

        def opengrep(root):
            payload = next(payloads)
            silenced = [{**item, "excluded_reason": {"$t": "scanning.opengrep.silenced_reason"}} for item in parse_opengrep(payload, silenced=True)]
            return {**scanners._result("opengrep", "completed", "", parse_opengrep(payload)), "silenced": silenced}

        empty = lambda key: lambda *args, **kwargs: scanners._result(key, "completed", "")  # noqa: E731
        replaced = {"engines_available": lambda: True, "host_mount_problem": lambda *args: None, "run_opengrep": opengrep,
                    "load_feeds": lambda *args: {"kev": {}, "epss": {}}, "run_betterleaks": empty("betterleaks"), "run_trivy": empty("trivy"),
                    "run_osv_scanner": empty("osv-scanner"), "run_checkov": empty("checkov"), "run_zizmor": empty("zizmor")}
        with tempfile.TemporaryDirectory() as folder:
            root, data_dir = Path(folder) / "code", Path(folder) / "data"
            root.mkdir()
            (root / "app.py").write_text("def new(user):\n    return eval(user)\n")
            patches = [patch.object(repository, name, side_effect=value) for name, value in replaced.items()]
            for item in patches:
                item.start()
            try:
                source = {"id": "github:org/api", "uid": "github#7", "name": "org/api", "provider": "github"}
                first = save_repository_scan(data_dir, repository.scan_repository(root, source, data_dir=data_dir))
                second = save_repository_scan(data_dir, repository.scan_repository(root, source, data_dir=data_dir))
            finally:
                for item in patches:
                    item.stop()
            digest = first["findings"][0]["fingerprint"]
            self.assertEqual([item["fingerprint"] for item in second["excluded_findings"]], [digest])
            self.assertIn("nosemgrep", " ".join(text(item, "en") for item in second["limitations"]))
            entry = registry.load(data_dir, "github#7")["findings"][digest]
            self.assertEqual((entry["status"], entry["excluded"]["reason"]["$t"]), ("excluded", "scanning.opengrep.silenced_reason"))


class CoverageLanguageTests(unittest.TestCase):
    def test_a_category_only_counts_the_rules_of_the_repository_languages(self):
        from pitangus.modules.scanning.coverage import rules_by_category
        every, go = rules_by_category(), rules_by_category(frozenset({"go"}))
        self.assertLess(sum(go.values()), sum(every.values()))
        self.assertTrue(go)
        self.assertEqual(rules_by_category(frozenset()), {})
