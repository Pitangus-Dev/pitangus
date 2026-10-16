"""Stable fingerprints: a secret keeps its identity when lines move, an advisory on a package has one fingerprint
whichever engine reports it, and a finding whose fingerprint changed formula keeps its state, triage, issue and
verification."""

import copy
import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pitangus.modules.scanning.secret_location import entropy
from pitangus.modules.findings import registry, tickets, triage, verifications
from pitangus.modules.intel.advisories import dependency_finding, fingerprint
from pitangus.modules.pullrequests.review import classify
from pitangus.modules.runs import registry as run_registry
from pitangus.modules.runs.store import save_repository_scan
from pitangus.modules.intel.packages import dependency_fingerprint
from pitangus.modules.scanning import config_engines, engines, image
from test_dashboard import _finding, _scan

# Placeholders stand where the secrets were: the parser only reads what precedes each one.
# Shaped like issued tokens: a run like "AAAA…" is a placeholder (secret_filter) and would never be a finding.
FIRST, SECOND = "gNSWPH8prVqsUeQCtDR3zzX6hqo35uwZqxZOOHjk", "JQQrkaPehMvbfrn2yzL7C5Mg3PR4hLLOOxl3gV3F"
PAIR_A, PAIR_B = "GRmrCNnFZsGqgh0frrhbkVAhRHLfBERkIyDtFDBA", "M0gqEzpC3N8FeKjFTrKCb0Tz8BbwTKx8EqwtHmcO"
KEY_VALUE = "JEZqgygcmtbaLGsH7Zwqhc9jXmaoq3Gq"  # gitleaks:allow


def source(first=FIRST, pair_a=PAIR_A):
    return (f'GITHUB_TOKEN = "{first}"\n# comment\n  token: {SECOND}\napi_key = "{KEY_VALUE}"\n'
            f'pair = ["{pair_a}", "{PAIR_B}"]\n')


def betterleaks(shift: int, first: str = FIRST, pair_a: str = PAIR_A) -> list[dict]:
    """What Betterleaks reports (--redact) for `source(first, pair_a)`, and with `shift` lines added on top: a Gitleaks
    8.30.1 recording with its columns as Betterleaks gives them (from 1 on every line, the last one included; checked
    with 1.9.0), and each secret's entropy."""
    return [{"RuleID": "github-pat", "File": "/src/app.py", "StartLine": 1 + shift, "StartColumn": 17, "EndColumn": 56,
             "Match": "REDACTED", "Entropy": entropy(first)},
            {"RuleID": "github-pat", "File": "/src/app.py", "StartLine": 3 + shift, "StartColumn": 10, "EndColumn": 49,
             "Match": "REDACTED", "Entropy": entropy(SECOND)},
            {"RuleID": "github-pat", "File": "/src/app.py", "StartLine": 5 + shift, "StartColumn": 10, "EndColumn": 49,
             "Match": "REDACTED", "Entropy": entropy(pair_a)},
            {"RuleID": "github-pat", "File": "/src/app.py", "StartLine": 5 + shift, "StartColumn": 54, "EndColumn": 93,
             "Match": "REDACTED", "Entropy": entropy(PAIR_B)},
            {"RuleID": "generic-api-key", "File": "/src/app.py", "StartLine": 4 + shift, "StartColumn": 1, "EndColumn": 44,
             "Match": 'api_key = "REDACTED"', "Entropy": entropy(KEY_VALUE)}]


def trivy(shift: int) -> dict:
    """What Trivy 0.74.0 reported for the same file (recorded): `Match` masks every secret on the line."""
    mask = "*" * 40
    secrets = [(1, f'GITHUB_TOKEN = "{mask}"'), (3, f"  token: {mask}"), (5, f'pair = ["{mask}", "{mask}"]'),
               (5, f'pair = ["{mask}", "{mask}"]')]
    return {"Results": [{"Target": "app.py", "Class": "secret", "Secrets": [
        {"RuleID": "github-pat", "Category": "GitHub", "Severity": "CRITICAL", "Title": "GitHub Personal Access Token",
         "StartLine": line + shift, "EndLine": line + shift, "Match": match} for line, match in secrets]}]}


class SecretIdentityTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)

    def snapshot(self, text: str) -> Path:
        root = Path(self.folder.name) / str(len(list(Path(self.folder.name).iterdir())))
        root.mkdir()
        (root / "app.py").write_text(text)
        return root

    def test_betterleaks_secrets_keep_their_fingerprint_when_lines_are_added_above(self):
        before = engines.parse_betterleaks(betterleaks(0), None, self.snapshot(source()))
        after = engines.parse_betterleaks(betterleaks(2), None, self.snapshot("import os\n\n" + source()))
        self.assertEqual([item["fingerprint"] for item in before], [item["fingerprint"] for item in after])
        self.assertEqual(len({item["fingerprint"] for item in before}), 5)
        # The former, line-based fingerprint travels along so the registry can carry the finding over.
        self.assertEqual(before[0]["previous_fingerprint"], engines._stable("secrets", "github-pat", "app.py", "1"))
        self.assertEqual([item["line"] for item in after], [3, 5, 7, 7, 6])

    def test_no_secret_value_goes_into_a_fingerprint(self):
        """The second secret on a line is identified by what precedes it with the first one masked: changing the
        first one's value changes nothing."""
        before = engines.parse_betterleaks(betterleaks(0), None, self.snapshot(source()))
        first, pair_a = "ZtWh0bA6yv4UdR1mLx9Kq8cNp3eHs7Ug2fJo5iXb", "Pd3kQw9Lz1Vb7Nt4Hy0Rc6Mx2Jf8Gs5Ue1Ka3Op7"
        rotated = engines.parse_betterleaks(betterleaks(0, first, pair_a), None, self.snapshot(source(first=first, pair_a=pair_a)))
        self.assertEqual([item["fingerprint"] for item in before], [item["fingerprint"] for item in rotated])

    def test_trivy_secrets_keep_their_fingerprint_when_lines_are_added_above(self):
        before = engines.parse_trivy(trivy(0), {}, root=self.snapshot(source()))
        after = engines.parse_trivy(trivy(2), {}, root=self.snapshot("import os\n\n" + source()))
        self.assertEqual([item["fingerprint"] for item in before], [item["fingerprint"] for item in after])
        self.assertEqual(len({item["fingerprint"] for item in before}), 4)  # both on the pair line are kept
        self.assertEqual(before[0]["previous_fingerprint"], engines._stable("secrets", "github-pat", "app.py", "1"))

    def test_without_the_snapshot_a_secret_is_unlinkable_and_never_named_by_its_place(self):
        """Without the file its value can't be read: the rule, the file and the line are any value's, so they never
        name it (R2); each report gets a name of its own."""
        found, again = engines.parse_betterleaks(betterleaks(0)), engines.parse_betterleaks(betterleaks(0))
        self.assertTrue(all(item.get("unlinkable") for item in found))
        self.assertNotEqual(found[0]["fingerprint"], engines._stable("secrets", "github-pat", "app.py", "1"))
        self.assertFalse({item["fingerprint"] for item in found} & {item["fingerprint"] for item in again})
        self.assertNotIn("previous_fingerprint", found[0])

    def test_internal_patterns_keep_their_fingerprint_when_lines_are_added_above(self):
        from pitangus.modules.scanning.repository import _secret_candidates
        token = "ghp_" + "Q" * 36
        before = _secret_candidates(self.snapshot(f'TOKEN = "{token}"\n') / "app.py", "app.py")
        after = _secret_candidates(self.snapshot(f'import os\n\nTOKEN = "{token}"\n') / "app.py", "app.py")
        self.assertEqual([item["fingerprint"] for item in before], [item["fingerprint"] for item in after])
        self.assertEqual((before[0]["line"], after[0]["line"]), (1, 3))

    def test_a_long_line_full_of_secrets_is_read_in_bounded_windows(self):
        import time

        def read(count):
            line = "".join(f'k{index} = "{FIRST}"; ' for index in range(count))
            starts = [found.start() for found in re.finditer(FIRST, line)]
            self.assertEqual(len(starts), count)
            report = [{"RuleID": "github-pat", "File": "/src/app.py", "StartLine": 1, "StartColumn": start + 1,
                       "EndColumn": start + 40, "Match": "REDACTED", "Entropy": entropy(FIRST)} for start in starts]
            snapshot = self.snapshot(line + "\n")
            started = time.process_time()
            found = engines.parse_betterleaks(report, None, snapshot)
            self.assertEqual(len({item["fingerprint"] for item in found}), count)
            return time.process_time() - started

        # Bounded windows mean the work grows linearly with the secrets on the line, whatever the machine: doubling
        # them must stay well under quadrupling the CPU time (absolute seconds depend on the CI runner).
        small, large = min(read(500) for _ in range(2)), min(read(1000) for _ in range(2))
        self.assertLess(large, 3.5 * small + 0.2)

    def test_a_path_outside_the_snapshot_is_never_read(self):
        root = self.snapshot(source())
        outside = [{**betterleaks(0)[0], "File": "/src/../../etc/passwd"}]
        found = engines.parse_betterleaks(outside, None, root)
        self.assertNotIn("previous_fingerprint", found[0])


class DependencyFingerprintTests(unittest.TestCase):
    """The same advisory on the same package version, as each engine names it."""

    def test_every_engine_gives_the_same_fingerprint(self):
        trivy_finding = engines._trivy_vulnerability(
            {"VulnerabilityID": "CVE-2026-1111", "PkgName": "Typing_Extensions", "InstalledVersion": "4.0.0", "Severity": "HIGH"},
            "requirements.txt", "pip", {})
        advisory = {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-1111"], "summary": "Bad"}
        osv_api = dependency_finding({"ecosystem": "PyPI", "name": "typing-extensions", "version": "4.0.0", "path": "requirements.txt"},
                                     advisory, {})
        osv_scanner = engines.parse_osv_scanner({"results": [{"source": {"path": "/src/requirements.txt"}, "packages": [
            {"package": {"name": "typing-extensions", "version": "4.0.0", "ecosystem": "PyPI"},
             "vulnerabilities": [advisory], "groups": [{"ids": ["GHSA-aaaa-bbbb-cccc"], "aliases": ["CVE-2026-1111"]}]}]}]}, {})[0]
        grype = image._grype_finding({"vulnerability": {"id": "GHSA-aaaa-bbbb-cccc", "severity": "High"},
                                      "relatedVulnerabilities": [{"id": "CVE-2026-1111"}],
                                      "artifact": {"name": "typing_extensions", "version": "4.0.0", "type": "python"}}, {})
        prints = {item["fingerprint"] for item in (trivy_finding, osv_api, osv_scanner, grype)}
        self.assertEqual(len(prints), 1)
        # The former fingerprints travel along, so the registry carries existing findings over.
        self.assertEqual(trivy_finding["previous_fingerprint"], fingerprint("sca", "CVE-2026-1111", "pip", "Typing_Extensions", "4.0.0"))
        self.assertEqual(osv_api["previous_fingerprint"], fingerprint("sca", "GHSA-aaaa-bbbb-cccc", "PyPI", "typing-extensions", "4.0.0"))
        self.assertNotIn("previous_fingerprint", osv_scanner)  # OSV-Scanner already used it

    def test_an_unchanged_fingerprint_carries_no_former_one(self):
        finding = engines._trivy_vulnerability({"VulnerabilityID": "CVE-2026-2222", "PkgName": "axios", "InstalledVersion": "1.0.0"},
                                               "package-lock.json", "npm", {})
        self.assertNotIn("previous_fingerprint", finding)

    def test_image_packages_keep_one_os_family(self):
        finding = image._finish_package({"rule_id": "CVE-2026-3333", "cve": ["CVE-2026-3333"], "ghsa": [],
                                         "package": {"ecosystem": "debian", "name": "openssl", "version": "3.0.1"}})
        self.assertEqual(finding["fingerprint"], fingerprint("sca", "CVE-2026-3333", "os", "openssl", "3.0.1"))
        self.assertNotIn("previous_fingerprint", finding)


KEY = "github#7"
OLD, NEW = "0" * 64, "1" * 64
USER = {"username": "ana", "role": "member"}


class CarryOverTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.clock = datetime.now(timezone.utc)

    def run_(self, findings):
        self.clock += timedelta(hours=1)
        record = _scan("org/api", findings, self.clock.isoformat())
        record["source"]["uid"] = KEY
        record["finished_at"] = self.clock.isoformat()
        return save_repository_scan(self.data_dir, record, created_at=self.clock.isoformat())

    def test_a_new_fingerprint_keeps_state_triage_issue_and_verification(self):
        first = self.run_([_finding(OLD)])
        state = registry.view(self.data_dir, KEY, status="all")
        triage.decide(self.data_dir, state, [OLD], "false_positive", reason="Test fixture, not a real dependency", user=USER)
        tickets._remember(self.data_dir, KEY, OLD, {"key": "SEC-1", "url": "https://jira.example/browse/SEC-1"})
        verifications.record(self.data_dir, KEY, OLD, first["id"], by="ana")

        self.run_([{**_finding(NEW), "previous_fingerprint": OLD}])
        entries = registry.load(self.data_dir, KEY)["findings"]
        self.assertEqual(set(entries), {NEW})
        self.assertEqual((entries[NEW]["first_run"], entries[NEW]["status"]), (first["id"], "open"))
        self.assertEqual(triage.load_asset(self.data_dir, KEY)[NEW]["status"], "false_positive")
        self.assertEqual(tickets.load_links(self.data_dir)[KEY][NEW]["key"], "SEC-1")
        self.assertEqual(verifications.load(self.data_dir)[KEY][NEW]["run_id"], first["id"])
        self.assertEqual(registry.summarize(self.data_dir, KEY)["suppressed"], 1)

        before = copy.deepcopy(registry.load(self.data_dir, KEY)["findings"])
        run_registry.rebuild(self.data_dir)
        after = registry.load(self.data_dir, KEY)["findings"]
        self.assertEqual({digest: entry["status"] for digest, entry in after.items()},
                         {digest: entry["status"] for digest, entry in before.items()})

    def test_different_decisions_under_the_new_and_the_old_fingerprint_leave_it_for_review(self):
        self.run_([_finding(OLD), _finding(NEW)])
        state = registry.view(self.data_dir, KEY, status="all")
        triage.decide(self.data_dir, state, [OLD], "false_positive", reason="Old decision about the old one", user=USER)
        triage.decide(self.data_dir, state, [NEW], "in_progress", user=USER)
        self.run_([{**_finding(NEW), "previous_fingerprint": OLD}])
        decision = triage.load_asset(self.data_dir, KEY)[NEW]
        self.assertEqual(decision["status"], "open")
        self.assertEqual({event["status"] for event in decision["history"]}, {"false_positive", "in_progress", "open"})
        # Both existed: they were the same finding all along, so the old one folds into the new one instead of being fixed.
        self.assertEqual({digest: entry["status"] for digest, entry in registry.load(self.data_dir, KEY)["findings"].items()},
                         {NEW: "open"})

    def test_a_pull_request_baseline_scanned_before_knows_the_former_fingerprint(self):
        finding = {**_finding(NEW), "previous_fingerprint": OLD}
        outcome = classify([finding], {"package-lock.json": None}, [_finding(OLD)])
        self.assertEqual((outcome["introduced"], outcome["preexisting"]), ([], [finding]))


if __name__ == "__main__":
    unittest.main()


class IdentityChangeTests(CarryOverTests):
    """Fingerprints that changed for reasons that aren't the finding's: it keeps its state and triage."""

    def test_an_advisory_that_gets_a_cve_stays_the_same_finding(self):
        ghsa = "GHSA-aaaa-bbbb-cccc"
        # Its identity comes from its advisory and package (no fixture identity): the subject here.
        before = {key: value for key, value in _finding("x").items() if key != "identity"} | {"rule_id": ghsa, "cve": [], "ghsa": [ghsa]}
        before["fingerprint"] = dependency_fingerprint({ghsa}, ghsa, "npm", "axios", "1.0.0")
        (stored,) = self.run_([before])["findings"]   # the engine's fingerprint, or in v2 the identity that replaces it
        state = registry.view(self.data_dir, KEY, status="all")
        triage.decide(self.data_dir, state, [stored["fingerprint"]], "false_positive", reason="Only in the build tooling, never shipped",
                      user=USER)
        # The advisory database now lists its CVE: the canonical identifier, so the fingerprint changes.
        after = {**before, "rule_id": ghsa, "cve": ["CVE-2026-9"], "ghsa": [ghsa]}
        after["fingerprint"] = dependency_fingerprint({ghsa, "CVE-2026-9"}, ghsa, "npm", "axios", "1.0.0")
        self.assertNotEqual(after["fingerprint"], before["fingerprint"])
        (now,) = self.run_([after])["findings"]
        entries = registry.load(self.data_dir, KEY)["findings"]
        self.assertEqual({digest: entry["status"] for digest, entry in entries.items()}, {now["fingerprint"]: "open"})
        self.assertEqual(triage.load_asset(self.data_dir, KEY)[now["fingerprint"]]["status"], "false_positive")

    def test_a_report_folded_into_another_one_isnt_marked_fixed(self):
        self.run_([_finding(OLD), _finding(NEW)])  # two engines' reports of one advisory, before names were compared
        self.run_([{**_finding(NEW), "previous_fingerprints": [OLD]}])
        self.assertEqual({digest: entry["status"] for digest, entry in registry.load(self.data_dir, KEY)["findings"].items()}, {NEW: "open"})


class StableIdentityTests(unittest.TestCase):
    def test_a_zizmor_finding_keeps_its_fingerprint_when_lines_are_added_above(self):
        workflow = ("name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
                    "      - uses: actions/checkout@v4\n")
        step = workflow.index("- uses")

        def report(text, offset):
            start = step + offset
            return [{"ident": "artipacked", "desc": "credential persistence", "determinations": {"severity": "Medium", "confidence": "Low"},
                     "locations": [{"symbolic": {"key": {"Local": {"verbatim_path": "/src/.github/workflows/ci.yml"}},
                                                 "annotation": "does not set persist-credentials: false", "kind": "Primary",
                                                 "route": {"route": [{"Key": "jobs"}, {"Key": "build"}, {"Key": "steps"}, {"Index": 0}]}},
                                    "concrete": {"location": {"start_point": {"row": text[:start].count("\n"), "column": 8},
                                                              "end_point": {"row": text[:start].count("\n"), "column": 40},
                                                              "offset_span": {"start": start, "end": start + 33}}}}]}]

        with tempfile.TemporaryDirectory() as folder:
            snapshot = Path(folder)
            (snapshot / ".github" / "workflows").mkdir(parents=True)
            target = snapshot / ".github" / "workflows" / "ci.yml"
            target.write_text(workflow)
            (first,) = config_engines.parse_zizmor(report(workflow, 0), snapshot)
            moved = "# Build and test on every push.\n# Owners: platform team.\n"
            target.write_text(moved + workflow)
            (second,) = config_engines.parse_zizmor(report(moved + workflow, len(moved)), snapshot)
        self.assertEqual(second["line"], first["line"] + 2)
        self.assertEqual(second["fingerprint"], first["fingerprint"])
        # The former, line-based fingerprint goes along, so a finding stored with it keeps its state.
        self.assertEqual(first["previous_fingerprint"], engines._stable("cicd", "artipacked", ".github/workflows/ci.yml", str(first["line"])))

    def test_an_image_history_step_is_known_by_its_command_not_its_position(self):
        build = "RUN curl -H 'Authorization: Bearer " + "abcdefgh" + "12345678' https://example.com/x.tgz | tar xz"   # built here: not a secret in this file

        def findings(history):
            metadata = {"ImageConfig": {"config": {"User": "app", "Healthcheck": {"Test": ["CMD", "true"]}},
                                        "history": [{"created_by": step} for step in history]}}
            return {item["rule_id"]: item for item in image.config_findings(metadata, {"asset": "image:ghcr.io/org/api", "tag": "1"})}

        before = findings(["ADD rootfs.tar /", build])["IMG-BUILD-URL-CREDENTIAL"]
        after = findings(["ADD rootfs.tar /", "RUN apk add --no-cache ca-certificates", build])["IMG-BUILD-URL-CREDENTIAL"]
        self.assertEqual((before["path"], after["path"]), ("image-history/step-2", "image-history/step-3"))
        self.assertEqual(after["fingerprint"], before["fingerprint"])
        self.assertNotEqual(before["previous_fingerprint"], before["fingerprint"])  # the position-based one, for the registry

    def test_trivy_and_grype_agree_on_java_and_go_names(self):
        def trivy(name, version, ecosystem):
            return {"rule_id": "CVE-2021-44228", "cve": ["CVE-2021-44228"], "ghsa": [], "confidence": 8, "fingerprint": f"t-{name}",
                    "package": {"ecosystem": ecosystem, "name": name, "version": version, "fixed_version": None}}

        def grype(name, version, ecosystem):
            return {"rule_id": "CVE-2021-44228", "fingerprint": f"g-{name}", "advisory": {"aliases": ["CVE-2021-44228"]},
                    "package": {"ecosystem": ecosystem, "name": name, "version": version, "fixed_version": "2.17.1"}}

        merged, counts = image.merge_packages([trivy("org.apache.logging.log4j:log4j-core", "2.14.1", "jar"), trivy("stdlib", "v1.22.1", "gobinary")],
                                              [grype("log4j-core", "2.14.1", "java-archive"), grype("stdlib", "go1.22.1", "go-module")])
        self.assertEqual((len(merged), counts["both"], counts["only_grype"]), (2, 2, 0))
        self.assertEqual(merged[0]["package"]["fixed_version"], "2.17.1")
        # Grype's report, a finding of its own before, folds into Trivy's instead of being marked fixed.
        self.assertEqual(merged[0]["previous_fingerprints"], ["g-log4j-core"])
