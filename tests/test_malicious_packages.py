"""Malicious packages: a finding of their own, acted on now, with the guide to remove them and treat what installed them
as compromised, whichever engine or database says so: by the kind of advisory (a MAL- one, one its database types as
malware) or by two signals that agree (a malicious-code CWE, the title, the description), never by one alone; and as one
finding per package version with every name its advisories have."""

import copy
import random
import json
import os
import unittest
from pathlib import Path

from hypothesis import HealthCheck, example, given, settings, strategies as st

from pitangus.modules.intel.advisories import MALICIOUS_CWES, is_malicious, mark_malicious, summarize_advisory
from pitangus.modules.scanning import engines, image
from pitangus.modules.scanning.dependency_merge import identifiers, merge_dependencies
from pitangus.shared.i18n import text

# The profiles of tests/test_invariants.py: the same examples on every run, many more and new ones every night.
PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

FIXTURES = Path(__file__).parent / "fixtures"


def osv() -> list[dict]:
    """OSV-Scanner 2.6.0's real report (offline database) for a lockfile with event-stream 3.3.6 and the flatmap-stream
    0.1.1 it pulled in, trimmed to what the parser reads."""
    return engines.parse_osv_scanner(json.loads((FIXTURES / "osv-2.6-malicious.json").read_text()), {})


class MaliciousPackageTests(unittest.TestCase):
    def test_a_mal_advisory_and_a_malware_classified_one_are_both_malicious_findings_to_act_on(self):
        findings = {(item["package"]["name"], item["rule_id"]): item for item in osv()}
        self.assertEqual(sorted(findings), [("event-stream", "GHSA-mh6f-8j2x-4483"), ("flatmap-stream", "GHSA-9x64-5r7x-2q53"),
                                            ("flatmap-stream", "GHSA-mh6f-8j2x-4483"), ("flatmap-stream", "MAL-2025-20690")])
        for key, finding in findings.items():
            with self.subTest(advisory=key):
                self.assertEqual((finding.get("malicious"), finding["priority"]["action"], finding["severity"]), (True, "act", "critical"))
                self.assertIsNone(finding["package"]["fixed_version"])  # removed, never upgraded
        guide = text(findings[("flatmap-stream", "MAL-2025-20690")]["remediation"], "en")
        self.assertIn("Remove flatmap-stream 0.1.1", guide)
        self.assertIn("rotate their tokens and keys", guide)

    def test_trivy_marks_one_by_its_classification_too(self):
        payload = {"Results": [{"Target": "package-lock.json", "Class": "lang-pkgs", "Type": "npm", "Vulnerabilities": [
            {"VulnerabilityID": "GHSA-9x64-5r7x-2q53", "PkgName": "flatmap-stream", "InstalledVersion": "0.1.1", "Severity": "CRITICAL",
             "Title": "Malicious Package in flatmap-stream", "CweIDs": ["CWE-506"]},
            {"VulnerabilityID": "CVE-2021-23337", "PkgName": "lodash", "InstalledVersion": "4.17.20", "FixedVersion": "4.17.21",
             "Severity": "HIGH", "CweIDs": ["CWE-94"]}]}]}
        flatmap, lodash = engines.parse_trivy(payload, {})
        self.assertEqual((flatmap.get("malicious"), flatmap["priority"]["action"]), (True, "act"))
        self.assertNotIn("malicious", lodash)

    def test_a_merge_never_loses_the_malicious_verdict(self):
        trivy = engines.parse_trivy({"Results": [{"Target": "package-lock.json", "Class": "lang-pkgs", "Type": "npm", "Vulnerabilities": [
            {"VulnerabilityID": "GHSA-9x64-5r7x-2q53", "PkgName": "flatmap-stream", "InstalledVersion": "0.1.1", "Severity": "CRITICAL"}]}]}, {})
        self.assertNotIn("malicious", trivy[0])  # this Trivy report doesn't say why
        merged, _ = merge_dependencies(trivy, ("osv-scanner", osv()))
        flatmap = next(item for item in merged if item["rule_id"] == "GHSA-9x64-5r7x-2q53")
        self.assertEqual((flatmap["tool"], flatmap.get("malicious"), flatmap["priority"]["action"]), ("trivy", True, "act"))
        self.assertIn("osv-scanner", flatmap["also_detected_by"])



def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


# Real titles and descriptions of advisories (OSV, Trivy), as they come: the ones saying the package is malware, and
# vulnerabilities whose text speaks of something malicious (what they receive, what an attacker does).
MALWARE = ["Embedded Malicious Code in ctx", "Malicious Package in flatmap-stream", "`logflux` was removed from crates.io for malicious code",
           "Bootstrap-sass contains code execution backdoor", "A number of releases of ultralytics contained malicious crypto miner software.",
           "Vulnerable app versions contains xmrig cryptominer", "strong_password Ruby gem malicious version causing Remote Code Execution vulnerability",
           "rest-client Gem Contains Malicious Code", "Two telnyx versions published containing credential harvesting malware", "cofee-script is malware",
           "Unauthorized npm publish of cline@2.3.0 with modified postinstall script", "debug@4.4.2 contains malware after npm account takeover",
           "It appeared to be attempting to steal credentials from local files.",
           "The npm package `coa` had versions published with malicious code. Users of affected versions should downgrade to 2.0.2.",
           "Affected versions of this package are vulnerable to Malicious Embedded Code. These versions have been compromised to install an "
           "xmrig cryptominer when installed from PyPI.",
           "The strong_password gem 0.0.7 for Ruby, as distributed on RubyGems.org, included a code-execution backdoor inserted by a third party.",
           "The ctx hosted project on PyPI was taken over via user account compromise and replaced with a malicious project which contained "
           "runtime code which collected the content of os.environ.items() when instantiating Ctx objects."]
VULNERABILITIES = ["Requests vulnerable to .netrc credentials leak via malicious URLs", "Malicious package may avoid detection in python auditing",
                   "Zenario allows authenticated admin users to upload PDF files containing malicious code",
                   "OpenClaw has an Arbitrary Malicious Code Execution Vulnerability",
                   "Signal K Server Vulnerable to Remote Code Execution via Malicious npm Package",
                   "Langflow CORS misconfiguration enables Account Takeover and RCE",
                   "RabbitMQ Java client: plaintext broker credentials leaked in exception message from ConnectionFactoryConfigurator.load()",
                   "While `tinymember` did not directly contain malicious code, it was owned by the same user as `arone` and `aronenao`.",
                   "Zarf has a Path Traversal via Malicious Package Metadata.Name", "Directory creation by malicious user in saltstack",
                   "Romeo's invalid NetworkPolicy enables a malicious actor to pivot into another namespace",
                   "OpenClaw's `tools.exec.safeBins` PATH-hijack allowed trojan binaries to bypass allowlist checks",
                   "Maliciously Crafted Model Archive Can Lead To Arbitrary File Write", "Grafana account takeover via OAuth vulnerability",
                   "Crawl4AI: LLM credential exfiltration in Docker server via request base_url and env: token resolution",
                   "lodash: prototype pollution in zipObjectDeep", ""]


class AdvisoryTypeTests(unittest.TestCase):
    def test_ctx_is_one_malicious_finding_with_every_name_whatever_engine_names_it(self):
        """ctx 0.2.6 (PyPI): OSV-Scanner 2.6.0 reports PYSEC-2022-199 and GHSA-67r3-h899-9w95 as two groups that share no
        alias, neither with a CWE or a MAL- id; Trivy 0.75.0 reports the GHSA, titled "Embedded Malicious Code in ctx".
        Real reports of both engines (offline databases, October 2026)."""
        trivy = [item for item in engines.parse_trivy(fixture("trivy-0.75-malicious.json"), {}) if item["scanner"] == "sca"]
        osv = engines.parse_osv_scanner(fixture("osv-2.6-ctx.json"), {})
        merged, _ = merge_dependencies(trivy, ("osv-scanner", osv))
        ctx = [item for item in merged if item["package"]["name"] == "ctx"]
        self.assertEqual(len(ctx), 1)
        self.assertEqual((ctx[0].get("malicious"), ctx[0]["priority"]["action"], ctx[0]["severity"], ctx[0]["package"]["fixed_version"]),
                         (True, "act", "critical", None))
        self.assertLessEqual({"GHSA-67r3-h899-9w95", "PYSEC-2022-199"}, identifiers(ctx[0]))
        self.assertIn("Remove ctx 0.2.6", text(ctx[0]["remediation"], "en"))
        # The npm packages of the same report, with no CWE (coa, rc) or another one (ua-parser-js: CWE-912, CWE-829), are
        # malicious too: their title and description both say so. requests' vulnerabilities aren't.
        verdicts = {(item["package"]["name"], bool(item.get("malicious"))) for item in merged}
        self.assertEqual(verdicts, {("coa", True), ("rc", True), ("ua-parser-js", True), ("ctx", True), ("requests", False)})

    def test_the_kind_of_advisory_decides_and_prose_only_with_a_second_signal(self):
        for title in MALWARE:
            self.assertFalse(is_malicious({"id": "GHSA-x", "summary": title}), title)  # a title alone never decides
        self.assertTrue(is_malicious({"id": "GHSA-x", "summary": "Embedded Malicious Code in ctx", "details": MALWARE[-1]}))
        self.assertTrue(is_malicious({"id": "GHSA-x", "summary": "Malicious Package in flatmap-stream", "cwe": [506]}))
        for title in VULNERABILITIES:
            self.assertFalse(is_malicious({"id": "GHSA-x", "summary": title, "details": title + " Upgrade.", "cwe": [506]}), title)
        # GHSA-h6w7-qmcm-q6xr: GitHub tags a credentials leak in an exception message CWE-509; the CWE alone isn't malware.
        self.assertFalse(is_malicious({"id": "GHSA-h6w7-qmcm-q6xr", "cwe": [509], "summary": VULNERABILITIES[6]}))
        mal = summarize_advisory({"id": "GHSA-2wg3-9fjw-vjvj", "summary": "x", "database_specific": {"malicious-packages-origins": [{"id": "x"}]}})
        self.assertTrue(is_malicious(mal))
        affected = summarize_advisory({"id": "MAL-2022-1", "affected": [{"database_specific": {"cwes": [{"cweId": "CWE-506"}]}}]})
        self.assertEqual((affected["cwe"], is_malicious(affected)), ([506], True))

    def test_an_image_keeps_the_removal_guide_and_grype_corroborates_with_its_related_record(self):
        match = {"vulnerability": {"id": "GHSA-73qr-pfmq-6rp8", "severity": "Critical", "description": "Embedded malware in coa",
                                   "fix": {"versions": ["2.0.4"]}, "cwes": [], "urls": []},
                 "relatedVulnerabilities": [], "artifact": {"name": "coa", "version": "2.0.3", "type": "npm", "locations": [{"path": "/app/package-lock.json"}]}}
        grype = image._grype_finding(match, {})
        self.assertEqual((grype.get("malicious"), grype["package"]["fixed_version"]), (None, "2.0.4"))  # one text, one signal
        related = copy.deepcopy(match)
        related["relatedVulnerabilities"] = [{"id": "CVE-2021-0001", "description": "The npm package coa had versions published with malicious code."}]
        self.assertTrue(image._grype_finding(related, {}).get("malicious"))
        trivy = [item for item in engines.parse_trivy(fixture("trivy-0.75-malicious.json"), {}) if item["package"]["name"] == "coa"]
        merged, counts = image.merge_packages(trivy, [grype])
        finished = image._finish_package(merged[0])
        self.assertEqual((len(merged), counts["both"], finished.get("malicious")), (1, 1, True))
        self.assertIn("Remove coa 2.0.3", text(finished["remediation"], "en"))

    def test_compromised_releases_with_no_malware_type_are_one_finding_to_act_on(self):
        """ultralytics 8.3.41 (PyPI), strong_password 0.0.7 and bootstrap-sass 3.2.0.3 (RubyGems): compromised releases whose
        advisories no database types as malware (Trivy: AQUA-2024-0001 and two CWE-94 CVEs; OSV: PYSEC-2024-154 and
        CWE-94 GHSAs). Real reports of Trivy 0.75.0 and OSV-Scanner 2.6.0, offline databases of October 2026, with no
        network. Before: ultralytics twice and on "track", the gems on "attend" next to six XSS findings."""
        trivy = [item for item in engines.parse_trivy(fixture("trivy-0.75-compromised.json"), {}) if item["scanner"] == "sca"]
        osv = engines.parse_osv_scanner(fixture("osv-2.6-compromised.json"), {})
        merged, _ = merge_dependencies(trivy, ("osv-scanner", osv))
        self.assertEqual(sorted(item["package"]["name"] for item in merged), ["bootstrap-sass", "strong_password", "ultralytics"])
        names = {"ultralytics": {"AQUA-2024-0001", "PYSEC-2024-154"}, "strong_password": {"CVE-2019-13354", "GHSA-5h5r-ffc4-c455"},
                 "bootstrap-sass": {"CVE-2019-10842", "GHSA-vqqv-v9m2-48p2", "CVE-2019-8331", "GHSA-9v3m-8fp8-mj99"}}
        for finding in merged:
            name = finding["package"]["name"]
            with self.subTest(package=name):
                self.assertEqual((finding.get("malicious"), finding["priority"]["action"], finding["severity"], finding["package"]["fixed_version"]),
                                 (True, "act", "critical", None))
                self.assertLessEqual(names[name], identifiers(finding))
                self.assertIn(f"Remove {name} ", text(finding["remediation"], "en"))
                self.assertIn("osv-scanner", finding["also_detected_by"])


# --- the merge as a graph: one finding per advisory, whatever the order ------------------------------------------------

NAMES = ["CVE-2022-1", "CVE-2022-2", "GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff", "PYSEC-2022-199", "PYSEC-2022-200", "MAL-2022-7", "GSD-2022-1",
         "OSV-2022-3"]
advisories = st.lists(st.fixed_dictionaries({"names": st.lists(st.sampled_from(NAMES), min_size=1, max_size=3, unique=True),
                                             "malware": st.sampled_from([False, False, False, True]),
                                             "tool": st.sampled_from(["trivy", "osv-scanner", "grype"]),
                                             "ecosystem": st.sampled_from(["pip", "PyPI", "python-pkg"]),
                                             "fixed": st.sampled_from([None, "0.2.7"])}),
                      min_size=1, max_size=8)


def reported(index: int, advisory: dict) -> dict:
    """An engine's dependency finding as its adapter writes it: ctx 0.2.6, under the advisory's names."""
    rule, *aliases = advisory["names"]
    finding = {"scanner": "sca", "tool": advisory["tool"], "rule_id": rule, "fingerprint": f"{index:02}-{rule}", "title": rule, "path": "requirements.txt",
               "line": 1, "severity": "medium", "confidence": 7, "cwe": [], "cve": [name for name in advisory["names"] if name.startswith("CVE-")],
               "ghsa": [name for name in advisory["names"] if name.startswith("GHSA-")], "advisory": {"id": rule, "aliases": sorted(aliases)},
               "package": {"ecosystem": advisory["ecosystem"], "name": "ctx", "version": "0.2.6", "fixed_version": advisory["fixed"]},
               "priority": {"action": "track", "factors": []}, "remediation": ""}
    if is_malicious({"id": rule, "aliases": aliases, "malware": advisory["malware"]}):
        mark_malicious(finding)
    return finding


def expected_groups(findings: list[dict]) -> set[tuple[frozenset, frozenset, bool]]:
    """The connected components of the alias graph (two findings sharing a name are one advisory), all of them as one
    when any is malicious: (names, fingerprints, malicious) of each."""
    groups = [({*identifiers(item)}, {item["fingerprint"]}, bool(item.get("malicious"))) for item in findings]
    merged = True
    while merged:
        merged = False
        for first in range(len(groups)):
            for second in range(first + 1, len(groups)):
                if groups[first][0] & groups[second][0] or (groups[first][2] and groups[second][2]):
                    names, prints, hostile = groups.pop(second)
                    groups[first] = (groups[first][0] | names, groups[first][1] | prints, groups[first][2] or hostile)
                    merged = True
                    break
            if merged:
                break
    if any(hostile for _, _, hostile in groups):
        groups = [({name for names, _, _ in groups for name in names}, {item for _, prints, _ in groups for item in prints}, True)]
    return {(frozenset(names), frozenset(prints), hostile) for names, prints, hostile in groups}


def outcome(merged: list[dict], with_names: bool = True) -> set[tuple]:
    return {(frozenset(identifiers(item)) if with_names else None, frozenset({item["fingerprint"], *(item.get("previous_fingerprints") or [])}),
             bool(item.get("malicious"))) for item in merged}


def split(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    return [item for item in findings if item["tool"] == "trivy"], [item for item in findings if item["tool"] != "trivy"]


class MergeGraphProperties(unittest.TestCase):
    @settings(max_examples=100 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(advisories, st.randoms(use_true_random=False))
    @example([{"names": ["PYSEC-2022-199", "GSD-2022-1"], "malware": False, "tool": "osv-scanner", "ecosystem": "PyPI", "fixed": None},
              {"names": ["GHSA-aaaa-bbbb-cccc"], "malware": True, "tool": "osv-scanner", "ecosystem": "PyPI", "fixed": None},
              {"names": ["GHSA-aaaa-bbbb-cccc"], "malware": True, "tool": "trivy", "ecosystem": "pip", "fixed": None}], random.Random(0))
    def test_one_finding_per_component_in_any_order_malicious_if_any_member_is(self, generated, rnd):
        findings = [reported(index, advisory) for index, advisory in enumerate(generated)]
        expected = expected_groups(findings)
        primary, others = split(copy.deepcopy(findings))
        merged, _ = merge_dependencies(primary, ("osv-scanner", others))
        self.assertEqual(outcome(merged), expected)
        for item in merged:
            if item.get("malicious"):
                self.assertEqual((item["priority"]["action"], item["package"]["fixed_version"], item["severity"]), ("act", None, "critical"))
        shuffled = copy.deepcopy(findings)
        rnd.shuffle(shuffled)
        primary, others = split(shuffled)
        again, _ = merge_dependencies(primary, ("osv-scanner", others))
        self.assertEqual(outcome(again), outcome(merged))
        self.assertEqual({(item["fingerprint"], item["rule_id"]) for item in again}, {(item["fingerprint"], item["rule_id"]) for item in merged})
        # Which engine reported which name never changes the groups: only which finding is kept.
        everything, _ = merge_dependencies([], ("osv-scanner", copy.deepcopy(shuffled)))
        self.assertEqual(outcome(everything), expected)
        # An image scan groups Trivy's and Grype's reports the same way (its fingerprints keep their own names).
        trivy, grype = split(copy.deepcopy(shuffled))
        packages, _ = image.merge_packages(trivy, grype)
        self.assertEqual(outcome(packages, with_names=False), {(None, prints, hostile) for _, prints, hostile in expected})


# --- the kind of advisory as a property: a type decides, prose and CWE only when two agree, through every adapter ----------

prose = st.one_of(st.sampled_from(MALWARE + VULNERABILITIES), st.text(max_size=300))


class ClassificationProperties(unittest.TestCase):
    @settings(max_examples=200 * SCALE, deadline=None)
    @given(prose, prose, st.integers(1, 1400), st.sampled_from(["GHSA-aaaa-bbbb-cccc", "PYSEC-2024-1", "CVE-2024-1", "RUSTSEC-2024-1", "AQUA-2024-0001"]))
    def test_one_signal_never_decides_and_a_type_always_does(self, title, details, cwe, identifier):
        for alone in ({"summary": title}, {"details": details}, {"cwe": [cwe]}, {"summary": title, "details": title}):
            self.assertFalse(is_malicious({"id": identifier, "aliases": [], **alone}), alone)
        for typed in ({"id": "MAL-2024-7"}, {"aliases": ["MAL-2024-7"]}, {"malware": True}):
            self.assertTrue(is_malicious({"id": identifier, "summary": title, "details": details, "cwe": [cwe], **typed}))
        stated = [title in MALWARE, details in MALWARE and details != title, cwe in MALICIOUS_CWES]
        if all(text in MALWARE + VULNERABILITIES for text in (title, details)):
            self.assertEqual(is_malicious({"id": identifier, "summary": title, "details": details, "cwe": [cwe]}), sum(stated) >= 2)


PACKAGES = {"ctx": "0.2.6", "requests": "2.31.0"}
reports = st.lists(st.fixed_dictionaries({
    "package": st.sampled_from(sorted(PACKAGES)), "names": st.lists(st.sampled_from(NAMES), min_size=1, max_size=3, unique=True),
    "engine": st.sampled_from(["trivy", "osv-scanner"]), "origins": st.sampled_from([False, False, False, True]),
    "title": st.sampled_from(MALWARE + VULNERABILITIES), "details": st.sampled_from(MALWARE + VULNERABILITIES),
    "cwe": st.sampled_from([[], [79], [94], [506], [509, 200]])}), min_size=1, max_size=10)


def payloads(generated: list[dict]) -> tuple[dict, dict]:
    """The engines' real report formats for what each reported: Trivy's JSON and OSV-Scanner's."""
    trivy, osv = {}, {}
    for report in generated:
        rule, *aliases = report["names"]
        if report["engine"] == "trivy":
            trivy.setdefault(report["package"], []).append(
                {"VulnerabilityID": rule, "VendorIDs": aliases, "PkgName": report["package"], "InstalledVersion": PACKAGES[report["package"]],
                 "Severity": "HIGH", "Title": report["title"], "Description": report["details"], "CweIDs": [f"CWE-{item}" for item in report["cwe"]]})
        else:
            specific = {"cwe_ids": [f"CWE-{item}" for item in report["cwe"]], "github_reviewed": True,
                        **({"malicious-packages-origins": [{"source": "ghsa-malware", "id": rule}]} if report["origins"] else {})}
            osv.setdefault(report["package"], []).append({"id": rule, "aliases": aliases, "summary": report["title"], "details": report["details"],
                                                          "database_specific": specific})
    return ({"Results": [{"Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip", "Vulnerabilities": entries}
                         for entries in trivy.values()]},
            {"results": [{"source": {"path": "/src/requirements.txt"}, "packages": [
                {"package": {"name": name, "version": PACKAGES[name], "ecosystem": "PyPI"}, "groups": [{"ids": [item["id"]]} for item in entries],
                 "vulnerabilities": entries} for name, entries in osv.items()]}]})


def malware_member(report: dict) -> bool:
    """What the advisory itself says, as its engine can tell it: a MAL- name (Trivy only keeps its main one), a malware
    origin (only OSV carries it), or two agreeing signals of CWE, title and description."""
    names = report["names"] if report["engine"] == "osv-scanner" else report["names"][:1]
    signals = [set(report["cwe"]) & MALICIOUS_CWES, report["title"] in MALWARE, report["details"] in MALWARE and report["details"] != report["title"]]
    return any(name.startswith("MAL-") for name in names) or (report["engine"] == "osv-scanner" and report["origins"]) or sum(map(bool, signals)) >= 2


class MaliciousVersionProperties(unittest.TestCase):
    @settings(max_examples=150 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(reports, st.randoms(use_true_random=False))
    @example([{"package": "ctx", "names": ["AQUA-2024-0001"], "engine": "trivy", "origins": False, "title": MALWARE[5], "details": MALWARE[14], "cwe": []},
              {"package": "ctx", "names": ["PYSEC-2022-199"], "engine": "osv-scanner", "origins": False, "title": MALWARE[4], "details": MALWARE[16], "cwe": []},
              {"package": "requests", "names": ["CVE-2022-1"], "engine": "trivy", "origins": False, "title": MALWARE[0], "details": "", "cwe": []}],
             random.Random(0))
    def test_a_version_is_malicious_iff_a_member_is_malware_and_then_one_finding(self, generated, rnd):
        # One advisory per main id and package in each engine's report, as the engines write them.
        generated = list({(item["engine"], item["package"], item["names"][0]): item for item in generated}.values())
        trivy, osv = payloads(generated)
        merged, _ = merge_dependencies(engines.parse_trivy(trivy, {}), ("osv-scanner", engines.parse_osv_scanner(osv, {})))
        for name in PACKAGES:
            mine = [item for item in merged if item["package"]["name"] == name]
            hostile = any(malware_member(report) for report in generated if report["package"] == name)
            self.assertEqual({bool(item.get("malicious")) for item in mine}, {hostile} if mine else set(), name)
            if hostile:
                self.assertEqual(len(mine), 1)
                self.assertEqual((mine[0]["priority"]["action"], mine[0]["severity"], mine[0]["package"]["fixed_version"]), ("act", "critical", None))
                self.assertLessEqual({report["names"][0] for report in generated if report["package"] == name}, identifiers(mine[0]))
        # Neither the order of the reports nor of their entries changes the outcome.
        shuffled = copy.deepcopy(generated)
        rnd.shuffle(shuffled)
        trivy, osv = payloads(shuffled)
        again, _ = merge_dependencies(engines.parse_trivy(trivy, {}), ("osv-scanner", engines.parse_osv_scanner(osv, {})))
        verdicts = lambda findings: sorted((item["package"]["name"], bool(item.get("malicious")), sorted(identifiers(item))) for item in findings)
        self.assertEqual(verdicts(again), verdicts(merged))
