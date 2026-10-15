"""Known vulnerabilities of the versions a site exposes: httpx's detections mapped to packages and looked up offline in
OSV's databases, one finding per product and version."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import testenv
from pitangus.modules.scanning import engines, web, web_tools, web_versions
from pitangus.shared.i18n import text

from test_web_tools import PINS, fake_tools

HOST = "pitangus.dev"
# OSV-Scanner 2.6.0, offline, on the SBOM of Express 4.17.1, Flask 2.2.3 and jQuery 3.4.1.
OSV = Path(__file__).resolve().parent / "engine-outputs" / "osv-scanner-web-versions.json"
DETECTED = [{"name": "Flask", "version": "2.2.3", "host": HOST}, {"name": "jQuery", "version": "3.4.1", "host": HOST},
            {"name": "jQuery", "version": "3.4.1", "host": "www.pitangus.dev"}, {"name": "Express", "version": "4.17.1", "host": HOST},
            {"name": "Nginx", "version": "1.27.5", "host": HOST}, {"name": "Cloudflare", "version": None, "host": HOST}]


ABSENT = {key: web.msg("scanning.web.tools.image_missing", tool=key) for key in web_tools.TOOLS}


def osv(command=None, **kwargs):
    return subprocess.CompletedProcess(command or [], 1, OSV.read_text(encoding="utf-8"), "")


def zap_js_library(version: str) -> dict:
    """ZAP's Vulnerable JS Library alert (retire.js) as the SARIF import stores it."""
    return {"tool": "ZAP", "rule_id": "10003", "path": f"https://{HOST}/assets/jquery.min.js", "title": "Vulnerable JS Library",
            "reason": "The identified library appears to be vulnerable.", "web": {"evidence": f"/*! jQuery v{version}"}}


class CandidateTests(unittest.TestCase):
    def test_only_mapped_products_with_a_full_version_are_looked_up_and_servers_are_said(self):
        packages, servers = web_versions.candidates([*DETECTED, {"name": "jQuery", "version": "3", "host": HOST},
                                                     {"name": "Django", "version": "latest", "host": HOST},
                                                     {"name": "SomeCMS", "version": "1.2.3", "host": HOST}])
        self.assertEqual([(item["ecosystem"], item["name"], item["version"], item["hosts"]) for item in packages],
                         [("npm", "express", "4.17.1", [HOST]), ("PyPI", "flask", "2.2.3", [HOST]), ("npm", "jquery", "3.4.1", [HOST, "www.pitangus.dev"])])
        self.assertEqual(servers, ["Nginx 1.27.5"])
        self.assertEqual([item["purl"] for item in web_versions.sbom(packages)["components"]],
                         ["pkg:npm/express@4.17.1", "pkg:pypi/flask@2.2.3", "pkg:npm/jquery@3.4.1"])


class FindingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.calls = []

    def run_osv(self, key, arguments, snapshot, **kwargs):
        self.calls.append((key, arguments, json.loads((snapshot / "bom.cdx.json").read_text()), kwargs))
        return osv()

    def check(self, zap=(), signals=None, **options):
        return web_versions.check(DETECTED, self.data_dir, list(zap), ready=options.get("ready"), run=self.run_osv,
                                  signals=signals or (lambda identifiers: {"kev": {}, "epss": {}}))

    def test_one_finding_per_product_version_with_every_cve_the_worst_severity_and_the_fix_for_all(self):
        step, findings, status = self.check()
        self.assertEqual((step["id"], step["status"], status), ("dast-versions", "completed", "completed"))
        self.assertIn("Nginx 1.27.5", text(step["detail"], "en"))
        by_name = {item["package"]["name"]: item for item in findings}
        self.assertEqual(set(by_name), {"express", "flask", "jquery"})
        flask = by_name["flask"]
        self.assertEqual((flask["tool"], flask["scanner"], flask["severity"], flask["confidence"]), ("httpx + OSV", "dast", "high", 5))
        self.assertEqual(flask["cve"], ["CVE-2023-30861", "CVE-2026-27205"])
        self.assertEqual(flask["package"]["fixed_version"], "3.1.3")  # the advisories' own fixed versions, the highest closes both
        self.assertEqual(text(flask["title"], "es"), "Flask 2.2.3 con vulnerabilidades conocidas")
        self.assertEqual(text(flask["title"], "en"), "Flask 2.2.3 has known vulnerabilities")
        self.assertIn("2.2.5", flask["web"]["evidence"])
        self.assertIn("sin verificar", text(flask["reason"], "es"))
        self.assertIn("3.1.3", text(flask["remediation"], "en"))  # nothing invented: the published fixed version
        self.assertTrue(flask["web"]["references"] and all(url.startswith("https://") for url in flask["web"]["references"]))
        self.assertEqual(flask["path"], f"https://{HOST}/")
        self.assertEqual(by_name["jquery"]["cve"], ["CVE-2020-11022", "CVE-2020-11023"])
        self.assertIn("www.pitangus.dev", text(by_name["jquery"]["reason"], "en"))
        # The lookup is offline and the SBOM carries packages only: nothing about the site leaves the machine.
        ((key, arguments, bom, options),) = self.calls
        self.assertEqual(key, "osv-scanner")
        self.assertTrue({"--offline-vulnerabilities", "--no-resolve"} <= set(arguments))
        self.assertNotIn(HOST, json.dumps(bom))
        self.assertNotIn("hosts", options)
        # Stable across runs: the same product and version is the same finding.
        self.assertEqual(self.check()[1][0]["fingerprint"], findings[0]["fingerprint"])

    def test_kev_and_epss_come_from_the_local_copy(self):
        asked = []

        def signals(identifiers):
            asked.append(set(identifiers))
            return {"kev": {"CVE-2020-11023": {"date_added": "2025-01-23", "due_date": "2025-02-13", "ransomware": False, "name": "jQuery XSS"}},
                    "epss": {"CVE-2020-11023": (0.3, 0.97)}}
        _, findings, _ = self.check(signals=signals)
        jquery = next(item for item in findings if item["package"]["name"] == "jquery")
        self.assertIn("CVE-2020-11023", asked[0])
        self.assertEqual((jquery["priority"]["action"], jquery["kev"]["date_added"], jquery["epss"]["score"]), ("act", "2025-01-23", 0.3))
        self.assertIn("sin verificar", text(jquery["priority"]["factors"][0], "es"))

    def test_a_javascript_library_zap_already_reported_isnt_reported_twice(self):
        _, findings, _ = self.check(zap=[zap_js_library("3.4.1")])
        self.assertNotIn("jquery", {item["package"]["name"] for item in findings})
        _, findings, _ = self.check(zap=[zap_js_library("3.5.1")])  # another version: not the same finding
        self.assertIn("jquery", {item["package"]["name"] for item in findings})

    def test_without_osv_scanner_or_when_it_fails_nothing_is_marked_fixed(self):
        step, findings, status = self.check(ready=web.msg("scanning.web.tools.image_missing", tool="OSV-Scanner"))
        self.assertEqual((step["status"], findings, status, self.calls), ("skipped", [], "inconclusive", []))
        with patch.object(self, "run_osv", side_effect=subprocess.TimeoutExpired(["docker"], 60)):
            step, findings, status = self.check()
        self.assertEqual((step["status"], findings, status), ("partial", [], "inconclusive"))
        step, findings, status = web_versions.check([{"name": "Nginx", "version": "1.27.5", "host": HOST}], self.data_dir, [], ready=None,
                                                    run=self.run_osv)
        self.assertEqual((step["status"], findings, status, self.calls), ("completed", [], "completed", []))


class ScanTests(unittest.TestCase):
    def setUp(self):
        testenv.docker_runner(self)
        which = patch.object(engines.shutil, "which", return_value="/usr/bin/docker")
        which.start()
        self.addCleanup(which.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.record = {"id": "a" * 24, "host": HOST, "url": f"https://{HOST}/", "kind": "web", "key": f"domain:{HOST}"}
        httpx = json.dumps({"url": f"https://{HOST}/", "input": f"https://{HOST}/", "host": HOST, "tech": ["Flask:2.2.3", "jQuery:3.4.1", "Nginx:1.27.5"]})
        self.outputs = {"httpx": httpx + "\n", "osv-scanner": OSV.read_text(encoding="utf-8")}

    def scan(self, ready):
        calls = []
        with fake_tools(self.outputs, calls=calls, returncodes={"osv-scanner": 1}):
            return web.scan_domain(self.record, PINS[HOST], data_dir=self.data_dir, tools=ready), calls

    def test_the_versions_httpx_read_become_findings_after_its_step(self):
        result, calls = self.scan({**ABSENT, "httpx": None, web_versions.KEY: None})
        # httpx twice: the technologies, then the statuses (each root's random path at least, for soft 404s).
        self.assertEqual([key for key, _, _ in calls], ["zap", "httpx", "httpx", "osv-scanner"])
        steps = [step["id"] for step in result["steps"]]
        self.assertEqual(steps[steps.index("dast-httpx") + 1], "dast-versions")
        found = [item for item in result["findings"] if item["tool"] == web_versions.TOOL]
        self.assertEqual(sorted(item["package"]["name"] for item in found), ["flask", "jquery"])
        self.assertTrue(all(item["web"]["coverage"] == "baseline" for item in found))
        self.assertEqual({tool["name"]: tool["status"] for tool in result["summary"]["tools"]}[web_versions.TOOL], "completed")
        self.assertIn("scanning.web.limitations.versions", json.dumps(result["limitations"]))
        # The OSV-Scanner container never gets the site's pinned addresses: it only reads its databases.
        (osv_call,) = [command for key, command, _ in calls if key == "osv-scanner"]
        self.assertNotIn("--add-host", osv_call)

    def test_without_osv_scanner_the_step_says_why_and_earlier_findings_stay_open(self):
        result, calls = self.scan({**ABSENT, "httpx": None})
        self.assertNotIn("osv-scanner", [key for key, _, _ in calls])
        step = next(step for step in result["steps"] if step["id"] == "dast-versions")
        self.assertEqual(step["status"], "skipped")
        self.assertEqual({tool["name"]: tool["status"] for tool in result["summary"]["tools"]}[web_versions.TOOL], "inconclusive")


if __name__ == "__main__":
    unittest.main()
