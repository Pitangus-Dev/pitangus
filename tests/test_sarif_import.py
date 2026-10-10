"""SARIF import: any tool's findings into an asset's registry, fixed only by a later full import of the same tool."""

import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from pitangus.modules.findings import registry, triage
from pitangus.modules.runs import registry as run_registry
from pitangus.modules.runs.imports import ImportRefused, import_sarif
from pitangus.modules.runs.store import load_run, render_repository_report, render_repository_sarif, save_repository_scan
from pitangus.modules.scanning.engines import _stable, parse_opengrep
from pitangus.modules.scanning.sarif_import import MAX_RESULTS, MAX_RUNS, SarifError, parse
from pitangus.shared.i18n import text

from test_auth import ORIGIN, PASSWORD, HttpCase
from test_dashboard import _finding, _scan

FIXTURE = Path(__file__).resolve().parent / "engine-outputs" / "import.sarif"
ZAP = Path(__file__).resolve().parent / "engine-outputs" / "zap.sarif"
NUCLEI = Path(__file__).resolve().parent / "engine-outputs" / "nuclei.sarif"
KEY = "github#7"
HOST = "app.example.com"
DOMAIN_KEY = f"domain:{HOST}"
A = "a" * 64
USER = {"username": "ana", "role": "member"}
TOKEN = "i" * 40


def fixture() -> dict:
    return json.loads(FIXTURE.read_text())


def zap() -> dict:
    return json.loads(ZAP.read_text())


def nuclei() -> dict:
    return json.loads(NUCLEI.read_text())


def verified_domain(data_dir: Path, host: str = HOST, *, verified: bool = True) -> dict:
    """A registered domain whose TXT proof was seen (without asking DNS)."""
    from pitangus.modules.sources import domains
    record = domains.register_domain(data_dir, f"https://{host}/", by="ana")
    if not verified:
        return record
    now = datetime.now(timezone.utc)
    return domains._mark(data_dir, record["id"], verified_at=now, verified_until=now + timedelta(days=domains.VERIFY_DAYS), checked_at=now)


def sarif(tool: str, results: list[dict], rules: list[dict] | None = None) -> dict:
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": tool, "rules": rules or []}}, "results": results}]}


def result(rule="rule.one", path="src/app.py", line=10, snippet="eval(x)", **extra) -> dict:
    region = {"startLine": line, **({"snippet": {"text": snippet}} if snippet is not None else {})}
    return {"ruleId": rule, "message": {"text": f"{rule} matched"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}, "region": region}}], **extra}


def only(document: dict, **options) -> list[dict]:
    return parse(document, **options)[0]["findings"]


def result_with_message(message: str) -> dict:
    return {**result(), "message": {"text": message}}


class ParserTests(unittest.TestCase):
    def test_fixture_one_entry_per_tool_with_severity_cwe_and_location(self):
        runs = parse(fixture())
        self.assertEqual([(run["tool"], run["version"], run["results"], run["skipped"]) for run in runs],
                         [("Semgrep OSS", "1.90.0", 3, 1), ("CodeQL", "2.19.0", 1, 0)])
        sql, evaluated = runs[0]["findings"]
        self.assertEqual((sql["scanner"], sql["severity"], sql["cwe"], sql["path"], sql["line"], sql["confidence"], sql["tool"]),
                         ("sast", "high", [89], "src/app/db.py", 42, 8, "Semgrep OSS"))
        self.assertEqual(sql["title"], "SQL built by string concatenation")  # third-party text, stored as published
        self.assertEqual((sql["priority"]["action"], sql["reason"]["$t"]),
                         ("attend", "scanning.sarif.reason"))
        self.assertEqual((evaluated["severity"], evaluated["path"], evaluated["cwe"]), ("medium", "app/tools.py", [95]))
        xss = runs[1]["findings"][0]
        self.assertEqual((xss["severity"], xss["cwe"], xss["rule_id"], xss["priority"]["action"]), ("critical", [79, 116], "js/xss", "act"))
        self.assertEqual((len(xss["fingerprint"]), xss["finding_id"]), (64, xss["fingerprint"][:16]))

    def test_severity_from_security_severity_then_level(self):
        def severity(**properties):
            level = properties.pop("level", None)
            return only(sarif("X", [result(**({"level": level} if level else {}), properties=properties)]))[0]["severity"]
        self.assertEqual([severity(**{"security-severity": value}) for value in ("9.0", "8.9", "7", "4.0", "3.9", "0.1", "0")],
                         ["critical", "high", "high", "medium", "low", "low", "info"])
        self.assertEqual([severity(level=level) for level in ("error", "warning", "note", "none")], ["high", "medium", "low", "info"])
        self.assertEqual(severity(), "medium")  # SARIF's default level is warning
        self.assertEqual(severity(**{"security-severity": "high", "level": "note"}), "low")  # not a number: the level decides
        rule = {"id": "rule.one", "defaultConfiguration": {"level": "error"}, "properties": {"security-severity": "9.8"}}
        self.assertEqual(only(sarif("X", [result()], [rule]))[0]["severity"], "critical")

    def test_cwe_from_tags_and_taxa_and_identifiers_from_the_rule(self):
        finding = only(sarif("X", [result(rule="CVE-2021-44228", properties={"tags": ["external/cwe/cwe-502", "GHSA-jfh8-c2jp-5v3q"]},
                                          taxa=[{"id": "20", "toolComponent": {"name": "CWE"}}])]))[0]
        self.assertEqual((finding["cwe"], finding["cve"], finding["ghsa"], finding["scanner"]),
                         ([20, 502], ["CVE-2021-44228"], ["GHSA-jfh8-c2jp-5v3q"], "sca"))

    def test_scanner_from_the_tool_or_the_tags(self):
        def scanner(tool, **extra):
            return only(sarif(tool, [result(**extra)]))[0]
        leak = scanner("gitleaks")
        self.assertEqual((leak["scanner"], leak["severity"]), ("secrets", "critical"))  # an exposed secret is always critical
        self.assertEqual(scanner("Trivy", properties={"tags": ["secret"]})["scanner"], "secrets")
        self.assertEqual(scanner("Trivy", properties={"tags": ["misconfiguration"]})["scanner"], "iac")
        self.assertEqual(scanner("Trivy")["scanner"], "sca")
        self.assertEqual(scanner("Checkov")["scanner"], "iac")
        self.assertEqual(scanner("zizmor")["scanner"], "cicd")
        self.assertEqual(scanner("Snyk Open Source")["scanner"], "sca")
        self.assertEqual(scanner("SnykCode")["scanner"], "sast")
        self.assertEqual(scanner("Claude Security")["scanner"], "sast")

    def test_fingerprint_ignores_the_line_and_is_namespaced_per_tool(self):
        before = only(sarif("Semgrep", [result(line=10)]))[0]["fingerprint"]
        self.assertEqual(only(sarif("Semgrep", [result(line=90)]))[0]["fingerprint"], before)  # lines added above
        self.assertEqual(only(sarif("semgrep", [result(line=90)]))[0]["fingerprint"], before)  # tool name case
        self.assertNotEqual(only(sarif("Semgrep", [result(snippet="eval(y)")]))[0]["fingerprint"], before)
        self.assertNotEqual(only(sarif("CodeQL", [result()]))[0]["fingerprint"], before)
        partial = {"partialFingerprints": {"primaryLocationLineHash": "abc:1"}}
        moved = only(sarif("CodeQL", [result(line=5, snippet="a", **partial)]))[0]["fingerprint"]
        self.assertEqual(only(sarif("CodeQL", [result(line=50, snippet="b", **partial)]))[0]["fingerprint"], moved)
        full = {"fingerprints": {"matchBasedId/v1": "f00"}}
        self.assertEqual(only(sarif("Semgrep", [result(path="a.py", **full)]))[0]["fingerprint"],
                         only(sarif("Semgrep", [result(path="renamed/a.py", **full)]))[0]["fingerprint"])
        twice = only(sarif("Semgrep", [result(line=1), result(line=2)]))
        self.assertEqual(len({item["fingerprint"] for item in twice}), 2)  # identical keys, told apart by order
        self.assertEqual(twice[0]["fingerprint"], before)

    def test_never_collides_with_pitangus_engines(self):
        opengrep = parse_opengrep({"results": [{"check_id": "rule.one", "path": "/src/src/app.py", "start": {"line": 10},
                                                "extra": {"lines": "eval(x)", "severity": "ERROR", "metadata": {}}}]})[0]
        imported = only(sarif("opengrep", [result()]))[0]
        self.assertEqual(opengrep["fingerprint"], _stable("sast", "rule.one", "src/app.py", "eval(x)"))
        self.assertNotEqual(imported["fingerprint"], opengrep["fingerprint"])

    def test_skips_suppressed_passing_and_absent_results(self):
        document = sarif("X", [result(), result(path="b.py", kind="pass"), result(path="c.py", baselineState="absent"),
                               result(path="d.py", suppressions=[{"kind": "external", "status": "accepted"}]),
                               result(path="e.py", suppressions=[{"kind": "external", "status": "rejected"}])])
        run = parse(document)[0]
        self.assertEqual(([item["path"] for item in run["findings"]], run["skipped"]), (["src/app.py", "e.py"], 3))

    def test_runs_of_the_same_tool_are_one_and_the_tool_can_be_named(self):
        document = {"version": "2.1.0", "runs": [*sarif("Semgrep", [result()])["runs"], *sarif("semgrep", [result(path="b.py")])["runs"]]}
        self.assertEqual([(run["tool"], len(run["findings"])) for run in parse(document)], [("Semgrep", 2)])
        named = parse(fixture(), tool="Strix")
        self.assertEqual([(run["tool"], len(run["findings"])) for run in named], [("Strix", 3)])

    def test_bounds_and_refusals(self):
        def refused(document, **options):
            with self.assertRaises(SarifError) as caught:
                parse(document, **options)
            return caught.exception.message["$t"]
        self.assertEqual(refused({"version": "2.0.0", "runs": []}), "scanning.sarif.errors.version")
        self.assertEqual(refused([]), "scanning.sarif.errors.version")
        self.assertEqual(refused({"version": "2.1.0", "runs": []}), "scanning.sarif.errors.no_runs")
        self.assertEqual(refused({"version": "2.1.0", "runs": [sarif("X", [])["runs"][0]] * (MAX_RUNS + 1)}), "scanning.sarif.errors.too_many_runs")
        self.assertEqual(refused(sarif("X", [result()] * (MAX_RESULTS + 1))), "scanning.sarif.errors.too_many_results")
        self.assertEqual(refused(sarif("", [result()])), "scanning.sarif.errors.no_tool")
        self.assertEqual(refused(sarif("X", [result()]), tool="  "), "scanning.sarif.errors.no_tool")
        long = only(sarif("X" * 500, [result(path="/" + "d/" * 900 + "f.py", rule="r" * 500)],
                          [{"id": "r" * 200, "shortDescription": {"text": "t" * 900}}]))[0]
        self.assertEqual((len(long["tool"]), len(long["path"]), len(long["rule_id"]), len(long["title"])), (100, 1000, 200, 300))
        garbage = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "X"}}, "results": [None, 3, {"locations": "x", "message": 5}]}]}
        self.assertEqual(only(garbage)[0]["path"], "")


class DastParserTests(unittest.TestCase):
    """Web scanners' SARIF: findings at URLs, classified as dast, keyed without the values a scan varies."""

    def test_zap_report_findings_are_dast_at_urls_without_query_strings(self):
        run = parse(zap())[0]
        self.assertEqual((run["tool"], run["version"], run["results"], run["skipped"]), ("ZAP", "2.16.1", 4, 0))
        xss, csp_root, csp_hello, cookie = run["findings"]
        self.assertEqual({item["scanner"] for item in run["findings"]}, {"dast"})
        self.assertEqual((xss["path"], xss["severity"], xss["cwe"], xss["confidence"], xss["title"], xss["line"]),
                         ("https://app.example.com/greeting", "high", [79], 6, "Cross Site Scripting (Reflected)", 10))
        self.assertEqual((csp_root["path"], csp_root["severity"], csp_root["cwe"], csp_root["confidence"]), ("https://app.example.com/", "medium", [693], 8))
        self.assertEqual(csp_hello["path"], "https://app.example.com/hello")  # ?lang=en#top dropped
        self.assertEqual((cookie["path"], cookie["severity"], cookie["web"]), ("https://app.example.com/login", "low",
                                                                              {"method": "POST", "parameter": "session", "evidence": "Set-Cookie: session"}))
        # ZAP keeps the fix under `solution`; the request and response it attached (cookies, bearer, body) never land.
        self.assertIn("vetted library", text(xss["remediation"], "en"))
        self.assertEqual(xss["web"], {"method": "GET", "parameter": "name", "evidence": "</p><script>alert(1);</script><p>"})
        self.assertNotIn("JSESSIONID", json.dumps(run["findings"]))
        self.assertNotIn("hunter2", json.dumps(run["findings"]))
        self.assertEqual(len({item["fingerprint"] for item in run["findings"]}), 4)

    def test_the_same_alert_on_the_root_with_and_without_its_slash_is_one_finding(self):
        """ZAP reports `https://host` and `https://host/` apart (seen against pitangus.dev, 2026-10-10)."""
        def result(uri):
            return {"ruleId": "10055", "level": "warning", "message": {"text": "CSP: style-src unsafe-inline"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]}
        document = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ZAP", "rules": [{"id": "10055", "name": "CSP"}]}},
                                                  "results": [result("https://pitangus.dev"), result("https://pitangus.dev/"),
                                                              result("https://pitangus.dev/es/")]}]}
        run = parse(document)[0]
        self.assertEqual([item["path"] for item in run["findings"]], ["https://pitangus.dev/", "https://pitangus.dev/es/"])
        self.assertEqual(run["results"], 3)

    def test_nuclei_export_reads_the_url_from_its_properties_not_the_template_path(self):
        run = parse(nuclei())[0]
        self.assertEqual((run["tool"], run["version"], len(run["findings"])), ("Nuclei", "v3.3.5", 3))
        hsts, csp, git = run["findings"]
        self.assertEqual({item["scanner"] for item in run["findings"]}, {"dast"})
        self.assertEqual((hsts["path"], hsts["rule_id"], hsts["web"]["parameter"]), ("https://app.example.com/", "http-missing-security-headers", "strict-transport-security"))
        self.assertEqual(csp["web"]["parameter"], "content-security-policy")
        self.assertNotEqual(hsts["fingerprint"], csp["fingerprint"])  # same template and URL, told apart by the matcher
        self.assertEqual((git["path"], git["severity"], git["cwe"], git["title"]), ("https://app.example.com/.git/config", "medium", [538], "Git Configuration File - Detect"))
        self.assertIn("Restrict access", text(git["remediation"], "en"))

    def test_fingerprints_survive_query_strings_fragments_and_evidence(self):
        def zap_result(uri, snippet="<script>", param="name", **extra):
            return {"ruleId": "40012", "message": {"text": "XSS"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                    "region": {"snippet": {"text": snippet}}}, "properties": {"param": param}}], **extra}
        before = only(sarif("ZAP", [zap_result("https://app.example.com/search?q=1&t=1728489601")]))[0]["fingerprint"]
        self.assertEqual(only(sarif("ZAP", [zap_result("https://app.example.com/search?q=2#x", snippet="<img onerror>")]))[0]["fingerprint"], before)
        self.assertEqual(only(sarif("ZAP", [zap_result("HTTPS://APP.example.com:443/search")]))[0]["fingerprint"], before)
        self.assertNotEqual(only(sarif("ZAP", [zap_result("https://app.example.com/search", param="page")]))[0]["fingerprint"], before)
        self.assertNotEqual(only(sarif("ZAP", [zap_result("https://app.example.com/other")]))[0]["fingerprint"], before)
        self.assertNotEqual(only(sarif("ZAP", [zap_result("http://app.example.com/search")]))[0]["fingerprint"], before)
        nuclei_a = only(nuclei())[2]["fingerprint"]
        changed = nuclei()
        changed["runs"][0]["results"][2]["properties"]["matched-at"] = "https://app.example.com/.git/config?nonce=7"
        changed["runs"][0]["results"][2]["message"]["text"] = "something else"
        self.assertEqual(only(changed)[2]["fingerprint"], nuclei_a)

    def test_credentials_echoed_by_the_scanner_never_land(self):
        document = nuclei()
        result = document["runs"][0]["results"][2]
        result["message"]["text"] += "\n\nReproduce:\n```bash\ncurl -X 'GET' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secret' -H \"Cookie: session=4f3c9a1b\" 'https://app.example.com/.git/config'\n```"
        result["locations"][0]["physicalLocation"]["region"] = {"snippet": {"text": "HTTP/1.1 200\nSet-Cookie: session=4f3c9a1b; Secure\nX-Api-Key=abc"}}
        finding = only(document)[2]
        reason, evidence = text(finding["reason"], "en"), finding["web"]["evidence"]
        for secret in ("eyJhbGciOiJIUzI1NiJ9.secret", "4f3c9a1b", "abc"):
            self.assertNotIn(secret, reason + evidence)
        self.assertIn("Authorization: [redacted]", reason)
        self.assertIn("Cookie: session=[redacted]", reason)  # the cookie's name stays: a finding is often about one cookie
        self.assertEqual(evidence, "HTTP/1.1 200 Set-Cookie: session=[redacted]; Secure X-Api-Key: [redacted]")
        # Nothing of that in a code scanner's message: the tool chose what to print.
        self.assertIn("Cookie: x", text(only(sarif("Semgrep", [result_with_message("Cookie: x")]))[0]["reason"], "en"))

    def test_any_tool_reporting_at_a_url_is_dynamic(self):
        finding = only(sarif("Some Web Scanner", [result(path="https://api.example.com/v1/users?id=3", snippet="x")]))[0]
        self.assertEqual((finding["scanner"], finding["path"], finding["web"]), ("dast", "https://api.example.com/v1/users", {"evidence": "x"}))
        self.assertEqual(only(sarif("Semgrep", [result(path="file:///src/app.py")]))[0]["scanner"], "sast")
        self.assertEqual(only(sarif("Nuclei", [result(path="http/cves/2021/CVE-2021-44228.yaml")]))[0]["path"], "http/cves/2021/CVE-2021-44228.yaml")
        self.assertEqual(only(sarif("ZAP", [result(path="https://app.example.com/" + "a" * 2000)]))[0]["path"][:24], "https://app.example.com/")


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.clock = datetime.now(timezone.utc)
        self.scan([_finding(A)])

    def scan(self, findings, *, pr=None):
        self.clock += timedelta(hours=1)
        record = _scan("org/api", findings, self.clock.isoformat())
        record["source"]["uid"] = KEY
        record["finished_at"] = self.clock.isoformat()
        if pr:
            record.update(type="pr_review", pull_request={"number": pr, "head_sha": "1" * 40, "head_ref": "feat"})
        return save_repository_scan(self.data_dir, record, created_at=self.clock.isoformat())

    def import_(self, document, **options):
        with patch("pitangus.modules.runs.imports.datetime") as clock:
            self.clock += timedelta(hours=1)
            clock.now.return_value = self.clock
            return import_sarif(self.data_dir, document, **{"asset": "org/api", "requested_by": "ana", **options})

    def entries(self):
        return registry.load(self.data_dir, KEY)["findings"]

    def status(self, tool=None):
        return {digest: entry["status"] for digest, entry in self.entries().items()
                if tool is None or (entry.get("origin") or {}).get("tool") == tool}

    def test_an_import_opens_one_run_per_tool_with_import_origin(self):
        outcome = self.import_(fixture(), commit="ABCDEF1", branch="main")
        self.assertEqual((outcome["asset"], outcome["name"]), (KEY, "org/api"))
        self.assertEqual([(run["tool"], run["findings"], run["opened"], run["fixed"], run["skipped"]) for run in outcome["runs"]],
                         [("Semgrep OSS", 2, 2, 0, 1), ("CodeQL", 1, 1, 0, 0)])
        record = load_run(self.data_dir, outcome["runs"][0]["id"])
        self.assertEqual((record["type"], record["status"], record["requested_by"], record["trigger"]["scope"], record["source"]["commit"],
                          record["source"]["branch"], record["source"]["uid"]),
                         ("sarif_import", "completed", "ana", "full", "abcdef1", "main", KEY))
        self.assertEqual(record["summary"]["severities"]["high"], 1)
        origins = {(entry["origin"]["kind"], entry["origin"].get("tool")) for entry in self.entries().values()}
        self.assertEqual(origins, {("scan", None), ("import", "Semgrep OSS"), ("import", "CodeQL")})
        # The run renders like any other: Markdown, SARIF export.
        self.assertIn("Semgrep OSS", render_repository_report(record, locale="en"))
        self.assertEqual(len(render_repository_sarif(record)["runs"][0]["results"]), 2)

    def test_a_full_import_of_the_same_tool_fixes_what_it_no_longer_reports(self):
        self.import_(fixture())
        semgrep = self.status("Semgrep OSS")
        without = fixture()
        without["runs"][0]["results"] = without["runs"][0]["results"][:1]  # the eval finding is gone
        outcome = self.import_({"version": "2.1.0", "runs": without["runs"][:1]})
        self.assertEqual((outcome["runs"][0]["opened"], outcome["runs"][0]["fixed"]), (0, 1))
        self.assertEqual(sorted(self.status("Semgrep OSS").values()), ["fixed", "open"])
        gone = next(entry for digest, entry in self.entries().items() if digest in semgrep and entry["status"] == "fixed")
        self.assertIn("Semgrep OSS", text(gone["fixed"]["how"], "en"))
        self.assertEqual(set(self.status("CodeQL").values()), {"open"})  # another tool's import vouches for nothing else
        self.assertEqual(self.status()[A], "open")                     # nor for Pitangus's own findings
        self.import_(fixture())
        self.assertEqual(set(self.status("Semgrep OSS").values()), {"open"})  # it came back: it reopens

    def test_a_partial_import_never_fixes(self):
        self.import_(fixture())
        outcome = self.import_(sarif("Semgrep OSS", []), scope="partial")
        self.assertEqual(outcome["runs"][0]["fixed"], 0)
        self.assertEqual(set(self.status("Semgrep OSS").values()), {"open"})
        self.assertEqual(load_run(self.data_dir, outcome["runs"][0]["id"])["steps"][0]["status"], "partial")

    def test_another_tools_full_import_fixes_nothing(self):
        self.import_(fixture())
        self.import_(sarif("Snyk Code", []))
        self.assertEqual(set(self.status().values()), {"open"})

    def test_pitangus_scans_and_pr_reviews_never_fix_imported_findings(self):
        self.import_(fixture())
        self.scan([])
        self.scan([], pr=3)
        states = self.status()
        self.assertEqual(states.pop(A), "fixed")  # the full scan does fix its own
        self.assertEqual(set(states.values()), {"open"})
        run_registry.rebuild(self.data_dir)      # replaying every run gives the same state
        self.assertEqual({digest: status for digest, status in self.status().items() if digest != A}, states)

    def test_triage_survives_new_imports(self):
        outcome = self.import_(fixture())
        record = load_run(self.data_dir, outcome["runs"][1]["id"])
        digest = record["findings"][0]["fingerprint"]
        triage.decide(self.data_dir, record, [digest], "false_positive", reason="sanitized upstream", user=USER)
        self.import_(fixture())
        self.assertEqual(triage.load(self.data_dir)[KEY][digest]["status"], "false_positive")
        self.assertEqual(registry.summarize(self.data_dir, KEY)["suppressed"], 1)

    def test_the_asset_must_exist(self):
        with self.assertRaises(ImportRefused) as caught:
            self.import_(fixture(), asset="org/unknown")
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(self.import_(fixture(), asset=KEY)["asset"], KEY)  # by key too
        self.assertEqual(self.import_(fixture(), asset="ORG/API")["asset"], KEY)  # names ignore case
        for options, status in (({"scope": "all"}, 400), ({"commit": "xyz"}, 400), ({"branch": "../x"}, 400), ({"asset": ""}, 400)):
            with self.assertRaises(ImportRefused) as caught:
                self.import_(fixture(), **options)
            self.assertEqual(caught.exception.status, status, options)

    def test_a_repository_the_app_covers_counts_as_an_asset(self):
        from pitangus.modules.sources import assets as source_assets
        source_assets.set_scan_branch(self.data_dir, "github#9", None, name="org/new", source_id="github:org/new", by="ana")
        outcome = self.import_(fixture(), asset="org/new")
        self.assertEqual(outcome["asset"], "github#9")
        self.assertEqual(load_run(self.data_dir, outcome["runs"][0]["id"])["source"]["id"], "github:org/new")

    def test_all_runs_of_a_document_or_none(self):
        from pitangus.modules.runs import imports, store
        calls = []

        def failing(*args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeError("boom")
            return store.save_and_apply(*args, **kwargs)
        before = len(store.find_runs(self.data_dir))
        with patch.object(imports, "save_and_apply", failing), self.assertRaises(RuntimeError):
            self.import_(fixture())
        self.assertEqual(len(store.find_runs(self.data_dir)), before)
        self.assertEqual(set(self.status()), {A})

    def test_a_verified_domain_is_an_asset_and_an_unverified_one_is_refused(self):
        pending = verified_domain(self.data_dir, verified=False)
        for wanted in (DOMAIN_KEY, HOST, pending["id"]):
            with self.assertRaises(ImportRefused) as caught:
                self.import_(zap(), asset=wanted)
            self.assertEqual(caught.exception.status, 409, wanted)
            self.assertIn(HOST, text(caught.exception.message, "en"))
        with self.assertRaises(ImportRefused) as caught:
            self.import_(zap(), asset="domain:nobody.example.com")
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(self.status(), {A: "open"})  # nothing landed
        from pitangus.modules.sources import domains
        now = datetime.now(timezone.utc)
        domains._mark(self.data_dir, pending["id"], verified_at=now, verified_until=now + timedelta(days=domains.VERIFY_DAYS))
        outcome = self.import_(zap(), asset=DOMAIN_KEY)
        self.assertEqual((outcome["asset"], outcome["name"], outcome["runs"][0]["tool"], outcome["runs"][0]["opened"]), (DOMAIN_KEY, HOST, "ZAP", 4))
        record = load_run(self.data_dir, outcome["runs"][0]["id"])
        self.assertEqual((record["source"]["id"], record["source"]["provider"], record["source"]["domain"]["host"], record["summary"]["dast"]),
                         (DOMAIN_KEY, "domain", HOST, 4))
        self.assertEqual(self.import_(nuclei(), asset=HOST)["asset"], DOMAIN_KEY)  # by host and by id too
        self.assertEqual(self.import_(nuclei(), asset=pending["id"])["asset"], DOMAIN_KEY)
        self.assertEqual({entry["finding"]["scanner"] for entry in registry.load(self.data_dir, DOMAIN_KEY)["findings"].values()}, {"dast"})
        # The proof ran out: the domain is no longer an asset until someone verifies it again.
        domains._mark(self.data_dir, pending["id"], verified_until=now - timedelta(seconds=1))
        with self.assertRaises(ImportRefused) as caught:
            self.import_(zap(), asset=DOMAIN_KEY)
        self.assertEqual(caught.exception.status, 409)

    def test_a_later_full_import_against_the_domain_fixes_what_the_scanner_no_longer_reports(self):
        verified_domain(self.data_dir)
        self.import_(zap(), asset=DOMAIN_KEY)
        states = lambda: {digest: entry["status"] for digest, entry in registry.load(self.data_dir, DOMAIN_KEY)["findings"].items()}  # noqa: E731
        self.assertEqual(sorted(states().values()), ["open"] * 4)
        later = zap()
        later["runs"][0]["results"] = [item for item in later["runs"][0]["results"] if item["ruleId"] != "40012"]
        # The same alerts at the same URLs with other query strings and other evidence: still the same findings.
        later["runs"][0]["results"][1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "https://app.example.com/hello?lang=es"
        outcome = self.import_(later, asset=DOMAIN_KEY)
        self.assertEqual((outcome["runs"][0]["opened"], outcome["runs"][0]["fixed"]), (0, 1))
        self.assertEqual(sorted(states().values()), ["fixed", "open", "open", "open"])
        self.assertEqual(self.import_(nuclei(), asset=DOMAIN_KEY)["runs"][0]["fixed"], 0)  # another tool vouches for nothing of ZAP's
        self.assertEqual(self.import_(zap(), asset=DOMAIN_KEY)["runs"][0]["opened"], 1)   # it came back: it reopens

    def test_the_dashboard_counts_imported_findings(self):
        from pitangus.modules.reporting import dashboard
        self.import_(fixture())
        without = fixture()
        without["runs"][0]["results"] = without["runs"][0]["results"][:1]
        self.import_({"version": "2.1.0", "runs": without["runs"][:1]})
        data = dashboard.compute(self.data_dir)
        asset = next(row for row in data["top_assets"] if row["name"] == "org/api")
        self.assertEqual((asset["open"], asset["critical"]), (3, 1))  # Pitangus's one + Semgrep's one + CodeQL's one
        self.assertEqual(data["kpis"]["fixed_in_window"], 1)


class ApiTests(HttpCase):
    def setUp(self):
        super().setUp()
        from pitangus.modules.identity.auth import Users
        record = _scan("org/api", [_finding(A)], datetime.now(timezone.utc).isoformat())
        record["source"]["uid"] = KEY
        save_repository_scan(self.data_dir, record)
        Users(self.data_dir).create("analista", PASSWORD)
        _, _, cookies = self.post("/api/auth/login", "login", {"username": "analista", "password": PASSWORD})
        self.member = cookies[0].split("; ")[0]

    def ci(self, body, *, token=TOKEN, query="", headers=None, raw=None):
        import asgi
        response = asgi.request(self.client, "POST", "/api/ci/sarif" + query, raw if raw is not None else json.dumps(body),
                                {**({"Authorization": f"Bearer {token}"} if token else {}), "Content-Type": "application/json", **(headers or {})})
        return response.status_code, response.json(), response.headers

    def test_members_import_from_the_panel_with_csrf(self):
        envelope = {"asset": "org/api", "sarif": fixture()}
        self.assertEqual(self.post("/api/imports/sarif", "import-sarif", envelope)[0], 401)
        self.assertEqual(self.post("/api/imports/sarif", "scan-repository", envelope, self.member)[0], 403)
        self.assertEqual(self.call("POST", "/api/imports/sarif", envelope, {"Cookie": self.member, "Origin": "http://evil.test",
                                                                            "X-Pitangus-Action": "import-sarif"})[0], 403)
        status, body, _ = self.post("/api/imports/sarif", "import-sarif", envelope, self.member)
        self.assertEqual((status, [run["tool"] for run in body["runs"]], body["asset"]), (200, ["Semgrep OSS", "CodeQL"], KEY))
        self.assertEqual(load_run(self.data_dir, body["runs"][0]["id"])["requested_by"], "analista")
        status, body, _ = self.post("/api/imports/sarif", "import-sarif", {**envelope, "asset": "org/nope"}, self.member)
        self.assertEqual(status, 404)
        self.assertEqual(self.post("/api/imports/sarif", "import-sarif", {**envelope, "sarif": {"version": "1"}}, self.member)[0], 400)
        self.assertEqual(self.post("/api/imports/sarif", "import-sarif", {**envelope, "extra": 1}, self.member)[0], 400)
        # Pitangus can't re-run another tool: re-verifying an imported finding asks for a new import.
        _, imported, _ = self.post("/api/imports/sarif", "import-sarif", envelope, self.member)
        run = load_run(self.data_dir, imported["runs"][1]["id"])
        status, answer, _ = self.post("/api/findings/reverify", "reverify-finding",
                                      {"run_id": run["id"], "fingerprint": run["findings"][0]["fingerprint"]}, self.member)
        self.assertEqual(status, 409)
        self.assertIn("CodeQL", answer["error"])

    def test_ci_route_is_off_without_a_long_token_and_bearer_only(self):
        envelope = {"asset": "org/api", "sarif": fixture()}
        self.assertEqual(self.ci(envelope)[0], 404)
        with patch.dict(os.environ, {"PITANGUS_IMPORT_TOKEN": "short"}):
            self.assertEqual(self.ci(envelope, token="short")[0], 404)
        with patch.dict(os.environ, {"PITANGUS_IMPORT_TOKEN": TOKEN}):
            status, _, headers = self.ci(envelope, token=None)
            self.assertEqual((status, headers["www-authenticate"]), (401, 'Bearer realm="pitangus-import"'))
            self.assertEqual(self.ci(envelope, token="x" * 40)[0], 401)
            self.assertEqual(self.ci(envelope, token=None, headers={"Authorization": f"Basic {TOKEN}"})[0], 401)
            status, body, _ = self.ci(envelope, headers={"X-Pitangus-Actor": "octo cat\n<script>"})
            self.assertEqual((status, len(body["runs"])), (200, 2))
            self.assertEqual(load_run(self.data_dir, body["runs"][0]["id"])["requested_by"], "ci:octocatscript")
            status, body, _ = self.ci(fixture(), query="?asset=org/api&tool=Strix&scope=partial")  # bare SARIF, options in the query
            self.assertEqual((status, [(run["tool"], run["scope"]) for run in body["runs"]]), (200, [("Strix", "partial")]))
            self.assertEqual(self.ci({**envelope, "asset": "org/nope"})[0], 404)
            # A pipeline's ZAP results land on a verified domain, and on nothing nobody vouches for.
            self.assertEqual(self.ci(zap(), query=f"?asset={DOMAIN_KEY}")[0], 404)
            verified_domain(self.data_dir, verified=False)
            status, body, _ = self.ci(zap(), query=f"?asset={DOMAIN_KEY}", headers={"Accept-Language": "en"})
            self.assertEqual((status, "verified" in body["error"]), (409, True))
            from pitangus.modules.sources import domains
            now = datetime.now(timezone.utc)
            domains._mark(self.data_dir, domains.find_domain(self.data_dir, HOST)["id"], verified_at=now, verified_until=now + timedelta(days=1))
            status, body, _ = self.ci(zap(), query=f"?asset={DOMAIN_KEY}")
            self.assertEqual((status, body["asset"], body["runs"][0]["findings"]), (200, DOMAIN_KEY, 4))
            self.assertEqual(self.ci(None, raw="[" * 100_000 + "]" * 100_000)[0], 400)  # nested too deep
            self.assertEqual(self.ci(None, raw="{not json")[0], 400)

    def test_only_the_import_routes_accept_large_bodies(self):
        large = b" " * 2_000_000 + json.dumps({"asset": "org/api", "sarif": fixture()}).encode()
        with patch.dict(os.environ, {"PITANGUS_IMPORT_TOKEN": TOKEN}):
            self.assertEqual(self.ci(None, raw=large)[0], 200)
            too_large = b" " * 10_000_001
            self.assertEqual(self.ci(None, raw=too_large)[0], 413)
        headers = {"Cookie": self.member, "Origin": ORIGIN, "X-Pitangus-Action": "import-sarif"}
        import asgi
        self.assertEqual(asgi.request(self.client, "POST", "/api/imports/sarif", large, headers).status_code, 200)
        self.assertEqual(asgi.request(self.client, "POST", "/api/imports/sarif", too_large, headers).status_code, 413)
        self.assertEqual(asgi.request(self.client, "POST", "/api/repositories/scans", large,
                                      {**headers, "X-Pitangus-Action": "scan-repository"}).status_code, 413)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        record = _scan("org/api", [_finding(A)], datetime.now(timezone.utc).isoformat())
        record["source"]["uid"] = KEY
        save_repository_scan(self.data_dir, record)

    def cli(self, *arguments, environment=None):
        from pitangus.cli.main import main
        with patch("sys.stdout", io.StringIO()) as out, patch("sys.stderr", io.StringIO()) as err, \
                patch.dict(os.environ, environment or {}):
            code = main(["--data-dir", str(self.data_dir), "import-sarif", *arguments])
        return code, out.getvalue(), err.getvalue()

    def test_local_import_into_the_database(self):
        code, out, _ = self.cli(str(FIXTURE), "--asset", "org/api", "--commit", "abcdef1")
        self.assertEqual(code, 0)
        self.assertIn("Semgrep OSS", out)
        self.assertEqual(len([line for line in out.splitlines() if "CodeQL" in line]), 1)
        second = self.data_dir / "second.sarif"
        second.write_text(json.dumps(sarif("CodeQL", [])))
        code, out, _ = self.cli(str(FIXTURE), str(second), "--asset", "org/api", "--partial")  # several files, one import
        self.assertEqual(code, 0)
        self.assertEqual(len([line for line in out.splitlines() if "CodeQL" in line]), 1)
        self.assertEqual(self.cli(str(FIXTURE), "--asset", "org/unknown")[0], 2)
        verified_domain(self.data_dir)
        code, out, _ = self.cli(str(ZAP), str(NUCLEI), "--asset", DOMAIN_KEY)
        self.assertEqual(code, 0)
        self.assertIn(DOMAIN_KEY, out)
        self.assertEqual(len([line for line in out.splitlines() if "ZAP" in line or "Nuclei" in line]), 2)
        code, _, err = self.cli(str(ZAP), "--asset", "domain:nobody.example.com")
        self.assertEqual(code, 2)
        self.assertIn("nobody.example.com", err)
        bad = self.data_dir / "bad.sarif"
        bad.write_text("{nope")
        code, _, err = self.cli(str(bad), "--asset", "org/api")
        self.assertEqual(code, 2)
        self.assertIn("bad.sarif", err)

    def test_remote_import_needs_the_token_and_https(self):
        self.assertEqual(self.cli(str(FIXTURE), "--asset", "org/api", "--server", "https://pitangus.example.com")[0], 2)
        env = {"PITANGUS_IMPORT_TOKEN": TOKEN}
        for server in ("http://pitangus.example.com", "ftp://x", "https://user@x.example.com", "https://x.example.com/?a=1"):
            self.assertEqual(self.cli(str(FIXTURE), "--asset", "org/api", "--server", server, environment=env)[0], 2, server)

    def test_remote_import_posts_to_the_ci_route_without_redirects(self):
        sent = []

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        class Opener:
            def open(self, request, timeout):
                sent.append(request)
                return Response(json.dumps({"asset": KEY, "name": "org/api", "runs": [
                    {"id": "f" * 32, "tool": "CodeQL", "version": None, "scope": "full", "status": "completed", "findings": 1,
                     "excluded": 0, "skipped": 0, "opened": 1, "fixed": 0}]}).encode())
        with patch("pitangus.shared.http.opener", return_value=Opener()):
            code, out, _ = self.cli(str(FIXTURE), "--asset", "org/api", "--tool", "CodeQL", "--server", "http://127.0.0.1:8766/",
                                    environment={"PITANGUS_IMPORT_TOKEN": TOKEN})
        self.assertEqual(code, 0)
        self.assertIn("CodeQL", out)
        request = sent[0]
        self.assertEqual((request.full_url, request.get_header("Authorization")), ("http://127.0.0.1:8766/api/ci/sarif", f"Bearer {TOKEN}"))
        payload = json.loads(request.data)
        self.assertEqual((payload["asset"], payload["tool"], payload["scope"], len(payload["sarif"]["runs"])), ("org/api", "CodeQL", "full", 2))
        self.assertNotIn(TOKEN, " ".join(request.full_url.split("?")))

    def test_remote_http_errors_exit_2(self):
        from urllib.error import HTTPError

        class Opener:
            def open(self, request, timeout):
                raise HTTPError(request.full_url, 404, "Not Found", {}, io.BytesIO(b'{"error": "No asset"}'))
        with patch("pitangus.shared.http.opener", return_value=Opener()):
            code, _, err = self.cli(str(FIXTURE), "--asset", "org/api", "--server", "https://pitangus.example.com",
                                    environment={"PITANGUS_IMPORT_TOKEN": TOKEN})
        self.assertEqual(code, 2)
        self.assertIn("404", err)


if __name__ == "__main__":
    unittest.main()
