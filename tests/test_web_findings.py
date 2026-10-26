"""Web findings: the scanner's own guidance kept as published, plus what Pitangus derives from the result (the highlighted
fragment of the evidence, a curl check of the headers, a web priority factor) and nothing invented."""

import json
import re
import shlex
import time
import unittest
from pathlib import Path

from hypothesis import given, settings, strategies as st

from pitangus.modules.findings import fix_guide, web_fix
from pitangus.modules.integrations.notifications import _where
from pitangus.modules.reporting.design import location
from pitangus.modules.runs.jira_brief import brief
from pitangus.modules.scanning.sarif_import import parse
from pitangus.shared import render
from pitangus.shared.i18n import localize, msg, text

OUTPUTS = Path(__file__).resolve().parent / "engine-outputs"
CSP = ("default-src 'self'; script-src 'self' 'sha256-abc='; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "form-action 'self'; frame-ancestors 'none'")


def zap_finding(rule: str, message: str, evidence: str = "", *, uri="https://pitangus.dev/", parameter="", method="GET",
                rule_extra: dict | None = None) -> dict:
    location = {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 1, **({"snippet": {"text": evidence}} if evidence else {})}},
                "properties": {"attack": "", **({"param": parameter} if parameter else {})}}
    rule_entry = {"id": rule, "name": "rule", "shortDescription": {"text": "rule"}, **(rule_extra or {})}
    document = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ZAP", "version": "2.17.0", "rules": [rule_entry]}},
                                              "results": [{"ruleId": rule, "level": "warning", "message": {"text": message}, "locations": [location],
                                                           "webRequest": {"method": method, "target": uri}}]}]}
    return parse(document)[0]["findings"][0]


def served(finding: dict) -> dict:
    return fix_guide.attach([dict(finding)])[0]


class KeptFromTheScannerTests(unittest.TestCase):
    def test_the_rules_description_solution_and_references_are_kept_as_published(self):
        findings = parse(json.loads((OUTPUTS / "zap-2.17.sarif").read_text()))[0]["findings"]
        csp = next(item for item in findings if item["rule_id"] == "10055")
        self.assertTrue(csp["web"]["description"].startswith("Content Security Policy (CSP) is an added layer"))
        self.assertIn("Content-Security-Policy header", csp["web"]["solution"])
        self.assertIn(render.url("https://www.w3.org/TR/CSP/"), csp["web"]["references"])   # a link, rendered like any URL
        self.assertEqual((csp["path"], csp["web"]["method"]), ("https://pitangus.dev/", "GET"))
        self.assertNotIn("CF-RAY", json.dumps(findings))  # the response it attached never lands
        # Reachability is a code question: a web finding is never asked to confirm it.
        self.assertNotIn("scanning.priority.confirm_reachability", json.dumps([item["priority"] for item in findings]))

    def test_references_are_links_only_bounded_and_the_attack_is_redacted(self):
        finding = zap_finding("40012", "XSS", "<script>", rule_extra={
            "helpUri": "https://www.zaproxy.org/docs/alerts/40012/",
            "properties": {"references": ["javascript:alert(1)", "https://owasp.org/xss", "see https://cwe.mitre.org/data/definitions/79.html.",
                                          "https://owasp.org/xss", *[f"https://e.example/{n}" for n in range(20)]], "wascid": "8"}})
        self.assertEqual(finding["web"]["references"][:3], ["https://owasp.org/xss", "https://cwe.mitre.org/data/definitions/79.html",
                                                            "https://e.example/0"])
        self.assertEqual(len(finding["web"]["references"]), 8)
        self.assertEqual(finding["web"]["wasc"], [8])
        document = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ZAP"}}, "results": [{
            "ruleId": "40012", "message": {"text": "XSS"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "https://a.example/"}},
                                                                          "properties": {"attack": "x\nAuthorization: Bearer abcdefgh123"}}]}]}]}
        attack = parse(document)[0]["findings"][0]["web"]["attack"]
        self.assertNotIn("abcdefgh123", attack)
        self.assertIn("Authorization: [redacted]", attack)


class DerivedTests(unittest.TestCase):
    def test_csp_highlights_the_keyword_inside_the_directive_the_message_names(self):
        fix = served(zap_finding("10055", "style-src includes unsafe-inline.", CSP))["fix"]
        self.assertEqual(fix["kind"], "web")
        highlight = fix["web"]["highlight"]
        self.assertEqual(highlight["match"], "'unsafe-inline'")
        self.assertTrue(highlight["before"].endswith("style-src 'self' "))
        self.assertEqual(highlight["before"] + highlight["match"] + highlight["after"], CSP)
        # The same keyword in another directive isn't the one this result is about.
        none = served(zap_finding("10055", "script-src includes unsafe-inline.", CSP))["fix"]["web"]["highlight"]
        self.assertIsNone(none)

    def test_cookie_hsts_and_server_version(self):
        cookie = served(zap_finding("10010", "A cookie has been set without the HttpOnly flag", "Set-Cookie: session", parameter="session"))
        self.assertEqual(cookie["fix"]["web"]["highlight"]["match"], "session")
        self.assertEqual(cookie["fix"]["web"]["check"], "curl -sI https://pitangus.dev/ | grep -i -E '^(set-cookie):'")
        self.assertEqual(cookie["priority"]["factors"][-1], msg("findings.web.factor.cookie"))
        hsts = served(zap_finding("10035", "A HTTP Strict Transport Security (HSTS) header was found, but it contains the directive max-age=0",
                                  "max-age=0; includeSubDomains"))
        self.assertEqual(hsts["fix"]["web"]["highlight"]["match"], "max-age=0")
        self.assertIn("strict-transport-security", hsts["fix"]["web"]["check"])
        self.assertEqual(hsts["priority"]["factors"][-1], msg("findings.web.factor.header"))
        server = served(zap_finding("10036", "The web/application server is leaking version information", "nginx/1.18.0 (Ubuntu)"))
        self.assertEqual(server["fix"]["web"]["highlight"]["match"], "1.18.0")
        self.assertEqual(server["fix"]["commands"][0]["action"], "check")

    def test_server_version_is_found_in_linear_time_after_a_long_run_of_digits(self):
        started = time.monotonic()
        highlight = web_fix.highlight({"rule_id": "10036", "web": {"evidence": "9" * 100_000 + " nginx/1.18.0"}}, "")
        self.assertLess(time.monotonic() - started, 2)  # quadratic before: about a minute
        self.assertEqual(highlight["match"], "1.18.0")

    def test_server_version_is_found_where_the_former_pattern_found_it(self):
        former = re.compile(r"(?<!\d)\d+(?:\.\d+)+[\w.-]*")
        cases = ["nginx/1.18.0 (Ubuntu)", "Apache/2.4.41", "PHP/8.1.2-1ubuntu2.14", "v1.2", "1.", "1.a", ".1.2", "12..3",
                 "build 2024 then 3.4", "x1.2.3_rc-1/2", "٣.٤", "9" * 50 + "." + "9" * 50, "1.2" * 1000, "", "no version"]

        def check(evidence):
            found = former.search(evidence)
            self.assertEqual(web_fix.version_span(evidence), (found.start(), found.end()) if found else None, evidence)
        for evidence in cases:
            check(evidence)
        settings(max_examples=3000, deadline=None)(given(st.text(alphabet="0123456789.-_ab/ (٣", max_size=40))(check))()

    def test_words_split_where_the_former_pattern_split_them(self):
        former = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
        for text_ in ("HTTPServer2", "parseHTTPResponse", "AbC", "ABCdef", "aB", "A", "Aa", "AAa", "getURLs", "v1Beta2",
                      "snake_case-ID", "ÁrbolÑu", "٣٤x", ""):
            self.assertEqual(render._identifier_words(text_), former.findall(text_), text_)

        @settings(max_examples=3000, deadline=None)
        @given(st.text(alphabet="AZaz09_-Éé٣ ", max_size=40))
        def same(text_):
            self.assertEqual(render._identifier_words(text_), former.findall(text_), text_)
        same()

    def test_words_and_versions_take_linear_time_on_long_runs(self):
        for pathological in ("A" * 200_000, "Aa" * 100_000, "A" * 100_000 + "a", "0" * 200_000, "0." * 100_000, "1" * 100_000 + "x"):
            started = time.monotonic()
            render._identifier_words(pathological)
            render.plain_share(pathological)
            web_fix.version_span(pathological)
            self.assertLess(time.monotonic() - started, 2, pathological[:10])

    def test_only_header_rules_on_get_get_a_check(self):
        self.assertIsNone(served(zap_finding("10096", "1831565813", "1831565813"))["fix"]["web"]["check"])
        self.assertEqual(served(zap_finding("10096", "1831565813", "1831565813"))["fix"]["commands"], [])
        self.assertIsNone(served(zap_finding("10010", "no HttpOnly", "Set-Cookie: s", parameter="s", method="POST"))["fix"]["web"]["check"])
        nuclei = parse(json.loads((OUTPUTS / "nuclei.sarif").read_text()))[0]["findings"]
        self.assertEqual(fix_guide.attach(nuclei)[0]["fix"]["web"]["check"],
                         "curl -sI https://app.example.com/ | grep -i -E '^(strict-transport-security):'")
        self.assertIsNone(nuclei[2]["fix"]["web"]["check"])  # .git/config is no header

    def test_the_check_quotes_whatever_url_the_site_has(self):
        for uri in ("https://pitangus.dev/a'b", "https://pitangus.dev/$(id)`uname`;rm", "https://pitangus.dev/x|y&z>w"):
            finding = served(zap_finding("10021", "X-Content-Type-Options header missing", uri=uri))
            command = finding["fix"]["web"]["check"]
            arguments = shlex.split(command.split(" | ")[0])
            self.assertEqual(arguments, ["curl", "-sI", finding["path"]])
            self.assertEqual(command.count(" | "), 1)
        self.assertIsNone(web_fix.check({"scanner": "dast", "tool": "ZAP", "rule_id": "10021", "path": "-o /etc/passwd", "web": {}}))

    def test_an_unknown_rule_keeps_the_scanners_text_and_says_to_rescan(self):
        finding = served(zap_finding("99999", "Something odd", "odd", rule_extra={"properties": {"solution": {"text": "Do the thing."}}}))
        steps = [text(step, "en") for step in finding["fix"]["steps"]]
        self.assertEqual(steps[0], "Guidance from ZAP: Do the thing.")
        self.assertIn("scan the domain again", steps[1])
        self.assertIsNone(finding["fix"]["web"]["check"])
        self.assertEqual(finding["priority"]["factors"][-1], msg("findings.web.factor.observed"))

    def test_findings_stored_before_still_render_and_lose_the_code_factor(self):
        stored = {"scanner": "dast", "tool": "ZAP", "rule_id": "10055", "path": "https://pitangus.dev/", "line": 1, "severity": "medium",
                  "reason": msg("scanning.sarif.reason", tool="ZAP", message="style-src includes unsafe-inline."),
                  "remediation": msg("scanning.sarif.remediation_help", tool="ZAP", help="Ensure that your web server sets it."),
                  "priority": {"action": "track", "factors": [msg("scanning.sarif.priority", tool="ZAP", severity="medium"),
                                                              msg("scanning.priority.confirm_reachability")]},
                  "web": {"method": "GET", "evidence": CSP}}
        original = json.loads(json.dumps(stored))
        twice = fix_guide.attach(fix_guide.attach([stored]))[0]
        self.assertEqual([item["$t"] for item in twice["priority"]["factors"]], ["scanning.sarif.priority", "findings.web.factor.header"])
        self.assertEqual(twice["fix"]["web"]["highlight"]["match"], "'unsafe-inline'")
        self.assertEqual(original["priority"]["factors"][1], msg("scanning.priority.confirm_reachability"))
        es = localize(twice["fix"], "es")
        self.assertIn("vuelve a analizar el dominio", es["steps"][1])
        self.assertEqual(es["commands"][0]["label"], "Revisa las cabeceras de la respuesta")

    def test_code_findings_keep_their_factor(self):
        code = {"scanner": "sast", "rule_id": "x", "remediation": "Fix it", "priority": {"action": "track", "factors": [msg("scanning.priority.confirm_reachability")]}}
        self.assertEqual(fix_guide.attach([code])[0]["priority"]["factors"], [msg("scanning.priority.confirm_reachability")])


class RenderedTests(unittest.TestCase):
    def test_a_url_never_gets_a_line(self):
        finding = {"scanner": "dast", "path": "https://pitangus.dev/", "line": 1}
        self.assertEqual(location(finding), "https://pitangus.dev/")
        self.assertEqual(_where(finding), "https://pitangus.dev/")
        self.assertEqual(location({"scanner": "sast", "path": "app.py", "line": 3}), "app.py:3")

    def test_jira_issue_for_a_web_finding(self):
        finding = served(zap_finding("10055", "style-src includes unsafe-inline.", CSP, rule_extra={
            "fullDescription": {"text": "CSP is an added layer of security."},
            "properties": {"solution": {"text": "Set the header."}, "references": ["https://www.w3.org/TR/CSP/"]}}))
        fingerprint = finding["fingerprint"]
        written = brief([{"fingerprint": fingerprint, "finding_id": fingerprint[:16], "severity": "medium", "summary": "x"}], {fingerprint: finding},
                        asset="pitangus.dev", source={"name": "pitangus.dev", "provider": "domain"}, first_seen={},
                        days={"medium": 90}, panel_url=None, locale="en")["text"]
        for expected in ("Site: pitangus.dev", "URL: GET https://pitangus.dev/", "According to ZAP: CSP is an added layer of security.",
                         "Guidance from ZAP: Set the header.", "Check the response headers:\n    curl -sI https://pitangus.dev/", "a new scan of the domain",
                         render.url("https://www.w3.org/TR/CSP/")):
            self.assertIn(expected, written)
        for code_talk in ("Repository", "pull request", ":1"):
            self.assertNotIn(code_talk, written)
