"""OWASP guidance for findings (modules/findings/references.py and references.yaml)."""

import ast
import re
import unittest
from pathlib import Path

import yaml

from pitangus.modules.findings import references
from pitangus.modules.findings.references import annotate, brief, guidance, mapping, owasp_of, top10

ROOT = Path(__file__).resolve().parents[1]
HOSTS = {"cheatsheet": "https://cheatsheetseries.owasp.org/cheatsheets/", "api_top10": "https://api-security.owasp.org/editions/2023/en/0xa",
         "wstg": "https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/", "top10": "https://top10.owasp.org/2025/A"}
# Where engines pass a CWE positionally: function name → index of the argument.
POSITIONAL_CWE = {"_finding": 7, "_config_finding": 5}


def _ints(node: ast.AST) -> set[int]:
    return {item.value for item in ast.walk(node) if isinstance(item, ast.Constant) and type(item.value) is int}


def emitted_cwes() -> set[int]:
    """Every CWE our rules and engines can put on a finding by themselves (imported SARIF brings its own)."""
    found: set[int] = set()
    for path in (ROOT / "rules").glob("*.yml"):
        for rule in yaml.safe_load(path.read_text())["rules"]:
            found |= {int(item) for item in rule.get("metadata", {}).get("cwe", [])}
    for folder in ("scanning", "intel"):
        for path in (ROOT / "pitangus/modules" / folder).glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Call):
                    found |= {value for keyword in node.keywords if keyword.arg == "cwe" for value in _ints(keyword.value)}
                    name = node.func.id if isinstance(node.func, ast.Name) else ""
                    if name in POSITIONAL_CWE and len(node.args) > POSITIONAL_CWE[name]:
                        found |= _ints(node.args[POSITIONAL_CWE[name]])
                elif isinstance(node, ast.Dict):
                    found |= {value for key, item in zip(node.keys, node.values)
                              if isinstance(key, ast.Constant) and key.value == "cwe" for value in _ints(item)}
    from pitangus.modules.scanning.config_engines import ZIZMOR_AUDITS
    return found | {cwe for _, cwe in ZIZMOR_AUDITS.values()}


class MappingFileTests(unittest.TestCase):
    def test_the_file_is_well_formed(self):
        data = mapping()
        self.assertEqual(data["version"], 1)
        self.assertRegex(data["reviewed"], r"^\d{4}-\d{2}-\d{2}$")
        for key, page in data["pages"].items():
            self.assertEqual(set(page), {"kind", "title", "url"}, key)
            self.assertIn(page["kind"], references.KINDS, key)
            self.assertTrue(page["url"].startswith(HOSTS[page["kind"]]), key)
            self.assertTrue(page["title"].strip(), key)
        if_wstg = [page for page in data["pages"].values() if page["kind"] == "wstg"]
        self.assertTrue(all(re.match(r"WSTG-[A-Z]{4}-\d{2} ", page["title"]) and page["url"].endswith("/") for page in if_wstg))
        self.assertEqual(len({page["url"] for page in data["pages"].values()}), len(data["pages"]))  # one key per page

    def test_every_page_named_exists_and_every_page_is_used(self):
        data = mapping()
        named = [*(page for pages in data["cwe"].values() for page in pages),
                 *(page for tools in data["rules"].values() for pages in tools.values() for page in pages),
                 *(page for pages in data["frameworks"].values() for page in pages),
                 *(page for entry in data["paths"] for page in entry["pages"]),
                 *(page for entry in data["scanners"].values() for page in entry["pages"])]
        self.assertEqual(set(named) - set(data["pages"]), set())
        self.assertEqual(set(data["pages"]) - set(named), set())
        for entry in data["paths"]:
            re.compile(entry["pattern"])

    def test_top10_is_the_official_2025_list(self):
        top = mapping()["top10"]
        self.assertEqual(list(top), [f"A{index:02d}" for index in range(1, 11)])
        every = [cwe for entry in top.values() for cwe in entry["cwe"]]
        self.assertEqual(len(every), len(set(every)))  # OWASP maps each CWE to one category
        for category, entry in top.items():
            self.assertTrue(entry["title"].startswith(f"{category}:2025 "), category)
            self.assertTrue(entry["url"].startswith(f"{HOSTS['top10']}{category[1:]}_2025-"), category)
        self.assertEqual(top10([89, 918, 798]), ["A01:2025", "A05:2025", "A07:2025"])

    def test_every_cwe_our_rules_emit_resolves_or_is_explicitly_unmapped(self):
        data = mapping()
        self.assertEqual(set(data["cwe"]) & set(data["unmapped"]), set())
        self.assertTrue(all(isinstance(reason, str) and reason for reason in data["unmapped"].values()))
        emitted = emitted_cwes()
        self.assertGreater(len(emitted), 30)  # the scan found the engines' CWEs
        self.assertEqual(sorted(emitted - set(data["cwe"]) - set(data["unmapped"])), [])

    def test_every_web_rule_family_and_header_rule_has_its_own_pages(self):
        from pitangus.modules.findings.web_fix import ZAP_HEADERS
        from pitangus.modules.scanning.web_merge import EQUIVALENT
        rules = [(tool, rule) for tools in EQUIVALENT.values() for tool, ids in tools.items() for rule in ids]
        rules += [("zap", rule) for rule in ZAP_HEADERS]
        for tool, rule in rules:
            self.assertTrue(references._rule_pages(tool, rule), (tool, rule))


class GuidanceTests(unittest.TestCase):
    def test_code_finding_gets_its_cwe_pages_then_its_category(self):
        finding = {"scanner": "sast", "tool": "opengrep", "rule_id": "appsec.py.sql", "cwe": [89], "owasp": ["A05:2025"], "path": "a.py"}
        links = guidance(finding)
        self.assertEqual(links[0], {"title": "SQL Injection Prevention Cheat Sheet", "kind": "cheatsheet",
                                    "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"})
        self.assertIn("wstg", [link["kind"] for link in links])
        self.assertEqual(links[-1]["kind"], "top10")
        self.assertEqual(links[-1]["title"], "A05:2025 Injection")

    def test_a_known_web_rule_beats_its_generic_cwe(self):
        csp = guidance({"scanner": "dast", "tool": "ZAP", "rule_id": "10038-1", "cwe": [693], "owasp": [], "path": "https://a.test/"})
        self.assertEqual([link["title"] for link in csp], ["Content Security Policy Cheat Sheet", "A06:2025 Insecure Design"])
        hsts = guidance({"scanner": "dast", "tool": "nuclei", "rule_id": "http-missing-security-headers:strict-transport-security",
                         "cwe": [], "owasp": [], "path": "https://a.test/"})
        self.assertEqual(hsts[0]["title"], "HTTP Strict Transport Security Cheat Sheet")
        other = guidance({"scanner": "dast", "tool": "nuclei", "rule_id": "http-missing-security-headers:referrer-policy", "path": "https://a.test/"})
        self.assertEqual(other[0]["title"], "HTTP Security Response Headers Cheat Sheet")
        tls = guidance({"scanner": "dast", "tool": "testssl", "rule_id": "TLS1_1", "cwe": [327], "owasp": [""], "path": "a.test:443"})
        self.assertEqual([link["title"] for link in tls][:2], ["Transport Layer Security Cheat Sheet", "WSTG-CRYP-01 Testing for Weak Transport Layer Security"])

    def test_pipelines_and_infrastructure_get_their_own_pages_and_no_web_tests(self):
        actions = guidance({"scanner": "cicd", "tool": "zizmor", "rule_id": "template-injection", "cwe": [94], "owasp": ["A03:2025"],
                            "path": ".github/workflows/ci.yml", "framework": "GitHub Actions"})
        self.assertEqual([link["title"] for link in actions], ["GitHub Actions Security Cheat Sheet", "CI/CD Security Cheat Sheet",
                                                               "A03:2025 Software Supply Chain Failures"])
        docker = guidance({"scanner": "iac", "tool": "trivy", "rule_id": "AVD-DS-0002", "cwe": [], "owasp": ["A02:2025"], "path": "app/Dockerfile"})
        self.assertEqual(docker[0]["title"], "Docker Security Cheat Sheet")
        terraform = guidance({"scanner": "iac", "tool": "checkov", "rule_id": "CKV_AWS_20", "path": "infra/s3.tf"})
        self.assertEqual(terraform[0]["title"], "Infrastructure as Code Security Cheat Sheet")
        unknown = guidance({"scanner": "iac", "tool": "trivy", "rule_id": "X", "path": "deploy.yaml", "cwe": [918]})
        # Neither the SSRF page nor its WSTG test for a config file: the scanner's page and the CWE's category.
        self.assertEqual([link["title"] for link in unknown], ["Infrastructure as Code Security Cheat Sheet", "A01:2025 Broken Access Control"])
        image = guidance({"scanner": "iac", "tool": "pitangus", "rule_id": "IMG-ROOT", "cwe": [250], "path": "image-config"})
        self.assertEqual(image[0]["title"], "Docker Security Cheat Sheet")

    def test_dependencies_and_secrets(self):
        sca = guidance({"scanner": "sca", "tool": "trivy", "rule_id": "CVE-2026-1", "cwe": [79], "owasp": ["A03:2025"], "path": "package-lock.json"})
        self.assertEqual([link["title"] for link in sca], ["Vulnerable Dependency Management Cheat Sheet", "Software Supply Chain Security Cheat Sheet",
                                                           "A03:2025 Software Supply Chain Failures"])
        secret = guidance({"scanner": "secrets", "tool": "gitleaks", "rule_id": "aws-access-token", "cwe": [798], "owasp": ["A04:2025"], "path": "Dockerfile"})
        self.assertEqual(secret[0]["title"], "Secrets Management Cheat Sheet")

    def test_owasp_is_filled_from_the_cwe_only_when_the_engine_set_none(self):
        self.assertEqual(owasp_of({"cwe": [918], "owasp": [""]}), ["A01:2025"])
        self.assertEqual(owasp_of({"cwe": [918], "owasp": []}), ["A01:2025"])
        self.assertEqual(owasp_of({"cwe": [918], "owasp": ["A10:2021"]}), ["A10:2021"])  # an imported SARIF's own edition is kept
        self.assertEqual(owasp_of({"cwe": [1188]}), [])
        imported = guidance({"scanner": "sast", "tool": "codeql", "rule_id": "x", "cwe": [918], "owasp": ["A10:2021"], "path": "a.py"})
        self.assertNotIn("top10", [link["kind"] for link in imported])  # only 2025 categories are linked
        [served] = annotate([{"scanner": "dast", "tool": "nuclei", "rule_id": "unknown", "cwe": [352], "owasp": [""], "path": "https://a.test/"}])
        self.assertEqual(served["owasp"], ["A01:2025"])
        self.assertEqual(served["guidance"][0]["title"], "Cross-Site Request Forgery Prevention Cheat Sheet")

    def test_no_guidance_without_anything_to_go_on(self):
        self.assertEqual(guidance({"scanner": "sast", "tool": "x", "rule_id": "y", "cwe": [], "owasp": [], "path": "a.py"}), [])

    def test_a_report_prints_three_pages_and_the_category(self):
        links = guidance({"scanner": "sast", "rule_id": "r", "cwe": [79, 89], "owasp": ["A05:2025"], "path": "a.py"})
        self.assertGreater(len(links), 4)
        self.assertEqual([link["kind"] for link in brief(links)], ["cheatsheet", "cheatsheet", "wstg", "top10"])


class ReportTests(unittest.TestCase):
    FINDING = {"fingerprint": "a" * 64, "finding_id": "a", "scanner": "sast", "tool": "opengrep", "severity": "critical", "rule_id": "py.sql",
               "title": "SQL built from a string", "path": "app/db.py", "line": 12, "reason": "SQL concatenado", "remediation": "Usa parámetros.",
               "cwe": [89], "owasp": ["A05:2025"], "cve": [], "ghsa": [], "kev": None,
               "advisory": {"references": ["https://example.test/advisory"]}}

    def record(self):
        return {"id": "r" * 32, "type": "repository_scan", "status": "completed", "created_at": "2026-09-25T10:00:00+00:00",
                "findings": [dict(self.FINDING)], "owasp_coverage": [], "limitations": [],
                "steps": [{"name": "Opengrep", "status": "completed", "detail": ""}],
                "source": {"name": "org/app", "provider": "github", "sha256": "abc"},
                "summary": {"files": 1, "dependencies": 0, "severities": {"critical": 1}, "priorities": {}}}

    def test_markdown_lists_the_guidance_after_the_tool_references(self):
        from pitangus.modules.runs.store import render_repository_report
        english, spanish = render_repository_report(self.record(), locale="en"), render_repository_report(self.record(), locale="es")
        line = next(item for item in english.splitlines() if item.startswith("OWASP guidance: "))
        self.assertIn("[SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)", line)
        self.assertIn("[A05:2025 Injection](https://top10.owasp.org/2025/A05_2025-Injection/)", line)
        self.assertLess(english.index("References: https://example.test/advisory"), english.index("OWASP guidance: "))
        self.assertIn("Guía OWASP: [SQL Injection Prevention Cheat Sheet]", spanish)

    def test_technical_pdf_sheet_lists_the_guidance_and_the_category(self):
        from pitangus.modules.reporting.technical import render_technical_pdf
        from test_report_design import rendered
        pdf, content = rendered(lambda: render_technical_pdf(self.record(), version="t", locale="en"))
        self.assertIn("CWE-89, A05:2025", content)
        self.assertIn("OWASP guidance: SQL Injection Prevention Cheat Sheet · Query Parameterization Cheat Sheet", content)
        self.assertLess(content.index("References: https://example.test/advisory"), content.index("OWASP guidance:"))
        self.assertIn(b"/URI (https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)", pdf)  # clickable

    def test_a_pdf_link_is_escaped_and_https_only(self):
        from pitangus.modules.reporting.design import link
        self.assertEqual(link("<b>x</b>", "javascript:alert(1)"), "&lt;b&gt;x&lt;/b&gt;")
        self.assertIn('href="https://a.test/?a=1&amp;b=&quot;2&quot;"', link("x", 'https://a.test/?a=1&b="2"'))


if __name__ == "__main__":
    unittest.main()
