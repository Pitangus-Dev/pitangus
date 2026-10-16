"""The Jira issue description: written for the developer who fixes it, and safe to build from what a scan found."""

import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from pitangus.modules.integrations import jira
from pitangus.modules.runs import jira_brief
from pitangus.modules.runs.jira_brief import brief
from pitangus.modules.runs.jira_sync import TITLE_MAX, issue_title

DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": 365}
SOURCE = {"id": "github:acme/api", "name": "acme/api", "branch": "main", "commit": "a" * 40}


def ticket(fingerprint, severity="high"):
    return {"fingerprint": fingerprint, "finding_id": fingerprint[:16], "severity": severity, "priority": "High", "summary": "x"}


def nodes(document, kind):
    found = []

    def walk(node):
        if isinstance(node, dict):
            if node.get("type") == kind:
                found.append(node)
            for child in node.get("content") or []:
                walk(child)
    walk(document)
    return found


class BriefTests(unittest.TestCase):
    def write(self, group, findings, **extra):
        return brief(group, findings, asset="acme/api", source=extra.pop("source", SOURCE), first_seen=extra.pop("first_seen", {}),
                     days=DAYS, panel_url=extra.pop("panel_url", None), locale="en")

    def test_code_finding_reads_in_the_order_a_developer_needs(self):
        finding = {"fingerprint": "1" * 64, "scanner": "sast", "rule_id": "python.sql-injection", "title": "SQL injection from request input",
                   "reason": "Request input reaches a SQL query built as text", "remediation": "Use the driver's parameters",
                   "path": "app/db.py", "line": 14, "severity": "high", "cwe": [89]}
        written = self.write([ticket("1" * 64)], {"1" * 64: finding}, first_seen={"1" * 64: "2026-09-20T10:00:00+00:00"},
                             panel_url="https://pitangus.acme.io/#/findings?repo=x&finding=y")
        # The first lines are the work: what to change, where, and how to verify it; why it matters comes after.
        self.assertEqual(written["blocks"][0], {"paragraph": [{"strong": "Use the driver's parameters."}]})
        text = written["text"]
        order = [text.index(part) for part in ("Use the driver's parameters.", "File: app/db.py:14", "Done when:", "Why", "Due date: 2026-10-20",
                                                "SQL injection from request input.")]
        self.assertEqual(order, sorted(order))
        self.assertEqual([block["heading"] for block in written["blocks"] if "heading" in block], ["Why"])
        document = jira.adf_document(written["blocks"])
        links = [mark["attrs"]["href"] for node in nodes(document, "text") for mark in node.get("marks") or [] if mark["type"] == "link"]
        self.assertIn(f"https://github.com/acme/api/blob/{'a' * 40}/app/db.py#L14", links)
        self.assertIn("https://cwe.mitre.org/data/definitions/89.html", links)
        for jargon in ("python.sql-injection", "sast", "attend", "Priority"):
            self.assertNotIn(jargon, written["text"])

    def test_a_secret_never_carries_its_value_or_panel_instructions(self):
        finding = {"fingerprint": "2" * 64, "scanner": "secrets", "rule_id": "github-pat", "title": "Exposed GitHub token",
                   "reason": "", "remediation": "", "path": "config/settings.py", "line": 3, "severity": "critical", "cwe": [798]}
        written = self.write([ticket("2" * 64, "critical")], {"2" * 64: finding})
        self.assertIn("isn't included here on purpose", written["text"])
        self.assertIn("Revoke", written["text"])
        self.assertNotIn("Verify again", written["text"])

    def test_a_package_lists_its_vulnerabilities_and_the_version_that_closes_them(self):
        def advisory(fingerprint, cve, fixed):
            return {"fingerprint": fingerprint, "scanner": "sca", "rule_id": cve, "cve": [cve], "title": cve, "path": "package-lock.json",
                    "line": 1, "severity": "high", "package": {"ecosystem": "npm", "name": "lodash", "version": "4.17.15", "fixed_version": fixed,
                                                                "direct": True}, "advisory": {"summary": "Prototype pollution", "cvss_score": 7.4}}
        findings = {"3" * 64: advisory("3" * 64, "CVE-2020-8203", "4.17.19"), "4" * 64: advisory("4" * 64, "CVE-2021-23337", "4.17.21")}
        written = self.write([ticket("3" * 64), ticket("4" * 64)], findings)
        # One action for the package: the version that closes every advisory, then the command.
        self.assertTrue(written["text"].startswith("Update lodash from 4.17.15 to 4.17.21.\n"))
        self.assertIn("npm install lodash@4.17.21", written["text"])
        self.assertIn("2 vulnerabilities: CVE-2020-8203, CVE-2021-23337", written["text"])
        self.assertIn("CVE-2020-8203 · High · Prototype pollution · fixed in 4.17.19", written["text"])
        self.assertNotIn("this advisory", written["text"])
        # The update, then how to check which version ended up installed.
        blocks = nodes(jira.adf_document(written["blocks"]), "codeBlock")
        self.assertEqual([(node["attrs"]["language"], node["content"][0]["text"]) for node in blocks],
                         [("bash", "npm install lodash@4.17.21"), ("bash", "npm ls lodash")])

    def test_a_transitive_dependency_says_who_brings_it_in_and_what_to_update_if_it_stays(self):
        package = {"ecosystem": "cargo", "name": "rustls-webpki", "version": "0.103.10", "fixed_version": "0.103.13", "direct": False,
                   "introduced_by": [{"name": "rustls", "version": "0.23.20", "direct": "reqwest", "direct_version": "0.12.9", "chain": ["reqwest", "rustls"]}]}
        finding = {"fingerprint": "6" * 64, "scanner": "sca", "rule_id": "GHSA-82j2-j2ch-gfr8", "ghsa": ["GHSA-82j2-j2ch-gfr8"], "title": "DoS",
                   "path": "Cargo.lock", "severity": "high", "package": package}
        written = self.write([ticket("6" * 64)], {"6" * 64: finding})
        self.assertTrue(written["text"].startswith("Update rustls-webpki to 0.103.13; if it stays below, update reqwest, which brings it in.\n"))
        commands = [node["content"][0]["text"] for node in nodes(jira.adf_document(written["blocks"]), "codeBlock")]
        self.assertEqual(commands, ["cargo update -p rustls-webpki@0.103.10 --precise 0.103.13", "cargo tree --invert rustls-webpki", "cargo update -p reqwest"])

    def test_nothing_a_finding_carries_can_become_a_link_or_markup(self):
        finding = {"fingerprint": "5" * 64, "scanner": "sast", "rule_id": "r", "severity": "medium", "path": "a.py", "line": 1,
                   "title": "[click](https://evil.example) <script>alert(1)</script> {{jira:macro}}", "reason": "",
                   "remediation": "see javascript:alert(1)"}
        document = jira.adf_document(self.write([ticket("5" * 64, "medium")], {"5" * 64: finding}, source={})["blocks"])
        hrefs = [mark["attrs"]["href"] for node in nodes(document, "text") for mark in node.get("marks") or [] if mark["type"] == "link"]
        self.assertFalse([href for href in hrefs if "evil" in href or href.startswith("javascript")])
        self.assertIn("[click](https://evil.example)", json.dumps(document))  # kept as plain text

    def test_the_document_builder_accepts_only_https_links_and_safe_languages(self):
        document = jira.adf_document([{"paragraph": [{"link": "x", "url": "http://plain.example"}, {"link": "y", "url": "https://ok.example"}]},
                                      {"code": "echo hi\x07", "language": "bash; rm"}, {"code": "print()", "language": "python"}])
        hrefs = [mark["attrs"]["href"] for node in nodes(document, "text") for mark in node.get("marks") or [] if mark["type"] == "link"]
        self.assertEqual(hrefs, ["https://ok.example"])
        blocks = nodes(document, "codeBlock")
        self.assertNotIn("attrs", blocks[0])
        self.assertNotIn("\x07", blocks[0]["content"][0]["text"])
        self.assertEqual(blocks[1]["attrs"], {"language": "python"})


if __name__ == "__main__":
    unittest.main()


SNAPSHOT = Path(__file__).parent / "fixtures" / "jira-adf-dependency.json"
# The guide's content is the fix guide's (findings/fix_guide.py), not this layout's: a fixed one keeps the snapshot
# about how the issue is laid out, whatever the guides say tomorrow.
GUIDE = {"action": "Update starlette from 0.37.2 to 0.47.2.", "steps": ["Update starlette from 0.37.2 to 0.47.2.", "Run the tests."],
         "commands": [{"code": 'poetry add "starlette>=0.47.2"', "action": "apply"},
                      {"code": "poetry show starlette", "action": "check", "label": "Check that it shows 0.47.2 or later"}]}


class AdfSnapshotTests(unittest.TestCase):
    def test_a_dependency_issue_is_this_document(self):
        """The exact Atlassian document Jira Cloud receives for a package with two advisories (UPDATE_SNAPSHOTS=1 rewrites
        it): first the change, where (linked to the file at the scanned commit), the commands and when it is done; then
        why in a few lines; the details last. Only nodes Pitangus builds: no Markdown, no code from the repository."""
        def advisory(fingerprint, cve, fixed, epss=None):
            return {"fingerprint": fingerprint, "scanner": "sca", "rule_id": cve, "cve": [cve], "title": cve, "path": "backend/poetry.lock",
                    "line": 1, "severity": "high", "cwe": [400], "epss": {"score": epss} if epss else None,
                    "package": {"ecosystem": "pypi", "name": "starlette", "version": "0.37.2", "fixed_version": fixed, "direct": True},
                    "advisory": {"summary": "Denial of service through multipart forms", "cvss_score": 7.5}}
        findings = {"3" * 64: advisory("3" * 64, "CVE-2024-47874", "0.40.0", 0.31), "4" * 64: advisory("4" * 64, "CVE-2025-54121", "0.47.2")}
        with patch.object(jira_brief, "_fix", return_value=GUIDE):
            written = brief([ticket("3" * 64), ticket("4" * 64)], findings, asset="org/fastapi_template", source=SOURCE,
                            first_seen={"3" * 64: "2026-10-01T09:00:00+00:00"}, days=DAYS,
                            panel_url="https://pitangus.example.com/#/findings?repo=github%3Aorg%2Fapi&finding=" + "3" * 64, locale="en")
        document = jira.adf_document(written["blocks"])
        if os.environ.get("UPDATE_SNAPSHOTS"):
            SNAPSHOT.write_text(json.dumps(document, ensure_ascii=False, indent=1) + "\n")
        self.assertEqual(document, json.loads(SNAPSHOT.read_text()))
        kinds = {node["type"] for node in _walk(document)}
        self.assertLessEqual(kinds, {"doc", "paragraph", "text", "heading", "bulletList", "orderedList", "listItem", "codeBlock"})
        self.assertEqual([node["content"][0]["text"] for node in nodes(document, "codeBlock")],
                         ['poetry add "starlette>=0.47.2"', "poetry show starlette"])


def _walk(node):
    yield node
    for child in node.get("content") or []:
        yield from _walk(child)


class IssueTitleTests(unittest.TestCase):
    """The summary says what and where, in Jira's 255 characters, and is the same every time for the same finding."""

    def title(self, **extra):
        values = {"severity": "High", "asset": "fastapi_template", "where": "poetry.lock", "title": "", "package": "starlette",
                  "version": "0.37.2", "target": "1.3.1", "locale": "en"} | extra
        return issue_title(**values)

    def test_what_and_where(self):
        self.assertEqual(self.title(), "High · starlette 0.37.2 → 1.3.1 · fastapi_template (poetry.lock)")
        self.assertEqual(self.title(target=None), "High · starlette 0.37.2 · no fix yet · fastapi_template (poetry.lock)")
        self.assertEqual(self.title(where=""), "High · starlette 0.37.2 → 1.3.1 · fastapi_template")
        self.assertEqual(self.title(package=None, title="SQL injection from request input", where="app/db.py:14"),
                         "High · SQL injection from request input · fastapi_template (app/db.py:14)")
        self.assertEqual(self.title(locale="es", severity="Alta"), "Alta · starlette 0.37.2 → 1.3.1 · fastapi_template (poetry.lock)")

    def test_long_paths_keep_their_end_and_long_titles_give_way_first(self):
        deep = "/".join(["services"] * 12) + "/backend/poetry.lock"
        self.assertEqual(self.title(where=deep), "High · starlette 0.37.2 → 1.3.1 · fastapi_template (…/backend/poetry.lock)")
        long = self.title(package=None, title="Unsafe " * 80, where="app/db.py:14", asset="org/" + "a" * 300)
        self.assertLessEqual(len(long), TITLE_MAX)
        self.assertTrue(long.startswith("High · Unsafe Unsafe"))
        self.assertIn("db.py:14", long)

    def test_always_fits_and_is_deterministic(self):
        cases = [{"package": None, "title": "x" * 1000, "where": "y/" * 400, "asset": "z" * 400},
                 {"package": "p" * 400, "version": "1" * 200, "target": "2" * 200, "where": "w" * 600, "asset": "a" * 500},
                 {"package": None, "title": "line\nbreak\x07 and\ttab", "where": "a.py:1"}]
        for case in cases:
            first = self.title(**case)
            self.assertLessEqual(len(first), TITLE_MAX)
            self.assertEqual(first, self.title(**case))
            self.assertNotRegex(first, r"[\x00-\x1f]")
