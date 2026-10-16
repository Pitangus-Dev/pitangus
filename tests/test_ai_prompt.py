"""'Fix it with your own AI': a prompt per finding, with the rule, the place and the fix. Pitangus stores no code, so
the prompt it builds has none: the reader's code goes in where they read it (the panel, the CLI), never a secret's."""

import json
import unittest
from datetime import datetime, timezone

from pitangus.modules.findings.ai_prompt import code_text, parts, prompt
from pitangus.modules.findings.fix_guide import attach
from pitangus.modules.identity.auth import Users
from pitangus.modules.runs.store import save_repository_scan
from test_auth import PASSWORD, HttpCase
from test_dashboard import _scan

TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def code(snippet, **extra):
    return {"finding_id": "c" * 16, "fingerprint": "c" * 64, "scanner": "sast", "tool": "opengrep", "rule_id": "appsec.py.eval-exec-non-literal",
            "title": "Code evaluated from a dynamic expression", "path": "app/views.py", "line": 12, "severity": "high", "confidence": 8,
            "verdict": "candidate", "cwe": [95], "owasp": ["A05:2025"], "cve": [], "ghsa": [], "package": None, "advisory": None,
            "kev": None, "epss": None, "priority": {"action": "attend", "factors": []}, "reason": "eval() runs what the user sent.",
            "remediation": "Use a lookup table of allowed functions.", "snippet": snippet, **extra}


class PromptTests(unittest.TestCase):
    def test_it_says_what_where_why_and_how_and_carries_code_only_when_given(self):
        finding = attach([code("result = eval(request.args['expr'])")])[0]
        text = prompt(finding, "en")
        for part in ("Code evaluated from a dynamic expression", "appsec.py.eval-exec-non-literal", "app/views.py:12",
                     "Use a lookup table"):
            self.assertIn(part, text)
        # Nothing stored is code: no fragment unless the reader's code is handed in.
        self.assertNotIn("```", text)
        self.assertNotIn("eval(request", text)
        self.assertIn("```python\nresult = eval(q)\n```", prompt(finding, "en", "result = eval(q)"))
        pieces = parts(finding, "en")
        self.assertEqual(text, f"{pieces['before']}\n\n{pieces['after']}\n")
        self.assertEqual(pieces["language"], "python")
        self.assertNotIn("Re-verify", text)  # the panel's own step means nothing to an assistant
        self.assertIn("Corrige este hallazgo", prompt(code("eval(x)"), "es"))

    def test_a_secret_never_reaches_the_prompt(self):
        secret = {**code(f'token = "{TOKEN}"'), "scanner": "secrets", "rule_id": "github-pat", "cwe": [798]}
        text = prompt(attach([secret])[0], "en", f'token = "{TOKEN}"')
        self.assertNotIn(TOKEN, text)
        self.assertNotIn("```", text)
        self.assertIn("rotated first", text)
        hardcoded = code('String password = "hunter2-prod";', cwe=[798], rule_id="appsec.java.hardcoded-password", path="App.java")
        self.assertNotIn("hunter2", prompt(hardcoded, "en", 'String password = "hunter2-prod";'))

    def test_a_withheld_line_says_so(self):
        lines = [{"number": 1, "text": "eval(q)", "focus": True}, {"number": 2, "text": "", "focus": False, "masked": "line"}]
        self.assertEqual(code_text(lines, "en"), "eval(q)\n(line withheld: a secret was found on it)")

    def test_a_dependency_says_its_package_and_the_version_that_fixes_it(self):
        dependency = {**code(None), "scanner": "sca", "path": "package-lock.json", "line": 1, "rule_id": "CVE-2021-23337",
                      "package": {"ecosystem": "npm", "name": "lodash", "version": "4.17.20", "fixed_version": "4.17.21", "introduced": None}}
        text = prompt(attach([dependency])[0], "en")
        self.assertIn("lodash 4.17.20; the first version without the problem is 4.17.21", text)
        self.assertNotIn("```", text)


class PromptApiTests(HttpCase):
    def test_signed_in_users_get_the_prompt_in_their_language_and_only_for_a_known_finding(self):
        Users(self.data_dir).create("analista", PASSWORD)
        record = _scan("org/api", [code(f"eval(user_input)  # {TOKEN}")], datetime.now(timezone.utc).isoformat())
        record["source"]["uid"] = "github#9"
        run = save_repository_scan(self.data_dir, record)
        known = run["findings"][0]["fingerprint"]   # as the run stores it (in v2, the problem's identity)
        _, _, cookies = self.post("/api/auth/login", "login", {"username": "analista", "password": PASSWORD})
        cookie = cookies[0].split("; ")[0]
        self.assertEqual(self.call("GET", f"/api/findings/prompt?run_id={run['id']}&fingerprint={known}")[0], 401)
        status, body, _ = self.call("GET", f"/api/findings/prompt?run_id={run['id']}&fingerprint={known}",
                                    headers={"Cookie": cookie, "Accept-Language": "es"})
        self.assertEqual(status, 200)
        self.assertIn("Corrige este hallazgo", body["prompt"])
        self.assertNotIn(TOKEN, json.dumps(body))
        self.assertNotIn("eval(user_input)", json.dumps(body))
        self.assertEqual(body["prompt"], f"{body['before']}\n\n{body['after']}\n")
        self.assertEqual((body["heading"], body["language"]), ("El código donde se encontró:", "python"))
        self.assertEqual(self.call("GET", f"/api/findings/prompt?run_id={run['id']}&fingerprint={'d' * 64}", headers={"Cookie": cookie})[0], 404)


if __name__ == "__main__":
    unittest.main()


class CliTests(unittest.TestCase):
    def test_the_prompt_format_gives_one_prompt_per_finding_worst_first(self):
        from pitangus.modules.runs.local import render_prompt
        low = {**code("print(x)"), "fingerprint": "e" * 64, "severity": "low", "title": "Low one"}
        rendered = render_prompt({"findings": [low, code("eval(x)")], "comparison": None}, locale="en")
        first, second = rendered.split("\n---\n\n")
        self.assertIn("Code evaluated from a dynamic expression", first)
        self.assertIn("Low one", second)
        self.assertIn("No", render_prompt({"findings": [], "comparison": None}, locale="en"))


class ScanOutputTests(unittest.TestCase):
    def test_scan_prints_no_internal_log_unless_asked(self):
        import contextlib
        import io
        import logging
        import os
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from pitangus.cli.main import _scan_logs
        logger = logging.getLogger("pitangus")
        saved = list(logger.handlers)
        try:
            logger.handlers = []
            stderr = io.StringIO()
            with patch.dict(os.environ, {"PITANGUS_LOG_LEVEL": ""}), contextlib.redirect_stderr(stderr), tempfile.TemporaryDirectory() as folder:
                _scan_logs(Path(folder))
                logging.getLogger("pitangus.engines").warning("local_engines_share_the_network")
            self.assertEqual(stderr.getvalue(), "")
        finally:
            logger.handlers = saved
