"""Community ready for others: demo data and first steps derived from the real state."""

import base64
import os
import socket
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from pitangus.app import demo
from pitangus.modules.integrations import code_tokens, notifications
from pitangus.modules.pullrequests import watch as pr_watch
from pitangus.modules.threats import model as tm
from pitangus.modules.identity.auth import Users, totp_code
from pitangus.modules.runs.store import list_runs, save_repository_scan
from test_auth import PASSWORD, HttpCase
from test_dashboard import _finding, _scan

ROOT = Path(__file__).resolve().parents[1]


class DemoTests(unittest.TestCase):
    def test_demo_analyses_the_bundled_examples_and_imports_the_model_once(self):
        seen = []

        def scan(root, source, **kwargs):
            seen.append((source["id"], sorted(path.name for path in Path(root).iterdir())))
            return {**_scan("demo · ejemplos vulnerables", [_finding("a" * 64)], datetime.now(timezone.utc).isoformat()),
                    "source": {**source, "sha256": "x"}, "context": kwargs.get("context", "")}

        with tempfile.TemporaryDirectory() as folder, patch("pitangus.modules.scanning.repository.scan_repository", side_effect=scan):
            data = Path(folder)
            first = demo.seed(data, fixtures=ROOT / "fixtures", models=ROOT / "web/src/examples/threat-models", report=lambda message: None)
            second = demo.seed(data, fixtures=ROOT / "fixtures", models=ROOT / "web/src/examples/threat-models", report=lambda message: None)
            self.assertEqual(seen[0], ("local:demo-ejemplos", ["sast-samples", "scanner-samples"]))
            self.assertEqual((first["code"]["status"], "threat_model" in first, "threat_model" in second), ("completed", True, False))
            self.assertEqual([model["name"] for model in tm.list_models(data)], [demo.model_name()])  # not duplicated
            self.assertEqual({row["source"]["id"] for row in list_runs(data)}, {"local:demo-ejemplos"})
            # Tests run with PITANGUS_DEFAULT_LOCALE=es: the demo speaks Spanish and imports the Spanish example.
            self.assertEqual(demo.model_name(), "Demo · Portal de clientes (STRIDE)")
            saved = tm.load(data, first["threat_model"])
            self.assertIn("Portal web", {item["name"] for item in saved["components"]})
            # Switching the default locale doesn't import the model again.
            with patch.dict(os.environ, {"PITANGUS_DEFAULT_LOCALE": "en"}):
                third = demo.seed(data, fixtures=ROOT / "fixtures", models=ROOT / "web/src/examples/threat-models", report=lambda message: None)
            self.assertNotIn("threat_model", third)
            with self.assertRaises(FileNotFoundError):
                demo.seed(data, fixtures=data / "no-existe", report=lambda message: None)

    def test_demo_texts_follow_the_default_locale(self):
        models = ROOT / "web/src/examples/threat-models"
        with patch.dict(os.environ, {"PITANGUS_DEFAULT_LOCALE": "en"}):
            self.assertEqual(demo.models_folder(models), models / "en")
            self.assertEqual(demo.model_name(), "Demo · Customer portal (STRIDE)")
            self.assertEqual(demo.demo_source(), {"id": "local:demo-ejemplos", "name": "demo · vulnerable samples", "provider": "local"})
        self.assertEqual(demo.models_folder(models), models / "es")
        self.assertEqual(demo.demo_source()["name"], "demo · ejemplos vulnerables")
        with tempfile.TemporaryDirectory() as folder:  # a flat folder (no per-language subfolders) is used as is
            self.assertEqual(demo.models_folder(Path(folder)), Path(folder))


class OnboardingTests(HttpCase):
    def test_steps_follow_the_real_state(self):
        with patch.dict(os.environ, {"PITANGUS_REQUIRE_TOTP": "none"}):
            Users(self.data_dir).create("admin", PASSWORD, role="admin")
            cookie = self.post("/api/auth/login", "login", {"username": "admin", "password": PASSWORD})[2][0].split("; ")[0]
            _, state, _ = self.call("GET", "/api/onboarding", headers={"Cookie": cookie})
            self.assertEqual({key: state[key] for key in ("github", "analyzed", "demo", "watching", "alerts", "admin")},
                             {"github": False, "analyzed": False, "demo": False, "watching": False, "alerts": False, "admin": True})
            demo_scan = _scan("demo · ejemplos vulnerables", [], datetime.now(timezone.utc).isoformat())
            save_repository_scan(self.data_dir, {**demo_scan, "source": {**demo_scan["source"], "id": "local:demo-ejemplos"}})
            _, state, _ = self.call("GET", "/api/onboarding", headers={"Cookie": cookie})
            self.assertEqual((state["demo"], state["analyzed"]), (True, False))  # the demo is not "your first scan"
            # Enable the second factor through the real flow: confirming reissues the session.
            _, body, _ = self.post("/api/auth/totp/setup", "totp-setup", {}, cookie)
            code = totp_code(base64.b32decode(body["secret"]), int(time.time()))
            cookie = self.post("/api/auth/totp/confirm", "totp-confirm", {"code": code}, cookie)[2][0].split("; ")[0]
            save_repository_scan(self.data_dir, _scan("acme/api", [], datetime.now(timezone.utc).isoformat()))
            pr_watch.configure(self.data_dir, "github#1", enabled=True, by="admin")
            _, state, _ = self.call("GET", "/api/onboarding", headers={"Cookie": cookie})
            self.assertEqual((state["analyzed"], state["watching"], state["mfa"]), (True, True, True))

    def steps(self, cookie):
        return self.call("GET", "/api/onboarding", headers={"Cookie": cookie})[1]

    def test_steps_done_anywhere_count(self):
        """Every step comes from the state it stands for, whichever screen (or the CLI) did it."""
        Users(self.data_dir).create("admin", PASSWORD, role="admin")
        cookie = self.post("/api/auth/login", "login", {"username": "admin", "password": PASSWORD})[2][0].split("; ")[0]
        now = datetime.now(timezone.utc).isoformat()
        save_repository_scan(self.data_dir, {**_scan("acme/broken", [], now), "status": "failed"})
        self.assertEqual({key: self.steps(cookie)[key] for key in ("github", "analyzed", "watching", "alerts")},
                         {"github": False, "analyzed": False, "watching": False, "alerts": False})
        # An incomplete scan (an optional engine missing) still analyzed the code; a failed one didn't.
        save_repository_scan(self.data_dir, {**_scan("acme/api", [], now), "status": "incomplete"})
        self.assertTrue(self.steps(cookie)["analyzed"])
        # A GitHub token connected in Integrations, or one in the environment, connects GitHub as the App does.
        code_tokens.connect("github", "ghp_token-de-prueba-123")
        self.assertTrue(self.steps(cookie)["github"])
        code_tokens.disconnect("github")
        self.assertFalse(self.steps(cookie)["github"])
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_token-del-entorno-123"}):
            self.assertTrue(self.steps(cookie)["github"])
        # Pull requests reviewed (by the Action or a webhook) mean they are watched, even with no repository enabled here.
        review = {**_scan("acme/api", [], now), "type": "pr_review", "pull_request": {"number": 3, "head_sha": "1" * 40, "head_ref": "feat"}}
        save_repository_scan(self.data_dir, review)
        self.assertTrue(self.steps(cookie)["watching"])
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]):
            notifications.save("webhook", "SIEM", "https://siem.example.com/in", ["findings"], "high", by="admin")
        self.assertTrue(self.steps(cookie)["alerts"])

    def test_imports_count_and_the_demo_organization_does_not(self):
        Users(self.data_dir).create("admin", PASSWORD, role="admin")
        cookie = self.post("/api/auth/login", "login", {"username": "admin", "password": PASSWORD})[2][0].split("; ")[0]
        now = datetime.now(timezone.utc).isoformat()
        fictional = _scan("demo-org/api", [], now)
        save_repository_scan(self.data_dir, {**fictional, "source": {**fictional["source"], "demo": True}})
        save_repository_scan(self.data_dir, {**fictional, "type": "pr_review", "source": {**fictional["source"], "demo": True},
                                             "pull_request": {"number": 1, "head_sha": "1" * 40, "head_ref": "feat"}})
        self.assertEqual((self.steps(cookie)["analyzed"], self.steps(cookie)["watching"]), (False, False))
        imported = _scan("acme/web", [], now)
        save_repository_scan(self.data_dir, {**imported, "type": "sarif_import"})
        self.assertTrue(self.steps(cookie)["analyzed"])


if __name__ == "__main__":
    unittest.main()
