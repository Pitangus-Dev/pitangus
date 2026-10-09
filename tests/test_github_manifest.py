import json
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from pitangus.modules.identity.auth import Users
from pitangus.modules.integrations import github_manifest
from pitangus.modules.integrations.github import GitHubAppError, config as github_config
from pitangus.shared import documents
from pitangus.shared.i18n import msg

from tests.test_auth import ORIGIN, PASSWORD, HttpCase
from tests.test_github_routes import VERIFIED

CREATED = {"id": 4242, "slug": "appsec-de-acme", "pem": VERIFIED["pem"], "client_secret": "nope", "webhook_secret": None}


class GitHubManifestTests(HttpCase):
    def setUp(self):
        super().setUp()
        Users(self.data_dir).create("admin", PASSWORD, role="admin")
        Users(self.data_dir).create("miembro", PASSWORD)
        self.admin, self.member = self.cookie("admin"), self.cookie("miembro")

    def cookie(self, username):
        _, _, cookies = self.post("/api/auth/login", "login", {"username": username, "password": PASSWORD})
        return cookies[0].split("; ")[0]

    def start(self, body=None, cookie=None):
        return self.post("/api/integrations/github/manifest", "create-github-app", body or {"name": "Pitangus Acme", "organization": "acme"}, cookie or self.admin)

    def test_only_admins_start_it_and_the_manifest_asks_for_the_minimum(self):
        self.assertEqual(self.start(cookie=self.member)[0], 403)
        status, answer, _ = self.start()
        self.assertEqual(status, 200)
        url = urlsplit(answer["url"])
        self.assertEqual((url.netloc, url.path), ("github.com", "/organizations/acme/settings/apps/new"))
        state = parse_qs(url.query)["state"][0]
        manifest = json.loads(answer["manifest"])
        self.assertEqual(manifest["redirect_url"], ORIGIN + github_manifest.RETURN_PATH)
        self.assertEqual(manifest["default_permissions"], {"contents": "read", "metadata": "read", "pull_requests": "write", "statuses": "write"})
        self.assertEqual((manifest["default_events"], manifest["public"], manifest["request_oauth_on_install"]), ([], False, False))
        self.assertNotIn("hook_attributes", manifest)
        # Only the state's hash is stored.
        stored = documents.load(self.data_dir, github_manifest.DOCUMENT, {})
        self.assertNotIn(state, json.dumps(stored))
        self.assertEqual(list(stored.values())[0]["user"], "admin")
        self.assertEqual(self.start({"name": "x" * 35})[0], 400)
        self.assertEqual(self.start({"name": "Pitangus", "organization": "-bad-"})[0], 400)
        self.assertEqual(urlsplit(self.start({"name": "Pitangus"})[1]["url"]).path, "/settings/apps/new")

    def test_the_return_stores_the_app_once_and_never_shows_its_key(self):
        state = parse_qs(urlsplit(self.start()[1]["url"]).query)["state"][0]
        with patch("pitangus.modules.integrations.github_manifest._convert", return_value=dict(CREATED)) as convert, \
                patch("pitangus.modules.integrations.github_manifest.verify_app", return_value=dict(VERIFIED)) as verify:
            status, body, _ = self.call("GET", f"{github_manifest.RETURN_PATH}?code=abc123&state={state}")
            self.assertEqual(status, 303)
            convert.assert_called_once_with("abc123")
            verify.assert_called_once_with("4242", VERIFIED["pem"])
            self.assertEqual((github_config()["app_id"], github_config()["slug"], github_config()["source"]), ("4242", "appsec-de-acme", "vault"))
            # The same return can't be replayed.
            status, body, _ = self.call("GET", f"{github_manifest.RETURN_PATH}?code=abc123&state={state}")
            self.assertEqual(status, 200)
            self.assertIn(b"caduc", body)
            self.assertEqual(convert.call_count, 1)

    def test_a_return_without_a_valid_state_never_calls_github(self):
        with patch("pitangus.modules.integrations.github_manifest._convert", side_effect=AssertionError("called GitHub")):
            for query in ("", "?code=abc", "?code=abc&state=" + "x" * 43, "?code=a%2Fb&state=" + "x" * 43):
                status, body, _ = self.call("GET", github_manifest.RETURN_PATH + query)
                self.assertEqual(status, 200)
                self.assertIsNone(github_config()["source"])
            statuses = [self.call("GET", f"{github_manifest.RETURN_PATH}?code=abc&state={'y' * 43}")[1] for _ in range(6)]
            self.assertIn(b"Demasiados intentos", statuses[-1])

    def test_an_expired_state_is_refused_and_github_errors_are_explained(self):
        state = parse_qs(urlsplit(self.start()[1]["url"]).query)["state"][0]
        with documents.edit(self.data_dir, github_manifest.DOCUMENT, {}) as pending:
            for entry in pending.values():
                entry["expires"] = 0
        with patch("pitangus.modules.integrations.github_manifest._convert", side_effect=AssertionError("called GitHub")):
            self.assertIn(b"caduc", self.call("GET", f"{github_manifest.RETURN_PATH}?code=abc&state={state}")[1])
        state = parse_qs(urlsplit(self.start()[1]["url"]).query)["state"][0]
        with patch("pitangus.modules.integrations.github_manifest._convert", side_effect=GitHubAppError(msg("integrations.github.manifest.code_rejected"))):
            status, body, _ = self.call("GET", f"{github_manifest.RETURN_PATH}?code=abc&state={state}")
        self.assertEqual(status, 200)
        self.assertIsNone(github_config()["source"])

    def test_pending_states_are_bounded(self):
        for _ in range(github_manifest.MAX_PENDING + 5):
            github_manifest.start(self.data_dir, base_url=ORIGIN, user="admin", name="Pitangus")
        self.assertEqual(len(documents.load(self.data_dir, github_manifest.DOCUMENT, {})), github_manifest.MAX_PENDING)
