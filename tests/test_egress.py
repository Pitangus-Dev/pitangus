"""Where web scans leave from: declared by the server, or detected once by an administrator through one HTTPS call."""

import os
import unittest
from unittest.mock import patch
from urllib.error import URLError

from pitangus.modules.scanning import egress
from pitangus.shared import documents, settings
from pitangus.shared.i18n import text

from test_auth import ORIGIN, PASSWORD, HttpCase


class SettingTests(unittest.TestCase):
    def test_the_setting_takes_addresses_and_ranges_and_refuses_anything_else(self):
        with patch.dict(os.environ, {"PITANGUS_EGRESS_IPS": " 203.0.113.10, 2001:db8::/48 ,203.0.113.10/32, 198.51.100.7"}):
            self.assertEqual(settings.addresses("PITANGUS_EGRESS_IPS"), ["203.0.113.10", "2001:db8::/48", "198.51.100.7"])
        base = {"PITANGUS_DATABASE_URL": "postgresql://x"}
        for bad in ("203.0.113.300", "example.com", "203.0.113.10; rm -rf /", ",".join(["10.0.0.1"] * 17)):
            with self.subTest(bad=bad):
                problems = [text(problem, "en") for problem in settings.problems({**base, "PITANGUS_EGRESS_IPS": bad})]
                self.assertTrue(any("PITANGUS_EGRESS_IPS" in problem for problem in problems), problems)
                with patch.dict(os.environ, {"PITANGUS_EGRESS_IPS": bad}):
                    self.assertEqual(settings.addresses("PITANGUS_EGRESS_IPS"), [])
        self.assertEqual(settings.problems({**base, "PITANGUS_EGRESS_IPS": "203.0.113.10"}), [])


class ApiTests(HttpCase):
    def setUp(self):
        super().setUp()
        from pitangus.modules.identity.auth import Users
        self.cookies = {}
        for name, role in (("jefa", "admin"), ("miembro", "member")):
            Users(self.data_dir).create(name, PASSWORD, role=role)
            self.cookies[role] = self.post("/api/auth/login", "login", {"username": name, "password": PASSWORD})[2][0].split("; ")[0]
        environment = patch.dict(os.environ, {"PITANGUS_EGRESS_IPS": ""})
        environment.start()
        self.addCleanup(environment.stop)

    def detect(self, role="admin"):
        return self.call("POST", "/api/domains/egress", {}, {"Origin": ORIGIN, "X-Pitangus-Action": "detect-egress",
                                                              "Cookie": self.cookies[role], "Accept-Language": "en"})

    def shown(self, role="member"):
        return self.call("GET", "/api/domains", headers={"Cookie": self.cookies[role]})[1]["egress"]

    def test_only_an_administrator_detects_and_only_one_public_address_is_kept(self):
        self.assertEqual(self.shown(), {"ips": [], "source": None, "detected_at": None})
        with patch.object(egress, "_fetch", side_effect=AssertionError("called")):
            self.assertEqual(self.detect(role="member")[0], 403)
        for answer in (b"10.0.0.5", b"127.0.0.1", b"<html>", b"203.0.113.10\n203.0.113.11", b"1" * 200):
            with self.subTest(answer=answer), patch.object(egress, "_fetch", return_value=answer):
                status, body, _ = self.detect()
                self.assertEqual(status, 502, body)
            self.state.auth.throttle.succeeded("egress-detect:jefa")
        with patch.object(egress, "_fetch", side_effect=URLError("down")):
            self.assertEqual(self.detect()[0], 502)
        self.assertIsNone(documents.load(self.data_dir, egress.DOCUMENT))
        with patch.object(egress, "_fetch", return_value=b"8.8.8.8\n"):
            status, body, _ = self.detect()
        self.assertEqual((status, body["ips"], body["source"], bool(body["detected_at"])), (200, ["8.8.8.8"], "detected", True))
        self.assertEqual(self.shown()["ips"], ["8.8.8.8"])
        self.assertEqual(documents.load(self.data_dir, egress.DOCUMENT)["by"], "jefa")

    def test_a_declared_setting_wins_and_nothing_is_asked(self):
        documents.save(self.data_dir, egress.DOCUMENT, {"ip": "8.8.8.8", "at": "2026-10-01T00:00:00+00:00", "by": "jefa"})
        with patch.dict(os.environ, {"PITANGUS_EGRESS_IPS": "203.0.113.10,198.51.100.0/24"}), \
                patch.object(egress, "_fetch", side_effect=AssertionError("called")):
            self.assertEqual(self.shown(), {"ips": ["203.0.113.10", "198.51.100.0/24"], "source": "setting", "detected_at": None})
            status, body, _ = self.detect()
        self.assertEqual(status, 409)
        self.assertIn("PITANGUS_EGRESS_IPS", body["error"])

    def test_the_echo_service_is_the_documented_https_url_without_redirects(self):
        self.assertEqual(egress.ECHO_URL, "https://api.ipify.org")

        class Answer:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self, size):
                return b"203.0.113.10"[:size]
        with patch("pitangus.shared.http.OpenerDirector.open", return_value=Answer()) as opened:
            self.assertEqual(egress._fetch(), b"203.0.113.10")
        request = opened.call_args.args[0]
        self.assertEqual((request.full_url, opened.call_args.kwargs["timeout"]), ("https://api.ipify.org", egress.TIMEOUT))
