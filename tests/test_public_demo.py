"""The public demo (PITANGUS_PUBLIC_DEMO): the server refuses every change and reaches nothing outside, whatever the
session, role or route; only the demo account signs in, and it can't be locked out or flooded."""

import os
import re
import socket
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.routing import APIRoute
from sqlalchemy import select

from pitangus.app import demo_org, public_demo
from pitangus.app.api import ROUTERS
from pitangus.cli.main import main as cli
from pitangus.modules.identity import auth
from pitangus.modules.identity.auth import Users
from pitangus.shared import db, settings
from pitangus.shared.i18n import msg, text
from test_auth import ORIGIN, PASSWORD, HttpCase
from test_demo_org import ROOT, offline

DEMO_PASSWORD = "lapis-labs-visita-publica"
DEMO_ENV = {"PITANGUS_PUBLIC_DEMO": "1", "PITANGUS_PUBLIC_DEMO_USER": "demo", "PITANGUS_PUBLIC_DEMO_PASSWORD": DEMO_PASSWORD,
            "PITANGUS_EUVD": "0", "PITANGUS_CVE_SYNC": "0", "PITANGUS_EMBEDDED_WORKER": "0"}
# Tables a read may touch without changing anything a person sees: sign-in bookkeeping and derived caches.
BOOKKEEPING = {"sessions", "auth_throttle", "auth_challenges"}


def routes() -> list[tuple[str, str, APIRoute]]:
    found = []
    for module in ROUTERS:
        for route in module.router.routes:
            if isinstance(route, APIRoute):
                found += [(method, route.path, route) for method in sorted(route.methods)]
    return found


def concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "x", path)


class DemoCase(HttpCase):
    def setUp(self):
        environment = patch.dict(os.environ, DEMO_ENV)
        environment.start()
        self.addCleanup(environment.stop)
        self.addCleanup(public_demo.unseal_outbound)
        super().setUp()
        Users(self.data_dir).create("operator", PASSWORD, role="admin")
        Users(self.data_dir).create("demo", DEMO_PASSWORD, display_name="Demo")
        status, _, cookies = self.post("/api/auth/login", "login", {"username": "demo", "password": DEMO_PASSWORD})
        self.assertEqual(status, 200)
        self.cookie = cookies[0].split("; ")[0]

    def write(self, method, path, cookie=None, action="x", language="es"):
        return self.call(method, path, {}, {"Origin": ORIGIN, "X-Pitangus-Action": action, "Accept-Language": language,
                                            **({"Cookie": cookie} if cookie else {})})


class ReadOnlyTests(DemoCase):
    def test_every_route_that_changes_or_acts_is_refused_except_the_allowlist(self):
        every = routes()
        self.assertGreater(len(every), 100)
        known = {(method, path) for method, path, _ in every}
        self.assertLessEqual(public_demo.ALLOWED, known, "an allowed route that no longer exists")
        self.assertLessEqual(public_demo.REFUSED_READS, {path for method, path in known if method == "GET"})
        refused = 0
        for method, path, route in every:
            policy = next((getattr(item.call, "policy", None) for item in route.dependant.dependencies
                           if getattr(item.call, "policy", None)), None)
            action = policy.action if policy and policy.action else "x"
            status, body, _ = self.write(method, concrete(path), self.cookie, action)
            if (method, path) in public_demo.ALLOWED or (method == "GET" and path not in public_demo.REFUSED_READS):
                self.assertFalse(status == 403 and (body or {}).get("code") == "public_demo", (method, path))
                continue
            self.assertEqual((status, body.get("code")), (403, "public_demo"), (method, path))
            refused += 1
        self.assertGreater(refused, 70)

    def test_refused_before_the_session_the_csrf_check_or_the_body(self):
        for headers in ({}, {"Cookie": self.cookie}, {"Origin": "https://evil.example", "X-Pitangus-Action": "x"}):
            response = self.call("POST", "/api/repositories/scans", None, {**headers, "Content-Length": "999999999"})
            self.assertEqual((response[0], response[1]["code"]), (403, "public_demo"))
        for path in ("/api/cron", "/api/metrics", "/github/app-created?code=a&state=b", "/oauth/callback?installation_id=1"):
            self.assertEqual(self.call("GET", path)[0], 403, path)
        # Methods no route has are refused the same way, and unknown paths too: nothing reaches a handler.
        for method in ("PUT", "PATCH", "DELETE"):
            self.assertEqual(self.write(method, "/api/runs", self.cookie)[0], 403)
        self.assertEqual(self.write("POST", "/api/auth/login/", self.cookie, "login")[0], 403)

    def test_the_refusal_speaks_the_readers_language(self):
        _, spanish, _ = self.write("POST", "/api/auth/password", self.cookie, "change-password")
        _, english, _ = self.write("POST", "/api/auth/password", self.cookie, "change-password", language="en")
        self.assertIn("demo pública de solo lectura", spanish["error"])
        self.assertIn("public read-only demo", english["error"])
        self.assertEqual(text(msg("api.public_demo_read_only"), "en"), english["error"])

    def test_the_shared_account_cant_be_taken_over(self):
        for path, action, body in (("/api/auth/password", "change-password", {"current": DEMO_PASSWORD, "new": "otra-clave-larga-1"}),
                                   ("/api/auth/totp/setup", "totp-setup", {}), ("/api/auth/setup", "setup-admin", {}),
                                   ("/api/users", "manage-users", {"action": "invite", "username": "x", "role": "admin", "display_name": "x"})):
            status, answer, _ = self.call("POST", path, body, {"Origin": ORIGIN, "X-Pitangus-Action": action, "Cookie": self.cookie})
            self.assertEqual((status, answer["code"]), (403, "public_demo"), path)
        self.assertEqual(self.post("/api/auth/login", "login", {"username": "demo", "password": DEMO_PASSWORD})[0], 200)

    def test_sign_out_and_evidence_pdfs_are_allowed(self):
        status, _, _ = self.write("POST", "/api/reports/audit", self.cookie, "audit-report")
        self.assertEqual(status, 400)  # reached the route: an empty request is its own 400, not the demo's 403
        self.assertEqual(self.post("/api/auth/logout", "logout", {}, self.cookie)[0], 200)
        self.assertEqual(self.call("GET", "/api/runs", headers={"Cookie": self.cookie})[0], 401)

    def test_reads_change_nothing_and_reach_nothing_outside(self):
        """Every GET over the made-up organization, as the demo account: no error, no connection attempted outside the
        process, and every table but the sign-in bookkeeping exactly as before."""
        with offline():
            demo_org.seed(self.data_dir, fixtures=ROOT / "fixtures", recordings=ROOT / "tests", report=lambda message: None)
        before = self._tables()
        attempts: list = []
        lookup, connect = socket.getaddrinfo, socket.socket.connect

        def looking_up(host, *args, **kwargs):
            attempts.append(host)
            return lookup(host, *args, **kwargs)

        def connecting(sock, address):
            attempts.append(address)
            return connect(sock, address)
        self.assertTrue(public_demo.sealed())
        with patch("socket.getaddrinfo", looking_up), patch.object(socket.socket, "connect", connecting):
            for method, path, _ in routes():
                if method != "GET" or path in public_demo.REFUSED_READS:
                    continue
                status, body, _ = self.call("GET", concrete(path), headers={"Cookie": self.cookie})
                self.assertLess(status, 500, (path, body))
        # The panel's KEV, EPSS and NVD feeds are tried (fixed addresses, cached once downloaded): the seal stops them
        # at the name lookup, before any connection.
        self.assertTrue(all(isinstance(item, str) and not item.startswith("127.") for item in attempts), attempts)
        after = self._tables()
        changed = sorted(name for name in before if before[name] != after[name] and name not in BOOKKEEPING)
        self.assertEqual(changed, [])

    def _tables(self) -> dict:
        snapshot = {}
        with db.transaction(self.data_dir) as connection:
            for name, table in db.metadata.tables.items():
                snapshot[name] = sorted(repr(tuple(row)) for row in connection.execute(select(table)))
        return snapshot


class IdentityTests(DemoCase):
    def test_only_the_demo_account_signs_in(self):
        status, body, _ = self.post("/api/auth/login", "login", {"username": "operator", "password": PASSWORD})
        self.assertEqual(status, 401)
        self.assertEqual(body["error"], text(msg("auth.errors.bad_credentials"), "es"))

    def test_any_other_session_counts_for_nothing(self):
        operator = Users(self.data_dir).get("operator")
        cookie = f"{auth.COOKIE_NAME}={self.state.auth.sessions.issue(operator, mfa=True)}"
        self.assertEqual(self.call("GET", "/api/runs", headers={"Cookie": cookie})[0], 401)
        self.assertEqual(self.call("GET", "/api/users", headers={"Cookie": cookie})[0], 401)
        self.assertEqual(self.call("GET", "/api/runs", headers={"Cookie": self.cookie})[0], 200)

    def test_an_administrator_named_like_the_demo_account_is_not_it(self):
        self.assertFalse(public_demo.is_demo_account({"username": "demo", "role": "admin"}))
        self.assertTrue(public_demo.is_demo_account({"username": "demo", "role": "member"}))

    def test_failures_lock_out_the_address_never_the_shared_account(self):
        for _ in range(auth.LOCK_AFTER + 2):
            try:
                self.state.auth.login("demo", "not-the-password", "203.0.113.7", public_account="demo")
            except auth.AuthError:
                pass
        with self.assertRaises(auth.Locked):
            self.state.auth.login("demo", DEMO_PASSWORD, "203.0.113.7", public_account="demo")
        self.assertIn("session", self.state.auth.login("demo", DEMO_PASSWORD, "198.51.100.9", public_account="demo"))

    def test_the_shared_account_keeps_a_bounded_number_of_sessions(self):
        with patch.object(auth, "PUBLIC_SESSIONS", 3):
            cookies = [self.state.auth.login("demo", DEMO_PASSWORD, "198.51.100.9", public_account="demo")["session"] for _ in range(5)]
        alive = [cookie for cookie in cookies if self.state.auth.sessions.resolve(cookie)]
        self.assertEqual(alive, cookies[-3:])

    def test_the_sign_in_page_learns_the_published_credentials(self):
        _, anonymous, _ = self.call("GET", "/api/auth/session")
        self.assertEqual(anonymous["public_demo"], {"username": "demo", "password": DEMO_PASSWORD})
        _, signed_in, _ = self.call("GET", "/api/auth/session", headers={"Cookie": self.cookie})
        self.assertEqual((signed_in["authenticated"], signed_in["public_demo"]["username"]), (True, "demo"))


class BackgroundTests(DemoCase):
    def test_no_worker_no_periodic_tasks_and_no_network(self):
        from pitangus.app.api.server import build_state
        with patch.dict(os.environ, {"PITANGUS_EMBEDDED_WORKER": "1"}), patch("pitangus.app.worker.start_periodic") as periodic:
            state = build_state(self.data_dir, watch_pull_requests=True)
        self.assertIsNone(state.jobs._thread)
        periodic.assert_not_called()
        self.assertTrue(public_demo.sealed())
        with self.assertRaises(public_demo.OutboundRefused), socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("127.0.0.1", 9))
        with self.assertRaises(OSError):
            socket.create_connection(("192.0.2.1", 443), timeout=1)

    def test_worker_and_periodic_refuse_to_run(self):
        for command in (["worker"], ["periodic"]):
            with patch("pitangus.app.worker.run") as run, patch("sys.stderr") as stderr:
                self.assertEqual(cli(["--data-dir", str(self.data_dir), *command]), 1)
            run.assert_not_called()
            self.assertIn("PITANGUS_PUBLIC_DEMO", "".join(str(call.args[0]) for call in stderr.write.call_args_list))


class SettingsTests(unittest.TestCase):
    def problems(self, **environment):
        base = {"PITANGUS_DATABASE_URL": "postgresql+psycopg://u:p@db/t", **DEMO_ENV}
        return [text(problem, "en") for problem in settings.problems({**base, **environment})]

    def test_a_demo_environment_has_no_problems(self):
        self.assertEqual(self.problems(), [])

    def test_credentials_and_calling_out_features_stop_it(self):
        found = self.problems(GITHUB_TOKEN="ghp_x", OPENAI_API_KEY="sk-x", PITANGUS_EUVD="", PITANGUS_EMBEDDED_WORKER="1")
        self.assertEqual(len(found), 4)
        for name in ("GITHUB_TOKEN", "OPENAI_API_KEY", "PITANGUS_EUVD", "PITANGUS_EMBEDDED_WORKER"):
            self.assertTrue(any(name in problem for problem in found), name)
        self.assertNotIn("ghp_x", " ".join(found))

    def test_outside_the_demo_nothing_changes(self):
        self.assertEqual(self.problems(PITANGUS_PUBLIC_DEMO="0", GITHUB_TOKEN="ghp_x", PITANGUS_EUVD="1"), [])
        with patch.dict(os.environ, {"PITANGUS_PUBLIC_DEMO": "0"}):
            self.assertFalse(public_demo.refuses("POST", "/api/repositories/scans"))
            self.assertIsNone(public_demo.credentials())


class OutsideTheDemoTests(HttpCase):
    def test_the_session_says_nothing_about_a_demo(self):
        _, body, _ = self.call("GET", "/api/auth/session")
        self.assertNotIn("public_demo", body)


class RecordedOnlyTests(unittest.TestCase):
    def test_builds_without_engines(self):
        from pitangus.app import demo
        with patch("pitangus.app.demo._analyze_examples") as analyze:
            result = demo.seed(Path("/nonexistent"), fixtures=Path("/nonexistent"), models=None, analyze=False, report=lambda message: None)
        analyze.assert_not_called()
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()
