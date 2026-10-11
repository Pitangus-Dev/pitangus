"""The fictional organization of `pitangus demo --full`: built offline, idempotent, and shaped like real data in the API."""

import os
import unittest
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from pitangus.app import demo_org
from pitangus.modules.identity.auth import Users
from pitangus.modules.runs import periodic
from pitangus.modules.runs.store import find_runs
from pitangus.modules.sources import domains, test_users
from test_auth import PASSWORD, HttpCase

ROOT = Path(__file__).resolve().parents[1]
CODE_SCANS = sum(len(repository.days) for repository in demo_org.REPOSITORIES)


def offline():
    """Anything that would leave the machine fails the test."""
    stack = ExitStack()
    for target in ("socket.getaddrinfo", "socket.create_connection", "subprocess.run", "urllib.request.urlopen"):
        stack.enter_context(patch(target, side_effect=AssertionError(f"{target} called")))
    return stack


class FullDemoTests(HttpCase):
    def setUp(self):
        super().setUp()
        Users(self.data_dir).create("admin", PASSWORD, role="admin")
        self.cookie = self.post("/api/auth/login", "login", {"username": "admin", "password": PASSWORD})[2][0].split("; ")[0]

    def seed(self):
        with offline():
            return demo_org.seed(self.data_dir, fixtures=ROOT / "fixtures", recordings=ROOT / "tests", report=lambda message: None)

    def get(self, path):
        status, body, _ = self.call("GET", path, headers={"Cookie": self.cookie})
        self.assertEqual(status, 200, (path, body))
        return body

    def test_builds_the_organization_offline_once(self):
        first = self.seed()
        self.assertEqual(first["repositories"], {"runs": CODE_SCANS, "pull_requests": 1})
        self.assertEqual((first["image"], first["domains"], first["members"]), (1, {"domains": 2, "web_runs": 2}, 2))
        self.assertEqual(first["triage"], 3)
        rows = find_runs(self.data_dir)
        self.assertEqual(len(rows), CODE_SCANS + 1 + 1 + 2)
        self.assertTrue(all((row.get("source") or {}).get("demo") is True for row in rows))
        # Running it again changes nothing.
        second = self.seed()
        self.assertEqual(second["repositories"], {"runs": 0, "pull_requests": 0})
        self.assertEqual((second["image"], second["domains"], second["members"], second["triage"]), (0, {"domains": 0, "web_runs": 0}, 0, 0))
        self.assertEqual(len(find_runs(self.data_dir)), len(rows))
        self.assertEqual(len(Users(self.data_dir).list()), 3)

    def test_the_panel_sees_it_like_real_data(self):
        self.seed()
        assets = self.get("/api/assets?limit=50")
        names = {row["name"] for row in assets["items"]}
        self.assertTrue({f"lapis-labs/{repository.name}" for repository in demo_org.REPOSITORIES} <= names)
        self.assertIn(demo_org.SHOP, names)
        self.assertGreater(sum(row["open"]["fixed"] for row in assets["items"]), 0)  # later scans fixed some
        self.assertTrue(any(row["open"]["from_pr"] for row in assets["items"]))
        checkout = next(row for row in assets["items"] if row["name"] == "lapis-labs/checkout-api")
        state = self.get(f"/api/assets/state?key={checkout['key']}&status=all")
        self.assertGreater(state["summary"]["sla"]["overdue"], 0)  # a month-old critical secret is past its due date
        self.assertTrue({"open", "fixed"} <= {item["lifecycle"]["status"] for item in state["findings"]})
        self.assertIn("false_positive", {(item.get("triage") or {}).get("status") for item in state["findings"]})
        self.assertTrue({"act", "attend", "track"} <= {item["priority"]["action"] for item in self.get("/api/findings/scope?status=open")["findings"]})

        listed = {item["host"]: item for item in self.get("/api/domains")["items"]}
        shop, pending = listed[demo_org.SHOP], listed[demo_org.PENDING]
        self.assertEqual((shop["verified"], pending["verified"]), (True, False))
        self.assertEqual({key: shop["schedule"][key] for key in ("frequency", "weekdays", "time", "timezone")},
                         {"frequency": "weekly", "weekdays": [1], "time": "09:00", "timezone": "America/Bogota"})
        self.assertEqual(len(shop["schedule"]["test_users"]), 1)
        scope = self.get(f"/api/domains/scope?domain_id={shop['id']}")
        self.assertEqual({item["host"]: item["state"] for item in scope["hosts"]},
                         {demo_org.SHOP_API: "in_scope", f"static.{demo_org.SHOP}": "in_scope", f"staging.{demo_org.SHOP}": "out_of_scope"})
        (user,) = test_users.list_users(self.data_dir, shop["id"])
        self.assertNotIn("password", user)

        web = find_runs(self.data_dir, types=["dast_scan"])
        latest = self.get(f"/api/runs/{web[0]['id']}")
        self.assertEqual((latest["status"], len(web)), ("completed", 2))
        self.assertTrue(latest["owasp_coverage"] and latest["summary"]["technologies"])
        self.assertTrue(all(demo_org.SHOP in item["path"] for item in latest["findings"]))
        self.assertTrue(any(item.get("guidance") for item in latest["findings"]))
        self.assertFalse(any("pitangus.dev" in str(item) for item in latest["findings"]))

        (review,) = find_runs(self.data_dir, types=["pr_review"])
        detail = self.get(f"/api/runs/{review['id']}")
        self.assertEqual(detail["pull_request"]["number"], 57)
        self.assertTrue(detail["findings"] and all(item["path"] == "component.jsx" for item in detail["findings"]))
        (image,) = find_runs(self.data_dir, types=["image_scan"])
        self.assertEqual(image["status"], "incomplete")  # no Grype output was recorded, and it says so
        self.assertTrue(self.get(f"/api/runs/{image['id']}")["findings"])

        members = {user["username"]: user for user in self.get("/api/users")["users"]}
        self.assertTrue(all("(demo)" in members[name]["display_name"] and not members[name]["has_password"]
                            for name, _ in demo_org.MEMBERS))
        self.assertFalse(self.get("/api/onboarding")["analyzed"])  # demo data is not your first scan
        with patch("pitangus.modules.reporting.dashboard.load_feeds", return_value={}), \
                patch("pitangus.modules.reporting.dashboard.load_recent_cves", return_value={"items": []}):
            kpis = self.get("/api/dashboard")["kpis"]
        self.assertGreater(kpis["fixed_in_window"], 0)
        self.assertIsNotNone(kpis["mttr_days"])
        self.assertEqual(kpis["triage"]["false_positive"], 1)


class DemoDomainTests(HttpCase):
    def test_members_wait_for_an_administrator(self):
        self.assertIsNone(demo_org.seed_members(self.data_dir))  # the first account is whoever installs Pitangus
        self.assertEqual(Users(self.data_dir).list(), [])

    def test_a_demo_domain_is_never_asked_for_its_proof_nor_scanned(self):
        with offline():
            demo_org.seed_domains(self.data_dir, demo_org.Recordings(ROOT / "tests"))
            shop = domains.find_domain(self.data_dir, demo_org.SHOP)
            self.assertEqual(domains.recheck(self.data_dir), {"kept": 0, "withdrawn": 0, "unanswered": 0})
            with self.assertRaises(domains.DomainError):
                domains.confirm_control(self.data_dir, shop["id"])
            due = datetime.now(timezone.utc).replace(year=datetime.now(timezone.utc).year + 1)
            with patch.object(self.state.jobs, "enqueue_dast_scan", side_effect=AssertionError("queued")), \
                    patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": "1"}):
                self.assertEqual(periodic._domain_scans(self.data_dir, self.state.jobs, now=due), {"queued": None})
        moved = domains.get_domain(self.data_dir, shop["id"])["schedule"]
        self.assertGreater(moved["next_run_at"], due.isoformat())
        self.assertEqual(moved["note"]["$t"], "sources.domains.demo")
        # Only the demo's own registrations under reserved names count as demo data.
        self.assertFalse(domains.is_demo({**shop, "registered_by": "admin"}))
        self.assertFalse(domains.is_demo({**shop, "host": "shop.example.co"}))
        with self.assertRaises(domains.DomainError):
            domains.vouch_demo(self.data_dir, domains.register_domain(self.data_dir, "https://real.example.io/", by="admin")["id"],
                               at=datetime.now(timezone.utc))


class PresenceTests(unittest.TestCase):
    def test_some_findings_are_fixed_and_some_appear_later(self):
        prints = [{"fingerprint": f"{value:08x}" + "0" * 56} for value in range(0, 0xFFFFFFFF, 0x1000000)]
        seen = [[demo_org.present(item, index, 5) for index in range(5)] for item in prints]
        self.assertTrue(any(row[0] and not row[-1] for row in seen))   # fixed along the way
        self.assertTrue(any(not row[0] and row[-1] for row in seen))   # appears later
        self.assertTrue(all(row[-1] for row in seen if row[0] and row[-1]))
        self.assertTrue(all(demo_org.present(item, 0, 1) for item in prints))
        self.assertEqual(demo_org.run_id("x", 1), demo_org.run_id("x", 1))


if __name__ == "__main__":
    unittest.main()
