"""Registered domains: a TXT proof makes one an asset for a while, administrators manage them, members only look."""

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from pitangus.modules.runs.imports import import_sarif
from pitangus.modules.runs.store import find_runs
from pitangus.modules.sources import domains
from pitangus.modules.sources.domains import DomainError
from pitangus.shared import documents

from test_auth import ORIGIN, PASSWORD, HttpCase
from test_sarif_import import ZAP

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
HOST = "app.example.com"


def seen(record):
    """DNS answering with the domain's TXT record."""
    return patch.object(domains, "lookup_txt", return_value=["v=spf1 -all", record["txt_value"]])


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)

    def test_verification_counts_for_ninety_days_and_the_recheck_extends_or_withdraws_it(self):
        record = domains.register_domain(self.data_dir, f"https://{HOST}/", "api", "Agenda API", by="jefa")
        self.assertEqual((record["verified"], record["expired"], record["key"], record["registered_by"], record["txt_name"]),
                         (False, False, f"domain:{HOST}", "jefa", f"_pitangus.{HOST}"))
        self.assertTrue(record["txt_value"].startswith("pitangus-verify="))
        with patch.object(domains, "lookup_txt", return_value=["something-else"]):
            with self.assertRaises(DomainError):
                domains.verify_domain(self.data_dir, record["id"], now=NOW)
        with patch.object(domains, "lookup_txt", return_value=None):
            with self.assertRaises(DomainError):
                domains.verify_domain(self.data_dir, record["id"], now=NOW)
        self.assertFalse(domains.get_domain(self.data_dir, record["id"])["verified"])
        with seen(record):
            verified = domains.verify_domain(self.data_dir, record["id"], now=NOW)
        self.assertEqual((verified["verified"], verified["verified_at"], verified["verified_until"]),
                         (True, NOW.isoformat(), (NOW + timedelta(days=90)).isoformat()))
        self.assertEqual(domains.find_domain(self.data_dir, f"DOMAIN:{HOST}")["id"], record["id"])
        self.assertEqual(domains.find_domain(self.data_dir, record["id"])["host"], HOST)
        self.assertIsNone(domains.find_domain(self.data_dir, "other.example.com"))
        # The daily re-check: the record still there extends the proof; DNS not answering changes nothing.
        with seen(record):
            self.assertEqual(domains.recheck(self.data_dir, now=NOW + timedelta(days=30)), {"kept": 1, "withdrawn": 0, "unanswered": 0})
        self.assertEqual(domains.get_domain(self.data_dir, record["id"])["verified_until"], (NOW + timedelta(days=120)).isoformat())
        with patch.object(domains, "lookup_txt", return_value=None):
            self.assertEqual(domains.recheck(self.data_dir, now=NOW + timedelta(days=31))["unanswered"], 1)
        self.assertTrue(domains.get_domain(self.data_dir, record["id"])["verified"])
        # The record was removed: whoever controls the zone no longer vouches.
        with patch.object(domains, "lookup_txt", return_value=[]):
            self.assertEqual(domains.recheck(self.data_dir, now=NOW + timedelta(days=32))["withdrawn"], 1)
        after = domains.get_domain(self.data_dir, record["id"])
        self.assertEqual((after["verified"], after["verified_at"], after["expired"]), (False, None, False))
        # Without any re-check, the proof simply runs out.
        now = datetime.now(timezone.utc)
        domains._mark(self.data_dir, record["id"], verified_at=now - timedelta(days=91), verified_until=now - timedelta(days=1))
        stale = domains.get_domain(self.data_dir, record["id"])
        self.assertEqual((stale["verified"], stale["expired"]), (False, True))

    def test_limits_and_duplicates(self):
        domains.register_domain(self.data_dir, f"https://{HOST}/")
        with self.assertRaises(DomainError):
            domains.register_domain(self.data_dir, f"https://{HOST}/other")
        with patch.object(domains, "LIMIT", 1), self.assertRaises(DomainError):
            domains.register_domain(self.data_dir, "https://two.example.com/")
        with self.assertRaises(DomainError):
            domains.get_domain(self.data_dir, "0" * 24)
        with self.assertRaises(DomainError):
            domains.get_domain(self.data_dir, "../x")
        self.assertIsNone(domains.lookup_txt("not a name"))  # never reaches dig

    def test_the_lookup_asks_dig_for_the_txt_name_only(self):
        record = domains.register_domain(self.data_dir, f"https://{HOST}/")
        with patch("pitangus.modules.sources.domains.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = f'"{record["txt_value"]}"\n"other"\n'
            with patch.object(domains, "_nameservers", return_value=[]):
                self.assertEqual(domains.lookup_txt(record["txt_name"]), [record["txt_value"], "other"])
        command = run.call_args.args[0]
        self.assertEqual((command[0], command[-2:], run.call_args.kwargs["env"]), ("dig", ["TXT", f"_pitangus.{HOST}"], {"PATH": "/usr/bin:/bin"}))

    def test_the_lookup_asks_the_zones_own_nameservers_first(self):
        """A resolver that cached "no such name" before the record existed must not hide it (dogfooding, 9-oct-2026)."""
        asked = []

        def dig(command, **kwargs):
            asked.append(command[4:])
            answer = {("NS", f"pitangus.{HOST}"): "", ("NS", HOST): "ns1.dns.example.\nns2.dns.example.\n; bad answer\n",
                      ("@ns1.dns.example.", "TXT", f"_pitangus.pitangus.{HOST}"): '"pitangus-verify=x"\n'}.get(tuple(command[4:]))
            return type("Result", (), {"returncode": 0 if answer is not None else 9, "stdout": answer or ""})()
        with patch("pitangus.modules.sources.domains.subprocess.run", side_effect=dig):
            self.assertEqual(domains.lookup_txt(f"_pitangus.pitangus.{HOST}"), ["pitangus-verify=x"])
        self.assertEqual(asked, [["NS", f"pitangus.{HOST}"], ["NS", HOST], ["@ns1.dns.example.", "TXT", f"_pitangus.pitangus.{HOST}"]])
        # Nameservers unreachable: the local resolver still answers.
        with patch.object(domains, "_nameservers", return_value=["ns1.dns.example."]), \
                patch.object(domains, "_dig", side_effect=lambda *args: None if args[0].startswith("@") else ['"v"']):
            self.assertEqual(domains.lookup_txt(f"_pitangus.{HOST}"), ["v"])

    def test_the_domains_document_of_earlier_versions_becomes_rows(self):
        documents.save(self.data_dir, "domains", [
            {"id": "a" * 24, "host": "old.example.com", "url": "https://old.example.com/", "kind": "web", "context": "", "txt_name": "_pitangus.old.example.com",
             "txt_value": "pitangus-verify=old", "verified": True, "registered_at": "2026-09-01T00:00:00+00:00", "verified_at": "2026-09-02T00:00:00+00:00"},
            {"id": "b" * 24, "host": "new.example.com", "url": "https://new.example.com/", "kind": "surface", "context": "x", "txt_name": "_pitangus.new.example.com",
             "txt_value": "pitangus-verify=new", "verified": False, "registered_at": "2026-09-03T00:00:00+00:00", "verified_at": None},
            {"garbage": True}, "nope"])
        self.assertEqual(domains.import_document(self.data_dir), 2)
        self.assertIsNone(documents.load(self.data_dir, "domains"))
        old, new = domains.list_domains(self.data_dir)
        self.assertEqual((old["host"], old["verified_at"], old["verified_until"], old["txt_value"]),
                         ("old.example.com", "2026-09-02T00:00:00+00:00", "2026-12-01T00:00:00+00:00", "pitangus-verify=old"))
        self.assertEqual((new["host"], new["kind"], new["verified"], new["verified_at"]), ("new.example.com", "surface", False, None))
        self.assertEqual(domains.import_document(self.data_dir), 0)  # once


class ApiTests(HttpCase):
    def setUp(self):
        super().setUp()
        from pitangus.modules.identity.auth import Users
        self.cookies = {}
        for name, role in (("jefa", "admin"), ("miembro", "member")):
            Users(self.data_dir).create(name, PASSWORD, role=role)
            self.cookies[role] = self.post("/api/auth/login", "login", {"username": name, "password": PASSWORD})[2][0].split("; ")[0]

    def send(self, path, action, body, role="admin"):
        return self.call("POST", path, body, {"Origin": ORIGIN, "X-Pitangus-Action": action, "Cookie": self.cookies[role], "Accept-Language": "en"})

    def test_administrators_manage_domains_and_members_only_see_them_without_the_txt(self):
        self.assertEqual(self.call("GET", "/api/domains")[0], 401)
        for path, action in (("/api/domains", "register-domain"), ("/api/domains/verify", "verify-domain"),
                             ("/api/domains/check", "check-domain"), ("/api/domains/remove", "remove-domain")):
            self.assertEqual(self.send(path, action, {"url": f"https://{HOST}/"}, role="member")[0], 403, path)
        status, added, _ = self.send("/api/domains", "register-domain", {"url": f"https://{HOST}/", "kind": "api", "context": "Agenda"})
        self.assertEqual((status, added["host"], added["kind"], added["verified"], added["key"], added["runs"], added["open"]),
                         (200, HOST, "api", False, f"domain:{HOST}", 0, 0))
        self.assertTrue(added["txt_value"].startswith("pitangus-verify="))
        for bad in ({"url": "http://x.example.com/"}, {"url": f"https://{HOST}/", "kind": "pwn"}, {"url": f"https://{HOST}/", "extra": 1}, {"url": 5}):
            self.assertEqual(self.send("/api/domains", "register-domain", bad)[0], 400, bad)
        self.assertEqual(self.send("/api/domains", "register-domain", {"url": f"https://{HOST}/"})[0], 400)  # twice
        status, page, _ = self.call("GET", "/api/domains", headers={"Cookie": self.cookies["member"]})
        self.assertEqual((status, page["total"], page["items"][0]["host"], "txt_value" in page["items"][0], "txt_name" in page["items"][0]),
                         (200, 1, HOST, False, False))
        self.assertIn("txt_value", self.call("GET", "/api/domains", headers={"Cookie": self.cookies["admin"]})[1]["items"][0])

        # Verifying: one DNS lookup; failures count against the lock-out, a success clears it.
        self.assertEqual(self.send("/api/domains/verify", "verify-domain", {"domain_id": "f" * 24})[0], 404)
        self.assertEqual(self.send("/api/domains/verify", "verify-domain", {"domain_id": "../x"})[0], 400)
        with patch.object(domains, "lookup_txt", return_value=[]):
            for _ in range(5):
                status, body, _ = self.send("/api/domains/verify", "verify-domain", {"domain_id": added["id"]})
                self.assertEqual(status, 400)
                self.assertIn("TXT", body["error"])
            status, body, _ = self.send("/api/domains/verify", "verify-domain", {"domain_id": added["id"]})
            self.assertEqual((status, body["retry_in"] > 0), (429, True))
        self.state.auth.throttle.succeeded(f"domain-verify:{added['id']}")
        with seen(added):
            status, verified, _ = self.send("/api/domains/verify", "verify-domain", {"domain_id": added["id"]})
        self.assertEqual((status, verified["verified"], bool(verified["verified_until"])), (200, True, True))

        # The probe before adding: public addresses only, one HEAD, and refused input never resolves anything.
        self.assertEqual(self.send("/api/domains/check", "check-domain", {"url": "https://localhost/"})[0], 400)
        private = [(2, 1, 6, "", ("10.0.0.5", 443))]
        with patch("pitangus.modules.sources.domains.socket.getaddrinfo", return_value=private), \
                patch("pitangus.modules.sources.domains.socket.create_connection", side_effect=AssertionError("connected")):
            status, probe, _ = self.send("/api/domains/check", "check-domain", {"url": "https://intranet.example.com/"})
        self.assertEqual((status, probe["reachable"], probe["status"]), (200, False, "private_address"))

    def test_removing_a_domain_takes_what_was_imported_against_it(self):
        _, added, _ = self.send("/api/domains", "register-domain", {"url": f"https://{HOST}/"})
        now = datetime.now(timezone.utc)
        domains._mark(self.data_dir, added["id"], verified_at=now, verified_until=now + timedelta(days=1))
        import_sarif(self.data_dir, json.loads(ZAP.read_text()), asset=f"domain:{HOST}", requested_by="ci")
        _, page, _ = self.call("GET", "/api/domains", headers={"Cookie": self.cookies["admin"]})
        self.assertEqual((page["items"][0]["runs"], page["items"][0]["open"]), (1, 4))
        _, assets, _ = self.call("GET", "/api/assets", headers={"Cookie": self.cookies["admin"]})
        self.assertEqual([(row["key"], row["name"], row["open"]["total"]) for row in assets["items"]], [(f"domain:{HOST}", HOST, 4)])
        status, removed, _ = self.send("/api/domains/remove", "remove-domain", {"domain_id": added["id"]})
        self.assertEqual((status, removed), (200, {"id": added["id"], "host": HOST, "runs_deleted": 1}))
        self.assertEqual(find_runs(self.data_dir, assets=[f"domain:{HOST}"]), [])
        self.assertEqual(self.call("GET", "/api/assets", headers={"Cookie": self.cookies["admin"]})[1]["total"], 0)
        self.assertEqual(self.call("GET", "/api/domains", headers={"Cookie": self.cookies["admin"]})[1]["total"], 0)
        self.assertEqual(self.send("/api/domains/remove", "remove-domain", {"domain_id": added["id"]})[0], 404)


if __name__ == "__main__":
    unittest.main()
