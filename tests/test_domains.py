"""Registered domains: a TXT proof makes one an asset for a while, administrators manage them, members only look."""

import json
import logging
import ssl
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from sqlalchemy import select

from pitangus.modules.runs.imports import import_sarif
from pitangus.modules.runs.store import find_runs
from pitangus.modules.sources import domains
from pitangus.modules.sources.domains import DomainError
from pitangus.shared import documents
from pitangus.shared.i18n import msg, text

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

    def test_https_fetches_validate_the_certificate_and_refuse_anything_below_tls_1_2(self):
        context = domains.tls_context()
        self.assertEqual((context.verify_mode, context.check_hostname), (ssl.CERT_REQUIRED, True))
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

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

    def test_removing_a_domain_keeps_what_was_imported_against_it(self):
        _, added, _ = self.send("/api/domains", "register-domain", {"url": f"https://{HOST}/"})
        now = datetime.now(timezone.utc)
        domains._mark(self.data_dir, added["id"], verified_at=now, verified_until=now + timedelta(days=1))
        import_sarif(self.data_dir, json.loads(ZAP.read_text()), asset=f"domain:{HOST}", requested_by="ci")
        _, page, _ = self.call("GET", "/api/domains", headers={"Cookie": self.cookies["admin"]})
        self.assertEqual((page["items"][0]["runs"], page["items"][0]["open"]), (1, 3))  # the CSP missing on two pages is one
        _, assets, _ = self.call("GET", "/api/assets", headers={"Cookie": self.cookies["admin"]})
        self.assertEqual([(row["key"], row["name"], row["open"]["total"]) for row in assets["items"]], [(f"domain:{HOST}", HOST, 3)])
        status, removed, _ = self.send("/api/domains/remove", "remove-domain", {"domain_id": added["id"]})
        self.assertEqual((status, removed), (200, {"id": added["id"], "host": HOST, "runs_kept": 1}))
        # The evidence stays: the run, its findings and the asset are still there.
        self.assertEqual(len(find_runs(self.data_dir, assets=[f"domain:{HOST}"])), 1)
        _, assets, _ = self.call("GET", "/api/assets", headers={"Cookie": self.cookies["admin"]})
        self.assertEqual([(row["key"], row["open"]["total"]) for row in assets["items"]], [(f"domain:{HOST}", 3)])
        self.assertEqual(self.call("GET", "/api/domains", headers={"Cookie": self.cookies["admin"]})[1]["total"], 0)
        self.assertEqual(self.send("/api/domains/remove", "remove-domain", {"domain_id": added["id"]})[0], 404)
        # Adding the host again links its history back.
        self.send("/api/domains", "register-domain", {"url": f"https://{HOST}/"})
        _, page, _ = self.call("GET", "/api/domains", headers={"Cookie": self.cookies["admin"]})
        self.assertEqual((page["items"][0]["runs"], page["items"][0]["open"]), (1, 3))


SECRET = "Bearer eyJhbGciOiJIUzI1NiJ9.c2VjcmV0"


def answering(status=200, body=b"", calls=None):
    """`https_get` answering `status` and `body`, from an address already checked as public."""
    def get(host, address, path, **kwargs):
        if calls is not None:
            calls.append((host, address, path))
        return status, body
    return patch.object(domains, "https_get", side_effect=get)


def public():
    return patch.object(domains, "public_address", return_value="104.21.32.173")


class FileAndMetaProofTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.record = domains.register_domain(self.data_dir, f"https://{HOST}/app")
        self.token = domains.token(self.record)

    def test_a_file_at_the_well_known_path_proves_the_host_and_the_recheck_asks_for_it_again(self):
        calls = []
        with public(), answering(200, f"{self.token}\n".encode(), calls), \
                patch.object(domains, "lookup_txt", side_effect=AssertionError("asked DNS")):
            verified = domains.verify_domain(self.data_dir, self.record["id"], "file", now=NOW)
            self.assertEqual(domains.recheck(self.data_dir, now=NOW + timedelta(days=1))["kept"], 1)
        self.assertEqual((verified["verified"], verified["proof_method"]), (True, "file"))
        self.assertEqual(calls[0], (HOST, "104.21.32.173", "/.well-known/pitangus-verify.txt"))
        self.assertEqual(verified["verify_file_url"], f"https://{HOST}/.well-known/pitangus-verify.txt")
        with public(), answering(404):
            self.assertEqual(domains.recheck(self.data_dir, now=NOW + timedelta(days=2))["withdrawn"], 1)
        self.assertFalse(domains.get_domain(self.data_dir, self.record["id"])["verified"])

    def test_the_file_must_answer_200_from_that_host_with_the_token_and_within_the_cap(self):
        for status, body, words in ((301, b"", "redirect"), (200, b"pitangus-verify=someone-else", "doesn't contain"),
                                    (404, self.token.encode(), "doesn't contain"),
                                    (200, self.token.encode() + b"x" * domains.BODY_LIMIT, "doesn't contain")):
            with self.subTest(status=status, size=len(body)), public(), answering(status, body), self.assertRaises(DomainError) as caught:
                domains.verify_domain(self.data_dir, self.record["id"], "file", now=NOW)
            self.assertIn(words, text(caught.exception.message, "en"))
        # The host not answering proves nothing: nothing is marked as checked.
        with public(), patch.object(domains, "https_get", side_effect=OSError("refused")), self.assertRaises(DomainError) as caught:
            domains.verify_domain(self.data_dir, self.record["id"], "file", now=NOW)
        self.assertIn("Couldn't reach", text(caught.exception.message, "en"))
        self.assertFalse(domains.get_domain(self.data_dir, self.record["id"])["verified"])

    def test_a_private_address_is_never_fetched(self):
        with patch("pitangus.modules.sources.domains.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("169.254.169.254", 443))]), \
                patch.object(domains, "https_get", side_effect=AssertionError("fetched")), self.assertRaises(DomainError) as caught:
            domains.verify_domain(self.data_dir, self.record["id"], "meta", now=NOW)
        self.assertIn("private or reserved", text(caught.exception.message, "en"))

    def test_the_meta_tag_is_read_however_the_page_writes_it(self):
        pages = (f'<html><head><meta name="pitangus-verify" content="{self.token}"></head></html>',
                 f"<META CONTENT='{self.token}' NAME='Pitangus-Verify'/>",
                 f'<head><title>x</title><meta name=pitangus-verify content={self.token}><p><div',
                 f'<meta name="pitangus-verify" content="pitangus-verify={self.token}">')
        for page in pages:
            with self.subTest(page=page[:40]), public(), answering(200, page.encode()):
                self.assertEqual(domains.verify_domain(self.data_dir, self.record["id"], "meta", now=NOW)["proof_method"], "meta")
        for page in (f"<!-- <meta name='pitangus-verify' content='{self.token}'> -->", f"<p>{self.token}</p>",
                     f'<meta name="description" content="{self.token}">'):
            with self.subTest(page=page[:40]), public(), answering(200, page.encode()), self.assertRaises(DomainError):
                domains.verify_domain(self.data_dir, self.record["id"], "meta", now=NOW)
        self.assertEqual(domains.meta_tokens(b"<meta name='pitangus-verify' content='a'><meta name=x content=b"), ["a"])

    def test_only_a_dns_proof_covers_subdomains(self):
        dns = {**self.record, "proof_method": "dns"}
        self.assertEqual(domains.scan_scope(dns, ["docs.app.example.com", "*.app.example.com", "DOCS.app.example.com."]),
                         {"hosts": [HOST, "docs.app.example.com"], "wildcards": ["*.app.example.com"]})
        for method in ("file", "meta"):
            self.assertEqual(domains.scan_scope({**self.record, "proof_method": method}, [HOST])["hosts"], [HOST])
            for extra in (["docs.app.example.com"], ["*.app.example.com"]):
                with self.subTest(method=method, extra=extra), self.assertRaises(DomainError) as caught:
                    domains.scan_scope({**self.record, "proof_method": method}, extra)
                self.assertIn("DNS TXT", text(caught.exception.message, "en"))
        for bad in (["example.com"], ["evil.com"], ["xapp.example.com"], ["*.*.app.example.com"], ["a b.app.example.com"],
                    ["localhost"], [5], [f"h{index}.app.example.com" for index in range(21)]):
            with self.subTest(bad=bad), self.assertRaises(DomainError):
                domains.scan_scope(dns, bad)


class ScheduleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.one = domains.register_domain(self.data_dir, "https://one.example.com/")
        self.two = domains.register_domain(self.data_dir, "https://two.example.com/")
        for record in (self.one, self.two):
            domains._mark(self.data_dir, record["id"], verified_at=NOW, verified_until=datetime.now(timezone.utc) + timedelta(days=30))

    def test_due_logic_one_scan_per_round_and_lapsed_proofs_skipped_with_the_reason(self):
        from pitangus.modules.runs import periodic
        from pitangus.modules.runs.jobs import BusyError
        self.assertEqual(domains.due_scans(self.data_dir, now=NOW), [])
        daily = {"frequency": "daily", "time": "12:00", "timezone": "UTC"}
        domains.set_schedule(self.data_dir, self.two["id"], daily, now=NOW - timedelta(hours=1))
        domains.set_schedule(self.data_dir, self.one["id"], {**daily, "time": "12:05"}, now=NOW - timedelta(hours=1))
        with self.assertRaises(DomainError):
            domains.set_schedule(self.data_dir, self.one["id"], {"frequency": "hourly", "time": "12:00", "timezone": "UTC"})
        self.assertEqual([item["host"] for item in domains.due_scans(self.data_dir, now=NOW + timedelta(hours=1))],
                         ["two.example.com", "one.example.com"])  # the longest overdue first
        jobs = MagicMock()
        jobs.enqueue_dast_scan.return_value = {"id": "r" * 32, "status": "queued"}
        later = NOW + timedelta(hours=1)
        self.assertEqual(periodic._domain_scans(self.data_dir, jobs, now=later), {"queued": "r" * 32, "host": "two.example.com"})
        kwargs = jobs.enqueue_dast_scan.call_args.kwargs
        self.assertEqual((kwargs["options"], kwargs["trigger"], kwargs["requested_by"]), ({"mode": "web", "use_scope": True}, {"kind": "schedule"}, "schedule"))
        two = domains.get_domain(self.data_dir, self.two["id"])["schedule"]
        self.assertEqual((two["last_run_id"], two["next_run_at"], two["note"]),
                         ("r" * 32, (NOW + timedelta(days=1)).isoformat(), None))
        # Another web scan running: it stays due, with the reason.
        jobs.enqueue_dast_scan.side_effect = BusyError(msg("scanning.web.errors.busy"))
        self.assertEqual(periodic._domain_scans(self.data_dir, jobs, now=later)["waiting"], "one.example.com")
        one = domains.get_domain(self.data_dir, self.one["id"])["schedule"]
        self.assertIn("another web scan", text(one["note"], "en"))
        self.assertEqual(one["next_run_at"], (NOW + timedelta(minutes=5)).isoformat())
        # A lapsed proof: skipped with the reason, nothing queued, still due.
        domains._mark(self.data_dir, self.one["id"], verified_at=None, verified_until=None)
        jobs.enqueue_dast_scan.reset_mock(side_effect=True)
        self.assertEqual(periodic._domain_scans(self.data_dir, jobs, now=later), {"queued": None})
        jobs.enqueue_dast_scan.assert_not_called()
        self.assertIn("lapsed", text(domains.get_domain(self.data_dir, self.one["id"])["schedule"]["note"], "en"))
        domains.set_schedule(self.data_dir, self.one["id"], None)
        self.assertIsNone(domains.get_domain(self.data_dir, self.one["id"])["schedule"])
        self.assertEqual([item["host"] for item in domains.due_scans(self.data_dir, now=later + timedelta(days=30))], ["two.example.com"])

    def test_the_rule_is_stored_normalized_and_the_next_run_skips_the_day_of_the_last_scan(self):
        weekly = {"frequency": "weekly", "weekdays": [5, 1, 5], "month_days": [3], "time": "09:00", "timezone": "America/Bogota"}
        schedule = domains.set_schedule(self.data_dir, self.one["id"], weekly, now=NOW)["schedule"]
        self.assertEqual({key: schedule[key] for key in ("frequency", "weekdays", "month_days", "time", "timezone")},
                         {"frequency": "weekly", "weekdays": [1, 5], "month_days": [], "time": "09:00", "timezone": "America/Bogota"})
        # Friday 7:00 in Bogotá: today's 9:00 is still ahead.
        self.assertEqual(schedule["next_run_at"], "2026-10-09T14:00:00+00:00")
        # Scanned by hand today: the next one is Monday.
        other = domains.set_schedule(self.data_dir, self.two["id"], weekly, now=NOW, last_scan_at=NOW - timedelta(hours=1))["schedule"]
        self.assertEqual(other["next_run_at"], "2026-10-12T14:00:00+00:00")
        # The same rule again keeps the next run; another one recomputes it.
        self.assertEqual(domains.set_schedule(self.data_dir, self.one["id"], weekly, now=NOW + timedelta(hours=3))["schedule"]["next_run_at"],
                         "2026-10-09T14:00:00+00:00")
        monthly = domains.set_schedule(self.data_dir, self.one["id"], {"frequency": "monthly", "month_days": [28, 1], "time": "23:30",
                                                                     "timezone": "Asia/Tokyo"}, now=NOW)["schedule"]
        self.assertEqual((monthly["month_days"], monthly["next_run_at"]), ([1, 28], "2026-10-28T14:30:00+00:00"))
        for bad in ({"frequency": "weekly", "weekdays": [], "time": "09:00", "timezone": "UTC"},
                    {"frequency": "weekly", "weekdays": [8], "time": "09:00", "timezone": "UTC"},
                    {"frequency": "weekly", "weekdays": [True], "time": "09:00", "timezone": "UTC"},
                    {"frequency": "monthly", "month_days": [29], "time": "09:00", "timezone": "UTC"},
                    {"frequency": "daily", "time": "24:00", "timezone": "UTC"},
                    {"frequency": "daily", "time": "9:00", "timezone": "UTC"},
                    {"frequency": "daily", "time": "09:00", "timezone": "Mars/Olympus"},
                    {"frequency": "daily", "time": "09:00", "timezone": "../zoneinfo/UTC"}):
            with self.subTest(bad=bad), self.assertRaises(DomainError):
                domains.set_schedule(self.data_dir, self.one["id"], bad, now=NOW)

    def test_a_domain_scanned_by_hand_that_day_moves_on_without_a_second_scan(self):
        from pitangus.modules.runs import periodic
        domains.set_schedule(self.data_dir, self.one["id"], {"frequency": "daily", "time": "12:00", "timezone": "UTC"}, now=NOW - timedelta(hours=1))
        jobs = MagicMock()
        with patch("pitangus.modules.runs.store.find_runs", return_value=[{"created_at": (NOW - timedelta(hours=2)).isoformat()}]):
            self.assertEqual(periodic._domain_scans(self.data_dir, jobs, now=NOW + timedelta(minutes=3)), {"queued": None})
        jobs.enqueue_dast_scan.assert_not_called()
        schedule = domains.get_domain(self.data_dir, self.one["id"])["schedule"]
        self.assertEqual(schedule["next_run_at"], (NOW + timedelta(days=1)).isoformat())
        self.assertIn("already scanned", text(schedule["note"], "en"))

    def test_queuing_and_moving_the_schedule_on_happen_together_or_not_at_all(self):
        from pitangus.modules.runs import periodic
        from pitangus.modules.runs.jobs import ScanJobs
        from pitangus.modules.runs.tables import jobs as job_table
        from pitangus.shared import db
        domains.set_schedule(self.data_dir, self.one["id"], {"frequency": "daily", "time": "12:00", "timezone": "UTC"}, now=NOW - timedelta(hours=1))
        scan_jobs = ScanJobs(self.data_dir, worker=False)

        def queued() -> int:
            with db.transaction(self.data_dir) as connection:
                return len(connection.execute(select(job_table.c.id).where(job_table.c.kind == "dast_scan")).all())

        # A crash after the job is queued but before the schedule moves on: neither is kept, and the slot stays due.
        with patch.object(domains, "schedule_queued", side_effect=RuntimeError("crash")), self.assertRaises(RuntimeError):
            periodic._domain_scans(self.data_dir, scan_jobs, now=NOW + timedelta(minutes=1))
        self.assertEqual((queued(), find_runs(self.data_dir, types=["dast_scan"])), (0, []))
        self.assertEqual(domains.get_domain(self.data_dir, self.one["id"])["schedule"]["next_run_at"], NOW.isoformat())
        # The next round queues it once, and the round after that finds nothing due.
        outcome = periodic._domain_scans(self.data_dir, scan_jobs, now=NOW + timedelta(minutes=6))
        self.assertEqual((queued(), outcome["host"]), (1, "one.example.com"))
        self.assertEqual(periodic._domain_scans(self.data_dir, scan_jobs, now=NOW + timedelta(minutes=11)), {"queued": None})
        self.assertEqual(queued(), 1)

    def test_old_weekly_schedules_get_the_weekday_and_time_of_their_next_run_in_utc(self):
        from pitangus.modules.runs import periodic
        sunday = datetime(2026, 10, 11, 3, 40, tzinfo=timezone.utc)
        domains._mark(self.data_dir, self.one["id"], schedule="weekly", schedule_next_at=sunday)
        legacy = domains.get_domain(self.data_dir, self.one["id"])["schedule"]  # read before the data migration
        self.assertEqual((legacy["frequency"], legacy["weekdays"], legacy["time"], legacy["timezone"], legacy["next_run_at"]),
                         ("weekly", [7], "03:40", "UTC", sunday.isoformat()))
        self.assertEqual(domains.adopt_schedule_rules(self.data_dir), 1)
        self.assertEqual(domains.adopt_schedule_rules(self.data_dir), 0)  # idempotent
        self.assertEqual(domains.get_domain(self.data_dir, self.one["id"])["schedule"], legacy)
        jobs = MagicMock()
        jobs.enqueue_dast_scan.return_value = {"id": "s" * 32, "status": "queued"}
        periodic._domain_scans(self.data_dir, jobs, now=sunday + timedelta(minutes=2))
        self.assertEqual(domains.get_domain(self.data_dir, self.one["id"])["schedule"]["next_run_at"], (sunday + timedelta(days=7)).isoformat())

    def test_the_task_is_off_without_web_scans(self):
        from pitangus.modules.runs import periodic
        from pitangus.modules.scanning import engine_switches
        with patch.dict("os.environ", {"PITANGUS_DAST_ENABLED": ""}):
            self.assertEqual(periodic.TASKS["domain_scans"].every(self.data_dir), -1)
            # Turned on in the panel, with nothing in the environment.
            engine_switches.set_switch(self.data_dir, "dast", True, user={"username": "ana"})
            self.assertEqual(periodic.TASKS["domain_scans"].every(self.data_dir), periodic.DOMAIN_SCAN_SECONDS)
        with patch.dict("os.environ", {"PITANGUS_DAST_ENABLED": "0"}):  # the server's variable wins
            self.assertEqual(periodic.TASKS["domain_scans"].every(self.data_dir), -1)
        with patch.dict("os.environ", {"PITANGUS_DAST_ENABLED": "1"}):
            self.assertEqual(periodic.TASKS["domain_scans"].every(self.data_dir), periodic.DOMAIN_SCAN_SECONDS)


class AccessApiTests(HttpCase):
    def setUp(self):
        super().setUp()
        from pitangus.modules.identity.auth import Users
        self.cookies = {}
        for name, role in (("jefa", "admin"), ("miembro", "member")):
            Users(self.data_dir).create(name, PASSWORD, role=role)
            self.cookies[role] = self.post("/api/auth/login", "login", {"username": name, "password": PASSWORD})[2][0].split("; ")[0]
        self.domain = self.send("/api/domains", "register-domain", {"url": f"https://{HOST}/"})[1]

    send = ApiTests.send

    def test_headers_are_admin_only_validated_encrypted_and_never_answered_or_logged(self):
        from pitangus.shared import db, vault
        records = []
        handler = _Records(records)
        logger = logging.getLogger("pitangus")
        logger.addHandler(handler)
        self.addCleanup(logger.removeHandler, handler)
        body = {"domain_id": self.domain["id"], "op": "save", "name": "Authorization", "value": SECRET}
        self.assertEqual(self.send("/api/domains/headers", "domain-headers", body, role="member")[0], 403)
        status, saved, _ = self.send("/api/domains/headers", "domain-headers", body)
        self.assertEqual((status, saved["headers"], saved["limit"]), (200, [{"name": "Authorization", "last4": SECRET[-4:], "saved_at": saved["headers"][0]["saved_at"]}], 10))
        _, page, _ = self.call("GET", "/api/domains", headers={"Cookie": self.cookies["admin"]})
        self.assertEqual(([item["name"] for item in page["items"][0]["headers"]], page["items"][0]["header_count"]), (["Authorization"], 1))
        _, page, _ = self.call("GET", "/api/domains", headers={"Cookie": self.cookies["member"]})
        self.assertEqual((page["items"][0]["headers"], page["items"][0]["header_count"]), (None, 1))
        self.assertNotIn("verify_token", page["items"][0])
        for bad in ({"name": "Host", "value": "x"}, {"name": "Content-Length", "value": "1"}, {"name": "Transfer-Encoding", "value": "chunked"},
                    {"name": "Connection", "value": "close"}, {"name": "Bad Name", "value": "x"}, {"name": "X-A", "value": "a\r\nInjected: 1"},
                    {"name": "X-A", "value": "x" * 4097}, {"name": "X-A", "value": "ñ"}, {"name": "X-A", "value": "   "}, {"name": "X-A"},
                    {"name": "X-A", "op": "remove", "value": "x"}, {"name": "Nope", "op": "remove"}):
            with self.subTest(bad=bad):
                status, answer, _ = self.send("/api/domains/headers", "domain-headers", {"domain_id": self.domain["id"], "op": "save", **bad})
                self.assertEqual(status, 400, answer)
        for index in range(9):
            self.send("/api/domains/headers", "domain-headers", {"domain_id": self.domain["id"], "op": "save", "name": f"X-K{index}", "value": "v"})
        status, answer, _ = self.send("/api/domains/headers", "domain-headers", {**body, "name": "X-Eleventh"})
        self.assertEqual((status, "at most 10" in answer["error"]), (400, True))
        self.assertEqual(self.send("/api/domains/headers", "domain-headers", {**body, "value": "Bearer replaced-value-1234"})[0], 200)  # replaces
        status, left, _ = self.send("/api/domains/headers", "domain-headers", {"domain_id": self.domain["id"], "op": "remove", "name": "authorization"})
        self.assertEqual((status, "Authorization" in [item["name"] for item in left["headers"]]), (200, False))
        self.assertEqual(self.send("/api/domains/headers", "domain-headers", {**body, "domain_id": "f" * 24})[0], 404)
        with db.transaction(self.data_dir) as connection:
            stored = json.dumps([list(row) for row in connection.execute(select(vault.vault_entries.c.data))])
        everything = json.dumps(records) + stored + json.dumps(self.call("GET", "/api/domains", headers={"Cookie": self.cookies["admin"]})[1])
        for value in (SECRET, "replaced-value-1234"):
            self.assertNotIn(value, everything)
        # Removing the domain takes its headers.
        self.send("/api/domains/remove", "remove-domain", {"domain_id": self.domain["id"]})
        self.assertNotIn(f"domain-headers:{self.domain['id']}", vault.names())

    def test_the_session_check_is_an_admin_setting_on_the_domain_or_its_subdomains(self):
        route = lambda url, role="admin": self.send("/api/domains/session-check", "domain-session-check",  # noqa: E731
                                                    {"domain_id": self.domain["id"], "url": url}, role=role)
        self.assertEqual(route(f"https://{HOST}/account", role="member")[0], 403)
        for bad in ("http://%s/account" % HOST, f"https://{HOST}:8443/account", f"https://user:pw@{HOST}/", "https://evil.example/account",
                    f"https://{HOST}/${{SECRET}}", "/account", f"https://{HOST}/a b"):
            with self.subTest(bad=bad):
                self.assertEqual(route(bad)[0], 400)
        status, saved, _ = route(f"https://app.{HOST}/account?tab=me")
        self.assertEqual((status, saved["session_check"]), (200, f"https://app.{HOST}/account?tab=me"))
        _, page, _ = self.call("GET", "/api/domains", headers={"Cookie": self.cookies["admin"]})
        self.assertEqual(page["items"][0]["session_check"], f"https://app.{HOST}/account?tab=me")
        _, page, _ = self.call("GET", "/api/domains", headers={"Cookie": self.cookies["member"]})
        self.assertNotIn("session_check", {key for key, value in page["items"][0].items() if value is not None})
        self.assertEqual(route("")[1]["session_check"], None)  # empty removes it
        self.assertEqual(self.send("/api/domains/session-check", "domain-session-check", {"domain_id": "f" * 24, "url": ""})[0], 404)

    def test_probe_verify_methods_and_schedule_routes(self):
        status, probe, _ = self.send("/api/domains/probe", "probe-domain", {"url": "https://intranet.example.com/"}, role="member")
        self.assertEqual(status, 403)
        with patch("pitangus.modules.sources.domains.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("10.0.0.5", 443))]), \
                patch("pitangus.modules.sources.domains.socket.create_connection", side_effect=AssertionError("connected")):
            status, probe, _ = self.send("/api/domains/probe", "probe-domain", {"url": "https://intranet.example.com/"})
        self.assertEqual((status, probe["host"], probe["reachable"], probe["https"], probe["status"], probe["public"]),
                         (200, "intranet.example.com", False, False, "private_address", False))
        self.assertEqual(self.send("/api/domains/probe", "probe-domain", {"url": "http://x.example.com/"})[0], 400)
        self.assertEqual(self.send("/api/domains/verify", "verify-domain", {"domain_id": self.domain["id"], "method": "smtp"})[0], 400)
        token = self.domain["verify_token"]
        self.assertEqual(self.domain["verify_meta"], f'<meta name="pitangus-verify" content="{token}">')
        with public(), answering(200, f"<meta name='pitangus-verify' content='{token}'>".encode()):
            status, verified, _ = self.send("/api/domains/verify", "verify-domain", {"domain_id": self.domain["id"], "method": "meta"})
        self.assertEqual((status, verified["verified"], verified["proof_method"]), (200, True, "meta"))
        rule = {"frequency": "weekly", "weekdays": [5], "time": "09:00", "timezone": "America/Bogota"}
        self.assertEqual(self.send("/api/domains/schedule", "schedule-domain", {"domain_id": self.domain["id"], "schedule": rule}, role="member")[0], 403)
        for bad in ("weekly", {**rule, "weekdays": []}, {**rule, "frequency": "hourly"}, {**rule, "time": "25:00"},
                    {**rule, "weekdays": [True]}, {**rule, "extra": 1}, {**rule, "frequency": "monthly", "month_days": [31]}):
            with self.subTest(bad=bad):
                self.assertEqual(self.send("/api/domains/schedule", "schedule-domain", {"domain_id": self.domain["id"], "schedule": bad})[0], 400)
        status, answer, _ = self.send("/api/domains/schedule", "schedule-domain", {"domain_id": self.domain["id"], "schedule": {**rule, "timezone": "Mars/Base"}})
        self.assertEqual((status, "Mars/Base" in answer["error"]), (400, True))
        self.assertEqual(self.send("/api/domains/schedule", "schedule-domain", {"domain_id": "f" * 24, "schedule": rule})[0], 404)
        status, row, _ = self.send("/api/domains/schedule", "schedule-domain", {"domain_id": self.domain["id"], "schedule": rule})
        schedule = row["schedule"]
        self.assertEqual((status, schedule["frequency"], schedule["weekdays"], schedule["month_days"], schedule["time"], schedule["timezone"]),
                         (200, "weekly", [5], [], "09:00", "America/Bogota"))
        moment = datetime.fromisoformat(schedule["next_run_at"])
        self.assertEqual((moment.utcoffset(), moment.isoweekday(), moment.hour, moment.minute), (timedelta(0), 5, 14, 0))
        status, row, _ = self.send("/api/domains/schedule", "schedule-domain", {"domain_id": self.domain["id"], "schedule": None})
        self.assertEqual((status, row["schedule"]), (200, None))


class _Records(logging.Handler):
    """Every log line with its extra fields, as raw as they were emitted."""

    def __init__(self, sink: list):
        super().__init__(level=logging.DEBUG)
        self.sink = sink

    def emit(self, record):
        self.sink.append(json.dumps({key: str(value) for key, value in record.__dict__.items()}) + record.getMessage())


if __name__ == "__main__":
    unittest.main()
