"""Related hosts of a domain and the scope saved for them: discovery keeps only public names under the domain, nothing
gets in scope without a DNS proof, the choice is saved with the domain and the next web scan reaches exactly it."""

import json
import os
import socket
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import select, update

import testenv
from pitangus.modules.runs.jobs import ScanJobs
from pitangus.modules.runs.store import load_run
from pitangus.modules.runs.tables import jobs
from pitangus.modules.scanning import discovery, engines, web
from pitangus.modules.sources import domain_scope, domains
from pitangus.modules.sources.domains import DomainError
from pitangus.shared import db
from pitangus.shared.i18n import text

from test_auth import ORIGIN, PASSWORD, HttpCase
from test_sarif_import import verified_domain
from test_web_scan import PUBLIC, fake_docker, real

HOST = "pitangus.dev"
NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)


def subfinder_output(*hosts: str) -> str:
    return "".join(json.dumps({"host": host, "input": HOST, "source": "crtsh"}) + "\n" for host in hosts)


def answers(table: dict):
    """getaddrinfo answering per name: a list of addresses, or None for a name that doesn't resolve."""
    def lookup(host, *args, **kwargs):
        found = table.get(host)
        if found is None:
            raise socket.gaierror(-2, "Name or service not known")
        return [(10 if ":" in address else 2, 1, 6, "", (address, 443)) for address in found]
    return patch("pitangus.modules.sources.domains.socket.getaddrinfo", side_effect=lookup)


class Case(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)


class NamesTests(unittest.TestCase):
    def test_only_valid_hosts_strictly_under_the_domain_are_read(self):
        output = subfinder_output("docs.pitangus.dev", "WWW.Pitangus.dev.", "pitangus.dev", "pitangus.dev.evil.com", "evilpitangus.dev",
                                  "other.example.com", "*.pitangus.dev", "bad_label.pitangus.dev", "a.b.pitangus.dev", "docs.pitangus.dev")
        output += "not json\n" + json.dumps(["docs2.pitangus.dev"]) + "\n" + json.dumps({"host": 7}) + "\n"
        self.assertEqual(discovery.names(output, HOST), ["a.b.pitangus.dev", "docs.pitangus.dev", "www.pitangus.dev"])

    def test_its_container_is_hardened_and_reaches_no_host_of_the_domain(self):
        self.assertNotIn("-active", discovery.arguments(HOST))
        self.assertNotIn("-all", discovery.arguments(HOST))
        testenv.docker_runner(self)
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, subfinder_output("docs.pitangus.dev", "intranet.pitangus.dev"), "")
        with patch.object(engines.shutil, "which", return_value="/usr/bin/docker"), \
                patch("pitangus.modules.scanning.engines.subprocess.run", side_effect=run), \
                answers({"docs.pitangus.dev": ["104.21.32.173"], "intranet.pitangus.dev": ["10.0.0.4"]}):
            found = discovery.discover(HOST)
        self.assertEqual(found, {"hosts": ["docs.pitangus.dev"], "counts": {"found": 2, "kept": 1, "private": 1, "unresolved": 0}})
        (command,) = calls
        for flag in (["--cap-drop", "ALL"], ["--security-opt", "no-new-privileges"], ["--network", "bridge"]):
            self.assertIn(flag, [command[index:index + 2] for index in range(len(command))])
        self.assertIn("--read-only", command)
        self.assertIn("--user", command)
        for forbidden in ("--privileged", "--add-host", "--cap-add", "host", "-v"):
            self.assertNotIn(forbidden, command)
        self.assertIn(engines.IMAGES["subfinder"]["image"], command)
        self.assertEqual(command[command.index(engines.IMAGES["subfinder"]["image"]) + 1:], discovery.arguments(HOST))

    def test_a_hung_or_failing_subfinder_is_a_clear_message(self):
        testenv.docker_runner(self)
        with patch.object(engines.shutil, "which", return_value="/usr/bin/docker"), \
                patch("pitangus.modules.scanning.engines.subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 75)), \
                self.assertRaises(discovery.DiscoveryError) as caught:
            discovery.discover(HOST)
        self.assertIn("75", text(caught.exception.message, "en"))


class ResolveTests(unittest.TestCase):
    def test_private_loopback_link_local_and_unresolved_names_are_dropped(self):
        table = {"www.pitangus.dev": ["104.21.32.173", "2606:4700:3030::6815:20ad"], "vpn.pitangus.dev": ["10.1.2.3"],
                 "local.pitangus.dev": ["127.0.0.1"], "meta.pitangus.dev": ["169.254.169.254"], "mixed.pitangus.dev": ["104.21.32.173", "192.168.1.1"],
                 "v6.pitangus.dev": ["fd00::1"], "cgnat.pitangus.dev": ["100.64.0.1"]}
        with answers(table):
            kept, counts = discovery.resolve([*table, "gone.pitangus.dev"])
        self.assertEqual(kept, ["www.pitangus.dev"])
        self.assertEqual(counts, {"found": 8, "kept": 1, "private": 6, "unresolved": 1})


class CoverageTests(Case):
    def test_only_a_current_dns_proof_lets_hosts_in_scope(self):
        record = verified_domain(self.data_dir, HOST)
        domain_scope.discovery_finished(self.data_dir, record["id"], ["docs.pitangus.dev"], {"found": 1})
        domain_scope.set_state(self.data_dir, record["id"], "docs.pitangus.dev", "in_scope")
        self.assertEqual(domain_scope.saved_hosts(self.data_dir, domains.get_domain(self.data_dir, record["id"])), ["docs.pitangus.dev"])
        # Verified again with a file: that proves the exact host only. The saved choice stays but nothing reaches it.
        domains._mark(self.data_dir, record["id"], proof_method="file")
        file_proof = domains.get_domain(self.data_dir, record["id"])
        self.assertEqual(domain_scope.saved_hosts(self.data_dir, file_proof), [])
        shown = domain_scope.view(self.data_dir, record["id"])
        self.assertEqual((shown["covered"], text(shown["reason"], "en")), (False, "Verify with DNS to include subdomains"))
        with self.assertRaises(DomainError) as caught:
            domain_scope.set_state(self.data_dir, record["id"], "docs.pitangus.dev", "in_scope")
        self.assertEqual(text(caught.exception.message, "es"), "Verifica con DNS para incluir subdominios")
        with self.assertRaises(DomainError):
            domain_scope.add_host(self.data_dir, record["id"], "shop.pitangus.dev")
        # Lapsed: not verified at all.
        domains._mark(self.data_dir, record["id"], proof_method="dns", verified_at=None, verified_until=None)
        lapsed = domains.get_domain(self.data_dir, record["id"])
        self.assertEqual(domain_scope.saved_hosts(self.data_dir, lapsed), [])
        self.assertIn("Verify pitangus.dev first", text(domain_scope.coverage_reason(lapsed), "en"))
        # Out of scope is always allowed.
        domain_scope.set_state(self.data_dir, record["id"], "docs.pitangus.dev", "out_of_scope")

    def test_hosts_outside_the_domain_or_the_domain_itself_are_refused(self):
        record = verified_domain(self.data_dir, HOST)
        for host in ("pitangus.dev", "pitangus.dev.evil.com", "evil.com", "xpitangus.dev", "*.pitangus.dev", "a..pitangus.dev", 7):
            with self.subTest(host=host), self.assertRaises(DomainError):
                domain_scope.add_host(self.data_dir, record["id"], host)
        stored = domain_scope.discovery_finished(self.data_dir, record["id"], ["evil.com", "pitangus.dev", "ok.pitangus.dev"], {"found": 3})
        self.assertEqual(stored["new"], 1)
        self.assertEqual([item["host"] for item in domain_scope.view(self.data_dir, record["id"])["hosts"]], ["ok.pitangus.dev"])


class PersistenceTests(Case):
    def test_discovered_hosts_start_out_and_the_choice_survives_the_next_round(self):
        record = verified_domain(self.data_dir, HOST)
        domain_scope.discovery_finished(self.data_dir, record["id"], ["docs.pitangus.dev", "www.pitangus.dev"], {"found": 2}, now=NOW)
        shown = domain_scope.view(self.data_dir, record["id"])
        self.assertEqual([(item["host"], item["state"], item["origin"]) for item in shown["hosts"]],
                         [("docs.pitangus.dev", "out_of_scope", "discovered"), ("www.pitangus.dev", "out_of_scope", "discovered")])
        self.assertEqual((shown["discovery"]["status"], shown["in_scope"]), ("done", 0))
        domain_scope.set_state(self.data_dir, record["id"], "docs.pitangus.dev", "in_scope", by="jefa")
        domain_scope.add_host(self.data_dir, record["id"], "Shop.Pitangus.dev.", by="jefa")
        later = NOW + timedelta(days=1)
        counts = domain_scope.discovery_finished(self.data_dir, record["id"], ["docs.pitangus.dev", "api.pitangus.dev"], {"found": 2}, now=later)
        self.assertEqual((counts["new"], counts["capped"]), (1, 0))
        rows = {item["host"]: item for item in domain_scope.view(self.data_dir, record["id"])["hosts"]}
        self.assertEqual({host: item["state"] for host, item in rows.items()},
                         {"api.pitangus.dev": "out_of_scope", "docs.pitangus.dev": "in_scope", "shop.pitangus.dev": "in_scope",
                          "www.pitangus.dev": "out_of_scope"})
        self.assertEqual((rows["docs.pitangus.dev"]["last_seen"], rows["docs.pitangus.dev"]["first_seen"]), (later.isoformat(), NOW.isoformat()))
        self.assertEqual((rows["www.pitangus.dev"]["last_seen"], rows["shop.pitangus.dev"]["origin"]), (NOW.isoformat(), "manual"))
        self.assertEqual(domain_scope.saved_hosts(self.data_dir, record), ["docs.pitangus.dev", "shop.pitangus.dev"])
        self.assertEqual(domain_scope.excluded_hosts(self.data_dir, record), ["api.pitangus.dev", "www.pitangus.dev"])
        # Hand-added hosts can be forgotten; discovered ones are excluded instead.
        with self.assertRaises(DomainError):
            domain_scope.remove_host(self.data_dir, record["id"], "docs.pitangus.dev")
        domain_scope.remove_host(self.data_dir, record["id"], "shop.pitangus.dev")
        self.assertEqual(domain_scope.exclude_all(self.data_dir, record["id"])["in_scope"], 0)
        # Removing the domain takes its hosts with it.
        domains.remove_domain(self.data_dir, record["id"])
        again = verified_domain(self.data_dir, HOST)
        self.assertEqual(domain_scope.view(self.data_dir, again["id"])["hosts"], [])

    def test_limits(self):
        record = verified_domain(self.data_dir, HOST)
        names = [f"h{index}.pitangus.dev" for index in range(domain_scope.HOSTS_LIMIT + 5)]
        counts = domain_scope.discovery_finished(self.data_dir, record["id"], names, {"found": len(names)})
        self.assertEqual((counts["new"], counts["capped"]), (domain_scope.HOSTS_LIMIT, 5))
        listed = [item["host"] for item in domain_scope.view(self.data_dir, record["id"])["hosts"]]
        for host in listed[:domains.SCOPE_LIMIT]:
            domain_scope.set_state(self.data_dir, record["id"], host, "in_scope")
        with self.assertRaises(DomainError):
            domain_scope.set_state(self.data_dir, record["id"], listed[domains.SCOPE_LIMIT], "in_scope")
        with self.assertRaises(DomainError):
            domain_scope.add_host(self.data_dir, record["id"], "extra.pitangus.dev")

    def test_one_discovery_round_at_a_time_unless_the_last_one_died(self):
        record = verified_domain(self.data_dir, HOST)
        self.assertTrue(domain_scope.request_discovery(self.data_dir, record["id"], now=NOW))
        self.assertFalse(domain_scope.request_discovery(self.data_dir, record["id"], now=NOW + timedelta(minutes=1)))
        shown = domain_scope.view(self.data_dir, record["id"], now=NOW + timedelta(hours=1))
        self.assertEqual(shown["discovery"]["status"], "failed")
        self.assertTrue(domain_scope.request_discovery(self.data_dir, record["id"], now=NOW + timedelta(hours=1)))


class DiscoveryJobTests(Case):
    def setUp(self):
        Case.setUp(self)
        testenv.docker_runner(self)
        self.jobs = ScanJobs(self.data_dir, worker=False)
        self.domain = verified_domain(self.data_dir, HOST)
        enabled = patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": "1"})
        enabled.start()
        self.addCleanup(enabled.stop)

    def run_job(self):
        self.assertTrue(self.jobs.enqueue_discovery(domain=self.domain))
        self.assertFalse(self.jobs.enqueue_discovery(domain=self.domain))
        with db.transaction(self.data_dir) as connection:
            payload = connection.execute(select(jobs.c.payload).where(jobs.c.kind == "domain_discovery")).scalars().all()[-1]
            connection.execute(update(jobs).where(jobs.c.kind == "domain_discovery").values(status="done"))
        self.jobs._execute({**payload, "kind": "domain_discovery", "run_id": None})
        return domain_scope.view(self.data_dir, self.domain["id"])

    def test_found_hosts_land_out_of_scope(self):
        with patch.object(discovery, "unavailable", return_value=None), \
                patch.object(discovery, "_run", return_value=subprocess.CompletedProcess([], 0, subfinder_output("docs.pitangus.dev", "db.pitangus.dev"), "")), \
                answers({"docs.pitangus.dev": ["104.21.32.173"], "db.pitangus.dev": ["172.16.0.9"]}):
            shown = self.run_job()
        self.assertEqual([(item["host"], item["state"]) for item in shown["hosts"]], [("docs.pitangus.dev", "out_of_scope")])
        self.assertEqual((shown["discovery"]["status"], shown["discovery"]["counts"]["private"]), ("done", 1))

    def test_without_docker_or_the_image_it_says_why(self):
        with patch.object(discovery, "docker_problem", return_value=""), patch.object(discovery, "image_available", return_value=False), \
                patch.object(discovery, "_run", side_effect=AssertionError("ran")):
            shown = self.run_job()
        self.assertEqual(shown["discovery"]["status"], "failed")
        self.assertIn("make engines", text(shown["discovery"]["note"], "en"))
        with patch.dict(os.environ, {"PITANGUS_ENGINE_RUNNER": "local"}), patch.object(discovery, "_run", side_effect=AssertionError("ran")):
            shown = self.run_job()
        self.assertIn("Docker runner", text(shown["discovery"]["note"], "en"))


class SavedScopeScanTests(Case):
    """The web scan reads the saved scope when it starts: its hosts in ZAP's context and pinned, the excluded ones out."""

    def setUp(self):
        Case.setUp(self)
        testenv.docker_runner(self)
        self.jobs = ScanJobs(self.data_dir, worker=False)
        self.domain = verified_domain(self.data_dir, HOST)
        for name, value in (("PITANGUS_DAST_ENABLED", "1"),):
            enabled = patch.dict(os.environ, {name: value})
            enabled.start()
            self.addCleanup(enabled.stop)
        docker = patch("pitangus.modules.scanning.engines.docker_problem", return_value="")
        docker.start()
        self.addCleanup(docker.stop)
        domain_scope.discovery_finished(self.data_dir, self.domain["id"], ["docs.pitangus.dev", "www.pitangus.dev", "old.pitangus.dev"], {"found": 3})
        domain_scope.set_state(self.data_dir, self.domain["id"], "docs.pitangus.dev", "in_scope")

    def run_job(self, options):
        queued = self.jobs.enqueue_dast_scan(domain=self.domain, requested_by="jefa", options=options)
        with db.transaction(self.data_dir) as connection:
            payload = connection.execute(select(jobs.c.payload).where(jobs.c.run_id == queued["id"])).scalar_one()
        calls, inputs = [], []
        addresses = {HOST: ["104.21.32.173"], "docs.pitangus.dev": ["104.21.32.174"], "www.pitangus.dev": ["104.21.32.175"]}
        with patch.object(domains, "lookup_txt", return_value=[self.domain["txt_value"]]), answers(addresses), \
                patch.object(engines.shutil, "which", return_value="/usr/bin/docker"), fake_docker(real(), calls=calls, inputs=inputs):
            self.jobs._execute({**payload, "kind": "dast_scan", "run_id": queued["id"]})
        with db.transaction(self.data_dir) as connection:
            connection.execute(update(jobs).where(jobs.c.run_id == queued["id"]).values(status="done"))
        return load_run(self.data_dir, queued["id"]), calls, inputs

    def test_the_plan_and_the_pins_follow_the_saved_scope(self):
        record, calls, inputs = self.run_job({"mode": "web", "use_scope": True})
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["scope"]["hosts"], [HOST, "docs.pitangus.dev"])
        (command,) = calls
        pins = [command[index + 1] for index, part in enumerate(command) if part == "--add-host"]
        self.assertEqual(pins, [f"{HOST}:104.21.32.173", "docs.pitangus.dev:104.21.32.174"])
        plan = json.loads(inputs[0])
        (context,) = plan["env"]["contexts"]
        self.assertEqual(context["urls"], [f"https://{HOST}/", "https://docs.pitangus.dev/"])
        self.assertEqual(context["includePaths"], [web.host_pattern(HOST), web.host_pattern("docs.pitangus.dev")])
        self.assertEqual(context["excludePaths"], [web.host_pattern("old.pitangus.dev"), web.host_pattern("www.pitangus.dev")])
        self.assertEqual([job["parameters"]["url"] for job in plan["jobs"] if job["type"] == "spider"],
                         [f"https://{HOST}/", "https://docs.pitangus.dev/"])

    def test_a_change_after_queueing_is_what_the_scan_reaches(self):
        queued = self.jobs.enqueue_dast_scan(domain=self.domain, requested_by="jefa", options={"mode": "web", "use_scope": True})
        with db.transaction(self.data_dir) as connection:
            connection.execute(update(jobs).where(jobs.c.run_id == queued["id"]).values(status="done"))
        domain_scope.set_state(self.data_dir, self.domain["id"], "www.pitangus.dev", "in_scope")
        domain_scope.set_state(self.data_dir, self.domain["id"], "docs.pitangus.dev", "out_of_scope")
        record, calls, _ = self.run_job({"mode": "web", "use_scope": True})
        self.assertEqual(record["scope"]["hosts"], [HOST, "www.pitangus.dev"])

    def test_without_the_dns_proof_the_saved_hosts_are_left_aside(self):
        domains._mark(self.data_dir, self.domain["id"], proof_method="file")
        self.domain = domains.get_domain(self.data_dir, self.domain["id"])
        with patch.object(domains, "proof_present", return_value=(True, None)):
            record, calls, _ = self.run_job({"mode": "web", "use_scope": True})
        self.assertEqual(record["scope"]["hosts"], [HOST])
        self.assertEqual([part for part in calls[0] if part.endswith(":104.21.32.174")], [])


class ApiTests(HttpCase):
    def setUp(self):
        HttpCase.setUp(self)
        from pitangus.modules.identity.auth import Users
        self.cookies = {}
        for name, role in (("jefa", "admin"), ("miembro", "member")):
            Users(self.data_dir).create(name, PASSWORD, role=role)
            self.cookies[role] = self.post("/api/auth/login", "login", {"username": name, "password": PASSWORD})[2][0].split("; ")[0]
        self.domain = verified_domain(self.data_dir, HOST)
        domain_scope.discovery_finished(self.data_dir, self.domain["id"], ["docs.pitangus.dev"], {"found": 1})

    def send(self, path, action, body, role="admin"):
        return self.call("POST", path, body, {"Origin": ORIGIN, "X-Pitangus-Action": action, "Cookie": self.cookies[role], "Accept-Language": "en"})

    def read(self, domain_id, role="member"):
        return self.call("GET", f"/api/domains/scope?domain_id={domain_id}", headers={"Cookie": self.cookies[role], "Accept-Language": "en"})

    def test_members_read_the_scope_and_administrators_change_it(self):
        status, shown, _ = self.read(self.domain["id"])
        self.assertEqual((status, shown["root"], shown["covered"], [item["host"] for item in shown["hosts"]]), (200, HOST, True, ["docs.pitangus.dev"]))
        self.assertEqual(self.read("f" * 24)[0], 404)
        self.assertEqual(self.read("../etc")[0], 400)
        body = {"domain_id": self.domain["id"], "op": "set", "host": "docs.pitangus.dev", "state": "in_scope"}
        self.assertEqual(self.send("/api/domains/scope", "domain-scope", body, role="member")[0], 403)
        status, shown, _ = self.send("/api/domains/scope", "domain-scope", body)
        self.assertEqual((status, shown["in_scope"]), (200, 1))
        self.assertEqual(self.send("/api/domains/scope", "domain-scope", {**body, "state": None})[0], 400)
        self.assertEqual(self.send("/api/domains/scope", "domain-scope", {"domain_id": self.domain["id"], "op": "add", "host": "evil.com"})[0], 400)
        status, shown, _ = self.send("/api/domains/scope", "domain-scope", {"domain_id": self.domain["id"], "op": "add", "host": "shop.pitangus.dev"})
        self.assertEqual((status, shown["in_scope"]), (200, 2))
        # A file proof covers the exact host only: 409 with the reason.
        domains._mark(self.data_dir, self.domain["id"], proof_method="file")
        status, answer, _ = self.send("/api/domains/scope", "domain-scope", body)
        self.assertEqual((status, answer["error"]), (409, "Verify with DNS to include subdomains"))
        self.assertEqual(self.send("/api/domains/scope", "domain-scope", {"domain_id": self.domain["id"], "op": "exclude_all"})[1]["in_scope"], 0)

    def test_discovery_on_registration_and_on_demand_only_with_web_scans_on(self):
        with patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": ""}), \
                patch.object(self.state.jobs, "enqueue_discovery", side_effect=AssertionError("queued")):
            self.assertEqual(self.send("/api/domains", "register-domain", {"url": "https://off.example.com/"})[0], 200)
            status, answer, _ = self.send("/api/domains/discover", "discover-domain", {"domain_id": self.domain["id"]})
            self.assertEqual(status, 409)
            self.assertIn("PITANGUS_DAST_ENABLED", answer["error"])
            self.assertFalse(self.read(self.domain["id"])[1]["discovery"]["available"])
        with patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": "1"}), \
                patch.object(self.state.jobs, "enqueue_discovery", return_value=True) as enqueue:
            status, created, _ = self.send("/api/domains", "register-domain", {"url": "https://on.example.com/"})
            self.assertEqual((status, enqueue.call_args.kwargs["domain"]["host"]), (200, "on.example.com"))
            self.assertEqual(self.send("/api/domains/discover", "discover-domain", {"domain_id": self.domain["id"]}, role="member")[0], 403)
            self.assertEqual(self.send("/api/domains/discover", "discover-domain", {"domain_id": self.domain["id"]})[0], 202)
            enqueue.return_value = False
            status, answer, _ = self.send("/api/domains/discover", "discover-domain", {"domain_id": self.domain["id"]})
            self.assertEqual((status, "already running" in answer["error"]), (409, True))

    def test_a_scan_with_the_saved_scope_checks_its_hosts_before_queueing(self):
        domain_scope.set_state(self.data_dir, self.domain["id"], "docs.pitangus.dev", "in_scope")
        body = {"domain_id": self.domain["id"], "use_scope": True}
        with patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": "1"}), \
                patch.object(self.state.jobs, "enqueue_dast_scan", return_value={"id": "r1", "status": "queued"}) as enqueue:
            self.assertEqual(self.send("/api/domains/scans", "scan-domain", {**body, "hosts": ["docs.pitangus.dev"]})[0], 400)
            with answers({HOST: ["104.21.32.173"], "docs.pitangus.dev": ["10.0.0.8"]}):
                status, answer, _ = self.send("/api/domains/scans", "scan-domain", body)
            self.assertEqual(status, 409)
            self.assertIn("docs.pitangus.dev", answer["error"])
            with answers({HOST: ["104.21.32.173"], "docs.pitangus.dev": list(dict.fromkeys(address[4][0] for address in PUBLIC))}):
                status, _, _ = self.send("/api/domains/scans", "scan-domain", body)
            self.assertEqual(status, 202)
            self.assertEqual(enqueue.call_args.kwargs["options"], {"mode": "web", "use_headers": False, "use_scope": True})


if __name__ == "__main__":
    unittest.main()
