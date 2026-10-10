"""Passive web scans of a verified domain with ZAP: the guardrails before anything reaches the site, the container it
runs in, and findings identical to an import of the same SARIF."""

import json
import os
import re

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import update

import testenv
from pitangus.modules.findings import registry as findings_registry
from pitangus.modules.runs.imports import import_sarif
from pitangus.modules.runs.jobs import BusyError, ScanJobs
from pitangus.modules.runs.store import load_run
from pitangus.modules.runs.tables import jobs
from pitangus.modules.scanning import engines, sarif_import, web
from pitangus.modules.sources import domains
from pitangus.shared import db
from pitangus.shared.i18n import msg, text

from test_auth import ORIGIN, PASSWORD, HttpCase
from test_sarif_import import verified_domain

REAL = Path(__file__).resolve().parent / "engine-outputs" / "zap-2.17.sarif"  # ZAP 2.17.0 against pitangus.dev
HOST = "pitangus.dev"
PUBLIC = [(2, 1, 6, "", ("104.21.32.173", 443)), (10, 1, 6, "", ("2606:4700:3030::6815:20ad", 443, 0, 0))]


def real() -> dict:
    return json.loads(REAL.read_text())


def resolving(*addresses):
    return patch("pitangus.modules.sources.domains.socket.getaddrinfo",
                 return_value=[(2, 1, 6, "", (address, 443)) for address in addresses])


def fake_docker(document: dict | None, *, returncode: int = 0, stdout: str = "", calls: list | None = None, modes: list | None = None):
    """`docker run` of ZAP: writes `document` as the SARIF report into the mounted work folder."""
    def run(command, **kwargs):
        if calls is not None:
            calls.append(command)
        mount = command[command.index("-v") + 1]
        work = Path(mount.rsplit(":", 2)[0])
        if modes is not None:
            modes.append((work.stat().st_mode & 0o777, work.parent.stat().st_mode & 0o777))
        if document is not None:
            (work / web.REPORT).write_text(json.dumps(document))
        return subprocess.CompletedProcess(command, returncode, stdout, "")
    return patch("pitangus.modules.scanning.engines.subprocess.run", side_effect=run)


class PlanTests(unittest.TestCase):
    def test_the_plan_crawls_and_reads_only_that_host_and_never_attacks(self):
        plan = web.plan(HOST, f"https://{HOST}/")
        self.assertEqual([job["type"] for job in plan["jobs"]], ["spider", "passiveScan-wait", "report"])
        spider = plan["jobs"][0]["parameters"]
        self.assertEqual((spider["maxDuration"], spider["postForm"], spider["context"]), (web.SPIDER_MINUTES, False, web.CONTEXT))
        (context,) = plan["env"]["contexts"]
        self.assertEqual(context["urls"], [f"https://{HOST}/"])
        (scope,) = context["includePaths"]
        inside = ("https://pitangus.dev", "https://pitangus.dev/", "https://pitangus.dev/es/?q=1")
        outside = ("http://pitangus.dev/", "https://pitangus.dev.evil.example/", "https://evil.example/?u=https://pitangus.dev/",
                   "https://pitangusXdev/", "https://pitangus.dev@evil.example/", "https://api.pitangus.dev/")
        for url in inside:
            self.assertTrue(re.fullmatch(scope, url), url)
        for url in outside:
            self.assertFalse(re.fullmatch(scope, url), url)
        self.assertEqual(plan["jobs"][2]["parameters"], {"template": "sarif-json", "reportDir": "/zap/wrk", "reportFile": "zap"})

    def test_the_plan_is_serialized_so_a_hostile_url_cannot_add_a_job(self):
        hostile = 'https://pitangus.dev/x"\n  - type: activeScan\n#'
        parsed = json.loads(web.plan_text(HOST, hostile))
        self.assertEqual([job["type"] for job in parsed["jobs"]], ["spider", "passiveScan-wait", "report"])
        self.assertEqual(parsed["jobs"][0]["parameters"]["url"], hostile)
        # The registered URL is only used on its own host; anything else starts at the host's root.
        self.assertEqual(web.start_url({"host": HOST, "url": "https://evil.example/"}), f"https://{HOST}/")
        self.assertEqual(web.start_url({"host": HOST, "url": f"https://{HOST}:8443/"}), f"https://{HOST}/")
        self.assertEqual(web.start_url({"host": HOST, "url": f"https://{HOST}/app"}), f"https://{HOST}/app")


class ContainerTests(unittest.TestCase):
    def setUp(self):
        testenv.docker_runner(self)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)

    def test_zap_runs_as_its_own_user_with_network_only_to_the_pinned_address(self):
        calls = []
        with patch.object(engines.shutil, "which", return_value="/usr/bin/docker"), fake_docker(None, calls=calls):
            web.run_zap(HOST, f"https://{HOST}/", "104.21.32.173", self.work)
        (argv,) = calls
        image = argv.index(engines.IMAGES["zap"]["image"])
        options, arguments = argv[:image], argv[image + 1:]
        self.assertIn("@sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2", argv[image])
        self.assertEqual(arguments, ["zap.sh", web.HEAP, "-cmd", "-silent", "-autorun", "/zap/wrk/zap.yaml"])
        self.assertNotIn("--user", options)  # Java takes its home from passwd: ZAP runs as the image's uid 1000
        self.assertNotIn("HOME=/tmp", options)
        def values(flag):
            return [options[index + 1] for index, item in enumerate(options) if item == flag]
        for flag, value in (("--cap-drop", "ALL"), ("--security-opt", "no-new-privileges"), ("--memory", "3g"), ("--cpus", "2"),
                            ("--pids-limit", "512"), ("--network", "bridge"), ("--add-host", f"{HOST}:104.21.32.173"),
                            ("-v", f"{engines.host_path(self.work)}:/zap/wrk:rw"), ("--tmpfs", web.HOME)):
            self.assertIn(value, values(flag), flag)
        self.assertEqual((values("--network"), values("--add-host"), values("-v")),
                         (["bridge"], [f"{HOST}:104.21.32.173"], [f"{engines.host_path(self.work)}:/zap/wrk:rw"]))
        self.assertIn("--read-only", options)
        self.assertFalse(any(part.endswith(":/src:ro") for part in options), "no snapshot is ever mounted")
        self.assertNotIn("--pull", options)  # pinned by digest
        plan = json.loads((self.work / "zap.yaml").read_text())
        self.assertEqual(plan["env"]["contexts"][0]["urls"], [f"https://{HOST}/"])
        self.assertEqual(self.work.stat().st_mode & 0o777, 0o777)  # ZAP's user writes its report there

    def test_an_engine_running_as_its_image_user_never_mounts_a_snapshot(self):
        with self.assertRaises(ValueError):
            engines._run("zap", ["zap.sh"], self.work, image_user=True)

    def test_zap_is_listed_and_pulled_only_with_web_scans_on(self):
        with patch.object(engines, "engine_ready", return_value=True), patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": ""}):
            self.assertNotIn("zap", [row["tool"] for row in engines.engine_status()])
        with patch.object(engines, "engine_ready", return_value=True), patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": "1"}):
            self.assertIn("zap", [row["tool"] for row in engines.engine_status()])
        self.assertNotIn("zap", engines.BINARIES)  # never in the worker without a socket
        with patch.dict(os.environ, {"PITANGUS_ENGINE_RUNNER": "local"}):
            self.assertFalse(engines.engine_ready("zap"))


class ScanTests(unittest.TestCase):
    def setUp(self):
        testenv.docker_runner(self)
        which = patch.object(engines.shutil, "which", return_value="/usr/bin/docker")
        which.start()
        self.addCleanup(which.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.record = {"id": "a" * 24, "host": HOST, "url": f"https://{HOST}/", "kind": "web", "key": f"domain:{HOST}"}

    def test_findings_are_the_ones_an_import_of_the_same_sarif_would_store(self):
        document = real()
        foreign = json.loads(json.dumps(document["runs"][0]["results"][0]))
        foreign["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "https://cdn.example.net/app.js"
        foreign["ruleId"] = "10099"
        document["runs"][0]["results"].append(foreign)
        events, modes = [], []
        with fake_docker(document, modes=modes):
            scan = web.scan_domain(self.record, "104.21.32.173", data_dir=self.data_dir, progress=lambda level, message: events.append(level))
        imported = [item for run in sarif_import.parse(real()) for item in run["findings"]]
        self.assertEqual([item["fingerprint"] for item in scan["findings"]], [item["fingerprint"] for item in imported])
        self.assertEqual(len(scan["findings"]), 9)  # ZAP reports the root as https://host and https://host/: one finding each
        self.assertTrue(all(item["scanner"] == "dast" and item["path"].startswith(f"https://{HOST}/") for item in scan["findings"]))
        self.assertEqual((scan["type"], scan["variant"], scan["status"], scan["source"]["id"]), ("dast_scan", "baseline", "completed", f"domain:{HOST}"))
        self.assertEqual(scan["summary"]["dast"], 9)
        self.assertEqual([step["status"] for step in scan["steps"]], ["completed", "not_tested", "pending"])
        # Never the request or response ZAP attached, nor the response headers that came with them.
        stored = json.dumps(scan)
        for leaked in ("webRequest", "webResponse", "CF-RAY", "cf-nel", "user-agent"):
            self.assertNotIn(leaked, stored)
        self.assertEqual(events, ["info", "ok"])
        self.assertEqual(modes, [(0o777, 0o700)])  # open for ZAP's user, inside a folder only Pitangus can enter
        self.assertFalse(any((self.data_dir / "work").iterdir()), "the work folder is removed")

    def test_without_a_report_or_past_the_time_limit_the_scan_fails_with_zaps_reason(self):
        failure = "Automation plan failures:\n\tJob spider failed to access URL https://pitangus.dev/ : connect timed out\n"
        with fake_docker(None, returncode=1, stdout=failure), self.assertRaises(web.WebScanError) as caught:
            web.scan_domain(self.record, "104.21.32.173", data_dir=self.data_dir)
        self.assertIn("connect timed out", text(caught.exception.message, "en"))
        with patch("pitangus.modules.scanning.engines.subprocess.run", side_effect=subprocess.TimeoutExpired(["docker"], web.TIMEOUT)), \
                self.assertRaises(web.WebScanError) as caught:
            web.scan_domain(self.record, "104.21.32.173", data_dir=self.data_dir)
        self.assertIn("15", text(caught.exception.message, "en"))
        with fake_docker(real(), returncode=1):
            self.assertEqual(web.scan_domain(self.record, "104.21.32.173", data_dir=self.data_dir)["status"], "incomplete")


class GuardrailTests(unittest.TestCase):
    """Everything is checked again in the worker, right before ZAP reaches the site."""

    def setUp(self):
        testenv.docker_runner(self)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.jobs = ScanJobs(self.data_dir, worker=False)
        self.domain = verified_domain(self.data_dir, HOST)
        enabled = patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": "1"})
        enabled.start()
        self.addCleanup(enabled.stop)
        docker = patch("pitangus.modules.scanning.engines.docker_problem", return_value="")
        docker.start()
        self.addCleanup(docker.stop)

    def run_job(self, *, txt=True, addresses=None) -> dict:
        queued = self.jobs.enqueue_dast_scan(domain=self.domain, requested_by="jefa")
        values = ["v=spf1 -all", self.domain["txt_value"]] if txt is True else txt
        with patch.object(domains, "lookup_txt", return_value=values), \
                patch("pitangus.modules.sources.domains.socket.getaddrinfo", return_value=addresses or PUBLIC):
            self.jobs._execute({"kind": "dast_scan", "run_id": queued["id"], "domain_id": self.domain["id"]})
        with db.transaction(self.data_dir) as connection:  # what the worker loop does after _execute
            connection.execute(update(jobs).where(jobs.c.run_id == queued["id"]).values(status="done"))
        return load_run(self.data_dir, queued["id"])

    def refused(self, record: dict) -> str:
        self.assertEqual(record["status"], "failed")
        return text(record["progress"][-1]["message"], "en")

    def test_a_full_scan_lands_in_the_registry_and_an_import_of_the_same_report_adds_nothing(self):
        calls = []
        with patch.object(engines.shutil, "which", return_value="/usr/bin/docker"), fake_docker(real(), calls=calls):
            record = self.run_job()
        self.assertEqual((record["status"], record["type"], len(record["findings"])), ("completed", "dast_scan", 9))
        self.assertIn(f"{HOST}:104.21.32.173", calls[0])  # IPv4 first among the public answers
        state = findings_registry.load(self.data_dir, f"domain:{HOST}")
        self.assertEqual(sum(1 for entry in state["findings"].values() if entry["status"] == "open"), 9)
        outcome = import_sarif(self.data_dir, real(), asset=f"domain:{HOST}", requested_by="ci")
        self.assertEqual(outcome["runs"][0]["opened"], 0)
        self.assertEqual(len(findings_registry.load(self.data_dir, f"domain:{HOST}")["findings"]), 9)

    def test_off_by_default(self):
        with patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": ""}), \
                patch.object(web, "scan_domain", side_effect=AssertionError("scanned")):
            self.assertIn("PITANGUS_DAST_ENABLED", self.refused(self.run_job()))

    def test_a_txt_record_gone_since_verification_stops_it_and_withdraws_the_proof(self):
        with patch.object(web, "scan_domain", side_effect=AssertionError("scanned")):
            self.assertIn("TXT", self.refused(self.run_job(txt=["v=spf1 -all"])))
        self.assertFalse(domains.get_domain(self.data_dir, self.domain["id"])["verified"])

    def test_dns_not_answering_stops_it(self):
        with patch.object(web, "scan_domain", side_effect=AssertionError("scanned")):
            self.assertIn("DNS", self.refused(self.run_job(txt=None)))

    def test_an_expired_proof_stops_it(self):
        domains._mark(self.data_dir, self.domain["id"], verified_at=None, verified_until=None)
        with patch.object(web, "scan_domain", side_effect=AssertionError("scanned")):
            self.assertIn("verify it again", self.refused(self.run_job()))

    def test_private_loopback_link_local_and_metadata_addresses_stop_it(self):
        for address in ("10.0.0.5", "127.0.0.1", "169.254.169.254", "::1", "fd00::1", "100.64.0.1"):
            with self.subTest(address=address), patch.object(web, "scan_domain", side_effect=AssertionError("scanned")):
                message = self.refused(self.run_job(addresses=[*PUBLIC, (2, 1, 6, "", (address, 443))]))
                self.assertIn("private or reserved", message)

    def test_the_worker_without_a_docker_socket_says_it_needs_one(self):
        with patch.dict(os.environ, {"PITANGUS_ENGINE_RUNNER": "local"}), \
                patch.object(web, "scan_domain", side_effect=AssertionError("scanned")):
            self.assertIn("Docker runner", self.refused(self.run_job()))

    def test_one_web_scan_at_a_time(self):
        self.jobs.enqueue_dast_scan(domain=self.domain, requested_by="jefa")
        with self.assertRaises(BusyError):
            self.jobs.enqueue_dast_scan(domain=self.domain, requested_by="jefa")


class ApiTests(HttpCase):
    def setUp(self):
        super().setUp()
        from pitangus.modules.identity.auth import Users
        self.cookies = {}
        for name, role in (("jefa", "admin"), ("miembro", "member")):
            Users(self.data_dir).create(name, PASSWORD, role=role)
            self.cookies[role] = self.post("/api/auth/login", "login", {"username": name, "password": PASSWORD})[2][0].split("; ")[0]
        self.domain = verified_domain(self.data_dir, HOST)

    def send(self, body, role="admin"):
        return self.call("POST", "/api/domains/scans", body, {"Origin": ORIGIN, "X-Pitangus-Action": "scan-domain",
                                                              "Cookie": self.cookies[role], "Accept-Language": "en"})

    def test_only_administrators_launch_a_web_scan_of_a_verified_public_domain_with_scans_on(self):
        body = {"domain_id": self.domain["id"]}
        self.assertEqual(self.send(body, role="member")[0], 403)
        with patch.object(self.state.jobs, "enqueue_dast_scan", side_effect=AssertionError("queued")):
            with patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": ""}):
                status, answer, _ = self.send(body)
                self.assertEqual(status, 409)
                self.assertIn("PITANGUS_DAST_ENABLED", answer["error"])
                self.assertFalse(self.call("GET", "/api/domains", headers={"Cookie": self.cookies["member"]})[1]["dast"])
            with patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": "1"}):
                self.assertTrue(self.call("GET", "/api/domains", headers={"Cookie": self.cookies["member"]})[1]["dast"])
                self.assertEqual(self.send({"domain_id": "f" * 24})[0], 404)
                self.assertEqual(self.send({"domain_id": "../x"})[0], 400)
                self.assertEqual(self.send({"domain_id": self.domain["id"], "active": True})[0], 400)
                with resolving("10.1.2.3"):
                    status, answer, _ = self.send(body)
                self.assertEqual(status, 409)
                self.assertIn("private", answer["error"])
                unverified = verified_domain(self.data_dir, "other.example.com", verified=False)
                status, answer, _ = self.send({"domain_id": unverified["id"]})
                self.assertEqual((status, "verify it again" in answer["error"]), (409, True))
        with patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": "1"}), resolving("104.21.32.173"):
            with patch.object(self.state.jobs, "enqueue_dast_scan", return_value={"id": "r1", "status": "queued"}) as enqueue:
                status, answer, _ = self.send(body)
            self.assertEqual((status, answer["run"]["id"], answer["domain"]["host"]), (202, "r1", HOST))
            self.assertEqual(enqueue.call_args.kwargs["requested_by"], "jefa")
            with patch.object(self.state.jobs, "enqueue_dast_scan", side_effect=BusyError(msg("scanning.web.errors.busy"))):
                status, answer, _ = self.send(body)
            self.assertEqual(status, 409)
            self.assertIn("already queued or running", answer["error"])


if __name__ == "__main__":
    unittest.main()
