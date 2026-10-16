"""Passive web scans of a verified domain with ZAP: the guardrails before anything reaches the site, the container it
runs in, and findings identical to an import of the same SARIF."""

import json
import logging
import os
import re

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import select, update

import testenv
from pitangus.modules.findings import registry as findings_registry
from pitangus.modules.runs.imports import import_sarif
from pitangus.modules.runs.jobs import BusyError, ScanJobs
from pitangus.modules.runs.store import load_run
from pitangus.modules.runs.tables import jobs
from pitangus.modules.scanning import engines, openapi_spec, sarif_import, web
from pitangus.modules.sources import domains
from pitangus.shared import db, vault
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


def fake_docker(document: dict | None, *, returncode: int = 0, stdout: str = "", calls: list | None = None, modes: list | None = None,
                inputs: list | None = None, files: list | None = None):
    """`docker run` of ZAP: writes `document` as the SARIF report into the mounted work folder. `inputs`: what it got on
    its standard input (the plan); `files`: the names in the work folder while it ran."""
    def run(command, **kwargs):
        if calls is not None:
            calls.append(command)
        if inputs is not None:
            inputs.append(kwargs.get("input"))
        mount = command[command.index("-v") + 1]
        work = Path(mount.rsplit(":", 2)[0])
        if modes is not None:
            modes.append((work.stat().st_mode & 0o777, work.parent.stat().st_mode & 0o777))
        if files is not None:
            files.append({path.name: path.read_text() for path in work.iterdir()})
        if document is not None:
            (work / web.REPORT).write_text(json.dumps(document))
        return subprocess.CompletedProcess(command, returncode, stdout, "")
    return patch("pitangus.modules.scanning.engines.subprocess.run", side_effect=run)


class PlanTests(unittest.TestCase):
    def test_the_plan_crawls_and_reads_only_that_host_and_never_attacks(self):
        plan = web.plan(HOST, f"https://{HOST}/")
        self.assertEqual([job["type"] for job in plan["jobs"]], ["passiveScan-config", "spider", "spiderAjax", "passiveScan-wait", "report"])
        spider = plan["jobs"][1]["parameters"]
        self.assertEqual((spider["maxDuration"], spider["postForm"], spider["context"]), (web.SPIDER_MINUTES, False, web.CONTEXT))
        # The AJAX spider only follows links, inside the context, time-boxed: no button, no input, no random value.
        ajax = plan["jobs"][2]["parameters"]
        self.assertEqual({key: ajax[key] for key in ("context", "url", "maxDuration", "inScopeOnly", "scopeCheck", "clickDefaultElems", "elements",
                                                     "randomInputs", "logoutAvoidance", "numberOfBrowsers", "browserId", "enableExtensions")},
                         {"context": web.CONTEXT, "url": f"https://{HOST}/", "maxDuration": web.AJAX_MINUTES, "inScopeOnly": True,
                          "scopeCheck": "Strict", "clickDefaultElems": False, "elements": ["a"], "randomInputs": False, "logoutAvoidance": True,
                          "numberOfBrowsers": 1, "browserId": "firefox-headless", "enableExtensions": False})
        self.assertNotIn("user", ajax)
        # The passive scanner looks only at the scope and the information-leak rules are on whatever the image's defaults.
        config = plan["jobs"][0]
        self.assertEqual(config["parameters"], {"scanOnlyInScope": True, "enableTags": False, "disableAllRules": False})
        rules = {rule["id"]: rule["threshold"] for rule in config["rules"]}
        self.assertTrue({10062, 10023, 10024, 10025, 10027, 10003} <= set(rules))
        self.assertFalse({"Off", "High"} & set(rules.values()))
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
        self.assertEqual(plan["jobs"][4]["parameters"], {"template": "sarif-json", "reportDir": "/zap/wrk", "reportFile": "zap"})

    def test_the_plan_is_serialized_so_a_hostile_url_cannot_add_a_job(self):
        hostile = 'https://pitangus.dev/x"\n  - type: activeScan\n#'
        parsed = json.loads(web.plan_text(HOST, hostile))
        self.assertEqual([job["type"] for job in parsed["jobs"]], ["passiveScan-config", "spider", "spiderAjax", "passiveScan-wait", "report"])
        self.assertEqual((parsed["jobs"][1]["parameters"]["url"], parsed["jobs"][2]["parameters"]["url"]), (hostile, hostile))
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
        calls, inputs = [], []
        with patch.object(engines.shutil, "which", return_value="/usr/bin/docker"), fake_docker(None, calls=calls, inputs=inputs):
            web.run_zap(web.plan_text(HOST, f"https://{HOST}/"), {HOST: "104.21.32.173"}, self.work)
        (argv,) = calls
        image = argv.index(engines.IMAGES["zap"]["image"])
        options, arguments = argv[:image], argv[image + 1:]
        self.assertIn("@sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2", argv[image])
        # The plan arrives on standard input and is written in the memory-only home, never in the host's work folder.
        self.assertEqual(arguments, ["sh", "-c", f'umask 077 && cat > {web.PLAN} && {{ exec zap.sh "$@" {web.PLAN}; }}', "zap.sh", web.HEAP,
                                     "-cmd", "-silent", "-autorun"])
        self.assertTrue(web.PLAN.startswith("/home/zap/") and web.HOME.startswith("/home/zap:"))
        self.assertIn("-i", options)
        self.assertEqual(options[options.index("--dns") + 1], "127.0.0.1")  # only the pinned names resolve
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
        # ZAP's home stays noexec: only its webdriver folder (geckodriver, for the AJAX spider's Firefox) may run code.
        tmpfs = {value.split(":", 1)[0]: value.split(":", 1)[1].split(",") for value in values("--tmpfs")}
        self.assertIn("noexec", tmpfs["/home/zap"])
        self.assertIn("noexec", tmpfs["/home/zap/.ZAP"])
        self.assertIn("exec", tmpfs["/home/zap/.ZAP/webdriver"])
        self.assertTrue(all({"nosuid", "nodev"} <= set(flags) for flags in tmpfs.values()))
        self.assertFalse(any(part.endswith(":/src:ro") for part in options), "no snapshot is ever mounted")
        self.assertNotIn("--pull", options)  # pinned by digest
        plan = json.loads(inputs[0])
        self.assertEqual(plan["env"]["contexts"][0]["urls"], [f"https://{HOST}/"])
        self.assertEqual(list(self.work.iterdir()), [])
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
        # The CSP misconfigured on every page is one finding of the site, and so is the same comment of the shared template
        # or the same Cache-Control value on every page; the hashed script, one of its own.
        self.assertEqual(len(scan["findings"]), 4)
        self.assertTrue(all(item["scanner"] == "dast" and item["path"].startswith(f"https://{HOST}/") for item in scan["findings"]))
        self.assertEqual((scan["type"], scan["variant"], scan["status"], scan["source"]["id"]), ("dast_scan", "baseline", "completed", f"domain:{HOST}"))
        self.assertEqual(scan["summary"]["dast"], 4)
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
        self.assertIn(str((web.TIMEOUT + 60 * (web.AJAX_MINUTES + 1)) // 60), text(caught.exception.message, "en"))
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
        self.assertEqual((record["status"], record["type"], len(record["findings"])), ("completed", "dast_scan", 4))
        self.assertIn(f"{HOST}:104.21.32.173", calls[0])  # IPv4 first among the public answers
        state = findings_registry.load(self.data_dir, f"domain:{HOST}")
        self.assertEqual(sum(1 for entry in state["findings"].values() if entry["status"] == "open"), 4)
        outcome = import_sarif(self.data_dir, real(), asset=f"domain:{HOST}", requested_by="ci")
        self.assertEqual(outcome["runs"][0]["opened"], 0)
        self.assertEqual(len(findings_registry.load(self.data_dir, f"domain:{HOST}")["findings"]), 4)

    def test_off_by_default(self):
        with patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": ""}), \
                patch.object(web, "scan_domain", side_effect=AssertionError("scanned")):
            # Off in the panel: says where an administrator turns it on, not a variable the panel can't change.
            refused = self.refused(self.run_job())
            self.assertTrue("Analysis engines" in refused or "Motores de análisis" in refused, refused)
            self.assertNotIn("PITANGUS_DAST_ENABLED", refused)
        with patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": "0"}), \
                patch.object(web, "scan_domain", side_effect=AssertionError("scanned")):
            self.assertIn("PITANGUS_DAST_ENABLED", self.refused(self.run_job()))  # pinned off by the server: named

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
        HttpCase.setUp(self)  # explicit: ScanContractTests borrows this setUp
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
                self.assertIn("Settings → Analysis engines", answer["error"])
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

    def test_the_exposure_check_runs_with_the_full_dast_off_and_only_anonymously(self):
        body = {"domain_id": self.domain["id"], "mode": "exposure"}
        with patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": ""}), resolving("104.21.32.173"):
            with patch.object(self.state.jobs, "enqueue_dast_scan", return_value={"id": "r2", "status": "queued"}) as enqueue:
                status, answer, _ = self.send(body)
            self.assertEqual((status, answer["run"]["id"]), (202, "r2"))
            self.assertEqual(enqueue.call_args.kwargs["options"]["mode"], "exposure")
            self.assertEqual(self.send({**body, "use_headers": True})[0], 400)
            self.assertEqual(self.send({"domain_id": self.domain["id"], "mode": "web"})[0], 409)  # the full DAST stays off
        self.assertEqual(self.send(body, role="member")[0], 403)

    def test_the_exposure_engines_are_listed_without_the_full_dast(self):
        with patch.object(engines, "engine_ready", return_value=True), patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": ""}):
            listed = {row["tool"] for row in engines.engine_status()}
        self.assertTrue({"nuclei", "testssl", "httpx"} <= listed)
        self.assertFalse({"zap", "katana", "subfinder"} & listed)


SECRET = "pkfixture_4f0c2b1e9a77d3c5aa01"  # gitleaks:allow
SPEC = {"openapi": "3.0.3", "info": {"title": "Agenda", "version": "1", "description": "internal-only-description"},
        "servers": [{"url": "http://localhost:8080/v1"}],
        "paths": {"/users": {"get": {"responses": {"200": {"description": "ok"}}},
                             "post": {"responses": {"201": {"description": "created"}}}},
                  "/users/{id}": {"parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                                  "get": {"responses": {"200": {"description": "ok"}}, "servers": [{"url": "https://evil.example"}]},
                                  "delete": {"responses": {"204": {"description": "gone"}}}},
                  "/health": {"head": {"responses": {"200": {"description": "ok"}}}}}}


class ScopeAndAccessPlanTests(unittest.TestCase):
    def test_listed_subdomains_widen_the_context_and_each_gets_a_spider_wildcards_only_the_context(self):
        plan = web.plan(HOST, f"https://{HOST}/", hosts=[HOST, "docs.pitangus.dev"], wildcards=["*.pitangus.dev"])
        (context,) = plan["env"]["contexts"]
        self.assertEqual(context["urls"], [f"https://{HOST}/", "https://docs.pitangus.dev/"])
        self.assertEqual([job["parameters"]["url"] for job in plan["jobs"] if job["type"] == "spider"],
                         [f"https://{HOST}/", "https://docs.pitangus.dev/"])
        wildcard = context["includePaths"][2]
        for url in ("https://a.pitangus.dev/", "https://a.b.pitangus.dev/x?y=1"):
            self.assertTrue(re.fullmatch(wildcard, url), url)
        for url in ("https://pitangus.dev/", "https://evilpitangus.dev/", "https://a.pitangus.dev.evil.example/", "http://a.pitangus.dev/"):
            self.assertFalse(re.fullmatch(wildcard, url), url)

    def test_saved_headers_go_through_a_replacer_limited_to_the_scope(self):
        plan = web.plan(HOST, f"https://{HOST}/", hosts=[HOST, "docs.pitangus.dev"], headers=[("X-Api-Key", SECRET)])
        replacer = plan["jobs"][1]
        self.assertEqual((replacer["type"], replacer["parameters"]), ("replacer", {"deleteAllRules": True}))
        (rule,) = replacer["rules"]
        self.assertEqual({key: rule[key] for key in ("matchType", "matchString", "matchRegex", "replacementString", "tokenProcessing")},
                         {"matchType": "req_header", "matchString": "X-Api-Key", "matchRegex": False, "replacementString": SECRET,
                          "tokenProcessing": False})
        for url in (f"https://{HOST}/", "https://docs.pitangus.dev/x"):
            self.assertTrue(re.fullmatch(rule["url"], url), url)
        for url in ("https://evil.example/", "https://api.pitangus.dev/", f"http://{HOST}/"):
            self.assertFalse(re.fullmatch(rule["url"], url), url)
        self.assertNotIn("activeScan", json.dumps(plan))

    def test_api_mode_adds_the_documented_endpoints_to_the_crawl(self):
        plan = web.plan(HOST, f"https://{HOST}/", api={"file": "/zap/wrk/spec.json", "target": f"https://{HOST}/v1"})
        self.assertEqual([job["type"] for job in plan["jobs"]], ["passiveScan-config", "spider", "spiderAjax", "openapi", "passiveScan-wait", "report"])
        self.assertEqual(plan["jobs"][3]["parameters"], {"apiFile": "/zap/wrk/spec.json", "context": web.CONTEXT, "targetUrl": f"https://{HOST}/v1"})
        self.assertEqual(plan["env"]["contexts"][0]["urls"], [f"https://{HOST}/", f"https://{HOST}/v1"])


class SecretAndApiScanTests(unittest.TestCase):
    def setUp(self):
        testenv.docker_runner(self)
        which = patch.object(engines.shutil, "which", return_value="/usr/bin/docker")
        which.start()
        self.addCleanup(which.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.record = {"id": "a" * 24, "host": HOST, "url": f"https://{HOST}/", "kind": "web", "key": f"domain:{HOST}"}

    def test_header_values_reach_zap_only_through_its_standard_input(self):
        document = real()
        document["runs"][0]["results"][0]["message"]["text"] += f" Request had X-Api-Key: {SECRET}"
        document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"] = {"snippet": {"text": f"key={SECRET}"}}
        inputs, files, calls, events = [], [], [], []
        with fake_docker(document, inputs=inputs, files=files, calls=calls, stdout=f"Job replacer set {SECRET}"):
            scan = web.scan_domain(self.record, "104.21.32.173", data_dir=self.data_dir, headers=[("X-Api-Key", SECRET)],
                                   progress=lambda level, message: events.append(message))
        self.assertIn(SECRET, inputs[0])                       # in the plan, on ZAP's standard input
        self.assertNotIn(SECRET, json.dumps(calls))            # never on the command line
        self.assertNotIn(SECRET, json.dumps(files))            # nor in a file on the host
        self.assertNotIn(SECRET, json.dumps(scan) + json.dumps(events))
        self.assertEqual(scan["scope"]["headers"], ["X-Api-Key"])
        self.assertEqual({item["web"]["coverage"] for item in scan["findings"]}, {"baseline+headers"})
        self.assertIn("[redacted]", json.dumps(scan))
        # A failing plan's reason is shown to people: scrubbed too.
        with fake_docker(None, returncode=1, stdout=f"Automation plan failures:\n\tJob replacer failed: {SECRET}\n"), \
                self.assertRaises(web.WebScanError) as caught:
            web.scan_domain(self.record, "104.21.32.173", data_dir=self.data_dir, headers=[("X-Api-Key", SECRET)])
        self.assertNotIn(SECRET, json.dumps(caught.exception.message))

    def test_a_session_check_that_fails_before_or_after_leaves_the_scan_incomplete(self):
        check = f"https://{HOST}/account"
        asked = []

        def answering(*codes):
            replies = iter(codes)

            def get(host, address, path, **options):
                asked.append((host, address, path, options["headers"]))
                return next(replies), b""
            return get

        def scan(*codes, url=check):
            with fake_docker(real()), patch.object(domains, "https_get", side_effect=answering(*codes)):
                return web.scan_domain(self.record, "104.21.32.173", data_dir=self.data_dir, headers=[("X-Api-Key", SECRET)],
                                       session_check=url)

        steps = lambda record: {step["id"]: step["status"] for step in record["steps"]}  # noqa: E731
        limits = lambda record: " ".join(text(item, "en") for item in record["limitations"])  # noqa: E731
        alive = scan(200, 204)
        self.assertEqual((alive["status"], steps(alive)["session"]), ("completed", "completed"))
        self.assertIn("answered with them before and after", limits(alive))
        # Asked at the pinned address, with the saved headers, before anything else and once more at the end.
        self.assertEqual(asked, [(HOST, "104.21.32.173", "/account", [("X-Api-Key", SECRET)])] * 2)
        self.assertNotIn(SECRET, json.dumps(alive))
        for codes in ((200, 302), (401, 200)):
            lost = scan(*codes)
            self.assertEqual((lost["status"], steps(lost)["session"]), ("incomplete", "partial"), codes)
            self.assertIn("instead of a 2xx", limits(lost))
        outside = scan(url="https://other.pitangus.dev/account")
        self.assertEqual(outside["status"], "incomplete")
        self.assertIn("outside this scan's scope", limits(outside))
        # Without a check page, the scan says the headers weren't verified, as before.
        with fake_docker(real()), patch.object(domains, "https_get", side_effect=AssertionError("asked")):
            unchecked = web.scan_domain(self.record, "104.21.32.173", data_dir=self.data_dir, headers=[("X-Api-Key", SECRET)])
        self.assertEqual(unchecked["status"], "completed")
        self.assertNotIn("session", steps(unchecked))
        self.assertIn("no session check page", limits(unchecked))

    def test_api_mode_sends_zap_only_the_safe_operations_aimed_at_the_domain_and_keeps_only_a_hash(self):
        api = {**openapi_spec.parse(json.dumps(SPEC).encode(), "agenda.json"), "source": "upload"}
        inputs, files = [], []
        with fake_docker(real(), inputs=inputs, files=files):
            scan = web.scan_domain(self.record, "104.21.32.173", data_dir=self.data_dir, api=api)
        given = json.loads(files[0][web.SPEC])
        self.assertEqual({route: sorted(set(item) & {"get", "head", "post", "delete"}) for route, item in given["paths"].items()},
                         {"/users": ["get"], "/users/{id}": ["get"], "/health": ["head"]})
        self.assertEqual(given["servers"], [{"url": f"https://{HOST}/v1"}])
        self.assertNotIn("evil.example", files[0][web.SPEC])
        plan = json.loads(inputs[0])
        self.assertEqual(next(job for job in plan["jobs"] if job["type"] == "openapi")["parameters"]["targetUrl"], f"https://{HOST}/v1")
        self.assertEqual((scan["variant"], scan["target"], scan["api"]), ("api", f"https://{HOST}/v1",
                                                                         {"sha256": api["sha256"], "endpoints": 3, "source": "upload"}))
        self.assertNotIn("internal-only-description", json.dumps(scan))
        self.assertEqual({item["web"]["coverage"] for item in scan["findings"]}, {"api:" + api["sha256"][:16]})


class ScrubTests(unittest.TestCase):
    def test_a_value_is_scrubbed_whole_and_by_the_pieces_a_tool_may_echo_alone(self):
        parts = web.secret_parts([("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.c2VjcmV0"),
                                  ("Cookie", "sessionid=4f0c2b1e9a77d3c5; theme=dark"), ("X-Env", "prod")])
        self.assertEqual(parts, ["sessionid=4f0c2b1e9a77d3c5; theme=dark", "Bearer eyJhbGciOiJIUzI1NiJ9.c2VjcmV0",
                                 "eyJhbGciOiJIUzI1NiJ9.c2VjcmV0", "4f0c2b1e9a77d3c5"])
        echoed = {"message": "JWT eyJhbGciOiJIUzI1NiJ9.c2VjcmV0 in a page; cookie sessionid=4f0c2b1e9a77d3c5 without HttpOnly", "env": "prod"}
        self.assertEqual(web.scrub(echoed, parts),
                         {"message": "JWT [redacted] in a page; cookie sessionid=[redacted] without HttpOnly", "env": "prod"})


def text_rows(row):
    return {**row, "reason": text(row["reason"], "es")}


class CoverageTests(unittest.TestCase):
    """A web scan only marks fixed what a scan like it had seen, on a host it looked at."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.domain = verified_domain(self.data_dir, HOST)

    def scan(self, findings, *, variant="baseline", coverage="baseline", hosts=(HOST,), steps=(), reached=None, tool=None, **scope):
        from pitangus.modules.runs.store import save_repository_scan
        base = web.findings_from(real(), HOST)[0][0]
        made = []
        for path, kind in findings:
            made.append({**base, "path": path, "fingerprint": f"{path}|{kind}", "web": {"coverage": kind}, **({"tool": tool} if tool else {})})
        summary = {"files": len(made), "dependencies": 0, "candidates": len(made), "severities": {}, "priorities": {}, "kev": 0,
                   "fixable": 0, "tools": []}
        return save_repository_scan(self.data_dir, {"type": "dast_scan", "status": "completed", "source": domains.source_for(self.domain),
                                                    "target": f"https://{HOST}/", "variant": variant, "findings": made, "context": "",
                                                    "scope": {"hosts": list(hosts), "wildcards": [], "coverage": coverage,
                                                              **({"reached": reached} if reached is not None else {}), **scope},
                                                    "summary": summary, "steps": list(steps), "limitations": [], "owasp_coverage": []})

    def states(self):
        """Each finding by where it is and the kind of scan that saw it (its fingerprint here; in v2 its key is the
        identity of its family): one entry each, so two that became one family would show."""
        entries = findings_registry.load(self.data_dir, f"domain:{HOST}")["findings"].values()
        return {f"{entry['finding']['path']}|{(entry['finding'].get('web') or {}).get('coverage') or 'baseline'}": entry["status"] for entry in entries}

    def keys(self):
        return {digest: entry["status"] for digest, entry in findings_registry.load(self.data_dir, f"domain:{HOST}")["findings"].items()}

    def test_a_web_scan_measures_owasp_coverage_with_the_tools_that_ran(self):
        # ZAP's alerts carry CWEs, not categories: the category comes from OWASP's own CWE mapping.
        steps = [{"id": "dast", "name": "ZAP", "status": "completed", "detail": ""},
                 {"id": "dast-testssl", "name": "testssl.sh", "status": "completed", "detail": ""},
                 {"id": "dast-nuclei", "name": "nuclei", "status": "skipped", "detail": ""}]
        saved = self.scan([(f"https://{HOST}/a", "baseline")], steps=steps)
        rows = {row["id"]: text_rows(row) for row in load_run(self.data_dir, saved["id"])["owasp_coverage"]}
        self.assertEqual(len(rows), 10)
        self.assertEqual(rows["A04"]["status"], "partial")
        self.assertIn("testssl.sh", rows["A04"]["reason"])
        self.assertEqual(rows["A02"]["status"], "partial")
        self.assertNotIn("nuclei", rows["A02"]["reason"])  # skipped: it checked nothing
        self.assertEqual(rows["A05"]["status"], "not_tested")
        self.assertIn("pruebas activas", rows["A05"]["reason"])
        self.assertIn("desde fuera", rows["A09"]["reason"])
        self.assertNotIn("repositorio", " ".join(row["reason"] for row in rows.values()))
        categories = [row for row in rows.values() if row["findings"]]
        self.assertTrue(categories)  # the ZAP finding lands in its category, counted
        self.assertTrue(all(row["status"] == "partial" for row in categories))

    def test_api_header_and_subdomain_findings_survive_a_scan_that_didnt_look_there(self):
        self.scan([(f"https://{HOST}/a", "baseline"), (f"https://{HOST}/admin", "baseline+headers"),
                   (f"https://{HOST}/v1/users", "api:0123456789abcdef"), ("https://docs.pitangus.dev/", "baseline")],  # gitleaks:allow
                  hosts=(HOST, "docs.pitangus.dev"))
        self.scan([], hosts=(HOST,))  # an anonymous crawl of the root only
        self.assertEqual(self.states(), {f"https://{HOST}/a|baseline": "fixed", f"https://{HOST}/admin|baseline+headers": "open",
                                         f"https://{HOST}/v1/users|api:0123456789abcdef": "open", "https://docs.pitangus.dev/|baseline": "open"})  # gitleaks:allow
        self.scan([], variant="api", coverage="api:0123456789abcdef")  # gitleaks:allow
        self.assertEqual(self.states()[f"https://{HOST}/v1/users|api:0123456789abcdef"], "fixed")  # gitleaks:allow
        self.scan([], coverage="baseline+headers", hosts=(HOST, "docs.pitangus.dev"))
        self.assertEqual(self.states()[f"https://{HOST}/admin|baseline+headers"], "fixed")
        self.assertEqual(self.states()["https://docs.pitangus.dev/|baseline"], "open")


    def test_only_a_page_the_crawl_reached_vouches_for_a_zap_finding(self):
        """The crawl is bounded: a page this scan didn't get to proves nothing, so its findings stay open."""
        self.assertEqual(web.findings_from(real(), HOST)[0][0]["tool"].lower(), "zap")
        self.scan([(f"https://{HOST}/a", "baseline"), (f"https://{HOST}/deep/page?id=7", "baseline")])
        self.scan([], reached=[f"https://{HOST}/a"])
        # Stored, a URL keeps its query's names, never its values (shared/render.py).
        self.assertEqual(self.states(), {f"https://{HOST}/a|baseline": "fixed", f"https://{HOST}/deep/page?id=***|baseline": "open"})
        self.scan([], reached=domains_pages([f"https://{HOST}/deep/page?id=9#top"]))  # another visit to the same page counts
        self.assertEqual(self.states()[f"https://{HOST}/deep/page?id=***|baseline"], "fixed")

    def test_a_nuclei_page_finding_is_only_fixed_on_a_page_its_page_pass_requested(self):
        self.scan([(f"https://{HOST}/", "baseline"), (f"https://{HOST}/admin/", "baseline"), (f"https://{HOST}/old", "baseline")], tool="nuclei")
        self.scan([], probed=[f"https://{HOST}/admin"])  # the root is probed on every run; /old wasn't requested this time
        self.assertEqual(self.states(), {f"https://{HOST}/|baseline": "fixed", f"https://{HOST}/admin/|baseline": "fixed",
                                         f"https://{HOST}/old|baseline": "open"})

    def test_a_header_scan_without_a_session_check_fixes_nothing_behind_the_login(self):
        self.scan([(f"https://{HOST}/admin", "baseline+headers")])
        self.scan([], coverage="baseline+headers", session_checked=False)
        self.assertEqual(self.states(), {f"https://{HOST}/admin|baseline+headers": "open"})
        self.scan([], coverage="baseline+headers", session_checked=True)
        self.assertEqual(self.states(), {f"https://{HOST}/admin|baseline+headers": "fixed"})


    def test_alerts_stored_per_page_before_fold_into_the_host_finding_instead_of_being_fixed(self):
        """0.14 made a site-wide header one finding per host. The per-page findings stored before (some already marked
        fixed by the first scan that ran this version) fold into it: none is reported fixed when the header is still missing."""
        from pitangus.modules.scanning import sarif_import
        document = real()
        csp = [item for item in document["runs"][0]["results"] if item["ruleId"] == "10055"]

        def former(result):  # how a result was keyed before folding: by its page as reported
            path = sarif_import._location(result, [], web=True)[0]
            message = sarif_import._text(result.get("message"), sarif_import.MESSAGE_MAX)
            return sarif_import._stable("sarif", "zap", sarif_import._key(result, "10055", path, "", message, web=True))

        old = sorted({former(result) for result in csp})  # https://host and https://host/ were one already: two pages
        self.assertEqual(len(old), 2)
        (host,) = [item for item in web.findings_from(document, HOST)[0][0:] if item["rule_id"].startswith("10055")]
        # The root was keyed the same way before: only the other page needs remembering.
        self.assertIn(host["fingerprint"], old)
        self.assertEqual(host["previous_fingerprints"], [digest for digest in old if digest != host["fingerprint"]])
        base = {key: value for key, value in host.items() if key != "previous_fingerprints"}
        self.scan_findings([{**base, "fingerprint": digest, "path": f"https://{HOST}/{index}"} for index, digest in enumerate(old)])
        self.scan_findings([])  # what the first scan after the change did: nothing under the old fingerprints
        self.assertEqual(set(self.keys().values()), {"fixed"})
        (stored,) = self.scan_findings([host])["findings"]   # in v2, its family's identity
        self.assertEqual(self.keys(), {stored["fingerprint"]: "open"})

    def scan_findings(self, findings):
        from pitangus.modules.runs.store import save_repository_scan
        summary = {"files": len(findings), "dependencies": 0, "candidates": len(findings), "severities": {}, "priorities": {}, "kev": 0,
                   "fixable": 0, "tools": []}
        return save_repository_scan(self.data_dir, {"type": "dast_scan", "status": "completed", "source": domains.source_for(self.domain),
                                                    "target": f"https://{HOST}/", "variant": "baseline", "findings": findings, "context": "",
                                                    "scope": {"hosts": [HOST], "wildcards": [], "coverage": "baseline"},
                                                    "summary": summary, "steps": [], "limitations": [], "owasp_coverage": []})


def domains_pages(urls):
    return [domains.page_of(url) for url in urls]


class ScopeGuardrailTests(unittest.TestCase):
    """The worker checks the scope, the headers and the definition again before ZAP starts."""

    setUp = GuardrailTests.setUp
    refused = GuardrailTests.refused

    def run_queued(self, options, *, addresses=None, proof=True):
        queued = self.jobs.enqueue_dast_scan(domain=self.domain, requested_by="jefa", options=options)
        with db.transaction(self.data_dir) as connection:
            payload = connection.execute(select(jobs.c.payload).where(jobs.c.run_id == queued["id"])).scalar_one()

        def resolve(host, *args, **kwargs):
            return [(2, 1, 6, "", ((addresses or {}).get(host, "104.21.32.173"), 443))]
        with patch.object(domains, "lookup_txt", return_value=[self.domain["txt_value"]] if proof else []), \
                patch("pitangus.modules.sources.domains.socket.getaddrinfo", side_effect=resolve):
            self.jobs._execute({**payload, "kind": "dast_scan", "run_id": queued["id"]})
        with db.transaction(self.data_dir) as connection:
            left = connection.execute(select(jobs.c.payload).where(jobs.c.run_id == queued["id"])).scalar_one()
            connection.execute(update(jobs).where(jobs.c.run_id == queued["id"]).values(status="done"))
        return load_run(self.data_dir, queued["id"]), left

    def test_every_listed_host_is_pinned_and_a_private_one_stops_the_scan(self):
        calls = []
        with patch.object(engines.shutil, "which", return_value="/usr/bin/docker"), fake_docker(real(), calls=calls):
            record, _ = self.run_queued({"mode": "web", "hosts": ["docs.pitangus.dev", "*.pitangus.dev"]},
                                        addresses={"docs.pitangus.dev": "104.21.32.174"})
        self.assertEqual(record["status"], "completed")
        self.assertIn(f"{HOST}:104.21.32.173", calls[0])
        self.assertIn("docs.pitangus.dev:104.21.32.174", calls[0])
        self.assertEqual(record["scope"]["hosts"], [HOST, "docs.pitangus.dev"])
        self.assertEqual(record["scope"]["wildcards"], ["*.pitangus.dev"])
        with patch.object(web, "scan_domain", side_effect=AssertionError("scanned")):
            record, _ = self.run_queued({"mode": "web", "hosts": ["docs.pitangus.dev"]}, addresses={"docs.pitangus.dev": "10.0.0.7"})
        self.assertIn("docs.pitangus.dev", self.refused(record))

    def test_a_file_or_meta_proof_never_reaches_subdomains(self):
        domains._mark(self.data_dir, self.domain["id"], proof_method="meta")
        with patch.object(domains, "_fetch_proof", return_value=(True, None)), \
                patch.object(web, "scan_domain", side_effect=AssertionError("scanned")):
            record, _ = self.run_queued({"mode": "web", "hosts": ["docs.pitangus.dev"]})
        self.assertIn("DNS TXT", self.refused(record))

    def test_saved_headers_are_read_by_the_worker_and_never_stored(self):
        from pitangus.modules.sources import domain_headers
        domain_headers.save(self.domain["id"], "Authorization", f"Bearer {SECRET}")
        inputs, records = [], []
        handler = _Records(records)
        logger = logging.getLogger("pitangus")
        logger.addHandler(handler)
        self.addCleanup(logger.removeHandler, handler)
        with patch.object(engines.shutil, "which", return_value="/usr/bin/docker"), fake_docker(real(), inputs=inputs):
            record, payload = self.run_queued({"mode": "web", "use_headers": True})
        self.assertEqual(record["status"], "completed")
        self.assertIn(SECRET, inputs[0])
        self.assertNotIn(SECRET, json.dumps(record) + json.dumps(payload) + "\n".join(records))
        with db.transaction(self.data_dir) as connection:
            stored = json.dumps([list(row) for row in connection.execute(select(vault.vault_entries.c.name, vault.vault_entries.c.data))])
        self.assertNotIn(SECRET, stored)  # encrypted in the vault
        # The domain's session check goes with the headers to the scan.
        domain_headers.set_check(self.data_dir, self.domain, f"https://{HOST}/account")
        with patch.object(web, "scan_domain", side_effect=web.WebScanError("stop")) as scanned:
            self.run_queued({"mode": "web", "use_headers": True})
        self.assertEqual(scanned.call_args.kwargs["session_check"], f"https://{HOST}/account")
        domain_headers.remove(self.domain["id"], "Authorization")
        with patch.object(web, "scan_domain", side_effect=AssertionError("scanned")):
            record, _ = self.run_queued({"mode": "web", "use_headers": True})
        self.assertIn("no saved headers", self.refused(record))

    def test_the_sealed_definition_leaves_the_job_as_soon_as_the_worker_opens_it(self):
        parsed = openapi_spec.parse(json.dumps(SPEC).encode(), "agenda.json")
        sealed = vault.seal({key: parsed[key] for key in ("document", "version", "server", "sha256", "endpoints")}, "dast-spec")
        self.assertNotIn("internal-only-description", sealed)
        with patch.object(engines.shutil, "which", return_value="/usr/bin/docker"), fake_docker(real()):
            record, payload = self.run_queued({"mode": "api", "spec": sealed, "spec_sha256": parsed["sha256"], "spec_endpoints": 3})
        self.assertEqual((record["status"], record["variant"], record["api"]["endpoints"]), ("completed", "api", 3))
        self.assertNotIn("spec", payload)
        self.assertNotIn("internal-only-description", json.dumps(record))
        # A definition by URL is fetched from the pinned address of a host of the scope, never followed elsewhere.
        fetched = []

        def get(host, address, path, **kwargs):
            fetched.append((host, address, path))
            return 200, json.dumps(SPEC).encode()
        with patch.object(engines.shutil, "which", return_value="/usr/bin/docker"), fake_docker(real()), \
                patch.object(domains, "https_get", side_effect=get):
            record, _ = self.run_queued({"mode": "api", "spec_url": f"https://{HOST}/openapi.json?v=2"})
        self.assertEqual((record["status"], record["api"]["source"], fetched), ("completed", "url", [(HOST, "104.21.32.173", "/openapi.json?v=2")]))
        with patch.object(domains, "https_get", return_value=(301, b"")), patch.object(web, "scan_domain", side_effect=AssertionError("scanned")):
            record, _ = self.run_queued({"mode": "api", "spec_url": f"https://{HOST}/openapi.json"})
        self.assertIn("301", self.refused(record))


class _Records(logging.Handler):
    """Every log line with its extra fields, as raw as they were emitted."""

    def __init__(self, sink: list):
        super().__init__(level=logging.DEBUG)
        self.sink = sink

    def emit(self, record):
        self.sink.append(json.dumps({key: str(value) for key, value in record.__dict__.items()}) + record.getMessage())


class ScanContractTests(HttpCase):
    setUp = ApiTests.setUp
    send = ApiTests.send

    def scan(self, body):
        with patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": "1"}), resolving("104.21.32.173"), \
                patch.object(self.state.jobs, "enqueue_dast_scan", return_value={"id": "r1", "status": "queued"}) as enqueue:
            status, answer, _ = self.send({"domain_id": self.domain["id"], **body})
        return status, answer, enqueue

    def spec(self, content: bytes, filename="agenda.yaml"):
        import base64
        return {"filename": filename, "content_base64": base64.b64encode(content).decode()}

    def test_the_request_contract(self):
        status, answer, enqueue = self.scan({})
        self.assertEqual((status, answer["run_id"], answer["run"]["id"]), (202, "r1", "r1"))
        self.assertEqual(enqueue.call_args.kwargs["options"], {"mode": "web", "hosts": [], "use_headers": False})
        status, answer, enqueue = self.scan({"hosts": ["docs.pitangus.dev", "*.pitangus.dev"]})
        self.assertEqual((status, enqueue.call_args.kwargs["options"]["hosts"]), (202, ["docs.pitangus.dev", "*.pitangus.dev"]))
        yaml_spec = ("openapi: 3.0.3\ninfo: {title: Agenda, version: '1'}\npaths:\n  /users:\n    get:\n      responses:\n"
                     "        '200': {description: ok}\n    post:\n      responses:\n        '201': {description: created}\n").encode()
        status, answer, enqueue = self.scan({"mode": "api", "spec": self.spec(yaml_spec)})
        options = enqueue.call_args.kwargs["options"]
        self.assertEqual((status, options["mode"], options["spec_endpoints"]), (202, "api", 1))
        self.assertNotIn("Agenda", options["spec"])  # sealed with the master key
        status, _, enqueue = self.scan({"mode": "api", "spec_url": f"https://{HOST}/openapi.json"})
        self.assertEqual((status, enqueue.call_args.kwargs["options"]["spec_url"]), (202, f"https://{HOST}/openapi.json"))

    def test_everything_is_validated_before_anything_is_queued(self):
        good = self.spec(json.dumps(SPEC).encode(), "agenda.json")
        for body, expected, words in (
                ({"mode": "web", "spec": good}, 400, None),
                ({"mode": "api"}, 400, None),
                ({"mode": "api", "spec": good, "spec_url": f"https://{HOST}/o.json"}, 400, None),
                ({"mode": "active"}, 400, None),
                ({"hosts": [f"h{index}.pitangus.dev" for index in range(21)]}, 400, None),
                ({"hosts": ["evil.example"]}, 400, "isn't pitangus.dev"),
                ({"hosts": ["pitangus.dev.evil.example"]}, 400, "isn't pitangus.dev"),
                ({"hosts": ["*.*.pitangus.dev"]}, 400, "valid host"),
                ({"use_headers": True}, 409, "no saved headers"),
                ({"mode": "api", "spec": self.spec(b"openapi: 3.0.0\npaths: {}\n", "agenda.txt")}, 400, ".json, .yaml"),
                ({"mode": "api", "spec": self.spec(b"a: &x [1]\nb: *x\n")}, 400, "aliases"),
                ({"mode": "api", "spec": {"filename": "a.json", "content_base64": "%%%%"}}, 400, "base64"),
                ({"mode": "api", "spec": self.spec(json.dumps({**SPEC, "paths": {"/a": {"get": {"$ref": "https://evil.example/x"}}}}).encode(), "a.json")},
                 400, "$ref"),
                ({"mode": "api", "spec": self.spec(json.dumps({**SPEC, "paths": {"/a": {"post": {}}}}).encode(), "a.json")}, 400, "GET or HEAD"),
                ({"mode": "api", "spec_url": "https://evil.example/openapi.json"}, 400, "isn't a host of this scan"),
                ({"mode": "api", "spec_url": f"http://{HOST}/openapi.json"}, 400, "HTTPS"),
                ({"mode": "api", "spec_url": f"https://{HOST}:8443/openapi.json"}, 400, "HTTPS")):
            with self.subTest(body=str(body)[:80]):
                status, answer, enqueue = self.scan(body)
                self.assertEqual(status, expected, answer)
                if words:
                    self.assertIn(words, answer["error"])
                enqueue.assert_not_called()
        with resolving("10.1.2.3"), patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": "1"}):
            status, answer, _ = self.send({"domain_id": self.domain["id"], "hosts": ["docs.pitangus.dev"]})
        self.assertEqual(status, 409)
        domains._mark(self.data_dir, self.domain["id"], proof_method="file")
        status, answer, _ = self.scan({"hosts": ["docs.pitangus.dev"]})
        self.assertEqual(status, 409)
        self.assertIn("DNS TXT", answer["error"])

    def test_a_definition_over_five_megabytes_is_refused(self):
        big = b"openapi: 3.0.0\npaths: {}\n#" + b"x" * openapi_spec.MAX_BYTES
        status, answer, enqueue = self.scan({"mode": "api", "spec": self.spec(big)})
        self.assertEqual(status, 400)
        enqueue.assert_not_called()


if __name__ == "__main__":
    unittest.main()
