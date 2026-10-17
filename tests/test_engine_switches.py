"""Engines turned on and off from the panel (Settings → Analysis engines): one resolver everywhere, the server's variable
wins and locks the switch, every change is audited, and an engine that is off or whose image is missing is declared not
run, never a clean pass."""

import logging
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import testenv
from pitangus.modules.findings import registry
from pitangus.modules.scanning import engine_switches, engines, plan as scan_plan, repository, rule_set, web_tools
from pitangus.modules.scanning.engines import EngineStep, ScanContext, run_engines
from pitangus.modules.runs.jobs import ScanJobs
from pitangus.modules.runs.tables import jobs as jobs_table
from pitangus.shared import db
from pitangus.shared.i18n import localize, text

from sqlalchemy import select
from test_auth import ORIGIN, PASSWORD, HttpCase

ALL_VARIABLES = {switch.setting: "" for switch in engine_switches.SWITCHES}
ADMIN = {"username": "jefa"}


class ResolverTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.data_dir = Path(folder.name)
        clean = patch.dict(os.environ, ALL_VARIABLES)
        clean.start()
        self.addCleanup(clean.stop)

    def test_defaults_core_on_and_checkov_grype_and_the_full_web_scan_off(self):
        state = engine_switches.resolve(self.data_dir)
        self.assertEqual({key for key, item in state.items() if not item["enabled"]}, {"checkov", "grype", "dast"})
        self.assertTrue(all(item["source"] == "default" and not item["locked"] for item in state.values()))

    def test_the_panel_decides_unless_the_server_sets_the_variable(self):
        engine_switches.set_switch(self.data_dir, "checkov", True, user=ADMIN)
        engine_switches.set_switch(self.data_dir, "opengrep", False, user=ADMIN)
        state = engine_switches.resolve(self.data_dir)
        self.assertEqual((state["checkov"]["enabled"], state["checkov"]["source"], state["checkov"]["by"]), (True, "workspace", "jefa"))
        self.assertFalse(state["opengrep"]["enabled"])
        self.assertFalse(engine_switches.enabled("opengrep", self.data_dir))
        with patch.dict(os.environ, {"PITANGUS_CHECKOV_ENABLED": "0", "PITANGUS_OPENGREP_ENABLED": "1"}):
            state = engine_switches.resolve(self.data_dir)
            self.assertEqual((state["checkov"]["enabled"], state["checkov"]["locked"], state["checkov"]["source"]), (False, True, "server"))
            self.assertEqual((state["opengrep"]["enabled"], state["opengrep"]["locked"]), (True, True))
            with self.assertRaises(engine_switches.SwitchError) as caught:
                engine_switches.set_switch(self.data_dir, "checkov", True, user=ADMIN)
            self.assertIn("PITANGUS_CHECKOV_ENABLED", text(caught.exception.message, "en"))
        # Without a database (a bare CLI scan) only the environment and the defaults count.
        self.assertTrue(engine_switches.resolve(None)["opengrep"]["enabled"])

    def test_every_change_is_kept_with_who_and_when_and_logged(self):
        with self.assertLogs("pitangus.engines", logging.INFO) as logs:
            engine_switches.set_switch(self.data_dir, "trivy", False, user=ADMIN)
            engine_switches.set_switch(self.data_dir, "trivy", True, user={"username": "ana"})
        history = engine_switches.history(self.data_dir)
        self.assertEqual([(item["engine"], item["enabled"], item["by"]) for item in history], [("trivy", True, "ana"), ("trivy", False, "jefa")])
        self.assertTrue(all(item["at"] for item in history))
        self.assertTrue(any(record.getMessage() == "engine_switched" and getattr(record, "reason", "").startswith("trivy off")
                            and getattr(record, "user", "") == "jefa" for record in logs.records))
        with self.assertRaises(engine_switches.SwitchError):
            engine_switches.set_switch(self.data_dir, "nmap", True, user=ADMIN)

    def test_a_malformed_document_falls_back_to_the_defaults(self):
        from pitangus.shared import documents
        documents.save(self.data_dir, engine_switches.DOCUMENT, {"engines": ["opengrep"]})
        self.assertTrue(engine_switches.resolve(self.data_dir)["opengrep"]["enabled"])
        documents.save(self.data_dir, engine_switches.IMAGES_DOCUMENT, {"preparing": {"trivy": {"at": "2026-10-15T10:00:00"}}})
        self.assertNotEqual(engine_switches.image_status(self.data_dir)["engines"]["trivy"]["status"], "preparing")

    def test_a_kind_of_check_left_without_engines_is_said(self):
        engine_switches.set_switch(self.data_dir, "betterleaks", False, user=ADMIN)
        self.assertNotIn("secrets", engine_switches.uncovered(engine_switches.resolve(self.data_dir)))  # Trivy still looks
        engine_switches.set_switch(self.data_dir, "trivy", False, user=ADMIN)
        state = engine_switches.resolve(self.data_dir)
        self.assertEqual(engine_switches.uncovered(state, ("secrets", "iac", "images", "sast")), ["secrets", "iac", "images"])
        said = [text(item, "en") for item in engine_switches.uncovered_limitations(state, ("secrets",))]
        self.assertEqual(said, ["Every engine for secrets is turned off: Pitangus didn't check it, and what it found there before stays open."])


class RunTests(unittest.TestCase):
    """What a scan does with the switches: an engine off isn't run and is declared so; a missing image the same."""

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.data_dir = Path(folder.name)
        clean = patch.dict(os.environ, ALL_VARIABLES)
        clean.start()
        self.addCleanup(clean.stop)

    def test_an_engine_turned_off_in_the_panel_is_not_run_and_its_step_says_where_to_turn_it_on(self):
        engine_switches.set_switch(self.data_dir, "opengrep", False, user=ADMIN)
        ran: list[str] = []
        steps = [EngineStep(key, lambda context, key=key: ran.append(key) or engines._result(key, "completed", ""), "scanning.progress.trivy")
                 for key in ("opengrep", "trivy")]
        with engine_switches.server_analysis():
            results = run_engines(steps, ScanContext(Path("."), self.data_dir, {}), lambda *_: None)
        self.assertEqual(ran, ["trivy"])
        self.assertEqual((results["opengrep"]["status"], results["opengrep"]["disabled"]), ("not_tested", True))
        self.assertEqual(text(results["opengrep"]["detail"], "es"),
                         "Opengrep: no ejecutado (desactivado). Un administrador lo activa en Ajustes → Motores de análisis; "
                         "lo que encontró antes sigue abierto y nunca se da por remediado.")
        # The server's variable is named only when it is what keeps the engine off.
        with patch.dict(os.environ, {"PITANGUS_OPENGREP_ENABLED": "0"}):
            off = engines.switched_off("opengrep", engine_switches.resolve(self.data_dir))
        self.assertIn("PITANGUS_OPENGREP_ENABLED", text(off["detail"], "en"))
        self.assertNotIn("PITANGUS_", text(results["opengrep"]["detail"], "en"))
        # A one-shot scan (`pitangus scan`, the Action, the hook) has no panel: it names the variable instead.
        one_shot = run_engines(steps, ScanContext(Path("."), self.data_dir, {}), lambda *_: None)
        self.assertEqual(text(one_shot["opengrep"]["detail"], "en"),
                         "Opengrep: not run (disabled). PITANGUS_OPENGREP_ENABLED=1 turns it on; what it found before stays open, never fixed.")

    def test_the_configuration_declares_engines_off_so_nothing_they_found_is_fixed(self):
        engine_switches.set_switch(self.data_dir, "betterleaks", False, user=ADMIN)
        switches = engine_switches.resolve(self.data_dir)
        declared = rule_set.code(None, switches)["engines"]
        self.assertEqual((declared["betterleaks"], declared["checkov"], declared["zizmor"] if "zizmor" in declared else None),
                         ({"off": True}, {"off": True}, None))
        self.assertIn("rules", declared["opengrep"])  # an engine that runs declares what it always did
        record = {"status": "completed", "type": "repository_scan", "configuration": {"engines": declared},
                  "summary": {"tools": [{"name": "betterleaks", "status": "not_tested"}]}}
        finding = {"tool": "betterleaks", "path": "app.py", "scanner": "secrets", "rule_id": "aws-access-token"}
        self.assertEqual(registry.configuration_cause(record, finding), "engine_off")
        self.assertEqual(rule_set.image(switches)["engines"], {"grype": {"off": True}, "checkov": {"off": True}})

    def test_a_secret_pass_with_both_engines_off_reads_nothing_and_fixes_nothing(self):
        for key in ("betterleaks", "trivy"):
            engine_switches.set_switch(self.data_dir, key, False, user=ADMIN)
        root = self.data_dir / "snapshot"
        secrets = repository.secrets_root(root)
        secrets.mkdir(parents=True)
        (secrets / ".env").write_text("TOKEN=abc\n")
        with patch.object(engines, "_run", side_effect=AssertionError("an engine ran")):
            found = repository.scan_credentials(root, self.data_dir, None, engines=True, switches=engine_switches.resolve(self.data_dir))
        self.assertEqual(found["findings"], [])
        self.assertEqual(set(found["unexamined"]), {"betterleaks", "trivy"})

    def test_a_server_analysis_declares_a_missing_image_and_never_pulls_it_mid_scan(self):
        testenv.docker_runner(self)
        with patch.object(engines, "docker_available", return_value=True), patch.object(engines, "image_available", return_value=False), \
                patch.object(engines, "_run", side_effect=AssertionError("ran without its image")), \
                patch.object(engines, "pull_image", side_effect=AssertionError("pulled mid-scan")), engines.declaring_missing_images():
            reason = engines.unavailable("trivy", None)
            result = engines.run_trivy(self.data_dir, self.data_dir / "cache", {}, None, self.data_dir)
        self.assertEqual(reason["$t"], "scanning.engines.image_missing")
        self.assertEqual((result["status"], result["detail"]["$t"]), ("not_tested", "scanning.engines.image_missing"))
        record = {"status": "completed", "type": "repository_scan", "summary": {"tools": [{"name": "trivy", "status": result["status"]}]}}
        self.assertEqual(registry.unproven_reason(record, {"tool": "trivy", "path": "package.json", "scanner": "sca"}), "engine_blind")

    def test_a_one_shot_scan_pulls_a_missing_image_by_digest_and_runs_the_engine(self):
        """`pitangus scan`, the Action and the hook have no worker to prepare anything: they pull, as before 0.15."""
        from test_secret_rules import _Engines
        testenv.docker_runner(self)
        present: set[str] = set()
        pulled: list[str] = []
        fake = _Engines([])
        snapshot = self.data_dir / "snapshot"
        snapshot.mkdir()
        (snapshot / "app.py").write_text("print('hi')\n")
        scan = threading.get_ident()

        def pull(key):
            # Only this scan's pulls: the patch is module-wide, and a worker thread may be running in this process.
            if threading.get_ident() == scan:
                pulled.append(key)
                present.add(key)
        with patch.object(engines, "docker_available", return_value=True), \
                patch.object(engines, "image_available", side_effect=lambda key: key in present), \
                patch.object(engines, "pull_image", side_effect=pull), \
                patch.object(engines, "_run", side_effect=fake):
            result = engines.run_betterleaks(snapshot, None)
        self.assertEqual((pulled, result["status"]), (["betterleaks"], "completed"))
        self.assertEqual([call["key"] for call in fake.calls], ["betterleaks"])
        # A pull that fails says so, without promising a preparation nobody will make.
        with patch.object(engines, "docker_available", return_value=True), patch.object(engines, "image_available", return_value=False), \
                patch.object(engines, "pull_image", return_value=engines.msg("scanning.engines.action.pull_failed")):
            said = text(engines.unavailable("zizmor", None), "en")
        self.assertIn("couldn't be downloaded", said)
        self.assertNotIn("being prepared", said)

    def test_the_scan_plan_and_the_web_tools_follow_the_switches(self):
        engine_switches.set_switch(self.data_dir, "zizmor", False, user=ADMIN)
        engine_switches.set_switch(self.data_dir, "nuclei", False, user=ADMIN)
        with patch.object(scan_plan, "files_of", return_value=[".github/workflows/ci.yml"]), \
                patch.object(scan_plan, "engine_ready", return_value=True):
            planned = localize(scan_plan.plan("github:o/r", installation_id=7, data_dir=self.data_dir), "en")
        self.assertIn("zizmor: turned off (Settings → Analysis engines).", planned["skips"])
        self.assertFalse(any("zizmor" in line for line in planned["runs"]))
        with engine_switches.server_analysis():  # web scans only run as the worker's jobs
            ready = web_tools.readiness(engine_switches.resolve(self.data_dir))
        self.assertEqual(ready["nuclei"]["$t"], "scanning.engines.disabled")


class ApiTests(HttpCase):
    def setUp(self):
        HttpCase.setUp(self)
        clean = patch.dict(os.environ, ALL_VARIABLES)
        clean.start()
        self.addCleanup(clean.stop)
        from pitangus.modules.identity.auth import Users
        self.cookies = {}
        for name, role in (("jefa", "admin"), ("miembro", "member")):
            Users(self.data_dir).create(name, PASSWORD, role=role)
            self.cookies[role] = self.post("/api/auth/login", "login", {"username": name, "password": PASSWORD})[2][0].split("; ")[0]

    def send(self, path, action, body, role="admin"):
        return self.call("POST", path, body, {"Origin": ORIGIN, "X-Pitangus-Action": action, "Cookie": self.cookies[role],
                                              "Accept-Language": "en"})

    def test_only_an_admin_reads_and_changes_them_with_the_action_header(self):
        self.assertEqual(self.call("GET", "/api/engines", headers={"Cookie": self.cookies["member"]})[0], 403)
        self.assertEqual(self.send("/api/engines", "engine-switch", {"engine": "grype", "enabled": True}, role="member")[0], 403)
        # Without its action header (CSRF), the change is refused before it reaches the engines.
        status, _, _ = self.call("POST", "/api/engines", {"engine": "grype", "enabled": True},
                                 {"Origin": ORIGIN, "Cookie": self.cookies["admin"]})
        self.assertEqual(status, 403)
        self.assertFalse(engine_switches.resolve(self.data_dir)["grype"]["enabled"])
        status, body, _ = self.call("GET", "/api/engines", headers={"Cookie": self.cookies["admin"]})
        self.assertEqual(status, 200)
        self.assertEqual([row["key"] for row in body["engines"]], [switch.key for switch in engine_switches.SWITCHES])
        status, body, _ = self.send("/api/engines", "engine-switch", {"engine": "grype", "enabled": True})
        self.assertEqual(status, 200, body)
        grype = next(row for row in body["engines"] if row["key"] == "grype")
        self.assertEqual((grype["enabled"], grype["source"], grype["changed_by"]), (True, "workspace", "jefa"))
        self.assertEqual(body["history"][0]["engine"], "grype")
        self.assertEqual(self.send("/api/engines", "engine-switch", {"engine": "nmap", "enabled": True})[0], 400)

    def test_a_switch_the_server_pins_shows_locked_and_cant_be_changed(self):
        with patch.dict(os.environ, {"PITANGUS_TRIVY_ENABLED": "1"}):
            body = self.call("GET", "/api/engines", headers={"Cookie": self.cookies["admin"]})[1]
            trivy = next(row for row in body["engines"] if row["key"] == "trivy")
            self.assertEqual((trivy["locked"], trivy["source"], trivy["setting"]), (True, "server", "PITANGUS_TRIVY_ENABLED"))
            status, answer, _ = self.send("/api/engines", "engine-switch", {"engine": "trivy", "enabled": False})
        self.assertEqual(status, 409)
        self.assertIn("PITANGUS_TRIVY_ENABLED", answer["error"])

    def test_prepare_queues_one_download_and_the_worker_records_what_is_there(self):
        engine_switches.record_images(self.data_dir, {key: key != "checkov" for key in engines.IMAGES}, runner="docker")
        rows = {row["key"]: row for row in self.call("GET", "/api/engines", headers={"Cookie": self.cookies["admin"]})[1]["engines"]}
        self.assertEqual((rows["checkov"]["image"], rows["trivy"]["image"]), ("missing", "ready"))
        self.assertEqual(self.send("/api/engines/prepare", "prepare-engine", {"engine": "checkov"}, role="member")[0], 403)
        for _ in range(2):  # asked twice while it's preparing: one job
            status, body, _ = self.send("/api/engines/prepare", "prepare-engine", {"engine": "checkov"})
            self.assertEqual(status, 200)
        self.assertEqual(next(row for row in body["engines"] if row["key"] == "checkov")["image"], "preparing")
        with db.transaction(self.data_dir) as connection:
            queued = connection.execute(select(jobs_table.c.kind, jobs_table.c.payload).where(jobs_table.c.kind == "engine_prepare")).all()
        self.assertEqual([(kind, payload["engine"]) for kind, payload in queued], [("engine_prepare", "checkov")])
        worker = ScanJobs(self.data_dir, worker=False)
        with patch.object(engines, "prepare", return_value=None) as prepared, \
                patch.object(engines, "image_readiness", return_value=dict.fromkeys(engines.IMAGES, True)), \
                patch.object(engines, "runner", return_value="docker"):
            worker._execute({"kind": "engine_prepare", "engine": "checkov", "run_id": None})
        prepared.assert_called_once_with("checkov")
        rows = {row["key"]: row for row in self.call("GET", "/api/engines", headers={"Cookie": self.cookies["admin"]})[1]["engines"]}
        self.assertEqual((rows["checkov"]["image"], rows["checkov"]["image_problem"]), ("ready", None))

    def queued(self) -> list[str]:
        with db.transaction(self.data_dir) as connection:
            return sorted(payload["engine"] for payload in connection.execute(
                select(jobs_table.c.payload).where(jobs_table.c.kind == "engine_prepare")).scalars())

    def test_turning_an_engine_on_prepares_its_missing_images_at_once(self):
        engine_switches.record_images(self.data_dir, {key: key not in ("grype", "zap", "katana") for key in engines.IMAGES}, runner="docker")
        body = self.send("/api/engines", "engine-switch", {"engine": "grype", "enabled": True})[1]
        self.assertEqual(next(row for row in body["engines"] if row["key"] == "grype")["image"], "preparing")
        self.assertEqual(self.queued(), ["grype"])
        self.send("/api/engines", "engine-switch", {"engine": "grype", "enabled": False})
        self.send("/api/engines", "engine-switch", {"engine": "grype", "enabled": True})
        self.assertEqual(self.queued(), ["grype"])  # still under way: not queued twice
        # The full web scan brings katana with it; an engine whose images are there queues nothing.
        self.send("/api/engines", "engine-switch", {"engine": "dast", "enabled": True})
        self.send("/api/engines", "engine-switch", {"engine": "checkov", "enabled": True})
        self.assertEqual(self.queued(), ["dast", "grype", "katana"])

    def test_the_worker_prepares_every_engine_that_is_on_and_lacks_its_image(self):
        worker = ScanJobs(self.data_dir, worker=False)
        # After an upgrade Trivy's digest changed and its image is missing; Checkov is off, so it isn't pulled.
        ready = {key: key not in ("trivy", "checkov") for key in engines.IMAGES}
        with patch.object(engines, "image_readiness", return_value=ready), patch.object(engines, "runner", return_value="docker"), \
                patch.object(engines, "docker_available", return_value=True):
            worker._record_images()
            worker._record_images()
        self.assertEqual(self.queued(), ["trivy"])
        # It failed (offline): the worker waits before trying again on its own; the button retries at once.
        engine_switches.prepare_finished(self.data_dir, "trivy", ready=ready, runner="docker", problem=engines.msg("scanning.engines.action.pull_failed"))
        with patch.object(engines, "image_readiness", return_value=ready), patch.object(engines, "runner", return_value="docker"), \
                patch.object(engines, "docker_available", return_value=True):
            worker._record_images()
        self.assertEqual(self.queued(), ["trivy"])
        self.assertTrue(worker.prepare_engine("trivy", by="jefa"))
        self.assertEqual(self.queued(), ["trivy", "trivy"])
        # Without Docker there is nothing to pull with: no job.
        engine_switches.prepare_finished(self.data_dir, "trivy", ready=ready, runner="docker")
        with patch.object(engines, "image_readiness", return_value=ready), patch.object(engines, "docker_available", return_value=False):
            worker._record_images()
        self.assertEqual(self.queued(), ["trivy", "trivy"])

    def test_a_missing_image_step_says_it_is_being_prepared(self):
        self.assertIn("will run in the next scan", text(engines.msg("scanning.engines.image_missing", engine="Trivy"), "en"))

    def test_an_analysis_is_picked_up_while_an_image_is_being_prepared(self):
        """A pull runs in its own lane: the analyses queued meanwhile don't wait for it."""
        from pitangus.modules.runs import queue as job_queue
        release, pulling = threading.Event(), threading.Event()

        def slow_prepare(key):
            pulling.set()
            release.wait(30)
            return None
        worker = ScanJobs(self.data_dir, worker=False)
        worker.idle_poll = 0.1
        job_queue.enqueue(self.data_dir, "engine_prepare", {"engine": "trivy", "by": "worker"})
        analysis = job_queue.enqueue(self.data_dir, "periodic", {"task": "nothing"})
        with patch.object(engines, "prepare", side_effect=slow_prepare), \
                patch.object(engines, "image_readiness", return_value=dict.fromkeys(engines.IMAGES, True)), \
                patch.object(ScanJobs, "_record_images"):
            thread = threading.Thread(target=worker.run_worker, daemon=True)
            thread.start()
            try:
                self.assertTrue(pulling.wait(10))
                for _ in range(100):
                    with db.transaction(self.data_dir) as connection:
                        status = connection.execute(select(jobs_table.c.status).where(jobs_table.c.id == analysis)).scalar_one()
                    if status == "done":
                        break
                    worker._stop.wait(0.1)
                self.assertEqual(status, "done")
                self.assertFalse(release.is_set())  # the pull is still under way
            finally:
                release.set()
                testenv.stop_worker(self, worker)
                thread.join(10)

    def test_a_failed_preparation_says_why(self):
        engine_switches.record_images(self.data_dir, dict.fromkeys(engines.IMAGES, False), runner="docker")
        self.send("/api/engines/prepare", "prepare-engine", {"engine": "grype"})
        worker = ScanJobs(self.data_dir, worker=False)
        with patch.object(engines, "prepare", return_value=engines.msg("scanning.engines.action.pull_failed")), \
                patch.object(engines, "image_readiness", return_value=dict.fromkeys(engines.IMAGES, False)):
            worker._execute({"kind": "engine_prepare", "engine": "grype", "run_id": None})
        grype = next(row for row in self.call("GET", "/api/engines", headers={"Cookie": self.cookies["admin"], "Accept-Language": "en"})[1]["engines"]
                     if row["key"] == "grype")
        self.assertEqual((grype["image"], grype["image_problem"]), ("missing", "download failed"))


if __name__ == "__main__":
    unittest.main()
