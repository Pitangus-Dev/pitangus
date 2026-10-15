"""Test users of a domain: saved encrypted and write-only, picked per web scan, and signed in with by ZAP's browser
authentication through environment variables, never through the plan, a file, the command line or a log."""

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
from pitangus.modules.runs.jobs import ScanJobs
from pitangus.modules.runs.store import load_run
from pitangus.modules.runs.tables import jobs
from pitangus.modules.scanning import engines, web, web_tools
from pitangus.modules.sources import domains, test_users
from pitangus.modules.sources.tables import domain_test_users
from pitangus.shared import db, vault
from pitangus.shared.i18n import text

from test_auth import ORIGIN, PASSWORD, HttpCase
from test_sarif_import import verified_domain
from test_web_scan import HOST, real

PASSWORD_1 = "Correct-Horse-Battery-71"  # gitleaks:allow
SEED = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
USERNAME = "qa-admin@pitangus.dev"


class _Records(logging.Handler):
    def __init__(self, sink: list):
        super().__init__(level=logging.DEBUG)
        self.sink = sink

    def emit(self, record):
        self.sink.append(json.dumps({key: str(value) for key, value in record.__dict__.items()}) + record.getMessage())


def capture_logs(case) -> list:
    records: list = []
    handler = _Records(records)
    logger = logging.getLogger("pitangus")
    logger.addHandler(handler)
    case.addCleanup(logger.removeHandler, handler)
    return records


def password_user(**extra) -> dict:
    return {"name": "Admin user", "method": "password", "username": USERNAME, "password": PASSWORD_1, **extra}


def totp_user(**extra) -> dict:
    return {"name": "MFA user", "method": "password_totp", "username": "mfa@pitangus.dev", "password": "Second-Pass-0042",  # gitleaks:allow
            "totp": {"secret": SEED.lower()[:16] + " " + SEED.lower()[16:], "digits": 6, "period": 30, "algorithm": "SHA1"}, **extra}


def stored_rows(data_dir: Path) -> str:
    with db.transaction(data_dir) as connection:
        return json.dumps([[str(value) for value in row] for row in connection.execute(select(domain_test_users))])


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.domain = verified_domain(self.data_dir, HOST)

    def test_secrets_are_sealed_bound_to_their_row_and_never_listed(self):
        first = test_users.save(self.data_dir, self.domain, password_user(), by="jefa")
        second = test_users.save(self.data_dir, self.domain, totp_user(login_url=f"https://{HOST}/login#/sign-in", notes="Read-only role"))
        listed = test_users.list_users(self.data_dir, self.domain["id"])
        self.assertEqual([(item["name"], item["method"], item["username"], item["applies_to"]) for item in listed],
                         [("Admin user", "password", USERNAME, HOST), ("MFA user", "password_totp", "mfa@pitangus.dev", HOST)])
        self.assertEqual((listed[1]["login_url"], listed[1]["notes"], first["created_by"]), (f"https://{HOST}/login#/sign-in", "Read-only role", "jefa"))
        self.assertEqual(set(first), {"id", "name", "method", "username", "login_url", "check_url", "notes", "applies_to", "created_by", "created_at",
                                      "updated_at", "last_used_at"})
        everything = json.dumps(listed) + json.dumps([first, second]) + stored_rows(self.data_dir)
        for secret in (PASSWORD_1, "Second-Pass-0042", SEED, SEED.lower()[:16]):  # gitleaks:allow
            self.assertNotIn(secret, everything)
        self.assertNotIn(USERNAME, stored_rows(self.data_dir))  # the username is sealed too
        # A sealed value moved to another row doesn't open.
        with db.transaction(self.data_dir) as connection:
            sealed = connection.execute(select(domain_test_users.c.secret).where(domain_test_users.c.id == first["id"])).scalar_one()
            connection.execute(update(domain_test_users).where(domain_test_users.c.id == second["id"]).values(secret=sealed))
        with self.assertRaises(vault.VaultError):
            test_users.list_users(self.data_dir, self.domain["id"])

    def test_a_change_keeps_secrets_left_out_and_switching_method_adds_or_drops_the_seed(self):
        saved = test_users.save(self.data_dir, self.domain, password_user())
        scope = {"hosts": [HOST], "wildcards": []}
        test_users.save(self.data_dir, self.domain, {"id": saved["id"], "name": "Admin", "method": "password", "username": "admin2"})
        (opened,) = test_users.credentials(self.data_dir, self.domain, [saved["id"]], scope)
        self.assertEqual((opened["name"], opened["username"], opened["password"], opened["totp"]), ("Admin", "admin2", PASSWORD_1, None))
        with self.assertRaises(test_users.TestUserError):  # a TOTP method needs a seed
            test_users.save(self.data_dir, self.domain, {"id": saved["id"], "name": "Admin", "method": "password_totp", "username": "admin2"})
        test_users.save(self.data_dir, self.domain, {"id": saved["id"], "name": "Admin", "method": "password_totp", "username": "admin2",
                                                     "totp": {"secret": SEED, "digits": 8, "period": 60, "algorithm": "sha256"}})
        (opened,) = test_users.credentials(self.data_dir, self.domain, [saved["id"]], scope)
        self.assertEqual(opened["totp"], {"secret": SEED, "digits": 8, "period": 60, "algorithm": "SHA256"})
        self.assertTrue(opened["last_used_at"] is None or opened["last_used_at"])
        test_users.save(self.data_dir, self.domain, {"id": saved["id"], "name": "Admin", "method": "password", "username": "admin2",
                                                     "password": "Brand-New-Pass-99"})
        (opened,) = test_users.credentials(self.data_dir, self.domain, [saved["id"]], scope)
        self.assertEqual((opened["password"], opened["totp"]), ("Brand-New-Pass-99", None))
        self.assertTrue(test_users.list_users(self.data_dir, self.domain["id"])[0]["last_used_at"])

    def test_what_is_refused(self):
        test_users.save(self.data_dir, self.domain, password_user())
        for change in ({"name": "admin USER"}, {"name": ""}, {"name": "a\nb"}, {"method": "magic_link"}, {"method": "email_code"},
                       {"username": "a\x00b"}, {"username": "${PITANGUS_LOGIN_2_PASSWORD}"}, {"password": "pa${HOME}ss"},
                       {"password": "line\nbreak"}, {"password": None},
                       {"login_url": f"http://{HOST}/login"}, {"login_url": f"https://{HOST}:8443/login"}, {"login_url": "https://evil.example/login"},
                       {"login_url": f"https://user:pw@{HOST}/"}, {"login_url": f"https://{HOST}.evil.example/"},
                       {"applies_to": "evil.example"}, {"applies_to": "localhost"}, {"notes": "x" * 1001}, {"check_url": f"http://{HOST}/account"},
                       {"check_url": "https://evil.example/account"}, {"check_url": f"https://{HOST}/${{HOME}}"},
                       {"method": "password_totp"}, {"method": "password_totp", "totp": {"secret": "not base32!"}},
                       {"method": "password_totp", "totp": {"secret": "JBSWY3DP"}},
                       {"method": "password_totp", "totp": {"secret": SEED, "digits": 5}},
                       {"method": "password_totp", "totp": {"secret": SEED, "period": 7}},
                       {"method": "password_totp", "totp": {"secret": SEED, "algorithm": "MD5"}}):
            with self.subTest(change=change), self.assertRaises(test_users.TestUserError):
                test_users.save(self.data_dir, self.domain, {**password_user(name="Other"), **change} if "name" not in change
                                else {**password_user(), **change})
        for index in range(test_users.LIMIT - 1):
            test_users.save(self.data_dir, self.domain, password_user(name=f"User {index}"))
        with self.assertRaises(test_users.TestUserError) as caught:
            test_users.save(self.data_dir, self.domain, password_user(name="Eleventh"))
        self.assertIn("at most 10", text(caught.exception.message, "en"))

    def test_a_scan_picks_at_most_three_users_of_its_own_domain_signing_in_inside_its_scope(self):
        other = verified_domain(self.data_dir, "other.example.com")
        mine = test_users.save(self.data_dir, self.domain, password_user())
        sub = test_users.save(self.data_dir, self.domain, password_user(name="Docs", applies_to="docs.pitangus.dev"))
        sso = test_users.save(self.data_dir, self.domain, password_user(name="SSO", login_url="https://login.pitangus.dev/start"))
        foreign = test_users.save(self.data_dir, other, password_user())
        scope = {"hosts": [HOST], "wildcards": []}
        self.assertEqual([user["id"] for user in test_users.check_selection(self.data_dir, self.domain, [mine["id"]], scope)], [mine["id"]])
        for ids, words in (([foreign["id"]], "doesn't exist"), (["z" * 24], "doesn't exist"), ([sub["id"]], "docs.pitangus.dev"),
                           ([sso["id"]], "login.pitangus.dev"), ([mine["id"]] * 2 + ["a" * 24, "b" * 24, "c" * 24], "at most 3")):
            with self.subTest(words=words), self.assertRaises(test_users.TestUserError) as caught:
                test_users.check_selection(self.data_dir, self.domain, ids, scope)
            self.assertIn(words, text(caught.exception.message, "en"))
        wide = {"hosts": [HOST, "docs.pitangus.dev", "login.pitangus.dev"], "wildcards": []}
        self.assertEqual(len(test_users.check_selection(self.data_dir, self.domain, [sub["id"], sso["id"]], wide)), 2)

    def test_removing_a_user_or_its_domain_deletes_it(self):
        saved = test_users.save(self.data_dir, self.domain, password_user())
        kept = test_users.save(self.data_dir, self.domain, totp_user())
        test_users.remove(self.data_dir, self.domain["id"], saved["id"])
        self.assertEqual([item["id"] for item in test_users.list_users(self.data_dir, self.domain["id"])], [kept["id"]])
        with self.assertRaises(test_users.TestUserError):
            test_users.remove(self.data_dir, self.domain["id"], saved["id"])
        domains.remove_domain(self.data_dir, self.domain["id"])
        self.assertEqual(stored_rows(self.data_dir), "[]")
        self.assertEqual(test_users.counts(self.data_dir), {})


class PlanTests(unittest.TestCase):
    USERS = [{"login_url": f"https://{HOST}/login", "start": f"https://{HOST}/", "totp": None},
             {"login_url": "https://docs.pitangus.dev/", "start": "https://docs.pitangus.dev/", "totp": {"digits": 6, "period": 30, "algorithm": "SHA1"}}]

    def test_each_user_signs_in_through_a_browser_in_its_own_context_and_crawls_as_itself(self):
        plan = web.plan(HOST, f"https://{HOST}/", hosts=[HOST, "docs.pitangus.dev"], users=self.USERS)
        anonymous, first, second = plan["env"]["contexts"]
        self.assertEqual(anonymous["name"], web.CONTEXT)
        self.assertNotIn("authentication", anonymous)
        self.assertEqual(first["includePaths"], anonymous["includePaths"])
        self.assertEqual(first["authentication"], {"method": "browser", "parameters": {"loginPageUrl": f"https://{HOST}/login", "loginPageWait": 5,
                                                                                       "browserId": "firefox-headless"},
                                                   "verification": {"method": "autodetect"}})
        self.assertEqual(first["sessionManagement"], {"method": "autodetect"})
        self.assertEqual(first["users"], [{"name": "login-1", "credentials": {"username": "${PITANGUS_LOGIN_1_USERNAME}",
                                                                             "password": "${PITANGUS_LOGIN_1_PASSWORD}"}}])
        self.assertEqual(second["users"][0]["credentials"]["totp"], {"secret": "${PITANGUS_LOGIN_2_TOTP}", "period": 30, "digits": 6, "algorithm": "SHA1"})
        # ZAP fills the username and password itself; the code goes in the first field named like one, then Return.
        steps = second["authentication"]["parameters"]["steps"]
        self.assertEqual([step["type"] for step in steps], ["AUTO_STEPS", "TOTP_FIELD", "RETURN"])
        self.assertTrue(all(step["description"] for step in steps) and steps[1]["cssSelector"] == steps[2]["cssSelector"] == web.TOTP_FIELD)
        self.assertIn("one-time-code", web.TOTP_FIELD)
        spiders = [job["parameters"] for job in plan["jobs"] if job["type"] == "spider"]
        self.assertEqual([(item["context"], item.get("user"), item["url"]) for item in spiders],
                         [(web.CONTEXT, None, f"https://{HOST}/"), (web.CONTEXT, None, "https://docs.pitangus.dev/"),
                          (f"{web.CONTEXT}-login-1", "login-1", f"https://{HOST}/"), (f"{web.CONTEXT}-login-2", "login-2", "https://docs.pitangus.dev/")])
        self.assertTrue(all(not item["postForm"] for item in spiders))
        # The AJAX spider runs anonymously from the domain's URL, then as each user that signed in, from where its crawl starts.
        ajax = [job["parameters"] for job in plan["jobs"] if job["type"] == "spiderAjax"]
        self.assertEqual([(item["context"], item.get("user"), item["url"]) for item in ajax],
                         [(web.CONTEXT, None, f"https://{HOST}/"), (f"{web.CONTEXT}-login-1", "login-1", f"https://{HOST}/"),
                          (f"{web.CONTEXT}-login-2", "login-2", "https://docs.pitangus.dev/")])
        self.assertTrue(all(item["logoutAvoidance"] and item["elements"] == ["a"] and not item["randomInputs"] for item in ajax))
        self.assertNotIn("activeScan", json.dumps(plan))
        self.assertEqual(plan["jobs"][-2:][0]["type"], "passiveScan-wait")

    def test_hosts_saved_out_of_scope_stay_out_of_every_users_context_too(self):
        plan = web.plan(HOST, f"https://{HOST}/", wildcards=["*.pitangus.dev"], excluded=["admin.pitangus.dev"], users=self.USERS[:1])
        # With a session to keep, every context also leaves the sign-out links alone.
        self.assertEqual([context.get("excludePaths") for context in plan["env"]["contexts"]],
                         [[web.host_pattern("admin.pitangus.dev"), web_tools.LOGOUT_ZAP]] * 2)
        self.assertEqual([job["parameters"].get("user") for job in plan["jobs"] if job["type"] == "spider"], [None, "login-1"])

    def test_in_api_mode_the_definition_is_imported_as_each_user(self):
        plan = web.plan(HOST, f"https://{HOST}/", api={"file": "/zap/wrk/spec.json", "target": f"https://{HOST}/v1"}, users=self.USERS[:1])
        (imported,) = [job["parameters"] for job in plan["jobs"] if job["type"] == "openapi"]
        self.assertEqual((imported["context"], imported["user"]), (f"{web.CONTEXT}-login-1", "login-1"))
        (anonymous,) = [job["parameters"] for job in web.plan(HOST, f"https://{HOST}/", api={"file": "f", "target": "t"})["jobs"] if job["type"] == "openapi"]
        self.assertNotIn("user", anonymous)

    def test_login_plan_puts_secrets_in_the_environment_only(self):
        users = [{"name": "Admin", "username": USERNAME, "password": PASSWORD_1, "totp": None, "login_url": None, "applies_to": HOST},
                 {"name": "MFA", "username": "mfa", "password": "Second-Pass-0042", "login_url": "https://docs.pitangus.dev/in",  # gitleaks:allow
                  "applies_to": "docs.pitangus.dev", "totp": {"secret": SEED, "digits": 8, "period": 60, "algorithm": "SHA256"}}]
        planned, environment = web.login_plan(users, HOST, f"https://{HOST}/app")
        self.assertEqual(planned, [{"name": "Admin", "login_url": f"https://{HOST}/", "start": f"https://{HOST}/app", "check_url": None,
                                    "totp": None},
                                   {"name": "MFA", "login_url": "https://docs.pitangus.dev/in", "start": "https://docs.pitangus.dev/",
                                    "check_url": None, "totp": {"digits": 8, "period": 60, "algorithm": "SHA256"}}])
        self.assertEqual(environment, {"PITANGUS_LOGIN_1_USERNAME": USERNAME, "PITANGUS_LOGIN_1_PASSWORD": PASSWORD_1,
                                       "PITANGUS_LOGIN_2_USERNAME": "mfa", "PITANGUS_LOGIN_2_PASSWORD": "Second-Pass-0042",  # gitleaks:allow
                                       "PITANGUS_LOGIN_2_TOTP": SEED})
        text_plan = web.plan_text(HOST, f"https://{HOST}/app", users=planned)
        for secret in (USERNAME, PASSWORD_1, SEED, "Second-Pass-0042"):
            self.assertNotIn(secret, text_plan)


def fake_zap(document, calls, *, signed_in=None, stdout="", check_stdout=""):
    """`docker run` of ZAP. A sign-in check run (its script runs `check-<n>.yaml`) writes each check's authentication
    report (`signed_in`: whether it worked, per check; all by default) and its marked output; the main run writes
    `document` as the SARIF. `calls`: each run's command, script, standard input and environment."""
    def run(command, **kwargs):
        work = Path(command[command.index("-v") + 1].rsplit(":", 2)[0])
        script = command[command.index("-c") + 1]
        calls.append({"command": command, "script": script, "input": kwargs.get("input"), "env": kwargs.get("env"),
                      "files": {path.name: path.read_text() for path in work.iterdir()}})
        checks = re.findall(r"check-(\d+)\.yaml < /dev/null", script)
        if checks:
            output = ""
            for number in checks:
                worked = True if signed_in is None else signed_in[int(number) - 1]
                (work / f"auth-{number}.json").write_text(json.dumps({
                    "summaryItems": [{"key": "auth.summary.auth", "passed": worked}],
                    "failureReasons": [] if worked else [{"key": "auth.failure.logged_in", "description": "No indication found of being logged in."}]}))
                output += f"{web.CHECK_MARK}-{number}\nJob requestor requesting URL https://{HOST}/ with user login-{number}\n{check_stdout}\n"
            return subprocess.CompletedProcess(command, 0, output + f"{web.CHECK_MARK}-end\n", "")
        if document is not None:
            (work / web.REPORT).write_text(json.dumps(document))
        return subprocess.CompletedProcess(command, 0 if document is not None else 1, stdout, "")
    return patch("pitangus.modules.scanning.engines.subprocess.run", side_effect=run)


def plan_of(call: dict) -> dict:
    """The main plan: what follows the secrets on standard input."""
    secrets = call["script"].count("IFS= read -r PITANGUS_LOGIN_")
    return json.loads(call["input"].split("\n", secrets)[secrets])


class SignInCheckTests(unittest.TestCase):
    """Each test user's sign-in is confirmed alone before the crawl: its check page, else ZAP's own report."""

    USER = {"name": "Admin", "check_url": None}

    def test_the_report_decides_without_a_check_page(self):
        worked = {"summaryItems": [{"key": "auth.summary.auth", "passed": True}]}
        self.assertEqual(web.sign_in_outcome(self.USER, worked, "requesting URL"), {"name": "Admin", "status": "signed_in", "reason": None})
        failed = {"summaryItems": [{"key": "auth.summary.auth", "passed": False}],
                  "failureReasons": [{"key": "auth.failure.no_successful_logins", "description": "No successful browser logins."}]}
        outcome = web.sign_in_outcome(self.USER, failed, "")
        self.assertEqual(outcome["status"], "failed")
        self.assertIn("No successful browser logins.", text(outcome["reason"], "en"))  # ZAP's words, as written
        for report in (None, {}, {"summaryItems": "nope"}):
            with self.subTest(report=report):
                outcome = web.sign_in_outcome(self.USER, report, "")
                self.assertEqual((outcome["status"], outcome["reason"]["$t"]), ("failed", "scanning.web.login.unconfirmed"))

    def test_a_check_page_must_answer_200_as_that_user(self):
        user = {"name": "Admin", "check_url": f"https://{HOST}/account"}
        report = {"summaryItems": [{"key": "auth.summary.auth", "passed": False}]}  # the check page wins over the report
        ran = f"Job requestor requesting URL https://{HOST}/account with user login-1\n"
        self.assertEqual(web.sign_in_outcome(user, report, ran)["status"], "signed_in")
        for output, status in ((ran + f"Difference in response code values for message GET https://{HOST}/account Expected : 200 Received : 302\n", "302"),
                               (ran + "Difference in response code values for message GET x Expected : 200 Received : 401", "401")):
            outcome = web.sign_in_outcome(user, None, output)
            self.assertEqual(outcome["status"], "failed")
            self.assertIn(f"answered {status} instead of 200", text(outcome["reason"], "en"))
        for output in ("", ran + "Error sending message GET x in job requestor"):
            self.assertEqual(web.sign_in_outcome(user, None, output)["reason"]["$t"], "scanning.web.login.check_unreached")

    def test_each_check_keeps_to_its_own_part_of_the_output(self):
        output = f"noise\n{web.CHECK_MARK}-1\none\n{web.CHECK_MARK}-2\ntwo\n{web.CHECK_MARK}-end\nafter\n"
        self.assertEqual(web._segments(output, 2), ["one\n", "two\n"])
        self.assertEqual(web._segments("", 2), ["", ""])


class SignedInScanTests(unittest.TestCase):
    def setUp(self):
        testenv.docker_runner(self)
        which = patch.object(engines.shutil, "which", return_value="/usr/bin/docker")
        which.start()
        self.addCleanup(which.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.record = {"id": "a" * 24, "host": HOST, "url": f"https://{HOST}/", "kind": "web", "key": f"domain:{HOST}"}
        self.users = [{"id": "b" * 24, "name": "Admin", "username": USERNAME, "password": PASSWORD_1, "login_url": None, "applies_to": HOST,
                       "check_url": None, "totp": {"secret": SEED, "digits": 6, "period": 30, "algorithm": "SHA1"}}]

    def test_secrets_reach_zap_only_on_its_standard_input_and_are_scrubbed_from_what_it_returns(self):
        document = real()
        document["runs"][0]["results"][0]["message"]["text"] += f" Form echoed password={PASSWORD_1}"
        calls, events = [], []
        with fake_zap(document, calls, stdout=f"Signed in with {PASSWORD_1} / {SEED}", check_stdout=f"echo {PASSWORD_1}"):
            scan = web.scan_domain(self.record, "104.21.32.173", data_dir=self.data_dir, users=self.users,
                                   progress=lambda level, message: events.append(message))
        check, main = calls
        for call in calls:
            command = call["command"]
            # Nothing in the container's configuration (`docker inspect`), its command line (`ps`) or the host's disk.
            self.assertIsNone(call["env"])
            self.assertFalse(any(part == "-e" or part.startswith("PITANGUS_LOGIN") for part in command))
            for secret in (PASSWORD_1, SEED, USERNAME):
                self.assertNotIn(secret, json.dumps(command) + json.dumps(call["files"]))
            self.assertIn(web.HOME_EXEC, command)  # geckodriver runs from ZAP's home
            # The wrapper reads them first, one per line, and exports them to ZAP's processes only.
            self.assertIn("IFS= read -r PITANGUS_LOGIN_1_PASSWORD && export PITANGUS_LOGIN_1_PASSWORD", call["script"])
            self.assertEqual(call["input"].split("\n")[:3], [USERNAME, PASSWORD_1, SEED])
        plan = plan_of(main)
        self.assertEqual(plan["env"]["contexts"][1]["users"][0]["credentials"]["password"], "${PITANGUS_LOGIN_1_PASSWORD}")
        for secret in (PASSWORD_1, SEED):
            self.assertNotIn(secret, json.dumps(plan) + json.dumps(scan) + json.dumps(events))
        self.assertIn("[redacted]", json.dumps(scan))
        self.assertEqual((scan["status"], scan["logins"]), ("completed", [{"name": "Admin", "status": "signed_in", "reason": None}]))
        self.assertEqual((scan["scope"]["test_users"], {item["web"]["coverage"] for item in scan["findings"]}), (["Admin"], {"baseline+login"}))
        self.assertIn("scanning.web.login.signed_in", json.dumps(events))
        # Without test users there is no check run, ZAP's home stays noexec and its standard input is the plan alone.
        calls.clear()
        with fake_zap(real(), calls):
            web.scan_domain(self.record, "104.21.32.173", data_dir=self.data_dir)
        (call,) = calls
        self.assertIn(web.HOME, call["command"])
        self.assertNotIn("read -r", call["script"])
        self.assertEqual(json.loads(call["input"])["env"]["contexts"][0]["name"], web.CONTEXT)

    def test_a_user_that_cant_sign_in_isnt_crawled_as_and_the_run_says_its_coverage_is_partial(self):
        users = [self.users[0], {**self.users[0], "id": "c" * 24, "name": "Viewer", "username": "viewer", "totp": None}]
        calls, events = [], []
        with fake_zap(real(), calls, signed_in=[True, False]):
            scan = web.scan_domain(self.record, "104.21.32.173", data_dir=self.data_dir, users=users,
                                   progress=lambda level, message: events.append((level, message)))
        check, main = calls
        self.assertEqual(len(plan_of(main)["env"]["contexts"]), 2)  # the anonymous one and Admin's
        self.assertNotIn("viewer", main["input"])
        self.assertEqual(scan["status"], "incomplete")
        self.assertEqual([(item["name"], item["status"]) for item in scan["logins"]], [("Admin", "signed_in"), ("Viewer", "failed")])
        self.assertIn("No indication found of being logged in.", text(scan["logins"][1]["reason"], "en"))
        steps = {step["id"]: step for step in scan["steps"]}
        self.assertEqual((steps["dast"]["status"], steps["login"]["status"]), ("partial", "partial"))
        self.assertIn("1 of 2 test users signed in", text(steps["login"]["detail"], "en"))
        self.assertIn("Couldn't sign in as Viewer", text(scan["limitations"], "en"))
        self.assertIn(("warn", "scanning.web.login.failed"), [(level, message["$t"]) for level, message in events if isinstance(message, dict)])
        # Nobody signed in: the crawl is anonymous, and its findings vouch only for what an anonymous crawl sees.
        calls.clear()
        with fake_zap(real(), calls, signed_in=[False]):
            scan = web.scan_domain(self.record, "104.21.32.173", data_dir=self.data_dir, users=self.users[:1])
        self.assertEqual((scan["status"], {item["web"]["coverage"] for item in scan["findings"]}), ("incomplete", {"baseline"}))
        self.assertNotIn("read -r", calls[1]["script"])

    def test_no_other_variable_reaches_the_plan_where_zap_would_fill_it_with_a_secret(self):
        calls = []
        with fake_zap(real(), calls), self.assertRaises(web.WebScanError) as caught:
            web.scan_domain(self.record, "104.21.32.173", data_dir=self.data_dir, users=self.users,
                            headers=[("X-Leak", "${PITANGUS_LOGIN_1_PASSWORD}")])
        self.assertEqual(calls, [])  # ZAP never started
        self.assertIn("${", text(caught.exception.message, "en"))
        self.assertEqual(web.start_url({**self.record, "url": f"https://{HOST}/${{PITANGUS_LOGIN_1_PASSWORD}}"}), f"https://{HOST}/")
        for bad in ({"a b": "x"}, {"PITANGUS_LOGIN_1_PASSWORD": "two\nlines"}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                web.run_zap("{}", {HOST: "104.21.32.173"}, Path(self.directory.name), secrets=bad)

    def test_a_failing_plan_is_scrubbed_too(self):
        calls = []
        with fake_zap(None, calls, stdout=f"Automation plan failures:\n\tJob spider failed for {PASSWORD_1}\n"), \
                self.assertRaises(web.WebScanError) as caught:
            web.scan_domain(self.record, "104.21.32.173", data_dir=self.data_dir, users=self.users)
        self.assertNotIn(PASSWORD_1, json.dumps(caught.exception.message))


class WorkerTests(unittest.TestCase):
    def setUp(self):
        testenv.docker_runner(self)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.jobs = ScanJobs(self.data_dir, worker=False)
        self.domain = verified_domain(self.data_dir, HOST)
        for patcher in (patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": "1"}),
                        patch("pitangus.modules.scanning.engines.docker_problem", return_value=""),
                        patch.object(engines.shutil, "which", return_value="/usr/bin/docker")):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_queued(self, options, calls, trigger=None):
        queued = self.jobs.enqueue_dast_scan(domain=self.domain, requested_by="jefa", options=options, trigger=trigger)
        with db.transaction(self.data_dir) as connection:
            payload = connection.execute(select(jobs.c.payload).where(jobs.c.run_id == queued["id"])).scalar_one()
        with patch.object(domains, "lookup_txt", return_value=[self.domain["txt_value"]]), \
                patch("pitangus.modules.sources.domains.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("104.21.32.173", 443))]), \
                fake_zap(real(), calls):
            self.jobs._execute({**payload, "kind": "dast_scan", "run_id": queued["id"]})
        with db.transaction(self.data_dir) as connection:
            connection.execute(update(jobs).where(jobs.c.run_id == queued["id"]).values(status="done"))
        return load_run(self.data_dir, queued["id"]), payload

    def test_the_worker_opens_the_chosen_users_only_for_zap_and_stores_nothing_secret(self):
        records = capture_logs(self)
        saved = test_users.save(self.data_dir, self.domain, totp_user(check_url=f"https://{HOST}/account"))
        calls = []
        record, payload = self.run_queued({"mode": "web", "test_users": [saved["id"]]}, calls)
        self.assertEqual(record["logins"][0]["name"], "MFA user")
        self.assertEqual(payload["test_users"], [saved["id"]])
        check, *_ = calls
        self.assertIn(f'"url": "https://{HOST}/account", "responseCode": 200', check["input"])
        self.assertEqual(check["input"].split("\n")[1:3], ["Second-Pass-0042", SEED])
        everything = json.dumps(record) + json.dumps(payload) + "\n".join(records) + json.dumps([call["command"] for call in calls])
        for secret in ("Second-Pass-0042", SEED):
            self.assertNotIn(secret, everything)
        self.assertTrue(test_users.list_users(self.data_dir, self.domain["id"])[0]["last_used_at"])
        # Removed after the scan was queued: the worker refuses it rather than scanning without it.
        test_users.remove(self.data_dir, self.domain["id"], saved["id"])
        calls.clear()
        record, _ = self.run_queued({"mode": "web", "test_users": [saved["id"]]}, calls)
        self.assertEqual((record["status"], calls), ("failed", []))
        self.assertIn("doesn't exist", text(record["progress"][-1]["message"], "en"))

    def test_a_scheduled_scan_runs_without_what_was_removed_since_and_says_so(self):
        kept = test_users.save(self.data_dir, self.domain, password_user())
        gone = test_users.save(self.data_dir, self.domain, totp_user())
        test_users.remove(self.data_dir, self.domain["id"], gone["id"])
        calls = []
        record, _ = self.run_queued({"mode": "web", "use_headers": True, "test_users": [kept["id"], gone["id"]]}, calls,
                                    trigger={"kind": "schedule"})
        self.assertNotEqual(record["status"], "failed", record["progress"])
        self.assertEqual([login["name"] for login in record["logins"]], ["Admin user"])
        warnings = [text(event["message"], "en") for event in record["progress"] if event["level"] == "warn"]
        self.assertTrue(any("was deleted" in line for line in warnings), warnings)
        self.assertTrue(any("headers" in line for line in warnings), warnings)


class ApiTests(HttpCase):
    def setUp(self):
        HttpCase.setUp(self)
        from pitangus.modules.identity.auth import Users
        self.cookies = {}
        for name, role in (("jefa", "admin"), ("miembro", "member")):
            Users(self.data_dir).create(name, PASSWORD, role=role)
            self.cookies[role] = self.post("/api/auth/login", "login", {"username": name, "password": PASSWORD})[2][0].split("; ")[0]
        self.domain = verified_domain(self.data_dir, HOST)

    def send(self, path, action, body, role="admin"):
        return self.call("POST", path, body, {"Origin": ORIGIN, "X-Pitangus-Action": action, "Cookie": self.cookies[role], "Accept-Language": "en"})

    def change(self, body, role="admin"):
        return self.send("/api/domains/test-users", "domain-test-users", {"domain_id": self.domain["id"], **body}, role=role)

    def test_administrators_manage_test_users_and_nobody_reads_a_secret_back(self):
        records = capture_logs(self)
        self.assertEqual(self.change({"op": "save", **password_user()}, role="member")[0], 403)
        self.assertEqual(self.send("/api/domains/test-users", "domain-headers", {"domain_id": self.domain["id"], "op": "save", **password_user()})[0], 403)
        status, saved, _ = self.change({"op": "save", **password_user()})
        self.assertEqual((status, saved["limit"], saved["per_scan"]), (200, 10, 3), saved)
        (user,) = saved["test_users"]
        self.assertEqual((user["name"], user["username"], user["method"], user["applies_to"], user["login_url"]),
                         ("Admin user", USERNAME, "password", HOST, None))
        status, saved, _ = self.change({"op": "save", **totp_user(applies_to="docs.pitangus.dev", notes="2FA")})
        self.assertEqual(status, 200, saved)
        _, page, _ = self.call("GET", "/api/domains", headers={"Cookie": self.cookies["admin"]})
        row = page["items"][0]
        self.assertEqual(([item["name"] for item in row["test_users"]], row["test_user_count"]), (["Admin user", "MFA user"], 2))
        _, page, _ = self.call("GET", "/api/domains", headers={"Cookie": self.cookies["member"]})
        self.assertEqual((page["items"][0]["test_users"], page["items"][0]["test_user_count"]), (None, 2))
        for bad in ({"op": "save", **password_user(), "method": "magic_link"}, {"op": "save", **password_user(), "password": "a${B}"},
                    {"op": "save", **password_user(), "totp": {"secret": SEED}}, {"op": "save", "name": "x"},
                    {"op": "remove"}, {"op": "remove", "id": user["id"], "name": "x"}, {"op": "save", **password_user(), "extra": 1},
                    {"op": "save", **password_user(name="Third"), "login_url": "https://evil.example/login"}):
            with self.subTest(bad=str(bad)[:60]):
                self.assertEqual(self.change(bad)[0], 400)
        self.assertEqual(self.change({"op": "remove", "id": "f" * 24})[0], 404)
        self.assertEqual(self.send("/api/domains/test-users", "domain-test-users", {"domain_id": "f" * 24, "op": "remove", "id": user["id"]})[0], 404)
        status, left, _ = self.change({"op": "remove", "id": user["id"]})
        self.assertEqual((status, [item["name"] for item in left["test_users"]]), (200, ["MFA user"]))
        everything = "\n".join(records) + json.dumps(page) + stored_rows(self.data_dir)
        for secret in (PASSWORD_1, "Second-Pass-0042", SEED, SEED.lower()[:16]):  # gitleaks:allow
            self.assertNotIn(secret, everything)
        self.assertIn("domain_test_user_changed", everything)

    def test_a_scan_takes_test_users_of_its_domain_inside_its_scope(self):
        mine = test_users.save(self.data_dir, self.domain, password_user())
        docs = test_users.save(self.data_dir, self.domain, password_user(name="Docs", applies_to="docs.pitangus.dev"))

        def scan(body):
            with patch.dict(os.environ, {"PITANGUS_DAST_ENABLED": "1"}), \
                    patch("pitangus.modules.sources.domains.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("104.21.32.173", 443))]), \
                    patch.object(self.state.jobs, "enqueue_dast_scan", return_value={"id": "r1", "status": "queued"}) as enqueue:
                status, answer, _ = self.send("/api/domains/scans", "scan-domain", {"domain_id": self.domain["id"], **body})
            return status, answer, enqueue
        status, _, enqueue = scan({"test_users": [mine["id"]]})
        self.assertEqual((status, enqueue.call_args.kwargs["options"]["test_users"]), (202, [mine["id"]]))
        status, _, enqueue = scan({"test_users": [docs["id"]], "hosts": ["docs.pitangus.dev"]})
        self.assertEqual(status, 202)
        # With the domain's saved scope, its in-scope hosts are where test users may sign in.
        from pitangus.modules.sources import domain_scope
        domain_scope.add_host(self.data_dir, self.domain["id"], "docs.pitangus.dev")
        domain_scope.set_state(self.data_dir, self.domain["id"], "docs.pitangus.dev", "out_of_scope")
        self.assertEqual(scan({"test_users": [docs["id"]], "use_scope": True})[0], 409)
        domain_scope.set_state(self.data_dir, self.domain["id"], "docs.pitangus.dev", "in_scope")
        status, _, enqueue = scan({"test_users": [docs["id"]], "use_scope": True})
        self.assertEqual((status, enqueue.call_args.kwargs["options"].get("use_scope"), enqueue.call_args.kwargs["options"]["test_users"]),
                         (202, True, [docs["id"]]))
        for body, expected in (({"test_users": [docs["id"]]}, 409), ({"test_users": ["f" * 24]}, 400),
                               ({"test_users": ["a" * 24, "b" * 24, "c" * 24, "d" * 24]}, 400), ({"test_users": ["nope"]}, 400)):
            with self.subTest(body=body):
                status, answer, enqueue = scan(body)
                self.assertEqual(status, expected, answer)
                enqueue.assert_not_called()

    def test_a_schedule_signs_in_as_test_users_of_its_scope_and_sends_headers_only_if_saved(self):
        from pitangus.modules.sources import domain_headers, domain_schedule, domain_scope
        self.assertEqual(domain_schedule.USERS_MAX, test_users.PER_SCAN)
        mine = test_users.save(self.data_dir, self.domain, password_user())
        docs = test_users.save(self.data_dir, self.domain, password_user(name="Docs", applies_to="docs.pitangus.dev"))
        rule = {"frequency": "daily", "time": "09:00", "timezone": "UTC"}

        def schedule(extra, role="admin"):
            return self.send("/api/domains/schedule", "schedule-domain", {"domain_id": self.domain["id"], "schedule": {**rule, **extra}}, role=role)
        self.assertEqual(schedule({"test_users": [mine["id"]]}, role="member")[0], 403)
        for extra, expected in (({"test_users": [docs["id"]]}, 409), ({"test_users": ["f" * 24]}, 404),
                                ({"test_users": ["nope"]}, 400), ({"test_users": ["a" * 24, "b" * 24, "c" * 24, "d" * 24]}, 400),
                                ({"use_headers": True}, 409), ({"use_headers": "yes"}, 400)):
            with self.subTest(extra=extra):
                self.assertEqual(schedule(extra)[0], expected)
        status, row, _ = schedule({"test_users": [mine["id"]]})
        self.assertEqual((status, row["schedule"]["test_users"], row["schedule"]["use_headers"]), (200, [mine["id"]], False))
        first = row["schedule"]["next_run_at"]
        # Only what the scan does changes: the next run stays.
        domain_headers.save(self.domain["id"], "Authorization", "Bearer abcdefgh12345678")
        domain_scope.add_host(self.data_dir, self.domain["id"], "docs.pitangus.dev")
        status, row, _ = schedule({"test_users": [mine["id"], docs["id"]], "use_headers": True})
        self.assertEqual((status, row["schedule"]["test_users"], row["schedule"]["use_headers"], row["schedule"]["next_run_at"]),
                         (200, [mine["id"], docs["id"]], True, first))

    def test_the_periodic_task_leaves_out_users_deleted_or_outside_the_scope_with_a_note(self):
        from datetime import datetime, timedelta, timezone
        from unittest.mock import MagicMock
        from pitangus.modules.runs import periodic
        from pitangus.modules.sources import domain_scope
        mine = test_users.save(self.data_dir, self.domain, password_user())
        docs = test_users.save(self.data_dir, self.domain, password_user(name="Docs", applies_to="docs.pitangus.dev"))
        gone = test_users.save(self.data_dir, self.domain, totp_user())
        domain_scope.add_host(self.data_dir, self.domain["id"], "docs.pitangus.dev")
        now = datetime.now(timezone.utc)
        domains.set_schedule(self.data_dir, self.domain["id"], {"frequency": "daily", "time": "00:00", "timezone": "UTC",
                                                                "test_users": [mine["id"], docs["id"], gone["id"]], "use_headers": True},
                             now=now - timedelta(days=2))
        test_users.remove(self.data_dir, self.domain["id"], gone["id"])
        domain_scope.set_state(self.data_dir, self.domain["id"], "docs.pitangus.dev", "out_of_scope")
        jobs_ = MagicMock()
        jobs_.enqueue_dast_scan.return_value = {"id": "r" * 32, "status": "queued"}
        self.assertEqual(periodic._domain_scans(self.data_dir, jobs_, now=now)["queued"], "r" * 32)
        self.assertEqual(jobs_.enqueue_dast_scan.call_args.kwargs["options"], {"mode": "web", "use_scope": True, "test_users": [mine["id"]]})
        schedule = domains.get_domain(self.data_dir, self.domain["id"])["schedule"]
        note = text(schedule["note"], "en")
        for part in ("was deleted", "Docs signs in outside", "none now"):
            self.assertIn(part, note)
        # The deleted user leaves the rule; the one outside the scope stays, for when the scope includes it again.
        self.assertEqual((schedule["test_users"], schedule["use_headers"]), ([mine["id"], docs["id"]], True))


if __name__ == "__main__":
    unittest.main()
