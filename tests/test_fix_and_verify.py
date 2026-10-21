"""Closing the loop: how to fix each finding and re-verify it without hunting for it by hand."""

import os
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from pitangus.modules.findings import registry as findings_registry
from pitangus.modules.findings import fix_guide
from pitangus.modules.findings import triage
from pitangus.modules.findings import verifications
from pitangus.modules.identity.auth import Users
from pitangus.modules.runs.store import save_repository_scan
from test_auth import PASSWORD, HttpCase
from test_dashboard import _finding, _scan
from pitangus.shared.i18n import localize, text


def dependency(path, name, version, fixed, *, ecosystem="npm", direct=True):
    return {"scanner": "sca", "path": path, "package": {"ecosystem": ecosystem, "name": name, "version": version, "fixed_version": fixed, "direct": direct}}


class FixGuideTests(unittest.TestCase):
    def test_the_command_matches_the_package_manager_and_closes_every_advisory(self):
        findings = fix_guide.attach([dependency("web/package-lock.json", "lodash", "4.17.20", "4.17.19"),
                                     dependency("web/package-lock.json", "lodash", "4.17.20", "4.17.21")])
        self.assertEqual(localize(findings[0]["fix"]["commands"]), [{"label": "Actualiza", "action": "update", "code": "npm install lodash@4.17.21"},  # fixes both advisories
                                                                   {"label": "Comprueba que muestre 4.17.21 o superior", "action": "check", "code": "npm ls lodash"}])
        cases = {("yarn.lock", "npm", True): "yarn add left-pad@1.3.0", ("poetry.lock", "pip", True): 'poetry add "left-pad>=1.3.0"',
                 ("poetry.lock", "pip", False): "poetry update left-pad", ("uv.lock", "pip", False): "uv lock --upgrade-package left-pad",
                 ("Cargo.lock", "cargo", True): "cargo update -p left-pad@1.0.0 --precise 1.3.0", ("composer.lock", "composer", True): 'composer require "left-pad:^1.3.0"',
                 ("Gemfile.lock", "bundler", True): "bundle update left-pad", ("packages.lock.json", "nuget", True): "dotnet add package left-pad --version 1.3.0"}
        for (path, ecosystem, direct), expected in cases.items():
            with self.subTest(path=path, direct=direct):
                fix = fix_guide.guide(dependency(path, "left-pad", "1.0.0", "1.3.0", ecosystem=ecosystem, direct=direct))
                self.assertEqual(fix["commands"][0]["code"], expected)
        go = fix_guide.guide(dependency("go.mod", "golang.org/x/net", "v0.1.0", "0.17.0", ecosystem="gomod"))
        self.assertEqual(go["commands"][0]["code"], "go get golang.org/x/net@v0.17.0 && go mod tidy")
        stdlib = fix_guide.guide(dependency("go.mod", "stdlib", "v1.22.1", "1.22.5", ecosystem="gomod"))
        self.assertEqual(stdlib["commands"][0]["code"], "go mod edit -toolchain=go1.22.5")  # not "go get stdlib@…"
        dev = {**dependency("yarn.lock", "jest", "29.0.0", "29.7.0"), "package": {**dependency("yarn.lock", "jest", "29.0.0", "29.7.0")["package"], "dev": True}}
        self.assertEqual(fix_guide.guide(dev)["commands"][0]["code"], "yarn add -D jest@29.7.0")  # stays dev-only

    def test_any_requirements_text_file_is_pip_and_a_long_name_is_read_in_linear_time(self):
        for name in ("requirements.txt", "api/requirements-dev.txt", "dev-requirements.txt"):
            self.assertEqual(fix_guide.manager(name, "pip"), "pip", name)
        for name in ("requirements/base.txt", "requirements.md", "notes.txt"):
            self.assertIsNone(fix_guide.manager(name, "pip"), name)
        started = time.monotonic()
        self.assertIsNone(fix_guide.manager("requirements" * 50_000, "pip"))
        self.assertLess(time.monotonic() - started, 1)

    def test_the_pull_request_table_only_shows_a_command_that_updates(self):
        from pitangus.modules.pullrequests.review import markdown_rows
        finding = {**_finding("e" * 64, "high", package="minimist"), "path": "package-lock.json",
                   "package": {"ecosystem": "npm", "name": "minimist", "version": "0.0.8", "fixed_version": "1.2.6", "direct": False}}
        row = markdown_rows([finding])[-1]
        self.assertIn("Actualizar a `1.2.6`", row)   # transitive: the command would just be "npm install"
        self.assertNotIn("`npm install`", row)
        direct = {**finding, "package": {**finding["package"], "direct": True}}
        self.assertIn("`npm install minimist@1.2.6`", markdown_rows([direct])[-1])

    def test_transitive_os_and_unfixable_dependencies_get_steps_not_wrong_commands(self):
        transitive = fix_guide.guide(dependency("package-lock.json", "minimist", "0.0.8", "1.2.6", direct=False))
        self.assertIn('"overrides"', transitive["example"]["after"])
        self.assertEqual(localize(transitive["commands"], "en"), [{"label": "Reinstall", "action": "reinstall", "code": "npm install"},
                                                                  {"label": "Check that it shows 1.2.6 or later", "action": "check", "code": "npm ls minimist"}])
        image = fix_guide.guide(dependency("var/lib/dpkg/status", "libssl1.1", "1.1.1n", "1.1.1w", ecosystem="debian"))
        self.assertEqual((image["example"]["language"], image["commands"]), ("dockerfile", []))  # nothing to run outside the Dockerfile
        self.assertIn("apt-get install -y --only-upgrade libssl1.1", image["example"]["after"])
        none = fix_guide.guide(dependency("package-lock.json", "abandoned", "1.0.0", None))
        self.assertEqual(none["commands"], [])
        odd = fix_guide.guide(dependency("package-lock.json", "a; rm -rf /", "1.0.0", "2.0.0"))
        self.assertEqual(odd["commands"], [])  # an odd name doesn't become a command

    def test_code_and_secrets_get_an_example_or_the_rotation_steps(self):
        code = fix_guide.guide({"scanner": "sast", "rule_id": "appsec.js.sql-injection", "remediation": "Usa parámetros."})
        self.assertEqual(code["example"]["language"], "javascript")
        self.assertIn("$1", code["example"]["after"])
        secret = fix_guide.guide({"scanner": "secrets", "path": "config.py"})
        self.assertTrue(text(secret["steps"][0]).startswith("Revoca o rota la credencial"))


class TransitiveFixTests(unittest.TestCase):
    """A transitive dependency: who brings it in comes from the lockfile's graph (any ecosystem), and the guide updates
    it, checks it and, if it doesn't move, updates the direct dependency that holds it back."""

    def guide(self, path, name, version, fixed, lead, ecosystem):
        finding = dependency(path, name, version, fixed, ecosystem=ecosystem, direct=False)
        finding["package"]["introduced_by"] = [lead]
        return localize(fix_guide.guide(finding), "en")

    def test_the_same_guide_for_every_ecosystem_with_its_own_commands(self):
        cases = {
            ("Cargo.lock", "cargo"): ("rustls-webpki", "0.103.10", "0.103.13", {"name": "rustls", "version": "0.23.20", "direct": "reqwest", "direct_version": "0.12.9"},
                                      ["cargo update -p rustls-webpki@0.103.10 --precise 0.103.13", "cargo tree --invert rustls-webpki", "cargo update -p reqwest"]),
            ("poetry.lock", "PyPI"): ("starlette", "0.37.2", "1.3.1", {"name": "fastapi", "version": "0.110.1", "direct": "fastapi", "direct_version": "0.110.1"},
                                      ["poetry update starlette", "poetry show starlette", "poetry add fastapi@latest"]),
            ("composer.lock", "composer"): ("guzzlehttp/psr7", "2.4.0", "2.4.5", {"name": "guzzlehttp/guzzle", "version": "7.5.0", "direct": "laravel/framework", "direct_version": "10.0.0"},
                                            ["composer update guzzlehttp/psr7 --with-dependencies", "composer show guzzlehttp/psr7", "composer update laravel/framework --with-dependencies"]),
        }
        for (path, ecosystem), (name, version, fixed, lead, commands) in cases.items():
            with self.subTest(path=path):
                fix = self.guide(path, name, version, fixed, lead, ecosystem)
                self.assertEqual([command["code"] for command in fix["commands"]], commands)
                self.assertEqual(fix["action"], f"Update {name} to {fixed}; if it stays below, update {lead['direct']}, which brings it in.")
                self.assertEqual(fix["commands"][-1]["label"], f"If it stays below {fixed}, update {lead['direct']}")
        self.assertIn("comes from reqwest 0.12.9 through rustls 0.23.20", self.guide(*["Cargo.lock", "rustls-webpki", "0.103.10", "0.103.13",
                      cases[("Cargo.lock", "cargo")][3], "cargo"])["steps"][0])

    def test_go_sets_the_version_itself_and_npm_forces_it_naming_who_to_update_instead(self):
        go = self.guide("go.mod", "golang.org/x/net", "v0.17.0", "0.23.0", {"name": "google.golang.org/grpc", "version": "v1.60.0", "direct": "google.golang.org/grpc"}, "gomod")
        self.assertNotIn("action", go)
        self.assertEqual([command["code"] for command in go["commands"]], ["go get golang.org/x/net@v0.23.0 && go mod tidy", "go list -m golang.org/x/net"])
        npm = self.guide("package-lock.json", "qs", "6.11.0", "6.11.1", {"name": "body-parser", "version": "1.20.1", "direct": "express", "direct_version": "4.18.2"}, "npm")
        self.assertIn('"overrides"', npm["example"]["after"])
        self.assertEqual(npm["example"]["note"], "Better still: update express, which brings it in.")

    def test_reports_say_the_same_first_action(self):
        from pitangus.modules.findings.remediation import action, fix_groups
        finding = dependency("poetry.lock", "starlette", "0.37.2", "1.3.1", ecosystem="PyPI", direct=False)
        finding["package"]["introduced_by"] = [{"name": "fastapi", "version": "0.110.1", "direct": "fastapi"}]
        self.assertEqual(action(fix_groups([finding])[0], locale="en"), "Update starlette to 1.3.1; if it stays below, update fastapi, which brings it in.")

    def test_names_that_could_be_options_never_reach_a_command(self):
        fix = self.guide("poetry.lock", "starlette", "0.37.2", "1.3.1", {"name": "fastapi", "version": "1", "direct": "--index-url=https://evil.example"}, "PyPI")
        self.assertNotIn("--index-url", " ".join(command["code"] for command in fix["commands"]))


class FixCommandSafetyTests(unittest.TestCase):
    def test_names_that_look_like_options_or_shell_never_reach_a_command(self):
        """Findings travel in `scan --format json` to assistants that may run `fix.commands`."""
        for name, fixed in (("--registry", "1.3.0"), ("left-pad;id", "1.3.0"), ("left-pad", "-1"), ("$(id)", "1.3.0")):
            fix = fix_guide.guide(dependency("package.json", name, "1.0.0", fixed, ecosystem="npm", direct=True))
            self.assertEqual(fix["commands"], [], name)
        safe = fix_guide.guide(dependency("package.json", "@scope/left-pad", "1.0.0", "1.3.0", ecosystem="npm", direct=True))
        self.assertEqual(safe["commands"][0]["code"], "npm install @scope/left-pad@1.3.0")


class ReverifyTests(HttpCase):
    def setUp(self):
        super().setUp()
        with patch.dict(os.environ, {"PITANGUS_REQUIRE_TOTP": "none"}):
            Users(self.data_dir).create("miembro", PASSWORD)
            _, _, cookies = self.post("/api/auth/login", "login", {"username": "miembro", "password": PASSWORD})
        self.cookie = cookies[0].split("; ")[0]
        self.run = save_repository_scan(self.data_dir, _scan("org/api", [_finding("a" * 64, "critical"), _finding("b" * 64, "high", package="lodash"),
                                                                         _finding("c" * 64, "low", package="left-pad")],
                                                             datetime.now(timezone.utc).isoformat()))

    def reverify(self, fingerprint, run_id=None):
        with patch.dict(os.environ, {"PITANGUS_REQUIRE_TOTP": "none"}):
            return self.post("/api/findings/reverify", "reverify-finding", {"run_id": run_id or self.run["id"], "fingerprint": fingerprint}, self.cookie)

    def test_reverify_rescans_once_and_reports_the_outcome(self):
        source = {"id": "github:org/api", "name": "org/api", "installation_id": 7, "uid": None}
        with patch("pitangus.app.api.findings.find_source", return_value=source), \
                patch("pitangus.modules.runs.jobs.ScanJobs.enqueue_repository_scan", return_value={"id": "f" * 32, "status": "queued"}) as enqueue:
            status, body, _ = self.reverify("a" * 64)
        self.assertEqual((status, body["joined"], enqueue.call_args.kwargs["trigger"]), (202, False, {"kind": "reverify"}))
        # The scan finishes: "a" is gone, "b" remains.
        done = save_repository_scan(self.data_dir, _scan("org/api", [_finding("b" * 64, "high", package="lodash"), _finding("c" * 64, "low", package="left-pad")],
                                                         datetime.now(timezone.utc).isoformat()))
        for fingerprint in ("a" * 64, "b" * 64):
            verifications.record(self.data_dir, "github:org/api", fingerprint, done["id"], by="miembro")
        view = triage.annotate(self.data_dir, findings_registry.view(self.data_dir, "github:org/api", status="all"))
        states = {item["fingerprint"][:1]: item.get("verification", {}).get("state") for item in view["findings"]}
        self.assertEqual((states["a"], states["b"], states["c"]), ("fixed", "present", None))

    def test_joins_a_scan_in_flight_and_refuses_open_pull_request_findings(self):
        queued = save_repository_scan(self.data_dir, {**_scan("org/api", [], datetime.now(timezone.utc).isoformat()), "status": "queued"})
        status, body, _ = self.reverify("b" * 64)
        self.assertEqual((status, body["joined"], body["run"]["id"]), (202, True, queued["id"]))
        state = findings_registry.load(self.data_dir, "github:org/api")
        state["findings"]["c" * 64]["origin"] = {"kind": "pr", "pr": 4}
        findings_registry._save(self.data_dir, state)
        self.assertEqual(self.reverify("c" * 64)[0], 409)
        self.assertEqual(self.reverify("d" * 64)[0], 404)
        self.assertEqual(self.reverify("zz")[0], 400)


if __name__ == "__main__":
    unittest.main()
