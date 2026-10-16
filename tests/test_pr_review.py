"""PR review: diff, baseline, verdict, comment and the full job against a simulated GitHub."""

import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from pitangus.app import wiring
from pitangus.modules.pullrequests import review as pr_review
from pitangus.modules.pullrequests import watch as pr_watch
from pitangus.modules.runs.jobs import ScanJobs
from pitangus.modules.identity.auth import Users
from pitangus.modules.integrations.github import GitHubAppError, PULLS_FORBIDDEN
from pitangus.modules.runs.store import load_run, save_repository_scan, render_profile_report
from pitangus.modules.scanning import engines as scan_engines, repository as scan_repository
from pitangus.modules.reporting.pdf import render_pdf
from pitangus.shared.i18n import text
from fake_github import fake_github
from test_auth import ORIGIN, PASSWORD, HttpCase

wiring.configure()  # like every Pitangus process: domain events and injected readers

SHA = "c" * 40
APP = "import subprocess\n\ndef old(cmd):\n    return subprocess.run(cmd, shell=True)\n\n\ndef new(user):\n    return eval(user)\n"
# The PR adds the function `new` (lines 7-8); `old` was already on the main branch.
PATCH = "@@ -3,2 +3,6 @@\n def old(cmd):\n     return subprocess.run(cmd, shell=True)\n+\n+\n+def new(user):\n+    return eval(user)\n"


RULES = {"eval(": "appsec.py.eval-exec-non-literal", "shell=True": "appsec.py.shell-command-non-literal"}


def fake_opengrep(root):
    """Opengrep as it would answer on these files (two of our rules), through the real parser."""
    results = [{"check_id": f"rules.{rule}", "path": f"/src/{path.relative_to(root).as_posix()}", "start": {"line": number},
                "extra": {"lines": line, "severity": "WARNING", "message": rule, "metadata": {"cwe": ["95"]}}}
               for path in sorted(root.rglob("*.py")) for number, line in enumerate(path.read_text().splitlines(), 1)
               for marker, rule in RULES.items() if marker in line]
    return scan_engines._result("opengrep", "completed", "", scan_engines.parse_opengrep({"results": results}))


def finding(fingerprint, path="app.py", line=8, severity="high", scanner="sast", package=None):
    return {"fingerprint": fingerprint, "path": path, "line": line, "severity": severity, "scanner": scanner,
            "title": "Regla | con barra", "remediation": "Arreglarlo", "package": package, "rule_id": "R", "snippet": f"{fingerprint}()"}


class LogicTests(unittest.TestCase):
    def test_changed_lines_follow_hunks(self):
        changed = pr_review.changed_lines([
            {"filename": "app.py", "status": "modified", "patch": PATCH + "\\ No newline at end of file"},
            {"filename": "logo.png", "status": "added"}, {"filename": "gone.py", "status": "removed", "patch": "@@ -1 +0,0 @@\n-x"}])
        self.assertEqual(changed, {"app.py": {5, 6, 7, 8}, "logo.png": None})

    def test_classify_against_baseline_and_diff(self):
        changed = {"app.py": {7, 8}, "package-lock.json": {10}}
        findings = [finding("new"), finding("old", line=4), finding("moved", line=7), finding("elsewhere", path="lib.py"),
                    finding("dep", path="package-lock.json", line=1, scanner="sca", package={"name": "axios"})]
        result = pr_review.classify(findings, changed, baseline=[finding("old", line=4), finding("moved", line=30)])
        self.assertEqual([item["fingerprint"] for item in result["introduced"]], ["new", "dep"])
        self.assertEqual([item["fingerprint"] for item in result["preexisting"]], ["moved"])
        # Without a baseline, everything that falls in the diff counts.
        self.assertEqual(len(pr_review.classify(findings, changed, baseline=None)["introduced"]), 3)

    def test_renamed_files_keep_their_previous_name(self):
        """GitHub's PR files: a renamed file says what it was called (`previous_filename`) and that nothing changed in it."""
        from pitangus.modules.integrations import github
        rows = [{"filename": "service.py", "status": "renamed", "previous_filename": "app.py", "changes": 0, "additions": 0},
                {"filename": "lib.py", "status": "modified", "patch": "@@ -1 +1 @@\n-a\n+b", "changes": 2}]
        with patch.object(github, "installation_token", return_value="t"), patch.object(github, "_get", return_value=rows):
            files = github.pull_files(7, "org/api", 12)
        self.assertEqual(pr_review.renames(files), {"service.py": "app.py"})
        self.assertEqual(pr_review.changed_lines(files), {"service.py": set(), "lib.py": {1}})

    def test_verdict_gate(self):
        items = [finding("a", severity="medium")]
        self.assertEqual(pr_review.verdict(items, "high")["state"], "success")
        self.assertEqual(pr_review.verdict(items, "medium")["state"], "failure")
        self.assertEqual(pr_review.verdict([finding("b", severity="critical")], "never")["state"], "success")

    def test_unused_dependencies_comment_is_informative(self):
        new = [{"name": "left-pad", "ecosystem": "npm", "manifest": "package.json", "line": 9}]
        before = [{"name": "moment", "ecosystem": "npm", "manifest": "package.json", "line": 7}]
        body = pr_review.render_unused_comment(new, before, ["npm"])
        self.assertIn("> [!WARNING]", body)
        self.assertIn("`left-pad`", body)
        self.assertIn("<summary>1 dependencia preexistente sin uso", body)
        self.assertIn("no bloquea el merge", body)
        self.assertIn("> [!TIP]", pr_review.render_unused_comment([], before, ["npm"]))

    def test_unused_dependency_detection(self):
        import tempfile
        from pitangus.modules.scanning.unused_deps import analyze, split_by_pr
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text(json.dumps({"dependencies": {"react": "19", "left-pad": "1", "tailwindcss": "4", "@scope/ui": "1", "prisma": "5"},
                                                           "scripts": {"migrate": "prisma migrate deploy"}}, indent=2))
            (root / "src").mkdir()
            (root / "src" / "App.tsx").write_text("import React from 'react'\nimport { Button } from '@scope/ui/button'\n")
            (root / "requirements.txt").write_text("fastapi==0.110\npython-dotenv==1.0\nrequests==2.31\ngunicorn==22\n")
            (root / "main.py").write_text("from fastapi import FastAPI\nfrom dotenv import load_dotenv\n")
            result = analyze(root)
        names = {item["name"] for item in result["unused"]}
        self.assertEqual(names, {"left-pad", "requests"})  # prisma is used from a script, gunicorn is implicit
        new, before = split_by_pr(result["unused"], {"package.json": {4}})
        self.assertEqual(([item["name"] for item in new], sorted(item["name"] for item in before)), (["left-pad"], ["requests"]))

    def test_lockfiles_are_not_declarations(self):
        import tempfile
        from pitangus.modules.scanning.unused_deps import analyze
        hashes = "    --hash=sha256:" + "a" * 64 + " \\\n    --hash=sha256:" + "b" * 64 + "\n"
        compiled = ("# Generated from requirements.in: every package pinned with its hashes.\n"
                    f"aiodns==3.6.1 \\\n{hashes}    # via checkov\n"
                    f"checkov==3.3.19 \\\n{hashes}    # via -r requirements.in\n"
                    f"gitpython==3.1 \\\n{hashes}    # via\n    #   checkov\n    #   other\n")

        def unused(files):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name, text in files.items():
                    (root / name).parent.mkdir(parents=True, exist_ok=True)
                    (root / name).write_text(text)
                return sorted((item["name"], item["manifest"], item["line"]) for item in analyze(root)["unused"])

        # pip-compile with a sibling .in, checkov used by the Dockerfile: transitive entries are never "unused".
        self.assertEqual(unused({"img/requirements.txt": compiled, "img/requirements.in": "checkov==3.3.19\n",
                                 "img/Dockerfile": "RUN pip install -r requirements.txt && checkov --version\n"}), [])
        # Without the .in, only the entry an input file asks for is direct, and it is reported when nothing uses it.
        self.assertEqual(unused({"requirements.txt": compiled, "main.py": "import os\n"}), [("checkov", "requirements.txt", 6)])
        self.assertEqual(unused({"requirements.txt": compiled, "requirements.in": "checkov\n", "app.py": "import os\n"}),
                         [("checkov", "requirements.in", 1)])
        # A uv export header, or hashes on every entry (poetry export), mark a lockfile even without `# via`.
        self.assertEqual(unused({"requirements.txt": "# This file was autogenerated by uv via the following command:\n"
                                                     "#    uv export --format requirements-txt\nidna==3.7\n"}), [])
        self.assertEqual(unused({"requirements.txt": f"idna==3.7 ; python_version >= '3.9' \\\n{hashes}"}), [])
        # A hand-written requirements file is still a declaration.
        self.assertEqual(unused({"requirements.txt": "# app deps\nfastapi==0.110\nrequests==2.31\n", "main.py": "import fastapi\n"}),
                         [("requests", "requirements.txt", 3)])
        # A lockfile isn't evidence of use either.
        self.assertEqual(unused({"package.json": json.dumps({"dependencies": {"left-pad": "1"}}, indent=2),
                                 "pnpm-lock.yaml": "packages:\n  left-pad@1.0.0: {}\n"}), [("left-pad", "package.json", 3)])

    def test_long_titles_are_cut_at_a_word(self):
        self.assertEqual(pr_review._cell("Uncovered a JSON Web Token, which may lead to unauthorized access", 40), "Uncovered a JSON Web Token, which may…")

    def test_file_names_cannot_inject_markdown(self):
        hostile = finding("a", path="a`|x\n[click](https://evil)|.py")
        outcome = {"introduced": [hostile], "preexisting": [], "verdict": pr_review.verdict([hostile])}
        body = pr_review.render_comment({"head_sha": SHA}, outcome, run_id="r" * 32, baseline_run="b", panel_url=None)
        row = next(line for line in body.splitlines() if "click" in line)
        self.assertEqual(row.count("`"), 2)       # only the code's own
        self.assertNotIn("\n[click]", body)
        self.assertIn("el panel de Pitangus", body)

    def test_comment_escapes_tables_and_mentions_preexisting(self):
        outcome = {"introduced": [finding("a")], "preexisting": [finding("b")], "verdict": pr_review.verdict([finding("a")])}
        body = pr_review.render_comment({"head_sha": SHA}, outcome, run_id="r" * 32, baseline_run="base", panel_url="https://panel")
        self.assertIn("Regla / con barra", body)
        self.assertIn("> [!CAUTION]", body)
        self.assertIn("1 hallazgo preexistente", body)
        self.assertIn("`app.py:8`", body)


class CopyCountTests(unittest.TestCase):
    """Pasting a problem above an identical one introduces one more instance, whatever the scanner: copies are counted
    per identity family, never collapsed into the original."""

    def gate(self, base, head, changed):
        return pr_review.classify(head, changed, base)

    def test_a_pasted_copy_is_introduced_for_every_scanner(self):
        from pitangus.modules.scanning import config_engines, engines, sarif_import

        def opengrep(lines):
            return engines.parse_opengrep({"results": [{"check_id": "rules.appsec.py.shell-command-non-literal", "path": "/src/app.py",
                                                        "start": {"line": line}, "extra": {"lines": "os.system(cmd)", "severity": "ERROR", "metadata": {}}}
                                                       for line in lines]})

        def secrets(lines):
            items = [({"finding_id": f"l{line}", "fingerprint": f"line-{line}", "scanner": "secrets", "tool": "betterleaks", "rule_id": "github-pat",
                       "path": "app.py", "line": line, "severity": "critical"}, 'TOKEN = "', (line, 9)) for line in lines]
            return engines.with_secret_identities(items)

        def sarif(lines):
            results = [{"ruleId": "py/command-line-injection", "message": {"text": "Command built from user input"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": line, "snippet": {"text": "os.system(cmd)"}}}}]}
                       for line in lines]
            return sarif_import.parse({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": results}]})[0]["findings"]

        def zizmor(lines):
            step = "      - uses: actions/checkout@v4\n"
            text = "jobs:\n  build:\n    steps:\n" + step * len(lines)
            starts = [text.index(step, 26 + offset * len(step)) + 8 for offset in range(len(lines))]
            report = [{"ident": "unpinned-uses", "desc": "unpinned", "determinations": {"severity": "Medium", "confidence": "High"},
                       "locations": [{"symbolic": {"key": {"Local": {"verbatim_path": "/src/ci.yml"}}, "annotation": "action is not pinned to a hash",
                                                   "kind": "Primary", "route": {"route": [{"Key": "jobs"}]}},
                                      "concrete": {"location": {"start_point": {"row": line - 1, "column": 8}, "end_point": {"row": line - 1, "column": 34},
                                                                "offset_span": {"start": start, "end": start + 26}}}}]}
                      for line, start in zip(lines, starts)]
            with tempfile.TemporaryDirectory() as folder:
                (Path(folder) / "ci.yml").write_text(text)
                return config_engines.parse_zizmor(report, Path(folder))

        for name, scanner, path in (("opengrep", opengrep, "app.py"), ("secrets", secrets, "app.py"), ("sarif", sarif, "app.py"),
                                    ("zizmor", zizmor, "ci.yml")):
            with self.subTest(scanner=name):
                # The base had it on line 5; the PR pastes a copy on line 5 and the original moves to line 6.
                outcome = self.gate(scanner([5]), scanner([5, 6]), {path: {5}})
                self.assertEqual([item["line"] for item in outcome["introduced"]], [5])
                self.assertEqual(outcome["preexisting"], [])
                # Touching the original without adding a copy introduces nothing.
                outcome = self.gate(scanner([5]), scanner([5]), {path: {5}})
                self.assertEqual((outcome["introduced"], len(outcome["preexisting"])), ([], 1))
                # Two copies at once: two introduced.
                self.assertEqual(len(self.gate(scanner([5]), scanner([4, 5, 6]), {path: {4, 5}})["introduced"]), 2)


class JobTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        self.repo = self.data_dir / "repo"
        self.repo.mkdir()
        (self.repo / "app.py").write_text(APP, encoding="utf-8")
        # The engines answer without Docker: Opengrep with what it would find here, the rest with nothing.
        empty = lambda key: lambda *args, **kwargs: scan_engines._result(key, "completed", "")  # noqa: E731
        for name, value in (("engines_available", lambda: True), ("host_mount_problem", lambda *args: None),
                            ("load_feeds", lambda *args: {"kev": {}, "epss": {}}), ("run_opengrep", fake_opengrep),
                            ("run_betterleaks", empty("betterleaks")), ("run_trivy", empty("trivy")), ("run_osv_scanner", empty("osv-scanner")),
                            ("run_checkov", empty("checkov")), ("run_zizmor", empty("zizmor"))):
            replaced = patch.object(scan_repository, name, side_effect=value)
            replaced.start()
            self.addCleanup(replaced.stop)
        self.posted = []

    def tearDown(self):
        self.directory.cleanup()

    def save_main(self):
        # The main branch already had `old`, with its fingerprint.
        main = self.data_dir / "main"
        main.mkdir(exist_ok=True)
        (main / "app.py").write_text(APP.split("\n\n\ndef new")[0] + "\n", encoding="utf-8")
        from pitangus.modules.scanning.repository import scan_repository
        scan = scan_repository(main, {"id": "github:org/api", "name": "org/api", "provider": "github", "files": 1})
        return save_repository_scan(self.data_dir, scan)

    def run_review(self, permissions, *, baseline=True, patch_text=PATCH, files=None):
        if baseline:
            self.save_main()

        def snapshot(source_id, destination, tokens, installation, ref=None, progress=None):
            self.assertEqual(ref, SHA)
            shutil.copytree(self.repo, destination, dirs_exist_ok=True)
            return destination, {"id": source_id, "name": "org/api", "provider": "github", "files": 1, "sha256": "x"}

        pull = {"number": 12, "title": "Nueva función", "url": "https://github.com/org/api/pull/12", "author": "ana",
                "head_sha": SHA, "head_ref": "feat", "base_ref": "main", "draft": False}
        with patch("pitangus.modules.runs.jobs.snapshot_source", snapshot), \
                patch("pitangus.modules.integrations.github.pull_files",
                      return_value=files or [{"filename": "app.py", "status": "modified", "patch": patch_text}]), \
                patch("pitangus.modules.integrations.github.installation_details", return_value={"permissions": permissions}), \
                patch("pitangus.modules.integrations.github.upsert_pr_comment", side_effect=lambda *args: self.posted.append(("comment", args)) or "created"), \
                patch("pitangus.modules.integrations.github.set_commit_status", side_effect=lambda *args: self.posted.append(("status", args))):
            jobs = ScanJobs(self.data_dir)
            queued = jobs.enqueue_pr_review(source_id="github:org/api", pull=pull, installation_id=7, requested_by="ana")
            for _ in range(200):
                record = load_run(self.data_dir, queued["id"])
                if record["status"] not in ("queued", "running"):
                    break
                time.sleep(0.05)
        return record

    def test_review_counts_only_what_the_pr_introduces_and_reports_it(self):
        record = self.run_review({"pull_requests": "write", "statuses": "write", "contents": "read"})
        self.assertEqual(record["type"], "pr_review")
        self.assertEqual([item["rule_id"] for item in record["findings"]], ["appsec.py.eval-exec-non-literal"])
        self.assertEqual(record["summary"]["candidates"], 1)
        self.assertIsNotNone(record["review"]["baseline_run"])
        self.assertEqual(record["review"]["verdict"]["state"], "success")  # medium, below the high threshold
        kinds = [kind for kind, _ in self.posted]
        self.assertEqual(kinds, ["comment", "status"])
        body = self.posted[0][1][3]
        self.assertIn("> [!WARNING]", body)
        self.assertIn("**1 hallazgo nuevo**", body)
        self.assertEqual(pr_watch.reviewed(self.data_dir, "github:org/api")["12"]["head_sha"], SHA)
        report = render_profile_report(record, "soc2")
        self.assertIn("una ejecución puntual", report)
        self.assertTrue(render_pdf(report, title="SOC 2 Tipo II", kind="Revisión de PR").startswith(b"%PDF-"))

    def test_without_write_permission_the_review_still_happens(self):
        record = self.run_review({"contents": "read", "metadata": "read"})
        self.assertEqual(self.posted, [])
        self.assertIn("sin permiso", text(record["review"]["delivery"]["comment"]))

    def test_a_review_counts_copies_like_the_registry_and_leaves_the_main_branch_as_it_was(self):
        from pitangus.modules.findings import registry
        from pitangus.modules.sources.assets import asset_key
        with patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": "v2"}):
            main = self.save_main()
            key = asset_key(main)
            before = json.dumps(registry.load(self.data_dir, key)["findings"], sort_keys=True)
            # The PR pastes one more copy of `old`, reformatted and commented, and comments the original.
            (self.repo / "app.py").write_text(APP.replace("    return subprocess.run(cmd, shell=True)\n",
                                                          "    return subprocess.run(cmd, shell=True)  # nosec\n"
                                                          "    return subprocess.run( cmd,  shell=True )\n"), encoding="utf-8")
            patch_text = ("@@ -4 +4,2 @@\n-    return subprocess.run(cmd, shell=True)\n+    return subprocess.run(cmd, shell=True)  # nosec\n"
                          "+    return subprocess.run( cmd,  shell=True )\n@@ -5,0 +7,3 @@\n+\n+def new(user):\n+    return eval(user)\n")
            record = self.run_review({}, baseline=False, patch_text=patch_text)
        self.assertEqual(sorted(item["rule_id"] for item in record["findings"]),
                         ["appsec.py.eval-exec-non-literal", "appsec.py.shell-command-non-literal"])
        self.assertEqual((record["review"]["baseline_run"], record["summary"]["preexisting"]), (main["id"], 1))
        after = registry.load(self.data_dir, key)["findings"]
        self.assertEqual(json.dumps({digest: after[digest] for digest in json.loads(before)}, sort_keys=True), before)

    def test_moving_a_line_to_another_file_or_renaming_one_introduces_nothing_and_copying_one_introduces_one(self):
        """S1, through the whole job: GitHub's files (a rename with its `previous_filename`), the stored baseline and the
        verdict. The main branch has `old` in app.py."""
        main = APP.split("\n\n\ndef new")[0] + "\n"
        line = "    return subprocess.run(cmd, shell=True)\n"
        moved = {"app.py": main.replace(line, "    return None\n"), "lib/run.py": f"import subprocess\n\ndef run(cmd):\n{line}"}
        cases = {
            "renamed": ({"service.py": main}, [{"filename": "service.py", "status": "renamed", "previous_filename": "app.py", "changes": 0}], 0),
            "moved": (moved, [{"filename": "app.py", "status": "modified", "patch": f"@@ -4 +4 @@\n-{line}+    return None\n"},
                              {"filename": "lib/run.py", "status": "added", "patch": None}], 0),
            "copied": ({"app.py": main, "lib/run.py": moved["lib/run.py"]}, [{"filename": "lib/run.py", "status": "added", "patch": None}], 1),
        }
        for name, (tree, files, expected) in cases.items():
            with self.subTest(name):
                shutil.rmtree(self.repo)
                for path, content in tree.items():
                    (self.repo / path).parent.mkdir(parents=True, exist_ok=True)
                    (self.repo / path).write_text(content, encoding="utf-8")
                record = self.run_review({}, files=files)
                self.assertEqual(record["status"], "completed")
                self.assertEqual([item["rule_id"] for item in record["findings"]], ["appsec.py.shell-command-non-literal"] * expected)
                self.assertIsNotNone(record["review"]["baseline_run"])

    def test_without_baseline_everything_in_the_diff_counts(self):
        record = self.run_review({}, baseline=False)
        self.assertEqual([item["rule_id"] for item in record["findings"]], ["appsec.py.eval-exec-non-literal"])
        self.assertIsNone(record["review"]["baseline_run"])


class SecretInDocsTests(unittest.TestCase):
    """Regression: a JWT added to README.md was ignored because documentation didn't make it into the snapshot."""

    tearDown = JobTests.tearDown

    def setUp(self):
        # Without Docker: the snapshot is what's under test, and the internal secret patterns read it.
        self.directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.directory.name)
        self.repo = self.data_dir / "repo"
        self.repo.mkdir()
        (self.repo / "app.py").write_text(APP, encoding="utf-8")
        engines = patch.dict("pitangus.modules.scanning.engines._docker_state", {"ok": False})
        engines.start()
        self.addCleanup(engines.stop)
        self.posted = []

    # The jwt.io sample JWT, assembled in parts so that the repository doesn't carry the literal.
    JWT = ".".join(("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0",
                    "KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"))

    def test_jwt_added_to_readme_is_introduced_and_blocks(self):
        from pitangus.modules.sources.repositories import _analyzable, credential_path
        self.assertTrue(_analyzable(Path("README.md")))
        self.assertIsNotNone(credential_path(("docs", ".npmrc")))  # read by the secret scanners alone
        self.assertFalse(_analyzable(Path("public/logo.png")))
        readme = "# Safari\n\nGetting started\n\n![img](a.png)\n" + self.JWT + "\nFirst, run the development server:\n"
        (self.repo / "README.md").write_text(readme, encoding="utf-8")
        patch_text = "@@ -3,3 +3,5 @@\n Getting started\n \n+![img](a.png)\n+" + self.JWT + "\n First, run the development server:\n"
        with patch("pitangus.modules.integrations.github.pull_files", return_value=[{"filename": "README.md", "status": "modified", "patch": patch_text}]):
            record = self._review_only({"pull_requests": "write", "statuses": "write"})
        secrets = [item for item in record["findings"] if item["scanner"] == "secrets"]
        self.assertEqual([(item["path"], item["line"]) for item in secrets], [("README.md", 6)])
        self.assertEqual(record["review"]["verdict"]["state"], "failure")
        self.assertNotIn(self.JWT, json.dumps(record))
        comment = next(args for kind, args in self.posted if kind == "comment")[3]
        self.assertNotIn(self.JWT, comment)
        self.assertIn("README.md:6", comment)

    def _review_only(self, permissions):
        # Same path as run_review, without a baseline and with the patch the test sets.
        def snapshot(source_id, destination, tokens, installation, ref=None, progress=None):
            import shutil
            shutil.copytree(self.repo, destination, dirs_exist_ok=True)
            return destination, {"id": source_id, "name": "org/api", "provider": "github", "files": 2, "sha256": "x"}
        pull = {"number": 4, "title": "README", "url": "u", "author": "ana", "head_sha": SHA, "head_ref": "p", "base_ref": "main", "draft": False}
        with patch("pitangus.modules.runs.jobs.snapshot_source", snapshot), \
                patch("pitangus.modules.integrations.github.installation_details", return_value={"permissions": permissions}), \
                patch("pitangus.modules.integrations.github.upsert_pr_comment", side_effect=lambda *args: self.posted.append(("comment", args)) or "created"), \
                patch("pitangus.modules.integrations.github.set_commit_status", side_effect=lambda *args: self.posted.append(("status", args))):
            jobs = ScanJobs(self.data_dir)
            queued = jobs.enqueue_pr_review(source_id="github:org/api", pull=pull, installation_id=7, requested_by="ana")
            for _ in range(200):
                record = load_run(self.data_dir, queued["id"])
                if record["status"] not in ("queued", "running"):
                    return record
                time.sleep(0.05)
        return record


class WatcherTests(unittest.TestCase):
    def test_poll_routes_each_organization_to_its_own_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            pr_watch.configure(data_dir, "github#1", enabled=True, by="operadora")
            pr_watch.configure(data_dir, "github#2", enabled=True, by="operadora")
            queued = []

            class Jobs:
                def pending(self):
                    return 0

                def enqueue_pr_review(self, **kwargs):
                    queued.append((kwargs["source_id"], kwargs["installation_id"]))

            def repositories(installation, *, fresh):
                name = "acme/api" if installation == 77 else "beta/web"
                return [{"id": f"github:{name}", "uid": "github#1" if installation == 77 else "github#2", "name": name}]

            pulls = [{"number": 1, "head_sha": "a" * 40, "draft": False}]
            with patch("pitangus.modules.integrations.github.installation_repositories", side_effect=repositories), \
                    patch("pitangus.modules.integrations.github.open_pull_requests", return_value=pulls):
                self.assertEqual(pr_watch.Watcher(data_dir, Jobs(), lambda: [77, 88]).poll(), 2)
            self.assertEqual(queued, [("github:acme/api", 77), ("github:beta/web", 88)])

    def test_poll_enqueues_each_head_once_and_skips_drafts(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            pr_watch.configure(data_dir, "github:org/api", enabled=True, by="operadora")
            pr_watch.configure(data_dir, "github:org/off", enabled=False, by="operadora")
            queued = []

            class Jobs:
                def pending(self):
                    return 0

                def enqueue_pr_review(self, **kwargs):
                    queued.append(kwargs["pull"]["number"])
                    pr_watch.mark(data_dir, kwargs["uid"], kwargs["pull"]["number"], kwargs["pull"]["head_sha"], "run")

            pulls = [{"number": 1, "head_sha": "a" * 40, "draft": False}, {"number": 2, "head_sha": "b" * 40, "draft": True}]
            watcher = pr_watch.Watcher(data_dir, Jobs(), lambda: 7)
            installed = [{"id": "github:org/api", "uid": "github#1", "name": "org/api"}, {"id": "github:org/off", "uid": "github#2", "name": "org/off"}]
            with patch("pitangus.modules.integrations.github.open_pull_requests", return_value=pulls) as listing, \
                    patch("pitangus.modules.integrations.github.installation_repositories", return_value=installed):
                self.assertEqual(watcher.poll(), 1)
                self.assertEqual(watcher.poll(), 0)  # same commit: not repeated
                pulls[0]["head_sha"] = "d" * 40      # new push
                self.assertEqual(watcher.poll(), 1)
            self.assertEqual(queued, [1, 1])
            # The settings saved by name were migrated to the stable identity.
            self.assertEqual(set(pr_watch.load(data_dir)["repositories"]), {"github#1", "github#2"})
            self.assertEqual({call.args[1] for call in listing.call_args_list}, {"org/api"})


class BranchWatchTests(unittest.TestCase):
    def test_the_default_branch_is_rescanned_when_it_changes(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"PITANGUS_BRANCH_MIN_MINUTES": "60"}):
            data_dir = Path(directory)
            for index in range(1, 6):
                pr_watch.configure(data_dir, f"github#{index}", enabled=True, by="operadora")
            pr_watch.configure(data_dir, "github#5", branch=False, by="operadora")  # PRs only
            queued = []

            class Jobs:
                pending_count = 0

                def pending(self):
                    return self.pending_count

                def enqueue_repository_scan(self, **kwargs):
                    queued.append((kwargs["source_id"], kwargs["trigger"]["head_sha"], kwargs["requested_by"]))
                    return {"id": f"{len(queued):032d}"}

            installed = [{"id": f"github:org/r{index}", "uid": f"github#{index}", "name": f"org/r{index}", "branch": "main"} for index in range(1, 6)]
            heads = {f"org/r{index}": "a" * 40 for index in range(1, 6)}
            jobs = Jobs()
            watcher = pr_watch.Watcher(data_dir, jobs, lambda: 7)
            with patch("pitangus.modules.integrations.github.installation_repositories", return_value=installed), \
                    patch("pitangus.modules.integrations.github.open_pull_requests", return_value=[]), \
                    patch("pitangus.modules.integrations.github.branch_head", side_effect=lambda installation, name, branch: heads[name]):
                self.assertEqual(watcher.poll(), 3)            # at most three per round
                self.assertEqual(watcher.poll(), 1)            # the fourth; the fifth only watches PRs
                self.assertEqual(watcher.poll(), 0)            # no new commits, no repeat
                heads["org/r1"] = "b" * 40                     # a merge, but within the minimum pause
                self.assertEqual(watcher.poll(), 0)
                state = pr_watch.load(data_dir)
                state["branches"]["github#1"]["heads"]["main"]["at"] = "2020-01-01T00:00:00+00:00"
                pr_watch._save(data_dir, state)
                jobs.pending_count = 5                         # queue full: waits
                self.assertEqual(watcher.poll(), 0)
                jobs.pending_count = 0
                self.assertEqual(watcher.poll(), 1)
            self.assertEqual(queued[-1], ("github:org/r1", "b" * 40, "vigilante"))
            self.assertNotIn("github:org/r5", {item[0] for item in queued})
            self.assertEqual(pr_watch.branch_state(data_dir, "github#1")["head_sha"], "b" * 40)


class RouteTests(HttpCase):
    def test_the_overview_shows_settings_saved_by_name_without_rewriting_them(self):
        """Old settings are keyed by name until the watcher moves them: a GET reads them and writes nothing."""
        with patch.dict(os.environ, {"PITANGUS_REQUIRE_TOTP": "none"}):
            Users(self.data_dir).create("lectora", PASSWORD, role="member")
            _, _, cookies = self.post("/api/auth/login", "login", {"username": "lectora", "password": PASSWORD})
            cookie = cookies[0].split("; ")[0]
            state = pr_watch.load(self.data_dir)
            state["repositories"]["github:org/api"] = {**pr_watch.DEFAULTS, "enabled": True}
            pr_watch._save(self.data_dir, state)
            pr_watch.mark(self.data_dir, "github:org/api", 3, "c" * 40, "0" * 32)
            before = pr_watch.load(self.data_dir)
            with patch("pitangus.app.api.pullrequests.github_installations", return_value=[7]), \
                    fake_github({7: [(1, "org/api"), (2, "org/web")]}, {7: ("org", "selected")}):
                status, overview, _ = self.call("GET", "/api/pull-requests/watch", headers={"Cookie": cookie})
            self.assertEqual(status, 200)
            self.assertEqual({row["name"]: (row["enabled"], row["reviewed"]) for row in overview["repositories"]},
                             {"org/api": (True, 1), "org/web": (False, 0)})
            self.assertEqual(pr_watch.load(self.data_dir), before)

    def test_settings_survive_when_github_denies_reading_pulls(self):
        with patch.dict(os.environ, {"PITANGUS_REQUIRE_TOTP": "none"}):
            Users(self.data_dir).create("operadora", PASSWORD, role="admin")
            _, _, cookies = self.post("/api/auth/login", "login", {"username": "operadora", "password": PASSWORD})
            cookie = cookies[0].split("; ")[0]
            with patch("pitangus.app.api.pullrequests.github_installations", return_value=[7]), \
                    fake_github({7: [(1, "org/api"), (2, "org/web")]}, {7: ("org", "selected")}), \
                    patch("pitangus.app.api.pullrequests.open_pull_requests", side_effect=GitHubAppError(PULLS_FORBIDDEN)):
                status, body, _ = self.call("GET", "/api/pull-requests?source_id=github:org/api", headers={"Cookie": cookie})
                self.assertEqual((status, body["pulls"], body["settings"]["gate"]), (200, [], "high"))
                self.assertIn("Pull requests", body["pulls_error"])
                # Several repositories at once, and the overview reflects them.
                status, body, _ = self.post("/api/pull-requests/settings", "pr-settings", {"source_ids": ["github:org/api", "github:org/web"], "enabled": True}, cookie)
                self.assertEqual((status, body["updated"]), (200, 2))
                _, overview, _ = self.call("GET", "/api/pull-requests/watch", headers={"Cookie": cookie})
                self.assertEqual((overview["enabled"], {row["name"]: row["enabled"] for row in overview["repositories"]}), (2, {"org/api": True, "org/web": True}))
                _, active, _ = self.call("GET", "/api/pull-requests/watch?only=enabled&q=web", headers={"Cookie": cookie})
                self.assertEqual(([row["name"] for row in active["repositories"]], active["total"]), (["org/web"], 1))
                status, _, _ = self.post("/api/pull-requests/settings", "pr-settings", {"source_ids": ["github:org/api", "github:otra/x"], "enabled": False}, cookie)
                self.assertEqual(status, 400)
                # Disabling all of them doesn't need to walk the catalog.
                status, body, _ = self.post("/api/pull-requests/settings", "pr-settings", {"all": True, "enabled": False}, cookie)
                self.assertEqual((status, body["updated"]), (200, 2))
                self.assertEqual(self.call("GET", "/api/pull-requests/watch", headers={"Cookie": cookie})[1]["enabled"], 0)
                # A repository outside the installation is not accepted.
                status, _, _ = self.call("GET", "/api/pull-requests?source_id=github:otra/cosa", headers={"Cookie": cookie})
                self.assertEqual(status, 400)
                status, _, _ = self.call("GET", "/api/pull-requests?source_id=github:org/fantasma", headers={"Cookie": cookie})
                self.assertEqual(status, 400)

    def test_anyone_signed_in_rescans_a_pull_request_once_at_a_time(self):
        Users(self.data_dir).create("analista", PASSWORD)
        _, _, cookies = self.post("/api/auth/login", "login", {"username": "analista", "password": PASSWORD})
        cookie = cookies[0].split("; ")[0]
        pull = {"number": 5, "title": "Add login", "url": "https://github.com/org/api/pull/5", "author": "ana", "draft": False,
                "head_sha": SHA, "head_ref": "feature", "base_ref": "main", "updated_at": None, "state": "open", "merged": False, "closed_at": None}
        body = {"source_id": "github:org/api", "number": 5}

        def review(action, payload, session=None):
            return self.call("POST", "/api/pull-requests/review", payload, {"Origin": ORIGIN, "X-Pitangus-Action": action,
                                                                            "Content-Type": "application/json", **({"Cookie": session} if session else {})})
        self.assertEqual(review("review-pr", body)[0], 401)
        with patch("pitangus.app.api.pullrequests.github_installations", return_value=[7]), \
                fake_github({7: [(1, "org/api")]}, {7: ("org", "selected")}), \
                patch("pitangus.app.api.pullrequests.pull_request", side_effect=lambda installation, name, number: dict(pull)) as fetched:
            self.assertEqual(review("wrong-action", body, cookie)[0], 403)
            for bad in ({**body, "number": True}, {**body, "number": 0}, {**body, "extra": 1}, {**body, "source_id": "gitlab:1"}):
                self.assertEqual(review("review-pr", bad, cookie)[0], 400, bad)
            self.assertEqual(review("review-pr", {**body, "source_id": "github:org/ghost"}, cookie)[0], 400)
            status, queued, _ = review("review-pr", body, cookie)
            self.assertEqual((status, queued["run"]["status"]), (202, "queued"))
            self.assertEqual(fetched.call_args.args[1:], ("org/api", 5))
            record = load_run(self.data_dir, queued["run"]["id"])
            self.assertEqual((record["requested_by"], record["source"]["uid"], record["pull_request"]["head_sha"]), ("analista", "github#1", SHA))
            # The same commit is already queued: a second click doesn't queue it twice.
            status, answer, _ = review("review-pr", body, cookie)
            self.assertEqual(status, 409)
            self.assertIn("#5", answer["error"])
            # Finished: it can be scanned again (e.g. after the settings changed).
            self.state.jobs._save({**record, "status": "completed"})
            status, again, _ = review("review-pr", body, cookie)
            self.assertEqual(status, 202)
            self.assertNotEqual(again["run"]["id"], queued["run"]["id"])
            # A new head commit is a different review even while the previous one is still queued.
            pull["head_sha"] = "d" * 40
            self.assertEqual(review("review-pr", body, cookie)[0], 202)

if __name__ == "__main__":
    unittest.main()
