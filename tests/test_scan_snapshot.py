"""What `pitangus scan --commit/--staged` (the pre-commit hook) scans: what git holds, never the folder on disk.

Property: for any repository, whatever is untracked, unstaged or staged on top, the findings of a scan of a commit are
those of a scan of a clean checkout of that commit, and a scan of the index is a scan of the commit the index would
make. A reference that doesn't exist fails with a message that says so, before anything is scanned.
"""

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hypothesis import HealthCheck, given, settings, strategies as st

from pitangus.modules.runs import local as local_scan
from pitangus.modules.runs.local import LocalScanError, run
from pitangus.shared.i18n import text

GIT = shutil.which("git")
ROOT = Path(__file__).resolve().parents[1]
PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

NAMES = ("app.py", "lib/util.py", "web/index.js", "docs/notes.txt", "svc/api.py")
CONTENT = st.one_of(st.none(), st.lists(st.sampled_from(["x = 1", "BAD one", "BAD two", "y = 2", "# note"]),
                                        min_size=1, max_size=4).map(lambda lines: "\n".join(lines) + "\n"))
STATE = st.fixed_dictionaries({"base": CONTENT, "head": CONTENT, "staged": CONTENT, "work": CONTENT,
                               "touch_index": st.booleans(), "touch_work": st.booleans()})
REPOSITORY = st.fixed_dictionaries(dict.fromkeys(NAMES, STATE)) | st.just({})
UNTRACKED = st.lists(st.sampled_from(["new.py", "lib/extra.py", "web/leak.js"]), unique=True, max_size=3)


def fake_scan(root, source, **_):
    """A deterministic engine: one finding per line that says BAD, identified by file and text."""
    findings = []
    for path in sorted(item for item in Path(root).rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if "BAD" in line:
                findings.append({"fingerprint": hashlib.sha256(f"{relative}|{line}".encode()).hexdigest(), "path": relative,
                                 "line": number, "severity": "high", "scanner": "sast", "rule_id": "bad", "title": "bad",
                                 "reason": "", "cwe": [], "owasp": [], "package": None})
    steps = [{"id": tool, "name": tool, "status": "completed", "detail": "", "tool": {"name": tool}}
             for tool in ("opengrep", "betterleaks", "trivy", "osv-scanner")]
    return {"status": "completed", "findings": findings, "steps": steps}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args], check=True,
                          capture_output=True, text=True).stdout


def write(repo: Path, name: str, content: str | None) -> None:
    path = repo / name
    if content is None:
        path.unlink(missing_ok=True)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def build(repo: Path, files: dict, untracked: list[str]) -> tuple[str, str]:
    """A base commit on main, a feature commit on top, then staged changes, unstaged edits and untracked files."""
    git(repo, "init", "-q", "-b", "main")
    for name, state in files.items():
        write(repo, name, state["base"])
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", "base")
    base = git(repo, "rev-parse", "HEAD").strip()
    git(repo, "checkout", "-q", "-b", "feature")
    for name, state in files.items():
        write(repo, name, state["head"])
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", "feature")
    head = git(repo, "rev-parse", "HEAD").strip()
    for name, state in files.items():
        if state["touch_index"]:
            write(repo, name, state["staged"])
    git(repo, "add", "-A")
    for name, state in files.items():
        if state["touch_work"]:
            write(repo, name, state["work"])
    for name in untracked:
        write(repo, name, "BAD untracked\n")
    return base, head


def comparable(result: dict) -> tuple:
    comparison = dict(result["comparison"] or {})
    return (sorted((item["path"], item["line"], item["fingerprint"]) for item in result["findings"]),
            sorted((item["fingerprint"], item["resolution"]) for item in result["resolved"]),
            comparison.get("changed_files"), comparison.get("preexisting_in_changed_code"), comparison.get("merge_base"),
            result["exit_code"])


def scan(path: Path, data: Path, **options) -> dict:
    with patch.object(local_scan, "scan_repository", side_effect=fake_scan), \
            patch("pitangus.modules.scanning.engines.docker_available", return_value=True):
        return run(path, data_dir=data, **options)


def tree(folder: Path) -> dict:
    return {path.relative_to(folder).as_posix(): path.read_bytes() for path in folder.rglob("*") if path.is_file()}


@unittest.skipUnless(GIT, "needs git")
class HookSnapshotProperties(unittest.TestCase):
    @settings(max_examples=12 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(REPOSITORY, UNTRACKED)
    def test_a_commit_scan_depends_only_on_the_commit(self, files, untracked):
        with tempfile.TemporaryDirectory() as folder:
            work, data = Path(folder) / "repo", Path(folder) / "data"
            work.mkdir()
            base, head = build(work, files, untracked)
            clean = Path(folder) / "clean"
            subprocess.run(["git", "clone", "-q", str(work), str(clean)], check=True, capture_output=True)
            for options in ({}, {"base": base}):
                dirty = scan(work, data, revision="HEAD", **options)
                self.assertEqual(dirty["snapshot"], head)
                # The same commit, checked out clean and scanned as a folder: nothing on disk changed the result.
                self.assertEqual(comparable(dirty), comparable(scan(clean, data, **options)), options)
                self.assertEqual(comparable(dirty), comparable(scan(clean, data, revision=head, **options)), options)
            # The copy holds exactly the commit's files, as a folder scan of the checkout would copy them.
            snapshot, reference = Path(folder) / "snap", Path(folder) / "ref"
            stats = local_scan.snapshot_git(work, snapshot, head)
            expected = local_scan.snapshot_directory(clean, reference)
            self.assertEqual(tree(snapshot), tree(reference))
            self.assertEqual(stats["files"], expected["files"])

    @settings(max_examples=12 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(REPOSITORY, UNTRACKED)
    def test_a_staged_scan_is_the_scan_of_the_commit_the_index_would_make(self, files, untracked):
        with tempfile.TemporaryDirectory() as folder:
            work, data = Path(folder) / "repo", Path(folder) / "data"
            work.mkdir()
            base, head = build(work, files, untracked)
            staged_tree = git(work, "write-tree").strip()
            would_be = git(work, "commit-tree", staged_tree, "-p", head, "-m", "next").strip()
            for options in ({}, {"base": base}):
                self.assertEqual(comparable(scan(work, data, staged=True, **options)),
                                 comparable(scan(work, data, revision=would_be, **options)), options)


@unittest.skipUnless(GIT, "needs git")
class HookSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name) / "repo"
        self.repo.mkdir()
        self.data = Path(self.directory.name) / "data"
        build(self.repo, {"app.py": {"base": "x = 1\n", "head": "x = 1\n", "staged": None, "work": None,
                                     "touch_index": False, "touch_work": False}}, ["leak.py"])

    def test_an_untracked_file_never_blocks_the_hook(self):
        self.assertEqual(scan(self.repo, self.data)["exit_code"], local_scan.EXIT_BLOCKED)  # the folder: it counts
        for options in ({"revision": "HEAD"}, {"revision": "HEAD", "base": "main"}, {"staged": True}):
            result = scan(self.repo, self.data, **options)
            self.assertEqual((result["findings"], result["exit_code"]), ([], local_scan.EXIT_OK), options)
            self.assertIn("staged changes" if options.get("staged") else "commit ",
                          local_scan.render_text(result, locale="en").splitlines()[0])

    def test_a_reference_that_does_not_exist_says_so_before_scanning(self):
        for options in ({"base": "origin/nope"}, {"revision": "nope"}, {"base": "main", "revision": "nope"}):
            with patch.object(local_scan, "scan_repository", side_effect=AssertionError("scanned")), \
                    self.assertRaises(LocalScanError) as raised:
                run(self.repo, data_dir=self.data, **options)
            self.assertEqual(raised.exception.message["$t"], "scanning.local.errors.unknown_ref", options)
            self.assertIn("doesn't exist", text(raised.exception.message, "en"))
            self.assertIn("No existe", text(raised.exception.message, "es"))

    def test_the_cli_prints_the_missing_reference(self):
        from contextlib import redirect_stderr
        from io import StringIO
        from pitangus.cli.main import main
        errors = StringIO()
        with redirect_stderr(errors), patch.dict(os.environ, {"PITANGUS_DEFAULT_LOCALE": "en"}):
            code = main(["--data-dir", str(self.data), "scan", str(self.repo), "--base", "origin/nope", "--quiet"])
        self.assertEqual(code, local_scan.EXIT_ERROR)
        self.assertIn("'origin/nope' doesn't exist", errors.getvalue())

    def test_unrelated_histories_have_no_starting_point(self):
        git(self.repo, "checkout", "-q", "--orphan", "other")
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "other")
        with self.assertRaises(LocalScanError) as raised:
            local_scan.merge_base(self.repo, "main")
        self.assertEqual(raised.exception.message["$t"], "scanning.local.errors.no_merge_base")

    def test_commit_and_staged_are_exclusive(self):
        with self.assertRaises(LocalScanError):
            run(self.repo, data_dir=self.data, revision="HEAD", staged=True)


FAKE_DOCKER = '#!/bin/sh\nfor arg in "$@"; do printf "%s\\n" "$arg"; done > "$DOCKER_LOG"\n'


@unittest.skipUnless(shutil.which("sh"), "needs sh")
class HookScriptTests(unittest.TestCase):
    """hooks/pitangus-docker with a fake docker: what it asks the scan for under each pre-commit environment."""

    def call(self, env: dict, *args: str) -> list[str]:
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "docker").write_text(FAKE_DOCKER)
            (Path(folder) / "docker").chmod(0o755)
            log = Path(folder) / "log"
            clean = {key: value for key, value in os.environ.items() if not key.startswith(("PRE_COMMIT", "PITANGUS_"))}
            subprocess.run(["sh", str(ROOT / "hooks" / "pitangus-docker"), *args], check=True, cwd=folder,
                           env={**clean, "PATH": f"{folder}:{os.environ['PATH']}", "DOCKER_LOG": str(log), **env})
            words = log.read_text().splitlines()
        return words[words.index("scan") + 1:]

    def options(self, words: list[str]) -> dict:
        return {word: words[index + 1] for index, word in enumerate(words) if word in ("--commit", "--base")}

    def test_at_pre_push_it_scans_the_pushed_commit_against_what_the_remote_has(self):
        words = self.call({"PRE_COMMIT_FROM_REF": "a" * 40, "PRE_COMMIT_TO_REF": "b" * 40, "PRE_COMMIT_REMOTE_BRANCH": "refs/heads/x"})
        self.assertEqual(self.options(words), {"--commit": "b" * 40, "--base": "a" * 40})
        self.assertIn("--quiet", words)

    def test_a_chosen_base_wins(self):
        words = self.call({"PRE_COMMIT_FROM_REF": "a" * 40, "PRE_COMMIT_TO_REF": "b" * 40, "PITANGUS_BASE": "origin/develop"})
        self.assertEqual(self.options(words), {"--commit": "b" * 40, "--base": "origin/develop"})

    def test_by_hand_it_scans_head_against_origin_main(self):
        self.assertEqual(self.options(self.call({})), {"--commit": "HEAD", "--base": "origin/main"})

    def test_a_new_history_is_all_new(self):
        words = self.call({"PRE_COMMIT_REMOTE_BRANCH": "refs/heads/main", "PRE_COMMIT_LOCAL_BRANCH": "refs/heads/main"})
        self.assertEqual(self.options(words), {"--commit": "refs/heads/main"})

    def test_staged_scans_the_index_never_the_folder(self):
        words = self.call({}, "--staged")
        self.assertNotIn("--commit", words)
        self.assertIn("--staged", words)

    def test_the_hook_never_scans_the_folder_on_disk(self):
        for env in ({}, {"PRE_COMMIT_FROM_REF": "a" * 40, "PRE_COMMIT_TO_REF": "b" * 40},
                    {"PRE_COMMIT_REMOTE_BRANCH": "r", "PRE_COMMIT_LOCAL_BRANCH": "l"}):
            for args in ((), ("--staged",), ("--fail-on", "medium")):
                words = self.call(env, *args)
                self.assertTrue("--commit" in words or "--staged" in words, (env, args))


if __name__ == "__main__":
    unittest.main()
