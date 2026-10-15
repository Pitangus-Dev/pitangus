"""What was committed is the commit's tree, not the provider's archive.

GitHub and GitLab serve `git archive`: it leaves out what `.gitattributes` marks `export-ignore`, a submodule's files and
an LFS object (only its pointer comes), and an archive may hold names no file here can be written under (`a\\b.py`). A
pull request could hide a secret by adding one line to `.gitattributes`. The property: every entry of the tree is in
the snapshot as committed, or it is declared unexamined with why, whatever made the archive leave it out, and however
many there are (a long list is declared by folder, never cut). The generated trees use random names, links,
submodules, LFS pointers and archives that drop random entries: nothing here depends on knowing why one is missing.
"""

import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from hypothesis import HealthCheck, example, given, settings, strategies as st

from pitangus.modules.findings import registry
from pitangus.modules.runs import local
from pitangus.modules.runs.store import save_and_apply
from pitangus.modules.scanning import engines, repository
from pitangus.modules.sources import repositories
from pitangus.modules.sources.repositories import _extract_limited, secrets_root
from pitangus.shared import coverage_units
from test_secret_pass_coverage import TOKEN, SecretEngines, _completed, detected

PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

PREFIX = "org-repo-abc123"
POINTER = b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"4d" * 32 + b"\nsize 123456\n"


def archive(members: list[tuple[str, bytes | None]]) -> bytes:
    """A provider's archive: each (path, content) a file, (path, None) a symbolic link."""
    blob = io.BytesIO()
    with tarfile.open(fileobj=blob, mode="w:gz") as tar:
        for name, data in members:
            info = tarfile.TarInfo(f"{PREFIX}/{name}")
            if data is None:
                info.type, info.linkname = tarfile.SYMTYPE, "elsewhere"
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    return blob.getvalue()


def held(root: Path) -> dict[str, bytes]:
    return {path.relative_to(folder).as_posix(): path.read_bytes() for folder in (root, secrets_root(root)) if folder.is_dir()
            for path in folder.rglob("*") if path.is_file() and not path.is_symlink()}


class TreeAssertions(unittest.TestCase):
    def assert_every_entry_held_or_declared(self, tree: dict[str, str], root: Path, stats: dict) -> None:
        copy = held(root)
        for path, kind in tree.items():
            probe = path if kind != "submodule" else path + "/any/file.py"
            as_committed = kind == "file" and path in copy and not repositories.lfs_pointer(copy[path])
            self.assertTrue(as_committed or coverage_units.inside(probe, stats["unexamined"]), (path, kind, stats["unexamined"]))
            if not as_committed:   # and a dependency found there before stays in its project, unexamined
                self.assertTrue(coverage_units.inside(coverage_units.unit(probe, "sca"), stats["unexamined"], "sca"), path)


SEGMENT = st.one_of(st.sampled_from(["src", "config", "docs", "a b", "ñandú", ".github", "node_modules", "dist", "x\\y", "tests"]),
                    st.from_regex(r"[a-z][a-z0-9_.\\-]{0,8}", fullmatch=True).filter(lambda name: name not in (".", "..", ".git")))
NAME = st.one_of(st.sampled_from(["app.py", "settings.py", "prod.env.txt", ".env", "win\\path.py", "logo.png", "big.psd", "id_rsa"]),
                 st.from_regex(r"[a-z][a-z0-9_\\-]{0,8}\.(py|js|txt|lock|bin)", fullmatch=True))
PATH = st.builds(lambda folders, name: "/".join([*folders, name]), st.lists(SEGMENT, max_size=4), NAME)
# What happens to each committed entry in the provider's archive.
FATES = ("held", "held", "held", "export-ignore", "lfs", "symlink", "submodule")


class TreePropertyTests(TreeAssertions):
    @settings(max_examples=60 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
    @given(st.dictionaries(PATH, st.sampled_from(FATES), min_size=1, max_size=25), st.integers(1, 30))
    @example({"src/app.py": "held", "config/settings.py": "export-ignore", "prod.env.txt": "export-ignore", "src\\win.py": "held"}, 30)
    @example({f"gen/m{index}.py": "export-ignore" for index in range(12)} | {"gen/keep.py": "held", "a.py": "held"}, 2)
    @example({"app.py": "submodule"}, 1)   # nightly: a submodule is its path and its folder
    def test_every_committed_entry_is_held_as_committed_or_declared(self, fates, cap):
        # A path can't be both a file and a folder: keep the first of each.
        names = sorted(fates)
        fates = {path: fate for path, fate in fates.items() if not any(other.startswith(path + "/") for other in names)}
        tree = {path: "submodule" if fate == "submodule" else "symlink" if fate == "symlink" else "file" for path, fate in fates.items()}
        members = [(path, None if fate == "symlink" else POINTER if fate == "lfs" else b"x = 1\n")
                   for path, fate in fates.items() if fate in ("held", "lfs", "symlink")]
        with tempfile.TemporaryDirectory() as folder, patch.object(repositories, "UNEXAMINED_MAX", cap):
            root = Path(folder) / "head"
            stats = _extract_limited(archive(members), root, tree)
            self.assert_every_entry_held_or_declared(tree, root, stats)
        # Never cut: a long list is coarser (by folder), down to a top-level entry and its folder at most.
        tops = {path.split("/", 1)[0] for path in tree}
        self.assertLessEqual(len(stats["unexamined"]), max(cap, 2 * len(tops)))
        self.assertEqual(stats.get("committed", {}).get("not_in_archive", 0),
                         sum(1 for fate in fates.values() if fate == "export-ignore"))

    def test_without_a_tree_every_member_is_held_or_declared_and_nothing_is_skipped_in_silence(self):
        """The archive alone (a caller with no tree): a name no file can be written under, a link, `..`, `.git`."""
        members = [("ok.py", b"x = 1\n"), ("src\\win.py", b"k = 1\n"), ("link", None), ("a/../../escape.py", b"x\n"), (".git/config", b"x\n")]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "head"
            stats = _extract_limited(archive(members), root)
            self.assertTrue((root / "ok.py").is_file())
        self.assertEqual(stats["unexamined"], {"src\\win.py": "unwritable_name", "link": "symlink", "a/": "unwritable_name", ".git/": "unwritable_name"})
        for path in ("src\\win.py", "link", "a/../../escape.py", ".git/config"):
            self.assertTrue(coverage_units.inside(path, stats["unexamined"]), path)

    def test_beyond_the_listing_cap_the_rest_is_declared_by_folder_not_dropped(self):
        members = [(f"gen/{index}/m.py", b"x" * 50) for index in range(40)] + [("keep.py", b"x\n")]
        with tempfile.TemporaryDirectory() as folder, patch.object(repositories, "UNEXAMINED_MAX", 5), \
                patch.object(repositories, "MAX_FILE", 10):
            root = Path(folder) / "head"
            stats = _extract_limited(archive(members), root)
        self.assertEqual(stats["unexamined"], {"gen/": "left_out"})
        self.assertTrue(all(coverage_units.inside(f"gen/{index}/m.py", stats["unexamined"]) for index in range(40)))
        self.assertFalse(coverage_units.inside("keep.py", stats["unexamined"]))


@unittest.skipUnless(shutil.which("git"), "git is not installed")
class GitArchiveTests(TreeAssertions):
    """The adversary's repository, as git builds it: `export-ignore` on a folder and a file, a name with a backslash, a
    link, a submodule and an LFS pointer. The archive is `git archive`'s, the tree `git ls-tree`'s."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name) / "repo"
        self.repo.mkdir()

    def git(self, *arguments: str) -> str:
        return subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false",
                               *arguments], check=True, capture_output=True, text=True).stdout

    def test_what_git_archive_leaves_out_is_declared(self):
        self.git("init", "-q")
        files = {".gitattributes": "config/** export-ignore\nprod.env.txt export-ignore\n", "src/app.py": "x = 1\n",
                 "config/settings.py": 'TOKEN = "x"\n', "prod.env.txt": 'TOKEN = "x"\n', "src\\win.py": 'TOKEN = "x"\n',
                 "assets/model.bin": POINTER.decode()}
        for name, content in files.items():
            (self.repo / name).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / name).write_text(content)
        (self.repo / "docs").mkdir()
        os.symlink("../src/app.py", self.repo / "docs" / "app.py")
        self.git("add", "-A")
        self.git("update-index", "--add", "--cacheinfo", "160000," + "1" * 40 + ",vendor/lib")
        self.git("commit", "-q", "-m", "init")
        blob = subprocess.run(["git", "-C", str(self.repo), "archive", "--format=tar.gz", f"--prefix={PREFIX}/", "HEAD"],
                              check=True, capture_output=True).stdout
        _, tree = local._tree_entries(self.repo, "HEAD")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "head"
            stats = _extract_limited(blob, root, tree)
            self.assert_every_entry_held_or_declared(tree, root, stats)
        self.assertEqual(stats["unexamined"],
                         {"config/": "not_in_archive", "prod.env.txt": "not_in_archive", "src\\win.py": "unwritable_name",
                          "assets/": "lfs_object", "docs/": "symlink", "vendor/": "submodule"})

    def test_a_local_commit_declares_what_it_doesnt_write(self):
        self.git("init", "-q")
        (self.repo / "app.py").write_text("x = 1\n")
        (self.repo / "model.bin").write_bytes(POINTER)
        os.symlink("app.py", self.repo / "link.py")
        self.git("add", "-A")
        self.git("update-index", "--add", "--cacheinfo", "160000," + "2" * 40 + ",sub")
        self.git("commit", "-q", "-m", "init")
        with tempfile.TemporaryDirectory() as folder:
            stats = local.snapshot_git(self.repo, Path(folder) / "head", local.resolve(self.repo, "HEAD"))
        self.assertEqual(stats["unexamined"], {"link.py": "symlink", "model.bin": "lfs_object", "sub": "submodule", "sub/": "submodule"})


class GitHubTreeTests(unittest.TestCase):
    """The tree comes from the provider's API for the exact commit of the archive; a truncated one is walked."""

    def test_a_truncated_tree_is_walked_and_what_stays_unlisted_is_declared_whole(self):
        trees = {
            ("c" * 40, True): {"truncated": True, "tree": []},
            ("c" * 40, False): {"tree": [{"path": "a", "type": "tree", "sha": "a" * 40}, {"path": "b", "type": "tree", "sha": "b" * 40},
                                         {"path": "README.md", "type": "blob", "mode": "100644"}]},
            ("a" * 40, True): {"truncated": False, "tree": [{"path": "x.py", "type": "blob", "mode": "100644"},
                                                            {"path": "lib", "type": "commit", "mode": "160000"}]},
            ("b" * 40, True): {"truncated": True, "tree": []},
            ("b" * 40, False): {"tree": [{"path": "deep", "type": "tree", "sha": "d" * 40}]},
            ("d" * 40, True): {"truncated": True, "tree": []},
        }

        def answer(url, token, provider):
            sha = url.split("/git/trees/")[1].split("?")[0]
            return trees[(sha, url.endswith("?recursive=1"))]
        with patch.object(repositories, "_json_request", side_effect=answer), patch.object(repositories, "TREE_REQUESTS", 6):
            tree = repositories._github_tree("org/repo", "c" * 40, "t")
        self.assertEqual(tree, {"README.md": "file", "a/x.py": "file", "a/lib": "submodule", "b/deep/": "unlisted"})

    def test_a_folder_sha_that_isnt_an_object_name_fails_the_snapshot_never_reaches_a_url(self):
        """The API's answer names the next tree to fetch: only a SHA-1 or SHA-256 object name goes into its URL."""
        for sha in ("../../users/x", "a" * 40 + "?x=1", "A" * 40, "a" * 39, "a" * 41, "", "a" * 63):
            urls: list[str] = []

            def answer(url, token, provider, sha=sha, urls=urls):
                urls.append(url)
                if len(urls) == 1:
                    return {"truncated": True, "tree": []}
                return {"tree": [{"path": "a", "type": "tree", "sha": sha}]}
            with self.subTest(sha=sha), patch.object(repositories, "_json_request", side_effect=answer):
                with self.assertRaises(repositories.SourceError):
                    repositories._github_tree("org/repo", "c" * 40, "t")
                self.assertEqual(len(urls), 2)
        with patch.object(repositories, "_json_request", side_effect=[{"truncated": True, "tree": []},
                                                                      {"tree": [{"path": "a", "type": "tree", "sha": "e" * 64}]},
                                                                      {"truncated": False, "tree": []}]):
            self.assertEqual(repositories._github_tree("org/repo", "c" * 40, "t"), {})

    def test_a_tree_that_cant_be_listed_fails_the_snapshot_never_trusts_the_archive(self):
        """Fault injection: the provider's tree answer broken in every way: the snapshot fails (the run says why), it
        never falls back to taking the archive as what was committed."""
        listing = json.dumps([{"full_name": "org/repo", "private": True, "default_branch": "main"}]).encode()
        for broken in (b"{not json", b"[]", b'{"tree": "x"}', b'{"truncated": false}', repositories.SourceError("down")):
            with self.subTest(answer=broken), tempfile.TemporaryDirectory() as folder, patch.dict("os.environ", {"GITHUB_TOKEN": "t"}), \
                    patch.object(repositories, "_request", side_effect=[listing, b"f" * 40, broken]), \
                    patch.object(repositories, "_download_archive", side_effect=lambda *args, **kwargs: args[3].write_bytes(archive([("a.py", b"x\n")]))):
                with self.assertRaises(repositories.SourceError):
                    repositories.snapshot_source("github:org/repo", Path(folder) / "head")
        for commit in (b"", b"not-a-sha", b"<html>", b"f" * 39):
            with self.subTest(commit=commit), tempfile.TemporaryDirectory() as folder, patch.dict("os.environ", {"GITHUB_TOKEN": "t"}), \
                    patch.object(repositories, "_request", side_effect=[listing, commit]):
                with self.assertRaises(repositories.SourceError):
                    repositories.snapshot_source("github:org/repo", Path(folder) / "head")

    def test_the_snapshot_says_what_the_commit_holds_that_the_archive_doesnt(self):
        commit = "f" * 40
        listing = json.dumps([{"full_name": "org/repo", "private": True, "default_branch": "main"}]).encode()
        tree = json.dumps({"truncated": False, "tree": [{"path": "app.py", "type": "blob", "mode": "100644"},
                                                        {"path": "secret.py", "type": "blob", "mode": "100644"}]}).encode()
        with tempfile.TemporaryDirectory() as folder, patch.dict("os.environ", {"GITHUB_TOKEN": "t"}), \
                patch.object(repositories, "_request", side_effect=[listing, commit.encode(), tree]), \
                patch.object(repositories, "_download_archive", side_effect=lambda *args, **kwargs: args[3].write_bytes(archive([("app.py", b"x\n")]))):
            _, selected = repositories.snapshot_source("github:org/repo", Path(folder) / "head")
        self.assertEqual(selected["snapshot"]["unexamined"], {"secret.py": "not_in_archive"})
        self.assertEqual(selected["snapshot"]["committed"], {"not_in_archive": 1})


class RegistryTests(unittest.TestCase):
    """A secret found in a file, then the same commit's archive without it (`export-ignore`, an LFS pointer in its
    place): never fixed. Deleted from the tree: fixed."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name) / "data"
        self.data_dir.mkdir()
        self.clock = datetime.now(timezone.utc)
        modes = patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "on", "PITANGUS_IDENTITY_MODE": "v2", "PITANGUS_FIX_HOLD_MINIMUM": "100000"})
        modes.start()
        self.addCleanup(modes.stop)

    def scan(self, members: list[tuple[str, bytes | None]], tree: dict[str, str]) -> tuple[dict, dict]:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "head"
            stats = _extract_limited(archive(members), root, tree)
            replaced = [patch.object(engines, "_run", side_effect=SecretEngines()), patch.object(engines, "unavailable", return_value=None),
                        patch.object(engines, "runner", return_value="docker"), patch.object(engines, "trivy_databases", return_value=[]),
                        patch.object(repository, "engines_available", return_value=True), patch.object(repository, "host_mount_problem", return_value=None),
                        patch.object(repository, "load_feeds", return_value={"kev": {}, "epss": {}}),
                        *(patch.object(repository, name, side_effect=_completed(key)) for name, key in
                          (("run_opengrep", "opengrep"), ("run_osv_scanner", "osv-scanner"), ("run_checkov", "checkov"), ("run_zizmor", "zizmor")))]
            for item in replaced:
                item.start()
            try:
                record = repository.scan_repository(root, {"id": "github:org/app", "uid": "github#tree", "name": "org/app", "provider": "github",
                                                           "snapshot": stats}, data_dir=Path(folder))
            finally:
                for item in replaced:
                    item.stop()
        self.clock += timedelta(hours=1)
        return save_and_apply(self.data_dir, {**record, "finished_at": self.clock.isoformat()}, created_at=self.clock.isoformat(), quiet=True)

    @settings(max_examples=8 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    @given(TOKEN, PATH.filter(lambda path: "\\" not in path and path != "app.py"), st.sampled_from(["export-ignore", "lfs", "symlink", "submodule"]))
    @example("ghp_" + "Zq9xK2mP7vL4wR8tY1nBc3dE5fG6hJ8kL0aS", "config/settings.py", "export-ignore")
    def test_a_secret_the_archive_stops_holding_is_never_fixed_and_one_deleted_is(self, token, path, fate):
        self.setUp()
        tree = {path: "file", "app.py": "file"}
        first, _ = self.scan([(path, f'k = "{token}"\n'.encode()), ("app.py", b"x = 1\n")], tree)
        found = {item["fingerprint"] for item in first["findings"] if item["scanner"] == "secrets" and item["path"] == path}
        self.assertTrue(found and detected(first, "betterleaks", path), path)
        hidden_tree = {**tree, path: {"symlink": "symlink", "submodule": "submodule"}.get(fate, "file")}
        members = [("app.py", b"x = 1\n"), *([(path, POINTER)] if fate == "lfs" else [(path, None)] if fate == "symlink" else [])]
        _, changes = self.scan(members, hidden_tree)
        self.assertFalse(found & set(changes["fixed_now"]), (path, fate))
        entries = registry.load(self.data_dir, "github#tree")["findings"]
        self.assertTrue(all(entries[digest]["status"] == "open" and entries[digest]["unseen"]["reason"] == "not_covered" for digest in found))
        _, changes = self.scan([("app.py", b"x = 1\n")], {"app.py": "file"})
        self.assertEqual(found, found & set(changes["fixed_now"]))


if __name__ == "__main__":
    unittest.main()
