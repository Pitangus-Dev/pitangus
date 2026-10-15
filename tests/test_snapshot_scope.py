"""What each engine reads of a repository (sources/repositories.py): everything committed goes through the secret pass,
whatever folder it's in and however deep; SAST and the other engines leave out only dependency and build output folders,
each listed unexamined with why, so nothing they found there before is taken as fixed."""

import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hypothesis import example, given, settings, strategies as st

from pitangus.modules.findings import registry
from pitangus.modules.scanning import engine_contract, engines, repository
from pitangus.modules.sources import repositories
from pitangus.modules.sources.repositories import _extract_limited, secrets_root, snapshot_directory
from pitangus.shared import coverage_units

PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

TOKEN = "const token = 'ghp_R7tqP2mXw9LkV4zN8sYb3HcJ6dFa1Ge5Ui0K';\n"  # gitleaks:allow
NAMED = sorted(repositories.DEPENDENCY_FOLDERS | repositories.OUTPUT_FOLDERS | repositories.LOCAL_ONLY
               | {"data", "src", "lib", "app", "tests", "public", "packages", "web", "static", "assets"})
folder = st.one_of(st.sampled_from(NAMED), st.from_regex(r"[a-z][a-z0-9_-]{0,8}", fullmatch=True))
folders = st.lists(folder, min_size=0, max_size=5)


def archive(files: dict[str, str]) -> bytes:
    blob = io.BytesIO()
    with tarfile.open(fileobj=blob, mode="w:gz") as tar:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(f"repo-abc123/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return blob.getvalue()


def tree(root: Path) -> set[str]:
    return {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()} if root.is_dir() else set()


class CommittedScopeTests(unittest.TestCase):
    @settings(max_examples=150 * SCALE, deadline=None)
    @given(folders, st.lists(st.tuples(folders, st.sampled_from(["package.json", "pom.xml", "app.js.map", "main.py", "README.md"])), max_size=4))
    @example(["src", "data"], [])
    @example(["src", "build"], [])
    @example(["vendor", "lib"], [])
    @example(["node_modules", "pkg"], [])
    @example(["packages", "web", "dist"], [(["packages", "web"], "package.json")])
    def test_a_committed_file_reaches_the_secret_pass_and_sast_leaves_it_out_only_with_a_reason(self, where, others):
        """Under any folder names at any depth: the token file is in the snapshot or in the copy only the secret scanners
        read; if it isn't in the snapshot, a folder of `apart` holds it with why; nothing in the snapshot is under one.
        A commit copied from git gives the same answer as the repository's archive."""
        target = "/".join([*where, "conf.js"])
        files = {target: TOKEN, **{"/".join([*place, name]): "x\n" for place, name in others}}
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "head"
            stats = _extract_limited(archive(files), root)
            main, secret = tree(root), tree(secrets_root(root))
            source = Path(folder) / "raw"
            for name, content in files.items():
                (source / name).parent.mkdir(parents=True, exist_ok=True)
                (source / name).write_text(content)
            again = Path(folder) / "again" / "head"
            committed = snapshot_directory(source, again, committed=True)
            self.assertEqual((tree(again), tree(secrets_root(again)), committed["apart"]), (main, secret, stats["apart"]))
        self.assertIn(target, main | secret)
        self.assertEqual(main | secret, set(files))
        self.assertFalse(main & secret)
        for path in secret:
            # Under a folder set apart (listed unexamined for the code engines), or a file they never read by its name.
            self.assertTrue(coverage_units.inside(path, stats["apart"]) or not repositories._analyzable(Path(path)), path)
        for path in main:
            self.assertFalse(coverage_units.inside(path, stats["apart"]), path)
        self.assertTrue(set(stats["apart"].values()) <= {"dependencies", "generated"})

    @settings(max_examples=100 * SCALE, deadline=None)
    @given(st.lists(st.from_regex(r"[a-z][a-z0-9]{1,8}", fullmatch=True).filter(lambda name: name not in NAMED), min_size=1, max_size=4),
           st.sampled_from(sorted(repositories.OUTPUT_FOLDERS - {"__pycache__"})))
    def test_a_build_folder_is_generated_only_with_a_signal(self, where, output):
        """`src/build/x.js` is source; the same folder next to a build manifest, or holding a source map, is build output.
        At the root it always is."""
        def apart(extra: dict[str, str]) -> dict[str, str]:
            with tempfile.TemporaryDirectory() as folder:
                return _extract_limited(archive({"/".join([*where, output, "x.js"]): TOKEN, **extra}), Path(folder) / "head")["apart"]
        inner = "/".join([*where, output]) + "/"
        self.assertEqual(apart({}), {})
        self.assertEqual(apart({"/".join([*where, "package.json"]): "{}"}), {inner: "generated"})
        self.assertEqual(apart({"/".join([*where, output, "x.js.map"]): "{}"}), {inner: "generated"})
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(_extract_limited(archive({f"{output}/x.js": TOKEN}), Path(folder) / "head")["apart"], {f"{output}/": "generated"})

    @settings(max_examples=60 * SCALE, deadline=None)
    @given(folders.filter(lambda where: not set(where) & repositories.LOCAL_ONLY), st.sampled_from(sorted(repositories.LOCAL_ONLY)))
    def test_a_folder_on_disk_leaves_out_only_what_tools_install_and_says_so(self, where, local):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "repo"
            for name in ("/".join([*where, "conf.js"]), "/".join([*where, local, "pkg", "conf.js"])):
                (source / name).parent.mkdir(parents=True, exist_ok=True)
                (source / name).write_text(TOKEN)
            head = Path(folder) / "work" / "head"
            stats = snapshot_directory(source, head)
            seen = tree(head) | tree(secrets_root(head))
        self.assertIn("/".join([*where, "conf.js"]), seen)
        self.assertNotIn("/".join([*where, local, "pkg", "conf.js"]), seen)
        self.assertEqual((stats["local_only"], stats["local_only_count"]), (["/".join([*where, local]) + "/"], 1))


class CoverageTests(unittest.TestCase):
    TOOLS = [{"tool": name, "name": name, "status": "completed", "coverage": engine_contract.coverage("*")}
             for name in ("opengrep", "betterleaks", "trivy", "osv-scanner", "checkov", "zizmor", "policies")]

    @given(st.dictionaries(st.builds(lambda parts: "/".join(parts) + "/", st.lists(folder, min_size=1, max_size=3)),
                           st.sampled_from(["dependencies", "generated"]), min_size=1, max_size=3),
           st.lists(folder, max_size=2), st.sampled_from(["x.js", "pom.xml", "main.tf"]))
    def test_what_only_the_secret_scanners_read_is_never_fixed_by_the_others(self, apart, below, name):
        record = {"type": "repository_scan", "status": "completed", "summary": {"tools": [{"name": tool["tool"], "status": "completed"} for tool in self.TOOLS]},
                  "unexamined": repository._unexamined([], self.TOOLS, {}, apart), "coverage": repository._coverage([], self.TOOLS, {}, apart)}
        folder_ = sorted(apart)[0]
        path = folder_ + "/".join([*below, name])
        for tool, scanner in (("opengrep", "sast"), ("trivy", "sca"), ("trivy", "iac"), ("osv-scanner", "sca"), ("checkov", "iac"),
                              ("zizmor", "cicd"), ("policies", "iac")):
            finding = {"tool": tool, "scanner": scanner, "rule_id": "r", "path": path}
            self.assertIn(registry.unproven_reason(record, finding), ("unexamined", "not_covered"), (tool, scanner))
            self.assertEqual(record["coverage"][tool]["unexamined"].get(folder_) or record["coverage"][tool]["by_scanner"][scanner][folder_],
                             apart[folder_])
        for tool in ("betterleaks", "trivy"):
            self.assertIsNone(registry.unproven_reason(record, {"tool": tool, "scanner": "secrets", "rule_id": "github-pat", "path": path}))
        # Outside them, every engine vouches as before.
        self.assertIsNone(registry.unproven_reason(record, {"tool": "opengrep", "scanner": "sast", "rule_id": "r", "path": "elsewhere-zz/x.js"}))

    def test_a_page_is_listed_only_by_itself(self):
        self.assertFalse(coverage_units.inside("https://host/admin", {"https://host/": "capped"}))
        self.assertTrue(coverage_units.inside("dist/app/x.js", {"dist/": "generated"}))
        self.assertFalse(coverage_units.inside("distribution/x.js", {"dist/": "generated"}))


class OpengrepScopeTests(unittest.TestCase):
    def test_opengrep_reads_what_the_snapshot_holds_and_lists_the_test_code_it_leaves_out(self):
        seen = {}

        def run(key, arguments, snapshot, **options):
            seen["ignore"] = (snapshot / ".semgrepignore").read_text()
            return subprocess.CompletedProcess(arguments, 0, json.dumps({"results": [], "paths": {}}), "")

        with tempfile.TemporaryDirectory() as folder, patch.object(engines, "runner", return_value="docker"), \
                patch.object(engines, "docker_available", return_value=True), patch.object(engines, "image_available", return_value=True), \
                patch.object(engines, "_run", side_effect=run):
            for name in ("src/build/x.js", "src/data/x.js", "src/vendor/x.js", "app.min.js", "src/test/a.js", "web/tests/deep/b.js", "pkg/x_test.go"):
                (Path(folder) / name).parent.mkdir(parents=True, exist_ok=True)
                (Path(folder) / name).write_text("eval(x);\n")
            result = engines.run_opengrep(Path(folder))
        # Its own default list (build/, dist/, vendor/, node_modules/, *.min.js) is replaced: only test code stays out.
        self.assertEqual([line for line in seen["ignore"].splitlines() if not line.startswith("#")], ["test/", "tests/", "*_test.go"])
        self.assertEqual(result["coverage"]["unexamined"], {"pkg/x_test.go": "tests", "src/test/": "tests", "web/tests/": "tests"})


class SecretPassTests(unittest.TestCase):
    def test_the_secret_scanners_read_the_folders_set_apart_and_the_others_list_them(self):
        from pitangus.modules.scanning import engines as scan_engines
        with tempfile.TemporaryDirectory() as temporary:
            source, head = Path(temporary) / "repo", Path(temporary) / "work" / "head"
            for name in ("dist/conf.js", "src/data/conf.js", "vendor/lib/conf.js", "app.py"):
                (source / name).parent.mkdir(parents=True, exist_ok=True)
                (source / name).write_text(TOKEN)
            stats = snapshot_directory(source, head, committed=True)
            seen: dict[str, list] = {}

            def reader(key):
                def run(root, *args, **kwargs):
                    seen.setdefault(key, []).append(sorted(tree(root)))
                    return scan_engines._result(key, "completed", "")
                return run

            def trivy_secret_pass(root, cache, settings, screened=None, gaps=None, allowed=None):
                seen.setdefault("trivy-secrets", []).append(sorted(tree(root)))
                return []

            replaced = {"engines_available": lambda: True, "host_mount_problem": lambda *args: None, "run_betterleaks": reader("betterleaks"),
                        "trivy_secrets": trivy_secret_pass, "load_feeds": lambda *args: {"kev": {}, "epss": {}},
                        "run_opengrep": reader("opengrep"), "run_trivy": reader("trivy"), "run_osv_scanner": reader("osv-scanner"),
                        "run_checkov": reader("checkov"), "run_zizmor": reader("zizmor")}
            patches = [patch.object(repository, name, side_effect=value) for name, value in replaced.items()]
            for item in patches:
                item.start()
            try:
                scan = repository.scan_repository(head, {"id": "local:demo", "name": "demo", "provider": "local", "snapshot": stats})
            finally:
                for item in patches:
                    item.stop()
        self.assertEqual(seen["opengrep"], [["app.py", "src/data/conf.js"]])
        self.assertEqual(sorted(seen["betterleaks"]), [["app.py", "src/data/conf.js"], ["dist/conf.js", "vendor/lib/conf.js"]])
        self.assertEqual(seen["trivy-secrets"], [["dist/conf.js", "vendor/lib/conf.js"]])
        self.assertEqual(scan["unexamined"]["opengrep"], ["dist/", "vendor/"])
        self.assertEqual(scan["unexamined"]["trivy:sca"], ["dist/", "vendor/"])
        self.assertNotIn("betterleaks", scan["unexamined"])
        self.assertNotIn("apart", scan["source"]["snapshot"])
        from pitangus.shared.i18n import text
        self.assertIn("dist/, vendor/", text(scan["steps"][0]["detail"], "en"))


if __name__ == "__main__":
    unittest.main()
