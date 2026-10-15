"""R3 without a list of package managers: a dependency finding lives in the project folder of every file it came from,
and that folder was examined by an engine in a run only if the engine inventoried a package from a file in it.

The manifests and lockfiles here have random names: which ones each engine reads is drawn per example, so no list of
names in Pitangus can be what makes the property hold. The property, over two complete scans through the real
adapters (Trivy, OSV-Scanner), the scan and the registry: deleting or emptying any file a dependency finding came
from never fixes it while its folder is still in the repository, whatever else the folder holds (a manifest, a
lockfile of another package manager, a lockfile in a format an engine stopped reading); deleting the whole folder, or
upgrading the package where it is, fixes it. Every engine that saw a finding must have inventoried that file again.
The adversary's cases (Conan, sbt, a Gradle buildscript lockfile, pip-tools, .NET's deps.json, renv, Stack, a pnpm
workspace without a package.json at its root) are seeds."""

import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from hypothesis import HealthCheck, example, given, settings, strategies as st

from pitangus.app import data_migrations
from pitangus.modules.findings import registry
from pitangus.modules.runs.store import save_and_apply
from pitangus.modules.scanning import engine_contract, engines, repository
from pitangus.shared import coverage_units

PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

PACKAGES = (("log4j-core", "2.14.1", "CVE-2021-44228"), ("lodash", "4.17.15", "CVE-2020-8203"), ("requests", "2.19.0", "CVE-2018-18074"))
FOLDERS = ("", "api/", "svc/billing/", "tools/")
NAME = st.from_regex(r"[a-z][a-z0-9_-]{0,8}\.(lock|lockfile|json|txt|yaml|toml|in|cfg)", fullmatch=True)
ACTIONS = ("keep", "delete-lock", "empty-lock", "delete-project", "upgrade", "replace-lock", "beside-other")

projects = st.lists(st.fixed_dictionaries({
    "manifest": NAME, "lockfile": NAME, "other": NAME,
    "packages": st.sets(st.integers(0, len(PACKAGES) - 1), min_size=1, max_size=2),
    "action": st.sampled_from(ACTIONS),
    "osv_reads": st.booleans(),        # whether OSV-Scanner reads this lockfile's format at all
    "osv_stops": st.booleans(),        # whether it stops reading it in the second scan (a format it no longer parses)
}), min_size=1, max_size=len(FOLDERS))


def _lock(packages) -> str:
    return "# lock\n" + "".join(f"{PACKAGES[index][0]}@{PACKAGES[index][1]}\n" for index in sorted(packages)) + "safe-lib@1.0.0\n"


class Repository:
    """Each folder a project: a manifest (never read by anyone), a lockfile the engines may read and, beside it, maybe
    another package manager's lockfile they read too."""

    def __init__(self, specs: list[dict]):
        self.projects = []
        for folder, spec in zip(FOLDERS, specs):
            names = {spec["manifest"], spec["lockfile"], spec["other"]}
            if len(names) < 3:
                continue
            self.projects.append({**spec, "folder": folder})

    def files(self, after: bool) -> dict[str, str]:
        found: dict[str, str] = {}
        for project in self.projects:
            folder, action = project["folder"], project["action"] if after else "keep"
            if action == "delete-project":
                continue
            found[folder + project["manifest"]] = "declares things in a syntax nobody reads\n"
            if action == "beside-other" or (action == "replace-lock"):
                # Another lockfile the engines read, with another package, beside it (or instead of it).
                found[folder + project["other"]] = "# lock\nother-lib@2.0.0\n"
            if action in ("delete-lock", "beside-other", "replace-lock"):
                continue
            found[folder + project["lockfile"]] = "" if action == "empty-lock" else _lock(set() if action == "upgrade" else project["packages"])
        return found

    def readable(self, engine: str, after: bool) -> set[str]:
        """The file names each engine reads (by their format: here, by name), drawn per example."""
        names = set()
        for project in self.projects:
            names.add(project["other"])
            if engine == "trivy" or (project["osv_reads"] and not (after and project["osv_stops"])):
                names.add(project["lockfile"])
        return names


def _advisory(name: str, version: str) -> str | None:
    return next((cve for package, affected, cve in PACKAGES if package == name and affected == version), None)


def fake_engines(readable: dict[str, set[str]]):
    def run(key, arguments, snapshot=None, **options):
        root = Path(snapshot)
        read = []
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.name in readable[key] and (text := path.read_text(encoding="utf-8")).strip():
                packages = [tuple(line.split("@", 1)) for line in text.splitlines() if "@" in line and not line.startswith("#")]
                read.append((path.relative_to(root).as_posix(), packages))
        if key == "trivy":
            results = [{"Target": path, "Class": "lang-pkgs", "Type": "anything",
                        "Packages": [{"ID": f"{name}@{version}", "Name": name, "Version": version} for name, version in packages],
                        "Vulnerabilities": [{"VulnerabilityID": cve, "PkgID": f"{name}@{version}", "PkgName": name, "InstalledVersion": version,
                                             "FixedVersion": "99.0.0", "Severity": "CRITICAL"}
                                            for name, version in packages if (cve := _advisory(name, version))]}
                       for path, packages in read]
            return subprocess.CompletedProcess(arguments, 0, json.dumps({"SchemaVersion": 2, "Results": results}), "")
        results = [{"source": {"path": f"/src/{path}", "type": "lockfile"},
                    "packages": [{"package": {"name": name, "version": version, "ecosystem": "Anything"},
                                  **({"vulnerabilities": [{"id": cve, "summary": cve, "aliases": [cve],
                                                           "affected": [{"package": {"name": name, "ecosystem": "Anything"},
                                                                         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "99.0.0"}]}]}]}],
                                      "groups": [{"ids": [cve], "aliases": [cve]}]} if (cve := _advisory(name, version)) else {})}
                                 for name, version in packages]}
                   for path, packages in read]
        log = "\n".join(["Scanning dir /src", *(f"Scanned /src/{path} file and found {len(packages)} packages" for path, packages in read)])
        return subprocess.CompletedProcess(arguments, 1 if results else 0, json.dumps({"results": results}), log)
    return run


def _quiet(key: str) -> dict:
    return {**engines._result(key, "completed", ""), "coverage": engine_contract.coverage("*")}


def _replay() -> tuple:
    def call(key):
        if key == "trivy":
            return lambda context: engines.run_trivy(context.root, context.data_dir / "trivy-cache", context.feeds, context.secret_settings, context.data_dir)
        if key == "osv-scanner":
            return lambda context: engines.run_osv_scanner(context.root, context.data_dir / "osv-cache", context.feeds)
        return lambda context: _quiet(key)
    return tuple(engines.EngineStep(engine.key, call(engine.key), engine.progress, engine.required, engine.merged) for engine in repository.CODE_ENGINES)


class Scans(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.count = 0

    def scan(self, files: dict[str, str], key: str, when: datetime, readable: dict[str, set[str]]) -> tuple[dict, dict]:
        self.count += 1
        data_dir = Path(self.directory.name)
        snapshot = data_dir / f"snapshot-{self.count}"
        snapshot.mkdir()
        for path, content in files.items():
            (snapshot / path).parent.mkdir(parents=True, exist_ok=True)
            (snapshot / path).write_text(content, encoding="utf-8")
        source = {"id": "github:org/api", "uid": key, "name": "org/api", "provider": "github"}
        with patch.object(engines, "_run", side_effect=fake_engines(readable)), patch.object(engines, "unavailable", return_value=None), \
                patch.object(engines, "trivy_databases", return_value=[]), \
                patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "on", "PITANGUS_FIX_HOLD_MINIMUM": "100000"}):
            record = repository.scan_repository(snapshot, source, data_dir=data_dir, replay=_replay(), feeds={"kev": {}, "epss": {}})
            return save_and_apply(data_dir, record, created_at=when.isoformat())

    def twice(self, before: dict[str, str], after: dict[str, str], readable_before, readable_after, key: str):
        clock = datetime.now(timezone.utc)
        self.scan(before, key, clock, readable_before)
        first = registry.load(Path(self.directory.name), key)["findings"]
        _, changes = self.scan(after, key, clock + timedelta(hours=1), readable_after)
        return first, changes, registry.load(Path(self.directory.name), key)["findings"]


class UnknownNamesPropertyTests(Scans):
    @settings(max_examples=30 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    @given(projects)
    @example([{"manifest": "conanfile.txt", "lockfile": "conan.lock", "other": "x.cfg", "packages": {0}, "action": "delete-lock",
               "osv_reads": False, "osv_stops": False}])
    @example([{"manifest": "requirements.in", "lockfile": "requirements.txt", "other": "x.cfg", "packages": {2}, "action": "empty-lock",
               "osv_reads": True, "osv_stops": False},
              {"manifest": "build.sbt", "lockfile": "build.sbt.lock", "other": "x.cfg", "packages": {0}, "action": "delete-lock",
               "osv_reads": False, "osv_stops": False}])
    @example([{"manifest": "Api.csproj", "lockfile": "Api.deps.json", "other": "packages.lock.json", "packages": {1}, "action": "beside-other",
               "osv_reads": True, "osv_stops": False},
              {"manifest": "DESCRIPTION", "lockfile": "renv.lock", "other": "x.cfg", "packages": {0}, "action": "keep",
               "osv_reads": True, "osv_stops": True}])
    @example([{"manifest": "stack.yaml", "lockfile": "stack.yaml.lock", "other": "x.cfg", "packages": {0}, "action": "replace-lock",
               "osv_reads": False, "osv_stops": False},
              {"manifest": "build.gradle", "lockfile": "buildscript-gradle.lockfile", "other": "x.cfg", "packages": {1}, "action": "upgrade",
               "osv_reads": True, "osv_stops": False}])
    def test_deleting_any_file_a_finding_came_from_never_fixes_it_while_its_folder_is_there(self, specs):
        generated = Repository(specs)
        if not generated.projects:
            return
        key = f"github#folders-{abs(hash(repr(specs))) % 10**10}"
        first, changes, now = self.twice(generated.files(False), generated.files(True),
                                         {engine: generated.readable(engine, False) for engine in ("trivy", "osv-scanner")},
                                         {engine: generated.readable(engine, True) for engine in ("trivy", "osv-scanner")}, key)
        reported = {cve for entry in first.values() for cve in entry["finding"].get("cve") or []}
        self.assertEqual(reported, {PACKAGES[index][2] for project in generated.projects for index in project["packages"]})
        after = generated.files(True)
        readable = {engine: generated.readable(engine, True) for engine in ("trivy", "osv-scanner")}

        def folder_there(folder: str) -> bool:
            return any(coverage_units.folder_of(path) == folder or path.startswith(folder + "/") or folder == "." for path in after)

        for digest, entry in first.items():
            finding = entry["finding"]
            places = coverage_units.sources(finding)
            package = finding.get("package") or {}
            present = any(f"{package.get('name')}@{package.get('version')}" in after.get(place, "") for place in places)
            # Gone, provably: for every file it came from, its folder left the repository, or every engine that saw it
            # inventoried that very file again.
            provable = all(not folder_there(coverage_units.folder_of(place)) if not after else
                           (not folder_there(coverage_units.folder_of(place))
                            or (after.get(place, "").strip() and all(place.rpartition("/")[2] in readable[engine] for engine in entry["detected_by"])))
                           for place in places)
            expected = "fixed" if provable and not present else "open"
            self.assertEqual(now[digest]["status"], expected, (places, [project["action"] for project in generated.projects], entry["detected_by"],
                                                                now[digest].get("unseen")))
        self.assertEqual(set(changes["fixed_now"]), {digest for digest, entry in now.items() if entry["status"] == "fixed"})


class SeedTests(Scans):
    """The adversary's cases, each by itself."""

    def check(self, before: dict[str, str], after: dict[str, str], readable: set[str]) -> None:
        both = {"trivy": readable, "osv-scanner": readable}
        first, changes, now = self.twice(before, after, both, both, f"github#seed-{abs(hash(repr(before))) % 10**8}")
        self.assertTrue(first)
        self.assertEqual(changes["fixed_now"], [], {entry["finding"]["path"]: entry.get("unseen") for entry in now.values()})

    def test_lockfiles_of_package_managers_nobody_listed(self):
        for manifest, lockfile in (("conanfile.txt", "conan.lock"), ("build.sbt", "build.sbt.lock"), ("build.gradle", "buildscript-gradle.lockfile"),
                                   ("requirements.in", "requirements.txt"), ("Api.csproj", "Api.deps.json"), ("DESCRIPTION", "renv.lock"),
                                   ("stack.yaml", "stack.yaml.lock")):
            with self.subTest(lockfile=lockfile):
                before = {manifest: "anything\n", lockfile: _lock({0, 1})}
                self.check(before, {manifest: "anything\n"}, {lockfile})
                self.check(before, {manifest: "anything\n", lockfile: ""}, {lockfile})

    def test_a_pnpm_workspace_without_a_package_json_at_its_root(self):
        before = {"pnpm-workspace.yaml": "packages:\n  - 'packages/*'\n", "pnpm-lock.yaml": _lock({1}),
                  "packages/a/package.json": '{"name": "a", "dependencies": {"lodash": "4.17.15"}}'}
        self.check(before, {path: text for path, text in before.items() if path != "pnpm-lock.yaml"}, {"pnpm-lock.yaml"})

    def test_a_lockfile_beside_another_package_managers_one(self):
        before = {"requirements.txt": _lock({2}), "package-lock.json": "# lock\nother@1.0.0\n", "package.json": "{}"}
        self.check(before, {path: text for path, text in before.items() if path != "requirements.txt"}, {"requirements.txt", "package-lock.json"})

    def test_deleting_the_whole_folder_fixes(self):
        both = {"trivy": {"conan.lock"}, "osv-scanner": {"conan.lock"}}
        _, changes, now = self.twice({"lib/conanfile.txt": "x\n", "lib/conan.lock": _lock({0}), "app.py": "x = 1\n"}, {"app.py": "x = 1\n"},
                                     both, both, "github#seed-gone")
        self.assertTrue(changes["fixed_now"])
        self.assertTrue(all(entry["status"] == "fixed" for entry in now.values()))


class EngineInventoryTests(unittest.TestCase):
    """The registry's rule by itself, over any spec an engine's coverage carries."""

    def test_a_folder_listed_or_a_file_not_inventoried_in_a_folder_that_is(self):
        spec = {"inventoried": ["api/x.lock", "y.lock"], "uninventoried": ["docs", "tools"]}
        finding = lambda path, *also: {"scanner": "sca", "path": path, "package": {"also_in": list(also)}}   # noqa: E731
        self.assertFalse(coverage_units.dependency_unexamined(finding("api/x.lock"), spec))
        self.assertTrue(coverage_units.dependency_unexamined(finding("api/gone.lock"), spec))      # the folder is there
        self.assertTrue(coverage_units.dependency_unexamined(finding("tools/conan.lock"), spec))  # nothing from it
        self.assertFalse(coverage_units.dependency_unexamined(finding("removed/conan.lock"), spec))  # no folder: gone
        self.assertTrue(coverage_units.dependency_unexamined(finding("y.lock", "tools/a.lock"), spec))
        many = {"inventoried": [], **coverage_units.folder_list([f"f{index}" for index in range(coverage_units.FOLDERS_LISTED + 1)])}
        self.assertIn("uninventoried_digests", many)
        self.assertTrue(coverage_units.dependency_unexamined(finding("f7/a.lock"), many))
        self.assertFalse(coverage_units.dependency_unexamined(finding("elsewhere/a.lock"), many))

    def test_every_engine_that_saw_it_must_have_inventoried_it(self):
        def tool(name, inventoried):
            return {"name": name, "status": "completed"}, {**engine_contract.coverage("*"), "dependencies": {"inventoried": inventoried, "uninventoried": []}}
        finding = {"tool": "trivy", "scanner": "sca", "path": "a/x.lock", "also_detected_by": ["osv-scanner"]}
        (trivy, trivy_cover), (osv, osv_cover) = tool("trivy", ["a/x.lock"]), tool("osv-scanner", ["a/other.lock"])
        record = {"type": "repository_scan", "status": "completed", "summary": {"tools": [trivy, osv]},
                  "coverage": {"trivy": trivy_cover, "osv-scanner": osv_cover}}
        self.assertEqual(registry.unproven_reason(record, finding), "unexamined")
        self.assertIsNone(registry.unproven_reason(record, {**finding, "also_detected_by": []}))
        self.assertEqual(registry.unproven_reason(record, {**finding, "also_detected_by": []}, engines=["osv-scanner"]), "unexamined")


class MigrationTests(unittest.TestCase):
    """Data migration `dependency_project_units`: findings stored with `deps://<ecosystem>/<folder>` get their project
    folders, in the registry and in the runs; idempotent."""

    def test_stored_units_become_project_folders(self):
        legacy = {"scanner": "sca", "tool": "trivy", "path": "svc/Cargo.lock", "units": ["deps://cargo/svc", "deps://npm/web"],
                  "package": {"also_in": ["web/yarn.lock"]}}
        self.assertEqual(data_migrations._project_units(legacy)["units"], ["project://svc", "project://web"])
        code = {"scanner": "sast", "path": "app.py", "units": ["app.py"]}
        self.assertIs(data_migrations._project_units(code), code)
        self.assertIs(data_migrations._project_units({"scanner": "dast", "path": "https://h/", "units": ["https://h/"]})["units"][0], "https://h/")
        migrated = data_migrations._project_units(legacy)
        self.assertIs(data_migrations._project_units(migrated), migrated)


if __name__ == "__main__":
    unittest.main()
