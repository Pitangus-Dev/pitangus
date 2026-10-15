"""F2 by unit: a finding is proven gone only over the unit it lives in, never by matching its path against the paths an
engine listed. A dependency finding lives in its project (the manifest and the lockfile that resolves it), so:

- deleting, emptying or hollowing out (well formed, listing nothing) any lockfile of any ecosystem never fixes what was
  reported in it, whatever its manifest declares and in whatever syntax (Gradle's map notation, `debugImplementation`,
  named arguments in Kotlin…): a lockfile counts only when the engine inventoried a package from it in that run;
- a unit an engine declares unexamined never fixes anything inside it, whatever the finding's path (its manifest, its
  lockfile, another lockfile it was also seen in, a folder above);
- deleting a whole project, or upgrading the package, still fixes.

The generated cases go through the real adapters (Trivy, OSV-Scanner), the whole code scan and the registry in
PostgreSQL. Whether a manifest declares anything is never read: the manifests are random text.
"""

import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from hypothesis import HealthCheck, example, given, settings, strategies as st

from pitangus.modules.findings import registry
from pitangus.modules.runs.store import save_and_apply
from pitangus.modules.scanning import dependency_coverage, engine_contract, engines, repository
from pitangus.shared import coverage_units

PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

# Ecosystems as their package managers lay them out: (manifest, lockfile, Trivy's type, OSV's ecosystem). The ones whose
# manifest is its own lockfile have none apart.
ECOSYSTEMS = {
    "cargo": ("Cargo.toml", "Cargo.lock", "cargo", "crates.io"),
    "pipenv": ("Pipfile", "Pipfile.lock", "pipenv", "PyPI"),
    "poetry": ("pyproject.toml", "poetry.lock", "poetry", "PyPI"),
    "uv": ("pyproject.toml", "uv.lock", "uv", "PyPI"),
    "composer": ("composer.json", "composer.lock", "composer", "Packagist"),
    "gradle": ("build.gradle", "gradle.lockfile", "gradle", "Maven"),
    "gradle-kts": ("build.gradle.kts", "gradle.lockfile", "gradle", "Maven"),
    "npm": ("package.json", "package-lock.json", "npm", "npm"),
    "pnpm": ("package.json", "pnpm-lock.yaml", "pnpm", "npm"),
    "yarn": ("package.json", "yarn.lock", "yarn", "npm"),
    "bundler": ("Gemfile", "Gemfile.lock", "bundler", "RubyGems"),
    "bundler-gems": ("gems.rb", "gems.locked", "bundler", "RubyGems"),
    "nuget": ("Api.csproj", "packages.lock.json", "nuget", "NuGet"),
    "swift": ("Package.swift", "Package.resolved", "swift", "SwiftURL"),
    "pub": ("pubspec.yaml", "pubspec.lock", "pub", "Pub"),
    "go": ("go.mod", None, "gomod", "Go"),
    "maven": ("pom.xml", None, "pom", "Maven"),
}
LOCKED = sorted(name for name, spec in ECOSYSTEMS.items() if spec[1])
FOLDERS = ("", "api/", "svc/billing/", "libs/core/", "web/", "tools/x/")
# Packages and the advisory each version has: shared between projects, so one finding is seen in several lockfiles.
PACKAGES = (("log4j-core", "2.14.1", "CVE-2021-44228"), ("jackson-databind", "2.9.8", "CVE-2019-12384"),
            ("lodash", "4.17.15", "CVE-2020-8203"), ("requests", "2.19.0", "CVE-2018-18074"), ("serde", "1.0.0", "CVE-2099-0001"))
# What a manifest may hold, in any syntax: never read to decide anything. The Log4Shell declarations a regex missed.
DECLARATIONS = (
    "implementation group: 'org.apache.logging.log4j', name: 'log4j-core', version: '2.+'",
    "debugImplementation 'org.apache.logging.log4j:log4j-core:2.14.1'",
    'implementation(group = "org.apache.logging.log4j", name = "log4j-core", version = "2.14.1")',
    "dependencies {\n    implementation libs.log4j\n}",
    '[dependencies]\nserde = { version = "1", features = ["derive"] }',
    '{"require": {"monolog/monolog": "^2.0"}}', '{"peerDependencies": {"react": "*"}}', "gem 'rails'",
    '<PackageReference Include="Newtonsoft.Json" Version="12.0.1" />', "plugins { id 'java' }",
    "[tool.ruff]\nline-length = 120", "{}",
)
manifest_texts = st.one_of(st.sampled_from(DECLARATIONS),
                           st.text(min_size=1, max_size=40).filter(lambda value: value.strip() and "\x00" not in value))
# A lockfile that is there, well formed, and lists nothing: any shape, generated (JSON of empty containers, TOML or YAML
# headers and keys, comments). Never read to decide anything either: only what the engine inventoried from it counts.
WORD = st.text(alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-", min_size=1, max_size=10)
hollow_locks = st.one_of(
    st.recursive(st.one_of(st.just({}), st.just([]), st.integers(0, 9), st.booleans(), st.none(), WORD),
                 lambda inner: st.dictionaries(WORD, inner, max_size=3) | st.lists(inner, max_size=2), max_leaves=6).map(json.dumps),
    st.lists(WORD, min_size=1, max_size=3).map(lambda headers: "".join(f"[{header}]\n" for header in headers)),
    st.tuples(WORD, st.integers(0, 9)).map(lambda pair: f"{pair[0]}: {pair[1]}\n"),
    st.tuples(WORD, st.integers(0, 9)).map(lambda pair: f"{pair[0]} = {pair[1]}\n"),
    WORD.map(lambda word: f"# {word}\n"),
)
# What happens to a project between two scans.
ACTIONS = ("keep", "delete-lock", "empty-lock", "delete-project", "upgrade", "hollow-lock")
SELF_LOCKED_ACTIONS = ("keep", "delete-project", "upgrade", "unresolved")
UNEXAMINED = ("unexamined", "not_covered")   # the unit was declared unexamined (by the engine's coverage, or the scan's)

projects = st.lists(st.fixed_dictionaries({
    "ecosystem": st.sampled_from(sorted(ECOSYSTEMS)),
    "manifest": manifest_texts,
    "packages": st.sets(st.integers(0, len(PACKAGES) - 1), min_size=1, max_size=3),
    "action": st.sampled_from(ACTIONS),
    "hollow": hollow_locks,
    "neighbour": st.booleans(),   # a tool-config manifest of another ecosystem beside it, without a lockfile
}), min_size=1, max_size=len(FOLDERS))


def _lock_text(packages) -> str:
    return "".join(f"{PACKAGES[index][0]}@{PACKAGES[index][1]}\n" for index in sorted(packages))


class Repository:
    """A generated repository: each folder one project, written to a snapshot; `scan` mutates it for the second scan."""

    def __init__(self, specs: list[dict]):
        self.projects = [{**spec, "folder": folder, "action": spec["action"] if ECOSYSTEMS[spec["ecosystem"]][1]
                          else SELF_LOCKED_ACTIONS[ACTIONS.index(spec["action"]) % len(SELF_LOCKED_ACTIONS)]}
                         for folder, spec in zip(FOLDERS, specs)]

    def files(self, after: bool) -> dict[str, str]:
        found: dict[str, str] = {}
        for project in self.projects:
            manifest, lockfile, _, _ = ECOSYSTEMS[project["ecosystem"]]
            action = project["action"] if after else "keep"
            if action == "delete-project":
                continue
            if project["neighbour"]:
                neighbour = "composer.json" if manifest == "pyproject.toml" else "pyproject.toml"
                found[project["folder"] + neighbour] = "[tool.black]\nline-length = 100\n"
            packages = set() if action == "upgrade" else project["packages"]
            if lockfile is None:   # its own lockfile: the manifest lists the packages
                # An upgrade leaves it listing the packages it still has (one that lists none is a folder nothing was
                # inventoried from: unexamined, never fixed).
                found[project["folder"] + manifest] = (project["manifest"] + "\n" + _lock_text(packages) + "safe-lib@1.0.0\n"
                                                       + ("unresolved\n" if action == "unresolved" else ""))
                continue
            found[project["folder"] + manifest] = project["manifest"]
            if action == "hollow-lock":
                found[project["folder"] + lockfile] = project["hollow"]
            elif action != "delete-lock":
                found[project["folder"] + lockfile] = "" if action == "empty-lock" else "# lock\n" + _lock_text(packages) + "safe-lib@1.0.0\n"
        return found

    def lockfile(self, project: dict) -> str:
        manifest, lockfile, _, _ = ECOSYSTEMS[project["ecosystem"]]
        return project["folder"] + (lockfile or manifest)


def _read(snapshot: Path) -> list[tuple[str, str, str, list[tuple[str, str]]]]:
    """What a dependency engine reads in the snapshot: each lockfile (or manifest that is its own) by its name only,
    with its packages; (path, Trivy type, OSV ecosystem, packages). An empty lockfile resolves nothing."""
    readable = {}
    for manifest, lockfile, kind, ecosystem in ECOSYSTEMS.values():
        readable[(lockfile or manifest).lower()] = (kind, ecosystem)
    found = []
    for path in sorted(snapshot.rglob("*")):
        relative = path.relative_to(snapshot).as_posix()
        if not path.is_file() or path.name.lower() not in readable:
            continue
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            continue
        unresolved = "unresolved" in text.splitlines()
        packages = [tuple(line.split("@", 1)) for line in text.splitlines() if "@" in line and not line.startswith("#")]
        if unresolved:   # a parent that didn't resolve: what it versions comes out without one
            packages = [(name, "") for name, _ in packages] + [("parent-managed", "")]
        found.append((relative, *readable[path.name.lower()], packages))
    return found


def _advisory(name: str, version: str) -> str | None:
    return next((cve for package, affected, cve in PACKAGES if package == name and affected == version), None)


def fake_engines(key, arguments, snapshot=None, **options):
    """Trivy and OSV-Scanner over the snapshot they were given, as they report: one result per lockfile they read."""
    read = _read(Path(snapshot))
    if key == "trivy":
        results = [{"Target": path, "Class": "lang-pkgs", "Type": kind,
                    "Packages": [{"ID": f"{name}@{version}", "Name": name, **({"Version": version} if version else {})} for name, version in packages],
                    "Vulnerabilities": [{"VulnerabilityID": cve, "PkgID": f"{name}@{version}", "PkgName": name, "InstalledVersion": version,
                                         "FixedVersion": "99.0.0", "Severity": "CRITICAL"}
                                        for name, version in packages if version and (cve := _advisory(name, version))]}
                   for path, kind, _, packages in read]
        return subprocess.CompletedProcess(arguments, 0, json.dumps({"SchemaVersion": 2, "Results": results}), "")
    results = [{"source": {"path": f"/src/{path}", "type": "lockfile"},
                "packages": [{"package": {"name": name, "version": version, "ecosystem": ecosystem},
                              **({"vulnerabilities": [{"id": cve, "summary": cve, "aliases": [cve],
                                                       "affected": [{"package": {"name": name, "ecosystem": ecosystem},
                                                                     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "99.0.0"}]}]}]}],
                                  "groups": [{"ids": [cve], "aliases": [cve]}]} if version and (cve := _advisory(name, version)) else {})}
                             for name, version in packages]}
               for path, _, ecosystem, packages in read]
    log = "\n".join(["Scanning dir /src", *(f"Scanned /src/{path} file and found {len(packages)} packages" for path, _, _, packages in read)])
    return subprocess.CompletedProcess(arguments, 1 if results else 0, json.dumps({"results": results}), log)


def _quiet(key: str) -> dict:
    return {**engines._result(key, "completed", ""), "coverage": engine_contract.coverage("*")}


def _replay() -> tuple:
    """The code engines: Trivy and OSV-Scanner through their real adapters over the fake processes, the rest silent."""
    def call(key):
        if key == "trivy":
            return lambda context: engines.run_trivy(context.root, context.data_dir / "trivy-cache", context.feeds, context.secret_settings, context.data_dir)
        if key == "osv-scanner":
            return lambda context: engines.run_osv_scanner(context.root, context.data_dir / "osv-cache", context.feeds)
        return lambda context: _quiet(key)
    return tuple(engines.EngineStep(engine.key, call(engine.key), engine.progress, engine.required, engine.merged) for engine in repository.CODE_ENGINES)


class EmptyLockfileShapeTests(unittest.TestCase):
    """A committed package-lock.json that is valid JSON but not an object (`[]`, `"x"`, `0`, `null`): found by the
    nightly profile, it stopped the whole scan in the inventory; now it lists nothing, and its project stays unexamined."""

    def test_a_lockfile_that_isnt_an_object_lists_nothing_and_breaks_nothing(self):
        for body in ("[]", '"x"', "0", "null", "[{}]"):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                (root / "package.json").write_text('{"dependencies": {"left-pad": "1.3.0"}}')
                (root / "package-lock.json").write_text(body)
                self.assertEqual(repository._dependencies(root), ([], []))

    def test_a_pyproject_whose_tables_are_other_types_lists_nothing_and_breaks_nothing(self):
        from pitangus.modules.scanning import inventory
        for body in ('project = "x"', "tool = 1", "[tool]\npoetry = 3"):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as folder:
                (Path(folder) / "pyproject.toml").write_text(body)
                self.assertEqual(inventory._python(Path(folder) / "pyproject.toml"), set())


class LockfileDeletionTests(unittest.TestCase):
    """Two complete code scans of a generated repository, through the adapters, the scan and the registry."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.examples = 0

    def scan(self, files: dict[str, str], key: str, when: datetime) -> tuple[dict, dict]:
        data_dir = Path(self.directory.name)
        snapshot = data_dir / f"snapshot-{key.replace('#', '-')}-{when.timestamp():.0f}"
        snapshot.mkdir()
        for path, content in files.items():
            (snapshot / path).parent.mkdir(parents=True, exist_ok=True)
            (snapshot / path).write_text(content, encoding="utf-8")
        source = {"id": "github:org/api", "uid": key, "name": "org/api", "provider": "github"}
        with patch.object(engines, "_run", side_effect=fake_engines), patch.object(engines, "unavailable", return_value=None), \
                patch.object(engines, "trivy_databases", return_value=[]), \
                patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "on", "PITANGUS_FIX_HOLD_MINIMUM": "100000"}):
            record = repository.scan_repository(snapshot, source, data_dir=data_dir, replay=_replay(), feeds={"kev": {}, "epss": {}})
            return save_and_apply(data_dir, record, created_at=when.isoformat())

    @settings(max_examples=25 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    @given(projects)
    @example([{"ecosystem": "gradle", "manifest": DECLARATIONS[0], "packages": {0}, "action": "delete-lock", "neighbour": False}])
    @example([{"ecosystem": "npm", "manifest": "x", "packages": {2}, "action": "delete-project", "neighbour": False},
              {"ecosystem": "cargo", "manifest": "x", "packages": {4}, "action": "keep", "neighbour": False}])
    @example([{"ecosystem": "gradle-kts", "manifest": DECLARATIONS[2], "packages": {0}, "action": "delete-lock", "neighbour": False},
              {"ecosystem": "gradle", "manifest": DECLARATIONS[1], "packages": {0, 1}, "action": "empty-lock", "neighbour": True}])
    @example([{"ecosystem": name, "manifest": "x", "packages": {index % len(PACKAGES)}, "action": "delete-lock", "neighbour": False}
              for index, name in enumerate(("cargo", "pipenv", "poetry", "composer", "gradle", "npm"))])
    @example([{"ecosystem": name, "manifest": "x", "packages": {index % len(PACKAGES)}, "action": "hollow-lock", "hollow": hollow, "neighbour": False}
              for index, (name, hollow) in enumerate((("npm", '{"lockfileVersion": 3}'), ("cargo", "version = 3\n"), ("pipenv", '{"_meta": {}}'),
                                                      ("composer", '{"packages": []}'), ("gradle", "# empty\n"), ("poetry", "[metadata]\n")))])
    def test_deleting_a_lockfile_never_fixes_what_was_reported_in_it(self, specs):
        self.examples += 1
        generated = Repository(specs)
        key = f"github#units-{self.examples}-{abs(hash(repr(specs))) % 10**8}"
        clock = datetime.now(timezone.utc)
        self.scan(generated.files(after=False), key, clock)
        before = registry.load(Path(self.directory.name), key)["findings"]
        self.assertTrue(all(entry["status"] == "open" for entry in before.values()))
        reported = {cve for entry in before.values() for cve in entry["finding"].get("cve") or []}
        self.assertEqual(reported, {PACKAGES[index][2] for project in generated.projects for index in project["packages"]})
        _, changes = self.scan(generated.files(after=True), key, clock + timedelta(hours=1))
        after = registry.load(Path(self.directory.name), key)["findings"]
        by_lockfile = {generated.lockfile(project): project for project in generated.projects}
        for digest, entry in before.items():
            finding = entry["finding"]
            places = [finding["path"], *((finding.get("package") or {}).get("also_in") or [])]
            owners = [by_lockfile[place] for place in places if place in by_lockfile]
            self.assertEqual(len(owners), len(places), places)
            actions = sorted(project["action"] for project in owners)
            now = after[digest]
            # A project deleted from the root while other folders stay leaves the root there: its files were deleted
            # from a folder still in the repository, so what came from them stays open (unexamined).
            remaining = generated.files(after=True)
            rooted = any(project["action"] == "delete-project" and project["folder"] == "" for project in owners) and bool(remaining)
            if "keep" in actions:     # still there, in a lockfile that is still read
                self.assertEqual(now["status"], "open", (finding["path"], actions))
            elif rooted or {"delete-lock", "empty-lock", "hollow-lock", "unresolved"} & set(actions):
                # Its project lost its lockfile (or didn't resolve): never fixed, whatever its manifest says, and why.
                self.assertEqual(now["status"], "open", (finding["path"], actions))
                self.assertIn((now.get("unseen") or {}).get("reason"), UNEXAMINED, (finding["path"], actions))
            else:                     # gone with its whole project, or upgraded where it was: fixed
                self.assertEqual(now["status"], "fixed", (finding["path"], actions))
        self.assertEqual(set(changes["fixed_now"]), {digest for digest, entry in after.items() if entry["status"] == "fixed"})

    def test_log4shell_declared_in_map_notation_stays_open_when_its_lockfile_goes(self):
        """The case a declaration regex missed: `implementation group: …, name: …, version: '2.+'` resolves through
        gradle.lockfile; without it the project is unexamined and Log4Shell stays open, said why."""
        generated = Repository([{"ecosystem": "gradle", "manifest": DECLARATIONS[0], "packages": {0}, "action": "delete-lock", "neighbour": False}])
        clock = datetime.now(timezone.utc)
        self.scan(generated.files(after=False), "github#log4shell", clock)
        _, changes = self.scan(generated.files(after=True), "github#log4shell", clock + timedelta(hours=1))
        entries = registry.load(Path(self.directory.name), "github#log4shell")["findings"]
        log4shell = [entry for entry in entries.values() if "CVE-2021-44228" in (entry["finding"].get("cve") or [entry["finding"].get("rule_id")])]
        self.assertTrue(log4shell)
        self.assertEqual(changes["fixed_now"], [])
        for entry in log4shell:
            self.assertEqual(entry["status"], "open")
            self.assertIn(entry["unseen"]["reason"], UNEXAMINED)
            self.assertEqual(entry["finding"]["units"], ["project://."])


# --- The registry over any coverage entry and any finding path in a unit ------------------------------------------

def _record(engine: str, where: str, entry: str, reason: str = "no_lockfile") -> dict:
    """A complete scan in which `engine` declared `entry` unexamined, at one of the places a coverage names it."""
    if where == "by_scanner":
        coverage = engine_contract.coverage("*", by_scanner={"sca": {entry: reason}})
    elif where == "unexamined":
        coverage = engine_contract.coverage("*", {entry: reason})
    else:
        coverage = engine_contract.coverage("*")
    tool = {**engines._result(engine, "completed", ""), "coverage": coverage}
    record = {"type": "repository_scan", "status": "completed", "coverage": repository._coverage([entry] if where == "left_out" else [], [tool], {}),
              "unexamined": repository._unexamined([entry] if where == "left_out" else [], [tool], {}),
              "summary": {"tools": [{"name": engine, "status": "completed"}]}}
    return record


def _decorated(path: str, how: int) -> str:
    return ("./" + path) if how == 1 else ("/" + path) if how == 2 else path


class UnitComparisonTests(unittest.TestCase):
    """An unexamined unit never fixes anything inside it, whatever the finding's path and however the coverage names it."""

    @settings(max_examples=300 * SCALE, deadline=None)
    @given(ecosystem=st.sampled_from(sorted(coverage_units.ECOSYSTEMS)), folder=st.sampled_from(FOLDERS), data=st.data())
    def test_an_unexamined_project_never_proves_a_dependency_finding_inside_it_gone(self, ecosystem, folder, data):
        manifests = coverage_units.ECOSYSTEMS[ecosystem]
        members = sorted({*(("App" + name) if name.startswith(".") else name for name in manifests),
                          *(lock for locks in manifests.values() for lock in locks), *coverage_units.MEMBERS.get(ecosystem, ())})
        listed = folder + data.draw(st.sampled_from(members), label="listed")
        if folder and data.draw(st.booleans(), label="as folder"):
            listed = folder.split("/")[0] + "/"
        place = folder + data.draw(st.sampled_from(members), label="finding's file")
        if data.draw(st.booleans(), label="seen elsewhere too"):   # the finding's own path is examined; its other lockfile isn't
            finding = {"tool": "osv-scanner", "scanner": "sca", "path": "elsewhere-zz/go.mod", "package": {"also_in": [place]}}
        else:
            finding = {"tool": "osv-scanner", "scanner": "sca", "path": _decorated(place, data.draw(st.integers(0, 2), label="decorated"))}
        if data.draw(st.booleans(), label="declares units"):
            coverage_units.declare(finding)
        where = data.draw(st.sampled_from(("by_scanner", "unexamined", "left_out")), label="where")
        record = _record("osv-scanner", where, listed)
        self.assertIsNotNone(registry.unproven_reason(record, finding), (listed, finding))

    @settings(max_examples=200 * SCALE, deadline=None)
    @given(ecosystem=st.sampled_from(sorted(coverage_units.ECOSYSTEMS)), data=st.data())
    def test_another_folder_or_another_scanner_is_not_held_back(self, ecosystem, data):
        """The unit is the project folder, not the file name nor the package manager: the next folder's project, and the
        secrets in the manifest itself, are still proven gone; anything else in that folder waits with it."""
        manifests = coverage_units.ECOSYSTEMS[ecosystem]
        manifest = next(iter(manifests))
        manifest = ("App" + manifest) if manifest.startswith(".") else manifest
        lock = sorted(next(iter(manifests.values())))[0]
        record = _record("trivy", "by_scanner", f"api/{manifest}")
        self.assertIsNotNone(registry.unproven_reason(record, {"tool": "trivy", "scanner": "sca", "path": f"api/{lock}"}))
        self.assertIsNone(registry.unproven_reason(record, {"tool": "trivy", "scanner": "sca", "path": f"apiv2/{lock}"}))
        self.assertIsNone(registry.unproven_reason(record, {"tool": "trivy", "scanner": "sca", "path": f"api/sub/{lock}"}))
        self.assertIsNone(registry.unproven_reason(record, {"tool": "trivy", "scanner": "secrets", "path": f"api/{manifest}"}))
        other = data.draw(st.from_regex(r"[a-z][a-z0-9._-]{0,12}", fullmatch=True), label="any other file of that folder")
        self.assertIsNotNone(registry.unproven_reason(record, {"tool": "trivy", "scanner": "sca", "path": f"api/{other}"}))

    @settings(max_examples=100 * SCALE, deadline=None)
    @given(scanner=st.sampled_from(("sast", "secrets", "iac", "cicd")), unexamined=st.sampled_from(("lib/x.py", "lib/")),
           key=st.sampled_from(("instances", "also_at")), engine=st.sampled_from(("opengrep", "betterleaks", "checkov", "zizmor")))
    def test_a_finding_seen_in_several_files_waits_for_every_one(self, scanner, unexamined, key, engine):
        """A family (or a report merged from several places) whose other copy is in an unexamined file isn't proven gone
        by its first file being examined."""
        finding = {"tool": engine, "scanner": scanner, "rule_id": "r", "path": "app/main.py", key: [{"path": "lib/x.py", "line": 3}]}
        for where in ("unexamined", "left_out"):
            self.assertIsNotNone(registry.unproven_reason(_record(engine, where, unexamined, "skipped"), finding), where)
        self.assertIsNone(registry.unproven_reason(_record(engine, "unexamined", "other/y.py", "skipped"), finding))

    def test_a_page_and_a_file_keep_their_own_units(self):
        self.assertTrue(coverage_units.inside("dist/app/x.js", {"dist/": "generated"}))
        self.assertFalse(coverage_units.inside("distribution/x.js", {"dist/": "generated"}))
        self.assertFalse(coverage_units.inside("https://host/admin", {"https://host/": "capped"}))
        self.assertTrue(coverage_units.inside("project://web/app", {"web/": "generated"}))
        self.assertFalse(coverage_units.inside("project://.", {"web/": "generated"}))
        self.assertTrue(coverage_units.inside("project://web", {"./": "tree_unlisted"}))
        self.assertEqual(coverage_units.unit("Svc/Cargo.lock", "sca"), coverage_units.unit("./Svc/cargo.toml", "sca"))
        self.assertEqual(coverage_units.unit("Svc/any.name", "sca"), "project://Svc")
        self.assertEqual(coverage_units.unit("Svc/Cargo.lock", "secrets"), "Svc/Cargo.lock")


class WithoutLockfileTests(unittest.TestCase):
    """The rule needs no syntax: any manifest that isn't empty, without its lockfile beside it, is unexamined."""

    @settings(max_examples=150 * SCALE, deadline=None)
    @given(ecosystem=st.sampled_from(LOCKED), text=manifest_texts, lock=st.sampled_from(("present", "absent", "empty")),
           folder=st.sampled_from(FOLDERS))
    def test_any_non_empty_manifest_without_its_lockfile_is_unexamined(self, ecosystem, text, lock, folder):
        manifest, lockfile, _, _ = ECOSYSTEMS[ecosystem]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / folder).mkdir(parents=True, exist_ok=True)
            (root / folder / manifest).write_text(text, encoding="utf-8")
            if lock != "absent":
                (root / folder / lockfile).write_text("x@1\n" if lock == "present" else " \n", encoding="utf-8")
            found = dependency_coverage.without_lockfile(root)
        self.assertEqual(found, {} if lock == "present" else {folder + manifest: "no_lockfile" if lock == "absent" else "empty_lockfile"})

    @settings(max_examples=150 * SCALE, deadline=None)
    @given(ecosystem=st.sampled_from(LOCKED), text=manifest_texts, hollow=hollow_locks, listed=st.booleans())
    def test_a_lockfile_counts_only_when_the_engine_inventoried_a_package_from_it(self, ecosystem, text, hollow, listed):
        manifest, lockfile, _, _ = ECOSYSTEMS[ecosystem]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "svc").mkdir()
            (root / "svc" / manifest).write_text(text, encoding="utf-8")
            (root / "svc" / lockfile).write_text(hollow, encoding="utf-8")
            found = dependency_coverage.without_lockfile(root, {f"svc/{lockfile}"} if listed else set())
        self.assertEqual(found, {} if listed else {f"svc/{manifest}": "empty_lockfile"})

    def test_an_empty_manifest_has_nothing_to_resolve(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "build.gradle").write_text(" \n")
            self.assertEqual(dependency_coverage.without_lockfile(Path(directory)), {})


if __name__ == "__main__":
    unittest.main()
