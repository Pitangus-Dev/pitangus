"""Invariants every engine, format and site must keep, tested as properties rather than as the example that broke.

I1  Only fixed with proof: a finding is fixed only when the engine that owns it looked at its location in a scan that
    succeeded; without proof it stays unseen, never fixed.
I2  A failure never looks clean: an unexpected exit code, invalid or empty output, a failed run or a timeout leaves
    the engine blind (never "completed").
I3  Stable and unique identity: the same problem keeps its identity when it moves or a build renames its assets; two
    different problems or resources never share one.
I4  Copies are counted: N identical copies are N instances.
I5  Merging never loses: two different findings are never joined into one.
I6  Determinism: the same input, in any order, gives the same output.
I7  Upgrades change nothing: the same commit scanned again, by new code or under a new identity version, opens nothing
    and fixes nothing, excluded findings included; a change of identity version never fixes.
I8  Configuration never fixes: turning a rule or an engine off, changing an allowlist or updating a rule between two
    scans of the same code fixes nothing; what it hid stays "not checked (configuration)" or excluded. With the same
    configuration, what left the code is fixed.
I9  Unproven is silent: a finding the fix hold keeps or a scan couldn't check reaches neither Jira nor the
    notifications.
I10 Coverage is per unit: an engine that ended `partial` proves gone what was in a unit it declares examined, never what
    was in one it didn't; one that failed or broke its contract proves nothing.

What the code doesn't guarantee yet is recorded here, not hidden: `KNOWN_GAPS` lists each adapter and failure an
engine still reports as clean, and the properties that still fail carry `expectedFailure` with the phase that
closes them. A gap that closes makes its test fail until the record is updated, so the list can only shrink.
"""

import json
import os
import subprocess
import tempfile
import unittest
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from hypothesis import HealthCheck, example, given, settings, strategies as st

from pitangus.modules.scanning.secret_location import entropy
from pitangus.modules.findings import canonical, registry
from pitangus.modules.findings.identity import family_counts, formers
from pitangus.shared import coverage_units, encodings
from pitangus.shared.i18n import text
from pitangus.modules.runs.store import save_repository_scan
from pitangus.modules.scanning import (config_engines, engine_contract, engines, image, nuclei_templates, policies, repository, rule_set,
                                       sarif_import, secret_identity, secret_rules, web_tools)
from pitangus.modules.scanning.secret_builtin_rules import OPT_IN_RULES
from pitangus.modules.sources.repositories import secrets_root
from pitangus.modules.scanning.dependency_merge import merge_dependencies
from pitangus.modules.scanning.folding import absorbed
import testenv
from test_betterleaks import TOKENS, placements, report


# These tests exercise the optional engines: turned on for the whole module, as an operator would.
_OPTIONAL_ON = patch.dict(os.environ, {"PITANGUS_CHECKOV_ENABLED": "1", "PITANGUS_GRYPE_ENABLED": "1"})


def setUpModule():
    _OPTIONAL_ON.start()


def tearDownModule():
    _OPTIONAL_ON.stop()

# Two profiles. On every pull request, the same examples on every run and machine (I6 holds for the tests too) and
# nothing written to disk. Every night (`HYPOTHESIS_PROFILE=nightly`, .github/workflows/nightly.yml), new random
# examples, many more of them: a counterexample it finds is printed with its reproduction blob and goes into the test as
# an `@example`, so the pull request profile checks it from then on.
PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1   # how many times more examples the night tries

# --- I2: fault injection, the same for every adapter ---------------------------------------------------------------

# What a broken engine can hand back: (exit code, output), or the exception its run raises.
FAILURES = {
    "exit-1": (1, ""), "exit-2": (2, ""), "exit-125": (125, ""), "exit-137": (137, ""),
    "exit-0-empty": (0, ""), "truncated": (0, '{"results": [{"check_id": "rules.x", "path": "/src/a'),
    "null": (0, "null"), "error-object": (0, '{"error": "the engine crashed"}'),
    "timeout": subprocess.TimeoutExpired(["engine"], 60), "os-error": OSError("cannot start the engine"),
}
HOST, PIN = "app.example.com", "93.184.216.34"


class FakeEngine:
    """A broken engine binary: writes `output` wherever it was told to write its report (any argument under a folder
    it mounted read-write), prints it, and exits with `code`; or raises."""

    def __init__(self, failure):
        self.failure = failure

    def __call__(self, key, arguments, snapshot=None, *, mounts=None, **options):
        if isinstance(self.failure, BaseException):
            raise self.failure
        code, output = self.failure
        folders = {}
        mounts = list(mounts or [])
        for flag, value in zip(mounts, mounts[1:]):
            if flag == "-v" and value.count(":") >= 1 and not value.endswith(":ro"):
                host, inside = value.split(":")[:2]
                folders[inside] = Path(host)
        for argument in arguments:
            for inside, host in folders.items():
                if isinstance(argument, str) and argument.startswith(inside + "/") and argument.endswith(".json"):
                    target = host / argument[len(inside) + 1:]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(output, encoding="utf-8")
        return subprocess.CompletedProcess(arguments, code, output, "the engine failed")


def _snapshot(root: Path) -> Path:
    """A snapshot with something for every code engine to look at."""
    snapshot = root / "snapshot"
    (snapshot / ".github" / "workflows").mkdir(parents=True)
    (snapshot / "app.py").write_text("import os\nos.system(input())\n")
    (snapshot / "Dockerfile").write_text("FROM python:3.12\n")
    (snapshot / "requirements.txt").write_text("requests==2.25.0\n")
    (snapshot / ".github" / "workflows" / "ci.yml").write_text("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n")
    return snapshot


def _credentials(root: Path) -> dict:
    """The secret scanners' pass over the credential files: clean only if both read every file."""
    snapshot = _snapshot(root)
    secrets_root(snapshot).mkdir(parents=True)
    (secrets_root(snapshot) / ".env").write_text("TOKEN=x\n")
    result = repository.scan_credentials(snapshot, root, None, engines=True)
    return {"status": "inconclusive" if result["unexamined"] else "completed"}


def _status(result) -> str:
    return result.status if isinstance(result, web_tools.ToolRun) else result[0].status if isinstance(result, tuple) \
        and isinstance(result[0], web_tools.ToolRun) else (result[0] if isinstance(result, tuple) else result)["status"]


IMAGE_METADATA = {"ImageConfig": {"history": [{"created_by": "/bin/sh -c apk add --no-cache curl"}], "config": {}}}

# Every engine adapter, called the way a scan calls it. A new engine adds one line here and gets every failure.
ADAPTERS = {
    "opengrep": lambda root: engines.run_opengrep(_snapshot(root)),
    "betterleaks": lambda root: engines.run_betterleaks(_snapshot(root)),
    "trivy": lambda root: engines.run_trivy(_snapshot(root), root / "trivy-cache", {}),
    "osv-scanner": lambda root: engines.run_osv_scanner(_snapshot(root), root / "osv-cache", {}),
    "checkov": lambda root: config_engines.run_checkov(_snapshot(root)),
    "zizmor": lambda root: config_engines.run_zizmor(_snapshot(root)),
    "trivy-image": lambda root: image.run_trivy_image("alpine:3.20", root / "trivy-cache", {}, None),
    "grype-image": lambda root: image.run_grype_image("alpine:3.20", root / "grype-cache", {}, None, "docker.io"),
    "checkov-image": lambda root: config_engines.run_checkov_image(IMAGE_METADATA, {"asset": "image:docker.io/library/alpine"}, root / "tmp"),
    "katana": lambda root: web_tools.run_katana([f"https://{HOST}/"], [HOST], {HOST: PIN}, root, headless=False),
    "nuclei": lambda root: web_tools.run_nuclei([f"https://{HOST}/"], [], [HOST], {HOST: PIN}, root, root / "nuclei"),
    "testssl": lambda root: web_tools.run_testssl([HOST], {HOST: PIN}, root),
    "httpx": lambda root: web_tools.run_httpx([HOST], {HOST: PIN}, root),
    "credentials": _credentials,
}

# (adapter, failure) pairs still reported as "completed" in shadow mode (PITANGUS_COVERAGE_MODE=shadow, a choice the
# operator can still make): the engine looked blind and said it was clean. With the engine contract on, none is. The
# adapters that read a snapshot or an image apply the contract in every mode (A3: UnfinishedRunTests).
KNOWN_GAPS: set[tuple[str, str]] = {
    ("nuclei", "exit-0-empty"), ("nuclei", "truncated"), ("nuclei", "null"), ("nuclei", "error-object"),
}


def run_adapter(name: str, failure) -> str:
    result = call_adapter(ADAPTERS[name], failure)
    return result if isinstance(result, str) else _status(result)


def call_adapter(call, failure):
    """What an adapter returns when every engine it starts fails with `failure` (or "crash:…" when it raises)."""
    with tempfile.TemporaryDirectory() as folder, \
            patch.object(engines, "_run", side_effect=FakeEngine(failure)), \
            patch.object(config_engines, "_run", side_effect=FakeEngine(failure)), \
            patch.object(image, "_run", side_effect=FakeEngine(failure)), \
            patch.object(web_tools, "_run", side_effect=FakeEngine(failure)), \
            patch.object(engines, "unavailable", return_value=None), \
            patch.object(config_engines, "unavailable", return_value=None), \
            patch.object(image, "unavailable", return_value=None), \
            patch.object(engines, "runner", return_value="docker"), \
            patch.object(engines, "docker_available", return_value=True), \
            patch.object(engines, "image_available", return_value=True), \
            patch.object(engines, "trivy_databases", return_value=[]), \
            patch.object(image, "trivy_databases", return_value=[]), \
            patch.object(nuclei_templates, "ensure", return_value=(Path(folder), {"hosts": 1, "pages": 1})), \
            patch.object(nuclei_templates, "ensure_own", return_value=(None, {})):
        root = Path(folder)
        try:
            return call(root)
        except Exception as exc:  # noqa: BLE001 - an adapter that crashes is a failure of its own, recorded as such
            return f"crash:{type(exc).__name__}"


class FailureInjectionTests(unittest.TestCase):
    """I2 for every adapter and every way an engine can fail."""

    def test_an_engine_left_off_is_not_run_never_clean(self):
        """Disabled is blind: any engine turned off (Checkov and Grype by default) reports `not_tested` without running,
        so nothing it found before is fixed."""
        from pitangus.modules.scanning import engine_switches
        from pitangus.modules.scanning.engines import EngineStep, ScanContext, run_engines
        with patch.dict(os.environ, {"PITANGUS_CHECKOV_ENABLED": "", "PITANGUS_GRYPE_ENABLED": "", "PITANGUS_OPENGREP_ENABLED": "0"}):
            switches = engine_switches.resolve(None)
            for key in ("checkov", "grype", "opengrep"):
                with self.subTest(engine=key):
                    result = engines.switched_off(key, switches)
                    self.assertEqual((result["status"], result["disabled"]), ("not_tested", True))
                    record = {"status": "completed", "type": "repository_scan", "summary": {"tools": [{"name": key, "status": result["status"]}]}}
                    self.assertEqual(registry.unproven_reason(record, {"tool": key, "path": "main.tf", "scanner": "iac"}), "engine_blind")
            ran: list[str] = []
            steps = [EngineStep(key, lambda context, key=key: ran.append(key) or engines._result(key, "completed", ""), "scanning.progress.trivy")
                     for key in ("opengrep", "trivy", "checkov")]
            results = run_engines(steps, ScanContext(Path("."), Path("."), {}, switches=switches), lambda *_: None)
        self.assertEqual(ran, ["trivy"])
        self.assertEqual({key: result["status"] for key, result in results.items()},
                         {"opengrep": "not_tested", "trivy": "completed", "checkov": "not_tested"})

    def test_no_failure_is_ever_reported_as_a_clean_run(self):
        """PITANGUS_COVERAGE_MODE=shadow: only KNOWN_GAPS look clean."""
        with patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "shadow"}):
            observed = {(name, failure) for name in ADAPTERS for failure, value in FAILURES.items()
                        if (status := run_adapter(name, value)) == "completed" or status.startswith("crash:")}
        self.assertEqual(sorted(observed - KNOWN_GAPS), [], "new ways an engine can fail and look clean")
        self.assertEqual(sorted(KNOWN_GAPS - observed), [], "closed gaps: remove them from KNOWN_GAPS")

    def test_with_the_engine_contract_on_no_failure_looks_clean_at_all(self):
        """PITANGUS_COVERAGE_MODE=on: every adapter goes through the engine contract, and KNOWN_GAPS is empty."""
        with patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "on"}):
            observed = {(name, failure) for name in ADAPTERS for failure, value in FAILURES.items()
                        if (status := run_adapter(name, value)) == "completed" or status.startswith("crash:")}
        self.assertEqual(sorted(observed), [])


# --- A3: a run that didn't finish neither opens nor closes findings, for every adapter but the web tools' ----------

# How each run can stop short, besides FAILURES: killed with half its output written, a wrong exit code over output that
# looks whole, and the engine's own JSON without the mark it writes whenever it read its input.
VALID = {   # what each engine writes when it read its input, so the failures below are about the run, not the fixture
    "opengrep": '{"results": [], "errors": [], "paths": {"scanned": ["/src/app.py"]}}', "betterleaks": "[]",
    "trivy": '{"SchemaVersion": 2, "Results": []}', "osv-scanner": '{"results": []}',
    "checkov": '{"check_type": "terraform", "results": {"failed_checks": []}, "summary": {"parsing_errors": 0}}', "zizmor": "[]",
    "trivy-image": '{"SchemaVersion": 2, "Metadata": {}, "Results": []}', "grype-image": '{"matches": [], "source": {"type": "image"}}',
}
VALID["checkov-image"] = VALID["checkov"]
MISSING_MARK = {"opengrep": '{"results": [], "errors": []}', "betterleaks": "", "trivy": '{"Results": []}',
                "osv-scanner": '{"experimental_config": {}}', "checkov": '{"check_type": "terraform", "results": {}}',
                "zizmor": "[]", "trivy-image": '{"SchemaVersion": 2, "Results": []}', "grype-image": '{"matches": []}',
                "checkov-image": '{"check_type": "dockerfile", "results": {}}', "credentials": '{"Results": []}'}
UNFINISHED = {**FAILURES, "killed": (-9, '{"SchemaVersion": 2, "Results": [{"Target": "requirements.txt"'),
              "killed-in-docker": (137, '[{"RuleID": "github-pat", "File": "/src/app.py", "StartLine": 1'),
              "exit-3-with-output": None, "missing-mark": None}


def _credential_result(root: Path) -> dict:
    snapshot = _snapshot(root)
    secrets_root(snapshot).mkdir(parents=True)
    (secrets_root(snapshot) / ".env").write_text("TOKEN=x\n")
    return repository.scan_credentials(snapshot, root, None, engines=True)


# Every adapter that reads a snapshot or an image: (the function it is, how a scan calls it, a finding the engine owns
# where it looks). A new engine adds one line here (test_every_engine_and_adapter_is_under_fault_injection says so).
UNFINISHED_ADAPTERS = {
    "opengrep": ("run_opengrep", ADAPTERS["opengrep"], {"tool": "opengrep", "scanner": "sast", "path": "app.py"}),
    "betterleaks": ("run_betterleaks", ADAPTERS["betterleaks"], {"tool": "betterleaks", "scanner": "secrets", "path": "app.py"}),
    "trivy": ("run_trivy", ADAPTERS["trivy"], {"tool": "trivy", "scanner": "sca", "path": "requirements.txt"}),
    "osv-scanner": ("run_osv_scanner", ADAPTERS["osv-scanner"], {"tool": "osv-scanner", "scanner": "sca", "path": "requirements.txt"}),
    "checkov": ("run_checkov", ADAPTERS["checkov"], {"tool": "checkov", "scanner": "iac", "path": "Dockerfile"}),
    "zizmor": ("run_zizmor", ADAPTERS["zizmor"], {"tool": "zizmor", "scanner": "cicd", "path": ".github/workflows/ci.yml"}),
    "trivy-image": ("run_trivy_image", lambda root: ADAPTERS["trivy-image"](root)[0], {"tool": "trivy", "scanner": "sca", "path": "alpine:3.20"}),
    "grype-image": ("run_grype_image", ADAPTERS["grype-image"], {"tool": "grype", "scanner": "sca", "path": "alpine:3.20"}),
    "checkov-image": ("run_checkov_image", ADAPTERS["checkov-image"], {"tool": "checkov", "scanner": "iac", "path": "image-config"}),
    "credentials": ("scan_credentials", _credential_result, {"tool": "betterleaks", "scanner": "secrets", "path": ".env"}),
}
UNFINISHED_ENGINE = {"trivy-image": "trivy", "grype-image": "grype", "checkov-image": "checkov", "credentials": "betterleaks"}
# No engine process that could stop short: the policy reader reads the files itself (each one it can't read is unexamined,
# test_policies), and run_engines is the loop that runs the adapters (and settles their results).
NO_PROCESS = {"run_policies", "run_engines"}


class UnfinishedRunTests(unittest.TestCase):
    """A3: killed, timed out, a wrong exit code, truncated or invalid JSON, no completion mark, empty output with a
    clean exit: whatever the mode, the engine's result opens no finding and no fix is attributed to it."""

    def failure(self, name: str, kind: str):
        if kind == "exit-3-with-output":
            return (3, VALID.get(name, "{}"))
        return (0, MISSING_MARK[name]) if kind == "missing-mark" else UNFINISHED[kind]

    def test_every_valid_output_is_a_finished_run(self):
        """The fixtures are right: each engine's own output with a clean exit is a completed run."""
        for name, output in VALID.items():
            with self.subTest(adapter=name):
                self.assertEqual(_status(call_adapter(UNFINISHED_ADAPTERS[name][1], (1 if name == "opengrep" else 0, output))), "completed")

    def test_a_run_that_did_not_finish_opens_nothing_and_fixes_nothing(self):
        for mode in ("shadow", "on"):
            for name, (_, call, probe) in UNFINISHED_ADAPTERS.items():
                for kind in UNFINISHED:
                    if kind == "exit-3-with-output" and name not in VALID:
                        continue
                    with self.subTest(mode=mode, adapter=name, failure=kind), patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": mode}):
                        result = call_adapter(call, self.failure(name, kind))
                        self.assertNotIsInstance(result, str, result)
                        self.assertEqual([*result["findings"], *(result.get("silenced") or []), *(result.get("withheld") or []),
                                          *(result.get("packages") or [])], [])
                        if name == "credentials":
                            self.assertEqual(result["unexamined"], {"betterleaks": {".env": "not_read"}, "trivy": {".env": "not_read"}})
                            record = _code_record([], result["unexamined"])
                        else:
                            unread = (result.get("coverage") or {}).get("unexamined") or {}
                            self.assertTrue(result["status"] != "completed" or probe["path"] in unread, result["status"])
                            record = _code_record([result])
                        self.assertIsNotNone(registry.unproven_reason(record, probe))
                        self.assertTrue(registry.unseen(probe, registry.blind_engines(record)) or not registry.covers(record, probe))

    def test_the_reference_run_of_the_secret_filters_that_did_not_finish_is_none(self):
        """trivy_secrets (the unfiltered run that tells a silenced secret from a fixed one): None, never an empty list."""
        call = lambda root: engines.trivy_secrets(_snapshot(root), root / "trivy-cache", None)  # noqa: E731
        for kind in UNFINISHED:
            with self.subTest(failure=kind):
                self.assertIsNone(call_adapter(call, (0, MISSING_MARK["trivy"]) if kind == "missing-mark" else
                                               (3, VALID["trivy"]) if kind == "exit-3-with-output" else UNFINISHED[kind]))

    def test_every_engine_and_adapter_is_under_fault_injection(self):
        """A new engine (engines.IMAGES, the code engines) or a new run_* adapter without a line in UNFINISHED_ADAPTERS
        fails here."""
        covered = {UNFINISHED_ENGINE.get(name, name) for name in UNFINISHED_ADAPTERS}
        self.assertEqual(sorted(set(engines.IMAGES) - engines.WEB_ENGINES - covered), [])
        self.assertEqual(sorted({engine.key for engine in repository.CODE_ENGINES} - set(UNFINISHED_ADAPTERS)), [])
        adapters = {name for module in (engines, config_engines, image, repository, policies) for name, value in vars(module).items()
                    if name.startswith("run_") and callable(value) and getattr(value, "__module__", None) == module.__name__}
        self.assertEqual(sorted(adapters - {function for function, _, _ in UNFINISHED_ADAPTERS.values()} - NO_PROCESS), [])

    def test_an_adapter_that_forgets_the_rule_still_opens_and_fixes_nothing(self):
        """The rule lives in the contract (engine_contract.settled), not in each adapter: an engine whose result says
        inconclusive but still carries findings, as a new adapter might, opens none of them and fixes nothing it saw
        before, through a whole scan and the registry."""
        for mode in ("shadow", "on"):
            for broken in repository.CODE_ENGINES:
                with self.subTest(mode=mode, engine=broken.key), tempfile.TemporaryDirectory() as folder, \
                        patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": mode, "PITANGUS_FIX_HOLD_MINIMUM": "1000"}):
                    data_dir, snapshot = Path(folder), _snapshot(Path(folder))
                    key = f"github#{broken.key}-{mode}"
                    source = {"id": "github:org/api", "uid": key, "name": "org/api", "provider": "github"}
                    _replay_scan(snapshot, source, data_dir, None)
                    before = registry.load(data_dir, key)["findings"]
                    # By rule: the registry keys a finding by its fingerprint or, in v2, by its identity.
                    rules = lambda entries: {entry["finding"]["rule_id"] for entry in entries.values()}  # noqa: E731
                    self.assertIn(_replayed(broken.key, None)["findings"][0]["rule_id"], rules(before))
                    record = _replay_scan(snapshot, source, data_dir, broken.key)
                    after = registry.load(data_dir, key)["findings"]
                    self.assertNotIn(_replayed(broken.key, broken.key)["findings"][0]["rule_id"], rules(after))   # opened nothing
                    self.assertEqual({digest: entry["status"] for digest, entry in after.items()},
                                     {digest: entry["status"] for digest, entry in before.items()})       # fixed nothing
                    self.assertNotIn(broken.key, {item["tool"] for item in record["findings"]})


REPLAYED = {"opengrep": ("sast", "app.py"), "betterleaks": ("secrets", "app.py"), "trivy": ("iac", "Dockerfile"),
            "osv-scanner": ("iac", "requirements.txt"), "checkov": ("iac", "main.tf"), "zizmor": ("cicd", ".github/workflows/ci.yml")}


def _replay_scan(snapshot: Path, source: dict, data_dir: Path, failing: str | None) -> dict:
    """A whole code scan from recorded engine results (`_replayed`), saved and applied to the registry."""
    replay = tuple(engines.EngineStep(engine.key, (lambda context, key=engine.key: _replayed(key, failing)), engine.progress,
                                      engine.required, engine.merged) for engine in repository.CODE_ENGINES)
    record = repository.scan_repository(snapshot, source, data_dir=data_dir, replay=replay, feeds={"kev": {}, "epss": {}})
    return save_repository_scan(data_dir, record)


def _replayed(key: str, failing: str | None) -> dict:
    """A recorded engine result with one finding; the failing engine's says inconclusive and still carries a new one."""
    scanner, path = REPLAYED[key]
    rule = f"{key}-new" if key == failing else f"{key}-old"
    finding = engines._base(scanner, rule, rule, path, 1, "high", reason="", remediation="", cwe=[], owasp="A05:2025", confidence=8,
                            digest=engines._stable(key, rule, path), tool=key)
    result = engines._result(key, "inconclusive" if key == failing else "completed", "", [finding])
    return result if key == failing else {**result, "coverage": engine_contract.coverage("*")}


# --- A8: a manifest that couldn't be resolved or read is the only thing left unexamined ---------------------------

FIXTURES = Path(__file__).parent / "fixtures"
TRIVY_429 = (FIXTURES / "trivy-0.75-maven-429.log").read_text(encoding="utf-8")   # what Trivy 0.75 prints, alone, when it stops
DEPENDENCY_DIRS = ("", "api/", "svc/", "libs/core/", "web/")


class FakeResolvingTrivy:
    """Trivy 0.75 as recorded: an online run over the snapshot stops, without output, at the first manifest whose remote
    resolution fails; an offline run (`--offline-scan`) reads everything; one manifest alone resolves or fails alone."""

    def __init__(self, manifests: list[str], failing: set[str]):
        self.manifests, self.failing = manifests, failing

    def __call__(self, key, arguments, snapshot=None, **options):
        target = arguments[-1].removeprefix("/src").lstrip("/")
        files = [target] if target else self.manifests
        scanners = arguments[arguments.index("--scanners") + 1].split(",")
        if "--offline-scan" not in arguments and self.failing & set(files):
            return subprocess.CompletedProcess(arguments, 1, "", TRIVY_429)
        results = [{"Target": path.rsplit("/", 1)[-1] if target else path, "Class": "lang-pkgs",
                    "Type": "pom" if path.endswith("pom.xml") else "npm",
                    "Packages": [{"ID": f"lib{index}@1.0", "Name": f"lib{index}", "Version": "1.0"}],
                    "Vulnerabilities": [{"VulnerabilityID": f"CVE-2024-{1000 + index}", "PkgID": f"lib{index}@1.0", "PkgName": f"lib{index}",
                                         "InstalledVersion": "1.0", "FixedVersion": "1.1", "Severity": "HIGH"}]}
                   for index, path in enumerate(self.manifests) if path in files]
        if not target and "secret" in scanners:   # every manifest holds a secret, read whatever its resolution did
            results += [{"Target": path, "Class": "secret", "Secrets": [{"RuleID": "aws-access-key-id", "Category": "AWS", "Title": "AWS",
                                                                         "StartLine": 2, "EndLine": 2, "Match": "key = ****"}]}
                        for path in self.manifests]
        if not target and "misconfig" in scanners:
            results.append({"Target": "Dockerfile", "Class": "config", "Type": "dockerfile", "Misconfigurations": [
                {"AVDID": "AVD-DS-0002", "Title": "Root user", "Severity": "HIGH", "Status": "FAIL", "CauseMetadata": {"StartLine": 1}}]})
        log = testenv.read_log("trivy", snapshot) if not target and "secret" in scanners else ""
        return subprocess.CompletedProcess(arguments, 0, json.dumps({"SchemaVersion": 2, "Results": results}), log)


manifest_sets = st.sets(st.tuples(st.sampled_from(DEPENDENCY_DIRS), st.sampled_from(("pom.xml", "package-lock.json"))),
                        min_size=1, max_size=8).map(lambda pairs: sorted(folder + name for folder, name in pairs))


def _code_record(tools: list[dict], credentials: dict[str, list[str]] | None = None) -> dict:
    """A complete code scan with these engine results, stored as scan_repository stores them."""
    return {"type": "repository_scan", "status": "completed", "coverage": repository._coverage([], tools, credentials or {}),
            "unexamined": repository._unexamined([], tools, credentials or {}),
            "summary": {"tools": [{"name": tool["tool"], "status": tool["status"], **({"contract": tool["contract"]} if tool.get("contract") else {})}
                                  for tool in tools]}}


class ResolutionTests(unittest.TestCase):
    """A8: a resolution or read that fails for one manifest leaves that manifest (and only for the scanner that needed
    it) unexamined; the rest of the engine's run still proves what it no longer sees."""

    def run_trivy(self, manifests: list[str], failing: set[str]) -> dict:
        with tempfile.TemporaryDirectory() as folder:
            snapshot = Path(folder) / "snapshot"
            for path in [*manifests, "Dockerfile"]:
                (snapshot / path).parent.mkdir(parents=True, exist_ok=True)
                (snapshot / path).write_text("FROM python:3.12\n" if path == "Dockerfile" else "<project/>\n")
            with patch.object(engines, "_run", side_effect=FakeResolvingTrivy(manifests, failing)), \
                    patch.object(engines, "unavailable", return_value=None), patch.object(engines, "trivy_databases", return_value=[]):
                return engines.run_trivy(snapshot, Path(folder) / "cache", {})

    @settings(max_examples=40 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(manifest_sets, st.data())
    def test_only_the_manifests_whose_resolution_failed_go_unexamined(self, manifests, data):
        remote = [path for path in manifests if path.endswith("pom.xml")]
        self.check_resolution(manifests, data.draw(st.sets(st.sampled_from(remote)) if remote else st.just(set())))

    def test_a_parent_pom_refused_by_maven_central_leaves_only_its_dependencies_unexamined(self):
        self.check_resolution(["pom.xml", "svc/pom.xml", "web/package-lock.json"], {"pom.xml"})

    def check_resolution(self, manifests: list[str], failing: set[str]) -> None:
        for mode in ("shadow", "on"):
            with patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": mode}):
                result = self.run_trivy(manifests, failing)
            self.assertEqual(result["status"], "completed")
            coverage = result["coverage"]
            self.assertEqual(set((coverage.get("by_scanner") or {}).get("sca", {})), failing)
            self.assertFalse(set(coverage["unexamined"]) & set(manifests), coverage)
            # A manifest not examined opens nothing: what the offline run guessed for it is left out.
            self.assertEqual({item["path"] for item in result["findings"] if item["scanner"] == "sca"}, set(manifests) - failing)
            self.assertEqual({item["path"] for item in result["findings"] if item["scanner"] == "secrets"}, set(manifests))
            self.assertIn("Dockerfile", {item["path"] for item in result["findings"] if item["scanner"] == "iac"})
            record = _code_record([result])
            # A dependency lives in its project folder: one manifest there that didn't resolve leaves the folder unexamined.
            held_back = {coverage_units.folder_of(path) for path in failing}
            with patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": mode}):
                for path in manifests:
                    dependency = {"tool": "trivy", "scanner": "sca", "path": path}
                    self.assertEqual(registry.unproven_reason(record, dependency) is not None, coverage_units.folder_of(path) in held_back, path)
                    self.assertEqual(registry.covers(record, dependency), coverage_units.folder_of(path) not in held_back, path)
                    self.assertIsNone(registry.unproven_reason(record, {"tool": "trivy", "scanner": "secrets", "path": path}), path)
                self.assertIsNone(registry.unproven_reason(record, {"tool": "trivy", "scanner": "iac", "path": "Dockerfile"}))

    def test_a_failure_that_is_not_a_resolution_still_leaves_trivy_blind(self):
        def broken(key, arguments, snapshot=None, **options):
            return subprocess.CompletedProcess(arguments, 1, "", "FATAL\tError\tinit error: DB error: failed to load the database")
        with tempfile.TemporaryDirectory() as folder:
            snapshot = Path(folder) / "snapshot"
            snapshot.mkdir()
            (snapshot / "pom.xml").write_text("<project/>\n")
            with patch.object(engines, "_run", side_effect=broken), patch.object(engines, "unavailable", return_value=None), \
                    patch.object(engines, "trivy_databases", return_value=[]):
                result = engines.run_trivy(snapshot, Path(folder) / "cache", {})
        self.assertEqual((result["status"], result["findings"]), ("inconclusive", []))

    def run_osv(self, files: dict[str, str], code: int, log: str, payload: dict) -> dict:
        with tempfile.TemporaryDirectory() as folder:
            snapshot = Path(folder) / "snapshot"
            for path, text in files.items():
                (snapshot / path).parent.mkdir(parents=True, exist_ok=True)
                (snapshot / path).write_text(text)
            snapshot.mkdir(exist_ok=True)
            fake = lambda key, arguments, snapshot=None, **options: subprocess.CompletedProcess(arguments, code, json.dumps(payload), log)  # noqa: E731
            with patch.object(engines, "_run", side_effect=fake), patch.object(engines, "unavailable", return_value=None):
                return engines.run_osv_scanner(snapshot, Path(folder) / "cache", {})

    def test_recorded_osv_runs_never_examine_everything_when_they_read_nothing(self):
        """OSV-Scanner 2.6's own logs: no manifests (exit 0), only an unreadable lockfile (exit 127) and one of two
        lockfiles unreadable (exit 1)."""
        empty = {"results": []}
        none = self.run_osv({"README.md": "hi\n"}, 0, (FIXTURES / "osv-2.6-no-manifests.log").read_text(), empty)
        # What it examined is said by folder: a folder of the repository it inventoried nothing from is unexamined.
        self.assertEqual((none["status"], none["coverage"]),
                         ("completed", {"examined": "*", "unexamined": {}, "dependencies": {"inventoried": [], "uninventoried": ["."]}}))
        unreadable = self.run_osv({"package-lock.json": "{not json\n"}, 127, (FIXTURES / "osv-2.6-unreadable.log").read_text(), empty)
        self.assertEqual((unreadable["status"], unreadable["coverage"]["unexamined"], unreadable["coverage"]["dependencies"]["uninventoried"]),
                         ("completed", {"package-lock.json": "parse_error"}, ["."]))
        mixed = self.run_osv({"a/package-lock.json": "{}\n", "b/package-lock.json": "{not json\n"}, 1, (FIXTURES / "osv-2.6-mixed.log").read_text(),
                             {"results": [{"source": {"path": "/src/a/package-lock.json", "type": "lockfile"},
                                           "packages": [{"package": {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}}]}]})
        self.assertEqual((mixed["coverage"]["examined"], mixed["coverage"]["unexamined"]), ("*", {"b/package-lock.json": "parse_error"}))
        self.assertEqual(mixed["coverage"]["dependencies"], {"inventoried": ["a/package-lock.json"], "uninventoried": [".", "b"]})
        for result, unit, proven in ((none, "package-lock.json", False), (unreadable, "package-lock.json", False),
                                     (mixed, "a/package-lock.json", True), (mixed, "b/package-lock.json", False)):
            reason = registry.unproven_reason(_code_record([result]), {"tool": "osv-scanner", "scanner": "sca", "path": unit})
            self.assertEqual(reason is None, proven, (unit, result["coverage"]))

    @settings(max_examples=40 * SCALE, deadline=None)
    @given(st.sets(st.sampled_from(DEPENDENCY_DIRS), max_size=5), st.data())
    def test_osv_leaves_unexamined_exactly_the_lockfiles_it_could_not_read(self, folders, data):
        lockfiles = sorted(f"{folder}package-lock.json" for folder in folders)
        unreadable = data.draw(st.sets(st.sampled_from(lockfiles)) if lockfiles else st.just(set()))
        read = [path for path in lockfiles if path not in unreadable]
        log = "\n".join(["Scanning dir /src", *(f"Scanned /src/{path} file and found 1 package" for path in read),
                         *(f"Error during extraction: (extracting as javascript/packagelockjson) src/{path}: could not extract: unexpected end of JSON input"
                           for path in sorted(unreadable)), "No package sources found" if not read else ""])
        code = 127 if unreadable and not read else 0
        payload = {"results": [{"source": {"path": f"/src/{path}", "type": "lockfile"},
                                "packages": [{"package": {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}}]} for path in read]}
        result = self.run_osv(dict.fromkeys(lockfiles, "{}\n"), code, log, payload)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["coverage"]["unexamined"], dict.fromkeys(sorted(unreadable), "parse_error"))
        self.assertEqual(result["coverage"]["dependencies"]["inventoried"], sorted(read))
        for path in lockfiles:
            reason = registry.unproven_reason(_code_record([result]), {"tool": "osv-scanner", "scanner": "sca", "path": path})
            self.assertEqual(reason is None, path in read, path)


# --- F2: what an engine doesn't resolve is unexamined, never examined ------------------------------------------------

TRIVY_MAVEN_OFFLINE = json.loads((FIXTURES / "trivy-0.75-maven-parent-offline.json").read_text(encoding="utf-8"))
# What each folder of a generated repository holds: a lockfile whose packages may be left without a version and which may
# be saved as UTF-16, a manifest that needs a lockfile (with it, without it, with only `bun.lockb`, or declaring nothing),
# or a pip requirements file whose requirements may not be pinned.
dependency_folders = st.lists(st.fixed_dictionaries({
    "kind": st.sampled_from(("pom", "npm-lock", "gradle", "npm", "pipfile", "gemfile", "requirements")),
    "packages": st.integers(1, 4),
    "unversioned": st.sets(st.integers(0, 3), max_size=2),
    "variant": st.sampled_from(("locked", "unlocked", "bun-binary", "declares-nothing")),
    "utf16": st.booleans(),
}), min_size=1, max_size=len(DEPENDENCY_DIRS))


class DependencyRepository:
    """A generated repository: its files, Trivy's and OSV-Scanner's output for them as each engine behaves (Trivy keeps a
    package whose version didn't resolve with an empty one and leaves an unpinned requirement out; OSV-Scanner lists both
    with an empty version; neither reads UTF-16, Trivy without a word), and what each engine must leave unexamined."""

    def __init__(self, folders: list[dict]):
        self.files: dict[str, bytes] = {}
        self.trivy: list[dict] = []
        self.osv: list[dict] = []
        self.log: list[str] = []
        self.sca: dict[str, str] = {}          # unexamined for the dependency scanner only
        self.unreadable: dict[str, str] = {}   # unexamined for every scanner (Trivy) or unread (OSV)
        self.osv_unreadable: dict[str, str] = {}
        self.total = 0                         # packages in Trivy's results
        for folder, spec in zip(DEPENDENCY_DIRS, folders):
            getattr(self, "_" + spec["kind"].replace("-", "_"))(folder, spec)

    def _write(self, path: str, content: str, utf16: bool = False) -> None:
        self.files[path] = content.encode("utf-16" if utf16 else "utf-8")


    def _packages(self, folder: str, spec: dict, unversioned: bool = True) -> list[tuple[str, str]]:
        missing = spec["unversioned"] if unversioned else set()
        return [(f"{folder.replace('/', '-')}lib{index}", "" if index in missing else f"1.{index}") for index in range(spec["packages"])]

    def _result(self, path: str, kind: str, packages: list[tuple[str, str]], root: str | None = None, utf16: bool = False) -> None:
        if utf16:   # neither engine decodes it: Trivy is silent, OSV-Scanner says it couldn't extract it
            self.unreadable[path] = "encoding"
            self.osv_unreadable[path] = "parse_error"
            self.log.append(f"Error during extraction: (extracting as {kind}) src/{path}: could not extract: invalid character '\\xff' looking for beginning of value")
            return
        entries = [*([(root, "1.0", "root")] if root else []), *((name, version, "direct") for name, version in packages)]
        self.total += len(entries)
        self.trivy.append({"Target": path, "Class": "lang-pkgs", "Type": kind,
                           "Packages": [{"ID": f"{name}@{version}", "Name": name, **({"Version": version} if version else {}), "Relationship": relation}
                                        for name, version, relation in entries]})
        self.osv.append({"source": {"path": f"/src/{path}", "type": "lockfile"},
                         "packages": [{"package": {"name": name, "version": version, "ecosystem": "Maven"}} for name, version in packages]})
        self.log.append(f"Scanned /src/{path} file and found {len(packages)} packages")
        if any(not version for _, version in packages):
            self.sca[path] = "unresolved_versions"

    def _pom(self, folder: str, spec: dict) -> None:
        self._write(f"{folder}pom.xml", "<project/>\n", spec["utf16"])
        self._result(f"{folder}pom.xml", "pom", self._packages(folder, spec), root=f"{folder}app", utf16=spec["utf16"])

    def _npm_lock(self, folder: str, spec: dict) -> None:
        self._write(f"{folder}package.json", '{"dependencies": {"lib0": "^1.0.0"}}\n')
        self._write(f"{folder}package-lock.json", '{"lockfileVersion": 3, "packages": {"node_modules/lib0": {"version": "1.0.0"}}}\n', spec["utf16"])
        self._result(f"{folder}package-lock.json", "npm", self._packages(folder, spec), utf16=spec["utf16"])
        if spec["utf16"]:   # the engine got no package from its lockfile: the project wasn't resolved
            self.sca[f"{folder}package.json"] = "empty_lockfile"

    def _locked_or_not(self, folder: str, spec: dict, manifest: tuple[str, str], lockfile: tuple[str, str], kind: str) -> None:
        self._write(folder + manifest[0], manifest[1])
        if spec["variant"] == "locked":
            self._write(folder + lockfile[0], lockfile[1])
            self._result(folder + lockfile[0], kind, self._packages(folder, spec, unversioned=False))
        else:
            self.sca[folder + manifest[0]] = "no_lockfile"

    def _gradle(self, folder: str, spec: dict) -> None:
        self._locked_or_not(folder, spec, ("build.gradle", "dependencies {\n    implementation 'org.example:lib0:1.0'\n}\n"),
                            ("gradle.lockfile", "org.example:lib0:1.0=compileClasspath\n"), "gradle")

    def _pipfile(self, folder: str, spec: dict) -> None:
        self._locked_or_not(folder, spec, ("Pipfile", '[packages]\nlib0 = "*"\n'), ("Pipfile.lock", '{"default": {"lib0": {"version": "==1.0"}}}\n'), "pipenv")

    def _gemfile(self, folder: str, spec: dict) -> None:
        self._locked_or_not(folder, spec, ("Gemfile", "source 'https://rubygems.org'\ngem 'lib0'\n"),
                            ("Gemfile.lock", "GEM\n  specs:\n    lib0 (1.0)\n"), "bundler")

    def _npm(self, folder: str, spec: dict) -> None:
        if spec["variant"] == "declares-nothing":   # scripts only: whether it declares anything is never read
            self._write(f"{folder}package.json", '{"scripts": {"test": "vitest"}}\n')
            self.sca[f"{folder}package.json"] = "no_lockfile"
            return
        if spec["variant"] == "locked":
            return self._npm_lock(folder, {**spec, "utf16": False})
        self._write(f"{folder}package.json", '{"devDependencies": {"lib0": "^1.0.0"}}\n')
        if spec["variant"] == "bun-binary":   # a lockfile no engine reads
            self.files[f"{folder}bun.lockb"] = b"#!/usr/bin/env bun\nbun-lockfile-format-v0\n\x00\x02\x00lib0\x00"
        self.sca[f"{folder}package.json"] = "no_lockfile"

    def _requirements(self, folder: str, spec: dict) -> None:
        path = f"{folder}requirements.txt"
        pinned = [(name, version) for name, version in self._packages(folder, spec) if version]
        loose = [name for name, version in self._packages(folder, spec) if not version]
        lines = [f"{name}=={version}" for name, version in pinned] + [f"{name}>=1.0" if index % 2 else name for index, name in enumerate(loose)]
        self._write(path, "\n".join(["# generated", *lines]) + "\n", spec["utf16"])
        if spec["utf16"]:   # OSV-Scanner reads it and finds nothing; Trivy reads it (with its BOM)
            self.osv_unreadable[path] = "encoding"
            self.log.append(f"Scanned /src/{path} file and found 0 packages")
            self.trivy.append({"Target": path, "Class": "lang-pkgs", "Type": "pip",
                               "Packages": [{"ID": f"{name}@{version}", "Name": name, "Version": version} for name, version in pinned]})
            self.total += len(pinned)
            if loose:
                self.sca[path] = "unresolved_versions"
            return
        if pinned:
            self.trivy.append({"Target": path, "Class": "lang-pkgs", "Type": "pip",
                               "Packages": [{"ID": f"{name}@{version}", "Name": name, "Version": version} for name, version in pinned]})
            self.total += len(pinned)
        if pinned or loose:
            self.osv.append({"source": {"path": f"/src/{path}", "type": "lockfile"},
                             "packages": [{"package": {"name": name, "version": version, "ecosystem": "PyPI"}} for name, version in pinned]
                             + [{"package": {"name": name, "version": "1.0" if index % 2 else "", "ecosystem": "PyPI"}} for index, name in enumerate(loose)]})
            self.log.append(f"Scanned /src/{path} file and found {len(pinned) + len(loose)} packages")
        if loose:
            self.sca[path] = "unresolved_versions"

    def unresolved(self) -> dict[str, str]:
        """What the engines' own output left unresolved (packages without a version)."""
        return {unit: why for unit, why in self.sca.items() if why == "unresolved_versions"}

    def trivy_inventoried(self) -> set[str]:
        """The files Trivy listed a package from (not the project itself)."""
        return {item["Target"] for item in self.trivy if any(package.get("Relationship") != "root" for package in item["Packages"])}

    def snapshot(self, folder: Path) -> Path:
        snapshot = folder / "snapshot"
        snapshot.mkdir()
        for path, content in self.files.items():
            (snapshot / path).parent.mkdir(parents=True, exist_ok=True)
            (snapshot / path).write_bytes(content)
        return snapshot


def _fake(stdout: str, log: str = "", code: int = 0):
    return lambda key, arguments, snapshot=None, **options: subprocess.CompletedProcess(arguments, code, stdout, log)


class DependencyCoverageTests(unittest.TestCase):
    """F2: a package left without a resolved version, a manifest without the lockfile that resolves it and a file in an
    encoding the engine can't decode leave that manifest unexamined for the dependency scanner, and the step says so;
    every other manifest stays examined, and no package goes uncounted."""

    def run_trivy(self, snapshot: Path, payload: dict, log: str = "") -> dict:
        def fake(key, arguments, snapshot=None, **options):   # its secret scanner reads every file, and says so
            return subprocess.CompletedProcess(arguments, 0, json.dumps(payload), (log and log + "\n") + testenv.read_log("trivy", snapshot))
        with patch.object(engines, "_run", side_effect=fake), \
                patch.object(engines, "unavailable", return_value=None), patch.object(engines, "trivy_databases", return_value=[]):
            return engines.run_trivy(snapshot, snapshot.parent / "cache", {})

    def run_osv(self, snapshot: Path, payload: dict, log: str) -> dict:
        with patch.object(engines, "_run", side_effect=_fake(json.dumps(payload), log, 1)), patch.object(engines, "unavailable", return_value=None):
            return engines.run_osv_scanner(snapshot, snapshot.parent / "cache", {})

    def assert_proven(self, result: dict, units: set[str], unexamined: set[str], scanner: str = "sca", inventoried: set[str] | None = None) -> None:
        """A dependency finding from any file of a project folder is unproven when any file of that folder is
        unexamined, or when the engine inventoried no package from the file it came from (`inventoried`: deleted,
        emptied, unreadable, a manifest beside the lockfile it resolves through)."""
        record = _code_record([result])
        for unit in units:
            reason = registry.unproven_reason(record, {"tool": result["tool"], "scanner": scanner, "path": unit})
            project = {path for path in units if path.rpartition("/")[0] == unit.rpartition("/")[0]} if scanner == "sca" else {unit}
            proven = not project & unexamined and (scanner != "sca" or unit in (inventoried or set()))
            self.assertEqual(reason is None, proven, (unit, scanner, result["coverage"]))

    @settings(max_examples=60 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(dependency_folders)
    def test_trivy_leaves_unexamined_exactly_what_it_could_not_resolve_or_read(self, folders):
        repository_ = DependencyRepository(folders)
        payload = {"SchemaVersion": 2, "Results": repository_.trivy}
        with tempfile.TemporaryDirectory() as folder:
            snapshot = repository_.snapshot(Path(folder))
            result = self.run_trivy(snapshot, payload)
        self.assertEqual(result["status"], "completed")
        coverage = result["coverage"]
        self.assertEqual(coverage["examined"], "*")
        self.assertEqual(coverage["unexamined"], repository_.unreadable)
        # What the engine's own output says it couldn't resolve; a manifest without its lockfile is a folder it
        # inventoried nothing from (`dependencies`), said in the step, never decided by its package manager's name.
        self.assertEqual((coverage.get("by_scanner") or {}).get("sca", {}), repository_.unresolved())
        self.assertEqual(coverage["dependencies"]["inventoried"], sorted(repository_.trivy_inventoried()))
        # Nothing silently dropped: every package is reported with its version or counted as left without one.
        self.assertEqual(len(engines.trivy_packages(payload)) + sum(map(len, engines.trivy_unversioned(payload).values())), repository_.total)
        # The step names each manifest it couldn't examine.
        detail = text(result["detail"], "en")
        for unit in [*repository_.sca, *repository_.unreadable]:
            self.assertIn(unit, detail)
        units = set(repository_.files)
        self.assert_proven(result, units, set(repository_.sca) | set(repository_.unreadable), inventoried=repository_.trivy_inventoried())
        # Their secrets were read, but not in a file whose bytes aren't text (UTF-16 left as it is, which the snapshot
        # rewrites as UTF-8 first; a binary lockfile): `encoding`.
        binary = {path for path, data in repository_.files.items() if not encodings.readable(data)}
        self.assert_proven(result, units, set(repository_.unreadable) | binary, scanner="secrets")

    @settings(max_examples=60 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(dependency_folders)
    def test_osv_leaves_unexamined_exactly_what_it_could_not_resolve_or_read(self, folders):
        repository_ = DependencyRepository(folders)
        expected = {**{unit: why for unit, why in repository_.unresolved().items() if unit not in repository_.osv_unreadable}, **repository_.osv_unreadable}
        said = {**{unit: why for unit, why in repository_.sca.items() if unit not in repository_.osv_unreadable}, **repository_.osv_unreadable}
        with tempfile.TemporaryDirectory() as folder:
            snapshot = repository_.snapshot(Path(folder))
            result = self.run_osv(snapshot, {"results": repository_.osv}, "\n".join(["Scanning dir /src", *repository_.log]))
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["coverage"]["unexamined"], expected)
        self.assertEqual(result["coverage"]["examined"], "*")
        inventoried = {item["source"]["path"].removeprefix("/src/") for item in repository_.osv if item["packages"]}
        self.assertEqual(result["coverage"]["dependencies"]["inventoried"], sorted(inventoried))
        detail = text(result["detail"], "en")
        for unit in said:
            self.assertIn(unit, detail)
        self.assert_proven(result, set(repository_.files), set(said), inventoried=inventoried)

    def test_a_parent_pom_that_did_not_resolve_leaves_its_manifest_unexamined(self):
        """Trivy 0.75 over a Spring Boot project with `--network none` (recorded): the starter parent doesn't resolve, the
        dependencies it versions come out with no version, the exit code is 0. With the network they resolve (the same
        result with their versions): then the manifest is examined. The advisories of the dependencies pinned in the POM
        still open either way."""
        with_network = json.loads(json.dumps(TRIVY_MAVEN_OFFLINE))
        for package in with_network["Results"][0]["Packages"]:
            package.setdefault("Version", "2.5.0")
        with tempfile.TemporaryDirectory() as folder:
            snapshot = Path(folder) / "snapshot"
            snapshot.mkdir()
            (snapshot / "pom.xml").write_text("<project/>\n")
            offline = self.run_trivy(snapshot, TRIVY_MAVEN_OFFLINE, "WARN\t[pom] Dependency version cannot be determined. Child dependencies will not be found.")
            online = self.run_trivy(snapshot, with_network)
        self.assertEqual(engines.trivy_unversioned(TRIVY_MAVEN_OFFLINE),
                         {"pom.xml": ["com.fasterxml.jackson.core:jackson-databind", "org.springframework.boot:spring-boot-starter-web"]})
        self.assertEqual(len(engines.trivy_packages(TRIVY_MAVEN_OFFLINE)), 3)
        self.assertEqual(offline["coverage"]["by_scanner"], {"sca": {"pom.xml": "unresolved_versions"}})
        self.assertNotIn("by_scanner", online["coverage"])
        self.assertIn("2 dependencies in pom.xml had no resolved version", text(offline["detail"], "en"))
        self.assertIn("2 dependencias de pom.xml no tenían una versión resuelta", text(offline["detail"], "es"))
        self.assertEqual(len([item for item in offline["findings"] if item["scanner"] == "sca"]), 7)
        advisory = {"tool": "trivy", "scanner": "sca", "path": "pom.xml"}
        self.assertIsNotNone(registry.unproven_reason(_code_record([offline]), advisory))
        self.assertIsNone(registry.unproven_reason(_code_record([online]), advisory))

    def test_recorded_osv_reads_nothing_from_a_utf16_requirements_file(self):
        """OSV-Scanner 2.6's own log: it scans a UTF-16 requirements.txt and finds 0 packages, without an error."""
        with tempfile.TemporaryDirectory() as folder:
            snapshot = Path(folder) / "snapshot"
            (snapshot / "a").mkdir(parents=True)
            (snapshot / "b").mkdir()
            (snapshot / "a" / "requirements.txt").write_bytes("django==2.2.0\n".encode("utf-16"))
            (snapshot / "b" / "requirements.txt").write_text("django==2.2.0\n")
            log = "Scanning dir /src\nScanned /src/a/requirements.txt file and found 0 packages\nScanned /src/b/requirements.txt file and found 1 package\n"
            result = self.run_osv(snapshot, {"results": [{"source": {"path": "/src/b/requirements.txt", "type": "lockfile"},
                                                          "packages": [{"package": {"name": "django", "version": "2.2.0", "ecosystem": "PyPI"}}]}]}, log)
        self.assertEqual((result["coverage"]["examined"], result["coverage"]["unexamined"]), ("*", {"a/requirements.txt": "encoding"}))

    def test_osv_resolution_vouches_for_unpinned_requirements_only_when_it_succeeded(self):
        """With deps.dev allowed, OSV-Scanner resolves a requirements file's ranges to real versions; when that fails
        (OSV-Scanner 2.6's own log line) it falls back to guessing them, and the file is unexamined again."""
        payload = {"results": [{"source": {"path": "/src/requirements.txt", "type": "lockfile"},
                                "packages": [{"package": {"name": name, "version": version, "ecosystem": "PyPI"}}
                                             for name, version in (("django", "2.2.28"), ("requests", "2.32.3"))]}]}
        scanned = "Scanned /src/requirements.txt file and found 2 packages\n"
        failed = scanned + ("failed resolution for src/requirements.txt: max retries exhausted: failed after 4 attempts: rpc error: code = "
                            "Unavailable desc = dns: A record lookup error: lookup api.deps.dev: network is unreachable\n")
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "requirements.txt").write_text("django>=2.2\nrequests\n")
            for log, resolve, unexamined in ((scanned, True, {}), (failed, True, {"requirements.txt": "unresolved_versions"}),
                                             (scanned, False, {"requirements.txt": "unresolved_versions"})):
                self.assertEqual(engines.osv_coverage(payload, log, Path(folder), resolve=resolve)["unexamined"], unexamined, (log, resolve))

    def test_a_workspace_lockfile_resolves_its_members_and_only_them(self):
        files = {"package.json": '{"workspaces": ["packages/*"], "devDependencies": {"a": "1"}}', "package-lock.json": "{}",
                 "packages/a/package.json": '{"dependencies": {"b": "1"}}', "tools/package.json": '{"dependencies": {"c": "1"}}',
                 "tools/pnpm-workspace.yaml": "packages: []", "tools/pnpm-lock.yaml": "lockfileVersion: '9.0'\n", "tools/x/package.json": '{"dependencies": {"d": "1"}}',
                 "other/package.json": '{"dependencies": {"e": "1"}}', "pyproject.toml": "[tool.ruff]\nline-length = 120\n",
                 "lib/pyproject.toml": '[project]\nname = "x"\ndependencies = ["requests"]\n', "web/build.gradle": "plugins { id 'java' }\n"}
        with tempfile.TemporaryDirectory() as folder:
            for path, content in files.items():
                (Path(folder) / path).parent.mkdir(parents=True, exist_ok=True)
                (Path(folder) / path).write_text(content)
            # The root lockfile resolves packages/*, which its workspaces list, not "other/"; pnpm's resolves its folder's:
            # members, said apart. What a manifest declares is never read: one that only configures tools has no lockfile
            # either, and its project stays unexamined.
            self.assertEqual(engines.dependency_coverage.without_lockfile(Path(folder)),
                             {"lib/pyproject.toml": "no_lockfile", "other/package.json": "no_lockfile", "pyproject.toml": "no_lockfile",
                              "web/build.gradle": "no_lockfile", "packages/a/package.json": "workspace", "tools/x/package.json": "workspace"})


# --- I1: the registry against the truth -------------------------------------------------------------------------

ENGINES = ("trivy", "checkov", "opengrep", "betterleaks")   # in the order a merge prefers them as the finding's owner
FILES = ("main.tf", "app.py", "config.env")
STATES = ("completed", "completed", "completed", "inconclusive", "not_tested")  # engines mostly work, and sometimes don't
# Problems: (id, file, the engines that can see it). Some only one engine sees; some two (merged into one finding).
SOLO = tuple((f"p{index}", FILES[index % 3], (ENGINES[index % 4],)) for index in range(6))
SHARED = (("s1", "main.tf", ("trivy", "checkov")), ("s2", "config.env", ("opengrep", "betterleaks")))

NOTHING_SKIPPED = {key: set() for key in ("*", *ENGINES)}
scan_steps = st.lists(st.fixed_dictionaries({
    "present": st.sets(st.integers(0, 7)),                                         # which problems exist in the code
    "states": st.fixed_dictionaries({engine: st.sampled_from(STATES) for engine in ENGINES}),
    "unexamined": st.fixed_dictionaries({key: st.sets(st.sampled_from(FILES), max_size=1) for key in ("*", *ENGINES)}),
}), min_size=2, max_size=6)


class RegistryTruth:
    """Runs scans built from which problems exist and which engines looked, as the scanners would report them: each
    seen problem is one finding, owned (and keyed) by the first engine that saw it, the others noted on it."""

    def __init__(self, test, data_dir: Path, problems):
        self.test, self.data_dir, self.problems = test, data_dir, problems
        self.key = f"github#{abs(hash((id(test), datetime.now().isoformat()))) % 10**9}"
        self.clock = datetime.now(timezone.utc)

    def scan(self, step) -> set[str]:
        present = {self.problems[index % len(self.problems)][0] for index in step["present"]}
        states, unexamined = step["states"], step["unexamined"]
        findings = []
        for problem, path, seers in self.problems:
            if problem not in present:
                continue
            looked = [engine for engine in seers if states[engine] == "completed"
                      and path not in unexamined["*"] and path not in unexamined[engine]]
            if looked:
                reports = [{"finding_id": f"{engine}-{problem}"[:16], "fingerprint": f"{engine}:{problem}", "scanner": "iac", "tool": engine,
                            "rule_id": problem, "title": problem, "path": path, "line": 1, "severity": "high", "confidence": 8,
                            "verdict": "candidate", "cwe": [], "owasp": [], "priority": {"action": "attend", "factors": []}, "reason": "", "remediation": ""}
                           for engine in looked]
                for other in reports[1:]:  # folded as every merge of two engines' reports does (scanning/folding.py)
                    absorbed(reports[0], other)
                findings.append(reports[0])
        self.clock += timedelta(hours=1)
        complete = all(state == "completed" for state in states.values())
        record = {"type": "repository_scan", "status": "completed" if complete else "incomplete",
                  "source": {"id": "github:org/api", "uid": self.key, "name": "org/api", "provider": "github", "sha256": "x"},
                  "target": "org/api", "variant": "code", "context": "", "steps": [], "findings": findings, "owasp_coverage": [],
                  "summary": {"files": 3, "dependencies": 0, "candidates": len(findings), "severities": {}, "priorities": {}, "kev": 0,
                              "fixable": 0, "tools": [{"name": engine, "version": "1", "status": state} for engine, state in states.items()]},
                  "limitations": [], "scanned_at": self.clock.isoformat(), "finished_at": self.clock.isoformat(),
                  "unexamined": {key: sorted(paths) for key, paths in unexamined.items() if paths},
                  # The same, as each engine declares it under the engine contract (PITANGUS_COVERAGE_MODE=on).
                  "coverage": {engine: {"examined": "*", "unexamined": dict.fromkeys(unexamined["*"] | unexamined[engine], "not_read")}
                               for engine in ENGINES if states[engine] == "completed"}}
        save_repository_scan(self.data_dir, record, created_at=self.clock.isoformat())
        return present

    def statuses(self) -> dict[str, str]:
        return {digest: entry["status"] for digest, entry in registry.load(self.data_dir, self.key)["findings"].items()}

    def falsely_fixed(self, before: dict[str, str], present: set[str]) -> list[str]:
        """What this scan marked fixed although its problem is still in the code. (A problem fixed earlier that comes
        back where no engine looks stays fixed until someone sees it: that's unseen, not a false fix.)"""
        entries = registry.load(self.data_dir, self.key)["findings"]
        # The problem is the finding's rule: its key is the owner's fingerprint, or in v2 the problem's identity.
        return sorted(digest for digest, entry in entries.items()
                      if entry["status"] == "fixed" and before.get(digest) != "fixed" and entry["finding"]["rule_id"] in present)


class RegistryTruthTests(unittest.TestCase):
    """I1: whatever happens to the engines, the registry never marks fixed a problem that still exists."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def check(self, problems, steps):
        truth = RegistryTruth(self, Path(self.directory.name), problems)
        for step in steps:
            before = truth.statuses()
            present = truth.scan(step)
            self.assertEqual(truth.falsely_fixed(before, present), [], step)

    @settings(max_examples=60 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(scan_steps)
    def test_a_problem_one_engine_owns_is_only_fixed_once_that_engine_looked_and_it_was_gone(self, steps):
        self.check(SOLO, steps)

    @settings(max_examples=60 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(scan_steps)
    def test_the_same_with_the_coverage_contract_on(self, steps):
        with patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "on", "PITANGUS_FIX_HOLD_MINIMUM": "1000"}):
            self.check(SOLO, steps)

    @settings(max_examples=60 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(scan_steps, st.sampled_from(["v1", "shadow"]))
    def test_the_same_with_the_rules_before_the_contract_and_engine_fingerprints(self, steps, identity):
        """The modes an operator can still choose: PITANGUS_COVERAGE_MODE=shadow, with the engines' fingerprints."""
        with patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "shadow", "PITANGUS_IDENTITY_MODE": identity}):
            self.check(SOLO + SHARED, steps)

    @settings(max_examples=60 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(scan_steps)
    @example([{"present": {6}, "states": dict.fromkeys(ENGINES, "completed"), "unexamined": NOTHING_SKIPPED},
              {"present": {6}, "states": {**dict.fromkeys(ENGINES, "completed"), "trivy": "inconclusive"}, "unexamined": NOTHING_SKIPPED},
              {"present": {6}, "states": dict.fromkeys(ENGINES, "completed"), "unexamined": NOTHING_SKIPPED}])
    def test_a_problem_two_engines_see_survives_its_owner_failing_and_coming_back(self, steps):
        """Trivy down: Checkov reports it under its own key; Trivy back: Checkov's key is among the folded finding's
        former names, so its entry moves instead of being marked fixed."""
        self.check(SOLO + SHARED, steps)

    def test_every_merge_of_two_engines_keeps_the_folded_fingerprint(self):
        """What the model above assumes, for each real merge: the folded report's fingerprint survives on the kept one."""
        # The same secret: both engines read one value, so both carry its identity (scanning/secret_identity.py).
        secret = {"scanner": "secrets", "path": "config.js", "line": 3, "severity": "critical", "rule_id": "github-pat", "identity": "i" * 64}
        kept = engines.merge_secrets([{**secret, "tool": "betterleaks", "fingerprint": "g"}], [{**secret, "tool": "trivy", "fingerprint": "t"}])
        self.assertEqual((len(kept), kept[0]["previous_fingerprints"]), (1, ["t"]))
        package = {"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}
        dependency = {"scanner": "sca", "rule_id": "CVE-2021-23337", "cve": ["CVE-2021-23337"], "path": "package-lock.json", "line": 1}
        merged, _ = merge_dependencies([{**dependency, "tool": "trivy", "fingerprint": "a", "package": dict(package)}],
                                       ("osv-scanner", [{**dependency, "tool": "osv-scanner", "fingerprint": "b", "package": dict(package)}]))
        self.assertEqual((len(merged), merged[0]["previous_fingerprints"]), (1, ["b"]))
        iac = {"scanner": "iac", "path": "main.tf", "line": 4, "end_line": 9, "severity": "high", "confidence": 7, "title": "S3 bucket public"}
        folded, _ = config_engines.merge_equivalent([{**iac, "tool": "trivy", "rule_id": "AVD-AWS-0086", "fingerprint": "x"}],
                                                    [{**iac, "tool": "checkov", "rule_id": "CKV_AWS_53", "fingerprint": "y"}],
                                                    {"AVD-AWS-0086": ("CKV_AWS_53",)})
        self.assertEqual((len(folded), folded[0]["previous_fingerprints"]), (1, ["y"]))



# --- I3 / I4: identity ------------------------------------------------------------------------------------------

def opengrep_report(lines: list[tuple[int, str]], path: str = "app.py") -> dict:
    """What Opengrep reports for these (line, code) matches of one rule."""
    return {"results": [{"check_id": "rules.appsec.py.shell-command-non-literal", "path": f"/src/{path}", "start": {"line": line},
                         "extra": {"lines": code, "severity": "ERROR", "metadata": {}}} for line, code in lines]}


snippets = st.lists(st.sampled_from(["os.system(cmd)", "subprocess.run(cmd, shell=True)", "eval(data)", "os.popen(name)"]),
                    min_size=1, max_size=6)


class CodeIdentityTests(unittest.TestCase):
    @settings(max_examples=200 * SCALE, deadline=None)
    @given(snippets, st.integers(0, 6), st.integers(1, 20))
    def test_lines_added_above_change_no_identity(self, codes, at, added):
        before = opengrep_report([(10 + index * 3, code) for index, code in enumerate(codes)])
        after = opengrep_report([(10 + index * 3 + (added if index >= at else 0), code) for index, code in enumerate(codes)])
        self.assertEqual(sorted(item["fingerprint"] for item in engines.parse_opengrep(before)),
                         sorted(item["fingerprint"] for item in engines.parse_opengrep(after)))

    @settings(max_examples=200 * SCALE, deadline=None)
    @given(snippets, st.data())
    def test_a_copy_adds_exactly_one_instance_and_deleting_one_removes_exactly_one(self, codes, data):
        lines = [(10 + index * 3, code) for index, code in enumerate(codes)]
        base = family_counts(engines.parse_opengrep(opengrep_report(lines)))
        copied = data.draw(st.sampled_from(lines))
        with_copy = family_counts(engines.parse_opengrep(opengrep_report(lines + [(200, copied[1])])))
        family = engines._stable("sast", "appsec.py.shell-command-non-literal", "app.py", copied[1])
        self.assertEqual(with_copy - base, {family: 1})
        dropped = data.draw(st.sampled_from(lines))
        without = family_counts(engines.parse_opengrep(opengrep_report([line for line in lines if line != dropped])))
        self.assertEqual(base - without, {engines._stable("sast", "appsec.py.shell-command-non-literal", "app.py", dropped[1]): 1})

    @settings(max_examples=100 * SCALE, deadline=None)
    @given(snippets, st.randoms(use_true_random=False))
    def test_the_order_engines_list_results_in_changes_nothing(self, codes, random):
        lines = [(10 + index * 3, code) for index, code in enumerate(codes)]
        shuffled = list(lines)
        random.shuffle(shuffled)
        self.assertEqual({item["fingerprint"]: item["line"] for item in engines.parse_opengrep(opengrep_report(lines))},
                         {item["fingerprint"]: item["line"] for item in engines.parse_opengrep(opengrep_report(shuffled))})

    def test_an_infrastructure_finding_is_its_resource_not_its_line(self):
        def trivy(resource_line, k8s=()):
            misconfigurations = [{"ID": "AVD-AWS-0086", "AVDID": "AVD-AWS-0086", "Title": "S3 public access", "Severity": "HIGH",
                                  "CauseMetadata": {"Resource": f"template.yaml:{resource_line}", "Provider": "AWS", "StartLine": resource_line}}]
            k8s_entries = [{"ID": "KSV012", "AVDID": "AVD-KSV-0012", "Title": "Runs as root", "Severity": "MEDIUM",
                            "CauseMetadata": {"Provider": "Kubernetes", "StartLine": line}} for line in k8s]
            return engines.parse_trivy({"Results": [{"Target": "template.yaml", "Class": "config", "Type": "cloudformation",
                                                     "Misconfigurations": misconfigurations},
                                                    {"Target": "deploy.yaml", "Class": "config", "Type": "kubernetes",
                                                     "Misconfigurations": k8s_entries}]}, {})
        # Trivy gives a position, not an address, for this template: the identity is the rule in the file, never the line.
        moved = [canonical.identity_of(item) for item in trivy(12) if item["path"] == "template.yaml"]
        self.assertEqual(moved, [canonical.identity_of(item) for item in trivy(14) if item["path"] == "template.yaml"])  # two comments above
        # Two Deployments without an address: one family with two instances, never one problem hiding the other.
        deployments = [item for item in canonical.collapse(trivy(12, k8s=(5, 40))) if item["path"] == "deploy.yaml"]
        self.assertEqual([item["count"] for item in deployments], [2])
        # With an address, each resource is its own.
        addressed = engines.parse_trivy({"Results": [{"Target": "main.tf", "Class": "config", "Type": "terraform", "Misconfigurations": [
            {"ID": "AVD-AWS-0086", "AVDID": "AVD-AWS-0086", "Title": "S3", "Severity": "HIGH",
             "CauseMetadata": {"Resource": name, "Provider": "AWS", "StartLine": line}} for name, line in (("aws_s3_bucket.a", 3), ("aws_s3_bucket.b", 30))]}]}, {})
        self.assertEqual(len({canonical.identity_of(item) for item in addressed}), 2)


class CanonicalTests(unittest.TestCase):
    """I3/I4/I6 on the canonical identity (findings/canonical.py), the same for every engine."""

    @settings(max_examples=200 * SCALE, deadline=None)
    @given(snippets, st.sampled_from(["  ", "\t", " \n    "]), st.sampled_from(["# nosemgrep", "# noqa: S102", "# TODO: check"]))
    def test_reformatting_or_commenting_code_changes_no_identity(self, codes, space, comment):
        code = codes[0]
        spaced = code.replace("(", f"({space}").replace(")", f"{space})").replace(", ", f",{space}")
        plain = canonical.identity_of(engines.parse_opengrep(opengrep_report([(4, code)]))[0])
        self.assertEqual(canonical.identity_of(engines.parse_opengrep(opengrep_report([(9, f"{spaced}  {comment}")]))[0]), plain)

    @settings(max_examples=200 * SCALE, deadline=None)
    @given(snippets, st.integers(1, 5))
    def test_a_family_counts_its_copies(self, codes, copies):
        lines = [(10 + index * 3, code) for index, code in enumerate(codes)] + [(500 + index, codes[0]) for index in range(copies)]
        families = {item["snippet"]: item["count"] for item in canonical.collapse(engines.parse_opengrep(opengrep_report(lines)))}
        self.assertEqual(families[codes[0]], codes.count(codes[0]) + copies)
        self.assertEqual(sum(families.values()), len({line for line, _ in lines}))

    @settings(max_examples=100 * SCALE, deadline=None)
    @given(snippets, st.randoms(use_true_random=False))
    def test_grouping_depends_on_the_findings_never_on_their_order(self, codes, random):
        findings = engines.parse_opengrep(opengrep_report([(10 + index * 3, code) for index, code in enumerate(codes)]))
        shuffled = list(findings)
        random.shuffle(shuffled)
        def families(items):
            return sorted((item["fingerprint"], item["count"], sorted(item.get("previous_fingerprints") or [])) for item in canonical.collapse(items))
        self.assertEqual(families(findings), families(shuffled))

    def test_a_secret_is_the_same_whichever_engine_found_it_and_its_value_never_shows(self):
        token, other = "ghp_" + "A1b2C3d4" * 4 + "Zz", "ghp_" + "Q9w8E7r6" * 4 + "Yy"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            content = f'x = 1\nGITHUB_TOKEN = "{token}"\nOTHER = "{other}"\n'
            (root / "config.py").write_text(content)

            def betterleaks(value, line):
                start = content.splitlines()[line - 1].index(value)
                return {"RuleID": "github-pat", "File": "/src/config.py", "StartLine": line, "EndLine": line,
                        "StartColumn": start + 1, "EndColumn": start + len(value), "Match": "REDACTED", "Entropy": entropy(value)}

            def trivy(value, line):
                text = content.splitlines()[line - 1]
                start = text.index(value)
                return {"RuleID": "github-pat", "Category": "GitHub", "Severity": "CRITICAL", "Title": "GitHub PAT", "StartLine": line,
                        "EndLine": line, "Match": text[:start] + "*" * len(value) + text[start + len(value):], "Offset": content.index(value)}

            found = engines.parse_betterleaks([betterleaks(token, 2), betterleaks(other, 3)], root=root)
            seen = engines.parse_trivy({"Results": [{"Target": "config.py", "Class": "secret", "Secrets": [trivy(token, 2), trivy(other, 3)]}]}, {}, root=root)
            self.assertEqual([item["identity"] for item in found], [item["identity"] for item in seen])
            self.assertNotEqual(found[0]["identity"], found[1]["identity"])
            self.assertTrue(all(token not in json.dumps(item) and other not in json.dumps(item) for item in [*found, *seen]))
            # The file changed under Trivy's offset: the value is read only where its masked line fits, never another's.
            (root / "config.py").write_text(content.replace("x = 1", "x = 12"))
            moved = engines.parse_trivy({"Results": [{"Target": "config.py", "Class": "secret", "Secrets": [trivy(token, 2)]}]}, {}, root=root)
            self.assertEqual(moved[0]["identity"], secret_identity.identity(token))
            (root / "config.py").write_text(content.replace(token, other))
            moved = engines.parse_trivy({"Results": [{"Target": "config.py", "Class": "secret", "Secrets": [trivy(token, 2)]}]}, {}, root=root)
            self.assertNotEqual(moved[0]["identity"], secret_identity.identity(token))

    def test_rotating_the_master_key_gives_every_secret_a_new_identity_with_the_new_key_id(self):
        import base64
        identities = []
        for byte in (b"\x01", b"\x02"):
            with patch.dict(os.environ, {"PITANGUS_MASTER_KEY": base64.b64encode(byte * 32).decode()}):
                secret_identity._key.cache_clear()
                identities.append(secret_identity.identity("ghp_value"))
        secret_identity._key.cache_clear()
        self.assertNotEqual(identities[0][:8], identities[1][:8])
        self.assertNotEqual(identities[0], identities[1])


# How bundlers name what they build: the same file, rebuilt, gets another hash.
HASHES = {
    "vite": st.text("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", min_size=8, max_size=8),
    "next": st.text("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", min_size=21, max_size=21),
    "esbuild": st.text("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", min_size=8, max_size=8),
    "webpack": st.text("0123456789abcdef", min_size=20, max_size=20),
    "angular": st.text("0123456789abcdef", min_size=16, max_size=16),
}
BUILT = {"vite": "https://h/assets/index-{}.js", "esbuild": "https://h/static/chunk-{}.js", "webpack": "https://h/js/app.{}.js",
         "angular": "https://h/main.{}.js", "next": "https://h/_next/static/{}/_buildManifest.js"}


class WebIdentityTests(unittest.TestCase):
    @staticmethod
    def web(url):
        return {"fingerprint": url, "scanner": "dast", "tool": "zap", "rule_id": "10098", "path": url, "line": 1, "severity": "low"}

    @settings(max_examples=300 * SCALE, deadline=None)
    @given(st.sampled_from(sorted(BUILT)), st.data())
    def test_a_rebuilt_asset_keeps_its_identity(self, bundler, data):
        """Before and after a deploy (the asset's earlier URL known to the registry): one family, one instance each
        time. The template comes from the two URLs, never from guessing which characters look like a hash."""
        alphabet = HASHES.get(bundler, HASHES["vite"])
        first, second = BUILT[bundler].format(data.draw(alphabet)), BUILT[bundler].format(data.draw(alphabet))
        before = canonical.collapse([self.web(first)], known_urls=[second])
        after = canonical.collapse([self.web(second)], known_urls=[first])
        self.assertEqual([(item["fingerprint"], item["count"]) for item in before], [(item["fingerprint"], item["count"]) for item in after])

    def test_different_documents_never_share_an_instance(self):
        """Two documents of one template are one family with two instances: counted, never collapsed into one."""
        for template, first, second in (("https://h/users/{}.html", "9f3c2a71", "4b8d0e52"), ("https://h/invoices/INV-{}.pdf", "a1b2c3d4", "e5f60718")):
            with self.subTest(template=template):
                urls = [template.format(first), template.format(second)]
                (family,) = canonical.collapse([self.web(url) for url in urls])
                self.assertEqual((family["count"], [item["path"] for item in family["instances"]]), (2, urls))

    @settings(max_examples=100 * SCALE, deadline=None)
    @given(st.lists(st.sampled_from(["https://h/a/x-1.js", "https://h/a/x-2.js", "https://h/b", "https://h/users/7.html",
                                     "https://h/users/8.html", "https://h/c/d/e"]), min_size=1, max_size=6, unique=True),
           st.randoms(use_true_random=False))
    def test_templates_depend_on_the_urls_never_on_their_order(self, urls, random):
        shuffled = list(urls)
        random.shuffle(shuffled)
        self.assertEqual(canonical.web_templates(urls), canonical.web_templates(shuffled))


# --- I5: merging never loses ----------------------------------------------------------------------------------------

class MergeTests(unittest.TestCase):
    def test_two_different_secrets_on_one_line_stay_two(self):
        base = {"scanner": "secrets", "path": "config.js", "line": 3, "severity": "critical"}
        betterleaks = {**base, "tool": "betterleaks", "rule_id": "generic-api-key", "fingerprint": "g"}
        trivy = {**base, "tool": "trivy", "rule_id": "twilio-api-key", "fingerprint": "t"}
        # Different values: their identities differ, and they stay two in every mode.
        self.assertEqual(len(engines.merge_secrets([{**betterleaks, "identity": "1" * 64}], [{**trivy, "identity": "2" * 64}])), 2)
        # Without identities, v2 joins nothing by guess.
        with patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": "v2"}):
            self.assertEqual(len(engines.merge_secrets([betterleaks], [trivy])), 2)
        # The same value: one finding, the other engine noted, whatever rule each engine named it by.
        self.assertEqual(len(engines.merge_secrets([{**betterleaks, "identity": "1" * 64}], [{**trivy, "identity": "1" * 64}])), 1)

    def test_the_same_go_advisory_from_two_engines_is_one_finding(self):
        trivy = engines.parse_trivy({"Results": [{"Target": "go.mod", "Class": "lang-pkgs", "Type": "gomod", "Vulnerabilities": [
            {"VulnerabilityID": "GHSA-xxxx-yyyy-zzzz", "PkgName": "golang.org/x/net", "InstalledVersion": "v0.3.7", "FixedVersion": "v0.7.0",
             "Severity": "HIGH"}]}]}, {})
        osv = engines.parse_osv_scanner({"results": [{"source": {"path": "/src/go.mod"}, "packages": [{
            "package": {"name": "golang.org/x/net", "version": "0.3.7", "ecosystem": "Go"},
            "vulnerabilities": [{"id": "GHSA-xxxx-yyyy-zzzz", "aliases": [], "summary": "x", "affected": []}],
            "groups": [{"ids": ["GHSA-xxxx-yyyy-zzzz"]}]}]}]}, {})
        merged, _ = merge_dependencies(trivy, ("osv-scanner", osv))
        self.assertEqual(len(merged), 1)
        self.assertEqual(canonical.identity_of(trivy[0]), canonical.identity_of(osv[0]))



# --- I7: upgrades change nothing ------------------------------------------------------------------------------------

UPGRADE_SNIPPETS = ["eval(data)", "os.system(cmd)", "subprocess.run(cmd, shell=True)"]
commits = st.fixed_dictionaries({
    "code": st.lists(st.tuples(st.integers(1, 400), st.sampled_from(UPGRADE_SNIPPETS)), max_size=8, unique_by=lambda item: item[0]),
    "secrets": st.lists(st.tuples(st.integers(1, 60), st.booleans()), max_size=4, unique_by=lambda item: item[0]),
    "deps": st.lists(st.tuples(st.sampled_from(["golang.org/x/net", "github.com/gin-gonic/gin"]), st.sampled_from(["v0.3.7", "v1.9.0"])),
                     max_size=2, unique=True),
    "iac": st.lists(st.tuples(st.integers(1, 90), st.booleans()), max_size=3, unique_by=lambda item: item[0]),
    "excluded": st.sets(st.sampled_from(["app.py", "config.py", "go.mod", "main.tf"]), max_size=2),   # excluded paths
})


def upgrade_findings(commit, random) -> tuple[list[dict], list[dict]]:
    """What the engines report for `commit`, as their adapters write it, in a random order: (findings, excluded)."""
    found = engines.parse_opengrep(opengrep_report(commit["code"]))
    for line, has_identity in commit["secrets"]:
        digest = engines._stable("secrets", "github-pat", "config.py", str(line))
        found.append({"finding_id": digest[:16], "fingerprint": digest, "scanner": "secrets", "tool": "betterleaks", "rule_id": "github-pat",
                      "title": "GitHub token", "path": "config.py", "line": line, "severity": "critical", "confidence": 8, "verdict": "candidate",
                      "cwe": [798], "owasp": ["A04:2025"], "priority": {"action": "act", "factors": []}, "reason": "", "remediation": "",
                      **({"identity": f"{line:064x}"} if has_identity else {})})
    found += engines.parse_trivy({"Results": [
        {"Target": "go.mod", "Class": "lang-pkgs", "Type": "gomod", "Vulnerabilities": [
            {"VulnerabilityID": "GHSA-xxxx-yyyy-zzzz", "PkgName": name, "InstalledVersion": version, "FixedVersion": "v9.0.0", "Severity": "HIGH"}
            for name, version in commit["deps"]]},
        {"Target": "main.tf", "Class": "config", "Type": "terraform", "Misconfigurations": [
            {"ID": "AVD-AWS-0086", "AVDID": "AVD-AWS-0086", "Title": "S3 public", "Severity": "HIGH",
             "CauseMetadata": {"Resource": f"aws_s3_bucket.b{line}" if addressed else "", "Provider": "AWS", "StartLine": line}}
            for line, addressed in commit["iac"]]}]}, {})
    random.shuffle(found)
    # Exclusions go by path, as an administrator's excluded paths do: every copy in an excluded file is excluded.
    excluded = [{**finding, "excluded_by": finding["path"], "excluded_reason": "Vulnerable on purpose"} for finding in found if finding["path"] in commit["excluded"]]
    return [finding for finding in found if finding["path"] not in commit["excluded"]], excluded


class UpgradeTests(unittest.TestCase):
    """I7, against the registry in PostgreSQL: v1 → shadow → v2 → v2 on the same commit, findings in any order."""

    def setUp(self):
        # One database schema for the whole property (PITANGUS_DB_ISOLATE=data-dir): each example is an asset of its own.
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.examples = 0

    @settings(max_examples=12 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    @given(commits, st.randoms(use_true_random=False))
    def test_the_same_commit_opens_and_fixes_nothing_whatever_the_identity_version(self, commit, random):
        from pitangus.modules.findings import triage
        from pitangus.modules.runs.store import save_and_apply
        self.examples += 1
        data_dir, clock, key = Path(self.directory.name), datetime.now(timezone.utc), f"github#{self.examples}-{abs(hash(str(commit))) % 10**8}"

        def scan(mode):
            nonlocal clock
            clock += timedelta(hours=1)
            findings, excluded = upgrade_findings(commit, random)
            record = {"type": "repository_scan", "status": "completed", "target": "org/api", "variant": "code", "context": "", "steps": [],
                      "source": {"id": "github:org/api", "uid": key, "name": "org/api", "provider": "github", "sha256": "x"},
                      "findings": findings, "excluded_findings": excluded, "owasp_coverage": [], "limitations": [],
                      "summary": {"files": 1, "dependencies": 0, "candidates": len(findings), "severities": {}, "priorities": {}, "kev": 0, "fixable": 0,
                                  "tools": [{"name": tool, "version": "1", "status": "completed"} for tool in ("opengrep", "betterleaks", "trivy")]},
                      "scanned_at": clock.isoformat(), "finished_at": clock.isoformat()}
            with patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": mode}):
                return save_and_apply(data_dir, record, created_at=clock.isoformat())

        first, _ = scan("v1")
        decided = first["findings"][0]["fingerprint"] if first["findings"] else None
        if decided:
            triage.decide(data_dir, first, [decided], "false_positive", reason="Sandboxed on purpose in this test", user={"username": "ana", "role": "admin"})
        for mode in ("v1", "shadow", "v2", "v2"):
            saved, changes = scan(mode)
            self.assertEqual((changes.get("new") or [], changes.get("fixed_now") or []), ([], []), (mode, commit))
            entries = registry.load(data_dir, key)["findings"]
            self.assertNotIn("fixed", {entry["status"] for entry in entries.values()}, mode)
            for finding in saved.get("excluded_findings") or []:
                self.assertEqual(entries[finding["fingerprint"]]["status"], "excluded", mode)
        if decided:  # the triage followed the finding to its family; unreviewed copies folded in with it leave it for review
            family = next(finding for finding in saved["findings"] + (saved.get("excluded_findings") or [])
                          if finding["fingerprint"] == decided or decided in (finding.get("previous_fingerprints") or []))
            v1 = {finding["fingerprint"] for finding in first["findings"] + (first.get("excluded_findings") or [])}
            copies = v1 & {family["fingerprint"], *(family.get("previous_fingerprints") or [])}
            self.assertEqual(triage.load(data_dir)[key][family["fingerprint"]]["status"], "false_positive" if copies == {decided} else "open")


class SecretFormulaUpgradeTests(unittest.TestCase):
    """I7 when a secret's identity formula changes (its value's span instead of Betterleaks' whole match, which held the
    key and the quotes): the values are never stored, so the first scan after upgrading computes the formula before next
    to the current one and records it as a former name. Entries stored under the earlier identities (v2) or under the
    engines' fingerprints (v1), with acceptances that expire and Jira issues, move to the value's identity: nothing opens,
    nothing is fixed, each family keeps the triage its copies agreed on (`triage.fold`) and every issue."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.examples = 0

    @settings(max_examples=10 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    @given(secrets=st.lists(st.tuples(TOKENS, st.lists(placements, min_size=1, max_size=3)), min_size=1, max_size=3, unique_by=lambda item: item[0]),
           stored=st.sampled_from(["v1", "v2"]), data=st.data())
    def test_the_first_scan_after_the_formula_changed_moves_every_entry_with_its_triage_and_issues(self, secrets, stored, data):
        from datetime import date
        from pitangus.modules.findings import tickets, triage
        from pitangus.modules.runs.store import save_and_apply
        self.examples += 1
        data_dir, clock = Path(self.directory.name), datetime.now(timezone.utc)
        key = f"github#f3-{self.examples}-{abs(hash(str(secrets))) % 10**8}"
        root = data_dir / f"snapshot-{self.examples}"
        root.mkdir()
        entries, trivy = report(root, [(value, placement) for value, where in secrets for placement in where])
        current = engines._betterleaks_identities

        def earlier(*args):  # the code before: the whole match's identity, no former name
            from pitangus.modules.scanning import secret_identity
            return secret_identity.Names(current(*args)[1], []) if current(*args)[1] else None, None

        def scan(mode, formula):
            nonlocal clock
            clock += timedelta(hours=1)
            with patch.object(engines, "_betterleaks_identities", side_effect=formula):
                findings = engines.merge_secrets(engines.parse_betterleaks(entries, None, root), engines.parse_trivy(trivy, {}, root=root))
            record = {"type": "repository_scan", "status": "completed", "target": "org/api", "variant": "code", "context": "", "steps": [],
                      "source": {"id": "github:org/api", "uid": key, "name": "org/api", "provider": "github", "sha256": "x"},
                      "findings": findings, "excluded_findings": [], "owasp_coverage": [], "limitations": [],
                      "summary": {"files": 1, "dependencies": 0, "candidates": len(findings), "severities": {}, "priorities": {}, "kev": 0, "fixable": 0,
                                  "tools": [{"name": tool, "version": "1", "status": "completed"} for tool in ("betterleaks", "trivy")]},
                      "scanned_at": clock.isoformat(), "finished_at": clock.isoformat()}
            with patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": mode}):
                return save_and_apply(data_dir, record, created_at=clock.isoformat())

        def triage_some(saved):
            fingerprints = [item["fingerprint"] for item in saved["findings"]]
            for index, digest in enumerate(fingerprints):
                if data.draw(st.booleans(), label=f"accept {index}"):
                    expiry = (date.today() + timedelta(days=data.draw(st.integers(5, 80), label="days"))).isoformat()
                    triage.decide(data_dir, saved, [digest], "accepted", reason="Rotation planned with the provider", expires_at=expiry, user={"username": "ana", "role": "admin"})
                if data.draw(st.booleans(), label=f"link {index}"):
                    tickets.remember(data_dir, key, digest, {"key": f"SEC-{self.examples}{index}{len(saved['id'])}", "url": "https://jira.example/browse/SEC",
                                                             "linked_at": clock.isoformat()})

        saved, _ = scan("v1", earlier)
        triage_some(saved)
        if stored == "v2":
            saved, changes = scan("v2", earlier)
            self.assertEqual((changes["new"], changes["fixed_now"]), ([], []))
            triage_some(saved)
        before = registry.load(data_dir, key)["findings"]
        decisions, links = triage.load_asset(data_dir, key), tickets.load_links(data_dir).get(key, {})

        saved, changes = scan("v2", current)
        self.assertEqual((changes["new"], changes["fixed_now"]), ([], []), stored)
        after = registry.load(data_dir, key)["findings"]
        self.assertEqual(set(after), {item["fingerprint"] for item in saved["findings"]})
        self.assertEqual({entry["status"] for entry in after.values()}, {"open"})
        self.assertEqual(len(after), len(secrets))                 # one family per value, whatever the formats and engines
        now_decisions, now_links = triage.load_asset(data_dir, key), tickets.load_links(data_dir).get(key, {})
        claimed: set[str] = set()
        for family in saved["findings"]:
            names = {family["fingerprint"], *(family.get("previous_fingerprints") or []), *(family.get("value_formers") or [])}
            # An entry is the family's by its own name or by a name both carried (registry._rekey).
            copies = sorted(digest for digest, entry in before.items() if digest in names or set(formers(entry.get("finding") or {})) & names)
            claimed.update(copies)
            decided = [decisions[digest] for digest in copies if digest in decisions]
            statuses = {item["status"] for item in decided}
            expected = None if not decided else statuses.pop() if len(decided) == len(copies) and len(statuses) == 1 else "open"
            self.assertEqual((now_decisions.get(family["fingerprint"]) or {}).get("status"), expected, (stored, copies))
            if expected == "accepted":
                self.assertEqual(now_decisions[family["fingerprint"]]["expires_at"], min(item["expires_at"] for item in decided))
            issues = {issue["key"] for digest in copies if digest in links for issue in tickets._issues(links[digest])}
            self.assertLessEqual(issues, {issue["key"] for issue in tickets._issues(now_links[family["fingerprint"]])} if issues else set())
        self.assertEqual(claimed, set(before))                    # no stored entry left behind to look fixed later
        saved, changes = scan("v2", current)
        self.assertEqual((changes["new"], changes["fixed_now"]), ([], []))


# --- I8: configuration never fixes ----------------------------------------------------------------------------------

# Rules of each kind: the secret engine's built-in ones (some opt-in), a custom one, our Opengrep rules, a third-party one
# and an optional engine's.
BUILTIN, OPT_IN = ("github-pat", "generic-api-key"), tuple(OPT_IN_RULES)
FILTERED = ("generic-password",)  # built-in, on by default since 0.14 behind the secret filter (scanning/secret_filter)
CUSTOM = secret_rules.engine_id("internal-token")
OWN = tuple(sorted(rule_set.own_rules())[:3])
THIRD = "gitlab.python.exec.python_exec_rule-subprocess-popen-shell-true"
RULES = (*[("betterleaks", rule) for rule in (*BUILTIN, *OPT_IN, CUSTOM)], *[("opengrep", rule) for rule in (*OWN, THIRD)], ("checkov", "CKV_AWS_20"))
PATHS = ("app.py", "config/settings.py", "tests/fixture.py")
SCANNER = {"betterleaks": "secrets", "opengrep": "sast", "checkov": "iac"}

configurations = st.fixed_dictionaries({
    "enabled": st.sets(st.sampled_from(OPT_IN)),            # opt-in rules turned on
    "custom": st.sampled_from([None, "tok_[a-z]{8}", "tok_[a-z0-9]{12}"]),   # the custom rule: absent, or its regex
    "disabled": st.sets(st.sampled_from(BUILTIN)),          # built-in rules turned off
    "allowed": st.sets(st.sampled_from(PATHS), max_size=2),  # allowlisted paths
    "checkov": st.booleans(), "third_party": st.booleans(),
    "changed": st.sets(st.sampled_from(OWN)),               # our rules at another definition
    "filters": st.sampled_from(["1", "2"]),                 # how Pitangus filters the built-in secret rules
})
codes = st.lists(st.tuples(st.sampled_from(RULES), st.sampled_from(PATHS)), min_size=1, max_size=12, unique=True)


class ConfiguredScanner:
    """Scans code (a list of ((engine, rule), path) problems) under a configuration as the engines do: an engine off or a
    rule that doesn't run reports nothing; a rule at another definition than the one the problem was written against
    (the first configuration's) no longer matches; what the allowlist or a disabled rule filters, only the unfiltered
    reference run sees, and it is recorded as excluded (secret_rules.withheld). Each run declares its configuration
    through scanning/rule_set, as a real scan does."""

    def __init__(self, data_dir: Path, key: str, first: dict):
        self.data_dir, self.key, self.first, self.clock = data_dir, key, first, datetime.now(timezone.utc)

    @staticmethod
    def settings(config: dict) -> dict:
        return {"allowlist": {"paths": sorted(config["allowed"]), "regexes": [], "stopwords": []}, "disabled_rules": sorted(config["disabled"]),
                "enabled_rules": sorted(config["enabled"]), "origins": {},
                "rules": [{"id": "internal-token", "description": "Internal token", "regex": config["custom"], "keywords": []}] if config["custom"] else []}

    @staticmethod
    def on(config: dict, engine: str) -> bool:
        return engine != "checkov" or config["checkov"]

    @staticmethod
    def runs(config: dict, engine: str, rule: str) -> bool:
        return (rule in config["enabled"] if rule in OPT_IN else bool(config["custom"]) if rule == CUSTOM
                else config["third_party"] if rule == THIRD else True) if ConfiguredScanner.on(config, engine) else False

    def unchanged(self, config: dict, rule: str) -> bool:
        return (config["custom"] == self.first["custom"] if rule == CUSTOM else (rule in config["changed"]) == (rule in self.first["changed"])
                if rule in OWN else config["filters"] == self.first["filters"] if rule in BUILTIN + OPT_IN + FILTERED else True)

    def filtered(self, config: dict, engine: str, rule: str, path: str) -> bool:
        return engine == "betterleaks" and (rule in config["disabled"] or path in config["allowed"])

    def configuration(self, config: dict) -> dict:
        digests = {rule: digest + ("-changed" if rule in config["changed"] else "") for rule, digest in rule_set.own_rules().items()}
        environment = {"PITANGUS_CHECKOV_ENABLED": "1" if config["checkov"] else "", "PITANGUS_THIRD_PARTY_RULES": "1" if config["third_party"] else ""}
        with patch.dict(os.environ, environment), patch.object(rule_set, "own_rules", return_value=digests), \
                patch.object(rule_set, "SECRET_FILTERS", config["filters"]):
            return rule_set.code(self.settings(config))

    def scan(self, code, config: dict, blind: frozenset[str] = frozenset()) -> tuple[dict, dict]:
        """`blind`: engines that failed in this scan (they report nothing, and a required one leaves it incomplete)."""
        from pitangus.modules.runs.store import save_and_apply
        findings, withheld = [], []
        for (engine, rule), path in code:
            if engine in blind or not self.runs(config, engine, rule) or not self.unchanged(config, rule):
                continue
            finding = {"finding_id": f"{engine}{rule}{path}"[:16], "fingerprint": f"{engine}:{rule}:{path}", "scanner": SCANNER[engine], "tool": engine,
                       "rule_id": rule, "title": rule, "path": path, "line": 1, "severity": "high", "confidence": 8, "verdict": "candidate", "cwe": [],
                       "owasp": [], "priority": {"action": "attend", "factors": []}, "reason": "", "remediation": ""}
            if self.filtered(config, engine, rule, path):
                withheld.append(secret_rules.withheld(finding, self.settings(config)))
            else:
                findings.append(finding)
        self.clock += timedelta(hours=1)
        engines_ = ("betterleaks", "opengrep", "checkov")
        record = {"type": "repository_scan", "status": "incomplete" if blind else "completed", "target": "org/api", "variant": "code", "context": "", "steps": [],
                  "source": {"id": "github:org/api", "uid": self.key, "name": "org/api", "provider": "github", "sha256": "x"},
                  "findings": findings, "excluded_findings": withheld, "owasp_coverage": [], "limitations": [],
                  "summary": {"files": 3, "dependencies": 0, "candidates": len(findings), "severities": {}, "priorities": {}, "kev": 0, "fixable": 0,
                              "tools": [{"name": engine, "version": "1", "status": "inconclusive" if engine in blind else "completed" if self.on(config, engine)
                                         else "not_tested"} for engine in engines_]},
                  "coverage": {engine: {"examined": "*", "unexamined": {}} for engine in engines_ if self.on(config, engine) and engine not in blind},
                  "configuration": self.configuration(config), "scanned_at": self.clock.isoformat(), "finished_at": self.clock.isoformat()}
        return save_and_apply(self.data_dir, record, created_at=self.clock.isoformat())


class ConfigurationTests(unittest.TestCase):
    """I8, against the registry in PostgreSQL, in both fixing modes (the hold kept out of the way: it is I9's)."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.examples = 0

    @settings(max_examples=40 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    @given(codes, configurations, configurations, st.sets(st.integers(0, 11)), st.sampled_from(["shadow", "on"]))
    @example(code=[(("betterleaks", "generic-password"), "app.py"), (("checkov", "CKV_AWS_20"), "app.py")],
             first={"enabled": set(OPT_IN), "custom": None, "disabled": set(), "allowed": set(), "checkov": True, "third_party": False,
                    "changed": set(), "filters": "1"},
             second={"enabled": set(), "custom": None, "disabled": set(), "allowed": set(), "checkov": False, "third_party": False,
                     "changed": set(), "filters": "1"}, removed=set(), mode="on")
    def test_toggling_configuration_between_two_scans_fixes_only_what_left_the_code(self, code, first, second, removed, mode):
        self.examples += 1
        scanner = ConfiguredScanner(Path(self.directory.name), f"github#cfg{self.examples}-{abs(hash(str((code, first, second)))) % 10**8}", first)
        with patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": mode, "PITANGUS_IDENTITY_MODE": "shadow", "PITANGUS_FIX_HOLD_MINIMUM": "1000"}):
            scanner.scan(code, first)
            kept = [item for index, item in enumerate(code) if index not in removed]
            _, changes = scanner.scan(kept, second)
        tracked = {f"{engine}:{rule}:{path}" for (engine, rule), path in code if scanner.runs(first, engine, rule)}
        # Fixed exactly when the problem left the code and the second scan's engine looked with the same rule, as it was.
        expected = sorted(f"{engine}:{rule}:{path}" for index, ((engine, rule), path) in enumerate(code) if index in removed
                          and f"{engine}:{rule}:{path}" in tracked and scanner.runs(second, engine, rule) and scanner.unchanged(second, rule))
        entries = registry.load(scanner.data_dir, scanner.key)["findings"]
        self.assertEqual(sorted(digest for digest, entry in entries.items() if entry["status"] == "fixed"), expected, (code, first, second, removed))
        self.assertEqual(sorted(changes.get("fixed_now") or []), expected)
        for (engine, rule), path in kept:
            digest = f"{engine}:{rule}:{path}"
            if digest in tracked and entries[digest]["status"] == "open" and not (scanner.runs(second, engine, rule) and scanner.unchanged(second, rule)):
                self.assertEqual(entries[digest]["unseen"]["reason"], "configuration", digest)

    def test_seed_72_generic_secrets_with_their_rules_turned_off_fix_nothing_and_tell_jira_nothing(self):
        """The validation's seed: 72 generic-password and generic-credential-uri findings on one asset (both opt-in then);
        the next scan with 0.14's defaults (generic-credential-uri off, generic-password on behind the new secret filter)
        fixes none, marks the 72 "not checked (configuration)" and queues nothing for Jira."""
        from pitangus.modules.findings import tickets
        from pitangus.modules.integrations import jira
        from pitangus.modules.integrations.tables import JIRA_CHANNEL, outbox
        from pitangus.shared import db
        from sqlalchemy import select
        generic = ("generic-password", "generic-credential-uri")
        code = [((("betterleaks", rule)), f"src/module{index}.py") for index in range(36) for rule in generic]
        on = {"enabled": set(OPT_IN), "custom": None, "disabled": set(), "allowed": set(), "checkov": False, "third_party": False, "changed": set(), "filters": "1"}
        for mode in ("on", "shadow"):
            with self.subTest(mode=mode), patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": mode, "PITANGUS_IDENTITY_MODE": "v2"}), \
                    patch.object(jira, "configured", return_value=True):
                scanner = ConfiguredScanner(Path(self.directory.name), f"github#seed72-{mode}", on)
                first, _ = scanner.scan(code, on)
                self.assertEqual(len(first["findings"]), 72)
                for index, finding in enumerate(first["findings"]):
                    tickets.remember(scanner.data_dir, scanner.key, finding["fingerprint"], {"key": f"SEC-{index}", "destination": "d"})
                _, changes = scanner.scan(code, {**on, "enabled": set(), "filters": "2"})
                entries = registry.load(scanner.data_dir, scanner.key)["findings"].values()
                self.assertEqual(changes.get("fixed_now"), [])
                self.assertEqual(sum(entry["status"] == "fixed" for entry in entries), 0)
                causes = Counter((entry["finding"]["rule_id"], (entry.get("unseen") or {}).get("reason"), (entry.get("unseen") or {}).get("cause"))
                                 for entry in entries)
                self.assertEqual(causes, {("generic-credential-uri", "configuration", "rule_off"): 36,
                                          ("generic-password", "configuration", "rule_changed"): 36})
                self.assertEqual(registry.summarize(scanner.data_dir, scanner.key)["unverified_configuration"], 72)
                with db.transaction(scanner.data_dir) as connection:
                    queued = connection.execute(select(outbox.c.payload).where(outbox.c.channel_id == JIRA_CHANNEL,
                                                                               outbox.c.payload["asset"].astext == scanner.key)).scalars().all()
                self.assertEqual(queued, [])


# --- I9: unproven is silent -----------------------------------------------------------------------------------------

# Each run: which problems are in the code, the configuration (None: the first one again) and the engines that failed.
silent_steps = st.lists(st.tuples(st.sets(st.integers(0, 11)), st.one_of(st.none(), configurations),
                                  st.one_of(st.just(set()), st.sets(st.sampled_from(("betterleaks", "opengrep")), max_size=1))),
                        min_size=2, max_size=5)
SAME = {"enabled": set(), "custom": None, "disabled": set(), "allowed": set(), "checkov": True, "third_party": False, "changed": set(), "filters": "1"}


class SilenceTests(unittest.TestCase):
    """I9: whatever the runs (code changing, configuration toggled, engines failing, the hold tripping), Jira gets a
    "fixed" comment and the notifications a finding only when the registry fixed or opened it with proof."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.examples = 0

    @settings(max_examples=20 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    @given(codes, silent_steps)
    @example(code=[(("betterleaks", "github-pat"), path) for path in PATHS] + [(("opengrep", rule), "app.py") for rule in OWN],
             steps=[(set(range(6)), SAME, set()), (set(), None, set()), (set(), None, set())])   # held, then confirmed and told
    @example(code=[(("betterleaks", "github-pat"), path) for path in PATHS] + [(("betterleaks", "generic-password"), path) for path in PATHS],
             steps=[(set(range(6)), {**SAME, "enabled": set(OPT_IN)}, set()), (set(range(3)), SAME, set()), (set(), None, set())])
    def test_nothing_held_or_unchecked_reaches_jira_or_the_notifications(self, code, steps):
        from pitangus.modules.findings import tickets
        from pitangus.modules.integrations import jira, notifications
        from pitangus.modules.integrations.tables import JIRA_CHANNEL, outbox
        from pitangus.shared import db
        from sqlalchemy import select
        self.examples += 1
        first = steps[0][1] or SAME
        scanner = ConfiguredScanner(Path(self.directory.name), f"github#quiet{self.examples}-{abs(hash(str((code, steps)))) % 10**8}", first)
        notified: list[str] = []
        told: set[str] = set()
        environment = {"PITANGUS_COVERAGE_MODE": "on", "PITANGUS_IDENTITY_MODE": "shadow", "PITANGUS_FIX_HOLD_MINIMUM": "2", "PITANGUS_FIX_HOLD_PERCENT": "30"}
        with patch.dict(os.environ, environment), patch.object(jira, "configured", return_value=True), \
                patch.object(notifications, "on_run", side_effect=lambda record, opened, **_: notified.extend(item["fingerprint"] for item in opened)):
            for present, config, blind in steps:
                saved, _ = scanner.scan([item for index, item in enumerate(code) if index in present], config or first, frozenset(blind))
                links = tickets.load_links(scanner.data_dir).get(scanner.key, {})
                for finding in saved["findings"]:   # one issue per finding, so a "fixed" comment names it
                    if finding["fingerprint"] not in links:
                        tickets.remember(scanner.data_dir, scanner.key, finding["fingerprint"], {"key": f"SEC-{finding['fingerprint']}", "destination": "d"})
                state = registry.load(scanner.data_dir, scanner.key)
                silent = set(((state["control"].get("hold") or {}).get("digests")) or []) \
                    | {digest for digest, entry in state["findings"].items() if entry.get("unseen")}
                with db.transaction(scanner.data_dir) as connection:
                    payloads = connection.execute(select(outbox.c.payload).where(outbox.c.channel_id == JIRA_CHANNEL,
                                                                                 outbox.c.payload["asset"].astext == scanner.key)).scalars().all()
                fixed = {payload["key"].removeprefix("SEC-") for payload in payloads if payload.get("event") == "fixed"} - told
                told |= fixed
                self.assertEqual(sorted(fixed & silent), [], (code, steps))
                self.assertTrue(all(state["findings"][digest]["status"] == "fixed" for digest in fixed))
                self.assertEqual(sorted(set(notified) & silent), [], (code, steps))
                notified.clear()


# --- I10: coverage is per unit -------------------------------------------------------------------------------------

UNITS = ("app.py", "lib/db.py", "web/views.py", "vendor/big.min.js")
coverage_runs = st.fixed_dictionaries({
    "status": st.sampled_from(["completed", "partial", "partial", "inconclusive", "not_tested"]),
    "broken": st.booleans(),                                                         # broke the engine contract
    "coverage": st.one_of(st.none(), st.fixed_dictionaries({
        "examined": st.one_of(st.just("*"), st.lists(st.sampled_from(UNITS), unique=True)),
        "unexamined": st.dictionaries(st.sampled_from(UNITS), st.sampled_from(["timeout", "skipped", "minified"]), max_size=3)})),
})


class PartialCoverageTests(unittest.TestCase):
    """I10, against the registry in PostgreSQL with the coverage contract on (the hold out of the way)."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.examples = 0

    def scan(self, key: str, clock: datetime, findings: list[dict], tool: dict, coverage: dict | None) -> None:
        record = {"type": "repository_scan", "status": "completed", "target": "org/api", "variant": "code", "context": "", "steps": [],
                  "source": {"id": "github:org/api", "uid": key, "name": "org/api", "provider": "github", "sha256": "x"},
                  "findings": findings, "owasp_coverage": [], "limitations": [],
                  "summary": {"files": 4, "dependencies": 0, "candidates": len(findings), "severities": {}, "priorities": {}, "kev": 0, "fixable": 0,
                              "tools": [tool]},
                  **({"coverage": {"opengrep": coverage}} if coverage is not None else {}),
                  "scanned_at": clock.isoformat(), "finished_at": clock.isoformat()}
        save_repository_scan(self.data_dir, record, created_at=clock.isoformat())

    @settings(max_examples=60 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    @given(st.lists(st.sampled_from(UNITS), min_size=1, max_size=4, unique=True), coverage_runs)
    @example(units=list(UNITS), run={"status": "partial", "broken": False, "coverage": {"examined": "*", "unexamined": {"vendor/big.min.js": "timeout"}}})
    def test_a_partial_engine_vouches_for_the_units_it_examined_and_only_those(self, units, run):
        self.examples += 1
        self.data_dir, key, clock = Path(self.directory.name), f"github#cov{self.examples}-{abs(hash(str((units, run)))) % 10**8}", datetime.now(timezone.utc)
        findings = [{"finding_id": f"sast-{unit}"[:16], "fingerprint": f"opengrep:{unit}", "scanner": "sast", "tool": "opengrep", "rule_id": "appsec.py.eval",
                     "title": "eval", "path": unit, "line": 1, "severity": "high", "confidence": 8, "verdict": "candidate", "cwe": [], "owasp": [],
                     "priority": {"action": "attend", "factors": []}, "reason": "", "remediation": ""} for unit in units]
        tool = {"name": "opengrep", "version": "1", "status": run["status"], **({"contract": {"blind": True, "cause": "empty"}} if run["broken"] else {})}
        with patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "on", "PITANGUS_IDENTITY_MODE": "shadow", "PITANGUS_FIX_HOLD_MINIMUM": "1000"}):
            self.scan(key, clock, findings, {"name": "opengrep", "version": "1", "status": "completed"}, {"examined": "*", "unexamined": {}})
            self.scan(key, clock + timedelta(hours=1), [], tool, run["coverage"])   # every finding gone from the code
        coverage = run["coverage"]
        looked = not run["broken"] and (run["status"] == "completed" or (run["status"] == "partial" and coverage is not None))

        def examined(unit):
            return coverage is None or (unit not in coverage["unexamined"] and (coverage["examined"] == "*" or unit in coverage["examined"]))
        entries = registry.load(self.data_dir, key)["findings"]
        self.assertEqual(sorted(digest for digest, entry in entries.items() if entry["status"] == "fixed"),
                         sorted(f"opengrep:{unit}" for unit in units if looked and examined(unit)), run)
        for digest, entry in entries.items():
            if entry["status"] == "open":
                self.assertEqual(entry["unseen"]["reason"], "unexamined" if looked else "engine_blind", (digest, run))


# --- Acceptance cases from the last validation, as seeds (each closed by a general mechanism, not its own code) -----

class CoverageSeeds(unittest.TestCase):
    def test_a_file_left_out_of_sast_for_one_long_line_is_unexamined(self):
        payload = json.dumps({"results": [], "errors": [], "paths": {"scanned": ["/src/app.py"]}})
        with tempfile.TemporaryDirectory() as folder:
            snapshot = Path(folder) / "snapshot"
            snapshot.mkdir()
            (snapshot / "app.py").write_text("eval(x)\n")
            (snapshot / "data.js").write_text("const blob = '" + "A" * 4000 + "'; eval(location.hash)\n")
            with patch.object(engines, "_run", side_effect=FakeEngine((0, payload))), patch.object(engines, "runner", return_value="docker"), \
                    patch.object(engines, "docker_available", return_value=True), patch.object(engines, "image_available", return_value=True):
                result = engines.run_opengrep(snapshot)
        self.assertEqual(result["coverage"]["unexamined"].get("data.js"), "minified")

    def test_sast_that_timed_out_on_one_file_still_proves_the_others(self):
        """The validation's seed (103 SAST findings that could never close): Opengrep ends `partial` for a rule that
        timed out on one file; what was in the files it read can be fixed, what was in that one can't."""
        payload = json.dumps({"results": [], "errors": [{"type": "Timeout", "level": "warn", "message": "timeout", "path": "/src/slow.py"}],
                              "paths": {"scanned": ["/src/app.py", "/src/slow.py"]}})
        with tempfile.TemporaryDirectory() as folder:
            snapshot = Path(folder) / "snapshot"
            snapshot.mkdir()
            (snapshot / "app.py").write_text("x = 1\n")
            (snapshot / "slow.py").write_text("y = 2\n")
            with patch.object(engines, "_run", side_effect=FakeEngine((0, payload))), patch.object(engines, "runner", return_value="docker"), \
                    patch.object(engines, "docker_available", return_value=True), patch.object(engines, "image_available", return_value=True), \
                    patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "on"}):
                result = engines.run_opengrep(snapshot)
        self.assertEqual(result["status"], "partial")
        record = {"status": "completed", "type": "repository_scan", "coverage": {"opengrep": result["coverage"]},
                  "summary": {"tools": [{"name": "opengrep", "status": result["status"], **({"contract": result["contract"]} if result.get("contract") else {})}]}}
        reasons = {path: registry.unproven_reason(record, {"tool": "opengrep", "scanner": "sast", "path": path, "rule_id": "appsec.py.eval"})
                   for path in ("app.py", "slow.py")}
        self.assertEqual(reasons, {"app.py": None, "slow.py": "unexamined"})

    def test_a_rule_that_did_not_load_leaves_sast_blind(self):
        payload = json.dumps({"results": [], "errors": [{"type": "Rule parse error", "level": "error", "message": "Invalid pattern"}],
                              "paths": {"scanned": ["/src/app.py"]}})
        with tempfile.TemporaryDirectory() as folder:
            snapshot = Path(folder) / "snapshot"
            snapshot.mkdir()
            (snapshot / "app.py").write_text("eval(x)\n")
            with patch.object(engines, "_run", side_effect=FakeEngine((0, payload))), patch.object(engines, "runner", return_value="docker"), \
                    patch.object(engines, "docker_available", return_value=True), patch.object(engines, "image_available", return_value=True):
                shadow = engines.run_opengrep(snapshot)
                with patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "on"}):
                    enforced = engines.run_opengrep(snapshot)
        self.assertTrue(shadow["contract"]["blind"])
        self.assertEqual(enforced["status"], "inconclusive")


class IdentitySeeds(unittest.TestCase):
    def test_a_nosemgrep_comment_before_the_code_keeps_its_identity(self):
        plain = canonical.identity_of(engines.parse_opengrep(opengrep_report([(4, "eval(user)")], "app.js"))[0])
        report = opengrep_report([(4, "/* nosemgrep */ eval( user )")], "app.js")
        report["results"][0]["extra"]["is_ignored"] = True
        self.assertEqual(canonical.identity_of(engines.parse_opengrep(report, silenced=True)[0]), plain)

    def test_the_same_result_in_two_categories_is_keyed_alike(self):
        def run(category):
            return {"tool": {"driver": {"name": "CodeQL"}}, "automationDetails": {"id": f"/language:{category}/"},
                    "results": [{"ruleId": "r", "message": {"text": "m"}, "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "a.js"}, "region": {"startLine": 1, "snippet": {"text": "x"}}}}]}]}
        alone = canonical.identity_of(sarif_import.parse({"version": "2.1.0", "runs": [run("python")]})[0]["findings"][0])
        both = sarif_import.parse({"version": "2.1.0", "runs": [run("javascript"), run("python")]})
        self.assertEqual(canonical.identity_of(next(item for item in both if item["category"] == "language:python")["findings"][0]), alone)

    def test_a_tool_rewording_its_message_keeps_the_identity(self):
        def result(message):
            return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Trivy"}}, "results": [{"ruleId": "CVE-2026-1", "message": {"text": message},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "package-lock.json"}, "region": {"startLine": 1}}}]}]}]}
        self.assertEqual(canonical.identity_of(sarif_import.parse(result("Package: lodash\nSeverity: HIGH\nFixed Version: 4.17.21"))[0]["findings"][0]),
                         canonical.identity_of(sarif_import.parse(result("Package: lodash\nSeverity: CRITICAL\nFixed Version: 4.17.22"))[0]["findings"][0]))

    @unittest.expectedFailure  # Phase 5: a site-wide finding groups pages by rule and value, never different values
    def test_different_policies_on_one_site_stay_apart(self):
        def result(page, policy):
            return {"ruleId": "10055", "message": {"text": "CSP"}, "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f"https://{HOST}/{page}"}, "region": {"snippet": {"text": policy}}}}]}
        document = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ZAP"}}, "results": [
            result("", "script-src 'unsafe-inline'"), result("admin/", "default-src *")]}]}
        self.assertEqual(len(sarif_import.parse(document)[0]["findings"]), 2)

    @unittest.expectedFailure  # Phase 5: what a host runs (an end-of-life server) is one finding per host, not per URL
    def test_an_end_of_life_server_is_one_finding_per_host(self):
        lines = "".join(json.dumps({"template-id": "nginx-eol", "info": {"name": "Nginx EOL", "severity": "medium", "tags": ["eol"]},
                                    "matched-at": f"https://{HOST}/{page}", "host": HOST, "type": "http"}) + "\n" for page in ("", "blog/", "about/"))
        findings, _ = web_tools.parse_nuclei(lines, [HOST])
        self.assertEqual(len(findings), 1)


class VersionSeeds(unittest.TestCase):
    def test_the_fixed_version_offered_is_never_below_the_installed_one(self):
        fixed = engines._pick_fixed("~> 6.0.6, >= 6.0.6.1, ~> 6.1.7, >= 6.1.7.1", "6.1.7")
        self.assertTrue(fixed and engines.compare_versions(fixed.lstrip("~>= "), "6.1.7") > 0, fixed)


if __name__ == "__main__":
    unittest.main()
