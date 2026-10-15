"""What a scanned repository says to suppress an engine's results is honoured and never silent (scanning/repo_controls.py).

Each engine is given a repository that suppresses something every way it knows: zizmor (`# zizmor: ignore[…]`,
`.github/zizmor.yml`), Checkov (`.checkov.yaml`, `checkov:skip=`, `checkov.io/skip`), Trivy (`.trivyignore`,
`trivy:ignore`) and OSV-Scanner (`osv-scanner.toml`). What they suppress is excluded and declared with its rule, its file
and line and what suppressed it, never fixed; PITANGUS_IGNORE_REPO_SUPPRESSIONS (or its earlier name) makes them suppress
nothing; and when the run that says what they hid fails, the scan fixes nothing. The engines are played back from what
the pinned images returned on this repository (tests/fixtures/repo-controls.json); `RealEnginesTests` runs the images
(skipped without Docker).
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pitangus.modules.scanning import config_engines, engines, repo_controls
from pitangus.shared.i18n import text

ROOT = Path(__file__).resolve().parent
RECORDED = ROOT / "fixtures" / "repo-controls.json"

WORKFLOW = b"""name: a
on: push
permissions: {}
jobs:
  b:
    name: b
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4  # zizmor: ignore[unpinned-uses]
        with:
          persist-credentials: false
      - uses: actions/setup-node@v4
      - run: echo "${{ github.event.head_commit.message }}"
"""
TERRAFORM = b"""#trivy:ignore:AVD-AWS-0086
resource "aws_s3_bucket" "b" {
  #checkov:skip=CKV_AWS_18:reviewed
  bucket = "x"
}
"""
POD = b"""apiVersion: v1
kind: Pod
metadata:
  name: p
  annotations:
    checkov.io/skip1: CKV_K8S_20=reviewed
spec:
  containers:
  - name: c
    image: nginx
"""
REPO = {".github/workflows/a.yml": WORKFLOW, ".github/zizmor.yml": b"rules:\n  template-injection:\n    disable: true\n",
        "main.tf": TERRAFORM, "k8s/pod.yaml": POD, ".checkov.yaml": b"skip-check:\n  - CKV_AWS_21\n", ".trivyignore": b"AVD-AWS-0087\n"}


def write(root: Path, files: dict[str, bytes]) -> Path:
    for path, content in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_bytes(content)
    return root


def excluded(result: dict) -> dict[tuple[str, str, int], str]:
    return {(item["rule_id"], item["path"], item["line"]): text(item["excluded_reason"], "en") for item in result.get("withheld") or []}


class Played:
    """The engines as the pinned images answered on REPO: which run it is is read from what it was given (the switches
    that honour nothing, or the mounted folder's comments and configuration), as the real engine would tell."""

    def __init__(self, fail_unhonoured: bool = False):
        self.calls = json.loads(RECORDED.read_text(encoding="utf-8"))
        self.fail = fail_unhonoured
        self.seen: list[tuple[str, list[str], set[str]]] = []

    @staticmethod
    def honoured(key: str, arguments: list[str], snapshot: Path) -> bool:
        if key == "zizmor":
            return "--no-ignores" not in arguments
        terraform = (snapshot / "main.tf").read_bytes()
        return (b"checkov:skip=" if key == "checkov" else b"trivy:ignore") in terraform

    def __call__(self, key, arguments, snapshot=None, **options):
        files = {path.relative_to(snapshot).as_posix() for path in snapshot.rglob("*") if path.is_file()}
        self.seen.append((key, list(arguments), files))
        honoured = self.honoured(key, arguments, snapshot)
        if self.fail and not honoured:
            return subprocess.CompletedProcess(arguments, 2, "", "boom")
        recorded = next(call for call in self.calls if call["key"] == key and call["honoured"] == honoured)
        return subprocess.CompletedProcess(arguments, recorded["returncode"], recorded["stdout"], "")


class Fixture(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = write(Path(folder.name) / "snapshot", REPO)
        for name, value in (("unavailable", None), ("switched_off", None)):
            replaced = patch.object(config_engines, name, return_value=value)
            replaced.start()
            self.addCleanup(replaced.stop)
        clean = patch.dict(os.environ, {"PITANGUS_IGNORE_REPO_SUPPRESSIONS": "", "PITANGUS_SECRETS_IGNORE_INLINE_ALLOW": ""})
        clean.start()
        self.addCleanup(clean.stop)

    def run_engine(self, function, played: Played) -> dict:
        with patch.object(config_engines, "_run", side_effect=played), patch.object(engines, "_run", side_effect=played):
            return function(self.root)


class ZizmorTests(Fixture):
    def test_a_comment_and_the_configuration_suppress_and_both_are_declared(self):
        result = self.run_engine(config_engines.run_zizmor, Played())
        self.assertEqual(result["status"], "completed")
        reasons = excluded(result)
        self.assertEqual(sorted(reasons), [("template-injection", ".github/workflows/a.yml", 13),
                                           ("unpinned-uses", ".github/workflows/a.yml", 9)])
        self.assertIn("zizmor: ignore comment", reasons[("unpinned-uses", ".github/workflows/a.yml", 9)])
        self.assertIn(".github/zizmor.yml", reasons[("template-injection", ".github/workflows/a.yml", 13)])
        self.assertEqual([(item["rule_id"], item["line"]) for item in result["findings"]], [("unpinned-uses", 12)])
        self.assertEqual(result["coverage"]["suppressed_inline"], [".github/workflows/a.yml:13", ".github/workflows/a.yml:9"])
        self.assertIn(".github/workflows/a.yml:9", text(result["detail"], "es"))
        for reason in reasons.values():
            self.assertNotIn("checkout@v4", reason)      # where and what suppressed it, never the code

    def test_with_the_setting_on_nothing_is_suppressed(self):
        for name in ("PITANGUS_IGNORE_REPO_SUPPRESSIONS", "PITANGUS_SECRETS_IGNORE_INLINE_ALLOW"):
            with self.subTest(name=name), patch.dict(os.environ, {name: "1"}):
                played = Played()
                result = self.run_engine(config_engines.run_zizmor, played)
                self.assertEqual(sorted((item["rule_id"], item["line"]) for item in result["findings"]),
                                 [("template-injection", 13), ("unpinned-uses", 9), ("unpinned-uses", 12)])
                self.assertFalse(result.get("withheld"))
                self.assertEqual([call[0] for call in played.seen], ["zizmor"])   # one run, honouring nothing
                self.assertIn("--no-config", played.seen[0][1])

    def test_when_the_run_that_says_what_was_hidden_fails_nothing_is_fixed(self):
        result = self.run_engine(config_engines.run_zizmor, Played(fail_unhonoured=True))
        self.assertEqual((result["status"], result["withheld"]), ("partial", None))


class CheckovTests(Fixture):
    def test_its_configuration_never_reaches_it_and_every_suppression_is_declared(self):
        played = Played()
        result = self.run_engine(config_engines.run_checkov, played)
        self.assertTrue(played.seen and all(".checkov.yaml" not in files for _, _, files in played.seen))
        self.assertTrue((self.root / ".checkov.yaml").is_file() and b"checkov:skip=" in (self.root / "main.tf").read_bytes())
        reasons = excluded(result)
        rules = {rule for rule, _, _ in reasons}
        self.assertTrue({"CKV_AWS_18", "CKV_AWS_21", "CKV_K8S_20"} <= rules, rules)
        self.assertIn(".checkov.yaml (skip-check)", next(reason for (rule, _, _), reason in reasons.items() if rule == "CKV_AWS_21"))
        self.assertIn("checkov:skip comment", next(reason for (rule, _, _), reason in reasons.items() if rule == "CKV_AWS_18"))
        self.assertFalse({item["rule_id"] for item in result["findings"]} & {"CKV_AWS_18", "CKV_AWS_21", "CKV_K8S_20"})
        self.assertIn("main.tf:2", result["coverage"]["suppressed_inline"])

    def test_with_the_setting_on_nothing_is_suppressed(self):
        with patch.dict(os.environ, {"PITANGUS_IGNORE_REPO_SUPPRESSIONS": "1"}):
            played = Played()
            result = self.run_engine(config_engines.run_checkov, played)
        self.assertEqual(len(played.seen), 1)
        self.assertTrue({"CKV_AWS_18", "CKV_AWS_21", "CKV_K8S_20"} <= {item["rule_id"] for item in result["findings"]})
        self.assertFalse(result.get("withheld"))

    def test_when_the_run_that_says_what_was_hidden_fails_nothing_is_fixed(self):
        result = self.run_engine(config_engines.run_checkov, Played(fail_unhonoured=True))
        self.assertEqual((result["status"], result["withheld"]), ("partial", None))

    def test_a_regular_expression_from_the_repository_is_never_run(self):
        (self.root / ".checkov.yaml").write_bytes(b"skip-path:\n  - '(a+)+$'\n  - k8s/\ncheck: LOW\n")
        findings = [{"rule_id": "CKV_K8S_8", "path": "k8s/pod.yaml", "line": 1}, {"rule_id": "CKV_AWS_18", "path": "main.tf", "line": 2}]
        kept, suppressed = config_engines._checkov_config(self.root, [".checkov.yaml"], findings)
        self.assertEqual(([item["rule_id"] for item in kept], [item["rule_id"] for item in suppressed]), (["CKV_AWS_18"], ["CKV_K8S_8"]))


class TrivyTests(Fixture):
    def run_trivy_misconfig(self, played: Played) -> tuple[dict | None, list, object]:
        with patch.object(engines, "_run", side_effect=played):
            ignore = engines.trivy_ignore_file(self.root)
            completed = engines._trivy_fs(self.root, self.root.parent / "cache", "misconfig", None, ignore=ignore)
            payload = json.loads(completed.stdout)
            honoured = [item for item in engines.parse_trivy(payload, {}, root=self.root) if item["scanner"] == "iac"]
            inline = engines._trivy_inline(self.root, self.root.parent / "cache", {}, (), ignore, honoured)
        return payload, engines.trivy_suppressed(payload, {}, None, self.root, ignore), inline

    def test_its_ignore_file_and_its_comments_suppress_and_are_declared(self):
        played = Played()
        payload, listed, inline = self.run_trivy_misconfig(played)
        arguments = played.seen[0][1]
        self.assertEqual(arguments[arguments.index("--ignorefile") + 1], "/ignore/.trivyignore")
        self.assertIn("--show-suppressed", arguments)
        self.assertEqual([(item["rule_id"], item["path"]) for item in listed], [("AWS-0087", "main.tf")])
        self.assertIn(".trivyignore", text(listed[0]["excluded_reason"], "en"))
        found, hidden = inline
        self.assertEqual([item["rule_id"] for item in hidden], ["AWS-0086"])
        self.assertIn("trivy:ignore comment", text(hidden[0]["excluded_reason"], "en"))
        self.assertNotIn("AWS-0086", [item["rule_id"] for item in found])

    def test_with_the_setting_on_it_reads_no_ignore_file_and_comments_hide_nothing(self):
        with patch.dict(os.environ, {"PITANGUS_IGNORE_REPO_SUPPRESSIONS": "1"}):
            played = Played()
            _, listed, inline = self.run_trivy_misconfig(played)
        arguments = played.seen[0][1]
        self.assertEqual(arguments[arguments.index("--ignorefile") + 1], "")
        found, hidden = inline
        self.assertEqual((listed, hidden), ([], []))
        self.assertIn("AWS-0086", [item["rule_id"] for item in found])

    def test_when_the_run_without_comments_fails_nothing_is_fixed(self):
        _, _, inline = self.run_trivy_misconfig(Played(fail_unhonoured=True))
        self.assertEqual(inline, "unknown")
        self.assertEqual(engines.controls_unknown({"status": "completed", "detail": "x"})["withheld"], None)


class OsvTests(unittest.TestCase):
    """OSV-Scanner loads an `osv-scanner.toml` from each folder it scans and only logs that it filtered something."""

    def test_what_its_configuration_filtered_out_is_declared_with_that_file(self):
        payload = json.loads((ROOT / "fixtures" / "osv-2.6-ctx.json").read_text(encoding="utf-8"))
        full = engines.parse_osv_scanner(payload, {})
        self.assertGreater(len(full), 1)
        hidden = full[0]
        trimmed = json.loads(json.dumps(payload))
        for result in trimmed["results"]:
            for package in result["packages"]:
                package["vulnerabilities"] = [item for item in package.get("vulnerabilities") or []
                                              if item["id"] != hidden.get("rule_id") and hidden["rule_id"] not in (item.get("aliases") or [])]
                package["groups"] = [group for group in package.get("groups") or [] if hidden["rule_id"] not in group["ids"]]
        folder = hidden["path"].rpartition("/")[0]
        config = f"{folder}/osv-scanner.toml" if folder else "osv-scanner.toml"
        calls = []

        def played(key, arguments, snapshot=None, **options):
            calls.append(arguments)
            if "--config" in arguments:
                return subprocess.CompletedProcess(arguments, 1, json.dumps(payload), "")
            return subprocess.CompletedProcess(arguments, 1, json.dumps(trimmed), f"Loaded filter from: /src/{config}\n")
        with tempfile.TemporaryDirectory() as directory, patch.object(engines, "_run", side_effect=played), \
                patch.object(engines, "unavailable", return_value=None), \
                patch.dict(os.environ, {"PITANGUS_IGNORE_REPO_SUPPRESSIONS": "", "PITANGUS_SECRETS_IGNORE_INLINE_ALLOW": ""}):
            snapshot = Path(directory) / "snapshot"
            snapshot.mkdir()
            result = engines.run_osv_scanner(snapshot, Path(directory) / "cache", {})
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[1][calls[1].index("--config") + 1], "/cfg/osv-scanner.toml")
            self.assertEqual([item["fingerprint"] for item in result["withheld"]], [hidden["fingerprint"]])
            self.assertIn(config, text(result["withheld"][0]["excluded_reason"], "en"))
            self.assertNotIn(hidden["fingerprint"], [item["fingerprint"] for item in result["findings"]])
            # With the setting on, one run that replaces every repository configuration with an empty one of Pitangus'.
            calls.clear()
            with patch.dict(os.environ, {"PITANGUS_IGNORE_REPO_SUPPRESSIONS": "1"}):
                result = engines.run_osv_scanner(snapshot, Path(directory) / "cache", {})
            self.assertEqual(len(calls), 1)
            self.assertIn("--config", calls[0])
            self.assertIn(hidden["fingerprint"], [item["fingerprint"] for item in result["findings"]])


class OpengrepTests(unittest.TestCase):
    def test_with_the_setting_on_a_nosemgrep_comment_silences_nothing(self):
        payload = json.loads((ROOT / "fixtures" / "opengrep.json").read_text(encoding="utf-8"))
        payload["results"][0].setdefault("extra", {})["is_ignored"] = True     # what --disable-nosem reports for one
        silenced = engines.parse_opengrep(payload, silenced=True)
        self.assertTrue(silenced)
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(engines, "_run", return_value=subprocess.CompletedProcess([], 1, json.dumps(payload), "")), \
                patch.object(engines, "runner", return_value="docker"), patch.object(engines, "docker_available", return_value=True), \
                patch.object(engines, "image_available", return_value=True):
            for value, reported in (("", False), ("1", True)):
                with patch.dict(os.environ, {"PITANGUS_IGNORE_REPO_SUPPRESSIONS": value}):
                    result = engines.run_opengrep(Path(directory))
                fingerprints = {item["fingerprint"] for item in result["findings"]}
                self.assertEqual(all(item["fingerprint"] in fingerprints for item in silenced), reported, value)
                self.assertEqual(bool(result["silenced"]), not reported)


class ViewTests(unittest.TestCase):
    def test_a_view_never_writes_the_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write(Path(directory) / "snapshot", {"a.tf": b"#checkov:skip=X\n", ".checkov.yaml": b"x: 1\n", "b/c.txt": b"c"})
            with repo_controls.view(root, drop=[".checkov.yaml"], rewrite={"a.tf": b"#checkov_skip=X\n"}) as copy:
                self.assertEqual(((copy / "a.tf").read_bytes(), (copy / ".checkov.yaml").exists(), (copy / "b/c.txt").read_bytes()),
                                 (b"#checkov_skip=X\n", False, b"c"))
            self.assertFalse(copy.exists())
            self.assertEqual(((root / "a.tf").read_bytes(), (root / ".checkov.yaml").is_file()), (b"#checkov:skip=X\n", True))

    def test_split_matches_by_place_not_by_order(self):
        full = [{"k": 1}, {"k": 1}, {"k": 2}]
        kept, suppressed, extra = repo_controls.split(full, [{"k": 1}, {"k": 3}], lambda item: item["k"])
        self.assertEqual((kept, suppressed, extra), ([{"k": 1}], [{"k": 1}, {"k": 2}], [{"k": 3}]))


class RepositoryScanTests(unittest.TestCase):
    """A whole code scan: what the repository suppressed is excluded and declared in the run (its limitations, the
    engine's coverage), never counted as a `nosemgrep` silence, and the scan fixes nothing when it can't tell."""

    TOKEN = "sk_live_" + "Rq7RkT2mWv5XyB7nPc3LdF9hJ"

    def scan(self, played: Played) -> dict:
        from test_secret_pass_coverage import SecretEngines, _completed, archive
        from pitangus.modules.scanning import repository
        from pitangus.modules.sources.repositories import _extract_limited
        files = {path: content for path, content in REPO.items() if not path.endswith(".tf")}
        files["src/keys.js"] = f'const a = 1;\nconst stripe = "{self.TOKEN}";\n'.encode()
        files[".gitleaksignore"] = b"src/keys.js:stripe-access-token:2\n"     # a file of the code, not only secret-only ones
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "head"
            stats = _extract_limited(archive(files), root)
            replaced = [patch.object(engines, "_run", side_effect=SecretEngines()), patch.object(engines, "unavailable", return_value=None),
                        patch.object(config_engines, "_run", side_effect=played), patch.object(config_engines, "unavailable", return_value=None),
                        patch.object(engines, "runner", return_value="docker"), patch.object(engines, "trivy_databases", return_value=[]),
                        patch.object(repository, "engines_available", return_value=True),
                        patch.object(repository, "host_mount_problem", return_value=None),
                        patch.object(repository, "load_feeds", return_value={"kev": {}, "epss": {}}),
                        patch.dict(os.environ, {"PITANGUS_IGNORE_REPO_SUPPRESSIONS": "", "PITANGUS_SECRETS_IGNORE_INLINE_ALLOW": ""}),
                        *(patch.object(repository, name, side_effect=_completed(key)) for name, key in
                          (("run_opengrep", "opengrep"), ("run_osv_scanner", "osv-scanner"), ("run_checkov", "checkov")))]
            for item in replaced:
                item.start()
            try:
                return repository.scan_repository(root, {"id": "github:org/app", "uid": "github#r5", "name": "org/app", "provider": "github",
                                                         "snapshot": stats}, data_dir=Path(folder))
            finally:
                for item in replaced:
                    item.stop()

    def test_suppressed_results_are_excluded_and_declared_in_the_run(self):
        record = self.scan(Played())
        self.assertEqual(record["status"], "completed")
        excluded_ = {(item["tool"], item["rule_id"], item["path"], item["line"]) for item in record.get("excluded_findings") or []
                     if item.get("inline_allowed")}
        self.assertTrue({("zizmor", "unpinned-uses", ".github/workflows/a.yml", 9), ("zizmor", "template-injection", ".github/workflows/a.yml", 13),
                         ("betterleaks", "stripe-access-token", "src/keys.js", 2)} <= excluded_, excluded_)
        self.assertEqual(record["coverage"]["zizmor"]["suppressed_inline"], [".github/workflows/a.yml:13", ".github/workflows/a.yml:9"])
        limitations = [text(item, "en") for item in record["limitations"]]
        self.assertTrue(any("suppressed by the repository's own" in item and ".github/workflows/a.yml:9" in item for item in limitations))
        self.assertFalse(any("nosemgrep" in item for item in limitations))
        self.assertNotIn(self.TOKEN, json.dumps(record, ensure_ascii=False))

    def test_when_the_run_that_says_what_was_hidden_fails_the_scan_is_incomplete(self):
        self.assertEqual(self.scan(Played(fail_unhonoured=True))["status"], "incomplete")


def real_engines() -> bool:
    return engines.docker_available() and all(engines.image_available(key) for key in ("zizmor", "checkov", "trivy"))


@unittest.skipUnless(real_engines(), "needs Docker with the zizmor, Checkov and Trivy images")
class RealEnginesTests(unittest.TestCase):
    """The pinned images on REPO: the same suppressions are honoured and declared."""

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = write(Path(folder.name) / "snapshot", REPO)
        environment = patch.dict(os.environ, {"PITANGUS_ENGINE_RUNNER": "docker", "PITANGUS_CHECKOV_ENABLED": "1",
                                              "PITANGUS_IGNORE_REPO_SUPPRESSIONS": "", "PITANGUS_SECRETS_IGNORE_INLINE_ALLOW": ""})
        environment.start()
        self.addCleanup(environment.stop)

    def test_zizmor(self):
        result = config_engines.run_zizmor(self.root)
        self.assertEqual(sorted((rule, line) for rule, _, line in excluded(result)), [("template-injection", 13), ("unpinned-uses", 9)])

    def test_checkov(self):
        result = config_engines.run_checkov(self.root)
        self.assertTrue({"CKV_AWS_18", "CKV_AWS_21", "CKV_K8S_20"} <= {rule for rule, _, _ in excluded(result)})

    def test_trivy(self):
        cache = self.root.parent / "cache"
        cache.mkdir()
        ignore = engines.trivy_ignore_file(self.root)
        completed = engines._trivy_fs(self.root, cache, "misconfig", None, skips=("--skip-check-update",), ignore=ignore, network=False)
        payload = json.loads(completed.stdout)
        self.assertEqual([item["rule_id"] for item in engines.trivy_suppressed(payload, {}, None, self.root, ignore)], ["AWS-0087"])
        honoured = [item for item in engines.parse_trivy(payload, {}, root=self.root) if item["scanner"] == "iac"]
        _, hidden = engines._trivy_inline(self.root, cache, {}, ("--skip-check-update",), ignore, honoured)
        self.assertEqual([item["rule_id"] for item in hidden], ["AWS-0086"])


if __name__ == "__main__":
    unittest.main()
