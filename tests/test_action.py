"""The GitHub Action (action.yml): the image of this version, no expressions inside scripts, pinned actions, inputs
documented in docs/cli.md, and the exact commands its scripts hand Docker and cosign (run against fakes)."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from pitangus.version import VERSION

ROOT = Path(__file__).resolve().parents[1]
ACTION = (ROOT / "action.yml").read_text(encoding="utf-8")
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
DOCS = (ROOT / "docs" / "cli.md", ROOT / "docs" / "es" / "cli.md")


def section(text: str, key: str) -> list[str]:
    """The lines under a top-level YAML key (no PyYAML: action.yml is simple enough to read by indentation)."""
    lines = text.splitlines()
    start = lines.index(f"{key}:") + 1
    end = next((i for i in range(start, len(lines)) if re.match(r"^[a-z]", lines[i])), len(lines))
    return lines[start:end]


def keys(text: str, key: str) -> list[str]:
    return [match.group(1) for line in section(text, key) if (match := re.match(r"^  ([a-z-]+):$", line))]


def defaults(text: str) -> dict[str, str]:
    found, current = {}, None
    for line in section(text, "inputs"):
        if match := re.match(r"^  ([a-z-]+):$", line):
            current = match.group(1)
        elif current and (match := re.match(r"^    default: (.*)$", line)):
            found[current] = json.loads(match.group(1)) if match.group(1).startswith('"') else match.group(1)
    return found


def steps(text: str) -> list[dict]:
    """Each composite step: its env ({VARIABLE: input}, literal values apart) and its `run: |` script, dedented."""
    found: list[dict] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.match(r"^    - ", line):
            found.append({"env": {}, "literal": {}, "run": ""})
        elif match := re.match(r"^        ([A-Z_]+): \$\{\{ inputs\.([a-z-]+) \}\}$", line):
            found[-1]["env"][match.group(1)] = match.group(2)
        elif match := re.match(r"^        ([A-Z_]+): (.+)$", line):
            value = match.group(2)
            found[-1]["literal"][match.group(1)] = value[1:-1] if value.startswith("'") else value
        elif re.match(r"^      run: \|$", line):
            block = []
            i += 1
            while i < len(lines) and (not lines[i].strip() or lines[i].startswith("        ")):
                block.append(lines[i][8:])
                i += 1
            found[-1]["run"] = "\n".join(block).strip() + "\n"
            continue
        i += 1
    return found


def run_blocks(text: str) -> list[str]:
    """Every `run:` script (inline or block) in a workflow or action file."""
    blocks, lines, i = [], text.splitlines(), 0
    while i < len(lines):
        match = re.match(r"^(\s*)(?:- )?run: ?(.*)$", lines[i])
        i += 1
        if not match:
            continue
        indent, rest = len(match.group(1)), match.group(2)
        if rest.strip() not in ("|", ">", "|-", ">-"):
            blocks.append(rest)
            continue
        block = []
        while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
            block.append(lines[i])
            i += 1
        blocks.append("\n".join(block))
    return blocks


def documented(path: Path, header: str) -> list[str]:
    """First-column names of the markdown table whose header starts with `header`."""
    rows = path.read_text(encoding="utf-8").splitlines()
    start = next(i for i, row in enumerate(rows) if re.match(rf"^\| ({header}) \|", row))
    names = []
    for row in rows[start + 2:]:
        if not row.startswith("|"):
            break
        names.append(re.match(r"^\| `([a-z-]+)` \|", row).group(1))
    return names


PUBLISHED = "ghcr.io/pitangus-dev/pitangus-worker"
DIGEST = "sha256:" + "ab" * 32

# FAKE_LOCAL: the image is already on the runner. FAKE_DIGESTS: its RepoDigests. FAKE_CODES: exit codes of the
# successive `docker run` calls. FAKE_COSIGN: cosign's exit code.
FAKE_DOCKER = f"""#!{sys.executable}
import json, os, sys
log = os.environ["FAKE_LOG"]
previous = [json.loads(line) for line in open(log)] if os.path.exists(log) else []
record = {{"tool": "docker", "argv": sys.argv[1:], "token": os.environ.get("PITANGUS_IMPORT_TOKEN"),
           "docker_config": os.environ.get("DOCKER_CONFIG"), "stdin": sys.stdin.read() if "login" in sys.argv else None}}
open(log, "a").write(json.dumps(record) + "\\n")
if sys.argv[1:3] == ["image", "inspect"]:
    pulled = any(call["argv"][:1] == ["pull"] for call in previous)
    if os.environ.get("FAKE_LOCAL") != "1" and not pulled:
        sys.exit(1)
    if "--format" in sys.argv:
        print(os.environ.get("FAKE_DIGESTS", "{PUBLISHED}@{DIGEST}").replace(" ", "\\n"))
    sys.exit(0)
if sys.argv[1] != "run":
    sys.exit(0)
if "scan" in sys.argv:
    open(os.path.join(os.environ["RUNNER_TEMP"], "pitangus", "result.sarif"), "w").write('{{"version": "2.1.0"}}')
runs = sum(call["argv"][:1] == ["run"] for call in previous)
codes = os.environ.get("FAKE_CODES", "").split(",")
sys.exit(int(codes[runs]) if runs < len(codes) and codes[runs] else 0)
"""

FAKE_COSIGN = f"""#!{sys.executable}
import json, os, sys
open(os.environ["FAKE_LOG"], "a").write(json.dumps({{"tool": "cosign", "argv": sys.argv[1:]}}) + "\\n")
sys.exit(int(os.environ.get("FAKE_COSIGN") or 0))
"""


PULL, MAIN = (next(i for i, step in enumerate(steps(ACTION)) if marker in step["run"])
              for marker in ("docker login", "python -m pitangus scan"))


class ActionDefinitionTests(unittest.TestCase):
    def test_the_default_image_is_this_version(self):
        self.assertEqual(defaults(ACTION)["image"], f"{PUBLISHED}:{VERSION}")
        self.assertEqual(steps(ACTION)[MAIN]["literal"]["PUBLISHED"], PUBLISHED)

    def test_only_the_release_workflow_of_a_version_tag_signs(self):
        signers = re.compile(steps(ACTION)[MAIN]["literal"]["SIGNERS"])
        for identity in ("https://github.com/Pitangus-Dev/pitangus/.github/workflows/release.yml@refs/tags/v0.10.4",
                         "https://github.com/Pitangus-Dev/pitangus/.github/workflows/release.yml@refs/tags/v0.12"):
            self.assertRegex(identity, signers)
        for identity in ("https://github.com/Pitangus-Dev/pitangus/.github/workflows/release.yml@refs/heads/main",
                         "https://github.com/Pitangus-Dev/pitangus/.github/workflows/ci.yml@refs/tags/v0.10.4",
                         "https://github.com/someone/pitangus/.github/workflows/release.yml@refs/tags/v0.10.4",
                         "https://github.com/Pitangus-Dev/pitangus/.github/workflows/release.yml@refs/tags/v0.10.4-evil",
                         "https://github.com/Pitangus-DevXpitangus/.github/workflows/release.yml@refs/tags/v0.10.4",
                         "https://github.com/BrayansStivens/appsec-agent/.github/workflows/release.yml@refs/tags/v0.10.1"):
            self.assertNotRegex(identity, signers)
        self.assertIn("if: inputs.verify != 'false'\n      uses: sigstore/cosign-installer@", ACTION)

    def test_scripts_never_interpolate_expressions(self):
        for path in (ROOT / "action.yml", *WORKFLOWS):
            for block in run_blocks(path.read_text(encoding="utf-8")):
                self.assertNotIn("${{", block, path)
        self.assertEqual(len(run_blocks(ACTION)), 2)

    def test_every_action_is_pinned_by_commit(self):
        for path in (ROOT / "action.yml", *WORKFLOWS):
            for reference in re.findall(r"^\s*(?:- )?uses: (\S+)", path.read_text(encoding="utf-8"), re.M):
                if reference != "./":
                    self.assertRegex(reference, r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$", path)

    def test_the_docs_list_the_same_inputs_and_outputs(self):
        for path in DOCS:
            self.assertEqual(documented(path, "Input|Entrada"), keys(ACTION, "inputs"), path)
            self.assertEqual(documented(path, "Output|Salida"), keys(ACTION, "outputs"), path)
            self.assertIn(f"pitangus-worker:{VERSION}", path.read_text(encoding="utf-8"), path)

    def test_the_self_test_job_uses_the_local_action(self):
        self.assertRegex((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"), r"(?m)^\s+uses: \./(\s|$)")


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class ActionScriptTests(unittest.TestCase):
    """The action's scripts, run as GitHub runs them (`bash -e -o pipefail`), with a fake docker that logs its calls."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        for folder in ("bin", "temp", "workspace/sub/dir", "workspace/reports"):
            (self.root / folder).mkdir(parents=True)
        for name, script in (("docker", FAKE_DOCKER), ("cosign", FAKE_COSIGN)):
            tool = self.root / "bin" / name
            tool.write_text(script)
            tool.chmod(0o755)
        (self.root / "workspace" / "a.sarif").write_text("{}")
        (self.root / "workspace" / "reports" / "b.sarif").write_text("{}")
        self.log = self.root / "calls.jsonl"
        self.output = self.root / "output"

    def run_step(self, index: int, inputs: dict | None = None, codes: str = "", **env) -> tuple[int, list[dict], dict]:
        step = steps(ACTION)[index]
        values = {**defaults(ACTION), **(inputs or {})}
        environment = {
            "PATH": f"{self.root / 'bin'}{os.pathsep}{os.environ['PATH']}", "RUNNER_TEMP": str(self.root / "temp"),
            "GITHUB_WORKSPACE": str(self.root / "workspace"), "GITHUB_OUTPUT": str(self.output),
            "GITHUB_REPOSITORY": "acme/shop", "GITHUB_ACTOR": "octocat", "FAKE_LOG": str(self.log), "FAKE_CODES": codes,
            "FAKE_LOCAL": "1", **step["literal"], **{variable: values[name] for variable, name in step["env"].items()}, **env}
        completed = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]],
                                   env=environment, capture_output=True, text=True, timeout=60)
        self.stdout = completed.stdout
        calls = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        outputs = dict(line.split("=", 1) for line in self.output.read_text().splitlines()) if self.output.exists() else {}
        return completed.returncode, calls, outputs

    def run_main(self, inputs: dict | None = None, codes: str = "", **env) -> tuple[int, list[dict], dict]:
        """The Pitangus step; `calls` are only the containers it starts (the checks are in `self.checks`)."""
        code, calls, outputs = self.run_step(MAIN, inputs, codes, **env)
        self.checks = [call for call in calls if call["argv"][:1] != ["run"]]
        return code, [call for call in calls if call["argv"][:1] == ["run"]], outputs

    def command(self, call: dict) -> list[str]:
        """What runs inside the container: everything after the image (the verified digest)."""
        return call["argv"][call["argv"].index(f"{PUBLISHED}@{DIGEST}") + 1:]

    def test_a_pull_request_scans_what_it_introduces(self):
        code, calls, outputs = self.run_main(GITHUB_BASE_REF="main")
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        argv = calls[0]["argv"]
        self.assertEqual(self.command(calls[0]), ["python", "-m", "pitangus", "scan", "/src", "--name", "shop",
                                                  "--fail-on", "high", "--format", "sarif", "--output",
                                                  "/data/result.sarif", "--summary", "/data/summary.md", "--base", "origin/main"])
        self.assertEqual(argv[:2], ["run", "--rm"])
        self.assertIn(f"{self.root / 'workspace'}:/src:ro", argv)
        self.assertIn(f"{self.root / 'temp' / 'pitangus'}:/data", argv)
        self.assertIn("PITANGUS_ENGINE_RUNNER=local", argv)
        self.assertIn(f"{os.getuid()}:{os.getgid()}", argv)
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
        self.assertFalse(any("docker.sock" in item for item in argv))
        self.assertIsNone(calls[0]["token"])
        sarif = self.root / "temp" / "pitangus.sarif"
        self.assertEqual(outputs, {"sarif": str(sarif), "exit-code": "0"})
        self.assertTrue(sarif.is_file())

    def test_inputs_become_arguments_without_a_shell(self):
        code, calls, outputs = self.run_main({
            "path": "./sub/dir/", "base": "main; touch pwned", "fail-on": "critical", "name": "$(touch pwned)",
            "exclude": "fixtures/\n  **/testdata  \n\n", "allow-incomplete": "true", "sarif": "out/pitangus.sarif"},
            codes="1")
        self.assertEqual(code, 1)
        self.assertEqual(self.command(calls[0]), [
            "python", "-m", "pitangus", "scan", "/src/sub/dir", "--name", "$(touch pwned)", "--fail-on", "critical",
            "--format", "sarif", "--output", "/data/result.sarif", "--summary", "/data/summary.md", "--base", "main; touch pwned",
            "--exclude", "fixtures/", "--exclude", "**/testdata", "--allow-incomplete"])
        self.assertEqual(outputs, {"sarif": str(self.root / "workspace" / "out" / "pitangus.sarif"), "exit-code": "1"})
        self.assertEqual(list(self.root.rglob("pwned")), [])

    def test_base_none_scans_everything_even_on_a_pull_request(self):
        code, calls, _ = self.run_main({"base": "none"}, codes="3", GITHUB_BASE_REF="main")
        self.assertEqual(code, 3)
        self.assertNotIn("--base", self.command(calls[0]))

    def test_usage_errors_stop_before_docker(self):
        for inputs in ({"path": "../elsewhere"}, {"path": "/etc"}, {"path": "sub/../../x"}, {"allow-incomplete": "yes"},
                       {"verify": "no"}, {"scan": "false"}, {"import-sarif": "a.sarif", "server": "https://t.example"},
                       {"import-sarif": "missing.sarif", "server": "https://t.example", "token": "t"}):
            with self.subTest(inputs=inputs):
                self.log.unlink(missing_ok=True)
                self.output.unlink(missing_ok=True)
                code, calls, outputs = self.run_main(inputs)
                self.assertEqual((code, outputs.get("exit-code")), (2, "2"))
                self.assertEqual(calls + self.checks, [])

    def test_import_only_passes_the_token_through_the_environment(self):
        code, calls, outputs = self.run_main({
            "scan": "false", "import-sarif": "a.sarif\n reports/b.sarif \n", "server": "https://pitangus.example.com",
            "token": "s3cret-token", "import-partial": "true"})
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.command(calls[0]), [
            "python", "-m", "pitangus", "import-sarif", "/data/import/1-a.sarif", "/data/import/2-b.sarif",
            "--asset", "acme/shop", "--server", "https://pitangus.example.com", "--partial"])
        self.assertEqual(calls[0]["token"], "s3cret-token")
        argv = calls[0]["argv"]
        self.assertIn("PITANGUS_IMPORT_TOKEN", argv)
        self.assertFalse(any("s3cret" in item for item in argv))
        self.assertEqual(outputs, {"exit-code": "0"})
        self.assertFalse((self.root / "temp" / "pitangus" / "import").exists())

    def test_scan_then_import_keeps_the_scan_verdict(self):
        code, calls, outputs = self.run_main({"import-sarif": "a.sarif", "server": "https://t.example",
                                                 "token": "t", "asset": "team/api"}, codes="1,0")
        self.assertEqual(code, 1)
        self.assertEqual([self.command(call)[3] for call in calls], ["scan", "import-sarif"])
        self.assertIsNone(calls[0]["token"])
        self.assertIn("team/api", self.command(calls[1]))
        self.assertEqual(outputs["exit-code"], "1")
        self.log.unlink()
        code, _, _ = self.run_main({"scan": "false", "import-sarif": "a.sarif", "server": "https://t.example",
                                       "token": "t"}, codes="2")
        self.assertEqual(code, 2)

    def test_the_image_runs_by_the_digest_whose_signature_was_checked(self):
        code, calls, _ = self.run_main()
        self.assertEqual(code, 0)
        inspect, digests, verify = self.checks
        self.assertEqual(inspect["argv"][:2], ["image", "inspect"])
        self.assertEqual(digests["argv"][-1], defaults(ACTION)["image"])
        self.assertEqual(verify["tool"], "cosign")
        argv = verify["argv"]
        self.assertEqual(argv[0], "verify")
        self.assertEqual(argv[argv.index("--certificate-oidc-issuer") + 1], "https://token.actions.githubusercontent.com")
        self.assertEqual(argv[argv.index("--certificate-identity-regexp") + 1], steps(ACTION)[MAIN]["literal"]["SIGNERS"])
        self.assertEqual(argv[-1], f"{PUBLISHED}@{DIGEST}")
        self.assertNotIn(defaults(ACTION)["image"], calls[0]["argv"])
        self.assertIn(f"Signature verified: {PUBLISHED}@{DIGEST}", self.stdout)

    def test_a_missing_image_is_pulled_before_resolving_its_digest(self):
        code, calls, _ = self.run_main({"image": f"{PUBLISHED}:0.10.4"}, FAKE_LOCAL="",
                                       FAKE_DIGESTS=f"ghcr.io/elsewhere/worker@sha256:{'cd' * 32} {PUBLISHED}@{DIGEST}")
        self.assertEqual(code, 0)
        self.assertEqual([call["argv"][0] for call in self.checks], ["image", "pull", "image", "verify"])
        self.assertEqual(self.checks[1]["argv"], ["pull", "--quiet", f"{PUBLISHED}:0.10.4"])
        self.assertEqual(self.checks[-1]["argv"][-1], f"{PUBLISHED}@{DIGEST}")
        self.assertEqual(len(calls), 1)

    def test_an_unsigned_or_unresolvable_image_never_runs(self):
        for env in ({"FAKE_COSIGN": "1"}, {"FAKE_DIGESTS": f"ghcr.io/elsewhere/worker@{DIGEST}"}, {"FAKE_DIGESTS": ""}):
            with self.subTest(env=env):
                self.log.unlink(missing_ok=True)
                self.output.unlink(missing_ok=True)
                code, calls, outputs = self.run_main(**env)
                self.assertEqual((code, outputs.get("exit-code")), (2, "2"))
                self.assertEqual(calls, [])
                self.assertIn("::error title=Pitangus::", self.stdout)

    def test_only_an_image_of_your_own_can_skip_the_check(self):
        code, calls, outputs = self.run_main({"verify": "false"})
        self.assertEqual((code, outputs.get("exit-code")), (2, "2"))
        self.assertEqual(calls + self.checks, [])
        for image in (f"{PUBLISHED}:0.10.4", f"{PUBLISHED}@{DIGEST}"):
            with self.subTest(image=image):
                self.output.unlink(missing_ok=True)
                code, calls, _ = self.run_main({"image": image, "verify": "false"})
                self.assertEqual(code, 2)
                self.assertEqual(calls, [])
        mirror = "registry.example.com:5000/team/pitangus-worker:0.10"
        self.output.unlink(missing_ok=True)
        code, calls, _ = self.run_main({"image": mirror, "verify": "false"})
        self.assertEqual(code, 0)
        self.assertEqual(self.checks, [])
        self.assertEqual(calls[0]["argv"][calls[0]["argv"].index(mirror) + 1:][:4], ["python", "-m", "pitangus", "scan"])
        self.assertIn(f"::warning title=Pitangus::Running {mirror} without checking its signature", self.stdout)

    def test_registry_login_reads_the_token_from_stdin_and_forgets_it(self):
        code, calls, _ = self.run_step(PULL, {"registry-token": "ghs_example"})
        self.assertEqual(code, 0)
        login, pull = calls
        self.assertEqual(login["argv"], ["login", "ghcr.io", "--username", "octocat", "--password-stdin"])
        self.assertEqual(login["stdin"], "ghs_example")
        self.assertEqual(pull["argv"], ["pull", "--quiet", defaults(ACTION)["image"]])
        self.assertTrue(login["docker_config"].startswith(str(self.root / "temp")))
        self.assertFalse(Path(login["docker_config"]).exists())


if __name__ == "__main__":
    unittest.main()
