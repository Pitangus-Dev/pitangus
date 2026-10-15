"""The PR gate, on the server and in `pitangus scan --base`, judges with the registry's identity (A7): both sides are
grouped into families by `canonical` and copies are counted, so what a change introduces is exactly what grew.

Metamorphic, through the real parsers and a real diff: moving a copy introduces nothing, pasting one introduces one,
commenting or reformatting a vulnerable line introduces nothing. And applying a PR review never changes the main
branch's families or counts in the registry.

Across files (S1): the whole repository decides, and renamed files map to their base (GitHub's `previous_filename`,
`git diff -M`): moving a line to another file or renaming a file introduces nothing, copying a line into another file
introduces one; for random edit scripts (move, rename, copy, delete, comment) over several files, the server's review
and the command line, each from its own diff, report the same, and as many as the repository's copies grew; what the
command line reports fixed is the same comparison the other way round (a move or a rename fixes nothing).
"""

import difflib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from hypothesis import HealthCheck, example, given, settings, strategies as st

from pitangus.modules.findings import canonical, registry
from pitangus.modules.pullrequests import review
from pitangus.modules.runs import local as local_scan
from pitangus.modules.runs.store import save_and_apply
from pitangus.modules.scanning import config_engines, engines, sarif_import
from test_dashboard import _scan
from test_invariants import SCALE

RULES = {"os.system(": "appsec.py.shell-command-non-literal", "eval(": "appsec.py.eval-exec-non-literal",
         "shell=True": "appsec.py.subprocess-shell-true"}
VULNERABLE = ["os.system(cmd)", "eval(data)", "subprocess.run(cmd, shell=True)"]
BENIGN = ["x = 1", "print(x)", "total = x + 2", "def handler(cmd):", "return None"]


def opengrep(text: str, path: str = "app.py") -> list[dict]:
    """What Opengrep reports on this file for three of our rules, through its real parser."""
    results = [{"check_id": f"rules.{rule}", "path": f"/src/{path}", "start": {"line": number},
                "extra": {"lines": line, "severity": "ERROR", "metadata": {}}}
               for number, line in enumerate(text.splitlines(), 1) for marker, rule in RULES.items() if marker in line]
    return engines.parse_opengrep({"results": results})


def codeql(text: str, path: str = "app.py") -> list[dict]:
    """The same matches as an imported CodeQL SARIF, through its real parser."""
    results = [{"ruleId": rule, "message": {"text": "Command built from user input"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}, "region": {"startLine": number, "snippet": {"text": line}}}}]}
               for number, line in enumerate(text.splitlines(), 1) for marker, rule in RULES.items() if marker in line]
    return sarif_import.parse({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": results}]})[0]["findings"]


PARSERS = {"opengrep": opengrep, "codeql": codeql}


def text_of(lines: list[str]) -> str:
    return "".join(f"{line}\n" for line in lines)


def changed(base: list[str], head: list[str], path: str = "app.py") -> dict:
    """The head's changed lines, from a real unified diff (as GitHub and `git diff --unified=0` give it)."""
    patch_text = "".join(difflib.unified_diff(text_of(base).splitlines(True), text_of(head).splitlines(True), n=0))
    return review.changed_lines([{"filename": path, "status": "modified", "patch": patch_text}])


def introduced(parser, base: list[str], head: list[str], baseline=None) -> list[dict]:
    before = parser(text_of(base)) if baseline is None else baseline
    return review.classify(parser(text_of(head)), changed(base, head), before)["introduced"]


def counts(findings: list[dict]) -> Counter:
    """The registry's own families and counts: what a v2 run stores."""
    return Counter({family["fingerprint"]: family["count"] for family in canonical.collapse(findings)})


files = st.lists(st.sampled_from(VULNERABLE + BENIGN), min_size=1, max_size=12).filter(lambda lines: any(line in VULNERABLE for line in lines))


def vulnerable(lines: list[str]) -> list[int]:
    return [index for index, line in enumerate(lines) if line in VULNERABLE]


class MetamorphicTests(unittest.TestCase):
    @settings(max_examples=150 * SCALE, deadline=None)
    @given(files, st.data(), st.sampled_from(sorted(PARSERS)))
    def test_moving_a_copy_introduces_nothing(self, base, data, parser):
        index = data.draw(st.sampled_from(vulnerable(base)))
        rest = base[:index] + base[index + 1:]
        to = data.draw(st.integers(0, len(rest)))
        head = rest[:to] + [base[index]] + rest[to:]
        self.assertEqual(introduced(PARSERS[parser], base, head), [], (base, head))

    @settings(max_examples=150 * SCALE, deadline=None)
    @given(files, st.data(), st.sampled_from(sorted(PARSERS)))
    def test_pasting_a_copy_introduces_exactly_one_of_its_family(self, base, data, parser):
        index = data.draw(st.sampled_from(vulnerable(base)))
        to = data.draw(st.integers(0, len(base)))
        head = base[:to] + [base[index]] + base[to:]
        found = introduced(PARSERS[parser], base, head)
        family = canonical.identity_of(next(item for item in PARSERS[parser](text_of([base[index]]))))
        self.assertEqual([canonical.identity_of(item) for item in found], [family], (base, head))

    @settings(max_examples=150 * SCALE, deadline=None)
    @given(files, st.data(), st.sampled_from(sorted(PARSERS)),
           st.sampled_from(["  # nosec", "  # noqa: S605", "  # TODO: validate cmd", "    "]),
           st.sampled_from([("(", "( "), (")", " )"), (", ", " ,  "), ("", "    ")]))
    def test_commenting_or_reformatting_a_vulnerable_line_introduces_nothing(self, base, data, parser, comment, spacing):
        index = data.draw(st.sampled_from(vulnerable(base)))
        old, new = spacing
        edited = (base[index].replace(old, new) if old else new + base[index]) + data.draw(st.sampled_from(["", comment]))
        head = base[:index] + [edited] + base[index + 1:]
        self.assertEqual(introduced(PARSERS[parser], base, head), [], (base, head))


class SameFunctionAsTheRegistryTests(unittest.TestCase):
    @settings(max_examples=200 * SCALE, deadline=None)
    @given(files, files, st.sampled_from(sorted(PARSERS)))
    def test_what_is_introduced_is_what_grew_whatever_shape_the_baseline_has(self, base, head, parser):
        parse = PARSERS[parser]
        before, after = parse(text_of(base)), parse(text_of(head))
        grew = Counter({family: count - counts(before)[family] for family, count in counts(after).items() if count > counts(before)[family]})
        everything = {"app.py": None}  # the whole file changed: every instance that grew is reported
        # The baseline as the CLI has it (an engine's reports), as a v2 run stores it (grouped) and as v1/shadow did.
        for shape, baseline in (("raw", before), ("v2", canonical.collapse(before)), ("shadow", canonical.annotate(before)[0])):
            found = review.classify(after, everything, baseline)["introduced"]
            self.assertEqual(Counter(canonical.identity_of(item) for item in found), grew, (shape, base, head))


class MainBranchUntouchedTests(unittest.TestCase):
    """A PR review is recorded, but the main branch's entries, families and counts stay byte for byte."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.clock = datetime.now(timezone.utc)
        self.examples = 0
        mode = patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": "v2", "PITANGUS_COVERAGE_MODE": "on"})
        mode.start()
        self.addCleanup(mode.stop)

    def save(self, key, findings, **extra):
        self.clock += timedelta(hours=1)
        record = {**_scan("org/api", findings, self.clock.isoformat()), "finished_at": self.clock.isoformat(),
                  "coverage": {"opengrep": {"examined": "*", "unexamined": {}}}, **extra}
        record["summary"]["tools"] = [{"name": "opengrep", "version": "1", "status": "completed"}]
        record["source"]["uid"] = key
        return save_and_apply(self.data_dir, record, created_at=self.clock.isoformat())[0]

    @settings(max_examples=12 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    @given(files, st.lists(files, min_size=1, max_size=3))
    def test_reviewing_a_pr_never_changes_the_main_branch_registry(self, base, heads):
        self.examples += 1
        key = f"github#pr-{self.examples}"
        main = self.save(key, opengrep(text_of(base)))
        before = json.dumps(registry.load(self.data_dir, key)["findings"], sort_keys=True)
        for head in heads:  # the PR pushed again and again
            outcome = review.classify(opengrep(text_of(head)), changed(base, head), main["findings"])
            self.save(key, outcome["introduced"], type="pr_review", variant="pull_request",
                      pull_request={"number": 7, "head_sha": "c" * 40, "head_ref": "feat", "base_ref": "main"})
        after = registry.load(self.data_dir, key)["findings"]
        main_entries = json.loads(before)
        self.assertEqual(json.dumps({digest: after.get(digest) for digest in main_entries}, sort_keys=True), before, (base, heads))
        # What the PR brought that main didn't have is recorded as the PR's.
        for digest, entry in after.items():
            if digest not in main_entries:
                self.assertEqual(entry["origin"]["kind"], "pr")


def every(parser, tree: dict[str, list[str]]) -> list[dict]:
    """What `parser` reports over every file of `tree` ({path: lines})."""
    return [finding for path in sorted(tree) for finding in parser(text_of(tree[path]), path)]


def unified(before: list[str], after: list[str]) -> str:
    lines = list(difflib.unified_diff(text_of(before).splitlines(True), text_of(after).splitlines(True), n=3))
    return "".join(lines[2:])


def github_files(base: dict[str, list[str]], head: dict[str, list[str]], renamed: dict[str, str], patch_of=None) -> list[dict]:
    """The PR's files as GitHub's API lists them: patches with three lines of context and no file header, a renamed
    file with its `previous_filename` (no patch and no changes when only renamed). `patch_of(base path, head path)`:
    the patch as git writes it (GitHub's), difflib's by default."""
    patch_of = patch_of or (lambda previous, path: unified(base.get(previous) or [], head[path]))
    files = []
    for path in sorted(head):
        if path in renamed:
            previous = renamed[path]
            body = patch_of(previous, path) if base[previous] != head[path] else ""
            files.append({"filename": path, "status": "renamed", "previous_filename": previous, "changes": body.count("\n+") + body.count("\n-"),
                          **({"patch": body} if body else {})})
        elif path not in base:
            files.append({"filename": path, "status": "added", "patch": unified([], head[path])})
        elif base[path] != head[path]:
            files.append({"filename": path, "status": "modified", "patch": patch_of(path, path)})
    gone = set(base) - set(head) - set(renamed.values())
    return files + [{"filename": path, "status": "removed", "patch": None} for path in sorted(gone)]


def server(parser, base: dict[str, list[str]], head: dict[str, list[str]], renamed: dict[str, str], patch_of=None) -> list[dict]:
    """The server's review: GitHub's files and the base as a v2 run stores it."""
    files = github_files(base, head, renamed, patch_of)
    return review.classify(every(parser, head), review.changed_lines(files), canonical.collapse(every(parser, base)), review.renames(files))["introduced"]


def grew(base: dict[str, list[str]], head: dict[str, list[str]]) -> int:
    """How many vulnerable lines the repository has more of, line by line (a comment changes no line)."""
    def counted(tree):
        return Counter(line.split("  #")[0] for lines in tree.values() for line in lines if line.split("  #")[0] in VULNERABLE)
    before, after = counted(base), counted(head)
    return sum(max(0, count - before[line]) for line, count in after.items())


class AcrossFilesTests(unittest.TestCase):
    BASE = {"app.py": ["def handler(cmd):", "os.system(cmd)", "eval(data)", "x = 1"], "lib.py": ["def helper():", "return None"]}

    def test_moving_a_line_to_another_file_renaming_a_file_or_copying_a_line_into_another(self):
        base = self.BASE
        cases = {
            "moved to another file": ({"app.py": ["def handler(cmd):", "eval(data)", "x = 1"], "lib.py": ["def helper():", "os.system(cmd)", "return None"]}, {}, 0),
            "file renamed": ({"service.py": base["app.py"], "lib.py": base["lib.py"]}, {"service.py": "app.py"}, 0),
            "renamed and edited": ({"service.py": [*base["app.py"], "print(x)"], "lib.py": base["lib.py"]}, {"service.py": "app.py"}, 0),
            "renamed and moved out": ({"service.py": ["def handler(cmd):", "eval(data)", "x = 1"], "lib.py": ["os.system(cmd)", *base["lib.py"]]},
                                      {"service.py": "app.py"}, 0),
            "copied into another file": ({"app.py": base["app.py"], "lib.py": ["def helper():", "os.system(cmd)", "return None"]}, {}, 1),
            "copied into a new file": ({**base, "tools.py": ["eval(data)"]}, {}, 1),
            "moved and commented": ({"app.py": ["def handler(cmd):", "os.system(cmd)", "x = 1"], "lib.py": ["eval(data)  # nosec", *base["lib.py"]]}, {}, 0),
        }
        for parser in sorted(PARSERS):
            for name, (head, renamed, expected) in cases.items():
                with self.subTest(parser=parser, case=name):
                    found = server(PARSERS[parser], base, head, renamed)
                    self.assertEqual(len(found), expected, found)

    def test_a_renamed_file_maps_to_its_base_even_when_its_findings_read_no_code(self):
        """Checkov without a resource identifies a finding by its rule in its file: only the rename says it is the same."""
        def checkov(path: str) -> list[dict]:
            return config_engines.parse_checkov({"check_type": "dockerfile", "results": {"failed_checks": [
                {"check_id": "CKV_DOCKER_2", "check_name": "Ensure that HEALTHCHECK instructions have been added", "file_path": f"/{path}",
                 "file_line_range": [1, 3], "resource": ""}]}})
        before, after = checkov("Dockerfile"), checkov("docker/api.Dockerfile")
        for files in ([{"filename": "docker/api.Dockerfile", "status": "renamed", "previous_filename": "Dockerfile", "changes": 0}],
                      [{"filename": "docker/api.Dockerfile", "status": "renamed", "previous_filename": "Dockerfile", "changes": 4000}]):
            with self.subTest(changes=files[0]["changes"]):
                outcome = review.classify(after, review.changed_lines(files), canonical.collapse(before), review.renames(files))
                self.assertEqual(outcome["introduced"], [])
        # The same file added fresh (no rename) is new, and so is the rule in a new file while the old one is fixed: with
        # no code to compare, two files are two problems.
        added = [{"filename": "docker/api.Dockerfile", "status": "added", "patch": None}]
        self.assertEqual(len(review.classify([*before, *after], review.changed_lines(added), before, review.renames(added))["introduced"]), 1)
        self.assertEqual(len(review.classify(after, review.changed_lines(added), before, review.renames(added))["introduced"]), 1)


GIT = shutil.which("git")


@unittest.skipUnless(GIT, "hace falta git")
class CommandLineTests(unittest.TestCase):
    """`pitangus scan --base`, with a real repository and its real diff and base snapshot: the engines read the
    snapshot they are given (Opengrep's parser over its files), so the comparison is the CLI's own."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name) / "repo"
        self.repo.mkdir()
        for args in (("init", "-q", "-b", "main"), ("config", "user.email", "t@t"), ("config", "user.name", "t")):
            self.git(*args)

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True)

    def gate(self, base: list[str], head: list[str]) -> dict:
        (self.repo / "app.py").write_text(text_of(base))
        self.git("add", "-A")
        self.git("commit", "-qm", "base", "--allow-empty")
        self.git("checkout", "-qB", "feature")
        (self.repo / "app.py").write_text(text_of(head))

        def scan(root, *args, **kwargs):
            findings = opengrep((root / "app.py").read_text()) if (root / "app.py").exists() else []
            steps = [{"id": tool, "name": tool, "status": "completed", "detail": "", "tool": {"name": tool}} for tool in local_scan.CORE_ENGINES]
            return {"status": "completed", "findings": [{**item, "severity": "high"} for item in findings], "steps": steps}

        with tempfile.TemporaryDirectory() as data, patch.object(local_scan, "scan_repository", side_effect=scan), \
                patch("pitangus.modules.scanning.engines.docker_available", return_value=True):
            result = local_scan.run(self.repo, data_dir=Path(data), base="main")
        self.git("checkout", "-q", "main")
        self.git("branch", "-qD", "feature")
        return result

    def test_the_command_line_gate_is_the_registry_comparison(self):
        base = ["def handler(cmd):", "os.system(cmd)", "eval(data)", "x = 1"]
        cases = {"moved": (["eval(data)", "x = 1", "def handler(cmd):", "os.system(cmd)"], 0),
                 "commented": (["def handler(cmd):", "os.system(cmd)  # nosec", "eval( data )", "x = 1"], 0),
                 "pasted": (["def handler(cmd):", "os.system(cmd)", "os.system(cmd)", "eval(data)", "x = 1"], 1)}
        for name, (head, expected) in cases.items():
            with self.subTest(name):
                result = self.gate(base, head)
                self.assertEqual(len(result["findings"]), expected, result["findings"])
                server = review.classify(opengrep(text_of(head)), changed(base, head), canonical.collapse(opengrep(text_of(base))))
                self.assertEqual(sorted(canonical.identity_of(item) for item in result["findings"]),
                                 sorted(canonical.identity_of(item) for item in server["introduced"]))
                self.assertEqual(result["exit_code"], local_scan.EXIT_BLOCKED if expected else local_scan.EXIT_OK)


OPERATIONS = ("move", "rename", "copy", "delete", "comment")


def edited(base: dict[str, list[str]], script: list[tuple[str, int, int, int]]) -> dict[str, list[str]]:
    """`base` after an edit script: each step picks its file, line and destination by index (modulo what exists)."""
    tree = {path: list(lines) for path, lines in base.items()}
    for operation, first, second, third in script:
        names = sorted(tree)
        source = names[first % len(names)]
        lines = tree[source]
        index = second % len(lines)
        if operation == "rename":
            name = f"moved{third % 3}/{source.rsplit('/', 1)[-1]}"
            if name not in tree:
                tree[name] = tree.pop(source)
        elif operation == "comment":
            if "  #" not in lines[index]:
                lines[index] += "  # checked"
        elif operation == "delete":
            if len(lines) > 1:
                lines.pop(index)
        else:
            target = tree[names[third % len(names)]]
            if operation == "move":
                if len(lines) == 1:
                    continue
                line = lines.pop(index)
            else:
                line = lines[index]
            target.insert((second + third) % (len(target) + 1), line)
    return tree


trees = st.dictionaries(st.sampled_from(["app.py", "lib.py", "pkg/util.py"]), st.lists(st.sampled_from(VULNERABLE + BENIGN), min_size=1, max_size=6),
                        min_size=1, max_size=3).filter(lambda tree: any(line in VULNERABLE for lines in tree.values() for line in lines))
scripts = st.lists(st.tuples(st.sampled_from(OPERATIONS), st.integers(0, 50), st.integers(0, 50), st.integers(0, 50)), min_size=1, max_size=5)


@unittest.skipUnless(shutil.which("git"), "hace falta git")
class ServerAndCommandLineTests(unittest.TestCase):
    """For random edit scripts, the server (GitHub's files, renames from `previous_filename`, the base as a v2 run)
    and `pitangus scan --base` (a real repository, `git diff -M`, the base scanned from its snapshot) report the
    same, and as many as the repository's copies of each vulnerable line grew."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.count = 0

    def git(self, repo: Path, *args) -> str:
        return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout

    def write(self, repo: Path, tree: dict[str, list[str]]) -> None:
        for path in repo.rglob("*.py"):
            path.unlink()
        for path, lines in tree.items():
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_text(text_of(lines))

    def command_line(self, base: dict[str, list[str]], head: dict[str, list[str]]):
        self.count += 1
        repo = Path(self.directory.name) / f"repo{self.count}"
        repo.mkdir()
        for args in (("init", "-q", "-b", "main"), ("config", "user.email", "t@t"), ("config", "user.name", "t")):
            self.git(repo, *args)
        self.write(repo, base)
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "base")
        self.git(repo, "checkout", "-qb", "feature")
        self.write(repo, head)
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "head", "--allow-empty")
        renamed = {}
        for row in self.git(repo, "diff", "-M", "--name-status", "main", "feature").splitlines():
            status, *paths = row.split("\t")
            if status.startswith("R"):
                renamed[paths[1]] = paths[0]

        def scan(root, *args, **kwargs):
            tree = {path.relative_to(root).as_posix(): path.read_text().splitlines() for path in root.rglob("*.py")}
            steps = [{"id": tool, "name": tool, "status": "completed", "detail": "", "tool": {"name": tool}} for tool in local_scan.CORE_ENGINES]
            return {"status": "completed", "findings": [{**item, "severity": "high"} for item in every(opengrep, tree)], "steps": steps}

        with tempfile.TemporaryDirectory() as data, patch.object(local_scan, "scan_repository", side_effect=scan), \
                patch("pitangus.modules.scanning.engines.docker_available", return_value=True):
            found = local_scan.run(repo, data_dir=Path(data), base="main")

        def patch_of(previous: str, path: str) -> str:
            # Which copy of a repeated line is the added one is the diff's choice: GitHub's is git's.
            text = self.git(repo, "diff", "-U3", "--no-color", f"main:{previous}", f"feature:{path}")
            return text[text.index("@@"):] if "@@" in text else ""
        return found, renamed, patch_of

    @settings(max_examples=40 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    @given(trees, scripts)
    @example(base={"app.py": ["os.system(cmd)", "eval(data)"]}, script=[("copy", 0, 0, 0)])   # which copy is new: the diff's choice
    @example(base={"app.py": ["os.system(cmd)", "x = 1"], "lib.py": ["print(x)"]}, script=[("rename", 0, 0, 1), ("move", 0, 0, 1)])
    def test_the_server_and_the_command_line_report_the_same_and_only_what_grew(self, base, script):
        head = edited(base, script)
        result, renamed, patch_of = self.command_line(base, head)
        found = result["findings"]
        online = [{**item, "severity": "high"} for item in server(opengrep, base, head, renamed, patch_of)]
        where = lambda items: sorted((item["path"], item["line"], item["rule_id"]) for item in items)  # noqa: E731
        self.assertEqual(where(found), where(online), (base, head, renamed))
        self.assertEqual(len(found), grew(base, head), (base, head, renamed))
        # What the change fixes is the same comparison the other way round: never the same copy as introduced and fixed.
        self.assertEqual(len(result["resolved"]), grew(head, base), (base, head, renamed))
        introduced, fixed = ({item["snippet"].split("  #")[0] for item in items} for items in (found, result["resolved"]))
        self.assertEqual(introduced & fixed, set(), (base, head, renamed))

    def test_moving_or_renaming_fixes_nothing_and_deleting_fixes_one(self):
        base = {"app.py": ["def handler(cmd):", "os.system(cmd)", "eval(data)", "x = 1"], "lib.py": ["def helper():", "return None"]}
        cases = {"moved to another file": ({"app.py": ["def handler(cmd):", "eval(data)", "x = 1"], "lib.py": ["def helper():", "os.system(cmd)", "return None"]}, 0),
                 "file renamed": ({"service.py": base["app.py"], "lib.py": base["lib.py"]}, 0),
                 "renamed and a line deleted": ({"service.py": ["def handler(cmd):", "os.system(cmd)", "x = 1"], "lib.py": base["lib.py"]}, 1),
                 "deleted": ({"app.py": ["def handler(cmd):", "eval(data)", "x = 1"], "lib.py": base["lib.py"]}, 1)}
        for name, (head, fixed) in cases.items():
            with self.subTest(name):
                result, renamed, _ = self.command_line(base, head)
                self.assertEqual((len(result["findings"]), len(result["resolved"])), (0, fixed), result["resolved"])
                self.assertEqual([item["resolution"] for item in result["resolved"]], ["fixed"] * fixed)


if __name__ == "__main__":
    unittest.main()
