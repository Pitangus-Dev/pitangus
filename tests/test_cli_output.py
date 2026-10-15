"""What `pitangus scan` prints, as properties of any result rather than of the output that looked wrong.

- The verdict counts the rows it shows (a package's advisories are one row), in the text and in the Markdown summary.
- A count is said in the singular exactly when it is 1, in English and Spanish.
- Every engine that didn't run is named, once: in its progress line and in its "Not analyzed" line; one the operator
  didn't turn on isn't announced as running. Without any engine, the output names the core engines that didn't run.
- A prompt for an AI assistant never sends the reader to the panel's "Reverify".
- A reason a file went unexamined is a language-neutral code, rendered in the reader's language.
- The snapshot step says why each file was left out; an empty lockfile was read (0 packages), not skipped.
"""

import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hypothesis import HealthCheck, given, settings, strategies as st

from pitangus.modules.findings import ai_prompt, fix_guide
from pitangus.modules.pullrequests.review import SEVERITY_ORDER
from pitangus.modules.runs import local as local_scan
from pitangus.modules.scanning import engine_contract, engines
from pitangus.modules.scanning.engines import IMAGES, EngineStep, ScanContext, run_engines, with_cause
from pitangus.modules.sources.repositories import snapshot_directory
from pitangus.shared.i18n import catalog, msg, t, text

PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

SEVERITY = st.sampled_from(SEVERITY_ORDER)
PACKAGE = st.sampled_from([("package-lock.json", "lodash", "4.17.20"), ("package-lock.json", "minimatch", "3.0.4"),
                           ("requirements.txt", "urllib3", "1.26.4")])


@st.composite
def findings(draw):
    items = []
    for index in range(draw(st.integers(0, 14))):
        severity = draw(SEVERITY)
        if draw(st.booleans()):
            path, name, version = draw(PACKAGE)
            package = {"ecosystem": "npm", "name": name, "version": version,
                       "fixed_version": draw(st.sampled_from([None, "9.0.0", "9.1.0"]))}
            items.append({"fingerprint": f"sca-{index}", "path": path, "line": 1, "severity": severity, "scanner": "sca",
                          "title": f"advisory {index}", "rule_id": f"GHSA-{index}", "package": package})
        else:
            items.append({"fingerprint": f"code-{index}", "path": f"src/{index}.py", "line": index + 1, "severity": severity,
                          "scanner": "sast", "title": f"rule {index}", "rule_id": f"r{index}", "package": None})
    return items


def steps(failed=(), details=None):
    details = details or {}
    return [{"id": key, "name": f"{IMAGES[key]['name']} {IMAGES[key]['version']}",
             "status": "inconclusive" if key in failed else "completed", "detail": details.get(key, ""), "tool": {"name": key}}
            for key in ("opengrep", "betterleaks", "trivy", "osv-scanner", "checkov", "zizmor")]


def scanned(items, *, scan_steps=None, fail_on="high", docker=True, extra=None, **options):
    record = {"status": "completed", "findings": items, "steps": steps() if scan_steps is None else scan_steps, **(extra or {})}
    with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as data, \
            patch.object(local_scan, "scan_repository", return_value=record), \
            patch("pitangus.modules.scanning.engines.docker_available", return_value=docker), \
            patch("pitangus.modules.scanning.engines.docker_problem", return_value=msg("scanning.local.no_docker")):
        return local_scan.run(Path(folder), data_dir=Path(data), fail_on=fail_on, **options)


def rows_of(items) -> dict:
    """Rows as the terminal shows them, worked out independently: one per package version, one per other finding."""
    order = {level: index for index, level in enumerate(SEVERITY_ORDER)}
    rows: dict = {}
    for item in items:
        key = (item["path"], item["package"]["name"], item["package"]["version"]) if item["package"] else item["fingerprint"]
        rows[key] = min(rows.get(key, item["severity"]), item["severity"], key=lambda level: order[level])
    return rows


class CounterProperties(unittest.TestCase):
    @settings(max_examples=60 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(findings(), st.sampled_from(["critical", "high", "medium", "low", "never"]), st.sampled_from(["en", "es"]))
    def test_the_verdict_counts_the_rows_shown(self, items, fail_on, locale):
        result = scanned(items, fail_on=fail_on)
        rows = rows_of(items)
        limit = None if fail_on == "never" else SEVERITY_ORDER.index(fail_on)
        blocking = sum(1 for level in rows.values() if limit is not None and SEVERITY_ORDER.index(level) <= limit)
        expected = (t("pulls.verdict.blocking", locale, count=blocking, gate=text(msg(f"pulls.gate.{fail_on}"), locale)) if blocking
                    else t("pulls.verdict.below", locale, count=len(rows)) if rows else t("pulls.verdict.clean", locale))
        output = local_scan.render_text(result, locale=locale, limit=100)
        shown = [line for line in output.splitlines()
                 if re.match(r"^(?:%s)\s" % "|".join(re.escape(t(f"scanning.cli.severity.{level}", locale).upper()) for level in SEVERITY_ORDER), line)]
        self.assertEqual(len(shown), len(rows))
        self.assertIn(expected, output.splitlines()[-1])
        summary = local_scan.render_markdown(result, locale=locale)
        self.assertIn(expected, summary)
        if rows:
            self.assertIn(t("scanning.cli.summary.introduced", locale, count=len(rows)), summary)
        # The exit code follows the same rows: a row blocks when its worst advisory does.
        self.assertEqual(result["exit_code"] == local_scan.EXIT_BLOCKED, blocking > 0)


INLINE_FORM = re.compile(r"\{\{\s*(\w+)\s*\|([^|}]*)\|([^|}]*)\}\}")
INLINE = {key for key, value in catalog("en").items() if INLINE_FORM.search(value)}
# Messages the CLI renders with a count, and the noun or verb that has to agree with it.
PLURAL_KEYS = {"scanning.cli.preexisting": {}, "scanning.cli.excluded": {"patterns": "x"},
               "scanning.cli.advisories": {}, "scanning.cli.scope_changes": {"base": "main", "commit": "abc"},
               "scanning.cli.resolved.fixed": {}, "scanning.cli.resolved.deleted": {}, "scanning.cli.resolved.unattributed": {},
               "scanning.cli.unexamined": {"engine": "Trivy", "reason": "r", "paths": "a"}, "scanning.cli.left_out": {"paths": "a"},
               "scanning.opengrep.skipped": {}, "scanning.checkov.unparsed": {},
               "pulls.verdict.blocking": {"gate": "high"}, "pulls.verdict.below": {}}


class PluralProperties(unittest.TestCase):
    def test_every_counted_message_has_both_forms_in_both_languages(self):
        for key in PLURAL_KEYS:
            for locale in ("en", "es"):
                self.assertIn(f"{key}_one", catalog(locale), (key, locale))
                self.assertTrue(f"{key}_other" in catalog(locale) or key in catalog(locale), (key, locale))

    @settings(max_examples=40 * SCALE, deadline=None)
    @given(st.sampled_from(sorted(PLURAL_KEYS)), st.sampled_from(["en", "es"]), st.integers(0, 500))
    def test_one_is_said_in_the_singular_and_every_other_count_in_the_plural(self, key, locale, count):
        params = PLURAL_KEYS[key]
        rendered = t(key, locale, count=count, **params)
        one = t(key, locale, count=1, **params)
        if count == 1:
            self.assertEqual(rendered, one)
        else:
            # The sentence itself changes, not only the number in it.
            self.assertNotEqual(rendered.replace(str(count), "1"), one, (key, locale, count))

    @settings(max_examples=200 * SCALE, deadline=None)
    @given(st.sampled_from(sorted(INLINE)), st.data())
    def test_a_message_with_several_counts_agrees_with_each(self, key, data):
        """`{{name|# one|# other}}`: each count of the message takes its own form, in both languages, stored runs too."""
        names = sorted({name for locale in ("en", "es") for name, _, _ in INLINE_FORM.findall(catalog(locale)[key])})
        values = {name: data.draw(st.integers(0, 3), label=name) for name in names}
        for locale in ("en", "es"):
            source, rendered = catalog(locale)[key], t(key, locale, **values)
            self.assertEqual({name for name, _, _ in INLINE_FORM.findall(source)}, set(names), (key, locale))
            for name, one, other in INLINE_FORM.findall(source):
                form = (one if values[name] == 1 else other).replace("#", str(values[name]))
                self.assertIn(form, rendered, (key, locale, values))
        for locale, wrong in (("en", r"\b1 (?:are|were|match|files|secrets|manifests|advisories)\b"),
                              ("es", r"\b1 (?:son|coinciden|archivos|secretos|manifiestos|avisos)\b")):
            self.assertNotRegex(t(key, locale, **values), wrong)

    @settings(max_examples=10 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(st.integers(0, 3))
    def test_the_terminal_agrees_with_one_excluded_finding(self, skipped):
        hidden = {"fingerprint": "h", "path": "x/a.py", "line": 1, "severity": "low", "scanner": "sast", "title": "t",
                  "rule_id": "r", "package": None}
        output = local_scan.render_text(scanned([hidden] * min(skipped, 1), exclude=["x/**"]), locale="en")
        self.assertNotRegex(output, r"\b1 (?:are|were|files)\b|\b1 in excluded paths \(x/\*\*\): they")


DETAILS = [
    lambda key, name: msg("scanning.engines.timeout", engine=name),
    lambda key, name: msg("scanning.engines.unreadable", engine=name),
    lambda key, name: with_cause(msg("scanning.engines.failed_early", engine=name), None),
    lambda key, name: msg("scanning.contract.empty", engine=name),
    lambda key, name: msg("scanning.engines.disabled", engine=name, setting="PITANGUS_X_ENABLED"),
    lambda key, name: msg("scanning.join.sentences", first=msg("scanning.engines.timeout", engine=name), second="x"),
    lambda key, name: {"opengrep": msg("scanning.opengrep.timeout"), "trivy": msg("scanning.trivy.timeout"),
                       "osv-scanner": msg("scanning.osv.timeout"), "betterleaks": msg("scanning.betterleaks.unreadable"),
                       "checkov": msg("scanning.checkov.timeout")}.get(key, msg("scanning.local.no_docker")),
    lambda key, name: msg("scanning.local.no_docker"),
]


def count_name(line: str, name: str) -> int:
    return len(re.findall(rf"(?<![\w-]){re.escape(name)}(?![\w-])", line))


class EngineLineProperties(unittest.TestCase):
    @settings(max_examples=60 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(st.dictionaries(st.sampled_from(["opengrep", "betterleaks", "trivy", "osv-scanner", "checkov", "zizmor"]),
                           st.integers(0, len(DETAILS) - 1)), st.sampled_from(["en", "es"]))
    def test_an_engine_that_did_not_run_is_named_once(self, failures, locale):
        details = {key: DETAILS[index](key, IMAGES[key]["name"]) for key, index in failures.items()}
        result = scanned([], scan_steps=steps(failed=tuple(failures), details=details))
        lines = [line for line in local_scan.render_text(result, locale=locale).splitlines()
                 if line.startswith(t("scanning.cli.not_analyzed", locale, item=""))]
        self.assertEqual(len(lines), len(failures))
        for key in failures:
            name = IMAGES[key]["name"]
            counts = [count_name(line, name) for line in lines]
            self.assertEqual((max(counts), counts.count(1)), (1, 1), (key, lines))
            progress = text(engines.labelled(name, details[key]), locale)
            self.assertEqual(count_name(progress, name), 1, progress)

    @settings(max_examples=20 * SCALE, deadline=None)
    @given(st.booleans())
    def test_an_engine_turned_off_is_not_announced_as_running(self, checkov_on):
        said = []
        listed = [EngineStep(key, lambda context, key=key: engines.switched_off(key) or engines._result(key, "completed", ""),
                             f"scanning.progress.{'osv' if key == 'osv-scanner' else key}") for key in ("trivy", "checkov")]
        with patch.dict(os.environ, {"PITANGUS_CHECKOV_ENABLED": "1" if checkov_on else ""}):
            run_engines(listed, ScanContext(Path("."), Path("."), {}), lambda level, message: said.append(message))
        started = [item["$t"] for item in said if item["$t"].startswith("scanning.progress.") and item["$t"] != "scanning.progress.engine"]
        self.assertEqual(started, ["scanning.progress.trivy", *(["scanning.progress.checkov"] if checkov_on else [])])
        self.assertTrue(any(text(item, "en").startswith("Checkov") for item in said))  # its result is still said

    def test_without_engines_the_core_engines_are_named(self):
        result = scanned([], scan_steps=[], docker=False)
        output = local_scan.render_text(result, locale="en")
        for key in local_scan.CORE_ENGINES:
            self.assertIn(IMAGES[key]["name"], output)
        self.assertEqual(sorted(result["engines"]["failed"]), sorted(IMAGES[key]["name"] for key in local_scan.CORE_ENGINES))

    @settings(max_examples=30 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(st.lists(st.sampled_from(local_scan.CORE_ENGINES), unique=True), st.lists(st.sampled_from(local_scan.CORE_ENGINES), unique=True))
    def test_every_core_engine_either_ran_or_is_named_as_not_run(self, present, failed):
        result = scanned([], scan_steps=[step for step in steps(failed=tuple(failed)) if step["tool"]["name"] in present])
        ran, missing = result["engines"]["ran"], result["engines"]["failed"]
        self.assertEqual(len(ran) + len(missing), len(local_scan.CORE_ENGINES))
        for key in local_scan.CORE_ENGINES:
            self.assertEqual(sum(IMAGES[key]["name"] in item for item in ran + missing), 1, key)


SCANNERS = st.sampled_from(["secrets", "sast", "sca", "iac", "cicd", "dast"])


class PromptProperties(unittest.TestCase):
    def test_every_step_that_points_to_the_panel_is_marked(self):
        for locale, button in (("en", "Reverify"), ("es", "Reverificar")):
            pointing = {key.removesuffix("_one").removesuffix("_other") for key, value in catalog(locale).items()
                        if key.startswith("findings.fix.") and button in value}
            self.assertLessEqual(pointing, fix_guide.PANEL_STEPS, locale)

    @settings(max_examples=60 * SCALE, deadline=None)
    @given(SCANNERS, st.sampled_from([[], [798], [79]]), st.booleans(), st.sampled_from(["en", "es"]))
    def test_a_prompt_never_sends_the_reader_to_the_panel(self, scanner, cwe, package, locale):
        finding = {"fingerprint": "f", "scanner": scanner, "rule_id": "r", "title": "t", "path": "app/config.py", "line": 3,
                   "severity": "high", "reason": "why", "remediation": "do this", "cwe": cwe, "owasp": [], "snippet": "x = 1",
                   "package": {"ecosystem": "npm", "name": "lodash", "version": "4.17.20", "fixed_version": "4.17.21"} if package else None}
        attached = fix_guide.attach([finding])[0]
        rendered = ai_prompt.prompt(attached, locale)
        self.assertNotIn("Reverif", rendered)


class CoverageReasonProperties(unittest.TestCase):
    @settings(max_examples=100 * SCALE, deadline=None)
    @given(st.recursive(st.one_of(st.text(max_size=30), st.none(), st.integers()),
                        lambda inner: st.lists(inner, max_size=3) | st.tuples(inner, inner), max_leaves=6))
    def test_a_reason_is_always_a_code_never_a_repr(self, value):
        code = engine_contract.coverage("*", {"a.py": value})["unexamined"]["a.py"]
        self.assertRegex(code, r"^[a-z0-9_]{1,40}$")
        self.assertEqual(engine_contract.reason(code), code)  # stable once stored
        for locale in ("en", "es"):
            self.assertNotIn("{{", text(engine_contract.reason_message(code), locale))

    def test_opengrep_error_types_become_their_codes(self):
        self.assertEqual(engine_contract.reason(["PartialParsing", [{"path": "a.py"}]]), "partialparsing")
        self.assertEqual(engine_contract.reason("Syntax error"), "syntax_error")
        self.assertEqual(text(engine_contract.reason_message("partialparsing"), "es"), "lectura parcial")

    def test_unexamined_files_are_listed_per_engine_and_reason(self):
        coverage = {"opengrep": {"examined": "*", "unexamined": {"a.py": "partialparsing", "b.py": "partialparsing", "big.js": "left_out"}}}
        result = scanned([], extra={"coverage": coverage, "unexamined": {"*": ["big.js"]}})
        output = local_scan.render_text(result, locale="en")
        self.assertIn("Opengrep 1.30.0 didn't examine 2 files (only partly parsed): a.py, b.py", output)
        self.assertIn("1 file was left out of the copy", output)
        self.assertEqual(output.count("big.js"), 1)


class SnapshotProperties(unittest.TestCase):
    @settings(max_examples=25 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(st.integers(0, 3), st.integers(0, 3), st.integers(0, 3))
    def test_the_snapshot_says_why_each_file_was_left_out(self, binaries, large, kept):
        from pitangus.modules.sources import repositories
        with tempfile.TemporaryDirectory() as folder, patch.object(repositories, "MAX_FILE", 100):
            source = Path(folder) / "src"
            source.mkdir()
            for index in range(binaries):
                (source / f"image{index}.png").write_bytes(b"\x89PNG")
            for index in range(large):
                (source / f"big{index}.py").write_text("x" * 200)
            for index in range(kept):
                (source / f"ok{index}.py").write_text("x = 1\n")
            stats = snapshot_directory(source, Path(folder) / "head")
        self.assertEqual((stats["skipped_not_analyzable"], stats["skipped_too_large"], stats["files"]), (binaries, large, kept))
        detail = text(msg("scanning.repository.snapshot.skipped", detail="", skipped=binaries + large,
                          not_analyzable=stats["skipped_not_analyzable"], too_large=stats["skipped_too_large"]), "en")
        if binaries + large:
            self.assertIn(f"{binaries} not analyzable", detail)

    def test_an_empty_lockfile_was_read_with_no_packages(self):
        empty = {"package-lock.json": '{"lockfileVersion": 3, "packages": {"": {"name": "app"}}}', "yarn.lock": "# yarn lockfile v1\n\n",
                 "poetry.lock": "[metadata]\nlock-version = '2.0'\n", "go.mod": "module example.com/app\n\ngo 1.22\n",
                 "composer.lock": '{"packages": [], "packages-dev": []}', "Cargo.lock": "version = 3\n", "Gemfile.lock": "  \n"}
        broken = {"package-lock.json": '{"packages": {"node_modules/a": {"version": "1.0.0"}', "yarn.lock": 'a@^1:\n  version "1.0.0"\n',
                  "poetry.lock": "[[package]]\nname = 'a'\n", "go.mod": "module x\nrequire a v1.0.0\n", "Gemfile.lock": "GEM\n  specs:\n    a (1.0)\n"}
        for files, unexamined in ((empty, set()), (broken, set(broken))):
            with tempfile.TemporaryDirectory() as folder:
                for name, content in files.items():
                    (Path(folder) / name).write_text(content)
                reasons = engines.trivy_coverage(Path(folder), {"Results": []}, "")["unexamined"]
            self.assertEqual(set(reasons), unexamined)


if __name__ == "__main__":
    unittest.main()
