"""Third-party code copied into a repository: recognised by the file's folders and content, never by its name nor by
the rule that fired; its SAST findings listed apart as excluded with why, never dropped and never fixed."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hypothesis import example, given, settings, strategies as st

from pitangus.modules.scanning import engines, vendored
from pitangus.modules.scanning.engines import parse_opengrep
from pitangus.shared.i18n import text

PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

HAND_WRITTEN = b"".join(b"export function render%d(items) {\n  const list = document.querySelector('#list');\n"
                        b"  list.innerHTML = items.map((item) => `<li>${item}</li>`).join('');\n}\n" % index for index in range(60))
# The project's own code with a critical match in it, large enough that size alone doesn't keep it.
EVAL = b"".join(b"export function run%d(input) {\n  // evaluate the expression the form sent\n  return eval(input);\n}\n" % index
                for index in range(120))
MINIFIED = b"(function(){var a=" + b"x.y(z),".join([b"q"] * 3000) + b"})();"
BANNER = b"/*!\n * Materialize v0.100.1 (http://materializecss.com)\n * MIT License\n */\n" + HAND_WRITTEN
OWN_HEADER = b"/*\n * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.\n * SPDX-License-Identifier: MIT\n */\n" + HAND_WRITTEN
OWN_BANNER = b"/*!\n * Acme Portal v2.3.0\n * Copyright (c) 2024 Acme Corp. All rights reserved.\n * Licensed under the MIT License.\n */\n" + EVAL
APACHE_HEADER = b"/**\n * Copyright 2017 Google Inc. All Rights Reserved.\n * Licensed under the Apache License, Version 2.0 (the \"License\");\n */\n" + EVAL
LARGE = HAND_WRITTEN * 4
THREE = b"/**\n * @author mrdoob / http://mrdoob.com/\n */\n\nvar THREE = { REVISION: '67' };\n\n" + LARGE
MARKERS = vendored.VENDOR_FOLDERS | vendored.LIBRARY_FOLDERS | vendored.STATIC_FOLDERS
own_folder = st.from_regex(r"[a-z][a-z0-9_-]{0,9}", fullmatch=True).filter(lambda name: name not in MARKERS)
own_name = st.from_regex(r"[a-z][a-zA-Z0-9]{2,11}", fullmatch=True)
# What anyone may call their own file: the names of libraries, their builds and plugins.
LIBRARY_NAMES = ["jquery-3.2.1.min.js", "jquery.form.js", "bootstrap-datepicker.js", "angular-route.js", "three.min.js", "three.js",
                 "d3.v5.js", "wysihtml5-0.3.0.js", "vue.esm.js", "lodash.core.js", "lodash-helpers.js", "moment-format.js",
                 "chart-core.js", "chart.js", "bootstrap.js", "materialize.js", "app.bundle.js", "vendor.min.js"]
script_name = st.one_of(st.sampled_from(LIBRARY_NAMES), st.builds(lambda name, suffix: name + suffix, own_name, st.sampled_from([".js", ".mjs", ".cjs"])))
own_path = st.builds(lambda folders, name, suffix: "/".join([*folders, name + suffix]), st.lists(own_folder, max_size=4), own_name,
                     st.sampled_from([".js", ".ts", ".mjs", ".py", ".java"]))
vendored_path = st.builds(lambda before, folder, after, name: "/".join([*before, folder, *after, name]), st.lists(own_folder, max_size=3),
                          st.sampled_from(sorted(vendored.VENDOR_FOLDERS)), st.lists(own_folder, max_size=2),
                          st.sampled_from(["app.js", "index.ts", "util.py", "Main.java"]))
library_path = st.builds(lambda folders, name: "/".join([*folders, name]), st.lists(own_folder, max_size=3), st.sampled_from(LIBRARY_NAMES))
# A known library's banner: its name opens it, with a release and a license, on a file as large as a library.
known_banner = st.builds(
    lambda name, version, license, body: (f"/*!\n * {name} v{version[0]}.{version[1]}.{version[2]}\n * (c) 2019 Its Authors | {license}\n */\n"
                                          .encode() + body),
    st.sampled_from(["jQuery JavaScript Library", "Bootstrap", "Chart.js", "Materialize", "Font Awesome Free", "Select2", "Popper.js",
                     "moment.js", "wysihtml5", "Ace", "D3", "Vue.js", "React", "AngularJS", "lodash"]),
    st.tuples(st.integers(0, 9), st.integers(0, 120), st.integers(0, 40)), st.sampled_from(["MIT License", "Released under the MIT license", "BSD"]),
    st.sampled_from([HAND_WRITTEN, EVAL, LARGE]))
third_party_content = st.one_of(st.just(MINIFIED), st.just(BANNER), st.just(THREE), known_banner)
own_content = st.sampled_from([HAND_WRITTEN, EVAL, OWN_HEADER, OWN_BANNER, APACHE_HEADER, b""])
contents = st.one_of(own_content, third_party_content, st.just(LARGE))
RULES = ["appsec.js.dom-xss-sink", "appsec.js.eval-non-literal", "gitlab.javascript.xss.rule-xss", "appsec.py.sql-injection"]


def finding(path: str, rule: str, line: int, scanner: str = "sast") -> dict:
    digest = f"{scanner}:{rule}:{path}:{line}"
    return {"scanner": scanner, "rule_id": rule, "path": path, "line": line, "severity": "medium", "fingerprint": digest}


class ClassifyTests(unittest.TestCase):
    @settings(max_examples=150 * SCALE)
    @given(vendored_path, contents)
    def test_a_vendor_folder_anywhere_is_third_party_whatever_the_file_says(self, path, content):
        self.assertEqual(vendored.classify(path, content)[0], "folder")

    @settings(max_examples=200 * SCALE)
    @given(st.lists(own_folder, max_size=4), script_name, script_name, contents)
    def test_the_file_name_never_decides(self, folders, name, other, content):
        """Metamorphic: the same bytes in the same folders under any other script name get the same answer."""
        verdict, renamed = vendored.classify("/".join([*folders, name]), content), vendored.classify("/".join([*folders, other]), content)
        self.assertEqual(verdict and verdict[0], renamed and renamed[0])
        self.assertEqual(verdict and verdict[0] == "banner" and verdict[1], renamed and renamed[0] == "banner" and renamed[1])

    @settings(max_examples=200 * SCALE)
    @given(st.lists(own_folder, max_size=4), script_name, own_content)
    @example(["lib", "utils"], "lodash-helpers.js", EVAL)
    @example(["src"], "moment-format.js", EVAL)
    @example(["src"], "chart-core.js", EVAL)
    @example(["src", "portal"], "app.js", OWN_BANNER)
    @example(["resources", "js"], "bootstrap.js", HAND_WRITTEN[:900])  # Laravel's own bootstrap file
    @example(["vanilla-js", "scripts"], "FriendlyEats.Data.js", APACHE_HEADER)  # "Version 2.0" of a license is no release
    def test_hand_written_code_is_the_project_own_whatever_it_is_called(self, folders, name, content):
        self.assertIsNone(vendored.classify("/".join([*folders, name]), content))

    @settings(max_examples=200 * SCALE)
    @given(st.lists(own_folder, max_size=4), script_name, third_party_content)
    def test_content_that_is_someone_else_stays_third_party_wherever_it_is(self, folders, name, content):
        self.assertIn(vendored.classify("/".join([*folders, name]), content)[0], ("minified", "banner"))

    @given(own_path)
    def test_hand_written_code_in_the_project_folders_is_the_project_own(self, path):
        for content in (HAND_WRITTEN, EVAL, OWN_HEADER, OWN_BANNER, b""):
            self.assertIsNone(vendored.classify(path, content))

    @given(known_banner)
    def test_a_known_banner_on_a_snippet_is_not_a_library(self, content):
        self.assertIsNone(vendored.classify("src/app.js", content[:content.index(b"*/") + 2] + b"\nexport const f = (x) => eval(x);\n"))

    def test_the_corpus_seeds(self):
        cases = {"src/main/resources/webgoat/static/js/libs/ace.js": (HAND_WRITTEN, "folder"),
                 "src/main/resources/webgoat/static/plugins/bootstrap-wysihtml5/js/wysihtml5-0.3.0.js": (HAND_WRITTEN, "folder"),
                 "sqli/static/js/materialize.js": (BANNER, "banner"), "frontend/src/assets/private/three.js": (THREE, "banner"),
                 "app/static/loader.js": (MINIFIED, "minified"), "public/js/jquery-3.2.1-min.js": (MINIFIED, "minified"),
                 "vulnerabilities/javascript/source/high_unobfuscated.js": (b"/**\n * [js-sha256]{@link https://github.com/emn178/js-sha256}\n"
                                                                            b" *\n * @version 0.9.0\n * @license MIT\n */\n" + HAND_WRITTEN, "banner")}
        for path, (content, kind) in cases.items():
            self.assertEqual(vendored.classify(path, content)[0], kind, path)
        for path in ("vulnerabilities/authbypass/authbypass.js", "src/main/resources/lessons/clientsidefiltering/js/clientSideFiltering.js",
                     "internal/ui/static/js/app.js", "frontend/src/assets/private/three.js"):
            self.assertIsNone(vendored.classify(path, HAND_WRITTEN), path)


class WithholdTests(unittest.TestCase):
    @settings(max_examples=60 * SCALE, deadline=None)
    @given(st.dictionaries(st.one_of(own_path, vendored_path, library_path), contents, min_size=1, max_size=6),
           st.lists(st.tuples(st.integers(0, 5), st.sampled_from(RULES), st.integers(1, 400), st.sampled_from(["sast", "sast", "secrets"])),
                    max_size=25), st.randoms(use_true_random=False))
    def test_the_split_reads_only_the_file_and_never_loses_a_finding(self, files, matches, random):
        paths = sorted(files)
        with tempfile.TemporaryDirectory() as folder:
            snapshot = Path(folder)
            for path, content in files.items():
                (snapshot / path).parent.mkdir(parents=True, exist_ok=True)
                (snapshot / path).write_bytes(content)
            found = list({item["fingerprint"]: item for item in (finding(paths[index % len(paths)], rule, line, scanner)
                                                                  for index, rule, line, scanner in matches)}.values())
            kept, withheld = vendored.withhold(found, snapshot)
            # Another rule firing at the same place, and any order: the same files are third-party.
            relabeled = [{**item, "rule_id": random.choice(RULES)} for item in random.sample(found, len(found))]
            kept_again, withheld_again = vendored.withhold(relabeled, snapshot)
        self.assertEqual(sorted(item["fingerprint"] for item in kept + withheld), sorted(item["fingerprint"] for item in found))
        self.assertEqual({item["fingerprint"] for item in withheld}, {item["fingerprint"] for item in withheld_again})
        for item in withheld:
            self.assertEqual(item["scanner"], "sast")
            self.assertTrue(vendored.is_vendored(item))
            self.assertIsNotNone(vendored.classify(item["path"], files[item["path"]]))
        for item in kept:
            self.assertFalse(item["scanner"] == "sast" and vendored.classify(item["path"], files[item["path"]]))
        self.assertTrue(all(item.get("excluded_reason") is None for item in kept + kept_again))

    def test_a_path_outside_the_snapshot_is_never_read(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "outside.js").write_bytes(MINIFIED)
            (Path(folder) / "snapshot").mkdir()
            self.assertEqual(vendored.read_head(Path(folder) / "snapshot", "../outside.js"), b"")


class OpengrepTests(unittest.TestCase):
    def match(self, path: str, line: int) -> dict:
        return {"check_id": "rules.appsec.js.eval-non-literal", "path": f"/src/{path}", "start": {"line": line},
                "extra": {"lines": "eval(code);", "severity": "ERROR", "message": "eval", "metadata": {"cwe": [95]}}}

    def test_opengrep_lists_matches_in_third_party_code_as_excluded_with_why(self):
        payload = {"results": [self.match("static/js/libs/ace.js", 3), self.match("src/app.js", 7)], "paths": {}}

        def run(key, arguments, snapshot, **options):
            return subprocess.CompletedProcess(arguments, 0, json.dumps(payload), "")

        with tempfile.TemporaryDirectory() as folder, patch.object(engines, "runner", return_value="docker"), \
                patch.object(engines, "docker_available", return_value=True), patch.object(engines, "image_available", return_value=True), \
                patch.object(engines, "_run", side_effect=run):
            for path in ("static/js/libs/ace.js", "src/app.js"):
                (Path(folder) / path).parent.mkdir(parents=True, exist_ok=True)
                (Path(folder) / path).write_bytes(HAND_WRITTEN)
            result = engines.run_opengrep(Path(folder))
        self.assertEqual([item["path"] for item in result["findings"]], ["src/app.js"])
        (apart,) = result["vendored"]
        self.assertEqual(apart["fingerprint"], next(item["fingerprint"] for item in parse_opengrep(payload) if item["path"] == apart["path"]))  # the same identity it had
        self.assertIn("static/js/libs", text(apart["excluded_reason"], "en"))
        self.assertIn("third-party code", text(result["detail"], "en"))

    def test_a_scan_keeps_them_as_excluded_and_says_how_many(self):
        from pitangus.modules.findings import registry
        from pitangus.modules.runs.store import save_repository_scan
        from pitangus.modules.scanning import repository
        payload = {"results": [self.match("public/lib/editor.js", 3), self.match("src/app.js", 7)]}

        def opengrep(root):
            kept, apart = vendored.withhold(parse_opengrep(payload), root)
            return {**engines._result("opengrep", "completed", "", kept), "vendored": apart}

        empty = lambda key: lambda *args, **kwargs: engines._result(key, "completed", "")  # noqa: E731
        replaced = {"engines_available": lambda: True, "host_mount_problem": lambda *args: None, "run_opengrep": opengrep,
                    "load_feeds": lambda *args: {"kev": {}, "epss": {}}, "run_betterleaks": empty("betterleaks"), "run_trivy": empty("trivy"),
                    "run_osv_scanner": empty("osv-scanner"), "run_checkov": empty("checkov"), "run_zizmor": empty("zizmor")}
        with tempfile.TemporaryDirectory() as folder:
            root, data_dir = Path(folder) / "code", Path(folder) / "data"
            for path in ("public/lib/editor.js", "src/app.js"):
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_bytes(HAND_WRITTEN)
            patches = [patch.object(repository, name, side_effect=value) for name, value in replaced.items()]
            for item in patches:
                item.start()
            try:
                source = {"id": "github:org/web", "uid": "github#8", "name": "org/web", "provider": "github"}
                record = save_repository_scan(data_dir, repository.scan_repository(root, source, data_dir=data_dir))
            finally:
                for item in patches:
                    item.stop()
            self.assertEqual([item["path"] for item in record["findings"]], ["src/app.js"])
            (apart,) = record["excluded_findings"]
            limitations = " ".join(text(item, "en") for item in record["limitations"])
            self.assertIn("1 SAST match is in third-party code", limitations)
            self.assertNotIn("nosemgrep", limitations)
            entry = registry.load(data_dir, "github#8")["findings"][apart["fingerprint"]]
            self.assertEqual((entry["status"], entry["excluded"]["reason"]["$t"]), ("excluded", "scanning.vendored.reason"))


if __name__ == "__main__":
    unittest.main()
