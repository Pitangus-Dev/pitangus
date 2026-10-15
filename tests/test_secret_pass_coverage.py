"""What a secret engine passes over on its own is declared (S6): Pitangus owns each engine's exclusion list, and a file
the engine's own log doesn't name as read is unexamined by it, whatever made the engine pass over it.

The property: a secret in any committed file is found by each secret engine, or the file is unexamined for that engine,
so nothing it saw there before is taken as fixed. The engines here pass over files by lists of their own that Pitangus
never sees (drawn at random): the mechanism can't depend on knowing them. The seeds (`node_modules/@acme/internal/
index.js`, `deploy/lambda/node_modules/…`) are what the built-in lists of Betterleaks 1.9 and Trivy 0.75 skipped."""

import io
import json
import os
import random
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from hypothesis import HealthCheck, example, given, settings, strategies as st

from pitangus.modules.scanning.secret_location import entropy
from pitangus.modules.findings import registry
from pitangus.modules.scanning import engine_contract, engines, repository, secret_coverage
from pitangus.modules.sources.repositories import _extract_limited, secrets_root
from pitangus.shared import coverage_units

PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

SECRET_ENGINES = ("betterleaks", "trivy")
ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
# High-entropy tokens of shapes both engines know, drawn at random (from a seed: a shrunk `0000…` would be a placeholder,
# which the secret filter rightly sets aside).
SHAPES = (lambda pick: "sk_live_" + pick(ALNUM, 24 + len(pick("0123", 1)) * 4), lambda pick: "ghp_" + pick(ALNUM, 36),
          lambda pick: "AKIA" + pick("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16),
          lambda pick: "xoxb-" + pick("0123456789", 11) + "-" + pick("0123456789", 12) + "-" + pick("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 24))


def _token(shape: int, seed: int) -> str:
    chooser = random.Random(seed)
    return SHAPES[shape](lambda alphabet, size: "".join(chooser.choice(alphabet) for _ in range(size)))


TOKEN = st.builds(_token, st.integers(0, len(SHAPES) - 1), st.integers(0, 2 ** 32))
TOKEN_SHAPE = re.compile(r"sk_live_[A-Za-z0-9]{24,40}|ghp_[A-Za-z0-9]{36}|AKIA[A-Z2-7]{16}|xoxb-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z]{24}")
FOLDERS = ["node_modules", "@acme", "internal", "vendor", "dist", "build", "deploy", "lambda", ".git-old", ".gitx", ".github",
           ".hg", ".pnpm", "test", "tests", "examples", "locale", "site-packages", "bower_components", "src", "lib", "out",
           "go", "pkg", "mod", "usr", "share", "a b", "ñandú"]
NAMES = ["index.js", "app.min.js", "jquery-3.7.1.min.js", "bundle.js.map", "package-lock.json", "yarn.lock", "go.sum", "README.md",
         "blob.bin", "data.dat", "logo.png", "font.woff2", "x.pyc", "Pipfile.lock", ".env.local", "config.yml", "settings.gradle",
         "credentials", "gitleaks.toml", ".gitleaksignore", "Makefile", "q\"uote.js"]
segment = st.one_of(st.sampled_from(FOLDERS), st.from_regex(r"[a-z][a-z0-9_.-]{0,10}", fullmatch=True).filter(lambda name: name not in (".", "..", ".git")))
filename = st.one_of(st.sampled_from(NAMES), st.from_regex(r"[a-z][a-z0-9_-]{0,8}\.(js|ts|py|txt|json|cfg|lock|min\.js|bin|dat|svg)", fullmatch=True))
committed_path = st.builds(lambda folders, name: "/".join([*folders, name]), st.lists(segment, max_size=8), filename)
STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"   # built here, so the repository's own scan doesn't flag this file
SEEDS = ["node_modules/@acme/internal/index.js", "deploy/lambda/node_modules/@acme/internal/index.js"]

# What the engines' built-in lists skip at the pinned versions (a sample): applied only when the configuration Pitangus
# hands them leaves them on, as the real engines do.
BETTERLEAKS_BUILT_IN = re.compile(r"(?:^|/)node_modules(?:/.*)?$|(?:^|/)vendor/(?:github\.com|golang\.org/x)|(?i:\.(?:png|bin|woff2?))$"
                                  r"|(?:^|/)(?:package-lock\.json|yarn\.lock|Pipfile\.lock)$|(?:^|/)jquery[^/]*\.js$|go\.sum$|gitleaks\.toml")
TRIVY_SKIPS = re.compile(r"(?:^|/)node_modules/|(?:^|/)(?:go\.sum|package-lock\.json|yarn\.lock|Pipfile\.lock)$|\.(?:png|bin|svg)$")
TRIVY_ALLOW = re.compile(r"(^(?i:test)|/test|-test|_test|\.test)|example|/vendor/|/locales?/|\.md$")


def archive(files: dict[str, bytes]) -> bytes:
    blob = io.BytesIO()
    with tarfile.open(fileobj=blob, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(f"repo-abc123/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return blob.getvalue()


def _mounted(mounts: list[str]) -> dict[str, Path]:
    return {spec.split(":")[1]: Path(spec.split(":")[0]) for flag, spec in zip(mounts[::2], mounts[1::2]) if flag == "-v"}


class SecretEngines:
    """Betterleaks and Trivy as they behave: each reads every file of the folder it's given but those its configuration's
    lists keep out (the built-in ones unless turned off, and the allowlist) and those it passes over by a list of its own
    (`hidden`, which Pitangus never sees). It names in its log what it read; what it passed over it names as skipped or
    not at all (`quiet`). In what it read it finds every token."""

    def __init__(self, hidden: dict[str, frozenset[str]] | None = None, quiet: frozenset[str] = frozenset()):
        self.hidden, self.quiet = hidden or {}, quiet
        self.read: dict[str, set[str]] = {engine: set() for engine in SECRET_ENGINES}
        self.roots: dict[str, Path] = {}

    def passes_over(self, engine: str, path: str) -> bool:
        return any(marker in path for marker in self.hidden.get(engine, ()))

    def __call__(self, key, arguments, snapshot=None, *, mounts=None, **options):
        if key not in SECRET_ENGINES:
            raise AssertionError(key)
        folders = _mounted(list(mounts or []))
        files = secret_coverage.committed(snapshot)
        log, found = [], []
        if key == "betterleaks":
            config = tomllib.loads((folders["/cfg"] / "betterleaks.toml").read_text())
            allow = [re.compile(pattern.removeprefix("^/src/")) for item in config.get("allowlists") or [] for pattern in item.get("paths") or []]
            built_in = "prefilter" not in config
        else:
            config = json.loads((folders["/cfg"] / "trivy-secret.yaml").read_text())
            allow = [re.compile(rule["path"].removeprefix("^")) for rule in config.get("allow-rules") or [] if "path" in rule]
            built_in = "skip-patterns" not in config or not config.get("disable-allow-rules")
            if "secret" not in arguments[arguments.index("--scanners") + 1].split(","):
                files = []
        for path in files:
            skip = (any(pattern.match(path) for pattern in allow) or self.passes_over(key, path)
                    or (built_in and (BETTERLEAKS_BUILT_IN if key == "betterleaks" else TRIVY_SKIPS).search(path))
                    or (built_in and key == "trivy" and TRIVY_ALLOW.search(path)))
            if skip:
                if key == "betterleaks" and key not in self.quiet:
                    log.append(f"6:01PM TRC scanning path path={json.dumps('/src/' + path)}\n")
                    log.append(f"6:01PM DBG skipping binary file mime_type=application/octet-stream path={json.dumps('/src/' + path)}\n")
                continue
            # Betterleaks scans the folder above the secret-only copy (`nested`): what it read, by repository path.
            self.read[key].add(path.removeprefix("files/") if snapshot.name.endswith(".credentials") else path)
            if key == "betterleaks":
                log.append(f"6:01PM TRC scanning path path={json.dumps('/src/' + path)}\n")
                log.append(f'6:01PM TRC skipping finding: rule filter finding=notasecret path={json.dumps("/src/" + path)} rule_id=generic-api-key\n')
            else:
                log.append(f"2026-10-14T18:04:16Z\tDEBUG\t[secret] Using streaming scanner\tfile_path={json.dumps(path)}\n")
            text = (snapshot / path).read_bytes().decode("utf-8", "surrogateescape")
            for number, line in enumerate(text.splitlines(), 1):
                for match in TOKEN_SHAPE.finditer(line):
                    if key == "betterleaks" and re.search(r"(?:gitleaks|betterleaks):allow", line) and "--ignore-gitleaks-allow" not in arguments:
                        # As Betterleaks traces it: with the value.
                        log.append(f'6:01PM TRC skipping finding: allow signature found finding={json.dumps(match.group(0) + chr(34))} '
                                   f'path={json.dumps("/src/" + path)} rule_id=stripe-access-token\n')
                        continue
                    found.append((path, number, match.start(), match.end(), line))
        if key == "betterleaks":
            # As Betterleaks 1.9 does, whatever its flags: the ignore files at the top of what it scans, applied silently.
            ignored = {line.strip() for name in (".gitleaksignore", ".betterleaksignore") if (snapshot / name).is_file()
                       for line in (snapshot / name).read_text().splitlines()}
            found = [item for item in found if f"/src/{item[0]}:stripe-access-token:{item[1]}" not in ignored]
            report = [{"RuleID": "stripe-access-token", "File": f"/src/{path}", "StartLine": number, "EndLine": number,
                       "StartColumn": len(line[:start].encode("utf-8", "surrogateescape")) + 1,
                       "EndColumn": len(line[:end].encode("utf-8", "surrogateescape")), "Match": "REDACTED", "Secret": "REDACTED",
                       "Entropy": entropy(line[start:end])} for path, number, start, end, line in found]
            (folders["/out"] / "report.json").write_text(json.dumps(report))
            return subprocess.CompletedProcess(arguments, 0, "", "".join(log))
        results = [{"Target": path, "Class": "secret", "Secrets": [{"RuleID": "stripe-secret-token", "Category": "Stripe", "Title": "Stripe",
                                                                   "StartLine": number, "EndLine": number, "Match": "key = ****"}]}
                   for path, number, _, _, _ in found]
        return subprocess.CompletedProcess(arguments, 0, json.dumps({"SchemaVersion": 2, "Results": results}), "".join(log))


def _completed(key: str):
    return lambda *args, **kwargs: {**engines._result(key, "completed", ""), "coverage": engine_contract.coverage("*")}


def scan(files: dict[str, bytes], fake: SecretEngines) -> dict:
    """A whole code scan of a repository archive, the secret engines `fake`, the others reading nothing of note."""
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder) / "head"
        stats = _extract_limited(archive(files), root)
        replaced = [patch.object(engines, "_run", side_effect=fake), patch.object(engines, "unavailable", return_value=None),
                    patch.object(engines, "runner", return_value="docker"), patch.object(engines, "trivy_databases", return_value=[]),
                    patch.object(repository, "engines_available", return_value=True), patch.object(repository, "host_mount_problem", return_value=None),
                    patch.object(repository, "load_feeds", return_value={"kev": {}, "epss": {}}),
                    *(patch.object(repository, name, side_effect=_completed(key)) for name, key in
                      (("run_opengrep", "opengrep"), ("run_osv_scanner", "osv-scanner"), ("run_checkov", "checkov"), ("run_zizmor", "zizmor")))]
        for item in replaced:
            item.start()
        try:
            return repository.scan_repository(root, {"id": "github:org/app", "uid": "github#r4", "name": "org/app", "provider": "github",
                                                     "snapshot": stats}, data_dir=Path(folder))
        finally:
            for item in replaced:
                item.stop()


def detected(record: dict, engine: str, path: str) -> bool:
    return any(item["scanner"] == "secrets" and item["path"] == path and engine in (item["tool"], *(item.get("also_detected_by") or []))
               for item in record["findings"])


def unproven(record: dict, engine: str, path: str) -> str | None:
    return registry.unproven_reason(record, {"tool": engine, "scanner": "secrets", "rule_id": "stripe-access-token", "path": path})


class SecretPassPropertyTests(unittest.TestCase):
    def check(self, record: dict, files: dict[str, bytes], secret_at: str, fake: SecretEngines) -> None:
        self.assertEqual(record["status"], "completed", record["steps"])
        for engine in SECRET_ENGINES:
            # The secret: found by the engine, or its file is unexamined for it (nothing it found there is fixed).
            self.assertTrue(detected(record, engine, secret_at) or unproven(record, engine, secret_at), (engine, secret_at))
            # No file is ever taken as read that the engine didn't read.
            for path in files:
                if path not in fake.read[engine]:
                    self.assertIsNotNone(unproven(record, engine, path), (engine, path, record.get("coverage", {}).get(engine)))

    @settings(max_examples=25 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
    @given(TOKEN, committed_path, st.lists(committed_path, max_size=6), st.lists(st.sampled_from(FOLDERS + NAMES + [".", "_", "s"]), max_size=3),
           st.lists(st.sampled_from(FOLDERS + NAMES + [".", "_", "s"]), max_size=3), st.sets(st.sampled_from(SECRET_ENGINES)), st.booleans())
    @example("sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc", SEEDS[0], ["src/app.py"], [], [], set(), False)
    # A token that reads as one: `…AbCdEfGh…` is a placeholder (secret_filter), set aside by an engine that reads its value.
    @example("sk_live_" + "51HxQ7rTzK9mWv2LpN4sJ8dYc6", SEEDS[1], ["README.md"], ["lambda"], [], {"trivy"}, True)
    def test_a_secret_in_any_committed_file_is_found_or_the_file_is_unexamined(self, token, secret_at, others, hidden_bl, hidden_tv,
                                                                                quiet, binary_looking):
        """Under engines that pass over files by lists Pitangus never sees, logging it or not."""
        content = (b"\x00\x01PK\x03" if binary_looking else b"") + f'const key = "{token}";\n'.encode()
        files = {**{path: b"x = 1\n" for path in others if not secret_at.startswith(path + "/")}, secret_at: content}
        files = {path: data for path, data in files.items() if not any(other.startswith(path + "/") for other in files if other != path)}
        if secret_at not in files:
            return
        fake = SecretEngines({"betterleaks": frozenset(hidden_bl), "trivy": frozenset(hidden_tv)}, frozenset(quiet))
        self.check(scan(files, fake), files, secret_at, fake)

    def test_the_seeds_are_found_by_both_engines_now_that_their_lists_are_pitangus_own(self):
        """With nothing hidden, the built-in lists are what kept these files out: turned off, both engines find them."""
        for path in SEEDS:
            with self.subTest(path=path):
                files = {path: f'const stripe = "{STRIPE}";\n'.encode(), "app.py": b"x = 1\n"}
                fake = SecretEngines()
                record = scan(files, fake)
                self.check(record, files, path, fake)
                self.assertTrue(all(detected(record, engine, path) for engine in SECRET_ENGINES), record["findings"])

    def test_an_engine_that_logs_nothing_vouches_for_nothing(self):
        """A run whose report is whole but whose log names no file read nothing, as far as anyone can tell."""
        files = {SEEDS[0]: f'k = "{STRIPE}"\n'.encode(), "src/app.py": b"x = 1\n", "README.md": b"# x\n"}
        fake = SecretEngines()

        def silent(key, arguments, snapshot=None, **options):
            done = fake(key, arguments, snapshot, **options)
            return subprocess.CompletedProcess(done.args, done.returncode, done.stdout, "")
        record = scan(files, silent)
        for engine in SECRET_ENGINES:
            for path in files:
                if not detected(record, engine, path):
                    self.assertIsNotNone(unproven(record, engine, path), (engine, path))


class InlineAllowTests(unittest.TestCase):
    """A `gitleaks:allow` comment is the owner's decision, written in the code: honoured, and every match it allows is
    declared (excluded with its file and line, in the coverage, the step, the limitations, the CLI and the prompt),
    never fixed and never with its value. PITANGUS_SECRETS_IGNORE_INLINE_ALLOW=1 ignores the comments."""

    TOKEN = "sk_live_" + "Zq8RkT2mWv5XyB7nPc3LdF9hJ"
    FILES = {"src/keys.js": f'const a = 1;\nconst stripe = "{TOKEN}"; // gitleaks:allow\n'.encode(),
             "node_modules/x/index.js": f'k = "{TOKEN}"  # betterleaks:allow\n'.encode(), "app.py": b"x = 1\n"}

    def test_an_allowed_match_is_excluded_and_listed_by_file_and_line_never_its_value(self):
        from pitangus.modules.runs.local import render_prompt, _suppressed_inline
        from pitangus.shared.i18n import text
        record = scan(self.FILES, SecretEngines())
        self.assertEqual(record["status"], "completed")
        self.assertFalse(any(item["tool"] == "betterleaks" for item in record["findings"]))
        allowed = sorted({(item["path"], item["line"]) for item in record.get("excluded_findings") or [] if item.get("inline_allowed")})
        self.assertEqual(allowed, [("node_modules/x/index.js", 1), ("src/keys.js", 2)])
        self.assertEqual(record["coverage"]["betterleaks"]["suppressed_inline"], ["node_modules/x/index.js:1", "src/keys.js:2"])
        reason = next(item for item in record["excluded_findings"] if item["path"] == "src/keys.js")["excluded_reason"]
        self.assertIn("src/keys.js:2", text(reason, "en"))
        self.assertTrue(any("gitleaks:allow" in text(item, "en") and "src/keys.js:2" in text(item, "en") for item in record["limitations"]))
        step = next(item for item in record["steps"] if item["id"] == "betterleaks")
        self.assertIn("src/keys.js:2", text(step["detail"], "es"))
        # Trivy has no comments of its own: Pitangus honours the same one for it, and declares it the same way.
        self.assertFalse(any(item["tool"] == "trivy" and item["path"] == "src/keys.js" for item in record["findings"]))
        self.assertEqual(record["coverage"]["trivy"]["suppressed_inline"], ["node_modules/x/index.js:1", "src/keys.js:2"])
        self.assertIsNotNone(unproven(record, "trivy", "src/keys.js") or next(
            (item for item in record["excluded_findings"] if item["tool"] == "trivy" or "trivy" in (item.get("also_detected_by") or [])), None))
        result = {"findings": [], "comparison": None, "scan": record}
        for output in (json.dumps(record, ensure_ascii=False), render_prompt(result, locale="en"), *_suppressed_inline(result, "es")):
            self.assertNotIn(self.TOKEN, output)
        self.assertIn("src/keys.js:2", render_prompt(result, locale="en"))

    def test_with_the_setting_on_the_comments_allow_nothing(self):
        with patch.dict(os.environ, {"PITANGUS_SECRETS_IGNORE_INLINE_ALLOW": "1"}):
            record = scan(self.FILES, SecretEngines())
        self.assertTrue(detected(record, "betterleaks", "src/keys.js") and detected(record, "betterleaks", "node_modules/x/index.js"))
        self.assertNotIn("suppressed_inline", record["coverage"]["betterleaks"])

    def test_if_the_allowed_matches_cant_be_named_nothing_is_fixed(self):
        fake = SecretEngines()

        def failing(key, arguments, snapshot=None, **options):
            if key == "betterleaks" and "--ignore-gitleaks-allow" in arguments:
                return subprocess.CompletedProcess(arguments, 2, "", "boom")
            return fake(key, arguments, snapshot, **options)
        record = scan(self.FILES, failing)
        self.assertEqual(record["status"], "incomplete")
        self.assertIsNotNone(unproven(record, "betterleaks", "src/keys.js"))


class IgnoreFileTests(unittest.TestCase):
    """A committed `.gitleaksignore` / `.betterleaksignore` is the owner's decision too: Betterleaks never loads it on its
    own (no committed file sits at the top of what it scans), Pitangus honours its entries and declares every match they
    allow, by file and line, never fixed and never with its value. PITANGUS_SECRETS_IGNORE_INLINE_ALLOW=1 ignores them."""

    TOKEN = "sk_live_" + "Hq7RkT2mWv5XyB7nPc3LdF9hJ"
    FILES = {".env": f"STRIPE={TOKEN}\n".encode(), ".secrets/key.txt": f"x = 1\nk = {TOKEN}\n".encode(),
             ".env.local": f"OTHER={TOKEN}\n".encode(), "app.py": b"x = 1\n",
             # The fingerprints are predictable: path, rule and line, never the value.
             ".betterleaksignore": b"/src/.env:stripe-access-token:1\n",
             ".gitleaksignore": b"# reviewed\n" + b"a" * 40 + b":.secrets/key.txt:stripe-access-token:2\n"}

    def test_a_listed_secret_is_excluded_and_declared_by_file_and_line_never_silently(self):
        from pitangus.shared.i18n import text
        record = scan(self.FILES, SecretEngines())
        self.assertEqual(record["status"], "completed")
        for path in (".env", ".secrets/key.txt"):
            self.assertFalse(any(item["tool"] == "betterleaks" and item["path"] == path for item in record["findings"]), path)
        excluded = {(item["path"], item["line"]): item for item in record.get("excluded_findings") or [] if item["tool"] == "betterleaks"}
        self.assertEqual(sorted(excluded), [(".env", 1), (".secrets/key.txt", 2)])
        self.assertIn(".betterleaksignore", text(excluded[(".env", 1)]["excluded_reason"], "en"))
        self.assertIn(".gitleaksignore (.secrets/key.txt:2)", text(excluded[(".secrets/key.txt", 2)]["excluded_reason"], "en"))
        self.assertEqual(record["coverage"]["betterleaks"]["suppressed_inline"], [".env:1", ".secrets/key.txt:2"])
        self.assertTrue(any(".env:1" in text(item, "en") for item in record["limitations"]))
        # What no entry lists is a finding as ever; the files themselves were read, and stay so.
        self.assertTrue(detected(record, "betterleaks", ".env.local"))
        self.assertIsNone(unproven(record, "betterleaks", ".env"))
        self.assertNotIn(self.TOKEN, json.dumps(record, ensure_ascii=False))

    def test_with_the_setting_on_they_allow_nothing(self):
        with patch.dict(os.environ, {"PITANGUS_SECRETS_IGNORE_INLINE_ALLOW": "1"}):
            record = scan(self.FILES, SecretEngines())
        self.assertTrue(detected(record, "betterleaks", ".env") and detected(record, "betterleaks", ".secrets/key.txt"))
        self.assertNotIn("suppressed_inline", record["coverage"]["betterleaks"])

    def test_entries_are_read_as_betterleaks_fingerprints(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / ".gitleaksignore").write_text("# c\n\n/src/a/.env:github-pat:3\n./b.js:generic-api-key:10\n"
                                                  + "f" * 64 + ":c:d.txt:aws-access-token:2\nbroken\nx:y:z\n")
            (root / "sub").mkdir()
            (root / "sub" / ".betterleaksignore").write_text("e.js:r:1\n")   # Betterleaks never reads one below the top
            self.assertEqual(engines.ignore_file_entries(root), {("a/.env", "github-pat", 3): ".gitleaksignore",
                                                                 ("b.js", "generic-api-key", 10): ".gitleaksignore",
                                                                 ("c:d.txt", "aws-access-token", 2): ".gitleaksignore"})


class ListingTests(unittest.TestCase):
    """The engines' logs, read: only what they name as read is read."""

    def test_betterleaks_reads_what_it_names_and_not_what_it_then_skips(self):
        log = ('6:01PM TRC scanning path path=/src/a.js\n'
               '6:01PM TRC scanning path path="/src/dir with space/q\\"uote.js"\n'
               '6:01PM TRC scanning path path="/src/ñ/x.js"\n'
               '6:01PM TRC scanning path path=/src/font.woff2\n'
               '6:01PM DBG skipping binary file mime_type=application/font-woff path=/src/font.woff2\n'
               '6:01PM DBG skipping directory: global allowlist path=/src/fixtures\n'
               '6:01PM TRC scanning path path=/src/fixtures/a.js\n'
               '6:01PM DBG skipping empty file path=/src/empty.txt\n'
               '6:01PM TRC skipping finding: rule filter finding=abc path=/src/b.js rule_id=generic-api-key\n'
               '6:01PM TRC scanning path path="/src/bad\\xff.js"\n'
               '6:01PM TRC scanning path path=/etc/passwd\n'
               '6:01PM INF scanned ~10 bytes in 1ms\n')
        read, rest = secret_coverage.read_betterleaks(log)
        self.assertEqual(read, {"a.js", "dir with space/q\"uote.js", "ñ/x.js", "empty.txt"})
        self.assertNotIn("scanning path", rest)
        self.assertIn("INF scanned", rest)

    def test_trivy_reads_what_its_secret_scanner_names_and_not_what_failed(self):
        log = ('2026-10-14T18:04:16Z\tDEBUG\t[secret] Using streaming scanner\tfile_path="a.js"\n'
               '2026-10-14T18:04:16Z\tDEBUG\t[secret] Using streaming scanner\tfile_path="b c/ñ.js"\n'
               '2026-10-14T18:04:16Z\tDEBUG\t[secret] Using streaming scanner\tfile_path="broken.js"\n'
               '2026-10-14T18:04:16Z\tERROR\t[secret] Failed to read content during streaming\tfile_path="broken.js" err="EOF"\n'
               '2026-10-14T18:04:16Z\tDEBUG\tSecret file\tfile_path="other.js"\n'
               '2026-10-14T18:04:16Z\tFATAL\tFatal error\trun error: secret config error\n')
        read, rest = secret_coverage.read_trivy(log)
        self.assertEqual(read, {"a.js", "b c/ñ.js"})
        self.assertEqual(rest.strip().splitlines()[-1].split("\t")[1], "FATAL")

    @settings(max_examples=100 * SCALE, deadline=None)
    @given(st.text(min_size=8, max_size=60).filter(lambda value: value.strip() and "\n" not in value and "\r" not in value))
    def test_what_the_engines_trace_of_a_candidate_never_stays(self, value):
        """Betterleaks traces every candidate it filters out with its value, and what it decodes: none of it is kept, and
        neither is anything else Trivy logs at debug level."""
        betterleaks = [f"6:01PM TRC skipping finding: rule filter finding={value} path=/src/a.js rule_id=generic-api-key\n",
                       f'6:01PM TRC skipping finding: allow signature found finding={json.dumps(value)} path=/src/a.js rule_id=r\n',
                       f'6:01PM TRC segment found: original=[1,4] pos=[1,4]: "{value}" -> "#" decoder=percent\n',
                       f"6:01PM DBG skipping generic-api-key finding ({value}), private-key rule takes precedence\n",
                       "6:01PM TRC translated rule filter expression filter=\"\n", f"  `{value}`,\n", "])\n",
                       "6:01PM TRC scanning path path=/src/a.js\n"]
        keep = secret_coverage.keep_betterleaks()
        kept = "".join(keep(line) or "" for line in betterleaks)
        self.assertNotIn(value, kept.replace("/src/a.js", ""))
        trivy = [f'2026-10-14T18:04:16Z\tERROR\t[terraform parser] Error parsing file\tfile_path="main.tf" cause="{value}"\n',
                 f'2026-10-14T18:04:16Z\tDEBUG\tWalk error\tfile_path="x" err="{value}"\n', f"  {value}\n",
                 '2026-10-14T18:04:16Z\tDEBUG\t[secret] Using streaming scanner\tfile_path="a.js"\n']
        keep = secret_coverage.keep_trivy()
        self.assertNotIn(value, "".join(keep(line) or "" for line in trivy).replace("a.js", ""))

    def test_a_crash_is_always_kept(self):
        keep = secret_coverage.keep_betterleaks()
        self.assertFalse(keep("6:01PM TRC skipping finding: rule filter finding=x path=/src/a rule_id=r\n"))
        self.assertTrue(keep("panic: runtime error: index out of range\n"))
        self.assertTrue(keep("goroutine 1 [running]:\n"))


class DeclaredTests(unittest.TestCase):
    @settings(max_examples=200 * SCALE, deadline=None)
    @given(st.sets(committed_path, min_size=1, max_size=40), st.data(), st.integers(1, 50))
    def test_a_declaration_says_exactly_which_files_went_unread_or_more_never_less(self, files, data, limit):
        files = {path for path in files if not any(other.startswith(path + "/") for other in files if other != path)}
        gaps = {path: data.draw(st.sampled_from(["skipped_by_engine", "allowlisted"])) for path in files if data.draw(st.booleans())}
        units = secret_coverage.declared(sorted(files), gaps, limit)
        exact = secret_coverage.declared(sorted(files), gaps)
        for path in files:
            self.assertTrue(coverage_units.inside(path, units) or path not in gaps, path)
            self.assertEqual(coverage_units.inside(path, exact), path in gaps, (path, exact))
        self.assertLessEqual(len(units), max(limit, len({path.split("/", 1)[0] for path in gaps})))


class FilteredRunnerTests(unittest.TestCase):
    """engines._filtered, under the faults a run can meet: a flood of log lines, output on both streams, a timeout."""

    def test_only_kept_lines_are_held_and_stdout_is_whole(self):
        program = ("import sys\nfor i in range(50000):\n    sys.stderr.write(f'6:01PM TRC skipping finding: rule filter finding=v{i} path=/src/a\\n')\n"
                   "    sys.stderr.write(f'6:01PM TRC scanning path path=/src/f{i}.js\\n')\nsys.stdout.write('[' + ','.join(['1'] * 100000) + ']')\n")
        code, out, err = engines._filtered([sys.executable, "-c", program], timeout=60, keep=secret_coverage.keep_betterleaks(),
                                           on_timeout=lambda process: process.kill())
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(out)), 100000)
        self.assertEqual(len(err.splitlines()), 50000)
        self.assertNotIn("finding=", err)

    def test_a_timeout_stops_the_engine_and_raises(self):
        stopped = []
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            engines._filtered([sys.executable, "-c", "import time, sys\nsys.stderr.write('x\\n')\ntime.sleep(60)"], timeout=1,
                              keep=lambda line: True, on_timeout=lambda process: (stopped.append(True), process.kill()))
        self.assertEqual(stopped, [True])
        self.assertLess(time.monotonic() - started, 30)


class AdapterFaultTests(unittest.TestCase):
    """The adapters this listing touches, fed broken logs: a run never vouches for a file its log doesn't name."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.snapshot = Path(self.folder.name) / "snapshot"
        for name in ("a.js", "node_modules/x/index.js", "dist/b.js"):
            (self.snapshot / name).parent.mkdir(parents=True, exist_ok=True)
            (self.snapshot / name).write_text("x = 1\n")
        for item in (patch.object(engines, "unavailable", return_value=None), patch.object(engines, "trivy_databases", return_value=[]),
                     patch.object(engines, "runner", return_value="docker")):
            item.start()
            self.addCleanup(item.stop)

    LOGS = {"none": "", "garbage": "\x00\x01 not a log line\n" * 3, "truncated": "6:01PM TRC scanning pa",
            "other-files": '6:01PM TRC scanning path path=/src/zzz.js\n2026-10-14T18:04:16Z\tDEBUG\t[secret] Using streaming scanner\tfile_path="zzz.js"\n',
            "outside": "6:01PM TRC scanning path path=/etc/a.js\n", "bad-quote": '6:01PM TRC scanning path path="/src/a.js\n',
            "only-a": '6:01PM TRC scanning path path=/src/a.js\n2026-10-14T18:04:16Z\tDEBUG\t[secret] Using streaming scanner\tfile_path="a.js"\n'}

    def run_engine(self, key: str, log: str) -> dict:
        def fake(engine, arguments, snapshot=None, *, mounts=None, **options):
            folders = _mounted(list(mounts or []))
            if engine == "betterleaks":
                (folders["/out"] / "report.json").write_text("[]")
                return subprocess.CompletedProcess(arguments, 0, "", log)
            return subprocess.CompletedProcess(arguments, 0, json.dumps({"SchemaVersion": 2, "Results": []}), log)
        with patch.object(engines, "_run", side_effect=fake):
            if key == "betterleaks":
                return engines.run_betterleaks(self.snapshot)
            if key == "trivy":
                return engines.run_trivy(self.snapshot, Path(self.folder.name) / "cache", {})
            gaps: dict = {}
            findings = engines.trivy_secrets(self.snapshot, Path(self.folder.name) / "cache", None, gaps=gaps)
            return {"findings": findings, "coverage": {"unexamined": gaps}}

    def test_no_broken_log_makes_an_unread_file_read(self):
        files = secret_coverage.committed(self.snapshot)
        for key in ("betterleaks", "trivy", "trivy_secrets"):
            for name, log in self.LOGS.items():
                with self.subTest(adapter=key, log=name):
                    result = self.run_engine(key, log)
                    coverage = result["coverage"]
                    gaps = (coverage.get("by_scanner") or {}).get("secrets", {}) if key == "trivy" else coverage["unexamined"]
                    read = {"a.js"} if name == "only-a" else set()
                    for path in files:
                        self.assertEqual(coverage_units.inside(path, gaps), path not in read, (path, gaps))

    def test_a_file_logged_as_read_in_bytes_that_arent_text_stays_unread(self):
        """`scanning path` for a file in UTF-16 (or any bytes that aren't UTF-8 text) says the engine opened it, not that
        a token in it was where its patterns look: still a gap, for every adapter."""
        for data in ('k = "x"\n'.encode("utf-16"), 'k = "x"\n'.encode("utf-32-be"), 'k = "x"\n'.encode("cp500"), b"\x00\x01binary"):
            (self.snapshot / "a.js").write_bytes(data)
            for key in ("betterleaks", "trivy", "trivy_secrets"):
                with self.subTest(adapter=key, data=data[:8]):
                    coverage = self.run_engine(key, self.LOGS["only-a"])["coverage"]
                    gaps = (coverage.get("by_scanner") or {}).get("secrets", {}) if key == "trivy" else coverage["unexamined"]
                    self.assertTrue(coverage_units.inside("a.js", gaps), gaps)

    def test_the_listing_never_reaches_the_cause_of_a_failure(self):
        log = "6:01PM TRC scanning path path=/src/a.js\n6:01PM ERR failed to open report\n"
        def fake(engine, arguments, snapshot=None, **options):
            return subprocess.CompletedProcess(arguments, 2, "", log)
        with patch.object(engines, "_run", side_effect=fake):
            result = engines.run_betterleaks(self.snapshot)
        self.assertEqual(result["status"], "inconclusive")
        self.assertNotIn("scanning path", json.dumps(result, ensure_ascii=False))
        self.assertNotIn("coverage", result)


@unittest.skipUnless(engines.docker_available() and engines.image_available("betterleaks") and engines.image_available("trivy"),
                     "needs Docker with the Betterleaks and Trivy images")
class RealEnginesTests(unittest.TestCase):
    """The pinned images themselves, on the seeds and a few other places their built-in lists covered: found by both."""

    PLACES = [*SEEDS, "vendor/github.com/acme/client/config.go", "test/fixtures/keys.js", "examples/app.js", "docs/setup.md",
              "public/jquery-3.7.1.min.js", "packages/web/dist/main.js", ".gitx/hooks/deploy.sh", "assets/blob.bin", "locale/en/strings.json"]

    def real_scan(self, files: dict[str, bytes]) -> dict:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "head"
            stats = _extract_limited(archive(files), root)
            replaced = [patch.object(repository, "load_feeds", return_value={"kev": {}, "epss": {}}),
                        *(patch.object(repository, name, side_effect=_completed(key)) for name, key in
                          (("run_opengrep", "opengrep"), ("run_osv_scanner", "osv-scanner"), ("run_checkov", "checkov"), ("run_zizmor", "zizmor")))]
            for item in replaced:
                item.start()
            try:
                return repository.scan_repository(root, {"id": "github:org/app", "uid": "github#r4-real", "name": "org/app",
                                                         "provider": "github", "snapshot": stats}, data_dir=Path(folder))
            finally:
                for item in replaced:
                    item.stop()

    def test_a_gitleaks_allow_comment_is_honoured_and_declared(self):
        token = "sk_live_" + "".join(random.SystemRandom().choice(ALNUM) for _ in range(32))
        record = self.real_scan({"src/keys.js": f'x = 1\nconst stripe = "{token}"; // gitleaks:allow\n'.encode(),
                                 "src/other.js": f'const b = "{token}";\n'.encode()})
        self.assertTrue(detected(record, "betterleaks", "src/other.js"))
        self.assertFalse(any(item["tool"] == "betterleaks" and item["path"] == "src/keys.js" for item in record["findings"]))
        self.assertEqual(record["coverage"]["betterleaks"]["suppressed_inline"], ["src/keys.js:2"])
        self.assertNotIn(token, json.dumps(record, ensure_ascii=False))

    def test_a_committed_ignore_file_never_silences_betterleaks(self):
        """As the audit saw it: Betterleaks loads `.gitleaksignore` / `.betterleaksignore` from the top of what it scans
        whatever its flags say. None is there now; Pitangus honours the entries and declares each match."""
        token = "sk_live_" + "".join(random.SystemRandom().choice(ALNUM) for _ in range(32))
        files = {".env": f"STRIPE_KEY={token}\n".encode(), ".config/keys.txt": f"x = 1\nSTRIPE_KEY={token}\n".encode(),
                 ".betterleaksignore": b"/src/.env:stripe-access-token:1\n",
                 ".gitleaksignore": b"/src/.config/keys.txt:stripe-access-token:2\n"}
        record = self.real_scan(files)
        self.assertFalse(any(item["tool"] == "betterleaks" and item["path"] in (".env", ".config/keys.txt") for item in record["findings"]))
        self.assertEqual(record["coverage"]["betterleaks"]["suppressed_inline"], [".config/keys.txt:2", ".env:1"])
        self.assertNotIn(token, json.dumps(record, ensure_ascii=False))
        with patch.dict(os.environ, {"PITANGUS_SECRETS_IGNORE_INLINE_ALLOW": "1"}):
            record = self.real_scan(files)
        self.assertTrue(detected(record, "betterleaks", ".env") and detected(record, "betterleaks", ".config/keys.txt"))

    def test_both_engines_find_a_secret_wherever_their_lists_used_to_skip_it(self):
        token = "sk_live_" + "".join(random.SystemRandom().choice(ALNUM) for _ in range(32))
        files = {path: f'const stripe = "{token}";\n'.encode() for path in self.PLACES}
        files["app.py"] = b"x = 1\n"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "head"
            stats = _extract_limited(archive(files), root)
            self.assertEqual(stats["unexamined"], {})
            replaced = [patch.object(repository, "load_feeds", return_value={"kev": {}, "epss": {}}),
                        *(patch.object(repository, name, side_effect=_completed(key)) for name, key in
                          (("run_opengrep", "opengrep"), ("run_osv_scanner", "osv-scanner"), ("run_checkov", "checkov"), ("run_zizmor", "zizmor")))]
            for item in replaced:
                item.start()
            try:
                record = repository.scan_repository(root, {"id": "github:org/app", "uid": "github#r4-real", "name": "org/app",
                                                           "provider": "github", "snapshot": stats}, data_dir=Path(folder))
            finally:
                for item in replaced:
                    item.stop()
            self.assertFalse(secrets_root(root).exists())
        missing = {(engine, path) for path in self.PLACES for engine in SECRET_ENGINES
                   if not detected(record, engine, path) and unproven(record, engine, path) is None}
        self.assertEqual(missing, set())
        for path in SEEDS:
            self.assertTrue(detected(record, "betterleaks", path) and detected(record, "trivy", path), path)
        self.assertNotIn(token, json.dumps(record, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
