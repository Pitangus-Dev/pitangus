"""Betterleaks, the secret scanner that replaced Gitleaks: its real output, the secret identity read at its columns, the
opt-in validation of active secrets, and findings stored under Gitleaks' name."""

import json
import random
import string
from collections import Counter
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hypothesis import example, given, settings, strategies as st

from pitangus.modules.scanning.secret_location import entropy
from pitangus.modules.findings import registry
from pitangus.modules.scanning import engines, secret_filter, secret_identity, secret_rules
from pitangus.modules.sources.repositories import _safe_name

PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

FIXTURES = Path(__file__).parent / "fixtures"
# The values of the recorded run (tests/fixtures/betterleaks-1.9.json), built here so no token sits in the repository.
GITHUB = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
SLACK = "xoxb-" + "2339545089-2835763688579-cpP7BEXvfqZgimdS7jnqFCiI"
KEY = ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7bq98vKaXzXbN1Lq0wC6pZ8yQ2r5tU3vW4xY6zA1bC2dE3fG\n"  # gitleaks:allow
       "H4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4cD5eF6gH7iJ8kL9mN0oP1qR2sT3uV4w\n-----END RSA PRIVATE KEY-----")


def snapshot(folder: str) -> Path:
    root = Path(folder) / "snapshot"
    (root / "config").mkdir(parents=True)
    (root / "fixtures").mkdir()
    (root / "config" / "app.py").write_text(f'x = 1\nGITHUB_TOKEN = "{GITHUB}"\nACME = "acme_a1b2c3d4e5f6g7h8i9j0k1l2"\nslack = "{SLACK}"\n')
    (root / "fixtures" / "test.py").write_text(f'TOKEN = "{GITHUB}"\n')
    (root / "key.pem").write_text(KEY + "\n")
    return root


class RecordedOutputTests(unittest.TestCase):
    def test_each_secret_is_read_at_its_columns_whole_even_across_lines(self):
        """Betterleaks 1.9.0's columns (from 1, last included, on every line) give each secret's own value: the identity
        of the token, of the same token in another file, and of the whole private key."""
        report = json.loads((FIXTURES / "betterleaks-1.9.json").read_text())
        with tempfile.TemporaryDirectory() as folder:
            findings = engines.parse_betterleaks(report, None, snapshot(folder))
        self.assertEqual([item["identity"] for item in findings],
                         [secret_identity.identity(value) for value in (GITHUB, SLACK, GITHUB, KEY)])
        self.assertEqual({item["tool"] for item in findings}, {"betterleaks"})
        self.assertTrue(all(GITHUB not in json.dumps(item) and SLACK not in json.dumps(item) for item in findings))


class BothEnginesTests(unittest.TestCase):
    """Real output of Trivy 0.75 and Betterleaks 1.9 for one file with two Slack tokens of one workspace: Trivy masks
    only the workspace part both share (`xoxb-` and its first number); Betterleaks reports each whole."""

    def test_both_engines_give_each_secret_one_identity_and_two_secrets_never_share_one(self):
        second = "xoxb-" + "2339545089-9876543210987-ZyXwVuTsRqPoNmLkJiHgFeDc"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "config.py").write_text(f'x = 1\nGITHUB_TOKEN = "{GITHUB}"\nslack = "{SLACK}"\nslack2 = "{second}"\n')
            found = engines.parse_betterleaks(json.loads((FIXTURES / "betterleaks-1.9-slack.json").read_text()), None, root)
            seen = engines.parse_trivy(json.loads((FIXTURES / "trivy-0.75-secrets.json").read_text()), {}, root=root)
        expected = [secret_identity.identity(value) for value in (GITHUB, SLACK, second)]
        self.assertEqual([item.get("identity") for item in found], expected)
        self.assertEqual([item.get("identity") for item in seen], expected)
        self.assertEqual(len(engines.merge_secrets(found, seen)), 3)


class ValidationTests(unittest.TestCase):
    def finding(self, status):
        entry = {**json.loads((FIXTURES / "betterleaks-1.9.json").read_text())[0], **({"ValidationStatus": status} if status else {})}
        return engines.parse_betterleaks([entry])[0]

    def test_validation_reorders_priority_and_never_hides_a_finding(self):
        self.assertEqual((self.finding("valid")["validation"], self.finding("valid")["priority"]["action"]), ("active", "act"))
        self.assertEqual((self.finding("revoked")["validation"], self.finding("revoked")["priority"]["action"]), ("revoked", "track"))
        self.assertEqual(self.finding("invalid")["validation"], "revoked")
        unknown, plain = self.finding("error"), self.finding(None)
        self.assertEqual((unknown["validation"], unknown["priority"]["action"]), ("unknown", plain["priority"]["action"]))
        self.assertNotIn("validation", plain)

    def runs(self, enabled: bool, settings: dict | None = None) -> list[tuple[list, bool]]:
        calls = []

        def run(key, arguments, snapshot, **options):
            calls.append((arguments, options.get("network", False)))
            out = Path(next(mount for mount in options["mounts"] if mount.endswith(":/out")).rsplit(":", 1)[0])
            (out / "report.json").write_text("[]")
            return subprocess.CompletedProcess(arguments, 0, "", "")
        with tempfile.TemporaryDirectory() as folder, patch.object(engines, "_run", side_effect=run), \
                patch.object(engines, "unavailable", return_value=None), \
                patch.dict(os.environ, {"PITANGUS_SECRET_VALIDATION": "1" if enabled else ""}):
            root = Path(folder) / "snapshot"
            root.mkdir()
            engines.run_betterleaks(root, settings)
        return calls

    def test_validation_is_off_unless_enabled_and_only_then_the_container_has_a_network(self):
        (arguments, network), = self.runs(False)
        self.assertEqual(("--validation" in arguments, network), (False, False))
        (arguments, network), = self.runs(True)
        self.assertEqual(("--validation" in arguments, network), (True, True))
        # The unfiltered reference run (settings that withhold) never validates nor goes online.
        filtered = secret_rules.normalize({"allowlist": {"paths": ["fixtures/**"]}})
        main, reference = self.runs(True, filtered)
        self.assertEqual((main[1], reference[1], "--validation" in reference[0]), (True, False, False))


class SuccessorTests(unittest.TestCase):
    def test_a_finding_stored_under_gitleaks_is_betterleaks_to_prove_gone(self):
        finding = {"tool": "gitleaks", "scanner": "secrets", "path": "config.py"}
        blind = {"status": "completed", "type": "repository_scan", "summary": {"tools": [{"name": "betterleaks", "status": "inconclusive"}]}}
        self.assertEqual(registry.unproven_reason(blind, finding), "engine_blind")
        skipped = {"status": "completed", "type": "repository_scan", "unexamined": {"betterleaks": ["config.py"]},
                   "summary": {"tools": [{"name": "betterleaks", "status": "completed"}]}}
        self.assertEqual(registry.unproven_reason(skipped, finding), "not_covered")


class SnapshotTests(unittest.TestCase):
    def test_a_repository_cannot_ship_its_own_scanner_settings_or_ignore_list(self):
        for name in (".betterleaks.toml", ".gitleaks.toml", ".betterleaksignore", ".gitleaksignore"):
            with self.subTest(name=name):
                self.assertIsNone(_safe_name(f"repo-abc/{name}"))
                self.assertIsNone(_safe_name(f"repo-abc/sub/{name}"))


def _entry(line: str, value: str, prefix_bytes: int, shift: int = 0) -> dict:
    """A Betterleaks generic-password entry for `line`, with the columns it reports: bytes, from 1, last included."""
    match = line[line.index("password"):line.index(value) + len(value) + 1]
    start = prefix_bytes + 1 + shift
    return {"RuleID": "generic-password", "File": "/src/app.js", "StartLine": 1, "EndLine": 1, "StartColumn": start,
            "EndColumn": start - 1 + len(match.encode()), "Match": match.replace(value, "REDACTED"), "Secret": "REDACTED", "Entropy": entropy(value)}


class ByteColumnTests(unittest.TestCase):
    """Betterleaks counts columns in bytes and, in big files it scans in fragments, they may not land on the match: the
    secret is read where it really is, whatever comes before it on its line."""

    def outcome(self, prefix: str, value: str, shift: int = 0):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            line = f'{prefix} ; password = "{value}";\n'
            (root / "app.js").write_text(line, encoding="utf-8")
            screened: Counter = Counter()
            found = engines.parse_betterleaks([_entry(line, value, len((prefix + " ; ").encode()), shift)], None, root, screened)
            return [item.get("identity") for item in found], dict(screened), secret_identity.values(root, found)

    @settings(deadline=None, max_examples=100 * SCALE)
    @given(prefix=st.text(alphabet="abc xyz=;:`'ñé·→€中😀", max_size=40),
           value=st.from_regex(r"[A-Za-z][A-Za-z0-9!#%+]{11,20}[0-9]", fullmatch=True),
           shift=st.sampled_from([0, 0, 3, -2, 17]))
    @example(prefix="label = `contraseña ñ ñ ñ`; ", value="Zq8!vR2#mK9pLx4w", shift=0)
    def test_a_secret_after_non_ascii_text_reads_as_after_ascii_text(self, prefix, value, shift):
        plain = "".join(char if ord(char) < 128 else "x" for char in prefix)
        identities, screened, values = self.outcome(prefix, value, shift if prefix.count("password") == 0 else 0)
        expected, _, expected_values = self.outcome(plain, value)
        self.assertEqual((identities, screened), (expected, {}))
        self.assertTrue(any(value in found for found in values.values()))

    @settings(deadline=None, max_examples=50 * SCALE)
    @given(prefix=st.text(alphabet="abc xyz=;ñé·→中", max_size=40), label=st.sampled_from(["Contraseña nueva", "Repite la contraseña", "no password"]))
    def test_interface_text_after_non_ascii_text_is_set_aside(self, prefix, label):
        identities, screened, _ = self.outcome(prefix, label)
        self.assertEqual((identities, screened), ([], {"prose": 1}))



# --- A secret's identity is its value's (F3) -------------------------------------------------------------------------

def formats_snapshot(root: Path) -> tuple[str, str]:
    """The files of the recorded run in tests/fixtures/{betterleaks-1.9,trivy-0.75}-formats.json: one OpenAI project key
    and one generic token, each assigned in several formats (ENV, YAML, JSON, TOML, Python, after non-ASCII text).
    Built here from a seed, so no token sits in the repository: (OpenAI key, generic token)."""
    seeded = random.Random(7)

    def token(size: int) -> str:
        return "".join(seeded.choice(string.ascii_letters + string.digits) for _ in range(size))
    openai = "sk-proj-" + token(74) + "T3BlbkFJ" + token(74)
    generic = token(32)
    files = {"a.env": f'x=1\nOPENAI_API_KEY={openai}\nAPI_KEY = "{generic}"\nSERVICE_TOKEN="{generic}"\n',
             "b.yaml": f'x: 1\nopenai:\n  api_key: "{openai}"\n  secret_key: {generic}\n',
             "c.json": '{\n  "apiKey": "%s",\n  "auth_token": "%s"\n}\n' % (openai, generic),
             "d.py": f"# contraseña · ñ\nlabel = 'ñandú' ; OPENAI_KEY = '{openai}'\nmy_api_key='{generic}'\n",
             "e.toml": f'[ai]\nkey = "{openai}"\n'}
    for name, content in files.items():
        (root / name).write_text(content, encoding="utf-8")
    return openai, generic


# How a value is assigned, format by format: what Betterleaks' generic rule matches spans the key, the separator and
# the quotes, and one character after the value when there is one.
LAYOUTS = ['{key}={value}', '{key} = "{value}"', "export {key}='{value}'", "{key}: {value}", '{key}: "{value}"',
           '"{key}": "{value}",', "{key} = '{value}';", "  {key}:\t'{value}'  # rotated"]
KEYS = st.from_regex(r"[A-Za-z]{0,8}[_.-]?(api_key|API_KEY|apiKey|token|Token|secret|SECRET|auth)", fullmatch=True)
PREFIXES = st.text(alphabet="abc xyz;ñé·→€中😀", max_size=24)
# A token: random bytes in base64url from a seed (shrinking never makes it less random), with a provider's prefix or none.
TOKENS = st.builds(lambda prefix, seed, size: prefix + random.Random(seed).randbytes(size).hex()[:size] + random.Random(~seed).choice("ABCxyz"),
                   st.sampled_from(["", "sk-proj-", "ghp_", "xoxb-"]), st.integers(0, 2**64), st.integers(16, 48)).filter(
    lambda value: secret_filter.verdict("generic-api-key", "app.py", "", value) is None)
# Who reports a placement: Betterleaks' generic rule (key included), a provider rule of Betterleaks (the value alone),
# Trivy (masks the value), or Betterleaks and Trivy both.
REPORTERS = st.sampled_from(["generic", "provider", "trivy", "generic+trivy", "provider+trivy"])
placements = st.tuples(st.sampled_from(LAYOUTS), KEYS, PREFIXES, REPORTERS, st.integers(0, 6), st.integers(0, 2))


def report(root: Path, rows: list[tuple[str, tuple]]) -> tuple[list[dict], dict]:
    """Writes one file per row (its value and its placement) and returns what Betterleaks and Trivy report for them,
    as they do: Betterleaks' columns in bytes from 1, last included, every copy of the value redacted in `Match`;
    Trivy's offset in bytes and one `*` per byte of the value."""
    entries, secrets = [], []
    for index, (value, (layout, key, prefix, reporters, cut, trail)) in enumerate(rows):
        line = (prefix + " ; " if prefix else "") + layout.format(key=key, value=value)
        content = "x = 1\n" + line + "\n"
        path = f"f{index}.cfg"
        (root / path).write_text(content, encoding="utf-8")
        at = line.index(value)
        if "generic" in reporters or "provider" in reporters:
            start = line.index(key) + min(cut, len(key) - 1) if "generic" in reporters else at
            after = len(line) - at - len(value)
            end = at + len(value) + min(trail, after, len(line[at + len(value):]) - len(line[at + len(value):].lstrip("\"';, ")))
            entries.append({"RuleID": "generic-api-key" if "generic" in reporters else "openai-api-key", "File": f"/src/{path}",
                            "StartLine": 2, "EndLine": 2, "StartColumn": len(line[:start].encode()) + 1,
                            "EndColumn": len(line[:end].encode()), "Match": line[start:end].replace(value, "REDACTED"),
                            "Secret": "REDACTED", "Entropy": entropy(value)})
        if "trivy" in reporters:
            secrets.append({"Target": path, "Class": "secret", "Secrets": [
                {"RuleID": "openai-project-api-key", "Category": "OpenAI", "Severity": "CRITICAL", "Title": "OpenAI", "StartLine": 2,
                 "EndLine": 2, "Offset": len(("x = 1\n" + line[:at]).encode()),
                 "Match": line[:at] + "*" * len(value.encode()) + line[at + len(value):]}]})
    return entries, {"Results": secrets}


def sarif(rows: list[tuple[str, tuple]]) -> list[dict]:
    """The same placements as a SARIF import would bring them: Gitleaks' results (the snippet is the secret) and a SAST
    tool's hard-coded credential results (CWE-798, the snippet is the line)."""
    from pitangus.modules.scanning import sarif_import
    results = {"gitleaks": [], "semgrep": []}
    for index, (value, (layout, key, prefix, *_)) in enumerate(rows):
        line = (prefix + " ; " if prefix else "") + layout.format(key=key, value=value)
        region = {"startLine": 2}
        results["gitleaks"].append({"ruleId": "generic-api-key", "message": {"text": "secret"}, "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f"f{index}.cfg"}, "region": {**region, "snippet": {"text": value}}}}]})
        results["semgrep"].append({"ruleId": "hardcoded-credential", "message": {"text": "credential"}, "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f"f{index}.cfg"}, "region": {**region, "snippet": {"text": line}}}}]})
    document = {"version": "2.1.0", "runs": [
        {"tool": {"driver": {"name": "gitleaks"}}, "results": results["gitleaks"]},
        {"tool": {"driver": {"name": "semgrep", "rules": [{"id": "hardcoded-credential", "properties": {"tags": ["CWE-798: Use of Hard-coded Credentials"]}}]}},
         "results": results["semgrep"]}]}
    return [finding for run in sarif_import.parse(document) for finding in run["findings"]]


class ValueIdentityTests(unittest.TestCase):
    """The same value is one secret whatever key holds it, in whichever format, quoted or not, after whatever text, and
    whichever engine and rule found it; two values are never one."""

    def test_the_recorded_run_gives_each_value_one_identity_across_formats_and_engines(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            openai, generic = formats_snapshot(root)
            found = engines.parse_betterleaks(json.loads((FIXTURES / "betterleaks-1.9-formats.json").read_text()), None, root)
            seen = engines.parse_trivy(json.loads((FIXTURES / "trivy-0.75-formats.json").read_text()), {}, root=root)
            merged = engines.merge_secrets(found, seen)
        identities = {secret_identity.identity(openai): "openai", secret_identity.identity(generic): "generic"}
        self.assertEqual(Counter(identities[item["identity"]] for item in found), Counter(openai=5, generic=5))
        self.assertEqual(Counter(identities[item["identity"]] for item in seen), Counter(openai=5))
        # Betterleaks' and Trivy's report of the OpenAI key on each line are one finding: ten secrets in all.
        self.assertEqual(Counter(identities[item["identity"]] for item in merged), Counter(openai=5, generic=5))
        self.assertTrue(all(item.get("also_detected_by") == ["trivy"] for item in merged if identities[item["identity"]] == "openai"))
        # The formula before read the whole match: five identities for one generic token, each now a former name of
        # that value (never an engine fingerprint, which any value in that place shares).
        legacy = {name for item in found if identities[item["identity"]] == "generic" for name in item.get("value_formers") or []}
        self.assertEqual(len(legacy), 5)
        self.assertFalse(legacy & set(identities))
        self.assertTrue(all(openai not in json.dumps(item) and generic not in json.dumps(item) for item in merged))

    @settings(deadline=None, max_examples=150 * SCALE)
    @given(value=TOKENS, where=st.lists(placements, min_size=2, max_size=5))
    @example(value="sk-proj-" + "a1B2c3D4e5" * 5, where=[('{key} = "{value}"', "API_KEY", "", "generic", 0, 1),
                                                         ('{key}="{value}"', "API_KEY", "", "generic", 0, 1),
                                                         ("{key}: {value}", "other_secret", "ñandú →", "generic+trivy", 2, 0)])
    def test_the_same_value_is_one_identity_whatever_the_key_format_quotes_text_or_engine(self, value, where):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            entries, trivy = report(root, [(value, placement) for placement in where])
            found = engines.parse_betterleaks(entries, None, root)
            seen = engines.parse_trivy(trivy, {}, root=root)
            merged = engines.merge_secrets(found, seen)
        self.assertEqual([item.get("identity") for item in [*found, *seen]], [secret_identity.identity(value)] * (len(found) + len(seen)))
        self.assertEqual(len(found) + len(seen), len(entries) + len(trivy["Results"]))
        self.assertEqual(len(merged), len(where))   # one finding per place, whichever engines reported it
        self.assertNotIn(value, json.dumps(merged))
        imported = sarif([(value, placement) for placement in where])
        self.assertEqual([item.get("identity") for item in imported], [secret_identity.identity(value)] * 2 * len(where))
        self.assertTrue(all(value not in item["fingerprint"] + json.dumps(item.get("previous_fingerprints") or []) for item in imported))

    @settings(deadline=None, max_examples=100 * SCALE)
    @given(values=st.lists(TOKENS, min_size=2, max_size=4, unique=True), placement=placements)
    def test_different_values_never_share_an_identity(self, values, placement):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            entries, trivy = report(root, [(value, placement) for value in values])
            findings = [*engines.parse_betterleaks(entries, None, root), *engines.parse_trivy(trivy, {}, root=root)]
        expected = {secret_identity.identity(value) for value in values}
        self.assertEqual(len(expected), len(values))
        self.assertEqual({item.get("identity") for item in findings}, expected)
        imported = sarif([(value, placement) for value in values])
        self.assertEqual(Counter(item.get("identity") for item in imported), Counter(dict.fromkeys(expected, 2)))
        self.assertEqual(len(engines.merge_secrets(*[[item for item in findings if item["tool"] == tool] for tool in ("betterleaks", "trivy")])),
                         len(values))


if __name__ == "__main__":
    unittest.main()
