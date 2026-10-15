"""The secret filter (scanning/secret_filter.py): what the engines match but can't be a secret is set aside, counted and
named, never dropped silently. Measured on the public corpus, and checked as properties: moving a match into tests or
docs never adds a finding, a reference is never a finding, a strong value assigned to a password in the code always is,
and each match is judged alone (in any order, with any neighbours). For every other rule: a key that says it is public
(a Supabase anon JWT) is set aside and one that doesn't never is, a placeholder by its shape is set aside, a random
token never is, and outside the code a token stays a finding with a lower priority, in both secret engines."""

import base64
import json
import os
import random
import string
import subprocess
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

from hypothesis import given, settings, strategies as st

import testenv
from pitangus.modules.scanning.secret_location import entropy, same_entropy
from pitangus.modules.scanning import engines, secret_filter as sf, secret_identity
from pitangus.shared.i18n import text

PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

FIXTURES = Path(__file__).parent / "fixtures"
PASSWORD = sf.GENERIC_PASSWORD
# Built here, so the repository's own scan doesn't flag this file.
SERVICE_ACCOUNT = "service" + "_account"
PRIVATE_KEY_HEADER, PRIVATE_KEY_FOOTER = "-----BEGIN " + "PRIVATE KEY-----", "-----END " + "PRIVATE KEY-----"
GO_SUM_DIGEST = "0BeftmEHU7i3Dv0VFwBtidy" + "/ba37Vcdjvqst9EYu8Sk="
FIREBASE_TOKEN = "4142e2a1-bf43-43b5-" + "b7cf-6616be3fd4e3"
GALLERY_HEX = "7617adae70159d09" + "ba78cfec73c13be3"


def corpus() -> list[tuple[str, str, str, str]]:
    """(label, repository, path, text) of tests/fixtures/generic-password-corpus.tsv."""
    rows = [line.split("\t") for line in (FIXTURES / "generic-password-corpus.tsv").read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")]
    return [(label, repository, path, text) for label, repository, path, _, text in rows]


def judged(path: str, text: str) -> str | None:
    return sf.verdict(PASSWORD, path, text, sf.assigned_value(text))


class CorpusTests(unittest.TestCase):
    """The validation's measurement (1525 matches of generic-password on 18 public repositories: 12 real, 10 unsure)
    reproduced on every match outside tests and docs plus a sample inside them."""

    def test_every_labeled_real_password_is_kept_and_what_is_left_is_mostly_real(self):
        """What this proves, and no more: on the labeled corpus the filter keeps the 12 real passwords (recall 12/12)
        and 6 of the 10 unsure seed values; of the 23 matches it keeps, 12 are real (52%) and 18 real or seed data
        (78%). The 1428 matches under tests, docs and translations outside this sample are set aside by path alone."""
        rows = corpus()
        kept = Counter(label for label, _, path, text in rows if judged(path, text) is None)
        labels = Counter(label for label, *_ in rows)
        self.assertEqual(labels, Counter(TP=12, unsure=10, FP=75))
        self.assertEqual(kept, Counter(TP=12, unsure=6, FP=5))

    def test_each_reason_is_one_of_the_named_ones(self):
        reasons = Counter(judged(path, text) for _, _, path, text in corpus())
        self.assertLessEqual(set(reasons) - {None}, set(sf.REASONS))
        self.assertTrue({"path", "placeholder", "identifier", "weak", "prose"} <= set(reasons))


# --- Properties --------------------------------------------------------------------------

segment = st.text(alphabet=string.ascii_lowercase + string.digits + "_-", min_size=1, max_size=10)
code_paths = st.lists(segment, min_size=1, max_size=4).map("/".join).map(lambda path: path + ".py").filter(lambda path: not sf.outside_code(path))
keys = st.sampled_from(["password", "DB_PASSWORD", "adminPassword", "mysql_root_password", "passwd", "PGPASSWORD", "user.password"])
# A strong value: letters and at least one digit, from characters that open no reference, prose or quote.
strong = st.text(alphabet=string.ascii_letters + string.digits + "!@^&*-_+.", min_size=sf.STRONG, max_size=40).filter(
    lambda value: any(char.isdigit() for char in value) and any(char.isalpha() for char in value)
    and not value.lower().startswith(("your", "my-")))
values = st.one_of(strong, st.text(alphabet=string.printable.strip(), min_size=1, max_size=30))
layouts = st.sampled_from(['{key} = "{value}"', "{key}: '{value}'", "- {key}={value}", '"{key}": "{value}",'])


class PropertyTests(unittest.TestCase):
    @settings(max_examples=200 * SCALE)
    @given(st.sampled_from([PASSWORD, "generic-api-key", "github-pat"]), code_paths, keys, values, layouts,
           st.sampled_from(["tests/", "docs/", "src/locales/", "examples/", "spec/", "e2e/fixtures/"]))
    def test_moving_a_match_into_tests_or_docs_never_adds_a_finding(self, rule, path, key, value, layout, folder):
        line = layout.format(key=key, value=value)
        here, there = sf.verdict(rule, path, line, value), sf.verdict(rule, folder + path, line, value)
        if here is not None:
            self.assertIsNotNone(there)
        if rule == PASSWORD:
            self.assertEqual(there, "path")

    @settings(max_examples=200 * SCALE)
    @given(code_paths, keys, layouts, st.text(alphabet=string.ascii_uppercase + string.digits + "_", min_size=1, max_size=20),
           st.sampled_from(["${{{name}}}", "{{{{ {name} }}}}", "$({name})", "%({name})s", "<{name}>", "process.env.{name}",
                            "os.environ['{name}']", "getenv(\"{name}\")", "${name}"]))
    def test_a_reference_in_place_of_the_value_is_never_a_finding(self, path, key, layout, name, shape):
        reference = shape.format(name=name)
        self.assertIsNotNone(sf.verdict(PASSWORD, path, layout.format(key=key, value=reference), reference))

    @settings(max_examples=300 * SCALE)
    @given(code_paths, keys, strong, layouts)
    def test_a_strong_value_assigned_to_a_password_in_the_code_is_always_a_finding(self, path, key, value, layout):
        self.assertIsNone(sf.verdict(PASSWORD, path, layout.format(key=key, value=value), value))

    @settings(max_examples=100 * SCALE)
    @given(code_paths, keys, values, layouts)
    def test_a_value_that_could_not_be_read_is_a_finding(self, path, key, value, layout):
        """Nothing is set aside unseen: without the value only the path decides."""
        self.assertIsNone(sf.verdict(PASSWORD, path, layout.format(key=key, value=value), None))

    @settings(max_examples=50 * SCALE, deadline=None)
    @given(st.lists(st.tuples(code_paths | st.sampled_from(["tests/a.py", "docs/b.md"]), keys, values, layouts).filter(
        lambda item: item[3].format(key=item[1], value=item[2]).count(item[2]) == 1 and "REDACTED" not in item[2]), min_size=1, max_size=8),
           st.randoms(use_true_random=False))
    def test_each_match_is_judged_alone_whatever_its_neighbours_and_order(self, matches, rng):
        """Through parse_betterleaks over a snapshot: the matches kept are exactly those the filter keeps one by one, in
        any order, and every one set aside is counted under its reason."""
        expected = Counter()
        with tempfile.TemporaryDirectory() as folder:
            root, payload = Path(folder), []
            for index, (path, key, value, layout) in enumerate(matches):
                path = f"{index}/{path}"
                line = layout.format(key=key, value=value)
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_text(f"x = 1\n{line}\n", encoding="utf-8")
                start = line.index(key)
                # As Betterleaks redacts: every copy of the value in the match.
                payload.append({"RuleID": PASSWORD, "File": f"/src/{path}", "StartLine": 2, "EndLine": 2, "StartColumn": start + 1,
                                "EndColumn": len(line), "Match": line[start:].replace(value, "REDACTED"), "Entropy": entropy(value)})
                reason = sf.verdict(PASSWORD, path, line, value)
                expected[reason or "kept"] += 1
            shuffled = payload[:]
            rng.shuffle(shuffled)
            for report in (payload, shuffled):
                screened = Counter()
                findings = engines.parse_betterleaks(report, None, root, screened)
                self.assertEqual(len(findings), expected["kept"])
                self.assertEqual(screened, Counter({reason: count for reason, count in expected.items() if reason != "kept"}))


# A password nobody would mistake for text: letters of one kind only, from a seed (shrinking keeps it random).
ONE_KIND = {"lowercase": string.ascii_lowercase, "uppercase": string.ascii_uppercase, "digits": string.digits,
            "accented": "abcdefghijklmnopqrstuvwxyzñáéíóúü"}
ACCENTED = str.maketrans("aeiounAEIOUN", "áéíóúñÁÉÍÓÚÑ")


def one_kind(kind: str, size: int, seed: int) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(ONE_KIND[kind]) for _ in range(size))


class StrengthPropertyTests(unittest.TestCase):
    """S3: what "weak", "prose" and "identifier" set aside is decided by length and kinds of characters, never by the
    script a password is written in, and a long password of one kind or a passphrase is a password."""

    @settings(max_examples=300 * SCALE)
    @given(code_paths, keys, layouts, st.sampled_from(sorted(ONE_KIND)), st.integers(sf.LONG, 40), st.integers(0, 2**64))
    def test_a_long_password_of_one_kind_is_always_a_finding(self, path, key, layout, kind, size, seed):
        value = one_kind(kind, size, seed)
        self.assertIsNone(sf.verdict(PASSWORD, path, layout.format(key=key, value=value), value))

    @settings(max_examples=200 * SCALE)
    @given(code_paths, keys, layouts, st.sampled_from(sorted(ONE_KIND)), st.integers(1, sf.LONG - 1), st.integers(0, 2**64))
    def test_a_shorter_password_of_one_kind_is_weak_or_a_placeholder(self, path, key, layout, kind, size, seed):
        value = one_kind(kind, size, seed)
        self.assertIn(sf.verdict(PASSWORD, path, layout.format(key=key, value=value), value), ("weak", "placeholder", "identifier"))

    @settings(max_examples=300 * SCALE)
    @given(code_paths, keys, strong, layouts)
    def test_writing_a_strong_password_with_accents_never_sets_it_aside(self, path, key, value, layout):
        """Metamorphic: `Contrasena2024!` and `Contraseña2024!` are the same password to the filter."""
        accented = value.translate(ACCENTED)
        self.assertEqual(sf.verdict(PASSWORD, path, layout.format(key=key, value=accented), accented),
                         sf.verdict(PASSWORD, path, layout.format(key=key, value=value), value))

    @settings(max_examples=200 * SCALE)
    @given(code_paths, keys, layouts, st.lists(st.from_regex(r"[a-z]{3,8}", fullmatch=True), min_size=4, max_size=7), st.sampled_from("-_"))
    def test_a_passphrase_of_four_words_is_a_finding_and_a_name_in_code_is_not(self, path, key, layout, words, separator):
        phrase = separator.join(words)
        verdict = sf.verdict(PASSWORD, path, layout.format(key=key, value=phrase), phrase)
        self.assertEqual(verdict, None if len(phrase) >= sf.PASSPHRASE_MIN else "identifier")
        for name in (".".join(words[:2]) + "." + "-".join(words[2:]), "-".join(words[:3])):   # namespaced, or three words
            self.assertEqual(sf.verdict(PASSWORD, path, layout.format(key=key, value=name), name), "identifier")

    def test_the_seeds(self):
        crapi = one_kind("lowercase", 19, 2024)   # crAPI's password: 19 lowercase letters, in 12 places
        lines = [f'password: "{crapi}"', f"- POSTGRES_PASSWORD={crapi}", f'"password": "{crapi}",', f"DB_PASSWORD = '{crapi}'"] * 3
        self.assertEqual([sf.verdict(PASSWORD, f"services/s{index}/config.yml", line, crapi) for index, line in enumerate(lines)], [None] * 12)
        for value in ("Contraseña2024!", "correct-horse-battery-staple"):
            self.assertIsNone(sf.verdict(PASSWORD, "app/settings.py", f'DB_PASSWORD = "{value}"', value))
        for label in ("Contraseña", "Repite la contraseña", "label.change-password", "message.two-factor-error-incorrect-password"):
            self.assertIsNotNone(sf.verdict(PASSWORD, "app/form.ts", f'password: "{label}"', label))


class LongLineTests(unittest.TestCase):
    """S3: in a line longer than Betterleaks' first fragment (~125 KB) its columns count from the fragment, not the line:
    each of several matches of one shape is still read once at most, at its own place, and Trivy's offsets give columns
    from the start of the line. A Betterleaks column there only says the value starts at it or later, and its pieces
    overlap (one secret may come twice), so a match with places of another value of its length and entropy from its
    column on can't be told apart: it is unlinkable, never another value's name. One with no such place is read."""

    FRAGMENT = 125_000

    @settings(max_examples=20 * SCALE, deadline=None)
    @given(st.lists(strong.filter(lambda value: len(value) >= 10), min_size=3, max_size=6, unique=True), st.data())
    def test_every_match_of_a_long_line_is_read_once_at_its_place(self, values, data):
        filler = data.draw(st.sampled_from(["x", "ñ", "a·", "中x"]))
        gaps = [data.draw(st.integers(210_000 // len(values), 210_000 // len(values) + 40_000), label="gap") for _ in values]
        parts, offsets = [], []
        for value, gap in zip(values, gaps):
            parts.append(filler * (gap // len(filler.encode())))
            parts.append(f'var password = "{value}";')
        line = "".join(parts)
        self.assertGreater(len(line.encode()), 200_000)
        content = "a = 1\n" + line + "\n"
        entries, secrets, base = [], [], len(b"a = 1\n")
        for value in values:
            at = line.index(f'password = "{value}"')
            start, size = len(line[:at].encode()), len(f'password = "{value}";'.encode())
            if start + size > self.FRAGMENT:
                # Counted from the start of a later fragment: anywhere before, even on another match of the same shape.
                start = data.draw(st.one_of(st.integers(0, start - 1), st.sampled_from(offsets or [0])), label="fragment column")
            offsets.append(len(line[:at].encode()))
            entries.append({"RuleID": PASSWORD, "File": "/src/bundle.js", "StartLine": 2, "EndLine": 2, "StartColumn": start + 1,
                            "EndColumn": start + size, "Match": 'password = "REDACTED";', "Entropy": entropy(value)})
            value_at = line.index(value)
            secrets.append({"RuleID": PASSWORD, "Category": "Generic", "Severity": "HIGH", "Title": "Secret", "StartLine": 2,
                            "EndLine": 2, "Offset": base + len(line[:value_at].encode()), "Match": 'password = "' + "*" * len(value.encode()) + '";'})
        data.draw(st.randoms(use_true_random=False), label="order").shuffle(entries)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "bundle.js").write_text(content, encoding="utf-8")
            screened = Counter()
            found = engines.parse_betterleaks(entries, None, root, screened)
            seen = engines.parse_trivy({"Results": [{"Target": "bundle.js", "Class": "secret", "Secrets": secrets}]}, {}, root=root)
            masked = secret_identity.values(root, found)
        expected = sorted(secret_identity.identity(value) for value in values)
        self.assertEqual((len(found), dict(screened)), (len(values), {}))
        self.assertEqual(sorted(item.get("identity") for item in seen), expected)
        read = [item for item in found if not item.get("unlinkable")]
        self.assertEqual(len({item["identity"] for item in read}), len(read))      # each value once at most
        alone = {value for value in values if not any(other != value and len(other.encode()) == len(value.encode())
                                                       and same_entropy(other, entropy(value)) for other in values)}
        self.assertLessEqual({secret_identity.identity(value) for value in alone}, {item["identity"] for item in read})
        for item in [*read, *seen]:
            first, start, last, end = item["span"]
            self.assertEqual(secret_identity.identity(line[start:end]), item["identity"])     # its own value, at its place
            self.assertIn(line[start:end], values)
        self.assertTrue({line[item["span"][1]:item["span"][3]] for item in read} <= masked["bundle.js"])


# --- Tokens (every rule but generic-password) -----------------------------------------------

TOKEN_RULES = st.sampled_from(["jwt", "generic-api-key", "curl-auth-header", "github-pat", "slack-webhook-url", "aws-access-token"])
# A random token: 18 to 48 random bytes, base64url, drawn from a seed so that shrinking never makes it less random. A
# placeholder shape appears in one by chance about once in 10^7.
tokens = st.builds(lambda seed, size: base64.urlsafe_b64encode(random.Random(seed).randbytes(size)).decode().rstrip("="),
                   st.integers(0, 2**64), st.integers(18, 48))


def jwt(header: dict, claims: dict, signature: str = "c2lnbmF0dXJl") -> str:
    def part(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    return f"{part(header)}.{part(claims)}.{signature}"


claim_values = st.one_of(st.text(string.ascii_letters + string.digits, max_size=12), st.integers(0, 2**40))
claim_sets = st.dictionaries(st.sampled_from(["iss", "ref", "sub", "iat", "exp", "aud", "email"]), claim_values, max_size=5)


class TokenPropertyTests(unittest.TestCase):
    @settings(max_examples=200 * SCALE)
    @given(TOKEN_RULES, code_paths, claim_sets, st.sampled_from(["anon", "service_role", "authenticated", "admin", None]),
           st.sampled_from(["HS256", "RS256", "ES256"]))
    def test_a_key_is_public_only_when_its_claims_say_anon(self, rule, path, claims, role, algorithm):
        """A Supabase anon key ships in every frontend; a service_role key bypasses row level security and stays a secret."""
        token = jwt({"alg": algorithm, "typ": "JWT"}, {**claims, **({"role": role} if role else {})})
        self.assertEqual(sf.verdict(rule, path, f'key = "{token}"', token) == "public", role == "anon")
        if role != "anon":
            self.assertIsNone(sf.verdict(rule, path, f'key = "{token}"', token))

    @settings(max_examples=100 * SCALE)
    @given(TOKEN_RULES, code_paths, claim_sets)
    def test_an_unsigned_jwt_is_never_a_secret(self, rule, path, claims):
        token = jwt({"alg": "none", "typ": "JWT"}, claims, signature="")
        self.assertEqual(sf.verdict(rule, path, token, token), "unsigned")

    @settings(max_examples=300 * SCALE)
    @given(TOKEN_RULES, code_paths | st.sampled_from(["tests/a.py", "docs/b.md", "examples/c.js"]), tokens)
    def test_a_random_token_is_never_set_aside_wherever_it_is(self, rule, path, token):
        self.assertIsNone(sf.verdict(rule, path, f'token = "{token}"', token))

    @settings(max_examples=200 * SCALE)
    @given(TOKEN_RULES, code_paths, tokens, st.integers(0, 40),
           st.one_of(st.sampled_from(["EXAMPLE", "placeholder", "changeme", "...", "REDACTED"]),
                     st.sampled_from("X0x*9aZ").map(lambda char: char * sf.VENDOR_RUN),
                     st.sampled_from(["1234567890", "0123456789", "abcdefghij", "qrstuvwxyz"])),
           st.sampled_from(["", "YOUR-", "your_", "MY-"]))
    def test_a_placeholder_word_or_a_typed_run_sets_any_token_aside(self, rule, path, token, at, shape, prefix):
        """`YOUR-ACCESS-TOKEN`, `EXAMPLE`, a vendor's prefix and ten zeros, or `1234567890abcdef…`: no issuer hands those out."""
        value = prefix + token[:at] + shape + token[at:]
        self.assertIn(sf.verdict(rule, path, f'token = "{value}"', value), ("placeholder", "identifier"))

    @settings(max_examples=200 * SCALE)
    @given(TOKEN_RULES, code_paths, tokens, st.integers(0, 40),
           st.one_of(st.sampled_from("X0x*9aZ").map(lambda char: char * sf.RUN), st.sampled_from(["123456", "abcdef", "345678"])))
    def test_a_counted_run_sets_aside_only_what_a_generic_rule_matched(self, rule, path, token, at, shape):
        """`XXXXXX`, `123456`: a generic rule has nothing else to go on. A vendor's rule matched the token's own format,
        and random digits make such a run once in 10^5: it never loses a token to one shorter than VENDOR_RUN. Nor
        does a password rule: a person does pick `Aa12345678`."""
        value = token[:at] + shape + token[at:]
        expected = "placeholder" if rule.startswith(sf.GENERIC) else None
        self.assertEqual(sf.verdict(rule, path, f'token = "{value}"', value), expected)
        self.assertIsNone(sf.verdict("hashicorp-tf-password", path, f'password = "Aa{shape}!"', f"Aa{shape}!"))
        self.assertIsNone(sf.verdict(PASSWORD, path, f'password = "Aa{token[:at]}{shape}!"', f"Aa{token[:at]}{shape}!"))

    @settings(max_examples=100 * SCALE)
    @given(TOKEN_RULES, code_paths, st.from_regex(r"[A-Z]{3,10}(_[A-Z]{3,10}){1,3}|[a-z]{3,8}(-[a-z]{3,8}){1,3}", fullmatch=True))
    def test_a_name_standing_in_for_the_value_is_never_a_secret(self, rule, path, name):
        """`Authorization: Bearer ACCESS_TOKEN`, `apikey: user-session-token`."""
        self.assertEqual(sf.verdict(rule, path, f"Authorization: Bearer {name}", name), "identifier")

    def test_the_seeds(self):
        anon = jwt({"alg": "HS256", "typ": "JWT"}, {"iss": "supabase-demo", "role": "anon", "exp": 1983812996})
        service = jwt({"alg": "HS256", "typ": "JWT"}, {"iss": "supabase-demo", "role": "service_role", "exp": 1983812996})
        self.assertEqual(sf.verdict("jwt", "app/client.ts", "", anon), "public")
        self.assertIsNone(sf.verdict("jwt", "app/server.ts", "", service))
        self.assertEqual(sf.verdict("curl-auth-header", "README.md", "", "YOUR-ACCESS-TOKEN"), "placeholder")
        slack = "https://hooks.slack.com/services/T" + "0" * 8 + "/B" + "0" * 8 + "/" + "X" * 24
        self.assertEqual(sf.verdict("slack-webhook-url", "views/integrations.html", "", slack), "placeholder")
        self.assertIsNone(sf.verdict("hashicorp-tf-password", "terraform/sql.tf", "", "Aa12345678"))
        self.assertEqual(sf.verdict("generic-api-key", "a.java", "", "API_KEY=12345678-1234-1234-1234-123456789abc"), "placeholder")
        self.assertEqual(sf.verdict("jwt", "src/x.ts", "", "sb_publishable_" + "a1B2c3D4e5" * 3), "public")


class PriorityTests(unittest.TestCase):
    @settings(max_examples=50 * SCALE, deadline=None)
    @given(st.sampled_from(["github-pat", "generic-api-key", "jwt"]), code_paths, tokens,
           st.sampled_from(["tests/", "docs/", "examples/", "src/__tests__/"]))
    def test_a_token_moved_outside_the_code_stays_a_finding_with_a_lower_priority(self, rule, path, token, folder):
        line = f'token = "{token}"'
        actions = []
        with tempfile.TemporaryDirectory() as root:
            for where in (path, folder + path):
                (Path(root) / where).parent.mkdir(parents=True, exist_ok=True)
                (Path(root) / where).write_text(f"x = 1\n{line}\n")
                entry = {"RuleID": rule, "File": f"/src/{where}", "StartLine": 2, "EndLine": 2, "StartColumn": 10, "EndColumn": 9 + len(token),
                         "Match": "REDACTED"}
                found = engines.parse_betterleaks([entry], None, Path(root))
                self.assertEqual(len(found), 1)
                actions.append(found[0]["priority"]["action"])
        self.assertEqual(actions, ["act", "attend"])


class TrivyTests(unittest.TestCase):
    def test_trivy_sets_aside_the_same_shapes_and_counts_them(self):
        """Trivy masks the value; it is read from the snapshot at the offset, judged, and the anon key and the placeholder
        are counted, never listed; the service_role key stays."""
        anon = jwt({"alg": "HS256", "typ": "JWT"}, {"role": "anon"})
        service = jwt({"alg": "HS256", "typ": "JWT"}, {"role": "service_role"})
        lines = [f'ANON = "{anon}"', f'SERVICE = "{service}"', 'HOOK = "https://hooks.slack.com/services/T00000000/B00000000/' + "X" * 24 + '"']
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            text = "\n".join(lines) + "\n"
            (root / "app.py").write_text(text)
            secrets, offset = [], 0
            for number, line in enumerate(lines, 1):
                start = line.index('"') + 1
                value = line[start:line.rindex('"')]
                secrets.append({"RuleID": "jwt-token" if number < 3 else "slack-web-hook", "Category": "JWT", "Title": "t", "StartLine": number,
                                "EndLine": number, "Offset": offset + start, "Match": line[:start] + "*" * len(value) + '"'})
                offset += len(line) + 1
            screened = Counter()
            found = engines.parse_trivy({"Results": [{"Target": "app.py", "Class": "secret", "Secrets": secrets}]}, {}, root=root, screened=screened)
        self.assertEqual([item["line"] for item in found], [2])
        self.assertEqual(screened, Counter({"public": 1, "placeholder": 1}))
        self.assertNotIn(anon, json.dumps(found))


class RedactionTests(unittest.TestCase):
    def test_a_value_redacted_in_its_key_too_is_still_read(self):
        """Betterleaks redacts every copy of the value, so `$password = "password"` comes back as
        `REDACTED = "REDACTED";`: the value is the text every copy shares."""
        self.assertEqual(sf.value_from_match('REDACTED = "REDACTED";', 'password = "password";'), "password")
        self.assertIsNone(sf.value_from_match('REDACTED = "REDACTED";', 'password = "secret12";'))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "app.php").write_text('<?php\n$password = "password";\n')
            screened = Counter()
            entry = {"RuleID": PASSWORD, "File": "/src/app.php", "StartLine": 2, "EndLine": 2, "StartColumn": 2, "EndColumn": 23,
                     "Match": 'REDACTED = "REDACTED";'}
            self.assertEqual(engines.parse_betterleaks([entry], None, root, screened), [])
            self.assertEqual(screened, Counter({"placeholder": 1}))


class EngineTests(unittest.TestCase):
    """What the filter sets aside is said in the Betterleaks step and the scan's limitations, never dropped silently."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.snapshot = Path(self.folder.name) / "snapshot"
        (self.snapshot / "app").mkdir(parents=True)
        (self.snapshot / "tests").mkdir()
        (self.snapshot / "app" / "settings.py").write_text('x = 1\nDB_PASSWORD = "Kp4!vR9zQe2w"\nLABEL_PASSWORD = "label.password"\n')
        (self.snapshot / "tests" / "conftest.py").write_text('x = 1\nPASSWORD = "Kp4!vR9zQe2w"\n')
        docker = patch.dict(engines._docker_state, {"ok": True}, clear=True)
        docker.start()
        self.addCleanup(docker.stop)
        testenv.docker_runner(self)

    def report(self) -> list[dict]:
        def entry(path, line, text, value):
            start = text.index("PASSWORD")
            return {"RuleID": PASSWORD, "File": f"/src/{path}", "StartLine": line, "EndLine": line, "StartColumn": start + 1,
                    "EndColumn": len(text), "Match": text[start:text.index(value)] + 'REDACTED"', "Entropy": entropy(value)}
        return [entry("app/settings.py", 2, 'DB_PASSWORD = "Kp4!vR9zQe2w"', "Kp4!vR9zQe2w"),
                entry("app/settings.py", 3, 'LABEL_PASSWORD = "label.password"', "label.password"),
                entry("tests/conftest.py", 2, 'PASSWORD = "Kp4!vR9zQe2w"', "Kp4!vR9zQe2w")]

    def test_the_step_counts_what_it_set_aside_by_reason_and_keeps_the_rest(self):
        report = self.report()

        def fake(key, arguments, snapshot, *, mounts=None, **kwargs):
            out = Path(next(mounts[index + 1] for index, flag in enumerate(mounts) if flag == "-v" and mounts[index + 1].endswith(":/out")).rsplit(":", 1)[0])
            (out / "report.json").write_text(json.dumps(report))
            return subprocess.CompletedProcess(arguments, 0, "", "")
        with patch.object(engines, "_run", side_effect=fake):
            result = engines.run_betterleaks(self.snapshot)
        self.assertEqual([(item["path"], item["line"]) for item in result["findings"]], [("app/settings.py", 2)])
        self.assertEqual(result["screened"], {"path": 1, "identifier": 1})
        detail = json.dumps(result["detail"])
        self.assertIn("scanning.secret_filter.screened", detail)
        self.assertNotIn("Kp4!vR9zQe2w", json.dumps(result))
        self.assertNotIn("label.password", json.dumps(result))
        self.assertEqual(engines.screened_detail(Counter()), None)
        self.assertIn("2 matches set aside as not secrets: 1 outside the code (tests, docs, examples or translations) and 1 identifier.",
                      text(result["detail"], "en"))
        self.assertIn("2 coincidencias descartadas porque no son secretos", text(result["detail"], "es"))


# --- Values that files hold in plain sight (lockfiles, go.sum, tests, examples, vendored code, docs) ----------------
# Every file is read (scanning/secret_coverage): what is set aside is decided by the value and the syntax right around
# it, never by the file it is in. The paths below are where these values live and also any other path: the verdict
# is the same.

ANY_PATHS = st.sampled_from(["go.sum", "pnpm-lock.yaml", "package-lock.json", "yarn.lock", "Pipfile.lock", "mvnw",
                             "tests/fixtures/a.json", "examples/app/config.ts", "vendor/lib/x.js", "node_modules/x/index.js",
                             "docs/guide.md", "contrib/bruno/Create a user.bru", "dataconnect/insert.gql"]) | code_paths
KEYWORDS = ["auth", "token", "key", "secret", "api", "password", "credential", "access"]
words = st.from_regex(r"[a-z]{3,9}", fullmatch=True)
module_paths = st.builds(lambda host, owner, name, word, at: f"{host}/{owner}/" + (name[:at] + word + name[at:]),
                         st.sampled_from(["github.com", "golang.org/x", "gopkg.in", "go.opentelemetry.io"]), words, words,
                         st.sampled_from(KEYWORDS), st.integers(0, 9))
semvers = st.builds(lambda a, b, c, pre: f"{a}.{b}.{c}" + pre, st.integers(0, 40), st.integers(0, 99), st.integers(0, 999),
                    st.sampled_from(["", "-rc.1", "-beta.3", "-alpha", "-canary.4f3c2a1", "+build.7", "-0.20240101120000-abcdef123456"]))
packages = st.builds(lambda scope, name, word: (f"@{scope}/" if scope else "") + name + "-" + word,
                     st.one_of(st.just(""), words), words, st.sampled_from(KEYWORDS))


def random_bytes(seed: int, size: int) -> bytes:
    return random.Random(seed).randbytes(size)


def peers(draw_versions: list[str], names: list[str]) -> str:
    """pnpm's peer suffix, nested on the first peer: `(a@1.0.0(b@2.0.0))(c@3.0.0)`."""
    out = ""
    for index, (name, version) in enumerate(zip(names, draw_versions)):
        out += f"({name}@{version}" + (f"({names[0]}@{draw_versions[0]})" if index == 1 else "") + ")"
    return out


# A secret of a common shape, random from a seed: what must be found wherever it is put.
SECRET_SHAPES = {
    "base64": lambda rng: base64.b64encode(rng.randbytes(rng.randint(24, 48))).decode(),
    "base64url": lambda rng: base64.urlsafe_b64encode(rng.randbytes(rng.randint(18, 40))).decode().rstrip("="),
    "hex": lambda rng: rng.randbytes(rng.choice([24, 30, 36])).hex(),
    "github": lambda rng: "ghp_" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(36)),
    "stripe": lambda rng: "sk_live_" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(24)),
    "aws": lambda rng: "".join(rng.choice(string.ascii_letters + string.digits + "/+") for _ in range(40)),
    "slack": lambda rng: "xoxb-" + "-".join(str(rng.randint(10**11, 10**12 - 1)) for _ in range(2)) + "-"
                         + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(24)),
    "password": lambda rng: "".join(rng.choice(string.ascii_letters + string.digits + "!@#%^*") for _ in range(rng.randint(12, 24))),
}
secrets_ = st.builds(lambda shape, seed: SECRET_SHAPES[shape](random.Random(seed)), st.sampled_from(sorted(SECRET_SHAPES)),
                     st.integers(0, 2**64)).filter(lambda value: any(c.isdigit() for c in value) and any(c.isalpha() for c in value))
# The rule that matches each shape: a vendor's by its format, a generic one otherwise.
SHAPE_RULES = {"github": "github-pat", "stripe": "stripe-access-token", "slack": "slack-bot-token", "aws": "aws-secret-access-key",
               "base64": "generic-api-key", "base64url": "generic-api-key", "hex": "generic-api-key", "password": PASSWORD}
shaped_secrets = st.builds(lambda shape, seed: (SHAPE_RULES[shape], SECRET_SHAPES[shape](random.Random(seed))),
                           st.sampled_from(sorted(SECRET_SHAPES)), st.integers(0, 2**64))


def kept(rule: str, secret: str) -> bool:
    """Whether a real secret matched by `rule` is a finding: always, but for a random token with a run the filter takes
    for a placeholder (TokenPropertyTests): of six for a generic rule, of VENDOR_RUN for a vendor's (once in 10^9 per
    position of random digits)."""
    if rule == PASSWORD:
        return True
    return not sf._counted(secret, sf.RUN if rule.startswith(sf.GENERIC) else sf.VENDOR_RUN)


# A vendor's token with a run of six to eight alike or consecutive characters forced into its random part: still that
# vendor's token.
runs = st.builds(lambda kind, size, first: first * size if kind == "same" else "".join(chr(ord(first) + index) for index in range(size)),
                 st.sampled_from(["same", "step"]), st.integers(sf.RUN, sf.VENDOR_RUN - 2), st.sampled_from("0aA"))


def with_run(shape: str, seed: int, at: int, run: str) -> tuple[str, str]:
    token = SECRET_SHAPES[shape](random.Random(seed))
    return SHAPE_RULES[shape], token[:len(token) - at] + run + token[len(token) - at:]


run_tokens = st.builds(with_run, st.sampled_from(["github", "stripe", "slack", "aws"]), st.integers(0, 2**64), st.integers(0, 20), runs)
SECRET_LAYOUTS = ['{key} = "{value}"', "{key}: '{value}'", "{key}={value}", '"{key}": "{value}",', "  {key}: {value}",
                  "const {key} = `{value}`;", "// {key}: '{value}'", "--{key} {value}"]
SECRET_KEYS = ["api_key", "API_TOKEN", "clientSecret", "auth_token", "accessKey", "password", "db_password", "secret"]


@st.composite
def benign(draw) -> tuple[str, str, str]:
    """(reason, line, value): a value a lockfile, go.sum, a test, an example or vendored code holds in plain sight,
    on a line whose key an engine flags."""
    kind = draw(st.sampled_from(["h1", "sri", "image", "pip", "checksum_key", "version", "operand", "link"]))
    seed = draw(st.integers(0, 2**64))
    if kind == "h1":
        digest = base64.b64encode(random_bytes(seed, 32)).decode()
        module, version = draw(module_paths), draw(semvers)
        return "checksum", f"{module} v{version}{draw(st.sampled_from(['', '/go.mod']))} h1:{digest}", digest
    if kind == "sri":
        algorithm, size = draw(st.sampled_from([("sha1", 20), ("sha256", 32), ("sha384", 48), ("sha512", 64)]))
        digest = base64.b64encode(random_bytes(seed, size)).decode()
        value = draw(st.sampled_from([f"{algorithm}-{digest}", digest]))
        line = draw(st.sampled_from(['"integrity": "{a}-{d}"', "resolution: {{integrity: {a}-{d}}}", "  integrity {a}-{d}",
                                    '<script src="x.js" integrity="{a}-{d}" crossorigin="anonymous">']))
        line = line.format(a=algorithm, d=digest)
        return "checksum", line[:line.index(digest) + len(digest)], value if value in line else digest
    if kind == "image":
        digest = random_bytes(seed, 32).hex()
        return "checksum", f"image: registry.example.com/{draw(packages)}@sha256:{digest}", digest
    if kind == "pip":
        digest = random_bytes(seed, 32).hex()
        return "checksum", f"{draw(packages)}=={draw(semvers)} --hash=sha256:{digest}", digest
    if kind == "checksum_key":
        size = draw(st.sampled_from([16, 20, 32, 64]))
        digest = draw(st.sampled_from([random_bytes(seed, size).hex(), base64.b64encode(random_bytes(seed, size)).decode()]))
        key = draw(st.sampled_from(["api_key_sha256", "tokenChecksum", "secret_hash", "accessKeyDigest", "auth_md5", "key_integrity"]))
        return "checksum", f'{key} = "{digest}"', digest
    if kind == "version":
        names = draw(st.lists(packages, min_size=0, max_size=3))
        value = draw(st.sampled_from(["", "^", "~", ">=", "npm:@x/y@"])) + draw(semvers) + peers(draw(st.lists(semvers, min_size=len(names), max_size=len(names))), names)
        return "version", f"      '{draw(packages)}': {value}", value
    if kind == "operand":
        variable = draw(st.from_regex(r"[A-Z]{2,8}_(PASSWORD|TOKEN|SECRET|KEY)", fullmatch=True))
        word = "-".join(draw(st.lists(words, min_size=2, max_size=3)))
        operator = draw(st.sampled_from([":+", "+", ":-", "-", ":=", ":?"]))
        line = f'case "${{{variable}{operator}{word}}}" in'
        cut = draw(st.integers(0, 2))   # where an engine's value starts: the operator, its last mark, or the word
        value = (operator + word)[max(0, len(operator) - cut) if cut < 2 else len(operator):] + "}"
        return "identifier", line[:line.index("}") + 1], value
    uuid = str(UUID(bytes=random_bytes(seed, 16), version=4))
    bucket, name = draw(words), draw(words)
    query = draw(st.sampled_from(["alt=media&token=", "token=", "alt=media&foo=1&token="]))
    return "link", f'imageUrl: "https://firebasestorage.googleapis.com/v0/b/{bucket}.appspot.com/o/movies%2F{name}.jpeg?{query}{uuid}', uuid


class ValuePropertyTests(unittest.TestCase):
    """Files are read wherever they are, so their values are judged by what they are: a digest of exactly its
    algorithm's length, a version, an expansion's operand, a public download link, a key header or marker with no key.
    Real secrets of every common shape in those same files and on those same keys are always findings."""

    @settings(max_examples=400 * SCALE)
    @given(st.sampled_from(["generic-api-key", PASSWORD]), ANY_PATHS, benign())
    def test_a_benign_value_is_set_aside_by_what_it_is_wherever_it_is(self, rule, path, item):
        reason, line, value = item
        verdict = sf.verdict(rule, path, line, value)
        if rule == PASSWORD and sf.outside_code(path):
            self.assertEqual(verdict, "path")
        else:
            self.assertEqual(verdict, reason, (line, value))

    @settings(max_examples=400 * SCALE)
    @given(ANY_PATHS, shaped_secrets | run_tokens, st.sampled_from(SECRET_LAYOUTS), st.sampled_from(SECRET_KEYS))
    def test_a_real_secret_is_a_finding_wherever_it_is(self, path, shaped, layout, key):
        """Random secrets of every common shape, runs of digits included, with the rule that matches them."""
        rule, secret = shaped
        if rule == PASSWORD and sf.outside_code(path):
            rule = "generic-api-key"   # a password under tests or docs is set aside by its path (CorpusTests)
        line = layout.format(key=key, value=secret)
        verdict = sf.verdict(rule, path, line[:line.index(secret) + len(secret)], secret)
        self.assertEqual(verdict, None if kept(rule, secret) else "placeholder", (rule, secret))

    @settings(max_examples=300 * SCALE)
    @given(run_tokens, ANY_PATHS)
    def test_a_vendor_token_is_never_set_aside_for_a_run_in_it(self, shaped, path):
        rule, secret = shaped
        self.assertEqual(sf.verdict(rule, path, f'token = "{secret}', secret), None if kept(rule, secret) else "placeholder", secret)
        self.assertTrue(sf._counted(secret))   # the run of six is there, and alone never sets the token aside

    @settings(max_examples=300 * SCALE)
    @given(secrets_.filter(lambda value: len(value) >= sf.STRONG and "}" not in value),
           st.sampled_from(["", "-", "+", "=", "?", ":", "!"]), st.sampled_from([":-", "-", ":=", "=", ":?", "?"]),
           st.from_regex(r"[A-Z]{2,8}_PASSWORD", fullmatch=True), st.data())
    def test_a_default_inside_an_expansion_is_judged_whole_as_the_password_it_is(self, secret, mark, operator, variable, data):
        """`${DB_PASSWORD:--S3cr3t!}` hard-codes `-S3cr3t!`: whatever character it starts with and wherever the
        engine's value starts (in the name, at the operator, inside the default), the verdict is the one the literal
        gets assigned on its own."""
        literal = mark + secret
        expansion = f"${{{variable}{operator}{literal}}}"
        line = f"DB_PASSWORD={expansion}"
        start = data.draw(st.integers(len("DB_PASSWORD=${"), len(line) - 2), label="engine's value starts")
        alone = sf.verdict(PASSWORD, "docker-compose.yml", f'DB_PASSWORD="{literal}"', literal)
        self.assertEqual(sf.verdict(PASSWORD, "docker-compose.yml", line, line[start:]), alone)
        self.assertIsNone(alone)   # a strong literal: the default is a password, whatever it starts with

    @settings(max_examples=200 * SCALE)
    @given(st.text(alphabet=string.ascii_letters + string.digits, min_size=sf.STRONG - 1, max_size=sf.STRONG - 1).filter(
               lambda value: any(c.isdigit() for c in value) and any(c.isalpha() for c in value)),
           st.sampled_from("-+=?:"), st.sampled_from([":-", "-", ":=", "="]), st.data())
    def test_the_first_character_of_a_default_counts(self, rest, mark, operator, data):
        """`${DB_PASSWORD:--Xk9fQz7}` defaults to an eight-character password: read without its `-` it would be seven,
        too short, and set aside. Its verdict is the literal's own, whatever the engine's value starts at."""
        literal = mark + rest
        line = f"DB_PASSWORD=${{DB_PASSWORD{operator}{literal}}}"
        start = data.draw(st.integers(len("DB_PASSWORD=${"), len(line) - 2), label="engine's value starts")
        alone = sf.verdict(PASSWORD, "docker-compose.yml", f'DB_PASSWORD="{literal}"', literal)
        self.assertEqual(sf.verdict(PASSWORD, "docker-compose.yml", line, line[start:]), alone, line[start:])

    @settings(max_examples=200 * SCALE)
    @given(st.integers(0, 2**64), st.sampled_from(["123456", "abc1234", "XYZ", "", "...", "<your key here>", "MIIE...", "REDACTED"]),
           st.sampled_from(["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY"]),
           st.sampled_from(["\\n", "\n", "\r\n"]), st.integers(48, 1200))
    def test_a_private_key_header_is_a_finding_only_with_a_key_body(self, seed, filler, kind, newline, size):
        body = base64.b64encode(random_bytes(seed, size)).decode()
        wrapped = newline.join(body[at:at + 64] for at in range(0, len(body), 64))
        empty = f"-----BEGIN {kind}-----{newline}{filler}{newline}-----END {kind}-----"
        real = f"-----BEGIN {kind}-----{newline}{wrapped}{newline}-----END {kind}-----"
        self.assertEqual(sf.verdict("private-key", "docs/a.ts", "", empty), "keyless")
        self.assertIsNone(sf.verdict("private-key", "docs/a.ts", "", real))
        # Read on past its own END (an engine's match that runs to a later header): the body is the block's own.
        self.assertEqual(sf.verdict("private-key", "docs/a.ts", "", empty + '";\n * Deno.serve({ cert, key });\n' + real), "keyless")

    @settings(max_examples=200 * SCALE)
    @given(st.integers(0, 2**64), st.sampled_from(['{{ "type": "{sa}" }}', '{{"type":"{sa}","project_id":"..."}}',
                                                 '{{ "type": "{sa}" ', "{{\n  \"type\": \"{sa}\",\n  \"project_id\": \"p\"\n}}"]),
           st.sampled_from(["serviceAccountKey: '{json}',", "const key = `{json}`", "{json}"]))
    def test_a_type_marker_is_a_finding_only_when_its_object_holds_a_key(self, seed, shape, layout):
        marker = f'"type": "{SERVICE_ACCOUNT}"' if '"type": "' in shape else f'"type":"{SERVICE_ACCOUNT}"'
        without = "it('x', () => {\n  check({ " + layout.format(json=shape.format(sa=SERVICE_ACCOUNT)) + " })\n})\n"
        body = base64.b64encode(random_bytes(seed, 1200)).decode()
        key = ', "private_key": "' + PRIVATE_KEY_HEADER + '\\n' + body + '\\n' + PRIVATE_KEY_FOOTER + '\\n"'
        with_key = without.replace(marker, marker + key, 1)
        for source, expected in ((without, "keyless"), (with_key, None)):
            at = source.index(marker)
            self.assertEqual(sf.verdict("gcp-service-account", "tests/a.test.ts", "", marker, (source, at)), expected, source)
        # Without the text around it, a marker is a finding: nothing is set aside unseen.
        self.assertIsNone(sf.verdict("gcp-service-account", "tests/a.test.ts", "", marker))

    @settings(max_examples=200 * SCALE)
    @given(secrets_, st.sampled_from(["https://api.example.com/v1/items?token=", "https://storage.googleapis.com/b/o?token=",
                                      "https://firebasestorage.googleapis.com/v0/b/x/o/y?token="]), st.integers(0, 2**64))
    def test_only_a_storage_download_token_is_a_link(self, secret, url, seed):
        """A token in any other URL, or anything but the UUID Firebase issues, stays a finding."""
        uuid = str(UUID(bytes=random_bytes(seed, 16), version=4))
        self.assertIsNone(sf.verdict("generic-api-key", "a.ts", f'url = "{url}{secret}', secret))
        expected = "link" if "firebasestorage" in url else None
        self.assertEqual(sf.verdict("generic-api-key", "a.ts", f'url = "{url}{uuid}', uuid), expected)

    @settings(max_examples=40 * SCALE, deadline=None)
    @given(st.lists(benign(), min_size=5, max_size=40), shaped_secrets | run_tokens, st.sampled_from(SECRET_LAYOUTS),
           st.sampled_from(SECRET_KEYS), ANY_PATHS, st.data())
    def test_a_secret_put_anywhere_in_a_file_of_benign_values_is_the_one_finding(self, items, shaped, layout, key, path, data):
        """Through parse_betterleaks over a snapshot, as if the engine flagged every line: the benign values are counted
        under their reasons, and the secret, put at any line and matched by its own rule, is the only finding."""
        rule, secret = shaped
        if rule == PASSWORD and sf.outside_code(path):
            rule = "generic-api-key"
        at = data.draw(st.integers(0, len(items)), label="where")
        rows = [(line, value) for _, line, value in items]
        secret_line = layout.format(key=key, value=secret)
        rows.insert(at, (secret_line[:secret_line.index(secret) + len(secret)], secret))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text("\n".join(line for line, _ in rows) + "\n", encoding="utf-8")
            entries = []
            for number, (line, value) in enumerate(rows, 1):
                start = line.rindex(value)
                entries.append({"RuleID": rule if number == at + 1 else "generic-api-key", "File": f"/src/{path}", "StartLine": number, "EndLine": number,
                                "StartColumn": 1, "EndColumn": start + len(value),
                                "Match": line[:start + len(value)].replace(value, "REDACTED"), "Entropy": entropy(value)})
            screened = Counter()
            found = engines.parse_betterleaks(entries, None, root, screened)
        if not kept(rule, secret):
            self.assertEqual((found, sum(screened.values())), ([], len(items) + 1))
            return
        self.assertEqual([item["line"] for item in found], [at + 1])
        self.assertEqual(sum(screened.values()), len(items))
        self.assertEqual(found[0].get("identity"), secret_identity.identity(secret))

    def test_trivy_reads_a_type_marker_with_its_object(self):
        """Through parse_trivy: Trivy masks the marker; the object around it in the snapshot decides."""
        body = base64.b64encode(random_bytes(7, 1200)).decode()
        marker = f'"type": "{SERVICE_ACCOUNT}"'
        files = {"a.test.ts": f"check({{ key: '{{ {marker} }}' }})\n",
                 "sa.json": f'{{\n  {marker},\n  "private_key": "{PRIVATE_KEY_HEADER}\\n{body}\\n{PRIVATE_KEY_FOOTER}\\n"\n}}\n'}
        with tempfile.TemporaryDirectory() as folder:
            root, results = Path(folder), []
            for name, content in files.items():
                (root / name).write_text(content, encoding="utf-8")
                offset = content.encode().index(marker.encode())
                line = content[:content.index(marker)].count("\n") + 1
                results.append({"Target": name, "Class": "secret", "Secrets": [
                    {"RuleID": "gcp-service-account", "Category": "Google", "Severity": "CRITICAL", "Title": "t", "StartLine": line,
                     "EndLine": line, "Offset": offset, "Match": content.splitlines()[line - 1].replace(marker, "*" * len(marker))}]})
            screened = Counter()
            found = engines.parse_trivy({"Results": results}, {}, root=root, screened=screened)
        self.assertEqual([item["path"] for item in found], ["sa.json"])
        self.assertEqual(screened, Counter(keyless=1))

    def test_the_seeds(self):
        """The corpus' matches that R4 brought in by reading every file."""
        seeds = [
            ("generic-api-key", "go.sum", f"github.com/go-webauthn/webauthn v0.18.2 h1:{GO_SUM_DIGEST}", GO_SUM_DIGEST, "checksum"),
            (PASSWORD, "pnpm-lock.yaml", "      '@inquirer/password': 4.0.23(@types/node@22.13.14)", "4.0.23(@types/node@22.13.14)", "version"),
            (PASSWORD, "mvnw", 'case "${MVNW_PASSWORD:+has-password}', "+has-password}", "identifier"),
            (PASSWORD, "contrib/bruno/miniflux/Create a new user.bru", '    "password": "secret123', "secret123", "placeholder"),
            ("generic-api-key", "dataconnect/moviedata_insert.gql",
             'imageUrl: "https://firebasestorage.googleapis.com/v0/b/fdc-web-quickstart.appspot.com/o/movie%2Fquantum_paradox.jpeg'
             '?alt=media&token=' + FIREBASE_TOKEN, FIREBASE_TOKEN, "link"),
            ("private-key", "lib.deno.d.ts", "", '-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n";\n   * Deno.serve(', "keyless"),
            # A 32-hex value under `api_key` in a commented-out block of vendored code: it is the shape of a live key.
            ("generic-api-key", "app/assets/javascripts/gallery.js", f"    //         api_key: '{GALLERY_HEX}", GALLERY_HEX, None),
            # People do deploy an account's name with a number.
            (PASSWORD, "docker-compose.yml", "- MYSQL_ROOT_PASSWORD=admin321", "admin321", None),
        ]
        for rule, path, line, value, expected in seeds:
            self.assertEqual(sf.verdict(rule, path, line, value), expected, value)
        self.assertIn("2 version numbers", text(engines.screened_detail(Counter(version=2)), "en"))
        self.assertIn("1 enlace público de descarga", text(engines.screened_detail(Counter(link=1)), "es"))


if __name__ == "__main__":
    unittest.main()
