"""R2: a secret's value is read where its engine's evidence verifies it, or the secret is unlinkable.

The value that names a secret is read from the file where the engine said and checked against what the engine said
independently (Betterleaks: its redacted match, its length in bytes and the value's entropy; Trivy: its offset from the
file's start and the text it masked around it, line by line over several lines). When no place fits, or the places that
fit hold several values nothing tells apart, the secret is unlinkable: named by its rule, its file and the content of
its lines, never a former name, never inheriting anything (scanning/secret_location.py).

The properties hold whatever the line: random length up to 1 MB (minified code, high-entropy blobs, repetition), any
line ending (LF, CRLF, CR alone), several values and copies on one line, multi-line keys of random content, and columns
that count from a fragment of the line the engine doesn't report (Betterleaks past about 125 KB), duplicates included:

* two distinct values never share an identity, and an identity named by a value is always one of the values there;
* the same content scanned twice gives the same identities (the identity gate's 0/0);
* a value changed in place never inherits the triage of the one before;
* one engine reporting one secret twice on a line gives one finding per occurrence of the value.

The engines are simulated as their real output was recorded (Betterleaks 1.9.0, Trivy 0.75.0); `RealEnginesTests`
runs the pinned images on the adversarial cases that broke the previous mechanism, and on random ones (skipped without
Docker).
"""

import base64
import hashlib
import json
import os
import random
import string
import struct
import tempfile
import unittest
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import NamedTuple
from unittest.mock import patch

from hypothesis import HealthCheck, example, given, settings, strategies as st

from pitangus.modules.findings import registry, triage
from pitangus.modules.findings.identity import formers, of_value, unlinkable
from pitangus.modules.runs.store import save_and_apply
from pitangus.modules.scanning import engines, secret_identity, secret_location
from pitangus.modules.scanning.secret_filter import PEM_BODY_MIN
from pitangus.modules.scanning.secret_location import entropy
from test_dashboard import _scan

PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1
LONG = 10 if PROFILE == "nightly" else 1    # examples with lines up to 1 MB: a third of the others' nightly scale

ADMIN = {"username": "ana", "role": "admin"}
ALNUM = string.ascii_letters + string.digits
# The adversary's seeds (R2 review): two GitHub tokens, a minified bundle, a private key, a file with CR line endings.
A = "ghp_" + "Zq9xK2mP7vL4wR8tY1nBc3dE5fG6hJ8kL0aS"
B = "ghp_" + "Ab3dE5gH7jK9mN1pQ3sT5vX7yZ9bC1dF3gH5"


def master() -> str:
    return base64.b64encode(hashlib.sha256(b"secret-location").digest()).decode()


def single(value: float) -> float:
    return struct.unpack("f", struct.pack("f", value))[0]


def token(seed: int, size: int = 36, prefix: str = "ghp_") -> str:
    rng = random.Random(seed)
    return prefix + "".join(rng.choice(ALNUM) for _ in range(size))


def filler(kind: str, size: int, seed: int) -> str:
    """Text around the secrets: minified code, a high-entropy blob (an inlined font, a hash), or one statement repeated."""
    rng = random.Random(seed)
    if kind == "repeat":
        return ("var a=1;" * (size // 8 + 1))[:size]
    if kind == "blob":
        return "".join(rng.choice(ALNUM + "+/") for _ in range(size))
    words = ["function(e){return e}", "var n=", "t.exports=", "{a:1,b:2}", ";", ",", "if(r)", "x=>x*2", "'use strict'", " "]
    out, length = [], 0
    while length < size:
        word = rng.choice(words)
        out.append(word)
        length += len(word)
    return "".join(out)[:size]


class Placed(NamedTuple):
    value: str
    start: int      # byte offset of the value in the file
    lead: str       # what Betterleaks' match shows before the value ("" for a token rule)
    tail: str


class Case(NamedTuple):
    content: bytes
    placed: list[Placed]
    rule: str


def build(values: list[str], cuts: list[float], kind: str, size: int, seed: int, ending: str, generic: list[bool],
          above: int) -> Case:
    """One file: `above` short lines, then one line of `size` characters of filler with `values` inserted at `cuts`
    (fractions of it), each as a token (`"…"`) or assigned (`API_KEY = "…"`)."""
    text = filler(kind, size, seed)
    marks = sorted(zip(cuts, range(len(values))))
    pieces, at = [], 0
    for cut, index in marks:
        where = int(cut * len(text))
        pieces.append(text[at:where])
        pieces.append((index, generic[index % len(generic)]))
        at = where
    pieces.append(text[at:])
    head = "".join(f"line{number} = {number}{ending}" for number in range(above))
    content, placed = head.encode(), []
    for piece in pieces:
        if isinstance(piece, str):
            content += piece.encode()
            continue
        index, assigned = piece
        lead = f'K{index}_API_KEY = "' if assigned else ""
        content += f';{lead}' .encode() if assigned else b';"'
        placed.append(Placed(values[index], len(content), lead, '"' if assigned else ""))
        content += values[index].encode() + b'";'
    return Case(content + ending.encode(), placed, "generic-api-key")


def _line_of(content: bytes, offset: int) -> tuple[int, int]:
    """(1-based line, where it starts) of byte `offset`, lines ending at "\\n" as both engines count them."""
    return content.count(b"\n", 0, offset) + 1, content.rfind(b"\n", 0, offset) + 1


def betterleaks(case: Case, rng: random.Random, duplicates: bool = True) -> list[dict]:
    """Betterleaks 1.9.0 with --redact: 1-based inclusive byte columns; in a file bigger than it reads in one piece
    (engines.BETTERLEAKS_ONE_PIECE), often from the start of a piece it doesn't report (anywhere before the secret,
    here), and sometimes the same secret twice (pieces overlap); `Match` with the value REDACTED and `Entropy` the
    value's, as a 32-bit float."""
    entries = []
    for item in case.placed:
        number, start = _line_of(case.content, item.start)
        split = len(case.content) > engines.BETTERLEAKS_ONE_PIECE
        column = item.start - len(item.lead.encode()) - start
        size = len((item.lead + item.value + item.tail).encode())
        reports = [rng.randrange(0, column + 1) if split and rng.random() < 0.7 else 0]
        if split and duplicates and rng.random() < 0.3:
            reports.append(rng.randrange(0, column + 1))
        for origin in reports:
            entries.append({"RuleID": "generic-api-key" if item.lead else "github-pat", "File": "/src/app.js", "StartLine": number,
                            "EndLine": number, "StartColumn": column - origin + 1, "EndColumn": column - origin + size,
                            "Match": f"{item.lead}REDACTED{item.tail}", "Secret": "REDACTED", "Entropy": single(entropy(item.value))})
    return entries


def trivy(case: Case, rng: random.Random) -> dict:
    """Trivy 0.75.0: the value's byte offset in the file, and its line with one `*` per byte of every secret on it,
    without the carriage returns it doesn't mask, cut around the secret on a long line."""
    secrets = []
    for item in case.placed:
        number, start = _line_of(case.content, item.start)
        end = case.content.find(b"\n", item.start)
        line = bytearray(case.content[start:end if end >= 0 else len(case.content)])
        for other in case.placed:
            if _line_of(case.content, other.start)[0] == number:
                line[other.start - start:other.start - start + len(other.value)] = b"*" * len(other.value)
        here = item.start - start
        before = line[:here].count(b"\r")
        shown = bytes(line).replace(b"\r", b"")
        here -= before
        left, right = rng.randrange(0, 31), rng.randrange(0, 31)
        window = shown if len(shown) < 200 else shown[max(0, here - left):here + len(item.value) + right]
        secrets.append({"RuleID": "github-pat", "Category": "GitHub", "Severity": "CRITICAL", "Title": "GitHub", "StartLine": number,
                        "EndLine": number, "Offset": item.start, "Match": window.decode()})
    return {"Results": [{"Target": "app.js", "Class": "secret", "Secrets": secrets}]} if secrets else {"Results": []}


def parse(root: Path, case: Case, seed: int) -> list[dict]:
    (root / "app.js").write_bytes(case.content)
    rng = random.Random(seed)
    return [*engines.parse_betterleaks(betterleaks(case, rng), None, root), *engines.parse_trivy(trivy(case, rng), {}, root=root)]


def pem(seed: int, lines: int, width: int = 64) -> str:
    rng = random.Random(seed)
    # At least the base64 characters of the smallest private key (secret_filter.PEM_BODY_MIN): fewer is no key at all.
    body = "".join(rng.choice(ALNUM + "+/") for _ in range(max(PEM_BODY_MIN, width * lines - rng.randrange(0, width // 2))))
    begin, end = "-----BEGIN RSA " + "PRIVATE KEY-----", "-----END RSA " + "PRIVATE KEY-----"   # built here: no key in this file
    return begin + "\n" + "\n".join(body[at:at + width] for at in range(0, len(body), width)) + "\n" + end + "\n"


def key_reports(content: bytes) -> tuple[list[dict], dict]:
    """Both engines over a file holding one private key: Betterleaks' match is the whole block, BEGIN to END (its
    secret too: the entropy counts its carriage returns); Trivy's is the body, masked line by line (a carriage return
    is masked with the line it ends, but the body's last)."""
    lines = content.split(b"\n")
    begin = next(index for index, line in enumerate(lines) if line.startswith(b"-----BEGIN"))
    end = next(index for index, line in enumerate(lines) if line.startswith(b"-----END") and index > begin)
    block = b"\n".join(lines[begin:end + 1]).rstrip(b"\r")
    finished = lines[end].rstrip(b"\r")
    better = [{"RuleID": "private-key", "File": "/src/deploy.key", "StartLine": begin + 1, "EndLine": end + 1, "StartColumn": 1,
               "EndColumn": len(finished), "Match": "REDACTED", "Secret": "REDACTED", "Entropy": single(entropy(block.decode()))}]
    offset = len(b"\n".join(lines[:begin + 1])) + 1
    body = lines[begin + 1:end]
    masked = [b"*" * (len(line) if index == len(body) - 1 else len(line)) for index, line in enumerate(body)]
    masked[-1] = b"*" * len(body[-1].rstrip(b"\r"))
    code = [{"Number": begin + 2 + index, "Content": line.decode(), "IsCause": True, "Truncated": False} for index, line in enumerate(masked)]
    trivy_report = {"Results": [{"Target": "deploy.key", "Class": "secret", "Secrets": [
        {"RuleID": "private-key", "Category": "AsymmetricPrivateKey", "Severity": "HIGH", "Title": "Asymmetric Private Key",
         "StartLine": begin + 2, "EndLine": end, "Offset": offset, "Match": masked[0].decode(), "Code": {"Lines": code}}]}]}
    return better, trivy_report


def parse_key(root: Path, content: bytes) -> list[dict]:
    (root / "deploy.key").write_bytes(content)
    better, trivy_report = key_reports(content)
    return [*engines.parse_betterleaks(better, None, root), *engines.parse_trivy(trivy_report, {}, root=root)]


VALUES = st.lists(st.builds(token, st.integers(0, 2**64), st.integers(16, 40)), min_size=1, max_size=3, unique=True)
LINES = st.fixed_dictionaries({
    "kind": st.sampled_from(["code", "blob", "repeat"]),
    # Short lines, files around what Betterleaks reads in one piece and around its first cut, up to 1 MB.
    "size": st.one_of(st.integers(0, 400), st.integers(95_000, 105_000), st.integers(120_000, 190_000), st.integers(0, 1 << 20)),
    "seed": st.integers(0, 2**32),
    "ending": st.sampled_from(["\n", "\r\n", "\r"]),
    "above": st.integers(0, 3)})


class Keys:
    def __enter__(self):
        secret_identity._key.cache_clear()
        self.patch = patch.dict(os.environ, {"PITANGUS_MASTER_KEY": master(), "PITANGUS_PREVIOUS_MASTER_KEY": "", "PITANGUS_IDENTITY_MODE": "v2"})
        self.patch.start()
        return self

    def __exit__(self, *exc):
        self.patch.stop()
        secret_identity._key.cache_clear()


def check_named(case_values: list[str], found: list[dict], test: unittest.TestCase) -> None:
    """Every identity named by a value is one of `case_values`'; an unlinkable one is no value's and has no other name."""
    allowed = {secret_identity.identity(value) for value in case_values}
    for item in found:
        if of_value(item):
            test.assertIn(item["identity"], allowed, "an identity named by a value that isn't on the line")
        else:
            test.assertTrue(unlinkable(item), item)
            test.assertNotIn(item["identity"], allowed)
            test.assertEqual(formers(item), [])
            test.assertNotIn("previous_fingerprint", item)


class PropertyTests(unittest.TestCase):
    def setUp(self):
        keys = Keys()
        keys.__enter__()
        self.addCleanup(keys.__exit__)

    @settings(max_examples=25 * LONG, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
    @given(first=VALUES, data=st.data(), shape=LINES)
    # The adversary's minified bundle: A, then B in its place, past the first fragment (200 000 statements).
    @example(first=[A], data=None, shape={"kind": "repeat", "size": 1_600_000, "seed": 0, "ending": "\n", "above": 0})
    @example(first=[A, B], data=None, shape={"kind": "repeat", "size": 320_000, "seed": 1, "ending": "\n", "above": 0})
    @example(first=[A], data=None, shape={"kind": "code", "size": 10, "seed": 2, "ending": "\r", "above": 1})
    # A copy as a token and another assigned, past one piece: each rule finds its own, a duplicate never a third.
    @example(first=[token(16, 16), A], data=None, shape={"kind": "code", "size": 100_615, "seed": 0, "ending": "\n", "above": 0})
    def test_distinct_values_never_share_an_identity_and_the_same_content_keeps_its_own(self, first, data, shape):
        if data is None:
            second = [B] if first == [A] else [token(100 + index) for index in range(len(first))]
            cuts, generic, seed = [index / (len(first) + 1) + 0.5 for index in range(len(first))], [False], 7
            cuts = [min(cut, 1.0) for cut in cuts]
        else:
            second = data.draw(st.lists(st.builds(token, st.integers(0, 2**64), st.integers(16, 40)), min_size=len(first),
                                        max_size=len(first), unique=True).filter(lambda values: not set(values) & set(first)), label="second")
            cuts = data.draw(st.lists(st.floats(0, 1), min_size=len(first), max_size=len(first)), label="cuts")
            # Copies: a value placed twice on the line.
            copies = data.draw(st.lists(st.integers(0, len(first) - 1), max_size=2), label="copies")
            first, second = [*first, *(first[index] for index in copies)], [*second, *(second[index] for index in copies)]
            cuts += data.draw(st.lists(st.floats(0, 1), min_size=len(copies), max_size=len(copies)), label="copy cuts")
            generic, seed = data.draw(st.lists(st.booleans(), min_size=1, max_size=3), label="generic"), data.draw(st.integers(0, 2**32))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            before = build(first, cuts, **shape, generic=generic)
            after = build(second, cuts, **shape, generic=generic)
            # The engines are deterministic: the same content gives the same report (columns, duplicates and all).
            found_before, again, found_after = parse(root, before, seed), parse(root, before, seed), parse(root, after, seed)
            # Another report of it (other fragments, other duplicates) names it by its values or not at all.
            check_named(first, parse(root, before, seed + 1), self)
        for values, found in ((first, found_before), (second, found_after)):
            check_named(values, found, self)
            # Trivy's offset counts from the start of the file and the text it masked confirms it: always read.
            self.assertTrue(all(of_value(item) for item in found if item["tool"] == "trivy"))
            # One engine's rule, one value: never more findings than copies of it on its line.
            named = Counter((item["tool"], item["rule_id"], item["identity"]) for item in found if of_value(item))
            for (_, _, identity), count in named.items():
                self.assertLessEqual(count, sum(secret_identity.identity(value) == identity for value in values))
        # Nothing names A and B alike: not a value's identity, not an unlinkable one (B's line is another content).
        self.assertFalse({item["identity"] for item in found_before} & {item["identity"] for item in found_after})
        # The same content is named the same.
        self.assertEqual(sorted((item["tool"], item["identity"]) for item in found_before if of_value(item)),
                         sorted((item["tool"], item["identity"]) for item in again if of_value(item)))
        self.assertEqual({item["identity"] for item in found_before if unlinkable(item)},
                         {item["identity"] for item in again if unlinkable(item)})

    @settings(max_examples=40 * SCALE, deadline=None)
    @given(seeds=st.lists(st.integers(0, 2**32), min_size=2, max_size=2, unique=True), lines=st.integers(1, 30),
           ending=st.sampled_from(["\n", "\r\n"]), above=st.integers(0, 3), width=st.sampled_from([64, 76, 70]))
    @example(seeds=[1, 2], lines=20, ending="\n", above=0, width=64)        # the adversary's deploy.key
    @example(seeds=[1, 2], lines=20, ending="\r\n", above=0, width=64)
    @example(seeds=[0, 26], lines=2, ending="\n", above=0, width=64)        # `END` inside the body
    def test_a_multi_line_key_is_named_by_its_whole_span_whatever_its_line_endings(self, seeds, lines, ending, above, width):
        keys = [pem(seed, lines, width) for seed in seeds]
        head = "x = 1\n" * above
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            found = [parse_key(root, (head + key).replace("\n", ending).encode()) for key in keys]
            unix = parse_key(root, (head + keys[0]).encode())
            again = parse_key(root, (head + keys[0]).replace("\n", ending).encode())
        for key, items in zip(keys, found):
            self.assertEqual(len(items), 2)
            self.assertTrue(all(of_value(item) for item in items), items)
            body = key.split("\n", 1)[1].rsplit("-----END", 1)[0].strip("\n")
            self.assertEqual({item["identity"] for item in items},
                             {secret_identity.identity(key.rstrip("\n")), secret_identity.identity(body)})
        self.assertFalse({item["identity"] for item in found[0]} & {item["identity"] for item in found[1]})
        # Line endings normalized: the same key with LF or CRLF is one value; scanned twice, one identity.
        self.assertEqual([item["identity"] for item in found[0]], [item["identity"] for item in unix])
        self.assertEqual([item["identity"] for item in found[0]], [item["identity"] for item in again])

    @settings(max_examples=40 * SCALE, deadline=None)
    @given(seeds=st.lists(st.integers(0, 2**32), min_size=2, max_size=2, unique=True), lines=st.integers(1, 30),
           ending=st.sampled_from(["\n", "\r\n"]))
    def test_a_key_whose_evidence_doesnt_hold_is_unlinkable_by_its_content(self, seeds, lines, ending):
        """Betterleaks' entropy off by a hair, Trivy's offset and mask one byte off: nothing is read; each key is named by
        its lines' content, the same for the same content, never another key's."""
        names = []
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for seed in [*seeds, seeds[0]]:
                content = pem(seed, lines).replace("\n", ending).encode()
                (root / "deploy.key").write_bytes(content)
                better, trivy_report = key_reports(content)
                better[0]["Entropy"] += 0.01
                reported = trivy_report["Results"][0]["Secrets"][0]
                reported.update(Offset=reported["Offset"] + 1, Match=reported["Match"] + "***")
                found = [*engines.parse_betterleaks(better, None, root), *engines.parse_trivy(trivy_report, {}, root=root)]
                self.assertTrue(all(unlinkable(item) for item in found), found)
                names.append({item["identity"] for item in found})
        self.assertFalse(names[0] & names[1])
        self.assertEqual(names[0], names[2])

    @settings(max_examples=200 * SCALE, deadline=None)
    @given(text=st.text(alphabet='ab=-_ ";:.~/+中\r', min_size=1, max_size=80), data=st.data())
    def test_a_line_s_tokens_read_once_are_the_tokens_read_one_by_one(self, text, data):
        start = data.draw(st.integers(0, len(text) - 1))
        end = data.draw(st.integers(start, len(text)))
        self.assertEqual(secret_location._Tokens(text).whole(start, end), secret_identity._whole(text, start, end))

    def test_one_secret_reported_twice_on_a_long_line_is_one_finding(self):
        """Betterleaks' fragments overlap: the secret past the first one comes twice, with two columns."""
        case = build([A], [0.9], "repeat", 300_000, 0, "\n", [False], 0)
        column = case.placed[0].start      # one line: its byte offset in the file is its column
        entry = {"RuleID": "github-pat", "File": "/src/app.js", "StartLine": 1, "EndLine": 1, "Match": "REDACTED",
                 "Secret": "REDACTED", "Entropy": single(entropy(A))}
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "app.js").write_bytes(case.content)
            for columns in ((column, column - 153_672), (column - 153_672, column - 97_000)):
                found = engines.parse_betterleaks([{**entry, "StartColumn": start + 1, "EndColumn": start + 40} for start in columns], None, root)
                self.assertEqual(len(found), 1, columns)
                check_named([A], found, self)
            # Its columns right, it is A's.
            found = engines.parse_betterleaks([{**entry, "StartColumn": column + 1, "EndColumn": column + 40}] * 2, None, root)
            self.assertEqual([item["identity"] for item in found], [secret_identity.identity(A)])


class GateTests(unittest.TestCase):
    """The PR gate and the stored names: B in A's place is introduced, the same content introduces nothing."""

    def setUp(self):
        keys = Keys()
        keys.__enter__()
        self.addCleanup(keys.__exit__)

    @settings(max_examples=8 * LONG, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
    @given(values=st.lists(st.builds(token, st.integers(0, 2**64), st.integers(16, 40)), min_size=2, max_size=2, unique=True),
           cut=st.floats(0, 1), shape=LINES, seed=st.integers(0, 2**32), stored=st.booleans())
    @example(values=[A, B], cut=1.0, shape={"kind": "repeat", "size": 160_000, "seed": 0, "ending": "\n", "above": 0}, seed=0, stored=True)
    def test_a_pr_that_changes_a_value_in_place_introduces_it_whatever_its_line(self, values, cut, shape, seed, stored):
        from pitangus.modules.findings import canonical
        from pitangus.modules.pullrequests import review
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            base, head = (parse(root, build([value], [cut], **shape, generic=[False]), seed) for value in values)
        if stored:
            base = canonical.collapse(base)
        changed = {"app.js": None}
        self.assertEqual(review.classify(base, changed, base)["introduced"], [])
        introduced = review.classify(head, changed, base)["introduced"]
        self.assertEqual({item["identity"] for item in introduced}, {item["identity"] for item in head})

    def test_the_stored_names_of_an_unlinkable_secret_are_never_taken_for_a_value_s(self):
        """Data migration `secret_value_identities` marks identities made with a known key as values': never an
        unlinkable one, which has that key's prefix too."""
        from pitangus.app import data_migrations
        found = {"scanner": "secrets", "identity": secret_identity.unlinkable("github-pat", "app.js", b"x"), "unlinkable": True}
        self.assertIs(data_migrations._named_by_value(found, secret_identity.key_ids()), found)
        self.assertFalse(of_value(found))


class RegistryTests(unittest.TestCase):
    """Through the registry: B in A's place is new, with no decision of A's, whatever its line."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name) / "data"
        self.root = Path(self.directory.name) / "snapshot"
        self.root.mkdir()
        self.clock = datetime.now(timezone.utc)
        mode = patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "on", "PITANGUS_FIX_HOLD_MINIMUM": "1000"})
        mode.start()
        self.addCleanup(mode.stop)
        keys = Keys()
        keys.__enter__()
        self.addCleanup(keys.__exit__)

    def scan(self, key: str, found: list[dict]):
        self.clock += timedelta(hours=1)
        record = {**_scan("org/api", found, self.clock.isoformat()), "finished_at": self.clock.isoformat(),
                  "coverage": {tool: {"examined": "*", "unexamined": {}} for tool in ("betterleaks", "trivy")},
                  "configuration": {"identity_keys": secret_identity.key_ids()}}
        record["summary"]["tools"] = [{"name": tool, "version": "1", "status": "completed"} for tool in ("betterleaks", "trivy")]
        record["source"]["uid"] = key
        return save_and_apply(self.data_dir, record, created_at=self.clock.isoformat())

    def decisions(self, key: str) -> dict:
        return triage.load(self.data_dir).get(key, {})

    def changed_in_place(self, key: str, before: list[dict], after: list[dict]) -> tuple[dict, dict]:
        saved, _ = self.scan(key, before)
        triage.decide(self.data_dir, saved, [item["fingerprint"] for item in saved["findings"]], "false_positive",
                      reason="A test fixture, revoked", user=ADMIN)
        again, changes = self.scan(key, before)
        self.assertEqual((changes["new"], changes["fixed_now"]), ([], []))     # the same content: 0/0
        saved, changes = self.scan(key, after)
        decided = self.decisions(key)
        for item in saved["findings"]:
            self.assertIsNone((decided.get(item["fingerprint"]) or {}).get("status"), item)
        self.assertEqual(sorted(changes["new"]), sorted(item["fingerprint"] for item in saved["findings"]))
        return saved, changes

    @settings(max_examples=8 * LONG, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
    @given(values=st.lists(st.builds(token, st.integers(0, 2**64), st.integers(16, 40)), min_size=2, max_size=2, unique=True),
           cut=st.floats(0, 1), shape=LINES, generic=st.booleans(), seed=st.integers(0, 2**32))
    @example(values=[A, B], cut=1.0, shape={"kind": "repeat", "size": 160_000, "seed": 0, "ending": "\n", "above": 0}, generic=False, seed=0)
    @example(values=[A, B], cut=0.5, shape={"kind": "code", "size": 8, "seed": 0, "ending": "\r", "above": 1}, generic=False, seed=0)
    def test_a_value_changed_in_place_never_inherits_the_triage_of_the_one_before(self, values, cut, shape, generic, seed):
        before, after = (parse(self.root, build([value], [cut], **shape, generic=[generic]), seed) for value in values)
        self.changed_in_place(f"github#{hashlib.sha256(repr((values, cut, shape)).encode()).hexdigest()[:12]}", before, after)

    @settings(max_examples=8 * SCALE, deadline=None)
    @given(seeds=st.lists(st.integers(0, 2**32), min_size=2, max_size=2, unique=True), ending=st.sampled_from(["\n", "\r\n"]))
    @example(seeds=[1, 2], ending="\n")
    def test_a_rotated_key_never_inherits_the_triage_of_the_one_before(self, seeds, ending):
        before, after = (parse_key(self.root, pem(seed, 20).replace("\n", ending).encode()) for seed in seeds)
        self.changed_in_place(f"github#key-{seeds[0]}-{seeds[1]}", before, after)

    def test_an_unlinkable_secret_is_never_fixed_while_its_file_still_reports_its_rule(self):
        """Nobody can tell whether the secret before is the one there now: it stays open, unverified."""
        found = [parse(self.root, build([value], [0.9], "repeat", 300_000, 0, "\n", [False], 0), 0) for value in (A, B)]
        for items in found:
            for item in items:
                if item["tool"] == "betterleaks":
                    item.update(engines.unlinkable_fingerprints([{**item, "unlinkable": True, "identity": secret_identity.unlinkable(
                        item["rule_id"], item["path"], item["identity"].encode())}])[0])
                    item.pop("value_formers", None)
        saved, _ = self.scan("github#unlinkable", found[0])
        (stored,) = [item["fingerprint"] for item in saved["findings"] if unlinkable(item)]
        saved, changes = self.scan("github#unlinkable", found[1])
        entry = registry.load(self.data_dir, "github#unlinkable")["findings"][stored]
        self.assertEqual((entry["status"], entry["unseen"]["reason"]), ("open", "unidentified"))
        self.assertNotIn(stored, changes["fixed_now"])


def real_engines() -> bool:
    return engines.docker_available() and engines.image_available("betterleaks") and engines.image_available("trivy")


@unittest.skipUnless(real_engines(), "needs Docker with the Betterleaks and Trivy images")
class RealEnginesTests(RegistryTests):
    """The pinned images on the adversary's cases (R2 review) and on random ones."""

    def setUp(self):
        super().setUp()
        runner = patch.dict(os.environ, {"PITANGUS_ENGINE_RUNNER": "docker"})
        runner.start()
        self.addCleanup(runner.stop)

    def real(self, files: dict[str, bytes]) -> list[dict]:
        for old in self.root.iterdir():
            old.unlink()
        for name, content in files.items():
            (self.root / name).write_bytes(content)
        found = engines.run_betterleaks(self.root)
        seen = engines.trivy_secrets(self.root, Path(self.directory.name) / "cache", None, gaps={})
        self.assertEqual(found["status"], "completed")
        self.assertIsNotNone(seen)
        return [item for item in engines.merge_secrets(found["findings"], seen or []) if item["rule_id"] in ("github-pat", "private-key")]

    # The other tests of RegistryTests run on simulated engines only.
    test_a_value_changed_in_place_never_inherits_the_triage_of_the_one_before = None
    test_a_rotated_key_never_inherits_the_triage_of_the_one_before = None
    test_an_unlinkable_secret_is_never_fixed_while_its_file_still_reports_its_rule = None

    @settings(max_examples=3 * LONG, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
    @given(values=st.lists(st.builds(token, st.integers(0, 2**64)), min_size=2, max_size=2, unique=True), cut=st.floats(0, 1),
           shape=LINES, copies=st.integers(1, 2))
    @example(values=[A, B], cut=1.0, shape={"kind": "repeat", "size": 160_000, "seed": 0, "ending": "\n", "above": 0}, copies=1)
    @example(values=[A, B], cut=1.0, shape={"kind": "repeat", "size": 1_600_000, "seed": 0, "ending": "\n", "above": 0}, copies=1)
    @example(values=[A, B], cut=0.5, shape={"kind": "code", "size": 8, "seed": 0, "ending": "\r", "above": 1}, copies=1)
    @example(values=[A, B], cut=0.5, shape={"kind": "code", "size": 40, "seed": 0, "ending": "\n", "above": 0}, copies=2)
    def test_the_pinned_engines_never_link_two_values(self, values, cut, shape, copies):
        contents = [build([value] * copies, [cut] * copies, **shape, generic=[False]).content for value in values]
        before, again, after = self.real({"app.js": contents[0]}), self.real({"app.js": contents[0]}), self.real({"app.js": contents[1]})
        check_named([values[0]], before, self)
        check_named([values[1]], after, self)
        self.assertFalse({item["identity"] for item in before} & {item["identity"] for item in after})
        self.assertEqual(sorted(item["identity"] for item in before), sorted(item["identity"] for item in again))
        for found, value in ((before, values[0]), (after, values[1])):
            # Each engine finds the value as many times as it is there, or fewer, never more.
            for tool in ("betterleaks", "trivy"):
                self.assertLessEqual(sum(1 for item in found if tool in [item["tool"], *(item.get("also_detected_by") or [])]
                                         and item["identity"] == secret_identity.identity(value)), copies)
        self.changed_in_place(f"github#real-{hashlib.sha256(json.dumps([values, cut, shape, copies]).encode()).hexdigest()[:12]}",
                              before, after)

    def test_columns_count_from_the_line(self):
        """What engines.BETTERLEAKS_ONE_PIECE rests on: in a file no bigger than it, its columns count from the line's
        start, whatever its lines. In a bigger one a short line can be cut, and its columns name nothing alone."""
        files = {}
        for before, size in ((0, 99_000), (90_000, 9_000), (60_000, 39_990), (99_000, 990)):
            line = "x" * (size - 60) + f'var t="{A}";'
            files[f"s{before}_{size}.js"] = ((("y" * 99 + "\n") * (before // 100) + line + "\n")[:engines.BETTERLEAKS_ONE_PIECE]).encode()
        files["cut.js"] = (("y" * 99 + "\n") * 1249 + "x" * 140 + f'var t="{A}";' + "\nz = 1\n").encode()
        for name, content in files.items():
            (self.root / name).write_bytes(content)
        payload: list = []
        parse = engines.parse_betterleaks
        with patch.object(engines, "parse_betterleaks", side_effect=lambda report, *args, **kwargs: payload.extend(report) or parse(report, *args, **kwargs)):
            engines.run_betterleaks(self.root)
        self.assertEqual(sorted(entry["File"] for entry in payload), sorted(f"/src/{name}" for name in files))
        columns = {}
        for entry in payload:
            content = files[entry["File"].removeprefix("/src/")]
            at = content.index(A.encode())
            columns[entry["File"].removeprefix("/src/")] = (entry["StartColumn"], at - content.rfind(b"\n", 0, at))
        for name, (reported, true) in columns.items():
            if len(files[name]) <= engines.BETTERLEAKS_ONE_PIECE:
                self.assertEqual(reported, true, name)
        self.assertNotEqual(*columns["cut.js"])   # a 190-byte line across the cut at 125 000: counted from the cut

    def test_the_adversary_s_private_key_and_cr_files(self):
        for name, before, after in (("deploy.key", pem(1, 20), pem(2, 20)),
                                     ("legacy_mac.py", f'x = 1\rTOKEN = "{A}"\r', f'x = 1\rTOKEN = "{B}"\r'),
                                     ("deploy_crlf.key", pem(3, 20).replace("\n", "\r\n"), pem(4, 20).replace("\n", "\r\n"))):
            with self.subTest(name):
                found = [self.real({name: content.encode()}) for content in (before, after)]
                self.assertTrue(found[0] and found[1])
                self.assertTrue(all(of_value(item) for items in found for item in items), found)
                self.changed_in_place(f"github#real-{name}", *found)


if __name__ == "__main__":
    unittest.main()
