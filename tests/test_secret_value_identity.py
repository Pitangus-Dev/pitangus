"""R2: two different values never share an identity; the same value keeps its own.

A secret is named by its value (the keyed HMAC, scanning/secret_identity.py). Its engine's fingerprint (the rule, the
file, what precedes it on its line) is the same for any value in that place, so it is never a former name of a value's
identity: in the registry, in the PR gate or in the dashboard, only names computed from the value link two reports
(findings/identity.may_take). The same value survives a master key rotation (PITANGUS_PREVIOUS_MASTER_KEY: the scan
computes its identity with the key before too) and a change of formula (the scan computes the earlier formulas too).

Properties, through the real parsers of Betterleaks and Trivy and the real registry: random values in random formats
and places, changed, kept, moved, with random key rotations and formula changes in between. The seed case is the one
that escaped before: `SLACK_BOT = "<A>"` changed to `"<B>"` in place inherited A's entry and triage.
"""

import base64
import hashlib
import os
import tempfile
import unittest
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from hypothesis import HealthCheck, example, given, settings, strategies as st

from pitangus.modules.findings import canonical, registry, triage
from pitangus.modules.findings.identity import formers, legacy_formers, of_value
from pitangus.modules.pullrequests import review
from pitangus.modules.runs.store import save_and_apply
from pitangus.modules.scanning import engines, secret_identity
from test_betterleaks import SCALE, TOKENS, placements, report
from test_dashboard import _scan

ADMIN = {"username": "ana", "role": "admin"}
SLACK_A = "xoxb-" + "2339545089-2835763688579-cpP7BEXvfqZgimdS7jnqFCiI"
SLACK_B = "xoxb-" + "9915523408-1172093561127-Ab3dE5gH7jK9mN1pQ3sT5vX7"
SLACK_BOT = ('{key} = "{value}"', "SLACK_BOT", "", "generic", 0, 1)


def master(seed: int) -> str:
    return base64.b64encode(hashlib.sha256(seed.to_bytes(8, "big")).digest()).decode()


def findings(root: Path, rows: list[tuple[int, str, tuple]]) -> list[dict]:
    """What Betterleaks and Trivy report for these rows (place, value, placement), one file per place (`f{place}.cfg`),
    merged as a scan does: a place keeps its file whatever the other places hold."""
    for old in root.glob("f*.cfg"):
        old.unlink()
    entries, results = [], []
    for place, value, placement in rows:
        with tempfile.TemporaryDirectory() as folder:
            found, trivy = report(Path(folder), [(value, placement)])
            (root / f"f{place}.cfg").write_bytes((Path(folder) / "f0.cfg").read_bytes())
        entries += [{**entry, "File": f"/src/f{place}.cfg"} for entry in found]
        results += [{**result, "Target": f"f{place}.cfg"} for result in trivy["Results"]]
    return engines.merge_secrets(engines.parse_betterleaks(entries, None, root), engines.parse_trivy({"Results": results}, {}, root=root))


def placed(pool: list[str], assignment: list[int], slots: list[tuple]) -> list[tuple[int, str, tuple]]:
    """The rows of one scan: place `i` holds `pool[assignment[i]]` in its format, or nothing when it is -1."""
    return [(place, pool[index], slot) for place, (index, slot) in enumerate(zip(assignment, slots)) if index >= 0]


class Keys:
    """The master key, the one before it and the formula in force, as a scan sees them; changed in place."""

    def __init__(self):
        self.seed, self.previous, self.version = 1, "", secret_identity.CURRENT
        self.formulas = dict(secret_identity.FORMULAS)

    def rotate(self):
        self.previous, self.seed = master(self.seed), self.seed + 1

    def new_formula(self):
        version = self.version + 1
        self.formulas[version] = lambda kid, mac, version=version: kid + hashlib.sha256(f"secret/{version}|{kid}|{mac}".encode()).hexdigest()[:56]
        self.version = version

    def __enter__(self):
        secret_identity._key.cache_clear()
        self.patches = [patch.dict(os.environ, {"PITANGUS_MASTER_KEY": master(self.seed), "PITANGUS_PREVIOUS_MASTER_KEY": self.previous}),
                        patch.object(secret_identity, "FORMULAS", self.formulas), patch.object(secret_identity, "CURRENT", self.version),
                        patch.object(secret_identity, "EARLIER", tuple(version for version in self.formulas if version < self.version)[-1:])]
        for item in self.patches:
            item.start()
        return self

    def __exit__(self, *exc):
        for item in reversed(self.patches):
            item.stop()
        secret_identity._key.cache_clear()


class WithoutAStoredKeyTests(unittest.TestCase):
    """No master key and nowhere to keep one (a CLI scan in a read-only container, as in CI): the process names with a
    key of its own, so scanning a commit twice in it changes nothing, and nothing it names links to another process."""

    def test_a_process_without_a_stored_key_names_the_same_value_and_content_the_same(self):
        from pitangus.shared import vault
        with patch.dict(os.environ, {"PITANGUS_MASTER_KEY": ""}), patch.object(vault, "_master_key", side_effect=vault.VaultError("read-only")):
            secret_identity._key.cache_clear()
            try:
                value = "sk_live_" + uuid.uuid4().hex
                first, again = secret_identity.names(value), secret_identity.names(value)
                self.assertIsNotNone(first)
                self.assertEqual(first, again)
                self.assertEqual(secret_identity.unlinkable("r", "a.env", b"K=v"), secret_identity.unlinkable("r", "a.env", b"K=v"))
                self.assertNotEqual(secret_identity.unlinkable("r", "a.env", b"K=v"), secret_identity.unlinkable("r", "a.env", b"K=w"))
                kid = secret_identity.key_ids()[0]
                self.assertTrue(first.identity.startswith(kid))
                secret_identity._key.cache_clear()   # another process
                self.assertNotEqual(secret_identity.names(value), first)
                self.assertNotEqual(secret_identity.key_ids(), [kid])
            finally:
                secret_identity._key.cache_clear()


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name) / "data"
        self.root = Path(self.directory.name) / "snapshot"
        self.root.mkdir()
        self.clock = datetime.now(timezone.utc)
        mode = patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": "v2", "PITANGUS_COVERAGE_MODE": "on", "PITANGUS_FIX_HOLD_MINIMUM": "1000"})
        mode.start()
        self.addCleanup(mode.stop)

    def scan(self, key: str, found: list[dict], mode: str = "v2"):
        self.clock += timedelta(hours=1)
        record = {**_scan("org/api", found, self.clock.isoformat()), "finished_at": self.clock.isoformat(),
                  "coverage": {tool: {"examined": "*", "unexamined": {}} for tool in ("betterleaks", "trivy")},
                  "configuration": {"identity_keys": secret_identity.key_ids()}}
        record["summary"]["tools"] = [{"name": tool, "version": "1", "status": "completed"} for tool in ("betterleaks", "trivy")]
        record["source"]["uid"] = key
        with patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": mode}):
            return save_and_apply(self.data_dir, record, created_at=self.clock.isoformat())

    def decision(self, key: str, digest: str) -> str | None:
        return (triage.load(self.data_dir).get(key, {}).get(digest) or {}).get("status")

    def test_a_value_changed_in_place_is_the_old_one_fixed_and_a_new_one_open_with_no_triage(self):
        """The seed case: same file, same line, same key, same engines; only the value changes."""
        key = "github#seed"
        with Keys():
            saved, _ = self.scan(key, findings(self.root, [(0, SLACK_A, SLACK_BOT)]))
            (a,) = [item["fingerprint"] for item in saved["findings"]]
            triage.decide(self.data_dir, saved, [a], "false_positive", reason="A test workspace token, revoked", user=ADMIN)
            saved, changes = self.scan(key, findings(self.root, [(0, SLACK_B, SLACK_BOT)]))
            (b,) = [item["fingerprint"] for item in saved["findings"]]
        self.assertNotEqual(a, b)
        self.assertEqual((changes["new"], changes["fixed_now"]), ([b], [a]))
        entries = registry.load(self.data_dir, key)["findings"]
        self.assertEqual((entries[a]["status"], entries[b]["status"]), ("fixed", "open"))
        self.assertEqual((self.decision(key, a), self.decision(key, b)), ("false_positive", None))

    def test_an_entry_stored_before_values_were_read_is_adopted_once_then_only_its_value_counts(self):
        """0.13 stored secrets under the engine fingerprint, without the value's identity: the first scan that reads the
        value takes the entry and its triage (nothing opens, nothing is fixed). From then on it is that value's alone."""
        key = "github#legacy"
        with Keys():
            stored = [{key_: value for key_, value in item.items() if key_ not in ("identity", "value_formers")}
                      for item in findings(self.root, [(0, SLACK_A, SLACK_BOT)])]
            saved, _ = self.scan(key, stored, "v1")
            (legacy,) = [item["fingerprint"] for item in saved["findings"]]
            triage.decide(self.data_dir, saved, [legacy], "accepted", reason="Rotation planned for the next release", user=ADMIN)
            saved, changes = self.scan(key, findings(self.root, [(0, SLACK_A, SLACK_BOT)]))
            (a,) = [item["fingerprint"] for item in saved["findings"]]
            self.assertEqual((changes["new"], changes["fixed_now"], self.decision(key, a)), ([], [], "accepted"))
            saved, changes = self.scan(key, findings(self.root, [(0, SLACK_B, SLACK_BOT)]))
            (b,) = [item["fingerprint"] for item in saved["findings"]]
        self.assertEqual((changes["new"], changes["fixed_now"], self.decision(key, b)), ([b], [a], None))

    def test_an_entry_stored_under_the_engine_fingerprint_with_its_value_is_only_that_values(self):
        """An entry stored in v1 is keyed by the engine fingerprint, which B in A's place shares, but it carries A's
        identity: B never takes it, nor its triage. A, scanned in v2, does."""
        for value, outcome in ((SLACK_A, "moved"), (SLACK_B, "new")):
            with self.subTest(outcome), Keys():
                key = f"github#v1-{outcome}"
                saved, _ = self.scan(key, findings(self.root, [(0, SLACK_A, SLACK_BOT)]), "v1")
                (stored,) = [item["fingerprint"] for item in saved["findings"]]
                triage.decide(self.data_dir, saved, [stored], "accepted", reason="Rotation planned for the next release", user=ADMIN)
                saved, changes = self.scan(key, findings(self.root, [(0, value, SLACK_BOT)]))
                (now,) = [item["fingerprint"] for item in saved["findings"]]
                if outcome == "moved":
                    self.assertEqual((changes["new"], changes["fixed_now"], self.decision(key, now)), ([], [], "accepted"))
                else:
                    self.assertEqual((changes["new"], changes["fixed_now"], self.decision(key, now)), ([now], [stored], None))

    def test_a_formula_change_moves_each_value_by_the_earlier_formula_computed_from_it(self):
        key = "github#formula"
        keys = Keys()
        with keys:
            saved, _ = self.scan(key, findings(self.root, [(0, SLACK_A, SLACK_BOT)]))
            (a,) = [item["fingerprint"] for item in saved["findings"]]
            triage.decide(self.data_dir, saved, [a], "accepted", reason="Rotation planned for the next release", user=ADMIN)
        keys.new_formula()
        with keys:
            saved, changes = self.scan(key, findings(self.root, [(0, SLACK_A, SLACK_BOT)]))
            (moved,) = [item["fingerprint"] for item in saved["findings"]]
        self.assertNotEqual(moved, a)
        self.assertEqual((changes["new"], changes["fixed_now"], self.decision(key, moved)), ([], [], "accepted"))

    def test_stored_value_identities_are_marked_once_and_no_longer_reached_by_an_engine_fingerprint(self):
        """Data migration `secret_value_identities`: entries and runs stored by 0.14 before the mark get it when their
        identity was made with a key the instance knows; the next value in the same place is then new, not A's."""
        from pitangus.app import data_migrations
        key = "github#migrated"
        with Keys():
            unmarked = [{name: value for name, value in item.items() if name != "value_formers"}
                        for item in findings(self.root, [(0, SLACK_A, SLACK_BOT)])]
            saved, _ = self.scan(key, unmarked)
            (a,) = [item["fingerprint"] for item in saved["findings"]]
            self.assertFalse(of_value(registry.load(self.data_dir, key)["findings"][a]["finding"]))
            self.assertGreaterEqual(data_migrations._secret_value_identities(self.data_dir), 2)   # the entry and the run
            self.assertEqual(data_migrations._secret_value_identities(self.data_dir), 0)
            self.assertTrue(of_value(registry.load(self.data_dir, key)["findings"][a]["finding"]))
            saved, changes = self.scan(key, findings(self.root, [(0, SLACK_B, SLACK_BOT)]))
        (b,) = [item["fingerprint"] for item in saved["findings"]]
        self.assertEqual((changes["new"], changes["fixed_now"]), ([b], [a]))

    @settings(max_examples=12 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
    @given(pool=st.lists(TOKENS, min_size=2, max_size=4, unique=True), slots=st.lists(placements, min_size=1, max_size=3),
           data=st.data())
    @example(pool=[SLACK_A, SLACK_B], slots=[SLACK_BOT], data=None)
    def test_values_are_never_linked_and_each_keeps_its_own_through_rotations_and_formulas(self, pool, slots, data):
        """Scans of the same places with random values (kept, changed, removed, copied to another place), and between
        them a master key rotation or a formula change at random. What opens is exactly the values that weren't there
        in the scan before; what is fixed, exactly the values that went away; the triage of the first value is never
        anywhere else."""
        if data is None:   # the seed: A, then B in its place
            plans = [([0], "same"), ([1], "same")]
        else:
            plans = data.draw(st.lists(st.tuples(st.lists(st.integers(-1, len(pool) - 1), min_size=len(slots), max_size=len(slots)),
                                                 st.sampled_from(["same", "rotate", "formula"])), min_size=2, max_size=4))
        key, keys = f"github#{uuid.uuid4().hex[:12]}", Keys()
        before: dict[str, str] = {}      # value: its identity in the scan before
        for assignment, change in plans:
            if change == "rotate":
                keys.rotate()
            elif change == "formula":
                keys.new_formula()
            rows = placed(pool, assignment, slots)
            with keys:
                saved, changes = self.scan(key, findings(self.root, rows))
                now = {value: secret_identity.identity(value) for _, value, _ in rows}
            present = {item["fingerprint"] for item in saved["findings"]}
            self.assertEqual(present, set(now.values()))
            self.assertEqual(sorted(changes["new"]), sorted(now[value] for value in set(now) - set(before)))
            self.assertEqual(sorted(changes["fixed_now"]), sorted(before[value] for value in set(before) - set(now)))
            first = now.get(pool[0])
            if first and self.decision(key, first) is None:
                triage.decide(self.data_dir, saved, [first], "accepted", reason="Rotation planned for the next release", user=ADMIN)
            for value, identity in now.items():
                # A's acceptance stays A's (a new copy of A puts it back to open: triage covers the copies it saw).
                self.assertIn(self.decision(key, identity), ("accepted", "open") if value == pool[0] else (None,))
            before = now


class PullRequestGateTests(unittest.TestCase):
    def classify(self, base, head, stored):
        changed = {item["path"]: None for item in head}
        if stored:
            with patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": "v2"}):
                base = canonical.collapse(base)
        return review.classify(head, changed, base)["introduced"]

    def test_a_pr_that_changes_a_value_in_place_introduces_the_new_one(self):
        with tempfile.TemporaryDirectory() as folder, Keys():
            root = Path(folder)
            base, head = findings(root, [(0, SLACK_A, SLACK_BOT)]), findings(root, [(0, SLACK_B, SLACK_BOT)])
            for stored in (False, True):
                with self.subTest(stored=stored):
                    self.assertEqual([item["identity"] for item in self.classify(base, head, stored)], [secret_identity.identity(SLACK_B)])
                    self.assertEqual(self.classify(base, base, stored), [])

    @settings(max_examples=40 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(pool=st.lists(TOKENS, min_size=2, max_size=4, unique=True), slots=st.lists(placements, min_size=1, max_size=4),
           data=st.data(), stored=st.booleans(), rotated=st.booleans())
    def test_a_pr_introduces_exactly_the_places_each_value_gained(self, pool, slots, data, stored, rotated):
        """Whatever values the base and the head hold in the same places, a PR introduces, for each value, as many
        places as it gained: a value is never another value, and the same value is the same across a key rotation."""
        draw = st.lists(st.integers(-1, len(pool) - 1), min_size=len(slots), max_size=len(slots))
        before, after = data.draw(draw), data.draw(draw)
        keys = Keys()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            base_rows, head_rows = placed(pool, before, slots), placed(pool, after, slots)
            with keys:
                base = findings(root, base_rows)
            if rotated:
                keys.rotate()
            with keys:
                head = findings(root, head_rows)
                identity = {value: secret_identity.identity(value) for value in pool}
                introduced = self.classify(base, head, stored)
        grew = Counter(value for _, value, _ in head_rows) - Counter(value for _, value, _ in base_rows)
        self.assertEqual(Counter(item["identity"] for item in introduced), Counter({identity[value]: count for value, count in grew.items()}))


class NamesTests(unittest.TestCase):
    @settings(max_examples=40 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(values=st.lists(TOKENS, min_size=1, max_size=4), slots=st.lists(placements, min_size=1, max_size=4))
    def test_no_name_a_value_is_known_by_is_an_engine_fingerprint(self, values, slots):
        """The mechanism: a value's former names are computed from the value; no engine fingerprint (which another value
        in the same place would have) is ever among them, before or after grouping into families."""
        rows = [(place, values[place % len(values)], slot) for place, slot in enumerate(slots)]
        keys = Keys()
        keys.rotate()
        keys.new_formula()
        with tempfile.TemporaryDirectory() as folder, keys:
            found = findings(Path(folder), rows)
            families = canonical.collapse(found)
        engine = {name for item in found for name in [item["fingerprint"], item.get("previous_fingerprint"), *(item.get("previous_fingerprints") or [])]}
        for item in [*found, *families]:
            self.assertTrue(of_value(item))
            self.assertFalse(set(formers(item)) & engine, item)
            self.assertFalse(set(legacy_formers(item)) & {secret_identity.identity(value) for value in values})


if __name__ == "__main__":
    unittest.main()
