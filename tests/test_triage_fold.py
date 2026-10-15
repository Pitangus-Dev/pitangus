"""Folding fingerprints never relaxes triage (A5): copies of one finding folded into a family, on the first v2 scan or
when an engine's fingerprint changes, keep a decision no more lenient than the strictest copy, the earliest expiry,
every copy's history and every Jira issue.

"Lenient" is how long a decision hides the finding: open or in progress hides nothing, an acceptance hides it until it
expires (an unreadable expiry already expired, none never does), a false positive or a manual fix hides it for good.
"""

import os
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from hypothesis import HealthCheck, given, settings, strategies as st

from pitangus.modules.findings import registry, tickets, triage
from pitangus.modules.runs import registry as run_registry
from pitangus.modules.runs.store import save_and_apply
from test_canonical_identity import code
from test_dashboard import _scan
from test_invariants import SCALE

ADMIN = {"username": "ana", "role": "admin"}
TODAY = datetime.now(timezone.utc).date()


def hidden_until(entry: dict | None) -> date:
    """Until when a decision keeps the finding out of the pending work."""
    status = (entry or {}).get("status", "open")
    if status in ("false_positive", "fixed"):
        return date.max
    if status == "accepted":
        return triage._expiry(entry)
    return date.min


def events(entry: dict | None) -> list[dict]:
    return list((entry or {}).get("history") or [])


stamps = st.datetimes(datetime(2025, 1, 1), datetime(2026, 12, 31)).map(lambda moment: moment.replace(tzinfo=timezone.utc).isoformat(timespec="seconds"))
expiries = st.one_of(st.none(), st.just("not-a-date"), st.dates(date(2025, 1, 1), date(2027, 12, 31)).map(date.isoformat))


@st.composite
def decisions(draw):
    status = draw(st.sampled_from(triage.STATUSES))
    at, by = draw(stamps), draw(st.sampled_from(["ana", "luis", "sistema"]))
    expires = draw(expiries) if status == "accepted" else None
    event = {"status": status, "reason": draw(st.sampled_from(["", "Sandboxed, input is a constant"])), "note": "", "by": by,
             "at": at, "expires_at": expires, "run_id": draw(st.sampled_from(["r1", "r2"]))}
    earlier = draw(st.lists(st.builds(lambda status, at: {"status": status, "reason": "", "note": "", "by": "luis", "at": at, "expires_at": None},
                                      st.sampled_from(triage.STATUSES), stamps), max_size=3))
    decision = {**event, "history": [*earlier, event]}
    if draw(st.booleans()):
        decision["count"] = draw(st.integers(1, 4))
    return decision


copies_ = st.dictionaries(st.text("0123456789abcdef", min_size=64, max_size=64), st.one_of(st.none(), decisions()), min_size=1, max_size=6)


class FoldPropertyTests(unittest.TestCase):
    @settings(max_examples=400 * SCALE, deadline=None)
    @given(copies_)
    def test_a_folded_decision_is_never_more_lenient_than_its_strictest_copy(self, copies):
        folded = triage.fold(copies, "2026-10-12T00:00:00+00:00")
        if not any(copies.values()):
            self.assertIsNone(folded)  # nothing decided: nothing stored, the family is open
            return
        strictest = min(hidden_until(entry) for entry in copies.values())
        self.assertLessEqual(hidden_until(folded), strictest, folded)
        statuses = {(entry or {}).get("status") for entry in copies.values()}
        if len(statuses) > 1 or None in statuses:
            self.assertEqual(folded["status"], "open")  # different decisions, or an unreviewed copy: pending review
        else:
            self.assertEqual(folded["status"], statuses.pop())
        if folded["status"] == "accepted":
            self.assertEqual(triage._expiry(folded), min(triage._expiry(entry) for entry in copies.values()))
        for entry in copies.values():
            for event in events(entry):
                self.assertIn(event, folded["history"])
        self.assertLessEqual(set(copies), set(folded["folded"]))
        # Folding the same copies again, with the result as the decision already there, changes nothing.
        self.assertEqual(triage.fold({**copies, "f" * 64: folded}, "2026-10-13T00:00:00+00:00")["status"], folded["status"])

    @settings(max_examples=300 * SCALE, deadline=None)
    @given(st.lists(st.lists(st.sampled_from(["SEC-1", "SEC-2", "SEC-3", "OPS-9"]), min_size=1, max_size=3, unique=True), min_size=1, max_size=5))
    def test_folding_links_drops_no_issue(self, groups):
        def link(keys):
            first, *rest = keys
            return {"key": first, "url": f"https://jira.example/browse/{first}", **({"replaces": rest} if rest else {})}
        links = [link(keys) for keys in groups]
        folded = tickets.fold(links)
        kept = {issue["key"] for issue in tickets._issues(folded)} | {key for issue in tickets._issues(folded) for key in issue.get("replaces") or []}
        self.assertEqual(kept, {key for keys in groups for key in keys})
        self.assertEqual(folded["key"], links[0]["key"])
        self.assertEqual(tickets.fold([folded, *links]), folded)  # idempotent


class MigrationTests(unittest.TestCase):
    """The first v2 scan after upgrading folds each family's v1 copies, whatever each one's decision was."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.clock = datetime.now(timezone.utc)
        self.examples = 0

    def scan(self, key, findings, mode):
        self.clock += timedelta(hours=1)
        record = {**_scan("org/api", findings, self.clock.isoformat()), "finished_at": self.clock.isoformat()}
        record["summary"]["tools"] = [{"name": "opengrep", "version": "1", "status": "completed"}]
        record["source"]["uid"] = key
        with patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": mode}):
            return save_and_apply(self.data_dir, record, created_at=self.clock.isoformat())[0]

    def decide(self, record, digest, choice):
        status, days = choice
        options = {"expires_at": (TODAY + timedelta(days=days)).isoformat()} if status == "accepted" else {}
        triage.decide(self.data_dir, record, [digest], status, reason="Reviewed by the team for this test", user=ADMIN, **options)

    @settings(max_examples=15 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    @given(st.lists(st.tuples(st.one_of(st.none(), st.tuples(st.sampled_from(["false_positive", "accepted", "in_progress"]), st.integers(1, 300))),
                              st.one_of(st.none(), st.sampled_from(["SEC-1", "SEC-2", "SEC-3"]))), min_size=1, max_size=4))
    def test_the_first_v2_scan_never_relaxes_a_family_and_keeps_every_issue(self, plan):
        self.examples += 1
        key = f"github#fold-{self.examples}"
        copies = [code(10 + index * 30) for index in range(len(plan))]
        first = self.scan(key, copies, "v1")
        for finding, (choice, issue) in zip(first["findings"], plan):
            if choice:
                self.decide(first, finding["fingerprint"], choice)
            if issue:
                tickets.remember(self.data_dir, key, finding["fingerprint"], {"key": issue, "url": f"https://jira.example/browse/{issue}"})
        before = triage.load_asset(self.data_dir, key)
        saved = self.scan(key, copies, "v2")
        (family,) = saved["findings"]
        digest = family["fingerprint"]
        decision = triage.load_asset(self.data_dir, key).get(digest)
        olds = {finding["fingerprint"]: before.get(finding["fingerprint"]) for finding in first["findings"]}
        self.assertLessEqual(hidden_until(decision), min(hidden_until(entry) for entry in olds.values()), plan)
        if any(olds.values()):
            for entry in olds.values():
                for event in events(entry):
                    self.assertIn(event, decision["history"])
        if decision and decision["status"] == "accepted":
            self.assertEqual(decision["expires_at"], min(entry["expires_at"] for entry in olds.values()))
        issues = {issue for _, issue in plan if issue}
        link = tickets.load_links(self.data_dir).get(key, {}).get(digest)
        self.assertEqual({item["key"] for item in tickets._issues(link)} if link else set(), issues)
        # Scanning again and rebuilding the asset's registry from its runs (as `rebuild` does) fold nothing twice.
        third = self.scan(key, copies, "v2")
        registry.forget_asset(self.data_dir, key)
        for run in (first, saved, third):
            registry.apply(self.data_dir, run)
        self.assertEqual(triage.load_asset(self.data_dir, key).get(digest), decision)

    def test_mixed_decisions_leave_the_family_for_review_and_agreeing_ones_keep_the_earliest_expiry(self):
        for name, plan, status, expiry in (("mixed", [("accepted", 30), None, ("false_positive", 0)], "open", None),
                                           ("agreeing", [("accepted", 60), ("accepted", 10), ("accepted", 200)], "accepted", 10)):
            with self.subTest(name):
                key = f"github#{name}"
                copies = [code(10 + index * 30) for index in range(len(plan))]
                first = self.scan(key, copies, "v1")
                for finding, choice in zip(first["findings"], plan):
                    if choice:
                        self.decide(first, finding["fingerprint"], choice)
                (family,) = self.scan(key, copies, "v2")["findings"]
                decision = triage.load_asset(self.data_dir, key)[family["fingerprint"]]
                self.assertEqual(decision["status"], status)
                self.assertEqual(decision["expires_at"], expiry and (TODAY + timedelta(days=expiry)).isoformat())
                self.assertEqual(sorted(item["fingerprint"] for item in decision["history"][-1]["folded"]),
                                 sorted(finding["fingerprint"] for finding in first["findings"]))
                if status == "accepted":
                    self.assertEqual(decision["count"], 3)
                # A decision taken on the family afterwards survives a rebuild of the registry.
                self.decide(registry.view(self.data_dir, key, status="all"), family["fingerprint"], ("false_positive", 0))
                run_registry.rebuild(self.data_dir)
                self.assertEqual(triage.load_asset(self.data_dir, key)[family["fingerprint"]]["status"], "false_positive")


if __name__ == "__main__":
    unittest.main()
