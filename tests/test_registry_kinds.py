"""Kinds of web scan never take each other's findings (registry.lane, canonical.keyed_by_kind).

An anonymous crawl, one with saved headers, one API definition and an exposure check look at different things, but the
engines fingerprint a report by tool, rule and URL alone: the same nuclei template on the same page has one engine
fingerprint whatever kind of scan ran it, and a site-level header finding remembers the same page fingerprints as former
names. Properties, in every identity mode (v1, shadow, v2) and coverage mode: for random sequences of scans of
different kinds over overlapping pages and rules, an entry's kind never changes; a scan of one kind never moves,
absorbs, fixes or touches an entry of another kind; an entry's first run is always a run of its kind. Metamorphic:
scanning the same site with alternating kinds settles after one round (nothing opens, moves or is fixed after it), in
the registry and in the dashboard's figures, which are those of each kind run alone.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hypothesis import HealthCheck, example, given, settings, strategies as st

from pitangus.modules.findings import registry, triage
from pitangus.modules.runs.store import save_and_apply
from pitangus.modules.sources import domains
from pitangus.shared.code_identity import digest

PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

HOST = "kinds.example.test"
ROOT = f"https://{HOST}/"
KINDS = ("baseline", "baseline+headers", "api:0123456789abcdef", "exposure")
PAGES = ("", ".env", ".git/config", "admin", "users/1", "users/2")
# (tool, rule, site-level): a site-level rule is one finding at the root remembering each page it was reported on.
RULES = (("nuclei", "git-config", False), ("nuclei", "http-missing-security-headers:csp", True), ("ZAP", "10038", True),
         ("nuclei", "laravel-debugbar-exposure", False))
MODES = ("v1", "shadow", "v2")


def engine_fingerprint(tool: str, rule: str, url: str) -> str:
    """As the engines do it: tool, rule and URL, never the kind of scan."""
    return digest("sarif", tool.lower(), rule, url)


def findings_for(kind: str, seen: set[tuple[int, int]]) -> list[dict]:
    """What a scan of `kind` reports for `seen` ((rule, page) indexes): page rules on each page, site-level rules once at
    the root with the page fingerprints as former names."""
    found: dict[str, dict] = {}
    for rule_index, page_index in sorted(seen):
        tool, rule, site = RULES[rule_index]
        page = f"{ROOT}{PAGES[page_index]}"
        url = ROOT if site else page
        fingerprint = engine_fingerprint(tool, rule, url)
        finding = found.setdefault(fingerprint, {
            "finding_id": fingerprint[:16], "fingerprint": fingerprint, "scanner": "dast", "tool": tool, "rule_id": rule, "title": rule,
            "path": url, "line": 1, "severity": "medium", "confidence": 7, "priority": {"action": "track", "factors": []}, "reason": "",
            "remediation": "", "cwe": [], "owasp": [], "web": {"coverage": kind}})
        if site and page != url:
            finding.setdefault("previous_fingerprints", []).append(engine_fingerprint(tool, rule, page))
    return list(found.values())


def kind_of(entry: dict) -> str:
    return ((entry.get("finding") or {}).get("web") or {}).get("coverage") or "baseline"


class Scans:
    def __init__(self, data_dir: Path, key: str):
        self.data_dir, self.key, self.kinds = data_dir, key, {}

    def run(self, kind: str, seen: set[tuple[int, int]]) -> dict:
        pages = [domains.page_of(f"{ROOT}{page}") for page in PAGES]
        tools = [{"name": "ZAP", "status": "completed"}, {"name": "nuclei", "status": "completed"}]
        findings = findings_for(kind, seen)
        record, changes = save_and_apply(self.data_dir, {
            "type": "dast_scan", "status": "completed", "variant": kind, "target": ROOT, "context": "", "findings": findings,
            "source": domains.source_for({"host": HOST, "id": "d" * 24, "key": self.key, "kind": "web", "url": ROOT}),
            "scope": {"hosts": [HOST], "wildcards": [], "coverage": kind, "reached": pages, "probed": pages},
            "coverage": {"zap": {"examined": pages, "unexamined": {}}, "nuclei": {"examined": pages, "unexamined": {}}},
            "summary": {"files": 0, "dependencies": 0, "candidates": len(findings), "severities": {}, "priorities": {}, "kev": 0, "fixable": 0,
                        "tools": tools},
            "steps": [], "limitations": [], "owasp_coverage": []}, quiet=True)
        self.kinds[record["id"]] = kind
        return changes

    def entries(self) -> dict:
        return registry.load(self.data_dir, self.key)["findings"]


class KindLaneTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.examples = 0

    def scans(self) -> Scans:
        self.examples += 1
        return Scans(self.data_dir, f"domain:{HOST}#{self.examples}")

    @settings(max_examples=40 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    @given(st.sampled_from(MODES), st.sampled_from(("on", "off", "shadow")),
           st.lists(st.tuples(st.sampled_from(KINDS), st.sets(st.tuples(st.integers(0, len(RULES) - 1), st.integers(0, len(PAGES) - 1)), max_size=10)),
                    min_size=2, max_size=6))
    @example(identity="v2", coverage="on", steps=[("baseline", {(0, 2), (1, 0), (1, 3), (2, 4)}), ("exposure", {(0, 2), (1, 0)}),
                                                  ("baseline", {(0, 2), (1, 0), (1, 3), (2, 4)}), ("exposure", {(0, 2), (1, 0)})])
    @example(identity="v1", coverage="on", steps=[("baseline", {(0, 2), (3, 1)}), ("exposure", {(0, 2), (3, 1)}), ("exposure", set())])
    @example(identity="shadow", coverage="shadow", steps=[("baseline+headers", {(1, 3), (1, 4)}), ("baseline", {(1, 3)}), ("baseline", set())])
    def test_a_scan_of_one_kind_never_moves_absorbs_fixes_or_touches_another_kinds_entries(self, identity, coverage, steps):
        """Whatever kinds of scan run, over whatever overlapping pages and rules: an entry keeps its kind forever, a scan
        leaves every entry of another kind exactly as it was, and an entry's first run is a run of its own kind."""
        scans = self.scans()
        kinds: dict[str, str] = {}
        with patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": identity, "PITANGUS_COVERAGE_MODE": coverage, "PITANGUS_FIX_HOLD_MINIMUM": "1000"}):
            for kind, seen in steps:
                before = scans.entries()
                scans.run(kind, seen)
                after = scans.entries()
                for name, entry in before.items():
                    if kind_of(entry) != kind:
                        self.assertEqual(after.get(name), entry, (kind, name))
                for name, entry in after.items():
                    self.assertEqual(kind_of(entry), kinds.setdefault(name, kind_of(entry)), name)
                    self.assertEqual(scans.kinds[entry["first_run"]], kind_of(entry), name)

    @settings(max_examples=25 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    @given(st.sampled_from(MODES), st.lists(st.sampled_from(KINDS), min_size=2, max_size=3, unique=True),
           st.sets(st.tuples(st.integers(0, len(RULES) - 1), st.integers(0, len(PAGES) - 1)), min_size=1, max_size=10), st.integers(2, 3))
    @example(identity="v2", order=["baseline", "exposure"], seen={(0, 2), (1, 0), (1, 3), (1, 4), (2, 4), (3, 1)}, rounds=3)
    def test_alternating_kinds_over_the_same_site_settles_after_one_round(self, identity, order, seen, rounds):
        """Metamorphic: the same site scanned by kinds in turn (each seeing the same pages and rules) gives, after the first
        round, rounds that open nothing, fix nothing, move nothing and leave every first run where it was."""
        scans = self.scans()
        with patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": identity, "PITANGUS_COVERAGE_MODE": "on", "PITANGUS_FIX_HOLD_MINIMUM": "1000"}):
            for kind in order:
                scans.run(kind, seen)
            settled = {name: (entry["first_run"], entry["status"]) for name, entry in scans.entries().items()}
            for _ in range(rounds - 1):
                for kind in order:
                    changes = scans.run(kind, seen)
                    self.assertEqual((changes["opened"], changes["fixed"]), (0, 0), kind)
                    self.assertEqual({name: (entry["first_run"], entry["status"]) for name, entry in scans.entries().items()}, settled, kind)

    def test_entries_stored_before_fingerprints_named_the_kind_move_without_opening_or_fixing(self):
        """I7 for this formula change, in v1 and shadow (v2 identities already named the kind): an exposure check's or
        a header scan's entry stored under the engine fingerprint moves to the fingerprint that names its kind; nothing
        opens, nothing is fixed, its triage follows it, and the anonymous crawl's entry under the same engine
        fingerprint stays where it was."""
        from pitangus.modules.findings import canonical
        for identity in ("v1", "shadow"):
            with self.subTest(identity=identity), patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": identity, "PITANGUS_COVERAGE_MODE": "on"}):
                scans = self.scans()
                seen = {(0, 2)}
                with patch.object(canonical, "keyed_by_kind", side_effect=lambda findings: findings):   # the code before
                    scans.run("exposure", seen)
                stored = scans.entries()
                (old,) = stored
                triage.decide(self.data_dir, registry.view(self.data_dir, scans.key, status="all"), [old], "accepted",
                              reason="Served on purpose to the health checker", user={"username": "ana", "role": "admin"})
                changes = scans.run("exposure", seen)
                self.assertEqual((changes["opened"], changes["fixed"]), (0, 0))
                entries = scans.entries()
                (moved,) = entries
                self.assertNotEqual(moved, old)
                self.assertEqual(entries[moved]["first_run"], stored[old]["first_run"])
                self.assertEqual(triage.load_asset(self.data_dir, scans.key)[moved]["status"], "accepted")
                scans.run("baseline", seen)
                entries = scans.entries()
                self.assertEqual(len(entries), 2)
                self.assertEqual(entries[moved]["first_run"], stored[old]["first_run"])
                self.assertEqual({kind_of(entry) for entry in entries.values()}, {"baseline", "exposure"})


def figures(data_dir: Path) -> tuple:
    """What the dashboard says: open findings by severity, found and fixed in the window, and the assets' open counts."""
    from pitangus.modules.reporting import dashboard
    kpis = dashboard.compute(data_dir)["kpis"]
    return kpis["open"], kpis["found_in_window"], kpis["fixed_in_window"]


def added(left: tuple, right: tuple) -> tuple:
    return {level: left[0].get(level, 0) + right[0].get(level, 0) for level in {*left[0], *right[0]}}, left[1] + right[1], left[2] + right[2]


class DashboardKindTests(unittest.TestCase):
    """The dashboard's trend reads each kind of web scan apart, like the registry: a scan of one kind never makes
    another kind's findings look fixed or new, nor hands them its first-seen dates."""

    @settings(max_examples=15 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    @given(st.sampled_from(MODES), st.booleans(), st.lists(st.sampled_from(KINDS), min_size=2, max_size=3, unique=True),
           st.dictionaries(st.sampled_from(KINDS), st.sets(st.tuples(st.integers(0, len(RULES) - 1), st.integers(0, len(PAGES) - 1)), max_size=8)),
           st.integers(2, 3))
    @example(identity="v2", legacy=False, order=["baseline", "exposure"], sites={"baseline": {(0, 2), (1, 0), (1, 3), (2, 4)}, "exposure": {(0, 2)}},
             rounds=2)
    @example(identity="v1", legacy=True, order=["exposure", "baseline"], sites={"baseline": {(0, 2), (3, 1)}, "exposure": {(0, 2), (3, 1)}}, rounds=2)
    def test_alternating_kinds_shows_what_each_kind_alone_shows_and_no_fixes(self, identity, legacy, order, sites, rounds):
        """Metamorphic: the same site scanned by kinds in turn gives the dashboard figures of each kind run alone, added
        up; nothing is fixed, and nothing is found after the first round. `legacy`: runs stored before fingerprints named
        their kind (one engine fingerprint for every kind)."""
        from pitangus.modules.findings import canonical
        keyed = patch.object(canonical, "keyed_by_kind", side_effect=lambda findings: findings) if legacy else patch.dict(os.environ, {})
        with keyed, patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": identity, "PITANGUS_COVERAGE_MODE": "on", "PITANGUS_FIX_HOLD_MINIMUM": "1000"}):
            alone: tuple = ({}, 0, 0)
            for kind in order:
                with tempfile.TemporaryDirectory() as folder:
                    scans = Scans(Path(folder), f"domain:{HOST}")
                    for _ in range(rounds):
                        scans.run(kind, sites.get(kind, set()))
                    alone = added(alone, figures(Path(folder)))
            with tempfile.TemporaryDirectory() as folder:
                scans = Scans(Path(folder), f"domain:{HOST}")
                for kind in order:
                    scans.run(kind, sites.get(kind, set()))
                first = figures(Path(folder))
                for _ in range(rounds - 1):
                    for kind in order:
                        scans.run(kind, sites.get(kind, set()))
                together = figures(Path(folder))
        clean = lambda value: ({level: count for level, count in value[0].items() if count}, value[1], value[2])  # noqa: E731
        self.assertEqual(together[2], 0)
        self.assertEqual(clean(together), clean(first))
        self.assertEqual(clean(together), clean(alone))


if __name__ == "__main__":
    unittest.main()
