"""A web finding's location is rendered like any URL, and what its identity and coverage read is pinned first
(shared/web_keys.py).

Properties: a random value in a path segment, a piece of one, a query (name or value), a fragment, user information or
a matrix parameter of a crawled URL never shows in anything stored or shown (the fragment oracle), while the page keeps
its identity from one scan of the site to the next; the identities are those the location form gave (templates built
on keys, piece for piece as on the location form, with earlier scans' pages known by their keys); two pages shown
alike are never one page to the registry. The data migration pins the keys of runs and registry entries stored in the
location form, keeps every identity and renders their URLs again, idempotently.
"""

import json
import os
import random
import string
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hypothesis import HealthCheck, example, given, settings, strategies as st
from sqlalchemy import select, update

from pitangus.modules.findings import canonical, registry
from pitangus.modules.runs.store import save_and_apply
from pitangus.modules.scanning.sarif_import import _references
from pitangus.modules.sources import domains
from pitangus.shared import db, masking, render, web_keys
from pitangus.shared.code_identity import digest

from test_credential_masking import _outputs
from value_oracle import leaked

PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

HOST = "shop.example.test"
KEY = f"domain:{HOST}"
ROOT = f"https://{HOST}/"
# Where a value sits in a crawled URL: every part a renderer could keep.
FORMS = {
    "segment": "https://shop.example.test/account/{v}",
    "piece": "https://shop.example.test/files/report-{v}.pdf",
    "deep": "https://shop.example.test/{v}/settings",
    "query": "https://shop.example.test/search?q={v}&page=2",
    "query_name": "https://shop.example.test/search?{v}=1",
    "fragment": "https://shop.example.test/doc#{v}",
    "fragment_pair": "https://shop.example.test/cb#access_token={v}&state=x",
    "user": "https://{v}@shop.example.test/login",
    "password": "https://admin:{v}@shop.example.test/login",
    "matrix": "https://shop.example.test/cart;session={v}/items",
}
ALPHABET = string.ascii_letters + string.digits


def value(seed: int, length: int) -> str:
    """A value nobody chose from words: letters and digits at random, at least one of each."""
    rng = random.Random(seed)
    text = "".join(rng.choice(ALPHABET) for _ in range(length - 2)) + rng.choice(string.ascii_letters) + rng.choice(string.digits)
    return "".join(rng.sample(text, len(text)))


def finding(url: str, rule: str = "10024", tool: str = "zap") -> dict:
    fingerprint = digest("sarif", tool, rule, url)
    return {"finding_id": fingerprint[:16], "fingerprint": fingerprint, "scanner": "dast", "tool": tool, "rule_id": rule, "title": "Information disclosure",
            "path": url, "line": 1, "severity": "medium", "confidence": 7, "priority": {"action": "track", "factors": []}, "reason": "",
            "remediation": "", "cwe": [200], "owasp": [], "web": {"coverage": "baseline", "method": "GET", "evidence": ""}}


def scan(findings: list[dict], reached: list[str], target: str = ROOT) -> dict:
    pages = sorted({page for url in reached if (page := domains.page_of(url))})
    findings = [dict(item) for item in findings]
    return {"type": "dast_scan", "status": "completed", "variant": "baseline", "target": target, "context": "", "findings": findings,
            "source": domains.source_for({"host": HOST, "id": "d" * 24, "key": KEY, "kind": "web", "url": ROOT}),
            "scope": {"hosts": [HOST], "wildcards": [], "coverage": "baseline", "reached": pages},
            "coverage": {"zap": {"examined": pages, "unexamined": {}}},
            "summary": {"files": 0, "dependencies": 0, "candidates": len(findings), "severities": {}, "priorities": {}, "kev": 0, "fixable": 0,
                        "tools": [{"name": "ZAP", "status": "completed"}]},
            "steps": [], "limitations": [], "owasp_coverage": []}


class Isolated(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        modes = patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "on", "PITANGUS_FIX_HOLD_MINIMUM": "1000"})
        modes.start()
        self.addCleanup(modes.stop)

    def fresh(self) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return Path(directory.name)

    def entries(self, data_dir: Path | None = None) -> dict:
        return registry.load(data_dir or self.data_dir, KEY)["findings"]


class NoValueInALocationTests(Isolated):
    @settings(max_examples=6 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(st.sampled_from(sorted(FORMS)), st.integers(0, 2**32), st.integers(6, 30))
    @example("segment", 7, 10)        # shorter than a token, kept by the location form before
    @example("piece", 11, 8)
    @example("password", 3, 12)
    def test_a_value_in_any_part_of_a_crawled_url_shows_nowhere_and_the_page_keeps_its_identity(self, form, seed, length):
        data_dir = self.fresh()
        secret = value(seed, length)
        url = FORMS[form].format(v=secret)
        other = f"{ROOT}help/topics/shipping/about"   # deeper than any form: never in a template with it
        findings = [finding(url), finding(other)]
        outputs = _outputs(data_dir, scan(findings, [url, other], target=url), KEY, "v2", cli_from="saved")
        for name, text in outputs.items():
            self.assertEqual(leaked(secret, text), [], f"{form}: {name}")
        first = {name: entry["finding"]["web_key"] for name, entry in self.entries(data_dir).items()}
        self.assertEqual(sorted(first.values()), sorted({web_keys.key(url), web_keys.key(other)}))
        _, changes = save_and_apply(data_dir, scan(findings, [url, other], target=url), quiet=True)
        self.assertEqual((changes["opened"], changes["fixed"]), (0, 0), form)
        self.assertEqual({name: entry["finding"]["web_key"] for name, entry in self.entries(data_dir).items()}, first)

    @settings(max_examples=40 * SCALE, deadline=None)
    @given(st.sampled_from(sorted(FORMS)), st.integers(0, 2**32), st.integers(6, 30))
    def test_a_rules_reference_is_rendered_like_any_url(self, form, seed, length):
        secret = value(seed, length)
        url = FORMS[form].format(v=secret)
        shown = _references({"helpUri": url, "properties": {"references": [f"See {url} and {url}."]}})
        self.assertEqual(leaked(secret, json.dumps(shown)), [], url)
        self.assertEqual(shown, [render.url(url)])


class PagesShownAlikeTests(Isolated):
    """The registry tells pages apart by their keys: two pages the renderer shows alike stay two."""

    def test_a_scan_that_reached_only_one_of_two_pages_shown_alike_fixes_only_that_one(self):
        one, other = f"{ROOT}{value(1, 9)}/{value(2, 9)}", f"{ROOT}{value(3, 9)}/{value(4, 9)}"
        self.assertEqual(render.url(one), render.url(other))   # both `/***/***`, and no template joins them
        _, changes = save_and_apply(self.data_dir, scan([finding(one), finding(other)], [one, other]), quiet=True)
        self.assertEqual(changes["opened"], 2)
        # Gone from the page it reached; the other, shown alike, wasn't reached: it stays open.
        _, changes = save_and_apply(self.data_dir, scan([], [one]), quiet=True)
        states = {entry["finding"]["web_key"]: entry["status"] for entry in self.entries().values()}
        self.assertEqual(states, {web_keys.key(one): "fixed", web_keys.key(other): "open"})

    def test_a_family_on_two_pages_shown_alike_counts_each(self):
        one, other = f"{ROOT}item/{value(5, 10)}", f"{ROOT}item/{value(6, 10)}"
        self.assertEqual(render.url(one), render.url(other))
        save_and_apply(self.data_dir, scan([finding(one), finding(other)], [one, other]), quiet=True)
        (entry,) = self.entries().values()
        self.assertEqual(entry["finding"]["count"], 2)
        self.assertEqual({item["key"] for item in entry["finding"]["instances"]}, {web_keys.key(one), web_keys.key(other)})
        # Both pages reached, the finding only on one: the family loses one instance, shown alike or not.
        save_and_apply(self.data_dir, scan([finding(one)], [one, other]), quiet=True)
        (entry,) = self.entries().values()
        self.assertEqual((entry["status"], entry["finding"]["count"]), ("open", 1))
        self.assertEqual((entry["partial"]["from"], entry["partial"]["to"]), (2, 1))


# Path pieces: words, numbers, build hashes and token-shaped runs, joined by separators.
PIECES = st.sampled_from(["index", "users", "app", "main", "v2", "123", "BkL9x2a1", "C0aZ77qp", "a8F3kQ9zLm2X", "report", "x"])
SEGMENTS = st.lists(st.tuples(PIECES, st.sampled_from(["-", "_", ".", "~", ""])), min_size=1, max_size=3).map(
    lambda parts: "".join(piece + separator for piece, separator in parts).rstrip("-_.~") or "x")
PATHS = st.lists(SEGMENTS, min_size=1, max_size=3).map(lambda segments: "/" + "/".join(segments))
TAILS = st.sampled_from(["", "?id=7", "#top", "?a=1&b=2", ";jsessionid=abc"])
URLS = st.tuples(st.sampled_from(["https", "http"]), st.sampled_from([HOST, "admin:pw@" + HOST, HOST + ":8443"]), PATHS, TAILS).map(
    lambda parts: f"{parts[0]}://{parts[1]}{parts[2]}{parts[3]}")


def location_identities(findings: list[dict], known: list[tuple[str, str, str, str]]) -> list[str]:
    """The identities as 0.13 computed them: templates built on the location form (render.location) of the URLs reported
    and of those stored earlier."""
    identities = []
    for item in findings:
        group = (item["tool"].lower(), item["rule_id"], canonical._web_template_key(render.location(item["path"]))[0])
        urls = [render.location(other["path"]) for other in findings
                if (other["tool"].lower(), other["rule_id"], canonical._web_template_key(render.location(other["path"]))[0]) == group]
        urls += [render.location(url) for tool, rule, url, _ in known if (tool, rule) == group[:2]
                 and canonical._web_template_key(render.location(url))[0] == group[2]]
        identities.append(web_keys.identity(item, canonical.web_templates(urls)[render.location(item["path"])]))
    return identities


class SameIdentitiesTests(unittest.TestCase):
    @settings(max_examples=300 * SCALE, deadline=None)
    @given(st.lists(st.tuples(URLS, st.sampled_from(["10024", "10038"])), min_size=1, max_size=8),
           st.lists(st.tuples(URLS, st.sampled_from(["10024", "10038"])), max_size=6))
    @example([("https://shop.example.test/assets/index-BkL9x2a1.js", "10024")], [("https://shop.example.test/assets/index-C0aZ77qp.js", "10024")])
    def test_the_identities_are_those_the_location_form_gave_with_earlier_pages_known_by_their_keys(self, reported, earlier):
        findings = [finding(url, rule) for url, rule in reported]
        known = [("zap", rule, url, "baseline") for url, rule in earlier]
        keyed = [("zap", rule, web_keys.key(url), "baseline") for url, rule in earlier]
        self.assertEqual(canonical._identities(findings, keyed), location_identities(findings, known))

    @settings(max_examples=200 * SCALE, deadline=None)
    @given(URLS, URLS)
    def test_a_key_tells_pages_apart_as_the_location_form_did_and_never_holds_a_path(self, left, right):
        self.assertEqual(web_keys.key(left) == web_keys.key(right),
                         urlsplit_key(render.location(left)) == urlsplit_key(render.location(right)))
        for url in (left, right):
            found = web_keys.key(url)
            self.assertEqual(web_keys.key(render.location(url)), found)   # the location form has the key the URL had
            path = found.partition("://")[2].partition("/")[2]
            self.assertRegex(path, r"^[0-9a-f/\-_.~?]*$")


def urlsplit_key(location: str) -> tuple:
    """What a key keeps of a location form: scheme, host, port other than the default, path, and query and fragment."""
    from urllib.parse import urlsplit
    parts = urlsplit(location)
    try:
        port = parts.port
    except ValueError:
        port = None
    port = None if port == {"https": 443, "http": 80}.get(parts.scheme) else port
    return parts.scheme, parts.hostname, port, parts.path, parts.query, parts.fragment


class WebLocationKeysMigrationTests(Isolated):
    """`web_location_keys`: runs and registry entries stored in the location form (0.14 before it) get their keys pinned
    from it, keep every identity, and have their URLs rendered again."""

    def setUp(self):
        super().setUp()
        from pitangus.app import data_migrations as migrations
        from pitangus.shared import documents
        self.migrations = migrations
        position = [migration.name for migration in migrations.MIGRATIONS].index("web_location_keys")
        documents.save(self.data_dir, migrations.VERSION_DOCUMENT, {"version": position, "history": []})

    def legacy_scan(self, record: dict) -> None:
        """Saved as before keys existed: every URL in the location form, nothing pinned."""
        from pitangus.modules.runs.tables import runs
        with patch.object(masking, "mask_url", render.location), patch.object(web_keys, "pinned", dict):
            saved, _ = save_and_apply(self.data_dir, record, quiet=True)
        with db.transaction(self.data_dir) as connection:
            stored = connection.execute(select(runs.c.record).where(runs.c.id == saved["id"])).scalar_one()
            stored.pop("keys", None)
            connection.execute(update(runs).where(runs.c.id == saved["id"]).values(record=stored))

    def test_keys_are_pinned_from_the_location_form_identities_stay_and_urls_are_rendered(self):
        from pitangus.modules.runs.store import _row, load_run
        secret, token = value(21, 11), value(22, 9)
        pages = [f"{ROOT}reset/{secret}", f"{ROOT}assets/index-BkL9x2a1.js", f"{ROOT}assets/index-C0aZ77qp.js", f"{ROOT}cb#code={token}"]
        record = scan([finding(url) for url in pages], pages, target=pages[0])
        self.legacy_scan(record)
        before = {name: (entry["finding"]["identity"], entry["finding"]["count"]) for name, entry in self.entries().items()}
        legacy = json.dumps(self.entries())
        self.assertIn(secret, legacy)                     # what the location form kept
        self.assertNotIn("web_key", legacy)

        self.assertEqual(self.migrations.upgrade(self.data_dir), ["web_location_keys", "drop_stored_code"])
        entries = self.entries()
        self.assertEqual({name: (entry["finding"]["identity"], entry["finding"]["count"]) for name, entry in entries.items()}, before)
        self.assertEqual({item["key"] for entry in entries.values() for item in entry["finding"]["instances"]}, {web_keys.key(url) for url in pages})
        (run,) = [load_run(self.data_dir, run_id) for run_id in registry.load(self.data_dir, KEY)["applied"]]
        self.assertEqual(run["target"], render.url(pages[0]))
        self.assertEqual(sorted(run["keys"]["scope"]["reached"]), sorted({web_keys.of_page(url) for url in pages}))
        with db.transaction(self.data_dir) as connection:
            from pitangus.modules.runs.tables import runs
            self.assertEqual(connection.execute(select(runs.c.row).where(runs.c.id == run["id"])).scalar_one(), _row(run))
        from test_credential_masking import _rows
        for item in (secret, token):
            self.assertEqual(leaked(item, _rows(self.data_dir)), [], item)
        # Idempotent, and the next scan of the site opens and fixes nothing.
        self.assertEqual(self.migrations._web_location_keys(self.data_dir), 0)
        _, changes = save_and_apply(self.data_dir, scan([finding(url) for url in pages], pages, target=pages[0]), quiet=True)
        self.assertEqual((changes["opened"], changes["fixed"]), (0, 0))
        self.assertEqual({name: entry["finding"]["identity"] for name, entry in self.entries().items()}, {name: item[0] for name, item in before.items()})


if __name__ == "__main__":
    unittest.main()
