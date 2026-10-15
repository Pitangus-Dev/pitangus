"""What the 0.14 validation checked only in one direction, now run end to end through the web adapters and the registry.

- F4: a 404 or a 410 after the file was really removed does fix (the whitelist isn't "never fix"): whichever paths
  went, answering either code, over either scheme, exactly those are fixed and the rest stay open.
- F5: the whole cycle exposure check → full scan → exposure check → full scan: every entry keeps the kind of scan that
  opened it, a scan of one kind never touches the other's entries, and the second round opens and fixes nothing.
- F6: the second run, on the fixing side: a finding about a URL is fixed only by an absent answer to that URL, with its
  own scheme; another scheme's answer, absent or not, never fixes it.
"""

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from hypothesis import HealthCheck, example, given, settings, strategies as st

import testenv
from pitangus.modules.findings import registry
from pitangus.modules.runs.store import save_and_apply
from pitangus.modules.scanning import engines, web
from pitangus.shared.web_keys import key as page
from test_web_evidence import HOST, SCALE, SENSITIVE, Site, exposure_check, path_of
from test_web_scan import fake_docker, real

KEY = f"domain:{HOST}"
SCHEMES = ("http", "https")


class SchemeSite(Site):
    """A site whose files are served per scheme: `served` holds (scheme, path); a path not served answers 404, or 410
    when it is in `gone` (the site says it removed it)."""

    def __init__(self, served: set[tuple[str, str]], gone: set[tuple[str, str]] = frozenset()):
        super().__init__({path for _, path in served}, {"kind": "honest"})
        self.served, self.gone = set(served), set(gone)

    def truth(self, url: str) -> int:
        scheme, path = url.split("://", 1)[0], path_of(url)
        if path == "/" or (scheme, path) in self.served:
            return 200
        return 410 if (scheme, path) in self.gone else 404


class Registry(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)
        self.clock = datetime.now(timezone.utc)
        modes = patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "on", "PITANGUS_FIX_HOLD_MINIMUM": "1000"})
        modes.start()
        self.addCleanup(modes.stop)

    def save(self, record: dict) -> dict:
        self.clock += timedelta(hours=1)
        return save_and_apply(self.data_dir, record, created_at=self.clock.isoformat(), quiet=True)[1]

    def check(self, site: Site) -> tuple[dict, dict]:
        record = exposure_check(site, self.data_dir)
        return record, self.save(record)

    def entries(self) -> dict:
        return registry.load(self.data_dir, KEY)["findings"]

    def states(self) -> dict[str, str]:
        """Each entry's status by its page's key (shared/web_keys.py): the URL stored is rendered."""
        return {entry["finding"]["web_key"]: entry["status"] for entry in self.entries().values()}


class RemovedFixesTests(Registry):
    """F4."""

    @settings(max_examples=12 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(st.sets(st.sampled_from(SENSITIVE), min_size=1, max_size=5), st.data())
    @example(set(SENSITIVE[:2]), None)
    def test_a_404_or_a_410_after_removing_the_file_fixes_exactly_what_was_removed(self, exposed, data):
        self.setUp()
        served = {(scheme, path) for scheme in SCHEMES for path in exposed}
        record, changes = self.check(SchemeSite(served))
        self.assertEqual(record["status"], "completed")
        opened = self.states()
        self.assertEqual(set(opened), {page(f"{scheme}://{HOST}{path}") for scheme, path in served})
        if data is None:     # the seed: one removed answering 404, the other 410
            removed, codes = served, {item: 404 if item[1] == SENSITIVE[0] else 410 for item in served}
        else:
            removed = data.draw(st.sets(st.sampled_from(sorted(served)), min_size=1))
            codes = {item: data.draw(st.sampled_from([404, 410])) for item in removed}
        record, changes = self.check(SchemeSite(served - removed, {item for item, code in codes.items() if code == 410}))
        self.assertEqual(record["status"], "completed")
        expected = {page(f"{scheme}://{HOST}{path}"): "fixed" if (scheme, path) in removed else "open" for scheme, path in served}
        self.assertEqual(self.states(), expected, codes)
        self.assertEqual(changes["fixed"], len(removed))

    def test_the_seed_codes_one_by_one(self):
        for code in (404, 410):
            with self.subTest(code=code):
                self.setUp()
                served = {("https", "/.env"), ("http", "/.env")}
                self.check(SchemeSite(served))
                _, changes = self.check(SchemeSite(set(), served if code == 410 else set()))
                self.assertEqual((changes["opened"], changes["fixed"]), (0, 2))
                self.assertEqual(set(self.states().values()), {"fixed"})


class SchemeFixTests(Registry):
    """F6: the fixing side, on the second run."""

    @settings(max_examples=12 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(st.sampled_from(SENSITIVE), st.sampled_from(SCHEMES), st.sampled_from([404, 410]))
    @example("/.env", "http", 404)
    def test_only_an_absent_answer_with_its_own_scheme_fixes_it(self, path, scheme, code):
        self.setUp()
        other = "https" if scheme == "http" else "http"
        _, changes = self.check(SchemeSite({(scheme, path)}))
        url = page(f"{scheme}://{HOST}{path}")
        self.assertEqual(self.states(), {url: "open"})
        # Second run: the other scheme now says it's gone too, but this one still serves it: not fixed.
        _, changes = self.check(SchemeSite({(scheme, path)}, {(other, path)} if code == 410 else set()))
        self.assertEqual((changes["opened"], changes["fixed"], self.states()), (0, 0, {url: "open"}))
        # The other scheme serves it now, this one doesn't: that one opens, this one is fixed.
        _, changes = self.check(SchemeSite({(other, path)}, {(scheme, path)} if code == 410 else set()))
        self.assertEqual(self.states(), {url: "fixed", page(f"{other}://{HOST}{path}"): "open"})
        self.assertEqual((changes["opened"], changes["fixed"]), (1, 1))
        # And then it's gone over both: both fixed.
        _, changes = self.check(SchemeSite(set(), {(other, path), (scheme, path)} if code == 410 else set()))
        self.assertEqual(set(self.states().values()), {"fixed"})


def kind_of(entry: dict) -> str:
    return ((entry.get("finding") or {}).get("web") or {}).get("coverage") or "baseline"


class CycleTests(Registry):
    """F5: exposure check → full scan → exposure check → full scan, on one site, through both adapters."""

    def setUp(self):
        super().setUp()
        testenv.docker_runner(self)
        which = patch.object(engines.shutil, "which", return_value="/usr/bin/docker")
        which.start()
        self.addCleanup(which.stop)
        self.document = json.loads(json.dumps(real()).replace("pitangus.dev", HOST))

    def full(self) -> dict:
        with fake_docker(self.document):
            record = web.scan_domain({"id": "d" * 24, "host": HOST, "url": f"https://{HOST}/", "kind": "web", "key": KEY},
                                     "93.184.216.34", data_dir=self.data_dir)
        self.assertEqual(record["status"], "completed")
        return self.save(record)

    def test_the_whole_cycle_keeps_every_kind_and_settles_after_one_round(self):
        for identity in ("v1", "shadow", "v2"):
            with self.subTest(identity=identity), patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": identity}):
                registry.reset(self.data_dir)
                site = SchemeSite({(scheme, path) for scheme in SCHEMES for path in SENSITIVE[:3]})
                _, first = self.check(site)
                exposure = dict(self.entries())
                self.assertEqual({kind_of(entry) for entry in exposure.values()}, {"exposure"})
                second = self.full()
                after_full = self.entries()
                for name, entry in exposure.items():
                    self.assertEqual(after_full[name], entry, "a full scan touched an exposure check's entry")
                full = {name: entry for name, entry in after_full.items() if name not in exposure}
                self.assertTrue(full)
                self.assertEqual({kind_of(entry) for entry in full.values()}, {"baseline"})
                self.assertEqual((first["opened"], second["opened"], second["fixed"]), (len(exposure), len(full), 0))
                settled = {name: (kind_of(entry), entry["first_run"], entry["status"]) for name, entry in after_full.items()}
                for step in ("exposure", "full"):
                    changes = self.check(site)[1] if step == "exposure" else self.full()
                    self.assertEqual((changes["opened"], changes["fixed"]), (0, 0), (identity, step))
                    self.assertEqual({name: (kind_of(entry), entry["first_run"], entry["status"]) for name, entry in self.entries().items()},
                                     settled, (identity, step))


if __name__ == "__main__":
    unittest.main()
