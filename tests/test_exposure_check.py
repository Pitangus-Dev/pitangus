"""The exposure check (scanning/web.scan_exposure): what it asks for, how it counts, what a soft 404 is, and how its
findings live next to a full scan's.

Properties rather than examples: a path finding on a page that answers like any random path of the site is dropped,
whatever the random path and even when the page echoes the path it was asked for; a site without a catch-all never loses one; the pages counter is the number of distinct
pages; a path finding's identity doesn't depend on any other rule's URLs; an exposure check never touches a full
scan's findings (nor fixes them, nor marks them unseen); and nothing it tells the user mentions ZAP or a crawl."""

import html
import json
import os
import random
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote, urlsplit

from hypothesis import HealthCheck, example, given, settings, strategies as st

import test_web_evidence as evidence
from pitangus.modules.findings import canonical, registry
from pitangus.modules.scanning import nuclei_templates, web, web_tools
from pitangus.modules.sources import domains
from pitangus.shared import web_keys
from pitangus.shared.i18n import MARK, text

PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

HOST = evidence.HOST
ROOT = f"https://{HOST}/"
segments = st.text("abcdefghijklmnopqrstuvwxyz0123456789-_.", min_size=1, max_size=12).filter(lambda part: part not in (".", ".."))


def flip(value: int, bits: int, rng: random.Random) -> int:
    for bit in rng.sample(range(64), bits):
        value ^= 1 << bit
    return value


KINDS = ("baseline", "baseline+headers", "api:0123456789abcdef", "exposure")


def kind_of(finding: dict) -> str:
    return (finding.get("web") or {}).get("coverage") or "baseline"


def web_finding(url: str, kind: str, index: int = 0) -> dict:
    """ZAP's CSP alert (the same rule and evidence on every page) on `url`, as a scan of `kind` stores it."""
    return {"finding_id": f"w{index}", "fingerprint": f"{url}|{kind}", "scanner": "dast", "tool": "ZAP", "rule_id": "10038", "title": "CSP",
            "path": url, "line": 1, "severity": "medium", "confidence": 7, "priority": {"action": "track", "factors": []}, "reason": "",
            "remediation": "", "cwe": [], "owasp": [], "web": {"coverage": kind}}


def nuclei_finding(path: str, rule: str = "laravel-debugbar-exposure", scheme: str = "https") -> dict:
    return {"fingerprint": f"{rule}:{path}", "tool": "nuclei", "rule_id": rule, "path": f"{scheme}://{HOST}{path}", "scanner": "dast"}


# A path as a site decodes it (anything but the characters that would decode twice: `%`, `&`) and the forms a
# catch-all page echoes it in.
decoded_paths = st.lists(st.text(st.characters(blacklist_categories=("Cs", "Cc", "Zl", "Zp"), blacklist_characters="%&?#/\\\r\n\t"),
                                 min_size=1, max_size=40), min_size=1, max_size=5).map(lambda parts: "/" + "/".join(parts))
ECHOES = (lambda decoded: quote(decoded), lambda decoded: decoded, lambda decoded: html.escape(decoded),
          lambda decoded: html.escape(quote(decoded)), lambda decoded: decoded.lstrip("/"), lambda decoded: f"{ROOT.rstrip('/')}{quote(decoded)}")
words = st.lists(st.sampled_from([f"w{index}" for index in range(300)]), min_size=1, max_size=80)
references = st.binary(min_size=8, max_size=8).map(lambda value: f"/pitangus-{value.hex()}")   # web.soft_404_references


def catch_all(template: list[str], decoded: str, places: list[tuple[int, int]]) -> str:
    """The catch-all page for `decoded`: the template's words with the path echoed at `places` (index, form)."""
    body = list(template)
    for index, form in sorted(places, reverse=True):
        body.insert(index % (len(body) + 1), f"<b>{ECHOES[form](decoded)}</b>")
    return "<html>" + " ".join(body) + "</html>"


def signature(status: int, body: str | None, decoded: str) -> tuple:
    return status, body, quote(decoded)


class SoftNotFoundTests(unittest.TestCase):
    @settings(max_examples=150 * SCALE, deadline=None)
    @given(decoded_paths, references, words, st.lists(st.tuples(st.integers(0, 200), st.integers(0, len(ECHOES) - 1)), min_size=1, max_size=4),
           st.sampled_from([200, 404]), words.map(lambda items: [f"real{item}" for item in items]), st.booleans())
    @example("/_debugbar/open", "/pitangus-0123456789abcdef", ["Sorry", "the", "page", "you", "asked", "for", "is", "not", "here"],
             [(3, 0), (9, 1)], 200, ["APP_DEBUG"], False)
    @example("/b", "/pitangus-0123456789abcdef", ["w0"], [(0, 0)], 200, ["realw0"], False)   # a tag named like the path once outweighed the words
    @example("/a<b/<i>x", "/pitangus-0123456789abcdef", ["w1", "w2"], [(0, 1), (1, 2), (2, 3)], 404, ["realw3"], True)
    @example("/0/0", "/pitangus-0123456789abcdef", ["w0"], [(0, 0), (0, 0), (0, 0)], 200, ["realw0"], True)
    def test_a_catch_all_page_that_echoes_the_path_is_a_soft_404_whatever_the_path(self, decoded, random_path, template, places,
                                                                                    status, real_words, linked):
        """A catch-all site answers every path with one page that repeats the path it was asked for (as sent, decoded,
        HTML-escaped, without its slash, inside the full URL), its template perhaps naming the path's words too (a
        link, a menu: `linked`): the finding on that path is dropped, whatever the path's length or characters and
        whatever the random reference path; a real page (other words) stays."""
        if linked:
            template = [*template, decoded]
        finding, real = nuclei_finding(quote(decoded)), nuclei_finding("/real-file")
        reference = f"{ROOT.rstrip('/')}{quote(random_path)}"
        signatures = {domains.page_of(reference): signature(status, catch_all(template, random_path, places), random_path),
                      domains.page_of(finding["path"]): signature(status, catch_all(template, decoded, places), decoded),
                      domains.page_of(real["path"]): signature(status, "<html>" + " ".join(real_words) + "</html>", "/real-file")}
        if domains.page_of(finding["path"]) in (domains.page_of(ROOT), domains.page_of(reference), domains.page_of(real["path"])):
            return
        kept, dropped = web_tools.soft_404([finding, real], signatures, {domains.page_of(ROOT): domains.page_of(reference)})
        self.assertEqual((kept, dropped), ([real], [finding]))

    def test_the_laravel_debugbar_echo_alone_split_the_pages(self):
        """The validation's case: without taking the paths out, the echo alone puts the two answers apart."""
        template = "Sorry the page you asked for is not here".split()
        mine, theirs = catch_all(template, "/_debugbar/open", [(3, 0)]), catch_all(template, "/pitangus-0123456789abcdef", [(3, 0)])
        self.assertFalse(web_tools.alike(web_tools.body_simhash(mine), web_tools.body_simhash(theirs)))
        echoes = ("/_debugbar/open", "/pitangus-0123456789abcdef")
        self.assertTrue(web_tools.alike(web_tools.body_simhash(mine, echoes), web_tools.body_simhash(theirs, echoes)))

    @settings(max_examples=150 * SCALE, deadline=None)
    @given(st.integers(0, 2**64 - 1), st.integers(0, 64), st.integers(0, 2**16))
    def test_a_few_bits_apart_is_the_same_page(self, page, noise, seed):
        """A nonce or a date flips a few bits of a page's simhash: up to SOFT_404_BITS it is the same page."""
        self.assertEqual(web_tools.alike(page, flip(page, noise, random.Random(seed))), noise <= web_tools.SOFT_404_BITS)

    @settings(max_examples=100 * SCALE, deadline=None)
    @given(st.lists(segments, min_size=1, max_size=6, unique=True), words, st.sampled_from([200, 301, 403]))
    def test_without_a_reference_or_with_a_different_answer_nothing_is_dropped(self, paths, template, status):
        findings = [nuclei_finding(f"/{path}") for path in paths]
        body = "<html>" + " ".join(template) + "</html>"
        signatures = {domains.page_of(item["path"]): (status, body, urlsplit(item["path"]).path) for item in findings}
        references = {domains.page_of(ROOT): f"{ROOT}pitangus-reference"}
        self.assertEqual(web_tools.soft_404(findings, signatures, {})[0], findings)   # httpx didn't run
        self.assertEqual(web_tools.soft_404(findings, signatures, references)[0], findings)   # nobody saw the reference
        signatures[f"{ROOT}pitangus-reference"] = (404, body, "/pitangus-reference")    # an honest 404: the paths answered something else
        self.assertEqual(web_tools.soft_404(findings, signatures, references)[0], findings)
        signatures[f"{ROOT}pitangus-reference"] = (status, None, "/pitangus-reference")   # httpx didn't say what the body was
        self.assertEqual(web_tools.soft_404(findings, signatures, references)[0], findings)

    def test_site_wide_and_root_findings_are_never_soft_404s(self):
        same = (200, "<html>one page</html>", "/x")
        signatures = {ROOT.rstrip("/"): same, f"{ROOT}x": same, f"https://{HOST}": same}
        findings = [nuclei_finding("/"), nuclei_finding("/x", "http-missing-security-headers:content-security-policy")]
        self.assertEqual(web_tools.soft_404(findings, signatures, {f"https://{HOST}/": f"{ROOT}x"})[0], findings)

    def test_the_laravel_debugbar_case_through_the_check(self):
        """The validation's false positive: a catch-all page carried the template's words on /_debugbar/open, and
        repeated the path it was asked for (8 to 22 bits from the random path's answer by the whole body's simhash)."""
        class CatchAll(evidence.FakeTools):
            def __call__(self, key, arguments, snapshot=None, *, mounts=None, **options):
                completed = super().__call__(key, arguments, snapshot, mounts=mounts, **options)
                if key == "nuclei":  # the debugbar template matched the catch-all page; nothing else did
                    line = json.dumps({"template-id": "laravel-debugbar-exposure", "info": {"name": "Laravel Debugbar", "severity": "medium"},
                                       "matched-at": f"{ROOT}_debugbar/open", "type": "http"})
                    return completed.__class__(completed.args, 0, line + "\n", completed.stderr)
                if key == "httpx" and f"{web_tools.WORK}/pages.txt" in arguments:
                    lines = [json.loads(line) for line in completed.stdout.splitlines()]
                    for line in lines:
                        path = urlsplit(line["input"]).path
                        line["status_code"] = 200
                        line["body"] = (f"<html><head><title>{path} - Not Found</title></head><body><h1>Whoops</h1><p>We looked for "
                                        f"{html.escape(path)} everywhere.</p><a href='{line['input']}'>retry</a> debugbar laravel</body></html>")
                    return completed.__class__(completed.args, 0, "".join(json.dumps(line) + "\n" for line in lines), "")
                return completed
        with tempfile.TemporaryDirectory() as folder:
            site = evidence.Site(set(), {"kind": "honest"})
            with patch.object(web_tools, "_run", side_effect=CatchAll(site)), \
                    patch.object(nuclei_templates, "ensure", return_value=(Path(folder), {"hosts": 1, "pages": 0})), \
                    patch.object(nuclei_templates, "ensure_own", return_value=(None, {"hosts": 0, "pages": 0})):
                record = web.scan_exposure({"host": HOST, "id": "d" * 24, "key": f"domain:{HOST}", "kind": "web", "url": ROOT}, evidence.PIN,
                                           data_dir=Path(folder), tools=dict.fromkeys(web_tools.TOOLS))
        self.assertEqual(record["findings"], [])
        self.assertEqual(record["status"], "completed")


class PagesTests(unittest.TestCase):
    @settings(max_examples=150 * SCALE, deadline=None)
    @given(st.lists(st.tuples(st.sampled_from(["https", "http"]), st.sampled_from(["/", "//", "///"]), st.lists(segments, max_size=3),
                              st.sampled_from(["", "/", "?q=1", "#top"])), max_size=30))
    def test_the_counter_is_the_number_of_distinct_pages(self, parts):
        """Earlier findings' pages, the roots and the known paths, written any way (a trailing slash, doubled
        slashes, a query): each page is checked and counted once."""
        recheck = [f"{scheme}://{HOST}{lead}{'/'.join(path)}{tail}" for scheme, lead, path, tail in parts]
        urls = web.exposure_pages([HOST], recheck)
        pages = [domains.page_of(url) for url in urls]
        self.assertEqual(len(pages), len(set(pages)))
        everything = {domains.page_of(url) for url in [ROOT, f"http://{HOST}/", *(f"{ROOT.rstrip('/')}{path}" for path in web.known_paths()), *recheck]}
        self.assertEqual(set(pages), everything)
        self.assertEqual(len(web.checked_pages(urls)), len(everything))

    def test_the_step_counts_what_it_checked_once(self):
        with tempfile.TemporaryDirectory() as folder:
            site = evidence.Site(set(), {"kind": "honest"})
            recheck = [f"{ROOT}.env", f"https://{HOST}//.env", f"{ROOT}old/", f"{ROOT}old", f"{ROOT}"]
            with patch.object(web_tools, "_run", side_effect=evidence.FakeTools(site)), \
                    patch.object(nuclei_templates, "ensure", return_value=(Path(folder), {"hosts": 1, "pages": 0})), \
                    patch.object(nuclei_templates, "ensure_own", return_value=(None, {"hosts": 0, "pages": 0})):
                record = web.scan_exposure({"host": HOST, "id": "d" * 24, "key": f"domain:{HOST}", "kind": "web", "url": ROOT}, evidence.PIN,
                                           data_dir=Path(folder), tools=dict.fromkeys(web_tools.TOOLS), recheck=recheck)
        detail = record["steps"][0]["detail"]
        self.assertEqual(detail["params"]["pages"], 2 + len(web.known_paths()) + 1)   # the roots, the known paths and /old
        self.assertEqual(detail["params"]["answered"], detail["params"]["pages"])

    def test_known_paths_include_what_the_docstring_promises_and_both_schemes_are_probed(self):
        paths = web.known_paths()
        for path in ("/.env", "/.git/config", "/actuator/env"):
            self.assertIn(path, paths)
        urls = web.exposure_pages([HOST])
        self.assertIn(f"http://{HOST}/", urls)
        self.assertIn(f"{ROOT}.git/config", urls)

    @settings(max_examples=150 * SCALE, deadline=None)
    @given(st.lists(segments, min_size=1, max_size=4), st.lists(st.integers(1, 3), min_size=5, max_size=5))
    def test_repeated_slashes_are_one_page_for_every_tool(self, path, slashes):
        """`//.env` is `/.env`: the tools send repeated slashes as one, so evidence and findings meet on one page."""
        plain = f"{ROOT}{'/'.join(path)}"
        doubled = f"https://{HOST}" + "".join("/" * count + part for count, part in zip(slashes, path))
        self.assertEqual(domains.page_of(doubled), domains.page_of(plain))
        self.assertEqual(web_tools.in_scope_url(doubled, [HOST]), web_tools.in_scope_url(plain, [HOST]))


class IdentityTests(unittest.TestCase):
    @settings(max_examples=200 * SCALE, deadline=None)
    @given(st.lists(segments, min_size=1, max_size=3, unique=True),
           st.lists(st.tuples(st.sampled_from(["nuclei", "zap"]), st.sampled_from(["git-config", "laravel-env", "10038", "other"]),
                              st.lists(segments, min_size=1, max_size=2)), max_size=12))
    def test_a_path_findings_identity_never_depends_on_other_rules_urls(self, paths, others):
        """Metamorphic: the identities of one rule's findings are the same whatever URLs other rules were seen on before
        (one-segment paths like `/.env` and `/.npmrc` included)."""
        findings = [{"fingerprint": f"f{index}", "scanner": "dast", "tool": "nuclei", "rule_id": "pitangus-sensitive-paths:dotenv",
                     "path": f"{ROOT}{path}", "line": 1, "severity": "high"} for index, path in enumerate(paths)]
        alone = sorted(item["fingerprint"] for item in canonical.collapse(findings))
        known = [(tool, rule, f"{ROOT}{'/'.join(parts)}") for tool, rule, parts in others]
        self.assertEqual(sorted(item["fingerprint"] for item in canonical.collapse(findings, known)), alone)

    @settings(max_examples=200 * SCALE, deadline=None)
    @given(st.lists(st.tuples(st.lists(segments, min_size=1, max_size=2).map(tuple), st.sampled_from(KINDS)), min_size=1, max_size=8, unique=True),
           st.lists(st.tuples(st.lists(segments, min_size=1, max_size=2), st.sampled_from(KINDS)), max_size=8))
    def test_a_family_is_of_one_kind_of_scan_and_its_identity_never_depends_on_another_kinds_urls(self, seen, before):
        """Only a scan of the kind that saw a finding can tell it is gone (registry.other_kind): the same rule on sibling
        pages seen by an anonymous crawl and behind a login (or in an API, or by an exposure check) are never one family,
        whatever URLs each kind saw before; and what one kind saw never shapes another kind's identities."""
        findings = [web_finding(f"{ROOT}{'/'.join(parts)}", kind, index) for index, (parts, kind) in enumerate(seen)]
        known = [("zap", "10038", f"{ROOT}{'/'.join(parts)}", kind) for parts, kind in before]
        families = canonical.collapse(findings, known)
        member = {finding["fingerprint"]: kind_of(finding) for finding in findings}
        for family in families:
            kinds = {member[name] for name in [*(family.get("previous_fingerprints") or []), family["fingerprint"]] if name in member}
            self.assertEqual(len(kinds | {kind_of(family)}), 1, family)
        for kind in KINDS:
            mine = [finding for finding in findings if kind_of(finding) == kind]
            alone = sorted(item["fingerprint"] for item in canonical.collapse(mine, [item for item in known if item[3] == kind]))
            self.assertEqual(sorted(item["fingerprint"] for item in canonical.collapse(mine, known)), alone, kind)

    def test_the_same_rules_earlier_urls_still_shape_its_template(self):
        first, second = f"{ROOT}assets/index-BkL9x2a1.js", f"{ROOT}assets/index-C0aZ77qp.js"
        finding = {"fingerprint": "a", "scanner": "dast", "tool": "zap", "rule_id": "10098", "path": first, "line": 1, "severity": "low"}
        (alone,) = canonical.collapse([finding])
        (shaped,) = canonical.collapse([finding], [("zap", "10098", second)])
        (foreign,) = canonical.collapse([finding], [("zap", "10038", second)])
        self.assertNotEqual(shaped["fingerprint"], alone["fingerprint"])
        self.assertEqual(foreign["fingerprint"], alone["fingerprint"])


class KindTests(unittest.TestCase):
    """An exposure check and a full scan look at different things: neither fixes, nor marks unseen, the other's."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)

    def save(self, kind: str, findings: list[dict], key: str = f"domain:{HOST}", looked: list[str] | None = None):
        """A web scan of `kind` that examined the pages `looked` (none unless given)."""
        from pitangus.modules.runs.store import save_repository_scan
        tools = [{"name": "ZAP", "status": "completed"}, {"name": "nuclei", "status": "completed"}]
        pages = [domains.page_of(url) for url in looked or []]
        return save_repository_scan(self.data_dir, {
            "type": "dast_scan", "status": "completed", "variant": kind, "target": ROOT, "context": "", "findings": findings,
            "source": domains.source_for({"host": HOST, "id": "d" * 24, "key": key, "kind": "web", "url": ROOT}),
            "scope": {"hosts": [HOST], "wildcards": [], "coverage": kind, "reached": pages, "probed": pages},
            "coverage": {"zap": {"examined": pages, "unexamined": {}}, "nuclei": {"examined": pages, "unexamined": {}}},
            "summary": {"files": 0, "dependencies": 0, "candidates": len(findings), "severities": {}, "priorities": {}, "kev": 0, "fixable": 0,
                        "tools": tools},
            "steps": [], "limitations": [], "owasp_coverage": []})

    def test_neither_kind_marks_the_others_findings_unseen(self):
        zap = {"finding_id": "z" * 16, "fingerprint": "z" * 64, "scanner": "dast", "tool": "ZAP", "rule_id": "10038", "title": "CSP",
               "path": f"{ROOT}about", "line": 1, "severity": "medium", "confidence": 7, "priority": {"action": "track", "factors": []},
               "reason": "", "remediation": "", "cwe": [], "owasp": [], "web": {"coverage": "baseline"}}
        exposed = {**zap, "finding_id": "e" * 16, "fingerprint": "e" * 64, "tool": "nuclei", "rule_id": "git-config", "path": f"{ROOT}.git/config",
                   "web": {"coverage": "exposure"}}
        with patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "on"}):
            self.save("baseline", [zap])
            self.save("exposure", [exposed])
            self.save("exposure", [exposed])
            self.save("baseline", [zap])
        entries = registry.load(self.data_dir, f"domain:{HOST}")["findings"]
        self.assertEqual({entry["finding"]["rule_id"]: (entry["status"], entry.get("unseen")) for entry in entries.values()},
                         {"10038": ("open", None), "git-config": ("open", None)})


    @settings(max_examples=40 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    @given(st.sets(st.tuples(st.sampled_from(["a", "admin", "b", "users/1", "users/2", "v1/users"]), st.sampled_from(KINDS)), min_size=1),
           st.lists(st.tuples(st.sampled_from(KINDS), st.sets(st.integers(0, 23))), min_size=1, max_size=6))
    @example(site={("a", "baseline"), ("admin", "baseline+headers")}, steps=[("baseline", set()), ("baseline+headers", set()), ("baseline", {0})])
    def test_a_scan_of_one_kind_never_fixes_nor_absorbs_what_only_another_kind_sees(self, site, steps):
        """With PITANGUS_COVERAGE_MODE=on and PITANGUS_IDENTITY_MODE=v2 (the defaults): whatever kinds of scan run and
        whatever disappears from the site, every page a scan of some kind reported and still has the problem is an open
        finding of that kind (never fixed by another kind's scan, never folded into another kind's family)."""
        self.examples = getattr(self, "examples", 0) + 1
        key = f"domain:{HOST}#{self.examples}"
        truth, reported = set(site), set()
        ordered = sorted(site)
        pages = [f"{ROOT}{path}" for path in ("a", "admin", "b", "users/1", "users/2", "v1/users")]   # each scan looks at every page
        for kind, removed in steps:
            truth -= {ordered[index] for index in removed if index < len(ordered)}
            with patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "on", "PITANGUS_IDENTITY_MODE": "v2"}):
                self.save(kind, [web_finding(f"{ROOT}{path}", seen, index) for index, (path, seen) in enumerate(sorted(truth)) if seen == kind],
                          key, pages)
            reported |= {(path, seen) for path, seen in truth if seen == kind}
            entries = registry.load(self.data_dir, key)["findings"].values()
            # By each page's key (shared/web_keys.py): the URL stored is rendered.
            by_key = {web_keys.key(page): page.removeprefix(ROOT) for page in pages}
            still = {(by_key.get(str(item.get("key") or item.get("web_key"))), kind_of(entry["finding"]))
                     for entry in entries if entry["status"] == "open" for item in entry["finding"].get("instances") or [entry["finding"]]}
            self.assertEqual(sorted((truth & reported) - still), [], (kind, sorted(truth)))


    def test_findings_stored_before_the_kind_was_part_of_the_identity_move_without_opening_or_fixing(self):
        """I7 for this formula change: a v2 family stored when the identity didn't name the kind of scan (an exposure
        check's, a header scan's) is found again by the engine fingerprint its members had; nothing opens, nothing is
        fixed, its triage follows it."""
        from pitangus.modules.findings import triage
        from pitangus.shared.code_identity import digest
        key = f"domain:{HOST}#formula"
        mode = patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": "v2"})
        mode.start()
        self.addCleanup(mode.stop)
        found = [web_finding(f"{ROOT}.git/config", "exposure", 0), web_finding(f"{ROOT}admin", "baseline+headers", 1)]
        before = [{**item, "identity": digest("web", "zap", "10038", item["path"], "")} for item in found]
        pages = [item["path"] for item in found]
        for item in before:
            self.save(item["web"]["coverage"], [item], key, pages)
        stored = registry.load(self.data_dir, key)["findings"]
        self.assertEqual(sorted(stored), sorted(item["identity"] for item in before))
        triage.decide(self.data_dir, registry.view(self.data_dir, key, status="all"), [before[0]["identity"]], "accepted",
                      reason="Served on purpose to the health checker", user={"username": "ana", "role": "admin"})
        for item in found:
            self.save(item["web"]["coverage"], [item], key, pages)
        entries = registry.load(self.data_dir, key)["findings"]
        self.assertEqual(len(entries), 2)
        self.assertEqual({entry["status"] for entry in entries.values()}, {"open"})
        self.assertTrue(set(entries).isdisjoint(stored))   # rekeyed to the identity that names the kind
        moved = next(digest for digest, entry in entries.items() if kind_of(entry["finding"]) == "exposure")
        self.assertEqual(triage.load_asset(self.data_dir, key)[moved]["status"], "accepted")


class WordingTests(unittest.TestCase):
    MENTIONS = re.compile(r"(?i)\bZAP\b|crawl|rastre|recorr|spider|araña")

    def test_nothing_the_exposure_check_says_mentions_zap_or_a_crawl(self):
        said = []
        with tempfile.TemporaryDirectory() as folder:
            site = evidence.Site(set(evidence.SENSITIVE), {"kind": "sprinkle", "share": 0.3, "seed": 7})
            with patch.object(web_tools, "_run", side_effect=evidence.FakeTools(site)), \
                    patch.object(nuclei_templates, "ensure", return_value=(Path(folder), {"hosts": 1, "pages": 0})), \
                    patch.object(nuclei_templates, "ensure_own", return_value=(None, {"hosts": 0, "pages": 0})):
                record = web.scan_exposure({"host": HOST, "id": "d" * 24, "key": f"domain:{HOST}", "kind": "web", "url": ROOT}, evidence.PIN,
                                           data_dir=Path(folder), tools=dict.fromkeys(web_tools.TOOLS),
                                           progress=lambda level, message: said.append(message))
        said += [step["detail"] for step in record["steps"]] + record["limitations"]
        said += [web.msg("runs.progress.web_target_exposure", host=HOST, address=evidence.PIN),
                 web.msg("scanning.web.exposure.errors.needs_docker"), web.msg("scanning.web.exposure.errors.unpinned")]
        for message in said:
            for locale in ("en", "es"):
                rendered = text(message, locale)
                with self.subTest(message=message.get(MARK), locale=locale):
                    self.assertIsNone(self.MENTIONS.search(rendered), rendered)


if __name__ == "__main__":
    unittest.main()
