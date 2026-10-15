"""A web finding is fixed only with evidence from the tool that owns it, on its page, in this run (engine_contract).

A fake site answers every request the web tools send, in the order they send them, from a behaviour Hypothesis
generates: an honest site, a rate limit on the sensitive paths only, a block that starts with nuclei's phase, a sliding
window of N requests every 30 seconds, refusals and server errors sprinkled at random, a WAF that answers one code
(406, 418, 999, 400…) to everything after N requests, a code on a few paths only, a challenge page served with 200, a
redirect to the login, a site that says 410 for what it removed, or several of those at once. The tools' outputs are
what nuclei, testssl.sh and httpx write for those answers (nuclei's stored responses as `URL status` lines, its trace
log, httpx's JSON lines with each body); nuclei's templates match a file's content, never a challenge or an error page. The
properties, over the exposure check and the registry's rules:

* only a status on the whitelist proves anything (a 2xx present, a 404 or a 410 absent): a finding about one path is
  proven gone only when nuclei got nothing but 404 or 410 for that path, in this run, on a host that didn't turn the run
  away; a challenge, a redirect or any other code never fixes;
* every status off the whitelist (redirects aside) counts toward the blocking check: a run the site turned away or
  rate-limited is never `completed`, so it fixes nothing;
* on an honest site, every finding that really went away (404 or 410) is proven gone (the rule isn't "never fix").

The three cases the 0.14 validation found first (429 on the sensitive paths only, 429 during nuclei's phase only, a
window of 20 requests every 30 seconds) gave `completed` with 9 false fixes; the next three (a WAF answering 406 after
30 requests, 418 on `/.env` and `/.git` only, a 200 JavaScript challenge) gave 10, 8 and 10. They are this test's
seeds."""

import json
import os
import random
import subprocess
import tempfile
import unittest
import zlib
from collections import deque
from pathlib import Path
from unittest.mock import patch

from hypothesis import HealthCheck, example, given, settings, strategies as st

from pitangus.modules.findings import registry
from pitangus.modules.scanning import engine_contract, nuclei_templates, web, web_tools
from pitangus.shared import web_keys

PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

HOST, PIN = "shop.example.com", "93.184.216.34"
ROOT = f"https://{HOST}/"
PATHS = web.known_paths()           # what nuclei's hosts pass asks for on each root, in this fake
SENSITIVE = PATHS[:9]               # the nine exposures the seeds start with
TICKS_PER_SECOND = web_tools.RATE  # the tools send at most RATE requests a second: one request, one tick
REFUSED = (401, 403, 500, 502, 503)
OFF_LIST = (400, 405, 406, 418, 451, 499, 520, 999)   # codes no blacklist named: refusals all the same
TESTSSL_SECONDS = 90               # how long testssl.sh keeps the run busy between nuclei and httpx
CHALLENGE = "<html><title>Just a moment...</title><script>solve({nonce})</script></html>"


def path_of(url: str) -> str:
    return "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"


class Site:
    """The fake target. `exposed`: the paths that serve a file (200 and its content); everything else answers 404 (410
    with `gone`). `behaviour` decides each answer from the tool, the URL and the tick (requests sent so far in the run);
    a `mix` applies its layers in order, each one over what the previous ones answered."""

    def __init__(self, exposed: set[str], behaviour: dict):
        self.exposed, self.behaviour, self.tick = exposed, behaviour, 0
        self.windows: dict[int, deque[int]] = {}
        self.random = random.Random(behaviour.get("seed", 0))
        self.log: list[tuple[str, str, int]] = []   # (tool, page, status) of every answer

    def truth(self, url: str) -> int:
        path = path_of(url)
        return 200 if path == "/" or path in self.exposed else 404

    def content(self, url: str, status: int) -> str:
        path = path_of(url)
        if status == 200:
            return "<html>home</html>" if path == "/" else f"SECRET{zlib.crc32(path.encode())}=value"
        return "" if 300 <= status < 400 else f"<html>error {status}</html>"

    def layer(self, index: int, behaviour: dict, tool: str, url: str, status: int, body: str) -> tuple[int, str]:
        kind, path = behaviour["kind"], path_of(url)
        if kind == "sensitive" and path in behaviour["paths"]:
            return 429, self.content(url, 429)
        if kind == "phase" and tool == behaviour["tool"]:
            return behaviour["status"], self.content(url, behaviour["status"])
        if kind == "window":
            window, seconds = self.windows.setdefault(index, deque()), behaviour["seconds"] * TICKS_PER_SECOND
            while window and window[0] <= self.tick - seconds:
                window.popleft()
            if len(window) >= behaviour["limit"]:
                return 429, self.content(url, 429)
            window.append(self.tick)
        elif kind == "sprinkle" and self.random.random() < behaviour["share"]:
            code = self.random.choice(REFUSED)
            return code, self.content(url, code)
        elif kind == "waf" and self.tick > behaviour["after"]:
            return behaviour["status"], self.content(url, behaviour["status"])
        elif kind == "codes" and any(path == item or path.startswith(item + "/") for item in behaviour["paths"]):
            return behaviour["status"], self.content(url, behaviour["status"])
        elif kind == "challenge" and (behaviour["scope"] == "all" or (behaviour["scope"] == "paths" and path != "/")
                                      or (behaviour["scope"] == "after" and self.tick > behaviour.get("after", 0))):
            return 200, CHALLENGE.format(nonce=self.random.getrandbits(32))
        elif kind == "redirect" and (path != "/" or behaviour["root"]):
            return behaviour["status"], ""
        elif kind == "gone" and status == 404:
            return 410, self.content(url, 410)
        elif kind == "split" and url.startswith("https://") and path != "/" and status == 200:   # exposed over plain HTTP only
            return 404, self.content(url, 404)
        return status, body

    def serve(self, tool: str, url: str) -> tuple[int, str]:
        self.tick += 1
        status = self.truth(url)
        answer = (status, self.content(url, status))
        for index, behaviour in enumerate(self.behaviour["layers"] if self.behaviour["kind"] == "mix" else [self.behaviour]):
            answer = self.layer(index, behaviour, tool, url, *answer)
        self.log.append((tool, web.domains.page_of(url) or url, answer[0]))
        return answer

    def answer(self, tool: str, url: str) -> int:
        return self.serve(tool, url)[0]


def fetched(url: str, arguments) -> str:
    """The URL httpx 1.12 really requests for `url`: without `-nfs` it asks for a plain HTTP URL over HTTPS first (on a
    host that serves both, that is the answer it keeps), as it does against a local site serving both schemes."""
    return url if "-nfs" in arguments or not url.startswith("http://") else "https://" + url.removeprefix("http://")


class FakeTools:
    """`web_tools._run` for nuclei, testssl.sh and httpx against a `Site`, writing what each writes."""

    def __init__(self, site: Site):
        self.site = site

    def __call__(self, key, arguments, snapshot=None, *, mounts=None, **options):
        work = Path(mounts[mounts.index("-v") + 1].split(":")[0])
        if key == "nuclei":
            targets = (work / "targets.txt").read_text().split()
            asked = [url for target in targets for url in [target, *(target.rstrip("/") + path for path in PATHS)]]
            statuses, matches = [], []
            for url in asked:
                status, body = self.site.serve("nuclei", url)
                statuses.append(f"{url} {status}\n")
                if status == 200 and body.startswith("SECRET"):  # an exposed file, served: the template matches its content
                    matches.append(json.dumps({"template-id": f"t{url.rsplit('/', 1)[-1]}", "info": {"name": "exposed", "severity": "high"},
                                               "matched-at": url, "type": "http"}) + "\n")
            (work / web_tools.NUCLEI_STATUSES).write_text("".join(statuses))
            (work / web_tools.NUCLEI_TRACE).write_text("".join(json.dumps({"input": url, "error": "none"}) + "\n" for url in asked))
            return subprocess.CompletedProcess(arguments, 0, "".join(matches), json.dumps({"requests": str(len(asked)), "total": str(len(asked))}))
        if key == "testssl":
            self.site.tick += TESTSSL_SECONDS * TICKS_PER_SECOND  # its TLS handshakes take minutes, and no HTTP status
            report = arguments[arguments.index("--jsonfile") + 1].rsplit("/", 1)[-1]
            (work / report).write_text(json.dumps([{"id": "scanTime", "severity": "INFO", "finding": "12"}]))
            return subprocess.CompletedProcess(arguments, 0, "", "")
        if key == "httpx":
            listed = "pages.txt" if f"{web_tools.WORK}/pages.txt" in arguments else "hosts.txt"
            lines = []
            for url in (work / listed).read_text().split():
                requested = fetched(url, arguments)
                status, body = self.site.serve("httpx", requested)
                lines.append(json.dumps({"input": url, "url": requested, "host": HOST, "status_code": status, "tech": [],
                                         "scheme": requested.split(":", 1)[0], "raw_header": f"HTTP/1.1 {status}\r\n\r\n",
                                         **({"body": body} if body else {})}) + "\n")
            return subprocess.CompletedProcess(arguments, 0, "".join(lines), "")
        raise AssertionError(f"unexpected tool {key}")


def exposure_check(site: Site, directory: Path) -> dict:
    with patch.object(web_tools, "_run", side_effect=FakeTools(site)), \
            patch.object(nuclei_templates, "ensure", return_value=(directory, {"hosts": 1, "pages": 0})), \
            patch.object(nuclei_templates, "ensure_own", return_value=(None, {"hosts": 0, "pages": 0})):
        return web.scan_exposure({"host": HOST, "id": "d" * 24, "key": f"domain:{HOST}", "kind": "web", "url": ROOT}, PIN,
                                 data_dir=directory, tools=dict.fromkeys(web_tools.TOOLS))


def earlier(path: str, scheme: str = "https") -> dict:
    """A nuclei finding an earlier exposure check stored at `path`."""
    url = f"{scheme}://{HOST}{path}"
    return {"fingerprint": f"nuclei:{url}", "scanner": "dast", "tool": "nuclei", "rule_id": f"t{path.rsplit('/', 1)[-1]}", "path": url,
            "web": {"coverage": "exposure"}}


def absent_answers(site: Site, tool: str, page: str) -> bool:
    """Whether `tool` got answers for `page` and every one of them said the path is gone (404 or 410)."""
    answers = [status for who, where, status in site.log if who == tool and where == page]
    return bool(answers) and all(engine_contract.absent(status) for status in answers)


layers = st.one_of(
    st.fixed_dictionaries({"kind": st.just("sensitive"), "paths": st.sets(st.sampled_from(PATHS), min_size=1, max_size=12)}),
    st.fixed_dictionaries({"kind": st.just("phase"), "tool": st.sampled_from(["nuclei", "httpx"]),
                           "status": st.sampled_from([403, 429, 503, *OFF_LIST])}),
    st.fixed_dictionaries({"kind": st.just("window"), "limit": st.integers(5, 400), "seconds": st.integers(5, 60)}),
    st.fixed_dictionaries({"kind": st.just("sprinkle"), "share": st.floats(0.01, 0.5), "seed": st.integers(0, 2**16)}),
    st.fixed_dictionaries({"kind": st.just("waf"), "after": st.integers(0, 120), "status": st.sampled_from([403, 429, *OFF_LIST])}),
    st.fixed_dictionaries({"kind": st.just("codes"), "paths": st.sets(st.sampled_from(["/.env", "/.git", "/.aws", "/actuator", *SENSITIVE]),
                                                                      min_size=1, max_size=6),
                           "status": st.sampled_from(OFF_LIST)}),
    st.fixed_dictionaries({"kind": st.just("challenge"), "scope": st.sampled_from(["all", "paths", "after"]), "after": st.integers(0, 120),
                           "seed": st.integers(0, 2**16)}),
    st.fixed_dictionaries({"kind": st.just("redirect"), "status": st.sampled_from([301, 302, 303, 307, 308]), "root": st.booleans()}),
    st.just({"kind": "gone"}),
)
behaviours = st.one_of(st.just({"kind": "honest"}), layers,
                       st.lists(layers, min_size=2, max_size=4).map(lambda items: {"kind": "mix", "layers": items}))
SEEDS = [{"kind": "sensitive", "paths": set(SENSITIVE)}, {"kind": "phase", "tool": "nuclei", "status": 429},
         {"kind": "window", "limit": 20, "seconds": 30}]
# The second round: a WAF that answers 406 once it counted 30 requests, a teapot on the dotfiles, a JavaScript challenge.
WHITELIST_SEEDS = [{"kind": "waf", "after": 30, "status": 406}, {"kind": "codes", "paths": ["/.env", "/.git"], "status": 418},
                   {"kind": "challenge", "scope": "all", "seed": 1}]


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)

    def run_check(self, exposed: set[str], behaviour: dict) -> tuple[Site, dict]:
        site = Site(exposed, behaviour)
        return site, exposure_check(site, self.data_dir)

    @settings(max_examples=60 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(behaviour=behaviours, fixed=st.sets(st.sampled_from(SENSITIVE)), plain=st.booleans())
    @example(behaviour=SEEDS[0], fixed=set(), plain=False)
    @example(behaviour=SEEDS[1], fixed=set(), plain=False)
    @example(behaviour=SEEDS[2], fixed=set(), plain=False)
    @example(behaviour=WHITELIST_SEEDS[0], fixed=set(), plain=False)
    @example(behaviour=WHITELIST_SEEDS[1], fixed=set(), plain=True)
    @example(behaviour=WHITELIST_SEEDS[2], fixed=set(), plain=False)
    @example(behaviour={"kind": "mix", "layers": [WHITELIST_SEEDS[2], {"kind": "gone"}]}, fixed=set(SENSITIVE[:4]), plain=False)
    @example(behaviour={"kind": "redirect", "status": 301, "root": True}, fixed=set(SENSITIVE), plain=True)
    def test_a_finding_is_proven_gone_only_by_its_own_tools_absent_answer(self, behaviour, fixed, plain):
        """Nine exposures stored before; `fixed` of them really went away. Whatever the site does, a finding proven
        gone had nothing but 404 or 410 from nuclei on its page; one still exposed is never proven gone; and every
        status off the whitelist counts toward the blocking check."""
        site, record = self.run_check(set(SENSITIVE) - fixed, behaviour)
        reported = {finding["path"] for finding in record["findings"]}
        for path in SENSITIVE:
            finding = earlier(path, "http" if plain else "https")
            if finding["path"] in reported:
                continue
            if registry.unproven_reason(record, finding) is None:
                self.assertEqual(record["status"], "completed")
                self.assertIn(path, fixed, f"{path}: still exposed, proven gone")
                self.assertTrue(absent_answers(site, "nuclei", web.domains.page_of(finding["path"])), path)
        detail = record["steps"][0]["detail"]["params"]
        self.assertLessEqual(detail["answered"], detail["pages"])
        statuses = [status for _, _, status in site.log]
        limited = statuses.count(429)
        refusals = sum(map(engine_contract.refused, statuses))
        if (limited and limited >= engine_contract.RATE_LIMIT_SHARE * len(statuses)) or (refusals and refusals >= engine_contract.BLOCK_SHARE * len(statuses)):
            self.assertEqual(record["status"], "incomplete", "a run the site refused or rate-limited fixes nothing")
        if behaviour["kind"] in ("honest", "gone"):
            self.assertEqual(record["status"], "completed")
            for path in fixed:
                self.assertIsNone(registry.unproven_reason(record, earlier(path, "http" if plain else "https")), path)

    def test_the_three_validation_cases_are_incomplete_and_fix_nothing(self):
        for behaviour in SEEDS:
            with self.subTest(behaviour=behaviour["kind"]):
                _, record = self.run_check(set(SENSITIVE), behaviour)
                self.assertEqual(record["status"], "incomplete")
                proven = [path for path in SENSITIVE if registry.unproven_reason(record, earlier(path)) is None]
                self.assertEqual(proven, [])
                self.assertIn("scanning.web.limitations.blocked", json.dumps(record["limitations"]))

    def test_the_whitelist_cases_fix_nothing(self):
        """A WAF answering 406 after 30 requests, 418 on the dotfiles only, a 200 challenge on every path: none of the
        nine exposures is proven gone, whether or not the run ends up blocked."""
        for behaviour in WHITELIST_SEEDS:
            for plain in (False, True):
                with self.subTest(behaviour=behaviour["kind"], plain=plain):
                    _, record = self.run_check(set(SENSITIVE), behaviour)
                    proven = [path for path in SENSITIVE if registry.unproven_reason(record, earlier(path, "http" if plain else "https")) is None]
                    self.assertEqual(proven, [])

    def test_a_redirect_proves_nothing_and_isnt_a_block(self):
        """Every path redirected to the login: nothing about the files is proven, and the run isn't blocked by it."""
        _, record = self.run_check(set(), {"kind": "redirect", "status": 302, "root": False})
        self.assertEqual(record["status"], "completed")
        self.assertEqual([path for path in SENSITIVE if registry.unproven_reason(record, earlier(path)) is None], [])
        page = web.domains.page_of(f"{ROOT.rstrip('/')}{SENSITIVE[0]}")
        self.assertEqual(record["coverage"]["nuclei"]["unexamined"][page], "http_302")

    def test_a_path_that_still_answers_isnt_proven_gone(self):
        """The template stopped matching but the path still serves a page (another file, a challenge, a catch-all): only
        a 404 or a 410 proves it gone. The root's 2xx still vouches for what is about the root."""
        _, record = self.run_check(set(), {"kind": "challenge", "scope": "paths", "seed": 3})
        page = web.domains.page_of(f"{ROOT.rstrip('/')}{SENSITIVE[0]}")
        self.assertEqual(record["coverage"]["nuclei"]["unexamined"][page], "present")
        self.assertIn(web.domains.page_of(ROOT), record["coverage"]["nuclei"]["examined"])

    def test_another_tools_answer_never_vouches_for_nucleis_finding(self):
        """nuclei got 429 on a sensitive path; httpx, later, got 404 there: the finding stays, whatever httpx saw."""
        site, record = self.run_check(set(), {"kind": "phase", "tool": "nuclei", "status": 429})
        page = web.domains.page_of(f"{ROOT.rstrip('/')}{SENSITIVE[0]}")
        self.assertIn(("httpx", page, 404), site.log)
        self.assertNotIn(page, record["coverage"]["nuclei"]["examined"])
        self.assertEqual(record["coverage"]["nuclei"]["unexamined"][page], "blocked")


class SchemeTests(unittest.TestCase):
    """What is asked for over plain HTTP is asked for over plain HTTP: every URL with its own scheme, each answer
    attributed to the exact URL it came from, and nothing counted as answered that wasn't asked for."""

    @settings(max_examples=100 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(st.lists(st.tuples(st.sampled_from(["http", "https"]), st.sampled_from(["/", *PATHS[:12], "/a%20b", "/caf%C3%A9"])),
                    min_size=1, max_size=20, unique=True),
           st.dictionaries(st.tuples(st.sampled_from(["http", "https"]), st.sampled_from(["/", *PATHS[:12], "/a%20b", "/caf%C3%A9"])),
                           st.sampled_from([200, 204, 301, 403, 404, 410, 418, 503])))
    def test_each_url_is_requested_with_its_scheme_and_answers_for_itself(self, urls, codes):
        requested: list[tuple[str, str]] = []

        class Split(FakeTools):
            def __call__(self, key, arguments, snapshot=None, *, mounts=None, **options):
                work = Path(mounts[mounts.index("-v") + 1].split(":")[0])
                if f"{web_tools.WORK}/pages.txt" in arguments:
                    requested.extend((url, fetched(url, arguments)) for url in (work / "pages.txt").read_text().split())
                return super().__call__(key, arguments, snapshot, mounts=mounts, **options)

        class Site2(Site):
            def truth(self, url):
                scheme, rest = url.split("://", 1)
                return codes.get((scheme, path_of(url)), 404 if rest.split("/", 1)[-1] else 200)

        site = Site2(set(), {"kind": "honest"})
        pages = [f"{scheme}://{HOST}{path}" for scheme, path in urls]
        with tempfile.TemporaryDirectory() as folder, patch.object(web_tools, "_run", side_effect=Split(site)):
            run, _ = web_tools.run_httpx([HOST], {HOST: PIN}, Path(folder), pages=pages, http=True)
        self.assertTrue(requested)
        for asked, got in requested:
            self.assertEqual(asked.split("://")[0], got.split("://")[0], "requested over another scheme")
        wanted = {web.domains.page_of(url) for url in [ROOT, *pages] if web_tools.in_scope_url(url, [HOST], http=True)}
        self.assertLessEqual(set(run.pages), wanted, "answered more than was asked")
        for page, statuses in run.pages.items():
            self.assertEqual(statuses, [site.truth(page if page.count("/") >= 3 else page + "/")], page)

    def test_an_answer_for_another_scheme_is_nobodys(self):
        """httpx without `-nfs` hands back, for a plain HTTP input, the HTTPS answer: it isn't the page's."""
        line = json.dumps({"input": f"http://{HOST}/.env", "url": f"https://{HOST}/.env", "status_code": 404})
        self.assertEqual(web_tools.httpx_statuses(line, [HOST], http=True), {})
        self.assertIn("-nfs", web_tools.httpx_status_arguments([PIN]))

    def test_the_split_site_opens_its_plain_http_exposures(self):
        """The validation's `split` site: `.env` served over plain HTTP only. nuclei matched it five times and the check
        opened nothing (httpx read the HTTPS 404 for the plain HTTP URL, so the finding looked like a soft 404)."""
        with tempfile.TemporaryDirectory() as folder:
            site = Site({"/.env", "/.git/config", "/.aws/credentials", "/.npmrc", "/.htpasswd"}, {"kind": "split"})
            record = exposure_check(site, Path(folder))
        opened = sorted(finding["path"] for finding in record["findings"])
        self.assertEqual(opened, sorted(f"http://{HOST}{path}" for path in ("/.env", "/.git/config", "/.aws/credentials", "/.npmrc", "/.htpasswd")))
        self.assertEqual(record["status"], "completed")


class RegistryTests(unittest.TestCase):
    """The same seeds through the registry, as the worker saves them: nothing is fixed, in either coverage mode."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name)

    def save(self, exposed: set[str], behaviour: dict) -> dict:
        from pitangus.modules.runs.store import save_repository_scan
        return save_repository_scan(self.data_dir, exposure_check(Site(exposed, behaviour), self.data_dir))

    def states(self) -> dict[str, str]:
        entries = registry.load(self.data_dir, f"domain:{HOST}")["findings"].values()
        return {entry["finding"]["web_key"]: entry["status"] for entry in entries}   # the URL stored is rendered

    def test_a_blocked_run_fixes_none_of_the_nine_and_an_honest_one_fixes_them_all(self):
        for mode in ("on", "shadow"):
            with self.subTest(mode=mode), patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": mode, "PITANGUS_FIX_HOLD_MINIMUM": "1000"}):
                registry.reset(self.data_dir)
                self.save(set(SENSITIVE), {"kind": "honest"})
                opened = self.states()
                self.assertEqual(sorted(opened), sorted(web_keys.key(f"{scheme}://{HOST}{path}") for path in SENSITIVE for scheme in ("http", "https")))
                for behaviour in [*SEEDS, *WHITELIST_SEEDS]:
                    self.save(set(SENSITIVE), behaviour)
                    self.assertEqual(self.states(), opened, behaviour["kind"])
                self.save(set(), {"kind": "honest"})  # the site really removed them, and answered honestly
                self.assertEqual(set(self.states().values()), {"fixed"})

    def test_a_site_that_says_gone_fixes_them(self):
        with patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "on", "PITANGUS_FIX_HOLD_MINIMUM": "1000"}):
            registry.reset(self.data_dir)
            self.save(set(SENSITIVE), {"kind": "honest"})
            self.save(set(), {"kind": "challenge", "scope": "paths", "seed": 5})   # removed, but a challenge answers there
            self.assertEqual(set(self.states().values()), {"open"})
            self.save(set(), {"kind": "gone"})
            self.assertEqual(set(self.states().values()), {"fixed"})


OUTPUTS = Path(__file__).resolve().parent / "engine-outputs"
EDGE = "edge.pitangus.test"   # the throwaway local site the fixtures were recorded on (test_web_tools)
# What a tool that didn't finish hands back: killed halfway (137, what it wrote so far), out of time (the container is
# removed, the partial output comes with the exception), output cut short (exit 0), or an error exit with its full output.
UNFINISHED = ("killed", "timeout", "truncated", "exit-1")


def _cut(text: str) -> str:
    return text[: max(1, len(text) * 2 // 3)]


class UnfinishedTool:
    """`_run` for one web tool that writes everything a finished run writes, then fails the way `failure` says."""

    def __init__(self, key: str, failure: str):
        self.key, self.failure = key, failure

    def outputs(self, work: Path, arguments) -> tuple[str, str]:
        if self.key == "nuclei":
            full = (OUTPUTS / "nuclei-3.11-edge.jsonl").read_text()
            (work / web_tools.NUCLEI_STATUSES).write_text("".join(f"https://{EDGE}{path} 404\n" for path in ("/", *PATHS)))
            (work / web_tools.NUCLEI_TRACE).write_text("")
            return full, (OUTPUTS / "nuclei-3.11-stats.log").read_text()
        if self.key == "testssl":
            report = work / arguments[arguments.index("--jsonfile") + 1].rsplit("/", 1)[-1]
            text = (OUTPUTS / "testssl-3.2-edge.json").read_text()
            report.write_text(_cut(text) if self.failure in ("killed", "truncated") else text)
            return "", ""
        if self.key == "httpx":
            listed = "pages.txt" if f"{web_tools.WORK}/pages.txt" in arguments else "hosts.txt"
            if listed == "hosts.txt":
                return (OUTPUTS / "httpx-1.12.jsonl").read_text().replace("pitangus.dev", EDGE), ""
            return "".join(json.dumps({"input": url, "url": url, "status_code": 200}) + "\n" for url in (work / listed).read_text().split()), ""
        if self.key == "katana":
            return (OUTPUTS / "katana-1.7-edge.jsonl").read_text(), ""
        raise AssertionError(self.key)

    def __call__(self, key, arguments, snapshot=None, *, mounts=None, **options):
        work = Path(mounts[mounts.index("-v") + 1].split(":")[0])
        stdout, stderr = self.outputs(work, arguments)
        if self.failure == "timeout":
            raise subprocess.TimeoutExpired([key], 60, output=_cut(stdout).encode(), stderr=stderr.encode())
        if self.failure == "killed":
            return subprocess.CompletedProcess(arguments, 137, _cut(stdout), stderr)
        if self.failure == "truncated":
            return subprocess.CompletedProcess(arguments, 0, _cut(stdout), stderr)
        return subprocess.CompletedProcess(arguments, 1, stdout, stderr)


WEB_ADAPTERS = {
    "katana": lambda root: (web_tools.run_katana([f"https://{EDGE}/"], [EDGE], {EDGE: PIN}, root, headless=False)[0], []),
    "nuclei": lambda root: web_tools.run_nuclei([f"https://{EDGE}/"], [], [EDGE], {EDGE: PIN}, root, root),
    "testssl": lambda root: (web_tools.run_testssl([EDGE], {EDGE: PIN}, root), []),
    "httpx": lambda root: web_tools.run_httpx([EDGE], {EDGE: PIN}, root, pages=[f"https://{EDGE}/a"]),
}


class UnfinishedToolTests(unittest.TestCase):
    """A3: a web tool that didn't finish neither opens nor closes anything, whichever way it failed."""

    def check(self, key: str, failure: str):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"PITANGUS_COVERAGE_MODE": "on"}), \
                patch.object(web_tools, "_run", side_effect=UnfinishedTool(key, failure)), \
                patch.object(nuclei_templates, "ensure", return_value=(Path(folder), {"hosts": 1, "pages": 0})), \
                patch.object(nuclei_templates, "ensure_own", return_value=(None, {"hosts": 0, "pages": 0})):
            run, detected = WEB_ADAPTERS[key](Path(folder))
        self.assertNotEqual(run.status, "completed")
        self.assertEqual(run.findings, [], "it opened findings")
        self.assertEqual(run.coverage()["examined"], [], "it proved something gone")
        self.assertEqual(detected, [], "its technologies would open version findings")
        self.assertEqual(run.roots, [])

    def test_every_web_adapter_and_every_way_it_can_stop(self):
        for key in WEB_ADAPTERS:
            for failure in UNFINISHED:
                with self.subTest(adapter=key, failure=failure):
                    self.check(key, failure)

    def test_each_adapter_opens_and_proves_when_it_does_finish(self):
        """The same outputs from a run that finished do open and prove: the failure, not the fixture, closes the door."""
        class Finished(UnfinishedTool):
            def __call__(self, key, arguments, snapshot=None, *, mounts=None, **options):
                work = Path(mounts[mounts.index("-v") + 1].split(":")[0])
                return subprocess.CompletedProcess(arguments, 0, *self.outputs(work, arguments))
        for key in ("nuclei", "testssl", "httpx"):
            with self.subTest(adapter=key), tempfile.TemporaryDirectory() as folder, \
                    patch.object(web_tools, "_run", side_effect=Finished(key, "")), \
                    patch.object(nuclei_templates, "ensure", return_value=(Path(folder), {"hosts": 1, "pages": 0})), \
                    patch.object(nuclei_templates, "ensure_own", return_value=(None, {"hosts": 0, "pages": 0})):
                run, detected = WEB_ADAPTERS[key](Path(folder))
                self.assertEqual(run.status, "completed")
                self.assertTrue(run.coverage()["examined"])
                self.assertTrue(run.findings or detected)

    def test_zap_that_didnt_finish_opens_nothing_and_proves_nothing(self):
        report = (OUTPUTS / "zap-2.17.sarif").read_text()
        tree = [{"node": "Sites", "children": [{"node": "GET:/", "url": "https://pitangus.dev/", "statusCode": 200}]}]
        for failure in UNFINISHED:
            def zap(key, command, snapshot=None, *, mounts=None, failure=failure, **options):
                work = Path(mounts[mounts.index("-v") + 1].split(":")[0])
                (work / web.REPORT).write_text(_cut(report) if failure == "truncated" else report)
                (work / web.TREE).write_text(json.dumps(tree))
                if failure == "timeout":
                    raise subprocess.TimeoutExpired([key], 60)
                return subprocess.CompletedProcess(command, 137 if failure == "killed" else 1 if failure == "exit-1" else 0, "", "")
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as folder, patch.object(web, "_run", side_effect=zap):
                try:
                    result = web.scan_domain({"host": "pitangus.dev", "url": "https://pitangus.dev/", "id": "a" * 24, "kind": "web",
                                              "key": "domain:pitangus.dev"}, "172.67.153.40", data_dir=Path(folder))
                except web.WebScanError:
                    continue  # no run at all: nothing opened, nothing fixed
                self.assertEqual([item for item in result["findings"] if item["tool"].lower() == "zap"], [])
                self.assertEqual(result["coverage"]["zap"]["examined"], [])
                self.assertEqual(result["status"], "incomplete")


class ContractTests(unittest.TestCase):
    """The rule itself, for any engine that reads URLs."""

    @settings(max_examples=200 * SCALE, deadline=None)
    @given(st.dictionaries(st.sampled_from([ROOT, *(f"{ROOT}{index}" for index in range(8))]),
                           st.lists(st.sampled_from([200, 204, 301, 302, 400, 401, 403, 404, 406, 407, 410, 418, 429, 500, 503, 599, 999]),
                                    max_size=5)),
           st.sets(st.sampled_from([f"{ROOT}{index}" for index in range(8)])), st.booleans())
    def test_a_page_is_examined_only_when_every_answer_proved_something(self, answers, failed, paths):
        """By default a page is examined only with answers on the whitelist (2xx, 404, 410); with `paths=absent`, a
        page other than the root only with 404 or 410."""
        coverage = engine_contract.http_coverage(answers, failed=failed, paths=engine_contract.absent if paths else None)
        for page in coverage["examined"]:
            self.assertTrue(answers[page] and page not in failed)
            self.assertTrue(all(engine_contract.proves(status) for status in answers[page]))
            if paths and page != ROOT:
                self.assertTrue(all(engine_contract.absent(status) for status in answers[page]))
        self.assertFalse(set(coverage["examined"]) & set(coverage["unexamined"]))
        self.assertLessEqual(set(coverage["unexamined"]), set(answers) | failed)
        blocked = engine_contract.http_coverage(answers, failed=failed, blocked=[HOST])
        self.assertEqual(blocked["examined"], [])

    @settings(max_examples=200 * SCALE, deadline=None)
    @given(st.dictionaries(st.sampled_from(["zap", "katana", "nuclei", "httpx"]),
                           st.lists(st.sampled_from([200, 404, 410, 301, 403, 406, 418, 429, 503, 999]), max_size=40)))
    def test_blocking_is_read_from_every_tools_answers_and_any_one_phase(self, statuses):
        answers = {tool: [(HOST, status) for status in items] for tool, items in statuses.items()}
        blocked = engine_contract.blocked_hosts(answers) == [HOST]
        everything = [status for items in statuses.values() for status in items]
        groups = [everything, *(items for items in statuses.values() if len(items) >= engine_contract.ENGINE_ANSWERS_MIN)]
        dominated = any(items and sum(map(engine_contract.refused, items)) >= engine_contract.BLOCK_SHARE * len(items) for items in groups)
        limited = any(items and items.count(429) >= engine_contract.RATE_LIMIT_SHARE * len(items) and 429 in items for items in groups)
        self.assertEqual(blocked, dominated or limited)

    @given(st.one_of(st.integers(-5, 1200), st.none(), st.booleans(), st.text(max_size=3)))
    def test_only_the_whitelist_proves_and_everything_else_but_a_redirect_is_a_refusal(self, status):
        """2xx present, 404 and 410 absent; 3xx neither, and not a refusal; anything else a refusal."""
        code = status if isinstance(status, int) and not isinstance(status, bool) else None
        self.assertEqual(engine_contract.present(status), code is not None and 200 <= code < 300)
        self.assertEqual(engine_contract.absent(status), code in (404, 410))
        self.assertEqual(engine_contract.refused(status), not (code is not None and (200 <= code < 400 or code in (404, 410))))
        self.assertEqual(sum([engine_contract.present(status), engine_contract.absent(status), engine_contract.redirect(status),
                              engine_contract.refused(status)]), 1)

    def test_the_codes_a_blacklist_missed_are_refusals(self):
        for status in (400, 401, 403, 405, 406, 407, 418, 429, 451, 500, 502, 503, 599, 999, 99, None, True, "200"):
            self.assertTrue(engine_contract.refused(status), status)
        for status in (200, 204, 301, 302, 304, 404, 410):
            self.assertFalse(engine_contract.refused(status), status)

if __name__ == "__main__":
    unittest.main()
