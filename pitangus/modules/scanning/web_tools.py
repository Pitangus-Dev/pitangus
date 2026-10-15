"""The passive web scan's other tools, around ZAP: katana crawls first, nuclei runs detection-only templates, testssl.sh
reads each host's TLS and httpx names the technologies. None of them attacks.

Each runs in its own container through `engines._run`, hardened like every engine (no capabilities, no privilege
escalation, read-only root, our own uid, memory, CPU and process caps, a hard timeout) and reaching only the scan's
verified hosts:

* every host of the scope is pinned to the address checked right before the scan (`--add-host`) and the container's
  DNS server is its own loopback, where nothing answers;
* ProjectDiscovery's tools carry their own resolver, which would ask public DNS servers directly: they get a resolver
  list with that dead loopback only (`-r`), so a name outside the scope never resolves. The hosts file still answers
  for the pinned names;
* katana's crawl scope is the scope's hosts (`-cs`), it follows no redirect by itself (a `Location` is a link like any
  other, inside the scope or not followed) and skips private addresses; its browser sends everything outside the
  scope to a proxy that doesn't exist. nuclei follows no redirect and refuses private and local addresses (`-lna`).
  httpx probes only the pinned addresses (`-allow`). testssl.sh connects to the pinned address (`--ip`) and makes no
  DNS lookup (`--nodns none`) nor any other call (no `--phone-out`).

What ZAP's sign-in does stays ZAP's: these tools run anonymously, and katana and nuclei add the domain's saved
headers only when the scan asked for them. Those headers reach the container on its standard input and are written
in its memory-only /tmp, never in a file on the host, the command line or the logs; whatever comes back is scrubbed.

Rate: katana and nuclei send at most `RATE` requests a second, httpx `RATE` too, testssl.sh one host at a time.
Time: see `BUDGET`.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
import subprocess
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from collections import Counter
from collections.abc import Iterable, Sequence
from typing import Any
from urllib.parse import unquote, urlsplit

from pitangus.modules.scanning import engine_contract, nuclei_templates
from pitangus.modules.scanning.engine_contract import Contract
from pitangus.modules.scanning.web_identity import identity_path, remember_former, root_of, site_level
from pitangus.modules.scanning.engines import IMAGES, _base, _run, _stable, docker_problem, host_path, image_available, runner
from pitangus.modules.sources.domains import page_of
from pitangus.shared.i18n import inline, msg
from pitangus.shared.model import Finding, Message

TOOLS = ("katana", "nuclei", "testssl", "httpx")
RATE = 10
WORK = "/work"
RESOLVERS = "resolvers.txt"
DEAD_RESOLVER = "127.0.0.1:53"
HEADERS_FILE = "/tmp/pitangus-headers.txt"
OUTPUT_MAX = 20_000_000
URL_MAX = 2000

KATANA_MINUTES = 2
KATANA_TIMEOUT = 4 * 60
KATANA_DEPTH = 3
KATANA_RETRY_SECONDS = 60   # a browser crawl that found nothing this fast didn't start: crawl again without it
NUCLEI = Contract("nuclei", frozenset({0}), (dict,))
KATANA = Contract("katana", frozenset({0}), (dict,))
HTTPX = Contract("httpx", frozenset({0}), (dict,))
NUCLEI_TRACE = "trace.jsonl"  # nuclei's log of every request it sent and whether it got an answer (-tlog)
# Every response nuclei got (-sresp), kept in the container's memory-only /tmp: the requests carry the saved headers.
# Before the container ends, a line per response (its URL and status) is copied to the work folder, nothing else.
NUCLEI_STORE = "/tmp/nuclei-responses"
NUCLEI_STATUSES = "statuses.txt"
NUCLEI_STATUS_AWK = r'/^\[[^]]*\] Dumped HTTP response /{u=$NF; next} u!="" && /^HTTP\/[0-9.]+ [0-9][0-9][0-9]/{print u, $2; u=""}'
SLASHES = re.compile(r"/{2,}")
ANSWERS_MAX = 200_000    # answers kept per tool for the run's blocking check
INVENTORY_MAX = 500      # URLs kept from the crawl (stored with the run)
ZAP_SEEDS_MAX = 200      # of those, handed to ZAP
PAGES_MAX = 100          # of those, read by nuclei's page-level templates (pages, not scripts, styles or images)
ASSET = re.compile(r"(?i)\.(?:js|mjs|css|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|eot|mp4|webm|mp3|pdf|zip|gz)$")

NUCLEI_HOST_MINUTES = 10
NUCLEI_MINUTES_PER_HOST = 4   # each host after the first adds to the hosts pass, up to NUCLEI_HOST_MINUTES_MAX
NUCLEI_HOST_MINUTES_MAX = 30
NUCLEI_PAGE_MINUTES = 3
NUCLEI_STATS_SECONDS = 3600   # its statistics at the end only: the last line says what it sent
# What nuclei logs on stderr (not with -silent) when it gives up on a target or a template can't run; it still exits 0.
NUCLEI_SKIPPED = re.compile(r"Skipped (\S+) from target list as found unresponsive")
NUCLEI_UNEXECUTED = re.compile(r"Could not execute (?:request )?for (\S+?):? ")
OWN_MOUNT = "/pitangus"   # Pitangus' own templates (`nuclei_templates.ensure_own`), read-only next to the release's
NUCLEI_EXCLUDED_TYPES = "headless,code,javascript,file,dns,tcp,websocket,whois,workflow"

TESTSSL_HOSTS_MAX = 3
TESTSSL_TIMEOUT = 5 * 60
TESTSSL_CHECKS = ("--protocols", "--server-defaults", "--server-preference", "--headers", "--fs", "--std")

HTTPX_TIMEOUT = 2 * 60
TECHNOLOGIES_MAX = 50

# The longest each tool may take, in minutes (ZAP's own budget is in web.py): a scan of three hosts stays under
# about 45 minutes in the worst case, most finish in 15 to 25.
BUDGET = {"katana": (KATANA_TIMEOUT + KATANA_RETRY_SECONDS) // 60, "nuclei": NUCLEI_HOST_MINUTES_MAX + NUCLEI_PAGE_MINUTES + 2,
          "testssl": TESTSSL_HOSTS_MAX * TESTSSL_TIMEOUT // 60, "httpx": HTTPX_TIMEOUT // 60}

SEVERITIES = ("critical", "high", "medium", "low", "info")
TESTSSL_SEVERITY = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}
# testssl.sh lists every cipher of a weak family on its own line; the family is the finding.
TESTSSL_SKIPPED = re.compile(r"^(?:cipher-|cipher_order|cipherorder_|clientsimulation-|engine_problem|scanTime|service|"
                             r"pre_128cipher|overall)")
TESTSSL_TITLE = {
    "SSLv2": "scanning.web.testssl.titles.sslv2", "SSLv3": "scanning.web.testssl.titles.sslv3",
    "TLS1": "scanning.web.testssl.titles.tls1", "TLS1_1": "scanning.web.testssl.titles.tls1_1",
    "HSTS": "scanning.web.testssl.titles.hsts", "HSTS_time": "scanning.web.testssl.titles.hsts",
    "FS": "scanning.web.testssl.titles.fs", "cert_expirationStatus": "scanning.web.testssl.titles.expiration",
    "cert_chain_of_trust": "scanning.web.testssl.titles.trust", "cert_trust": "scanning.web.testssl.titles.name",
}
TESTSSL_FAMILY_TITLE = (("cipherlist_", "scanning.web.testssl.titles.ciphers"),)
# With several certificates (RSA and ECDSA) or intermediates, testssl.sh suffixes an id with which one: `<hostCert#1>`, `<#2>`.
TESTSSL_QUALIFIER = re.compile(r"\s*<([^<>]{1,40})>")
# Every certificate check (chain of trust, revocation, expiry, lifetime, an intermediate's…) is one finding per host.
TESTSSL_CERTIFICATE = ("cert_", "certs_", "certificate_", "intermediate_cert")
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
NUCLEI_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
TECH_ROOT = "/http/technologies/"
# Informational results that describe rather than flag (the TLS versions offered, the certificate's issuer and names).
FACT_TAGS = frozenset({"discovery", "enum", "detect", "tech"})
FACT_TEMPLATES = frozenset({"ssl-dns-names", "ssl-issuer", "tls-version", "wildcard-tls"})
VERSION = re.compile(r"[0-9][0-9A-Za-z.+_-]{0,40}")
DETECT_SUFFIX = re.compile(r"\s*[-–]?\s*(?:version\s+)?(?:detect(?:ion)?|discovery)\s*$", re.IGNORECASE)
REFERENCES_MAX, REFERENCE_MAX, TEXT_MAX, TITLE_MAX = 8, 300, 2000, 300


# A page's answer as httpx's status pass read it: its status, the start of its body (None when httpx didn't say) and
# the path and query it asked for, which a catch-all page may echo back.
Signature = tuple[int, str | None, str]


class ToolRun:
    """What one tool did in a scan: its step for the run and what it found. `unreached`: the scope's hosts it couldn't
    check (a tool that exits 0 without reaching a host is not a clean result for that host).

    Its evidence, of its own requests only (engine_contract): `answers`, every (host, status) it got in the run, for the
    run's blocking check; `pages`, every status it got per page, and `failed`, pages with a request that got no answer,
    both from the passes that finished (a tool that didn't finish proves nothing); `examined` and `unexamined`, for a
    tool whose units aren't pages it read over HTTP (testssl.sh's hosts); `paths`, what a page other than a root needs to
    count as examined, for a tool whose findings there are about one path (`engine_contract.http_coverage`)."""

    def __init__(self, key: str, status: str, detail, *, findings: list | None = None, duration: float | None = None,
                 unreached: list[str] | None = None, probed: list[str] | None = None, answers: list | None = None,
                 pages: dict[str, list[int]] | None = None, failed=(), examined: list[str] | None = None,
                 unexamined: dict[str, str] | None = None, contract=None, paths=None):
        self.key, self.status, self.detail = key, status, detail
        # The pages it requested one by one (nuclei's page pass): only those vouch for a page-level finding's absence.
        self.probed = list(probed or [])
        self.answers: list[tuple[str, int]] = list(answers or [])[:ANSWERS_MAX]
        self.pages = {page: list(statuses) for page, statuses in (pages or {}).items()}
        self.failed = set(failed)
        self.examined, self.unexamined = examined, dict(unexamined or {})
        self.paths = paths
        self.signatures: dict[str, Signature] = {}   # httpx: each page's answer (`soft_404`)
        self.roots: list[str] = []                                 # httpx: the roots its technologies pass got an answer from
        self.contract = contract  # the engine contract's verdict: None, or why the run can't be trusted
        self.findings: list[Finding] = findings or []
        self.duration = duration
        self.unreached = sorted(set(unreached or []))
        self.blocked: list[str] = []
        if self.unreached:
            self.status = "partial"
            self.detail = msg("scanning.web.tools.unreached", detail=detail, hosts=", ".join(self.unreached))

    def block(self, hosts: list[str]) -> None:
        """The hosts that turned the run away (`engine_contract.blocked_hosts`), among those this tool got answers from."""
        mine = sorted({host for host, _ in self.answers} & set(hosts) - set(self.unreached))
        if mine:
            self.blocked, self.status = mine, "partial"
            self.detail = msg("scanning.web.tools.blocked", detail=self.detail, hosts=", ".join(mine))

    def coverage(self, blocked=()) -> dict:
        """What this run proves about each of its units, for the registry (engine_contract.coverage)."""
        if self.examined is not None:
            hosts = set(blocked)
            return engine_contract.coverage([unit for unit in self.examined if (urlsplit(unit).hostname or "") not in hosts],
                                            {**self.unexamined, **{unit: "blocked" for unit in self.examined
                                                                   if (urlsplit(unit).hostname or "") in hosts}})
        return engine_contract.http_coverage(self.pages, paths=self.paths, failed=self.failed, blocked=blocked)

    def step(self) -> dict:
        meta = IMAGES[self.key]
        return {"id": f"dast-{self.key}", "name": msg(f"scanning.web.tools.{self.key}.name"), "status": self.status, "detail": self.detail,
                "tool": {"name": self.key, "version": meta["version"], "image": meta["image"], "duration_s": self.duration}}


def evidence(answers: list[tuple[str, int]]) -> tuple[list[tuple[str, int]], dict[str, list[int]]]:
    """(url, status) answers as a tool's evidence: (host, status) for the blocking check, and every status per page."""
    pages: dict[str, list[int]] = {}
    for url, status in answers:
        if page := page_of(url):
            pages.setdefault(page, []).append(status)
    return [((urlsplit(url).hostname or "").lower(), status) for url, status in answers], pages


def readiness() -> dict[str, Message | None]:
    """For each tool, None if it can run here, else why not (the step says so and the scan goes on without it)."""
    if runner() == "local":
        return {key: msg("scanning.web.tools.needs_docker") for key in TOOLS}
    if problem := docker_problem():
        return dict.fromkeys(TOOLS, problem)
    return {key: None if image_available(key) else msg("scanning.web.tools.image_missing", tool=IMAGES[key]["name"]) for key in TOOLS}


def _pins_ok(pins: dict[str, str], hosts: list[str]) -> None:
    if not hosts or any(host not in pins for host in hosts):
        raise ValueError("every host a tool reaches is pinned")


def host_regex(hosts: list[str]) -> str:
    return "^https://(?:" + "|".join(re.escape(host) for host in hosts) + ")(?::443)?(?:[/?#].*)?$"


def in_scope_url(value: Any, hosts: list[str], *, http: bool = False, collapse: bool = True) -> str | None:
    """`value` as scheme, host and path when it is an https URL on one of `hosts` (no user, no other port; with `http`,
    plain HTTP on port 80 too), else None. The query string and the fragment are dropped: they carry the values a crawl
    varies, and sometimes tokens. Repeated slashes are one (`//.env` is `/.env`): the tools send them as one."""
    if not isinstance(value, str) or len(value) > URL_MAX:
        return None
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    scheme = parts.scheme.lower()
    plain = http and scheme == "http" and port in (None, 80)
    if not (plain or (scheme == "https" and port in (None, 443))) or parts.username or parts.password or host not in hosts:
        return None
    path = "".join(ch for ch in (parts.path or "/") if ch.isprintable() and not ch.isspace()) or "/"
    if collapse:
        path = SLASHES.sub("/", path)
    if "${" in path:
        return None
    return f"{scheme}://{host}{path if path.startswith('/') else '/' + path}"


def host_of(target: Any) -> str:
    """The host name in what a tool prints as its target: a URL, `host:port` or a bare host."""
    value = str(target or "").strip().strip("\"'")
    value = value.split("://", 1)[-1].split("/", 1)[0].rsplit("@", 1)[-1]
    if value.count(":") == 1:
        value = value.rsplit(":", 1)[0]
    return value.lower().rstrip(".")


def _wrap(binary: str, arguments: list[str], headers, after: str = "") -> tuple[list[str], str | None, str | None]:
    """(arguments, entrypoint, stdin): with saved headers, a shell reads them from standard input into the
    container's memory-only /tmp and starts the tool with `-H` on that file. `after`: what the shell runs once the
    tool exits (it exits with the tool's code)."""
    if not headers and not after:
        return arguments, None, None
    if any(any(character in f"{name}{value}" for character in "\r\n\0") for name, value in headers):
        raise ValueError("a header is one line")
    command = f'{binary} "$@"' + (f" -H {HEADERS_FILE}" if headers else "")
    script = "umask 077 && " + (f"cat > {HEADERS_FILE} && " if headers else "") + (f"{command}; code=$?; {after}; exit $code" if after
                                                                                    else f"exec {command}")
    return ["-c", script, binary, *arguments], "sh", "".join(f"{name}: {value}\n" for name, value in headers) if headers else None


def _work(folder: Path, files: dict[str, str]) -> None:
    for name, content in files.items():
        (folder / name).write_text(content, encoding="utf-8")
        (folder / name).chmod(0o644)
    folder.chmod(0o755)


# --- katana ------------------------------------------------------------------------------------------------------


# Sign-out links: a crawl that follows one ends the session it carries (saved headers, a test user) and everything after
# it is scanned anonymously. Go's regexp for katana; ZAP's (Java) one matches the whole URL.
LOGOUT = r"(?i)/(?:log[-_]?out|sign[-_]?out|log[-_]?off)(?:[/?#.]|$)"
LOGOUT_ZAP = r"(?i).*/(?:log[-_]?out|sign[-_]?out|log[-_]?off)(?:[/?#.].*)?"


def katana_arguments(hosts: list[str], *, headless: bool = True) -> list[str]:
    # No `-kf` (known files): with it, katana 1.7 drops links it also saw in robots.txt or a sitemap (pitangus.dev's
    # /es/ went missing). robots.txt and the sitemaps are read by `web_seeds` instead.
    arguments = ["-list", f"{WORK}/seeds.txt", "-d", str(KATANA_DEPTH), "-jc", "-ct", f"{KATANA_MINUTES}m",
                 "-fs", "fqdn", "-cs", host_regex(hosts), "-e", "private-ips", "-dr", "-iqp",
                 "-c", "4", "-p", "2", "-rl", str(RATE), "-timeout", "10", "-retry", "1", "-mrs", "2097152",
                 "-r", f"{WORK}/{RESOLVERS}", "-j", "-or", "-ob", "-silent", "-nc", "-duc", "-cos", LOGOUT]
    if headless:
        # Its browser runs inside the container, which is its sandbox (Chromium's own needs privileges the container
        # doesn't have); whatever it asks for outside the scope goes to a proxy that isn't there.
        arguments += ["-hh", "-xhr", "-scp", "/usr/bin/chromium", "-nos", "-cdd", "/tmp/chromium",
                      "-ho", "--proxy-server=http://127.0.0.1:9", "-ho", "--proxy-bypass-list=" + ";".join(hosts)]
    return arguments


def _katana_entries(output: str) -> list[tuple[dict, Any]]:
    """katana's GET lines as (request, response), without those it asked for and never got: an error with no response,
    unless another line was found on that URL (its headless browser reports a page that never went idle as an error,
    after reading it)."""
    entries: list[tuple[dict, Any, bool]] = []
    sources: set[str] = set()
    for line in output.splitlines()[:50_000]:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        request = entry.get("request") if isinstance(entry, dict) else None
        if not isinstance(request, dict) or str(request.get("method") or "GET").upper() != "GET":
            continue
        response = entry.get("response")
        entries.append((request, response, bool(entry.get("error")) and not isinstance(response, dict)))
        if isinstance(request.get("source"), str):
            sources.add(request["source"])
    return [(request, response) for request, response, failed in entries if not failed or request.get("endpoint") in sources]


def katana_answers(output: str, hosts: list[str]) -> list[tuple[str, int]]:
    """Every HTTP status katana got for an in-scope page (without query string), in the order it got them: what tells
    a page reached (2xx) from a redirect, an error page or a refusal."""
    answers = []
    for request, response in _katana_entries(output):
        status = response.get("status_code") if isinstance(response, dict) else None
        if isinstance(status, int) and (url := in_scope_url(request.get("endpoint"), hosts)):
            answers.append((url, status))
    return answers


def parse_katana(output: str, hosts: list[str]) -> list[str]:
    """The in-scope pages katana found (GET answered without an error or a redirect: the redirect's target is found on
    its own), without query strings, sorted, at most INVENTORY_MAX."""
    found: set[str] = set()
    for request, response in _katana_entries(output):
        # A link the browser saw but didn't open has no response yet: ZAP and nuclei will ask for it.
        status = response.get("status_code") if isinstance(response, dict) else None
        if isinstance(status, int) and status >= 300:
            continue
        url = in_scope_url(request.get("endpoint"), hosts)
        if url:
            found.add(url)
    return sorted(found, key=lambda url: (url.count("/"), url))[:INVENTORY_MAX]


def katana_reached(output: str, hosts: list[str]) -> set[str]:
    """The hosts katana got anything from. One whose every line is an error with no response (an unreachable seed),
    or that never shows up, wasn't crawled, whatever katana's exit code says."""
    return {host for request, _ in _katana_entries(output) for host in [host_of(request.get("endpoint"))] if host in hosts}


def _katana_once(seeds: list[str], hosts: list[str], pins: dict[str, str], work: Path, headers, headless: bool):
    with TemporaryDirectory(prefix="katana-", dir=work) as temporary:
        folder = Path(temporary)
        _work(folder, {"seeds.txt": "".join(f"{url}\n" for url in seeds), RESOLVERS: f"{DEAD_RESOLVER}\n"})
        arguments, entrypoint, stdin = _wrap("katana", katana_arguments(hosts, headless=headless), headers)
        return _run("katana", arguments, None, network=True, mounts=["-v", f"{host_path(folder)}:{WORK}:ro"],
                    timeout=KATANA_TIMEOUT, hosts={host: pins[host] for host in hosts}, pinned_only=True,
                    entrypoint=entrypoint, stdin=stdin)


def run_katana(seeds: list[str], hosts: list[str], pins: dict[str, str], work: Path, *, headers=(), scrub=lambda text: text,
               headless: bool = True) -> tuple[ToolRun, list[str]]:
    """The crawl, with a browser; when the browser can't start (nothing found, quickly), once more without it."""
    _pins_ok(pins, hosts)
    started = time.time()
    urls: list[str] = []
    for browser in ([True, False] if headless else [False]):
        attempt = time.time()
        try:
            completed = _katana_once(seeds, hosts, pins, work, headers, browser)
        except subprocess.TimeoutExpired:
            return ToolRun("katana", "partial", msg("scanning.web.tools.timeout", minutes=KATANA_TIMEOUT // 60),
                           duration=round(time.time() - started, 1)), []
        except (OSError, ValueError):
            return ToolRun("katana", "partial", msg("scanning.web.tools.failed", tool="katana"), duration=round(time.time() - started, 1)), []
        output = scrub(completed.stdout or "")[:OUTPUT_MAX]
        urls = parse_katana(output, hosts)
        if urls or time.time() - attempt > KATANA_RETRY_SECONDS:
            break
    duration = round(time.time() - started, 1)
    answers, pages = evidence(katana_answers(output, hosts))
    _, broken = engine_contract.jsonl(KATANA, completed.returncode, output)
    # A crawl that didn't finish still hands its URLs on (they are only what ZAP and nuclei request), never its evidence.
    if completed.returncode != 0 or (broken and engine_contract.enforced()):
        return ToolRun("katana", "partial", msg("scanning.web.tools.failed", tool="katana"), duration=duration, answers=answers,
                       contract=broken), urls
    detail = "scanning.web.tools.katana.detail" if browser else "scanning.web.tools.katana.detail_plain"
    reached = katana_reached(output, hosts)
    seeded = sorted({host_of(url) for url in seeds} & set(hosts))
    return ToolRun("katana", "completed", msg(detail, count=len(urls), minutes=KATANA_MINUTES, depth=KATANA_DEPTH),
                   duration=duration, unreached=[host for host in seeded if host not in reached], answers=answers, pages=pages,
                   contract=broken), urls


# --- nuclei ------------------------------------------------------------------------------------------------------


def nuclei_arguments(folder: str, minutes: int, *, own: bool = False) -> list[str]:
    """Only the filtered templates (`nuclei_templates`; with `own`, Pitangus' own too), and nothing that could bring
    others back: no update, no out-of-band server, no redirects, no private addresses, the excluded protocols and tags
    again."""
    return ["-t", f"/templates/{folder}", *(["-t", f"{OWN_MOUNT}/{folder}"] if own else []), "-l", f"{WORK}/targets.txt", "-r", f"{WORK}/{RESOLVERS}",
            "-tlog", f"{WORK}/{NUCLEI_TRACE}", "-sresp", "-srd", NUCLEI_STORE,
            "-duc", "-ni", "-dr", "-lna", "-no-stdin", "-nc", "-jsonl", "-or", "-ot", "-stats", "-sj", "-si", str(NUCLEI_STATS_SECONDS),
            "-ept", NUCLEI_EXCLUDED_TYPES, "-etags", ",".join(sorted(nuclei_templates.DENY_TAGS)),
            "-rl", str(RATE), "-c", "10", "-bs", "5", "-timeout", "10", "-retries", "1", "-mt", f"{minutes}m"]


def _strings(value: Any, limit: int = 20) -> list[str]:
    items = value if isinstance(value, list) else [value] if isinstance(value, str) else []
    return [item.strip() for item in items if isinstance(item, str) and item.strip()][:limit]


def _clean(value: Any, limit: int = TEXT_MAX) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def _nuclei_location(entry: dict, hosts: list[str], http: bool = False, collapse: bool = True) -> str | None:
    """The URL a result is at; a TLS result (`host:443`) is about its host's root."""
    for candidate in (entry.get("matched-at"), entry.get("url")):
        if url := in_scope_url(candidate, hosts, http=http, collapse=collapse):
            return url
    host = str(entry.get("host") or entry.get("matched-at") or "").lower()
    name = host.split("//")[-1].split("/")[0].rsplit(":", 1)[0]
    return f"https://{name}/" if entry.get("type") == "ssl" and name in hosts else None


def parse_nuclei(output: str, hosts: list[str], *, http: bool = False) -> tuple[list[Finding], list[dict]]:
    """nuclei's JSON lines as findings (one per template, matcher and URL), plus what its technology templates
    detected. What the template says (description, remediation, references, CWE, CVE) is kept as published; the
    request, the response, the curl line and the extracted values are never kept."""
    findings: list[Finding] = []
    technologies: list[dict] = []
    kept: dict[str, Finding] = {}
    for line in output.splitlines()[:20_000]:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict) or not isinstance(entry.get("info"), dict):
            continue
        template = _clean(entry.get("template-id"), 200)
        location = _nuclei_location(entry, hosts, http)
        if not template or not location:
            continue
        reported = location
        if site_level("nuclei", template):  # a header every page lacks: one finding per host, not one per URL
            location = root_of(location)
        info = entry["info"]
        matcher = _clean(entry.get("matcher-name"), 200)
        name = _clean(info.get("name"), TITLE_MAX) or template
        # Pitangus' own templates carry their Spanish text in `metadata`; the release's text stays as published.
        own = template.startswith(nuclei_templates.OWN_PREFIX) and str(entry.get("template-path") or "").startswith(OWN_MOUNT + "/")
        spanish = info.get("metadata") if own and isinstance(info.get("metadata"), dict) else {}
        tags = {tag.lower() for tag in _strings(info.get("tags"), 50)}
        severity = NUCLEI_SEVERITY.get(str(info.get("severity") or "").lower(), "info")
        # A version past its end of life is something to act on, not just a name: it stays a finding.
        # A technology: a template of the technologies folder, or one tagged `tech` that only informs. A `tech`-tagged
        # template of higher severity (an unauthenticated etcd, an open installer) is a finding.
        informs = str(info.get("severity") or "").lower() in ("", "info", "unknown")
        if (TECH_ROOT in str(entry.get("template-path") or "") or ("tech" in tags and informs)) and "eol" not in tags:
            # "nginx/1.27.5" or "1.27.5": the version is the last part.
            extracted = next((part for item in _strings(entry.get("extracted-results"), 5)
                              for part in [re.split(r"[/ ]", item)[-1]] if VERSION.fullmatch(part)), None)
            technologies.append({"name": matcher or DETECT_SUFFIX.sub("", name), "version": extracted, "host": urlsplit(location).hostname})
            continue
        if severity == "info" and "eol" not in tags and (tags & FACT_TAGS or template in FACT_TEMPLATES):
            continue  # what a certificate or a protocol is, not something to fix
        rule = f"{template}:{matcher}" if matcher else template
        key = "\x1f".join((rule, identity_path(location), ""))
        # Before site-level folding and hash normalization (0.14), a result was keyed by its URL as reported, its
        # slashes as nuclei printed them.
        raw = _nuclei_location(entry, hosts, http, collapse=False) or reported
        former = _stable("sarif", "nuclei", "\x1f".join((rule, raw, "")))
        if key in kept:
            remember_former(kept[key], former)
            continue
        classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
        cwes = sorted({int(match) for item in _strings(classification.get("cwe-id")) for match in re.findall(r"(?i)cwe-0*(\d{1,5})", item)})
        cves = sorted({item.upper() for item in _strings(classification.get("cve-id")) if re.fullmatch(r"(?i)CVE-\d{4}-\d{4,}", item)})
        references = [item for item in _strings(info.get("reference"), REFERENCES_MAX) if item.startswith(("https://", "http://"))
                      and len(item) <= REFERENCE_MAX]
        description: Any = _clean(info.get("description"))
        remediation: Any = _clean(info.get("remediation"))
        title = (f"{name} ({matcher})" if matcher else name)[:TITLE_MAX]
        shown: Any = title
        if own:
            es = _clean(spanish.get("pitangus-name-es"), TITLE_MAX)
            shown = inline({"en": title, "es": (f"{es} ({matcher})" if matcher and es else es)[:TITLE_MAX]})
            description = inline({"en": description, "es": _clean(spanish.get("pitangus-description-es"))})
            remediation = inline({"en": remediation, "es": _clean(spanish.get("pitangus-remediation-es"))})
        finding = _base("dast", rule, title, location, 1, severity, tool="nuclei",
                        reason=msg("scanning.web.tools.nuclei.reason", template=template, title=shown),
                        remediation=remediation if own and remediation
                        else msg("scanning.sarif.remediation_help", tool="nuclei", help=remediation) if remediation
                        else msg("scanning.web.remediation", tool="nuclei"),
                        cwe=cwes, owasp="", confidence=8 if own else 7, digest=_stable("sarif", "nuclei", key))
        finding["title"], finding["cve"], finding["owasp"] = shown, cves, []
        finding["priority"]["factors"] = [msg("scanning.sarif.priority", tool="nuclei", severity=msg(f"scanning.severity.{severity}"))]
        finding["web"] = {"method": "GET", **({"parameter": matcher} if matcher else {}), **({"description": description} if description else {}),
                          **({"solution": remediation} if remediation else {}), **({"references": references} if references else {})}
        remember_former(finding, former)
        kept[key] = finding
        findings.append(finding)
    return findings, technologies


def nuclei_stats_seen(log: str) -> bool:
    """Whether nuclei printed its statistics (`-stats -sj`): the evidence that it ran its templates at all. It prints no
    line for a target where nothing matched."""
    for line in log.splitlines()[:100_000]:
        line = line.strip()
        if line.startswith("{"):
            try:
                stats = json.loads(line)
            except ValueError:
                continue
            if isinstance(stats, dict) and "requests" in stats and "total" in stats:
                return True
    return False


def nuclei_trace(text: str, hosts: list[str], *, http: bool = False) -> set[str]:
    """The pages nuclei sent a request to that got no answer: its trace log names every request it sent (`input`, the
    URL) and the error it ended with ("none" when an answer came back; a refused, filtered or timed out one names why)."""
    failed: set[str] = set()
    for line in text.splitlines()[:500_000]:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and str(entry.get("error") or "none") != "none" \
                and (url := in_scope_url(entry.get("input"), hosts, http=http)) and (page := page_of(url)):
            failed.add(page)
    return failed


def nuclei_statuses(text: str, hosts: list[str], *, http: bool = False) -> list[tuple[str, int]]:
    """The status of every response nuclei got for an in-scope URL, one `URL status` line each (`NUCLEI_STATUS_AWK`
    over its stored responses): its own evidence of what each page answered."""
    answers = []
    for line in text.splitlines()[:500_000]:
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit() and len(parts[1]) == 3 and (url := in_scope_url(parts[0], hosts, http=http)):
            answers.append((url, int(parts[1])))
    return answers


def _plain(target: str) -> bool:
    """Whether a target nuclei names is plain HTTP (the exposure check's port 80): a host that doesn't serve it isn't
    a host nuclei couldn't check."""
    value = target.strip().lower()
    return value.startswith("http://") or value.rsplit("/", 1)[0].endswith(":80")


def nuclei_log(log: str, hosts: list[str]) -> tuple[set[str], bool]:
    """What nuclei's log says it couldn't do: the scope's hosts it skipped as unresponsive or where a template couldn't
    run, and whether the pass is incomplete: any of those, or final statistics with requests planned and none sent. Its
    percentage isn't read: a finished scan of pitangus.dev ends at 99% (templates that stop at their first match skip
    the rest of their requests). Plain HTTP targets don't count here (`plain_unreached`)."""
    unreached: set[str] = set()
    incomplete = False
    sent: tuple[int, int] | None = None
    for line in log.splitlines()[:100_000]:
        line = line.strip()
        if line.startswith("{"):
            try:
                stats = json.loads(line)
                if isinstance(stats, dict) and "requests" in stats and "total" in stats:
                    sent = (int(str(stats["requests"])), int(str(stats["total"])))
            except ValueError:
                pass
            continue
        match = NUCLEI_SKIPPED.search(line) or NUCLEI_UNEXECUTED.search(line)
        if match and not _plain(match.group(1)):
            incomplete = True
            if (host := host_of(match.group(1))) in hosts:
                unreached.add(host)
    return unreached, incomplete or (sent is not None and sent[0] == 0 and sent[1] > 0)


def plain_unreached(log: str, hosts: list[str]) -> set[str]:
    """The hosts whose plain HTTP root nuclei skipped or couldn't run a template on (nothing on port 80, say)."""
    return {host for line in log.splitlines()[:100_000] for match in [NUCLEI_SKIPPED.search(line) or NUCLEI_UNEXECUTED.search(line)]
            if match and _plain(match.group(1)) and (host := host_of(match.group(1))) in hosts}


def _text_of(value) -> str:
    """A process's output as text: what a timeout hands back may be bytes, or nothing."""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value or ""


def run_nuclei(roots: list[str], pages: list[str], hosts: list[str], pins: dict[str, str], work: Path, cache_dir: Path, *,
               headers=(), scrub=lambda text: text, http: bool = False) -> tuple[ToolRun, list[dict]]:
    """Two passes: every allowed template on each host's root, then the page-level ones on the crawled URLs (one
    request per URL: nuclei folds templates that ask for the same page). `http`: the roots include plain HTTP ones.

    A pass that didn't finish (killed, out of time, an exit code other than 0, or output the engine contract rejects
    when it is enforced) neither opens nor closes anything: its findings are dropped and its pages prove nothing. Its
    answers still count for the run's blocking check. A finding about one path (anything but a root) is proven gone
    only by a 404 or a 410 there: a page that still answers, a challenge or a catch-all page proves nothing."""
    _pins_ok(pins, hosts)
    started = time.time()
    try:
        templates, counts = nuclei_templates.ensure(cache_dir)
    except nuclei_templates.TemplatesError:
        return ToolRun("nuclei", "skipped", msg("scanning.web.tools.nuclei.no_templates", release=nuclei_templates.RELEASE)), []
    own, own_counts = nuclei_templates.ensure_own(cache_dir)
    findings: list[Finding] = []
    technologies: list[dict] = []
    status = "completed"
    unreached: set[str] = set()
    documents = [url for url in pages if url not in roots and not ASSET.search(urlsplit(url).path)][:PAGES_MAX]
    # Every host gets the whole template set: the pass grows with them, so three hosts at the rate limit still fit.
    host_minutes = min(NUCLEI_HOST_MINUTES + NUCLEI_MINUTES_PER_HOST * max(0, len(roots) - 1), NUCLEI_HOST_MINUTES_MAX)
    passes = [("hosts", roots, host_minutes), *([("pages", documents, NUCLEI_PAGE_MINUTES)] if documents else [])]
    contract: Message | None = None
    answers: list[tuple[str, int]] = []
    evidence_pages: dict[str, list[int]] = {}
    failed: set[str] = set()
    for folder_name, targets, minutes in passes:
        finished, sent, statuses = True, set(), ""
        with TemporaryDirectory(prefix="nuclei-", dir=work) as temporary:
            folder = Path(temporary)
            _work(folder, {"targets.txt": "".join(f"{url}\n" for url in targets), RESOLVERS: f"{DEAD_RESOLVER}\n"})
            mine = own is not None and (own / folder_name).is_dir()
            after = f"find {NUCLEI_STORE} -type f -exec awk '{NUCLEI_STATUS_AWK}' {{}} + > {WORK}/{NUCLEI_STATUSES} 2>/dev/null"
            arguments, entrypoint, stdin = _wrap("nuclei", nuclei_arguments(folder_name, minutes, own=mine), headers, after)
            try:
                # Its folder is writable for the trace log and the statuses only: the targets and resolvers are read from it.
                completed = _run("nuclei", arguments, None, network=True,
                                 mounts=["-v", f"{host_path(folder)}:{WORK}:rw", "-v", f"{host_path(templates)}:/templates:ro",
                                         *(["-v", f"{host_path(own)}:{OWN_MOUNT}:ro"] if mine and own is not None else [])],
                                 timeout=(minutes + 2) * 60, hosts={host: pins[host] for host in hosts}, pinned_only=True,
                                 entrypoint=entrypoint, stdin=stdin)
                output, log = completed.stdout or "", completed.stderr or ""
                finished = completed.returncode == 0
                _, broken = engine_contract.jsonl(NUCLEI, completed.returncode, output)
            except subprocess.TimeoutExpired as exc:
                output, log, finished = _text_of(exc.stdout), _text_of(exc.stderr), False
                broken = msg("scanning.engines.timeout", engine="nuclei")
            except (OSError, ValueError):
                status = "partial"
                contract = contract or msg("scanning.engines.unreadable", engine="nuclei")
                continue
            trace, recorded = folder / NUCLEI_TRACE, folder / NUCLEI_STATUSES
            sent = nuclei_trace(_text(trace), hosts, http=http)
            statuses = _text(recorded)
        broken = broken or (None if nuclei_stats_seen(log) else msg("scanning.contract.empty", engine="nuclei"))
        contract = contract or broken
        finished = finished and not (broken and engine_contract.enforced())
        got, by_page = evidence(nuclei_statuses(statuses, hosts, http=http))
        answers += got
        skipped, incomplete = nuclei_log(scrub(log)[:OUTPUT_MAX], hosts)
        unreached |= skipped
        if incomplete or not finished:
            status = "partial"
        if not finished:
            continue
        for page, codes in by_page.items():
            evidence_pages.setdefault(page, []).extend(codes)
        # A host nuclei gave up on (as unresponsive, or a template that couldn't run there) left requests unsent.
        plain = plain_unreached(scrub(log)[:OUTPUT_MAX], hosts)
        failed |= sent | {page for page in by_page if (host := urlsplit(page).hostname or "") in skipped
                          or (host in plain and page.startswith("http://"))}
        found, detected = parse_nuclei(scrub(output)[:OUTPUT_MAX], hosts, http=http)
        findings += found
        technologies += detected
    unique = {finding["fingerprint"]: finding for finding in findings}
    detail = msg("scanning.web.tools.nuclei.detail_own" if documents else "scanning.web.tools.nuclei.detail_roots",
                 release=nuclei_templates.RELEASE, templates=counts.get("hosts", 0), own=own_counts.get("hosts", 0), pages=len(documents),
                 count=len(unique), rate=RATE)
    if contract and engine_contract.enforced():
        status = "partial"
    return ToolRun("nuclei", status, detail, findings=list(unique.values()), duration=round(time.time() - started, 1),
                   unreached=sorted(unreached), probed=documents, answers=answers, pages=evidence_pages, failed=failed,
                   contract=contract, paths=engine_contract.absent), technologies


def _text(path: Path) -> str:
    """A file a tool wrote in its work folder, as text; "" when it is missing, a link or too large."""
    try:
        if path.is_file() and not path.is_symlink() and path.stat().st_size <= OUTPUT_MAX:
            return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    return ""


# --- testssl.sh --------------------------------------------------------------------------------------------------


def testssl_arguments(host: str, address: str, report: str) -> list[str]:
    return ["--quiet", "--color", "0", "--warnings", "off", "--ip", address, "--nodns", "none", "--jsonfile", f"{WORK}/{report}",
            "--connect-timeout", "10", "--openssl-timeout", "10", *TESTSSL_CHECKS, f"https://{host}/"]


def _testssl_title(identifier: str):
    if identifier in TESTSSL_TITLE:
        return msg(TESTSSL_TITLE[identifier])
    for prefix, key in TESTSSL_FAMILY_TITLE:
        if identifier.startswith(prefix):
            return msg(key, check=identifier)
    return msg("scanning.web.testssl.titles.other", check=identifier)


def testssl_check(identifier: str) -> tuple[str, str]:
    """(the check, which certificate it is about): `cert_notAfter <#1> <hostCert#2>` → ("cert_notAfter", "hostCert#2 #1")."""
    qualifiers = TESTSSL_QUALIFIER.findall(identifier)
    return TESTSSL_QUALIFIER.sub("", identifier).strip(), " ".join(reversed(qualifiers))


def parse_testssl(document: Any, host: str) -> list[Finding]:
    """testssl.sh's JSON (flat list) as findings: only what it rates LOW or worse, one per check (a check repeated per
    certificate is one, its lines in the evidence); every certificate problem is a single `certificate` finding per
    host with each check as evidence; the per-cipher lines of a weak family are folded into that family's finding."""
    if not isinstance(document, list):
        return []
    path = f"https://{host}/"
    ciphers = [str(item.get("finding") or "").split()[2] for item in document[:5000]
               if isinstance(item, dict) and str(item.get("id") or "").startswith("cipher-") and item.get("severity") in TESTSSL_SEVERITY
               and len(str(item.get("finding") or "").split()) > 2]
    checks: dict[str, list[tuple[str, str, str, dict]]] = {}
    for item in document[:5000]:
        if not isinstance(item, dict):
            continue
        identifier, which = testssl_check(_clean(item.get("id"), 100))
        severity = TESTSSL_SEVERITY.get(str(item.get("severity") or ""))
        if not identifier or severity is None or TESTSSL_SKIPPED.match(identifier):
            continue
        rule = "certificate" if identifier.startswith(TESTSSL_CERTIFICATE) else identifier
        checks.setdefault(rule, []).append((identifier, which, severity, item))
    findings: list[Finding] = []
    for rule, lines in checks.items():
        severity = min((severity for _, _, severity, _ in lines), key=lambda value: SEVERITY_RANK[value])
        parts = [f"{identifier}{f' ({which})' if which else ''}: {_clean(item.get('finding'), 300)}" for identifier, which, _, item in lines]
        text = "; ".join(parts) if rule == "certificate" or len(lines) > 1 else _clean(lines[0][3].get("finding"), 500)
        evidence = text + (" · " + ", ".join(ciphers[:20]) if rule.startswith("cipherlist_") and ciphers else "")
        cwes = sorted({int(number) for *_, item in lines for number in re.findall(r"(?i)cwe-0*(\d{1,5})", str(item.get("cwe") or ""))})
        cves = sorted({value.upper() for *_, item in lines for value in re.findall(r"(?i)CVE-\d{4}-\d{4,}", str(item.get("cve") or ""))})
        named = sorted(dict.fromkeys(identifier for identifier, *_ in lines))
        title = (msg("scanning.web.testssl.titles.certificate_family", checks=", ".join(named[:6]), count=len(named)) if rule == "certificate"
                 else _testssl_title(rule))
        finding = _base("dast", rule, title, path, 1, severity, tool="testssl",
                        reason=msg("scanning.web.testssl.reason", check=", ".join(named[:6]), host=host, finding=text[:500]),
                        remediation=msg("scanning.web.remediation", tool="testssl.sh"),
                        cwe=cwes, owasp="", confidence=8, digest=_stable("sarif", "testssl", "\x1f".join((rule, path, ""))))
        finding["cve"] = cves
        finding["priority"]["factors"] = [msg("scanning.sarif.priority", tool="testssl.sh", severity=msg(f"scanning.severity.{severity}"))]
        finding["web"] = {"evidence": evidence[:TEXT_MAX]}
        findings.append(finding)
    return findings


def testssl_finished(document: Any) -> bool:
    """Whether testssl.sh's report is of a finished scan: its closing `scanTime`, and no fatal `scanProblem` (it couldn't
    connect) nor an interrupted scan, which it reports with that same `scanTime`."""
    if not isinstance(document, list):
        return False
    items = [item for item in document[:5000] if isinstance(item, dict)]
    if any(item.get("severity") == "FATAL" or item.get("id") == "scanProblem" for item in items):
        return False
    return any(item.get("id") == "scanTime" and "interrupted" not in str(item.get("finding") or "").lower() for item in items)


def run_testssl(hosts: list[str], pins: dict[str, str], work: Path) -> ToolRun:
    """testssl.sh on each host (the first TESTSSL_HOSTS_MAX). Its unit is the host: only a host whose report is of a
    finished scan (exit 0 and `testssl_finished`) opens findings or proves them gone; a killed, timed out, truncated or
    failed one does neither."""
    started = time.time()
    findings: list[Finding] = []
    targets, failed = hosts[:TESTSSL_HOSTS_MAX], 0
    unreached: list[str] = []
    examined: list[str] = []
    unexamined = {f"https://{host}/": "capped" for host in hosts[TESTSSL_HOSTS_MAX:]}
    for index, host in enumerate(targets):
        _pins_ok(pins, [host])
        with TemporaryDirectory(prefix="testssl-", dir=work) as temporary:
            folder = Path(temporary)
            folder.chmod(0o700)
            report = f"testssl-{index}.json"
            try:
                completed = _run("testssl", testssl_arguments(host, pins[host], report), None, network=True,
                                 mounts=["-v", f"{host_path(folder)}:{WORK}:rw"], timeout=TESTSSL_TIMEOUT,
                                 hosts={host: pins[host]}, pinned_only=True)
                document = json.loads((folder / report).read_text(encoding="utf-8", errors="replace")) \
                    if (folder / report).is_file() and (folder / report).stat().st_size < OUTPUT_MAX else None
            except (subprocess.TimeoutExpired, OSError, ValueError):
                completed, document = None, None
        if completed is None or completed.returncode != 0 or not testssl_finished(document):
            failed += 1
            unreached.append(host)
            unexamined[f"https://{host}/"] = "unfinished"
            continue
        examined.append(f"https://{host}/")
        findings += parse_testssl(document, host)
    status = "partial" if failed or len(hosts) > len(targets) else "completed"
    detail = msg("scanning.web.tools.testssl.detail", hosts=", ".join(targets), count=len(findings))
    if len(hosts) > len(targets):
        detail = msg("scanning.web.tools.testssl.detail_capped", hosts=", ".join(targets), count=len(findings), max=TESTSSL_HOSTS_MAX,
                     total=len(hosts))
    return ToolRun("testssl", status, detail, findings=findings, duration=round(time.time() - started, 1), unreached=unreached,
                   examined=examined, unexamined=unexamined)


# --- httpx -------------------------------------------------------------------------------------------------------


def httpx_arguments(addresses: list[str]) -> list[str]:
    return ["-l", f"{WORK}/hosts.txt", "-r", f"{WORK}/{RESOLVERS}", "-allow", ",".join(sorted(set(addresses))), "-nfs", "-fhr",
            "-td", "-server", "-sc", "-j", "-ob", "-silent", "-nc", "-duc", "-no-stdin", "-rl", str(RATE), "-timeout", "10",
            "-retries", "1"]


TECH = re.compile(r"^(?P<name>[^:]{1,80})(?::(?P<version>[0-9][0-9A-Za-z.+_-]{0,40}))?$")


def parse_httpx(output: str, hosts: list[str]) -> list[dict]:
    """The technologies httpx names per host ("Nginx:1.25.3" → name and version), without repeats."""
    return _httpx_lines(output, hosts)[0]


def httpx_answered(output: str, hosts: list[str]) -> set[str]:
    """The hosts httpx got an answer from: one it couldn't reach prints no line at all, and httpx still exits 0."""
    return _httpx_lines(output, hosts)[1]


def _httpx_lines(output: str, hosts: list[str]) -> tuple[list[dict], set[str]]:
    found, answered = [], set()
    for line in output.splitlines()[:1000]:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict):
            continue
        host = str(entry.get("host") or urlsplit(str(entry.get("url") or "")).hostname or "").lower()
        if host not in hosts:
            try:
                host = (urlsplit(str(entry.get("input") or "")).hostname or "").lower()
            except ValueError:
                continue
        if host not in hosts:
            continue
        if entry.get("failed") is not True:
            answered.add(host)
        for item in _strings(entry.get("tech"), 100):
            match = TECH.match(item)
            if match:
                found.append({"name": match.group("name").strip(), "version": match.group("version"), "host": host})
    return found, answered


def technologies_of(*groups: list[dict]) -> list[dict]:
    """One row per technology (name and version, whatever the case each tool writes it in), with the hosts it was seen
    on; sorted, at most TECHNOLOGIES_MAX."""
    names: dict[str, str] = {}
    merged: dict[tuple[str, str | None], set[str]] = {}
    for group in groups:
        for item in group:
            name = " ".join(str(item.get("name") or "").split())[:80]
            if not name or not item.get("host"):
                continue
            key = name.lower()
            # httpx writes "Cloudflare", nuclei's matcher "cloudflare": the capitalized one is shown.
            if key not in names or (names[key] == key and name != key):
                names[key] = name
            merged.setdefault((key, item.get("version") or None), set()).add(str(item["host"]))
    # A version-less row adds nothing next to the same technology with its version.
    versioned = {key for key, version in merged if version}
    kept = sorted(((key, version, hosts) for (key, version), hosts in merged.items() if version or key not in versioned),
                  key=lambda row: (row[0], row[1] or ""))
    return [{"name": names[key], **({"version": version} if version else {}), "hosts": sorted(hosts)}
            for key, version, hosts in kept][:TECHNOLOGIES_MAX]


STATUS_PAGES_MAX = 500   # pages whose HTTP status httpx checks after the scan (what makes a page count as reached)
SOFT_404_BITS = 3        # of 64: bodies whose simhashes (`body_simhash`) differ by at most this many bits are the same page
BODY_READ = 8192         # bytes of each page's body the status pass reads: enough to tell one page from another
STATUS_OUTPUT_MAX = 40_000_000   # its output with those bodies: JSON escapes `<` as six bytes, for every page
WORD = re.compile(r"\w+")
TAG = re.compile(r"</?[A-Za-z][^<>]*>")   # markup isn't what a page says: a tag name is no word of its text


def httpx_status_arguments(addresses: list[str]) -> list[str]:
    """The status pass: each page once, over its own scheme (`-nfs`: without it httpx asks for a plain HTTP URL over
    HTTPS first, and the answer would be another URL's), no redirect followed (a redirect to the login is a redirect,
    not the page) and nothing else asked; the body's simhash, to tell a page from the site's answer to any path
    (`soft_404`): the first BODY_READ bytes of it, read here and never kept."""
    return ["-l", f"{WORK}/pages.txt", "-r", f"{WORK}/{RESOLVERS}", "-allow", ",".join(sorted(set(addresses))), "-nfs", "-sc", "-j", "-irr",
            "-rstr", str(BODY_READ), "-silent", "-nc", "-duc", "-no-stdin", "-rl", str(RATE), "-timeout", "10", "-retries", "1"]


def _as_asked(entry: dict) -> bool:
    """Whether httpx's answer is the one for the URL it was given (`input`): the URL it requested (`url`) has the same
    scheme, host, port and path. One it fetched another way answers for a URL nobody asked about."""
    def target(value) -> tuple:
        parts = urlsplit(str(value or ""))
        scheme = parts.scheme.lower()
        return scheme, (parts.hostname or "").lower(), parts.port or {"https": 443, "http": 80}.get(scheme), unquote(parts.path or "/")
    try:
        return bool(entry.get("url")) and target(entry.get("input")) == target(entry.get("url"))
    except ValueError:
        return False


def _httpx_entries(output: str, hosts: list[str], http: bool = False):
    for line in output.splitlines()[:20_000]:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and isinstance(entry.get("status_code"), int) and _as_asked(entry) \
                and (url := in_scope_url(entry.get("input"), hosts, http=http)):
            yield url, entry


def httpx_statuses(output: str, hosts: list[str], *, http: bool = False) -> dict[str, int]:
    """The HTTP status of each in-scope page httpx asked for (its `input`, without query string)."""
    return {url: entry["status_code"] for url, entry in _httpx_entries(output, hosts, http)}


def httpx_signatures(output: str, hosts: list[str], *, http: bool = False) -> dict[str, Signature]:
    """Each page's answer as httpx's status pass read it (`Signature`). httpx leaves an empty body out of its line."""
    signatures = {}
    for url, entry in _httpx_entries(output, hosts, http):
        body = entry["body"] if isinstance(entry.get("body"), str) else "" if "raw_header" in entry else None
        parts = urlsplit(str(entry.get("input")))
        if page := page_of(url):
            signatures[page] = (entry["status_code"], None if body is None else body[:BODY_READ],
                                parts.path + (f"?{parts.query}" if parts.query else ""))
    return signatures


def run_httpx(hosts: list[str], pins: dict[str, str], work: Path, pages: Sequence[str] = (), *, http: bool = False) -> tuple[ToolRun, list[dict]]:
    """httpx on each host's root (its technologies), then, with `pages`, the HTTP status of each of them (at most
    STATUS_PAGES_MAX). A pass that didn't finish (killed, out of time, an exit code other than 0, or output the engine
    contract rejects when it is enforced) names no technology and proves nothing about a page; its answers still count
    for the run's blocking check. `http`: `pages` may be plain HTTP ones on port 80."""
    _pins_ok(pins, hosts)
    started = time.time()
    with TemporaryDirectory(prefix="httpx-", dir=work) as temporary:
        folder = Path(temporary)
        _work(folder, {"hosts.txt": "".join(f"https://{host}/\n" for host in hosts), RESOLVERS: f"{DEAD_RESOLVER}\n"})
        try:
            completed = _run("httpx", httpx_arguments([pins[host] for host in hosts]), None, network=True,
                             mounts=["-v", f"{host_path(folder)}:{WORK}:ro"], timeout=HTTPX_TIMEOUT,
                             hosts={host: pins[host] for host in hosts}, pinned_only=True)
        except (subprocess.TimeoutExpired, OSError, ValueError):
            return ToolRun("httpx", "partial", msg("scanning.web.tools.failed", tool="httpx"), duration=round(time.time() - started, 1)), []
    output = (completed.stdout or "")[:OUTPUT_MAX]
    _, broken = engine_contract.jsonl(HTTPX, completed.returncode, output)
    finished = completed.returncode == 0 and not (broken and engine_contract.enforced())
    detected = parse_httpx(output, hosts) if finished else []
    names = technologies_of(detected)
    answered = httpx_answered(output, hosts) if finished else set()
    # The first pass follows same-host redirects (for the technologies), so its statuses aren't the page's own: they
    # count for the blocking check only.
    answers = [(host, status) for url, status in httpx_statuses(output, hosts).items() if (host := urlsplit(url).hostname or "")]
    pages_of: dict[str, list[int]] = {}
    signatures: dict[str, Signature] = {}
    wanted = [url for url in dict.fromkeys([*(f"https://{host}/" for host in hosts), *pages]) if in_scope_url(url, hosts, http=http)][:STATUS_PAGES_MAX]
    if pages and wanted:
        with TemporaryDirectory(prefix="httpx-pages-", dir=work) as temporary:
            folder = Path(temporary)
            _work(folder, {"pages.txt": "".join(f"{url}\n" for url in wanted), RESOLVERS: f"{DEAD_RESOLVER}\n"})
            try:
                checked = _run("httpx", httpx_status_arguments([pins[host] for host in hosts]), None, network=True,
                               mounts=["-v", f"{host_path(folder)}:{WORK}:ro"], timeout=HTTPX_TIMEOUT,
                               hosts={host: pins[host] for host in hosts}, pinned_only=True)
                text = (checked.stdout or "")[:STATUS_OUTPUT_MAX]
                asked = {page_of(url) for url in wanted}
                got, by_page = evidence([(url, status) for url, status in httpx_statuses(text, hosts, http=http).items() if page_of(url) in asked])
                answers += got
                _, unread = engine_contract.jsonl(HTTPX, checked.returncode, text)
                if checked.returncode == 0 and not (unread and engine_contract.enforced()):
                    pages_of, signatures = by_page, httpx_signatures(text, hosts, http=http)
                else:
                    finished = False
            except (subprocess.TimeoutExpired, OSError, ValueError):
                finished = False  # without statuses those pages simply don't count as reached
    run = ToolRun("httpx", "completed" if finished else "partial", msg("scanning.web.tools.httpx.detail", count=len(names), hosts=", ".join(hosts)),
                  duration=round(time.time() - started, 1), unreached=[host for host in hosts if host not in answered],
                  answers=answers, pages=pages_of, contract=broken)
    run.signatures = signatures
    run.roots = sorted(f"https://{host}/" for host in answered)
    return run, detected


def _words(text: str) -> list[str]:
    return WORD.findall(TAG.sub(" ", unquote(html.unescape(text))).lower())


def _without(words: list[str], echo: list[str]) -> list[str]:
    kept, index = [], 0
    while index < len(words):
        if echo and words[index:index + len(echo)] == echo:
            index += len(echo)
        else:
            kept.append(words[index])
            index += 1
    return kept


def body_simhash(body: str, echoes: Iterable[str] = ()) -> int:
    """A body's 64-bit simhash over the words of its text (entities and percent escapes decoded, tags left out,
    lowercased), with every run of the
    words of each path in `echoes` taken out first: a page that repeats the path it was asked for, as sent, decoded,
    HTML-escaped or without its leading slash, is still the same page whatever the path."""
    words, size = _words(body), -1
    paths = sorted({tuple(_words(item)) for item in echoes}, key=len, reverse=True)
    while size != len(words):   # again until nothing is left to take: taking one path out can join the words of another
        size = len(words)
        for echo in paths:
            words = _without(words, list(echo))
    weights = [0] * 64
    for word, count in Counter(words).items():
        value = int.from_bytes(hashlib.blake2b(word.encode(), digest_size=8).digest(), "big")
        for bit in range(64):
            weights[bit] += count if value >> bit & 1 else -count
    return sum(1 << bit for bit in range(64) if weights[bit] > 0)


def alike(first: int, second: int) -> bool:
    """Whether two simhashes are the same page: at most SOFT_404_BITS bits apart (a nonce, a date)."""
    return bin(first ^ second).count("1") <= SOFT_404_BITS


def soft_404(findings: list[Finding], signatures: dict[str, Signature], references: dict[str, str]) -> tuple[list[Finding], list[Finding]]:
    """(kept, dropped): a finding about one path (not the root, not a site-wide header) whose page answered exactly as
    a random path of its site does (same status, the same body once both paths are taken out of both bodies:
    `body_simhash`) proves nothing about that path: the site answers anything that way (a catch-all page, a soft 404),
    even when it echoes the path back. `references`: each root's random path (`page_of` of both), whose answer is the
    reference."""
    kept, dropped = [], []
    for finding in findings:
        page = page_of(str(finding.get("path") or ""))
        root = page_of(root_of(page)) if page else None
        reference = signatures.get(references.get(root or "", ""))
        mine = signatures.get(page or "")
        if page is None or urlsplit(page).path == "/" or site_level(str(finding.get("tool") or ""), str(finding.get("rule_id") or "")) \
                or reference is None or mine is None or reference[1] is None or mine[1] is None or mine[0] != reference[0]:
            kept.append(finding)
        elif alike(body_simhash(mine[1], (mine[2], reference[2])), body_simhash(reference[1], (mine[2], reference[2]))):
            dropped.append(finding)
        else:
            kept.append(finding)
    return kept, dropped


def skipped(key: str, reason) -> ToolRun:
    return ToolRun(key, "skipped", reason)

