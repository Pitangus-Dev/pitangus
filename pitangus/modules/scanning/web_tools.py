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

import json
import re
import subprocess
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from urllib.parse import urlsplit

from pitangus.modules.scanning import nuclei_templates
from pitangus.modules.scanning.engines import IMAGES, _base, _run, _stable, docker_problem, host_path, image_available, runner
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
INVENTORY_MAX = 500      # URLs kept from the crawl (stored with the run)
ZAP_SEEDS_MAX = 200      # of those, handed to ZAP
PAGES_MAX = 100          # of those, read by nuclei's page-level templates (pages, not scripts, styles or images)
ASSET = re.compile(r"(?i)\.(?:js|mjs|css|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|eot|mp4|webm|mp3|pdf|zip|gz)$")

NUCLEI_HOST_MINUTES = 10
NUCLEI_PAGE_MINUTES = 3
NUCLEI_STATS_SECONDS = 3600   # its statistics at the end only: the last line says how far it got
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
BUDGET = {"katana": (KATANA_TIMEOUT + KATANA_RETRY_SECONDS) // 60, "nuclei": NUCLEI_HOST_MINUTES + NUCLEI_PAGE_MINUTES + 2,
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
TESTSSL_FAMILY_TITLE = (("cipherlist_", "scanning.web.testssl.titles.ciphers"), ("cert_", "scanning.web.testssl.titles.certificate"))
NUCLEI_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
TECH_ROOT = "/http/technologies/"
# Informational results that describe rather than flag (the TLS versions offered, the certificate's issuer and names).
FACT_TAGS = frozenset({"discovery", "enum", "detect", "tech"})
FACT_TEMPLATES = frozenset({"ssl-dns-names", "ssl-issuer", "tls-version", "wildcard-tls"})
VERSION = re.compile(r"[0-9][0-9A-Za-z.+_-]{0,40}")
DETECT_SUFFIX = re.compile(r"\s*[-–]?\s*(?:version\s+)?(?:detect(?:ion)?|discovery)\s*$", re.IGNORECASE)
REFERENCES_MAX, REFERENCE_MAX, TEXT_MAX, TITLE_MAX = 8, 300, 2000, 300


class ToolRun:
    """What one tool did in a scan: its step for the run and what it found. `unreached`: the scope's hosts it couldn't
    check (a tool that exits 0 without reaching a host is not a clean result for that host)."""

    def __init__(self, key: str, status: str, detail, *, findings: list | None = None, duration: float | None = None,
                 unreached: list[str] | None = None):
        self.key, self.status, self.detail = key, status, detail
        self.findings: list[Finding] = findings or []
        self.duration = duration
        self.unreached = sorted(set(unreached or []))
        if self.unreached:
            self.status = "partial"
            self.detail = msg("scanning.web.tools.unreached", detail=detail, hosts=", ".join(self.unreached))

    def step(self) -> dict:
        meta = IMAGES[self.key]
        return {"id": f"dast-{self.key}", "name": msg(f"scanning.web.tools.{self.key}.name"), "status": self.status, "detail": self.detail,
                "tool": {"name": self.key, "version": meta["version"], "image": meta["image"], "duration_s": self.duration}}


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


def in_scope_url(value: Any, hosts: list[str]) -> str | None:
    """`value` as scheme, host and path when it is an https URL on one of `hosts` (no user, no other port), else None.
    The query string and the fragment are dropped: they carry the values a crawl varies, and sometimes tokens."""
    if not isinstance(value, str) or len(value) > URL_MAX:
        return None
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if parts.scheme.lower() != "https" or parts.username or parts.password or port not in (None, 443) or host not in hosts:
        return None
    path = "".join(ch for ch in (parts.path or "/") if ch.isprintable() and not ch.isspace()) or "/"
    if "${" in path:
        return None
    return f"https://{host}{path if path.startswith('/') else '/' + path}"


def host_of(target: Any) -> str:
    """The host name in what a tool prints as its target: a URL, `host:port` or a bare host."""
    value = str(target or "").strip().strip("\"'")
    value = value.split("://", 1)[-1].split("/", 1)[0].rsplit("@", 1)[-1]
    if value.count(":") == 1:
        value = value.rsplit(":", 1)[0]
    return value.lower().rstrip(".")


def _wrap(binary: str, arguments: list[str], headers) -> tuple[list[str], str | None, str | None]:
    """(arguments, entrypoint, stdin): with saved headers, a shell reads them from standard input into the
    container's memory-only /tmp and starts the tool with `-H` on that file."""
    if not headers:
        return arguments, None, None
    if any(any(character in f"{name}{value}" for character in "\r\n\0") for name, value in headers):
        raise ValueError("a header is one line")
    script = f'umask 077 && cat > {HEADERS_FILE} && exec {binary} "$@" -H {HEADERS_FILE}'
    return ["-c", script, binary, *arguments], "sh", "".join(f"{name}: {value}\n" for name, value in headers)


def _work(folder: Path, files: dict[str, str]) -> None:
    for name, content in files.items():
        (folder / name).write_text(content, encoding="utf-8")
        (folder / name).chmod(0o644)
    folder.chmod(0o755)


# --- katana ------------------------------------------------------------------------------------------------------


def katana_arguments(hosts: list[str], *, headless: bool = True) -> list[str]:
    arguments = ["-list", f"{WORK}/seeds.txt", "-d", str(KATANA_DEPTH), "-jc", "-kf", "all", "-ct", f"{KATANA_MINUTES}m",
                 "-fs", "fqdn", "-cs", host_regex(hosts), "-e", "private-ips", "-dr", "-iqp",
                 "-c", "4", "-p", "2", "-rl", str(RATE), "-timeout", "10", "-retry", "1", "-mrs", "2097152",
                 "-r", f"{WORK}/{RESOLVERS}", "-j", "-or", "-ob", "-silent", "-nc", "-duc"]
    if headless:
        # Its browser runs inside the container, which is its sandbox (Chromium's own needs privileges the container
        # doesn't have); whatever it asks for outside the scope goes to a proxy that isn't there.
        arguments += ["-hh", "-xhr", "-scp", "/usr/bin/chromium", "-nos", "-cdd", "/tmp/chromium",
                      "-ho", "--proxy-server=http://127.0.0.1:9", "-ho", "--proxy-bypass-list=" + ";".join(hosts)]
    return arguments


def parse_katana(output: str, hosts: list[str]) -> list[str]:
    """The in-scope URLs katana found (GET, not answered with an error), without query strings, sorted, at most INVENTORY_MAX."""
    found: set[str] = set()
    for line in output.splitlines()[:50_000]:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        request = entry.get("request") if isinstance(entry, dict) else None
        response = entry.get("response") if isinstance(entry, dict) else None
        if not isinstance(request, dict) or str(request.get("method") or "GET").upper() != "GET":
            continue
        if entry.get("error") and not isinstance(response, dict):
            continue  # asked for and never answered (a timeout, a refused connection)
        # A link the browser saw but didn't open has no response yet: ZAP and nuclei will ask for it.
        status = response.get("status_code") if isinstance(response, dict) else None
        if isinstance(status, int) and status >= 400:
            continue
        url = in_scope_url(request.get("endpoint"), hosts)
        if url:
            found.add(url)
    return sorted(found, key=lambda url: (url.count("/"), url))[:INVENTORY_MAX]


def katana_reached(output: str, hosts: list[str]) -> set[str]:
    """The hosts katana got anything from: a line without an error. One that only errored (an unreachable seed) or
    never shows up wasn't crawled, whatever katana's exit code says."""
    reached: set[str] = set()
    for line in output.splitlines()[:50_000]:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        request = entry.get("request") if isinstance(entry, dict) else None
        if not isinstance(request, dict) or (entry.get("error") and not isinstance(entry.get("response"), dict)):
            continue
        host = host_of(request.get("endpoint"))
        if host in hosts:
            reached.add(host)
    return reached


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
    if completed.returncode != 0 and not urls:
        return ToolRun("katana", "partial", msg("scanning.web.tools.failed", tool="katana"), duration=duration), []
    detail = "scanning.web.tools.katana.detail" if browser else "scanning.web.tools.katana.detail_plain"
    reached = katana_reached(output, hosts)
    seeded = sorted({host_of(url) for url in seeds} & set(hosts))
    return ToolRun("katana", "completed", msg(detail, count=len(urls), minutes=KATANA_MINUTES, depth=KATANA_DEPTH),
                   duration=duration, unreached=[host for host in seeded if host not in reached]), urls


# --- nuclei ------------------------------------------------------------------------------------------------------


def nuclei_arguments(folder: str, minutes: int, *, own: bool = False) -> list[str]:
    """Only the filtered templates (`nuclei_templates`; with `own`, Pitangus' own too), and nothing that could bring
    others back: no update, no out-of-band server, no redirects, no private addresses, the excluded protocols and tags
    again."""
    return ["-t", f"/templates/{folder}", *(["-t", f"{OWN_MOUNT}/{folder}"] if own else []), "-l", f"{WORK}/targets.txt", "-r", f"{WORK}/{RESOLVERS}",
            "-duc", "-ni", "-dr", "-lna", "-no-stdin", "-nc", "-jsonl", "-or", "-ot", "-stats", "-sj", "-si", str(NUCLEI_STATS_SECONDS),
            "-ept", NUCLEI_EXCLUDED_TYPES, "-etags", ",".join(sorted(nuclei_templates.DENY_TAGS)),
            "-rl", str(RATE), "-c", "10", "-bs", "5", "-timeout", "10", "-retries", "1", "-mt", f"{minutes}m"]


def _strings(value: Any, limit: int = 20) -> list[str]:
    items = value if isinstance(value, list) else [value] if isinstance(value, str) else []
    return [item.strip() for item in items if isinstance(item, str) and item.strip()][:limit]


def _clean(value: Any, limit: int = TEXT_MAX) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def _nuclei_location(entry: dict, hosts: list[str]) -> str | None:
    """The URL a result is at; a TLS result (`host:443`) is about its host's root."""
    for candidate in (entry.get("matched-at"), entry.get("url")):
        if url := in_scope_url(candidate, hosts):
            return url
    host = str(entry.get("host") or entry.get("matched-at") or "").lower()
    name = host.split("//")[-1].split("/")[0].rsplit(":", 1)[0]
    return f"https://{name}/" if entry.get("type") == "ssl" and name in hosts else None


def parse_nuclei(output: str, hosts: list[str]) -> tuple[list[Finding], list[dict]]:
    """nuclei's JSON lines as findings (one per template, matcher and URL), plus what its technology templates
    detected. What the template says (description, remediation, references, CWE, CVE) is kept as published; the
    request, the response, the curl line and the extracted values are never kept."""
    findings: list[Finding] = []
    technologies: list[dict] = []
    seen: set[str] = set()
    for line in output.splitlines()[:20_000]:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict) or not isinstance(entry.get("info"), dict):
            continue
        template = _clean(entry.get("template-id"), 200)
        location = _nuclei_location(entry, hosts)
        if not template or not location:
            continue
        info = entry["info"]
        matcher = _clean(entry.get("matcher-name"), 200)
        name = _clean(info.get("name"), TITLE_MAX) or template
        # Pitangus' own templates carry their Spanish text in `metadata`; the release's text stays as published.
        own = template.startswith(nuclei_templates.OWN_PREFIX) and str(entry.get("template-path") or "").startswith(OWN_MOUNT + "/")
        spanish = info.get("metadata") if own and isinstance(info.get("metadata"), dict) else {}
        tags = {tag.lower() for tag in _strings(info.get("tags"), 50)}
        severity = NUCLEI_SEVERITY.get(str(info.get("severity") or "").lower(), "info")
        # A version past its end of life is something to act on, not just a name: it stays a finding.
        if (TECH_ROOT in str(entry.get("template-path") or "") or "tech" in tags) and "eol" not in tags:
            # "nginx/1.27.5" or "1.27.5": the version is the last part.
            extracted = next((part for item in _strings(entry.get("extracted-results"), 5)
                              for part in [re.split(r"[/ ]", item)[-1]] if VERSION.fullmatch(part)), None)
            technologies.append({"name": matcher or DETECT_SUFFIX.sub("", name), "version": extracted, "host": urlsplit(location).hostname})
            continue
        if severity == "info" and "eol" not in tags and (tags & FACT_TAGS or template in FACT_TEMPLATES):
            continue  # what a certificate or a protocol is, not something to fix
        rule = f"{template}:{matcher}" if matcher else template
        key = "\x1f".join((rule, location, ""))
        if key in seen:
            continue
        seen.add(key)
        classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
        cwes = sorted({int(match) for item in _strings(classification.get("cwe-id")) for match in re.findall(r"(?i)cwe-0*(\d{1,5})", item)})
        cves = sorted({item.upper() for item in _strings(classification.get("cve-id")) if re.fullmatch(r"(?i)CVE-\d{4}-\d{4,}", item)})
        references = [item for item in _strings(info.get("reference"), REFERENCES_MAX) if item.startswith(("https://", "http://"))
                      and len(item) <= REFERENCE_MAX]
        description, remediation = _clean(info.get("description")), _clean(info.get("remediation"))
        title = (f"{name} ({matcher})" if matcher else name)[:TITLE_MAX]
        shown: Any = title
        if own:
            es = _clean(spanish.get("pitangus-name-es"), TITLE_MAX)
            shown = inline({"en": title, "es": (f"{es} ({matcher})" if matcher else es)[:TITLE_MAX]})
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
        findings.append(finding)
    return findings, technologies


def nuclei_log(log: str, hosts: list[str]) -> tuple[set[str], bool]:
    """What nuclei's log says it couldn't do: the scope's hosts it skipped as unresponsive or where a template couldn't
    run, and whether the pass is incomplete (any of those, or its last statistics short of 100%)."""
    unreached: set[str] = set()
    incomplete = False
    percent: int | None = None
    for line in log.splitlines()[:100_000]:
        line = line.strip()
        if line.startswith("{"):
            try:
                stats = json.loads(line)
                if isinstance(stats, dict) and "percent" in stats:
                    percent = int(str(stats["percent"]))
            except ValueError:
                pass
            continue
        match = NUCLEI_SKIPPED.search(line) or NUCLEI_UNEXECUTED.search(line)
        if match:
            incomplete = True
            if (host := host_of(match.group(1))) in hosts:
                unreached.add(host)
    return unreached, incomplete or (percent is not None and percent < 100)


def run_nuclei(roots: list[str], pages: list[str], hosts: list[str], pins: dict[str, str], work: Path, cache_dir: Path, *,
               headers=(), scrub=lambda text: text) -> tuple[ToolRun, list[dict]]:
    """Two passes: every allowed template on each host's root, then the page-level ones on the crawled URLs (one
    request per URL: nuclei folds templates that ask for the same page)."""
    _pins_ok(pins, hosts)
    started = time.time()
    try:
        templates, counts = nuclei_templates.ensure(cache_dir)
    except nuclei_templates.TemplatesError:
        return ToolRun("nuclei", "skipped", msg("scanning.web.tools.nuclei.no_templates", release=nuclei_templates.RELEASE)), []
    own, own_counts = nuclei_templates.ensure_own(cache_dir)
    findings: list[Finding] = []
    technologies: list[dict] = []
    status, notes = "completed", 0
    unreached: set[str] = set()
    documents = [url for url in pages if url not in roots and not ASSET.search(urlsplit(url).path)][:PAGES_MAX]
    passes = [("hosts", roots, NUCLEI_HOST_MINUTES), *([("pages", documents, NUCLEI_PAGE_MINUTES)] if documents else [])]
    for folder_name, targets, minutes in passes:
        with TemporaryDirectory(prefix="nuclei-", dir=work) as temporary:
            folder = Path(temporary)
            _work(folder, {"targets.txt": "".join(f"{url}\n" for url in targets), RESOLVERS: f"{DEAD_RESOLVER}\n"})
            mine = own is not None and (own / folder_name).is_dir()
            arguments, entrypoint, stdin = _wrap("nuclei", nuclei_arguments(folder_name, minutes, own=mine), headers)
            try:
                completed = _run("nuclei", arguments, None, network=True,
                                 mounts=["-v", f"{host_path(folder)}:{WORK}:ro", "-v", f"{host_path(templates)}:/templates:ro",
                                         *(["-v", f"{host_path(own)}:{OWN_MOUNT}:ro"] if mine and own is not None else [])],
                                 timeout=(minutes + 2) * 60, hosts={host: pins[host] for host in hosts}, pinned_only=True,
                                 entrypoint=entrypoint, stdin=stdin)
            except (subprocess.TimeoutExpired, OSError, ValueError):
                status, notes = "partial", notes + 1
                continue
        if completed.returncode != 0:
            status, notes = "partial", notes + 1
        skipped, incomplete = nuclei_log(scrub(completed.stderr or "")[:OUTPUT_MAX], hosts)
        unreached |= skipped
        if incomplete:
            status, notes = "partial", notes + 1
        found, detected = parse_nuclei(scrub(completed.stdout or "")[:OUTPUT_MAX], hosts)
        findings += found
        technologies += detected
    unique = {finding["fingerprint"]: finding for finding in findings}
    detail = msg("scanning.web.tools.nuclei.detail_own", release=nuclei_templates.RELEASE, templates=counts.get("hosts", 0),
                 own=own_counts.get("hosts", 0), pages=len(documents), count=len(unique), rate=RATE)
    return ToolRun("nuclei", status, detail, findings=list(unique.values()), duration=round(time.time() - started, 1),
                   unreached=sorted(unreached)), technologies


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


def parse_testssl(document: Any, host: str) -> list[Finding]:
    """testssl.sh's JSON (flat list) as findings: only what it rates LOW or worse, one per check; the per-cipher lines
    of a weak family are folded into that family's finding as its evidence."""
    if not isinstance(document, list):
        return []
    path = f"https://{host}/"
    ciphers = [str(item.get("finding") or "").split()[2] for item in document[:5000]
               if isinstance(item, dict) and str(item.get("id") or "").startswith("cipher-") and item.get("severity") in TESTSSL_SEVERITY
               and len(str(item.get("finding") or "").split()) > 2]
    findings: list[Finding] = []
    for item in document[:5000]:
        if not isinstance(item, dict):
            continue
        identifier = _clean(item.get("id"), 100)
        severity = TESTSSL_SEVERITY.get(str(item.get("severity") or ""))
        if not identifier or severity is None or TESTSSL_SKIPPED.match(identifier):
            continue
        text = _clean(item.get("finding"), 500)
        evidence = text + (" · " + ", ".join(ciphers[:20]) if identifier.startswith("cipherlist_") and ciphers else "")
        cwes = sorted({int(number) for number in re.findall(r"(?i)cwe-0*(\d{1,5})", str(item.get("cwe") or ""))})
        cves = sorted({value.upper() for value in re.findall(r"(?i)CVE-\d{4}-\d{4,}", str(item.get("cve") or ""))})
        finding = _base("dast", identifier, _testssl_title(identifier), path, 1, severity, tool="testssl",
                        reason=msg("scanning.web.testssl.reason", check=identifier, host=host, finding=text),
                        remediation=msg("scanning.web.remediation", tool="testssl.sh"),
                        cwe=cwes, owasp="", confidence=8, digest=_stable("sarif", "testssl", "\x1f".join((identifier, path, ""))))
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
    started = time.time()
    findings: list[Finding] = []
    targets, failed = hosts[:TESTSSL_HOSTS_MAX], 0
    unreached: list[str] = []
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
        if completed is None or not testssl_finished(document):
            failed += 1
            unreached.append(host)
        findings += parse_testssl(document, host)
    status = "partial" if failed or len(hosts) > len(targets) else "completed"
    detail = msg("scanning.web.tools.testssl.detail", hosts=", ".join(targets), count=len(findings))
    if len(hosts) > len(targets):
        detail = msg("scanning.web.tools.testssl.detail_capped", hosts=", ".join(targets), count=len(findings), max=TESTSSL_HOSTS_MAX,
                     total=len(hosts))
    return ToolRun("testssl", status, detail, findings=findings, duration=round(time.time() - started, 1), unreached=unreached)


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


def run_httpx(hosts: list[str], pins: dict[str, str], work: Path) -> tuple[ToolRun, list[dict]]:
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
    detected = parse_httpx(output, hosts)
    status = "completed" if completed.returncode == 0 else "partial"
    names = technologies_of(detected)
    answered = httpx_answered(output, hosts)
    return ToolRun("httpx", status, msg("scanning.web.tools.httpx.detail", count=len(names), hosts=", ".join(hosts)),
                   duration=round(time.time() - started, 1), unreached=[host for host in hosts if host not in answered]), detected


def skipped(key: str, reason) -> ToolRun:
    return ToolRun(key, "skipped", reason)

