"""Passive web and API scans of a verified domain with ZAP: a spider, the AJAX spider (or an OpenAPI import) and the
passive rules, never an attack.

ZAP crawls the site and reads its responses (headers, cookies, information leaks, PII); its active scanner and form
submissions stay off. The AJAX spider (a headless Firefox, `ajax_spider`) only follows links: it clicks no button,
fills no input and stays in the scope's context. In API mode it imports the definition too, reduced beforehand
to its GET and HEAD operations (`openapi_spec`), so every request is one a browser could send.

Time: the classic spider gets SPIDER_MINUTES (plus EXTRA_SPIDER_MINUTES per listed host), the AJAX spider
AJAX_MINUTES, and each test user LOGIN_SPIDER_MINUTES and AJAX_MINUTES more; the container's limit is TIMEOUT plus
all of those (`scan_domain`).

Before it starts, the caller has confirmed the domain's proof and resolved every host of the scope to public
addresses only; the container gets those addresses pinned (`--add-host`) and a DNS server that answers nothing, so
ZAP never resolves a name on its own (no DNS rebinding between the check and the scan, and no host outside the
scope). The plan's context holds the scope's hosts and nothing else: links and redirects elsewhere are seen, not
followed. Wildcards (`*.example.com`) only widen that context; hosts reached through them don't resolve.

The plan reaches ZAP on its standard input and is written inside the container's memory-only home: the headers a
domain saved (API keys, tokens, cookies) go into it, never into a file on the host, the command line or the logs.
Test users sign in with ZAP's browser-based authentication, each in a context of its own (its login page). Each
sign-in is checked first, alone in a ZAP of its own so its result is about that user (its check page, else ZAP's
authentication report); a spider (or the OpenAPI import) then runs as each one that signed in. Their usernames,
passwords and TOTP seeds aren't in the plan, only `${PITANGUS_LOGIN_<n>_…}` references: they come first on the
container's standard input and a wrapper exports them to ZAP's processes only, never `docker run -e` (which
`docker inspect` shows), a command line or a file. Whatever ZAP returns is scrubbed of all those values.

The container is the only engine that reaches the internet on purpose. It runs as the image's own user (ZAP's Java
needs a home from passwd), with no capabilities, no privilege escalation, a read-only root, memory and CPU caps and
an explicit heap. The residual risks are written down in docs/security.md.

The SARIF it writes goes through the same parser as `import-sarif`: a native scan and an import of the same site
share fingerprints, so neither duplicates the other.
"""

from __future__ import annotations

import http.client
import json
import re
import subprocess
import time
from pathlib import Path
from secrets import token_hex
from tempfile import TemporaryDirectory
from typing import Any
from urllib.parse import urlsplit

import yaml

from pitangus.modules.scanning import engine_contract, openapi_spec, sarif_import, web_merge, web_seeds, web_tools, web_versions
from pitangus.modules.scanning.engines import IMAGES, _run, host_path, with_cause
from pitangus.modules.sources import domains
from pitangus.shared import log as logging_setup
from pitangus.shared.i18n import MARK, is_msg, msg
from pitangus.shared.model import Message, RunRecord

_log = logging_setup.get("web")
SPIDER_MINUTES = 2
EXTRA_SPIDER_MINUTES = 1   # each listed host besides the domain's own
PASSIVE_MINUTES = 5
SESSION_SECONDS = 15   # the saved headers' session check, before and after the scan
TIMEOUT = 15 * 60
# Under the container's 3 GB: zap.sh would otherwise take a quarter of the host's memory.
HEAP = "-Xmx1536m"
# ZAP keeps its configuration and session (HSQLDB) in $HOME/.ZAP; the image's user is uid 1000.
HOME = "/home/zap:rw,noexec,nosuid,nodev,size=512m,uid=1000,gid=1000,mode=0700"
# Signing in drives Firefox through geckodriver, which ZAP unpacks into that home and runs from there.
HOME_EXEC = HOME.replace("noexec", "exec")
# The AJAX spider drives Firefox through that geckodriver too: without test users, only ZAP's webdriver folder is
# executable and the rest of its home stays noexec. Its parent is a tmpfs of its own so that ZAP's user owns it.
DRIVERS = ["--tmpfs", "/home/zap/.ZAP:rw,noexec,nosuid,nodev,size=448m,uid=1000,gid=1000,mode=0700",
           "--tmpfs", "/home/zap/.ZAP/webdriver:rw,exec,nosuid,nodev,size=64m,uid=1000,gid=1000,mode=0700"]
PLAN = "/home/zap/plan.yaml"   # in that tmpfs: the plan carries the saved headers
WORK = "/zap/wrk"
REPORT = "zap.json"
SPEC = "spec.json"
SEEDS = "seeds.txt"         # the inventory's URLs (katana, robots.txt, sitemaps, the definition), for ZAP to request
EXPORT = "urls.txt"         # the URLs ZAP's spider reached, one a line, for the inventory
TREE = "tree.yaml"          # ZAP's sites tree: each URL it requested and the status it got (its own evidence)
REACHED_MAX = 5000          # pages kept with the run as reached: past it, unlisted pages aren't marked fixed
EXPORT_MAX = 5_000_000
SEED_SECONDS = 2           # more time for ZAP per URL it is handed
CONTEXT = "pitangus"
SEVERITIES = ("critical", "high", "medium", "low", "info")
SCRUB_MIN = 6               # shorter header values aren't secrets, and scrubbing them would mangle the findings
REDACTED = "[redacted]"
LOGIN_SPIDER_MINUTES = 2   # each test user's own crawl
LOGIN_WAIT = 5             # seconds ZAP waits after submitting the login form
BROWSER = "firefox-headless"
# The field a sign-in page asks the authenticator code in, after the password: how sites usually name it.
TOTP_FIELD = ", ".join(f"input{match}:not([type='hidden'])" for match in (
    "[autocomplete='one-time-code']", "[name*='otp' i]", "[id*='otp' i]", "[name*='mfa' i]", "[id*='mfa' i]", "[name*='2fa' i]",
    "[name*='code' i]", "[id*='code' i]"))
TOTP_WAIT_MS = 15_000
SECRET_NAME = re.compile(r"PITANGUS_LOGIN_[0-9]+_[A-Z]+")
CHECK_PLAN = "/home/zap/check-{}.yaml"
CHECK_MARK = "PITANGUS-SIGN-IN-CHECK"
CHECK_SECONDS = 150        # one test user's sign-in check, ZAP's start included
AJAX_MINUTES = 2           # the AJAX spider, anonymous and again as each test user
AJAX_DEPTH = 5
AJAX_STATES = 100          # distinct page states it may visit
# Passive rules set explicitly (the image bundles pscanrules and retire, not pscanrulesBeta or pscanrulesAlpha):
# id → (name, threshold). Every other rule of the image keeps its default.
PASSIVE_RULES = {
    10003: ("Vulnerable JS Library", "Medium"),
    10023: ("Information Disclosure - Debug Error Messages", "Medium"),
    10024: ("Information Disclosure - Sensitive Information in URL", "Medium"),
    10025: ("Information Disclosure - Sensitive Information in HTTP Referrer Header", "Medium"),
    10027: ("Information Disclosure - Suspicious Comments", "Medium"),
    10062: ("PII Disclosure", "Medium"),
    10009: ("In Page Banner Information Leak", "Medium"),
    10036: ("Server Leaks Version Information via Server HTTP Response Header Field", "Medium"),
    10037: ("Server Leaks Information via X-Powered-By HTTP Response Header Field(s)", "Medium"),
    10039: ("X-Backend-Server Header Information Leak", "Medium"),
    10052: ("X-ChromeLogger-Data (XCOLD) Header Information Leak", "Medium"),
    10056: ("X-Debug-Token Information Leak", "Medium"),
    10061: ("X-AspNet-Version Response Header", "Medium"),
    2: ("Private IP Disclosure", "Medium"),
    3: ("Session ID in URL Rewrite", "Medium"),
    10097: ("Hash Disclosure", "Medium"),
    10109: ("Modern Web Application", "Medium"),
}


class WebScanError(ValueError):
    """A web scan that couldn't run; `message` is a catalog message."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


def start_url(record: dict) -> str:
    """The registered URL when it is on the registered host; the host's root otherwise."""
    host, url = record["host"], record.get("url") or ""
    try:
        parts = urlsplit(url)
        same = parts.scheme == "https" and (parts.hostname or "").lower() == host and parts.port is None
    except ValueError:
        same = False
    # ZAP reads `${…}` as a variable, and the test users' secrets are some: never in a URL of the plan.
    return url if same and not parts.query and not parts.fragment and "${" not in url else f"https://{host}/"


def host_pattern(host: str) -> str:
    return f"https://{re.escape(host)}(?:[/?].*)?"


def wildcard_pattern(wildcard: str) -> str:
    """`*.example.com` → any subdomain of example.com (one label or more), never example.com itself."""
    return f"https://(?:[a-z0-9-]+\\.)+{re.escape(wildcard.removeprefix('*.'))}(?:[/?].*)?"


def login_variables(index: int, totp: bool) -> dict[str, str]:
    """The environment variables that carry test user `index`'s secrets (1-based)."""
    prefix = f"PITANGUS_LOGIN_{index}_"
    return {"username": f"{prefix}USERNAME", "password": f"{prefix}PASSWORD", **({"totp": f"{prefix}TOTP"} if totp else {})}


def _login_context(index: int, user: dict, urls: list[str], patterns: list[str]) -> dict:
    """One test user's context: the scope's hosts, ZAP's browser-based sign-in on its login page, and the session
    handling and logged-in check that ZAP detects. Credentials are references to the environment, never values."""
    names = login_variables(index, bool(user.get("totp")))
    credentials: dict[str, Any] = {"username": f"${{{names['username']}}}", "password": f"${{{names['password']}}}"}
    parameters: dict[str, Any] = {"loginPageUrl": user["login_url"], "loginPageWait": LOGIN_WAIT, "browserId": BROWSER}
    if user.get("totp"):
        credentials["totp"] = {"secret": f"${{{names['totp']}}}", "period": user["totp"]["period"],
                               "digits": user["totp"]["digits"], "algorithm": user["totp"]["algorithm"]}
        # ZAP's own steps fill the username and password and submit them; the code field only gets a step of its own.
        parameters["steps"] = [{"description": "username and password", "type": "AUTO_STEPS"},
                               {"description": "TOTP code", "type": "TOTP_FIELD", "cssSelector": TOTP_FIELD, "timeout": TOTP_WAIT_MS},
                               {"description": "submit the code", "type": "RETURN", "cssSelector": TOTP_FIELD, "timeout": TOTP_WAIT_MS}]
    return {"name": f"{CONTEXT}-login-{index}", "urls": urls, "includePaths": patterns,
            "authentication": {"method": "browser", "parameters": parameters, "verification": {"method": "autodetect"}},
            "sessionManagement": {"method": "autodetect"},
            "users": [{"name": f"login-{index}", "credentials": credentials}]}


def passive_config() -> dict:
    """The passive scanner: only what is in the scope's contexts, every rule of the image at its default, and the
    information-leak rules in `PASSIVE_RULES` set explicitly so an image or add-on update can't turn them off."""
    return {"type": "passiveScan-config", "parameters": {"scanOnlyInScope": True, "enableTags": False, "disableAllRules": False},
            "rules": [{"id": rule, "name": name, "threshold": threshold} for rule, (name, threshold) in PASSIVE_RULES.items()]}


def ajax_spider(context: str, url: str, *, user: str | None = None) -> dict:
    """ZAP's AJAX spider: one headless Firefox that follows links only. It clicks `<a>` elements and nothing else (no
    buttons, no form inputs, no random values), stays inside the context, avoids logout links and stops after
    `AJAX_MINUTES`. What the pages' own scripts request when they load is what any visitor's browser would."""
    return {"type": "spiderAjax", "parameters": {
        "context": context, **({"user": user} if user else {}), "url": url, "maxDuration": AJAX_MINUTES, "maxCrawlDepth": AJAX_DEPTH,
        "maxCrawlStates": AJAX_STATES, "numberOfBrowsers": 1, "browserId": BROWSER, "inScopeOnly": True, "scopeCheck": "Strict",
        "runOnlyIfModern": False, "enableExtensions": False, "clickDefaultElems": False, "elements": ["a"], "clickElemsOnce": True,
        "randomInputs": False, "logoutAvoidance": True}}


def plan(host: str, url: str, *, hosts=(), wildcards=(), excluded=(), headers=(), api: dict | None = None, users=(),
         seeds: str | None = None, export: str | None = None, tree: str | None = None) -> dict:
    """The Automation Framework plan: the passive scanner's configuration, then inside a context of the scope's hosts
    only, a spider per listed host and the AJAX spider from `url` (plus the OpenAPI import in API mode) and the
    passive rules; with `headers`, a replacer that adds them to requests for
    those hosts only. `excluded`: hosts saved out of the domain's scope, kept out of the context even if a wildcard
    would match them. With `users` ({login_url, start, totp}), one more context per test user (the same hosts) that
    signs in through a browser, and a spider, an AJAX spider (and the import) that run as that user. `seeds`: a file (in the
    container) of in-scope URLs the crawler found, each requested with a GET before the spider starts. `export`: a file
    (in the container) where ZAP writes every URL it requested (source `all`: its history alone lacks the spider's), once it's done, for the scan's inventory.
    `tree`: a file (in the container) for ZAP's sites tree, each URL with the status ZAP got: no header, no body."""
    extra = [item for item in hosts if item != host]
    excluded = [item for item in excluded if item != host and item not in extra]
    patterns = [host_pattern(host), *(host_pattern(item) for item in extra), *(wildcard_pattern(item) for item in wildcards)]
    jobs: list[dict[str, Any]] = [passive_config()]
    if headers:
        scope = patterns[0] if len(patterns) == 1 else "(?:" + "|".join(patterns) + ")"
        jobs.append({"type": "replacer", "parameters": {"deleteAllRules": True},
                     "rules": [{"description": f"pitangus header {index + 1}", "url": scope, "matchType": "req_header",
                                "matchString": name, "matchRegex": False, "replacementString": value, "tokenProcessing": False}
                               for index, (name, value) in enumerate(headers)]})
    if seeds:
        jobs.append({"type": "import", "parameters": {"type": "url", "fileName": seeds}})
    # The spec adds the documented endpoints to the crawl, it doesn't replace it: a site and its API are one target.
    jobs.append({"type": "spider", "parameters": {"context": CONTEXT, "url": url, "maxDuration": SPIDER_MINUTES, "maxDepth": 5,
                                                  "threadCount": 2, "postForm": False, "acceptCookies": True}})
    jobs += [{"type": "spider", "parameters": {"context": CONTEXT, "url": f"https://{item}/", "maxDuration": EXTRA_SPIDER_MINUTES,
                                               "maxDepth": 5, "threadCount": 2, "postForm": False, "acceptCookies": True}}
             for item in extra]
    jobs.append(ajax_spider(CONTEXT, url))
    start = list(dict.fromkeys([url, *(f"https://{item}/" for item in extra), *([api["target"]] if api is not None else [])]))
    contexts = [{"name": CONTEXT, "urls": start, "includePaths": patterns}]
    for index, user in enumerate(users, start=1):
        contexts.append(_login_context(index, user, start, patterns))
        jobs.append({"type": "spider", "parameters": {"context": f"{CONTEXT}-login-{index}", "user": f"login-{index}", "url": user["start"],
                                                      "maxDuration": LOGIN_SPIDER_MINUTES, "maxDepth": 5, "threadCount": 2,
                                                      "postForm": False, "acceptCookies": True}})
        jobs.append(ajax_spider(f"{CONTEXT}-login-{index}", user["start"], user=f"login-{index}"))
    for context in contexts:
        # Saved headers or a test user carry a session: a sign-out link would end it halfway through the crawl.
        paths = [host_pattern(item) for item in excluded] + ([web_tools.LOGOUT_ZAP] if headers or users else [])
        if paths:
            context["excludePaths"] = paths
    if api is not None:
        # With test users the definition is imported as each of them; anonymous callers are the spider's part.
        jobs += [{"type": "openapi", "parameters": {"apiFile": api["file"], "context": f"{CONTEXT}-login-{index}", "user": f"login-{index}",
                                                    "targetUrl": api["target"]}} for index in range(1, len(users) + 1)] \
            or [{"type": "openapi", "parameters": {"apiFile": api["file"], "context": CONTEXT, "targetUrl": api["target"]}}]
    jobs.append({"type": "passiveScan-wait", "parameters": {"maxDuration": PASSIVE_MINUTES}})
    if export:
        jobs.append({"type": "export", "parameters": {"context": CONTEXT, "type": "url", "source": "all", "fileName": export}})
    if tree:
        jobs.append({"type": "export", "parameters": {"context": CONTEXT, "type": "yaml", "source": "sitestree", "fileName": tree}})
    jobs.append({"type": "report", "parameters": {"template": "sarif-json", "reportDir": WORK, "reportFile": "zap"}})
    return {"env": {"contexts": contexts, "parameters": {"failOnError": True, "failOnWarning": False, "progressToStdout": True}},
            "jobs": jobs}


def plan_text(host: str, url: str, **options) -> str:
    # JSON is YAML: serialized, never assembled, so nothing in a host, a URL or a header can add a key or a job.
    return json.dumps(plan(host, url, **options), indent=2) + "\n"


def run_zap(text: str | None, pins: dict[str, str], work: Path, *, timeout: int = TIMEOUT, secrets: dict[str, str] | None = None,
            checks=()) -> subprocess.CompletedProcess:
    """ZAP over a fresh work folder only it writes to (its user isn't ours): the plan in through standard input
    (into its memory-only home), the SARIF out. `pins`: every host it may reach, with its checked address.

    `secrets`: the test users' secrets the plans refer to as `${NAME}`. They come first on standard input, one per
    line, and the wrapper exports them to ZAP's own processes only: never `docker run -e` (which `docker inspect`
    shows), a command line, a file or a log. `checks`: one-line plans run one after another before the main plan
    (or instead of it, without `text`), each after a `CHECK_MARK-<n>` line on standard output."""
    secrets = dict(secrets or {})
    if any(not SECRET_NAME.fullmatch(name) or any(character in value for character in "\r\n\0") for name, value in secrets.items()):
        raise ValueError("a secret is one line, under a PITANGUS_LOGIN_ name")
    if any("\n" in check for check in checks):
        raise ValueError("a check plan is one line")
    work.chmod(0o777)
    # `umask 077`: what lands in the tmpfs is readable by ZAP's user only. All of standard input is read before ZAP
    # starts; `IFS= read -r` keeps each value exactly as it was sent.
    reads = ["umask 077", *(f"IFS= read -r {name} && export {name}" for name in secrets),
             *(f"IFS= read -r line && printf '%s\\n' \"$line\" > {CHECK_PLAN.format(index)}" for index in range(1, len(checks) + 1)),
             *([f"cat > {PLAN}"] if text is not None else [])]
    runs = [f'echo {CHECK_MARK}-{index}; zap.sh "$@" {CHECK_PLAN.format(index)} < /dev/null' for index in range(1, len(checks) + 1)]
    runs.append(f'exec zap.sh "$@" {PLAN}' if text is not None else f"echo {CHECK_MARK}-end")
    command = ["sh", "-c", " && ".join(reads) + " && { " + "; ".join(runs) + "; }", "zap.sh", HEAP, "-cmd", "-silent", "-autorun"]
    stdin = "".join(f"{value}\n" for value in secrets.values()) + "".join(f"{check}\n" for check in checks) + (text or "")
    home = HOME_EXEC if secrets or checks else HOME
    drivers = [] if home == HOME_EXEC else DRIVERS
    return _run("zap", command, None, network=True, mounts=["-v", f"{host_path(work)}:{WORK}:rw", "--tmpfs", home, *drivers],
                timeout=timeout, hosts=pins, pinned_only=True, image_user=True, stdin=stdin)


def check_plan(index: int, user: dict, urls: list[str], patterns: list[str]) -> dict:
    """One test user's sign-in check, alone in its ZAP so what ZAP reports is about it: sign in, ask for its check
    page (or where its crawl starts) as that user, and ZAP's authentication report for its login host."""
    target = user.get("check_url") or user["start"]
    request: dict[str, Any] = {"url": target, **({"responseCode": 200} if user.get("check_url") else {})}
    host = urlsplit(user["login_url"]).hostname or ""
    return {"env": {"contexts": [_login_context(index, user, urls, patterns)],
                    "parameters": {"failOnError": False, "failOnWarning": False, "progressToStdout": True}},
            "jobs": [{"type": "requestor", "parameters": {"user": f"login-{index}"}, "requests": [request]},
                     {"type": "passiveScan-wait", "parameters": {"maxDuration": 1}},
                     {"type": "report", "parameters": {"template": "auth-report-json", "reportDir": WORK, "reportFile": f"auth-{index}"},
                      "sections": ["summary"], "sites": [f"https://{host}"]}]}


def sign_in_outcome(user: dict, report: dict | None, output: str) -> dict:
    """Whether a test user's check signed in: its check page answering 200 when it has one (a redirect to the login,
    401 or 403 means it didn't), else ZAP's authentication report. The reason quotes ZAP as it wrote it."""
    summary = {item.get("key"): item for item in (report or {}).get("summaryItems") or [] if isinstance(item, dict)}
    passed = summary.get("auth.summary.auth", {}).get("passed")
    zap = "; ".join(str(item["description"]) for item in (report or {}).get("failureReasons") or []
                    if isinstance(item, dict) and item.get("description"))[:300]
    failed = None
    if user.get("check_url"):
        code = re.search(r"Expected\s*:\s*200\s+Received\s*:\s*(\d{3})", output)
        if code:
            failed = (msg("scanning.web.login.check_status_zap", url=user["check_url"], status=code.group(1), reason=zap) if zap
                      else msg("scanning.web.login.check_status", url=user["check_url"], status=code.group(1)))
        elif "Error sending message" in output or "requesting URL" not in output:
            failed = msg("scanning.web.login.check_unreached", url=user["check_url"])
    elif passed is False:
        failed = msg("scanning.web.login.zap_failed", reason=zap) if zap else msg("scanning.web.login.unconfirmed")
    elif passed is not True:
        failed = msg("scanning.web.login.unconfirmed")
    return {"name": user["name"], "status": "failed" if failed else "signed_in", "reason": failed}


def _segments(output: str, count: int) -> list[str]:
    """Each check's part of standard output, between its marker and the next."""
    parts, current, index = [""] * count, None, 0
    for line in output.splitlines():
        marker = re.fullmatch(rf"{CHECK_MARK}-(\d+|end)", line.strip())
        if marker:
            index = int(marker.group(1)) if marker.group(1).isdigit() else 0
            current = index - 1 if 0 < index <= count else None
        elif current is not None:
            parts[current] += line + "\n"
    return parts


def _no_stray_variables(planned: dict) -> None:
    """ZAP replaces every `${NAME}` in a plan from its environment: only the test users' credentials may refer to it,
    never a definition's path, a saved header or a URL that would send their secrets somewhere else."""
    if "${" in json.dumps({**planned, "env": {**planned["env"], "contexts": [
            {key: value for key, value in context.items() if key != "users"} for context in planned["env"]["contexts"]]}}):
        raise WebScanError(msg("scanning.web.errors.variable"))


def secret_parts(headers) -> list[str]:
    """What to scrub for each saved header: its whole value and the pieces a tool may echo alone (the token after
    `Bearer`, each cookie's value), longest first so a piece never leaves part of a longer match behind."""
    found: set[str] = set()
    for _, value in headers:
        found.add(value)
        for segment in re.split(r"[;,]", value):
            # `name=value` pairs (cookies) keep their names: a finding is often about one cookie.
            pieces = [segment.split("=", 1)[1]] if "=" in segment else segment.split()
            found.update(piece.strip() for piece in pieces if len(piece.strip()) >= 8)
    return sorted((item for item in found if len(item) >= SCRUB_MIN), key=len, reverse=True)


def scrub(value, secrets: list[str]):
    """`value` with every secret replaced, in every string of any structure (catalog messages included)."""
    if not secrets:
        return value
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, REDACTED)
        return value
    if isinstance(value, dict):
        return {key: scrub(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [scrub(item, secrets) for item in value]
    return value


def _plan_failure(completed: subprocess.CompletedProcess) -> subprocess.CompletedProcess:
    """ZAP prints why its plan failed on stdout, after «Automation plan failures:»; that line is the cause to show
    (Java's stderr ends with a stack trace instead)."""
    lines = [line.strip() for line in (completed.stdout or "").splitlines()]
    if "Automation plan failures:" in lines:
        reason = next((line for line in lines[lines.index("Automation plan failures:") + 1:] if line), "")
        if reason:
            return subprocess.CompletedProcess(completed.args, completed.returncode, completed.stdout, reason)
    return completed


def _text(path: Path) -> str:
    """A text file a tool wrote in its work folder, or "" when it's missing or too large."""
    try:
        if path.is_file() and not path.is_symlink() and path.stat().st_size <= EXPORT_MAX:
            return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    return ""


def _read(path: Path) -> dict | None:
    try:
        if not path.is_file() or path.stat().st_size > sarif_import.MAX_BYTES:
            return None
        document = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    return document if isinstance(document, dict) else None


def findings_from(document: dict, host: str, *, scope: dict | None = None) -> tuple[list, str | None, int]:
    """The SARIF's web findings inside the scope (`host` alone by default), as `import-sarif` would store them; also
    ZAP's version and the results read. Anything about another host is dropped: the scan vouches only for those."""
    scope = scope or {"hosts": [host], "wildcards": []}
    try:
        parsed = sarif_import.parse(document)
    except sarif_import.SarifError as exc:
        raise WebScanError(msg("scanning.web.errors.unreadable")) from exc
    findings, seen, version, results = [], set(), None, 0
    for run in parsed:
        version = version or run["version"]
        results += run["results"]
        for finding in run["findings"]:
            try:
                inside = domains.in_scope(urlsplit(finding["path"]).hostname or "", scope)
            except ValueError:
                inside = False
            if finding["scanner"] == "dast" and inside and finding["fingerprint"] not in seen:
                seen.add(finding["fingerprint"])
                findings.append(finding)
    return findings, version, results


def session_alive(url: str, pins: dict[str, str], headers) -> tuple[bool, Message]:
    """Whether the domain's session check page (`domain_headers.set_check`) answers 2xx with the saved headers, and
    what to say about it. A redirect (to the login), 401 or 403 means the headers no longer sign in."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    if host not in pins:
        return False, msg("scanning.web.session.outside", url=url)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    try:
        status, _ = domains.https_get(host, pins[host], path, limit=0, seconds=SESSION_SECONDS, headers=headers)
    except (OSError, http.client.HTTPException):
        return False, msg("scanning.web.session.unreached", url=url)
    if 200 <= status < 300:
        return True, msg("scanning.web.session.answered", url=url, status=status)
    return False, msg("scanning.web.session.status", url=url, status=status)


def coverage_key(api: dict | None, headers, users=()) -> str:
    """What a scan looked at, for the registry: a scan only marks fixed what a scan like it had seen (an anonymous
    crawl can't vouch for pages behind a login, nor one definition for another's endpoints)."""
    return ("api:" + api["sha256"][:16] if api else "baseline") + ("+headers" if headers else "") + ("+login" if users else "")


def login_plan(users, host: str, url: str) -> tuple[list[dict], dict[str, str]]:
    """For each test user (`test_users.credentials`), what the plan says about it (login page, where its crawl
    starts, the TOTP settings without the seed) and the environment that carries its secrets."""
    planned, environment = [], {}
    for index, user in enumerate(users, start=1):
        totp = user.get("totp") or None
        own = user["applies_to"]
        planned.append({"name": user["name"], "login_url": user.get("login_url") or f"https://{own}/",
                        "start": url if own == host else f"https://{own}/", "check_url": user.get("check_url") or None,
                        "totp": {key: totp[key] for key in ("digits", "period", "algorithm")} if totp else None})
        names = login_variables(index, bool(totp))
        environment[names["username"]], environment[names["password"]] = user["username"], user["password"]
        if totp:
            environment[names["totp"]] = totp["secret"]
    return planned, environment


def _sign_in(users: list[dict], host: str, url: str, pins: dict[str, str], work: Path, hosts: dict, secrets: list[str]) -> list[dict]:
    """Each test user's sign-in check, one after another in one container (a ZAP of its own each, so its report is
    about that user alone), before the scan. One outcome per user, in order."""
    logins, environment = login_plan(users, host, url)
    probe = plan(host, url, **hosts, users=logins)
    urls, patterns = probe["env"]["contexts"][0]["urls"], probe["env"]["contexts"][0]["includePaths"]
    checks = []
    for index, login in enumerate(logins, start=1):
        checked = check_plan(index, login, urls, patterns)
        _no_stray_variables(checked)
        checks.append(json.dumps(checked))
    with TemporaryDirectory(prefix="web-login-", dir=work) as temporary:
        shared = Path(temporary) / "wrk"
        shared.mkdir()
        try:
            completed = run_zap(None, pins, shared, timeout=60 + CHECK_SECONDS * len(users), secrets=environment, checks=checks)
            output = scrub(completed.stdout or "", secrets)
        except subprocess.TimeoutExpired:
            output = ""
        except OSError as exc:
            raise WebScanError(msg("scanning.web.errors.failed")) from exc
        reports = [_read(shared / f"auth-{index}.json") for index in range(1, len(users) + 1)]
    return [sign_in_outcome(login, scrub(report, secrets) if report else None, segment)
            for login, report, segment in zip(logins, reports, _segments(output, len(users)))]


def zap_statuses(text: str, hosts: list[str]) -> list[tuple[str, int]]:
    """Every in-scope URL of ZAP's sites tree export (YAML: nested `node`s, each with its `url` and the `statusCode`
    ZAP got) with that status."""
    try:
        document = yaml.safe_load(text) if text else None
    except yaml.YAMLError:
        return []
    found: list[tuple[str, int]] = []
    pending = list(document) if isinstance(document, list) else []
    while pending and len(found) < REACHED_MAX * 10:
        node = pending.pop()
        if not isinstance(node, dict):
            continue
        if isinstance(node.get("children"), list):
            pending.extend(node["children"])
        status = node.get("statusCode")
        if isinstance(status, int) and not isinstance(status, bool) and (url := web_tools.in_scope_url(node.get("url"), hosts)):
            found.append((url, status))
    return found


def soft_404_references(hosts: list[str], *, http: bool = False) -> dict[str, str]:
    """For each root, a random path of it, new every run: how the site answers a path that doesn't exist."""
    roots = [f"https://{host}/" for host in hosts] + ([f"http://{host}/" for host in hosts] if http else [])
    return {root: f"{root}pitangus-{token_hex(8)}" for root in roots}


def page_references(references: dict[str, str]) -> dict[str, str]:
    return {domains.page_of(root) or root: domains.page_of(url) or url for root, url in references.items()}


def versions_coverage(httpx: web_tools.ToolRun, blocked) -> dict:
    """What httpx + OSV vouches for: the roots httpx's technologies pass read, when it finished."""
    return web_tools.ToolRun("httpx", httpx.status, "", examined=httpx.roots if httpx.status == "completed" else []).coverage(blocked)


def _tool_progress(report, run: web_tools.ToolRun) -> None:
    level = "ok" if run.status == "completed" else "info" if run.status == "skipped" else "warn"
    report(level, msg("scanning.progress.engine", engine=IMAGES[run.key]["name"], detail=run.detail))


def scan_domain(record: dict, address, *, data_dir: Path, progress=None, scope: dict | None = None,
                headers=(), api: dict | None = None, excluded=(), users=(), tools: dict | None = None,
                session_check: str = "") -> RunRecord:
    """One passive scan of a verified domain. `address`: the root's checked address, or {host: address} for every
    host of `scope` (`domains.scan_scope`). `headers`: (name, value) pairs to add to the scope's requests;
    `session_check`: the page that proves they still sign in, asked for before and after (without a 2xx either time,
    the scan is incomplete: what it didn't see behind the login proves nothing). `api`: the
    parsed definition (`openapi_spec.parse`) plus its `source`, for API mode. `excluded`: hosts saved out of scope.
    `users`: test users to sign in as, with their secrets (`test_users.credentials`). `tools`: the other tools of the
    scan (`web_tools.readiness()`: None for each one that can run, else why it can't); without it, ZAP alone.

    With them, in this order: katana crawls the scope; robots.txt and the sitemaps (and the definition's paths) add
    their URLs (`web_seeds`); ZAP requests that inventory before its spider; what the spider reached joins it; nuclei
    reads the whole inventory; testssl.sh; httpx. A tool that fails leaves its step partial and the scan goes on."""
    host, url = record["host"], start_url(record)
    scope = scope or {"hosts": [host], "wildcards": []}
    pins = dict(address) if isinstance(address, dict) else {host: address}
    if any(item not in pins for item in scope["hosts"]):
        raise WebScanError(msg("scanning.web.errors.failed"))
    headers, users = list(headers), list(users)
    passwords = {value for user in users for value in (user["password"], (user.get("totp") or {}).get("secret") or "") if len(value) >= SCRUB_MIN}
    secrets = sorted(set(secret_parts(headers)) | passwords, key=len, reverse=True)
    extra = [item for item in scope["hosts"] if item != host]
    ready = dict(tools) if tools is not None else None

    def report(level: str, message) -> None:
        if progress:
            progress(level, message)

    meta = IMAGES["zap"]
    target = openapi_spec.target_url(api, host, scope["hosts"]) if api else ""
    work = data_dir / "work"
    work.mkdir(parents=True, exist_ok=True)
    patterns_hosts = {"hosts": scope["hosts"], "wildcards": scope["wildcards"],
                      "excluded": [item for item in excluded if not domains.in_scope(item, {"hosts": scope["hosts"]})]}
    # Before anything reaches the site: the whole plan, as it would be with every test user, refers to no stray variable.
    _no_stray_variables(plan(host, url, **patterns_hosts, headers=headers, users=login_plan(users, host, url)[0],
                             api={"file": f"{WORK}/{SPEC}", "target": target} if api else None, seeds=f"{WORK}/{SEEDS}",
                             export=f"{WORK}/{EXPORT}", tree=f"{WORK}/{TREE}"))
    runs: dict[str, web_tools.ToolRun] = {}
    inventory: list[str] = []
    roots = list(dict.fromkeys([url, *(f"https://{item}/" for item in extra)]))

    def tool(key: str, call) -> None:
        if ready is None:
            return
        reason = ready.get(key, msg("scanning.web.tools.image_missing", tool=IMAGES[key]["name"]))
        if reason is not None:
            runs[key] = web_tools.skipped(key, reason)
        else:
            report("info", msg(f"scanning.web.tools.{key}.progress", version=IMAGES[key]["version"]))
            runs[key] = call()
        _tool_progress(report, runs[key])

    def crawl():
        run, urls = web_tools.run_katana(roots, scope["hosts"], pins, work, headers=headers, scrub=lambda value: scrub(value, secrets))
        inventory.extend(urls)
        return run

    sessions: list[tuple[bool, Message]] = []
    watched = bool(headers and session_check)

    def check_session(moment: str) -> None:
        alive, said = session_alive(session_check, pins, headers)
        sessions.append((alive, said))
        report("ok" if alive else "warn", msg(f"scanning.web.session.{moment}", detail=said))

    if watched:
        check_session("before")
    tool("katana", crawl)
    # The inventory is what nuclei reads: without it, ZAP's spider reads robots.txt and the sitemaps on its own.
    inventoried = ready is not None and ready.get("nuclei", False) is None
    sources: dict[str, list[str]] = {"katana": list(inventory)}
    if inventoried:
        report("info", msg("scanning.web.progress.known_files", hosts=", ".join(scope["hosts"])))
        sources.update(web_seeds.known_files(scope["hosts"], pins))
        if api:
            sources["openapi"] = web_seeds.api_urls(api, target, scope["hosts"])
        inventory[:] = web_seeds.merge(sources)[0]

    if api:
        report("info", msg("scanning.web.progress.starting_api", version=meta["version"], count=api["endpoints"], target=target))
    else:
        report("info", msg("scanning.web.progress.starting", version=meta["version"], host=host, minutes=SPIDER_MINUTES))
    if extra or scope["wildcards"]:
        report("info", msg("scanning.web.progress.scope", hosts=", ".join([*extra, *scope["wildcards"]])))
    if headers:
        report("info", msg("scanning.web.progress.headers", count=len(headers), names=", ".join(name for name, _ in headers)))
    if users:
        report("info", msg("scanning.web.progress.login", count=len(users), names=", ".join(user["name"] for user in users),
                           minutes=LOGIN_SPIDER_MINUTES))
    outcomes: list[dict] = []
    if users:
        outcomes = _sign_in(users, host, url, pins, work, patterns_hosts, secrets)
        for outcome in outcomes:
            report("ok" if outcome["status"] == "signed_in" else "warn",
                   msg("scanning.web.login.signed_in", name=outcome["name"]) if outcome["status"] == "signed_in"
                   else msg("scanning.web.login.failed", name=outcome["name"], reason=outcome["reason"]))
        # Who couldn't sign in isn't crawled as: it would only log in again and again, and vouch for nothing.
        users = [user for user, outcome in zip(users, outcomes) if outcome["status"] == "signed_in"]
    logins, environment = login_plan(users, host, url)
    seeds = [item for item in inventory if item not in roots][:web_tools.ZAP_SEEDS_MAX]
    # The AJAX spider runs once anonymously and once per test user, each with a minute to start and stop Firefox.
    timeout = (TIMEOUT + 60 * EXTRA_SPIDER_MINUTES * len(extra) + 60 * (LOGIN_SPIDER_MINUTES + 1) * len(users) + (SEED_SECONDS * len(seeds))
               + 60 * (AJAX_MINUTES + 1) * (1 + len(users)))
    zap_started = time.time()
    with TemporaryDirectory(prefix="web-", dir=work) as temporary:
        # ZAP's user must write in it, so it is open to everyone; its private parent keeps other local users out.
        shared = Path(temporary) / "wrk"
        shared.mkdir()
        options: dict[str, Any] = {**patterns_hosts, "headers": headers, "users": logins, "tree": f"{WORK}/{TREE}"}
        if api:
            (shared / SPEC).write_text(openapi_spec.for_zap(api, target), encoding="utf-8")
            (shared / SPEC).chmod(0o644)
            options["api"] = {"file": f"{WORK}/{SPEC}", "target": target}
        if seeds:
            (shared / SEEDS).write_text("".join(f"{item}\n" for item in seeds), encoding="utf-8")
            (shared / SEEDS).chmod(0o644)
            options["seeds"] = f"{WORK}/{SEEDS}"
        if inventoried:
            options["export"] = f"{WORK}/{EXPORT}"
        planned = plan(host, url, **options)
        _no_stray_variables(planned)
        text = json.dumps(planned, indent=2) + "\n"
        try:
            completed = run_zap(text, pins, shared, timeout=timeout, secrets=environment)
        except subprocess.TimeoutExpired as exc:
            raise WebScanError(msg("scanning.web.errors.timeout", minutes=timeout // 60)) from exc
        except OSError as exc:
            raise WebScanError(msg("scanning.web.errors.failed")) from exc
        document = _read(shared / REPORT)
        exported = _text(shared / EXPORT)
        tree = _text(shared / TREE)
    completed = subprocess.CompletedProcess(completed.args, completed.returncode, scrub(completed.stdout or "", secrets),
                                            scrub(completed.stderr or "", secrets))
    if document is None:
        _log.warning("zap_failed", extra={"reason": f"{host}: exit {completed.returncode}"})
        raise WebScanError(with_cause(msg("scanning.web.errors.failed"), _plan_failure(completed)))
    findings, version, results = findings_from(scrub(document, secrets), host, scope=scope)
    complete = completed.returncode == 0
    # ZAP's own evidence: the status it got for each URL (its sites tree). A ZAP that didn't finish opens nothing (its
    # report may be of half a crawl) and proves nothing.
    zap_answers, zap_pages = web_tools.evidence(zap_statuses(scrub(tree, secrets), scope["hosts"]))
    if not complete:
        findings, zap_pages = [], {}
    zap_only = list(findings)
    for finding in findings:
        # The import's generic advice names the next import; here, the next scan is what proves a fix.
        if is_msg(finding.get("remediation")) and finding["remediation"][MARK] == "scanning.sarif.remediation":
            finding["remediation"] = msg("scanning.web.remediation", tool=finding["tool"])
    zap_duration = round(time.time() - zap_started, 1)
    report("ok" if complete else "warn", msg("scanning.progress.engine", engine=meta["name"],
                                             detail=msg("scanning.web.detail", count=len(findings), results=results)))

    counts: dict[str, int] = {}
    spidered = web_seeds.zap_urls(scrub(exported, secrets), scope["hosts"])
    # What the crawls visited (katana, ZAP's spider): httpx reads each one's status after the scan.
    visited: dict[str, str] = {}
    for url in [*sources["katana"], *spidered]:
        if page := domains.page_of(url):
            visited.setdefault(page, url)   # the URL as it was visited: without its slash a page can answer a redirect
    if inventoried:
        sources["zap"] = spidered
        merged, counts = web_seeds.merge(sources)
        inventory[:] = merged
    technologies: list[dict] = []
    tool("nuclei", lambda: _nuclei(roots, inventory, scope["hosts"], pins, work, data_dir, headers, secrets, technologies))
    tool("testssl", lambda: web_tools.run_testssl(scope["hosts"], pins, work))

    exposed: list[dict] = []
    references = soft_404_references(scope["hosts"])
    # The soft 404 references and nuclei's findings first: httpx reads at most STATUS_PAGES_MAX pages.
    pages = [*references.values(), *(finding["path"] for finding in (runs["nuclei"].findings if "nuclei" in runs else [])),
             *(visited[page] for page in sorted(visited))]

    def fingerprint():
        run, detected = web_tools.run_httpx(scope["hosts"], pins, work, pages=list(dict.fromkeys(pages)))
        technologies.extend(detected)
        exposed.extend(detected)
        return run

    tool("httpx", fingerprint)
    if watched:
        check_session("after")
    lost = [said for alive, said in sessions if not alive]
    # Every answer of every tool over the whole run decides whether a host turned the scan away (engine_contract).
    blocked = engine_contract.blocked_hosts({"zap": zap_answers, **{key: run.answers for key, run in runs.items()}})
    for run in runs.values():
        run.block(blocked)
    if "nuclei" in runs and "httpx" in runs:
        runs["nuclei"].findings, _ = web_tools.soft_404(runs["nuclei"].findings, runs["httpx"].signatures, page_references(references))
    others = [finding for key in ("nuclei", "testssl") if key in runs for finding in runs[key].findings]
    folded = 0
    if others:
        findings, folded = web_merge.merge([*findings, *others])
    versions: tuple[dict, list, str] | None = None
    if "httpx" in runs and runs["httpx"].status != "skipped":
        # The versions httpx read, looked up in the local advisory databases; ZAP's own JavaScript library rule wins.
        missing = msg("scanning.web.tools.image_missing", tool=IMAGES[web_versions.KEY]["name"])
        versions = web_versions.check(exposed, data_dir, zap_only, ready=(ready or {}).get(web_versions.KEY, missing))
        status = versions[0]["status"]
        report("ok" if status == "completed" else "info" if status == "skipped" else "warn",
               msg("scanning.progress.engine", engine=web_versions.TOOL, detail=versions[0]["detail"]))
        known = {finding["fingerprint"] for finding in findings}
        findings += [finding for finding in versions[1] if finding["fingerprint"] not in known]
    coverage = coverage_key(api, headers, users)
    for finding in findings:
        finding.setdefault("web", {})["coverage"] = coverage
    failed = [outcome["name"] for outcome in outcomes if outcome["status"] != "signed_in"]
    severities = {level: sum(1 for item in findings if item["severity"] == level) for level in SEVERITIES}
    tool_meta = {"name": "zap", "version": version or meta["version"], "image": meta["image"], "duration_s": zap_duration}
    zap_findings = sum(1 for item in findings if str(item.get("tool")).lower() == "zap")
    if api:
        first = {"id": "dast", "name": msg("scanning.web.steps.api.name"), "status": "completed" if complete else "partial",
                 "detail": msg("scanning.web.steps.api.detail", count=api["endpoints"], target=target, findings=zap_findings), "tool": tool_meta}
    else:
        first = {"id": "dast", "name": msg("scanning.web.steps.passive.name"), "status": "completed" if complete else "partial",
                 "detail": msg("scanning.web.steps.passive.detail", host=host, minutes=SPIDER_MINUTES, count=zap_findings), "tool": tool_meta}
    if seeds:
        first["detail"] = msg("scanning.web.steps.with_inventory", detail=first["detail"], count=len(seeds))
    ajax = [int(count) for count in re.findall(r"Job spiderAjax found (\d+) URLs", completed.stdout or "")]
    if ajax:
        first["detail"] = msg("scanning.web.steps.with_ajax", detail=first["detail"], count=sum(ajax), minutes=AJAX_MINUTES)
    if failed:
        first["status"] = "partial"
    steps: list[dict[str, Any]] = [
        *([runs["katana"].step()] if "katana" in runs else []),
        first,
        *([{"id": "dast-inventory", "name": msg("scanning.web.steps.inventory.name"), "status": "completed",
            "detail": msg("scanning.web.steps.inventory.detail", count=len(inventory), katana=counts.get("katana", 0),
                          robots=counts.get("robots", 0), sitemap=counts.get("sitemap", 0), zap=counts.get("zap", 0),
                          openapi=counts.get("openapi", 0))}] if inventoried else []),
        *([{"id": "login", "name": msg("scanning.web.steps.login.name"), "status": "partial" if failed else "completed",
            "detail": msg("scanning.web.steps.login.detail", count=len(outcomes), signed_in=len(outcomes) - len(failed))}] if outcomes else []),
        *([{"id": "session", "name": msg("scanning.web.steps.session.name"), "status": "partial" if lost else "completed",
            "detail": msg("scanning.web.steps.session.detail", before=sessions[0][1], after=sessions[1][1])}] if watched else []),
        *(runs[key].step() for key in ("nuclei", "testssl", "httpx") if key in runs),
        *([versions[0]] if versions else []),
        *([{"id": "dast-merge", "name": msg("scanning.web.steps.merge.name"), "status": "completed",
            "detail": msg("scanning.web.steps.merge.detail", count=folded) if folded else msg("scanning.web.steps.merge.none")}] if others else []),
        {"id": "active", "name": msg("scanning.web.steps.active.name"), "status": "not_tested",
         "detail": msg("scanning.web.steps.active.detail")},
        {"id": "review", "name": msg("scanning.steps.review"), "status": "pending", "detail": msg("scanning.web.steps.review.detail")},
    ]
    # How the scan got past the login, if it did: test users, saved headers whose session was checked, or not checked.
    access = ([msg("scanning.web.limitations.login", count=len(users))] if users else [] if lost
              else [msg("scanning.web.limitations.headers_checked")] if watched else [msg("scanning.web.limitations.headers")] if headers
              else [msg("scanning.web.limitations.unauthenticated")])
    limitations: list[Message] = [msg("scanning.web.limitations.passive"),
                   *([msg("scanning.web.limitations.login_failed", count=len(failed), names=", ".join(failed))] if failed else []),
                   *([msg("scanning.web.limitations.session_lost", reason=lost[0])] if lost else []),
                   *([msg("scanning.web.limitations.blocked", hosts=", ".join(blocked))] if blocked else []),
                   *access,
                   msg("scanning.web.limitations.api", count=api["endpoints"]) if api
                   else msg("scanning.web.limitations.spider", minutes=SPIDER_MINUTES),
                   msg("scanning.web.limitations.ajax", minutes=AJAX_MINUTES),
                   *([msg("scanning.web.limitations.versions")] if versions and versions[1] else []),
                   *([msg("scanning.web.limitations.wildcards")] if scope["wildcards"] else []),
                   *([msg("scanning.web.limitations.tools_anonymous")] if runs and users else []),
                   *(msg("scanning.web.limitations.tool_skipped", tool=IMAGES[key]["name"]) for key, run in runs.items() if run.status == "skipped"),
                   *(msg("scanning.web.limitations.tool_unreached", tool=IMAGES[key]["name"], hosts=", ".join(run.unreached)) if run.unreached
                     else msg("scanning.web.limitations.tool_partial", tool=IMAGES[key]["name"]) for key, run in runs.items() if run.status == "partial"),
                   *([msg("scanning.web.limitations.nuclei")] if "nuclei" in runs and runs["nuclei"].status != "skipped" else []),
                   *([msg("scanning.web.limitations.tls_capped", max=web_tools.TESTSSL_HOSTS_MAX)]
                     if "testssl" in runs and len(scope["hosts"]) > web_tools.TESTSSL_HOSTS_MAX else []),
                   msg("scanning.web.limitations.not_pentest")]
    rows = web_tools.technologies_of(technologies)
    # Coverage (engine_contract): each tool vouches only for what it got itself in this run. ZAP for the pages it got a
    # 2xx for (never a redirect, an error page or a refusal), nuclei for the roots its own requests got a 2xx, 404 or 410
    # for and the other pages they got a 404 or 410 for (engine_contract), testssl.sh for the hosts it finished, httpx +
    # OSV for the roots httpx read; nothing on a blocked host.
    examined: dict[str, dict] = {"zap": engine_contract.http_coverage(zap_pages, accept=engine_contract.present, blocked=blocked)}
    examined.update({key: runs[key].coverage(blocked) for key in ("nuclei", "testssl") if key in runs and runs[key].status != "skipped"})
    if versions:
        examined[web_versions.TOOL.lower()] = versions_coverage(runs["httpx"], blocked)
    reached = examined["zap"]["examined"]
    scanned: dict[str, Any] = {"hosts": scope["hosts"], "wildcards": scope["wildcards"], "headers": [name for name, _ in headers],
                               "test_users": [user["name"] for user in users], "coverage": coverage,
                               "reached": reached[:REACHED_MAX], **({"reached_truncated": True} if len(reached) > REACHED_MAX else {}),
                               # Whether the saved headers were proven to sign in (a session check page answered 2xx before
                               # and after): without it, a header scan fixes nothing behind the login.
                               **({"session_checked": watched and not lost} if headers else {}),
                               # The pages nuclei's page pass requested: its page-level findings elsewhere aren't fixed.
                               **({"probed": sorted({page for url in runs["nuclei"].probed if (page := domains.page_of(url))})}
                                  if "nuclei" in runs and runs["nuclei"].status != "skipped" else {})}
    summary_tools = [{"name": "ZAP", "version": tool_meta["version"], "status": "completed" if complete else "inconclusive"}]
    # A tool that didn't finish (or didn't run) is blind in this scan: what only it saw before isn't marked fixed.
    summary_tools += [{"name": key, "version": IMAGES[key]["version"], "status": "completed" if run.status == "completed" else "inconclusive",
                       **({"contract": {"blind": True, "cause": run.contract}} if run.contract else {})} for key, run in runs.items()]
    if versions:
        blind = versions[2] != "completed" or runs["httpx"].status != "completed"
        summary_tools.append({"name": web_versions.TOOL, "version": IMAGES[web_versions.KEY]["version"],
                              "status": "inconclusive" if blind else "completed"})
    result: RunRecord = {
        # A test user that couldn't sign in leaves the run incomplete: "no findings" behind its login proves nothing.
        # So does a session check that failed: what the saved headers should have opened may not have been seen.
        # And so does a WAF that turned the crawl away: the pages behind it answered nothing but refusals.
        "type": "dast_scan", "status": "completed" if complete and not failed and not lost and not blocked else "incomplete",
        "logins": outcomes,
        "source": domains.source_for(record), "target": target or url, "variant": "api" if api else "baseline", "context": "",
        "scope": scanned, "steps": steps, "findings": findings, "coverage": examined, "owasp_coverage": [], "limitations": limitations,
        "summary": {"files": len({item["path"] for item in findings}), "dependencies": 0, "candidates": len(findings),
                    "sast": 0, "secrets": 0, "sca": 0, "iac": 0, "cicd": 0, "dast": len(findings),
                    "severities": severities,
                    "priorities": {action: sum(1 for item in findings if item["priority"]["action"] == action)
                                   for action in ("act", "attend", "track")},
                    "kev": 0, "fixable": 0, "tools": summary_tools,
                    **({"technologies": rows} if "httpx" in runs or rows else {})}}
    if inventoried:
        result["web_inventory"] = {"sources": counts, "count": len(inventory), "urls": inventory}
    if api:
        result["api"] = {"sha256": api["sha256"], "endpoints": api["endpoints"], "source": api.get("source", "upload")}
    return result


def _nuclei(roots, inventory, hosts, pins, work, data_dir, headers, secrets, technologies):
    run, detected = web_tools.run_nuclei(roots, inventory, hosts, pins, work, data_dir / "nuclei-templates", headers=headers,
                                         scrub=lambda value: scrub(value, secrets))
    technologies.extend(detected)
    return run


# --- Exposure check: roots and known paths, no crawl -------------------------------------------------------------

KNOWN_PATH = re.compile(r"\{\{BaseURL\}\}(/[^\s\"'{}]*)")


def known_paths() -> list[str]:
    """The fixed paths Pitangus' own nuclei templates ask for (`/.env`, `/.git/config`, `/actuator/env`…), read from the
    templates themselves: the exposure check sees their status, so a 404 there proves the file is no longer exposed."""
    from pitangus.modules.scanning import nuclei_templates
    found = {match.group(1) for _, content in nuclei_templates.own_templates() for match in KNOWN_PATH.finditer(content.decode("utf-8", "replace"))}
    return sorted(path for path in found if path != "/")


def scan_exposure(record: dict, address, *, data_dir: Path, progress=None, scope: dict | None = None, tools: dict | None = None,
                  recheck=()) -> RunRecord:
    """The light check of a verified domain: each host's root and known paths, over HTTPS and plain HTTP on port 80, no
    crawl and no ZAP. httpx (what runs there, and the status of every path it checks), testssl.sh (TLS) and nuclei's
    detection-only templates on the roots (headers, exposed files, consoles). The same rules as a full scan: pinned
    addresses, each tool vouching only for what it got itself (engine_contract: only a 2xx, a 404 or a 410 proves
    anything, and only a 404 or a 410 that a path is gone), a host that turned the run away leaves it incomplete, and a finding on a path the site
    answers like any random one (a soft 404) isn't one. `recheck`: pages earlier findings were on, whose status is
    checked again."""
    host = record["host"]
    scope = scope or {"hosts": [host], "wildcards": []}
    pins = dict(address) if isinstance(address, dict) else {host: address}
    if any(item not in pins for item in scope["hosts"]):
        raise WebScanError(msg("scanning.web.exposure.errors.unpinned"))
    ready = dict(tools) if tools is not None else {}

    def report(level: str, message) -> None:
        if progress:
            progress(level, message)

    work = data_dir / "work"
    work.mkdir(parents=True, exist_ok=True)
    roots = [f"https://{item}/" for item in scope["hosts"]]
    plain = [f"http://{item}/" for item in scope["hosts"]]
    runs: dict[str, web_tools.ToolRun] = {}
    technologies: list[dict] = []

    def tool(key: str, call) -> None:
        reason = ready.get(key, msg("scanning.web.tools.image_missing", tool=IMAGES[key]["name"]))
        if reason is not None:
            runs[key] = web_tools.skipped(key, reason)
        else:
            report("info", msg(f"scanning.web.exposure.progress.{key}", version=IMAGES[key]["version"]))
            runs[key] = call()
        _tool_progress(report, runs[key])

    def detect():
        run, detected = web_tools.run_nuclei([*roots, *plain], [], scope["hosts"], pins, work, data_dir / "nuclei-templates", http=True)
        technologies.extend(detected)
        return run

    tool("nuclei", detect)
    tool("testssl", lambda: web_tools.run_testssl(scope["hosts"], pins, work))
    checked = exposure_pages(scope["hosts"], recheck)
    references = soft_404_references(scope["hosts"], http=True)
    exposed: list[dict] = []

    def fingerprint():
        found = [finding["path"] for finding in (runs["nuclei"].findings if "nuclei" in runs else [])]
        run, detected = web_tools.run_httpx(scope["hosts"], pins, work, pages=list(dict.fromkeys([*references.values(), *found, *checked])),
                                            http=True)
        technologies.extend(detected)
        exposed.extend(detected)
        return run

    tool("httpx", fingerprint)
    blocked = engine_contract.blocked_hosts({key: run.answers for key, run in runs.items()})
    for run in runs.values():
        run.block(blocked)
    if "nuclei" in runs and "httpx" in runs:
        runs["nuclei"].findings, _ = web_tools.soft_404(runs["nuclei"].findings, runs["httpx"].signatures, page_references(references))
    findings: list = [finding for key in ("nuclei", "testssl") if key in runs for finding in runs[key].findings]
    folded = 0
    if findings:
        findings, folded = web_merge.merge(findings)
    versions: tuple[dict, list, str] | None = None
    if "httpx" in runs and runs["httpx"].status != "skipped":
        missing = msg("scanning.web.tools.image_missing", tool=IMAGES[web_versions.KEY]["name"])
        versions = web_versions.check(exposed, data_dir, [], ready=ready.get(web_versions.KEY, missing))
        known = {finding["fingerprint"] for finding in findings}
        findings += [finding for finding in versions[1] if finding["fingerprint"] not in known]
    for finding in findings:
        finding.setdefault("web", {})["coverage"] = "exposure"
    examined: dict[str, dict] = {key: runs[key].coverage(blocked) for key in ("nuclei", "testssl") if key in runs and runs[key].status != "skipped"}
    if versions:
        examined[web_versions.TOOL.lower()] = versions_coverage(runs["httpx"], blocked)
    probed = (examined.get("nuclei") or {}).get("examined") or []
    statuses = (runs["httpx"].pages if "httpx" in runs else {})
    answered = [page for page in checked_pages(checked) if page in statuses and not any(engine_contract.refused(code) for code in statuses[page])
                and (urlsplit(page).hostname or "") not in blocked]
    failed = [key for key, run in runs.items() if run.status != "completed"]
    complete = not failed and not blocked
    severities = {level: sum(1 for item in findings if item["severity"] == level) for level in ("critical", "high", "medium", "low", "info")}
    summary_tools = [{"name": key, "version": IMAGES[key]["version"], "status": "completed" if run.status == "completed" else "inconclusive",
                      **({"contract": {"blind": True, "cause": run.contract}} if run.contract else {})} for key, run in runs.items()]
    if versions:
        summary_tools.append({"name": web_versions.TOOL, "version": IMAGES[web_versions.KEY]["version"],
                              "status": "inconclusive" if versions[2] != "completed" or runs["httpx"].status != "completed" else "completed"})
    steps: list[dict[str, Any]] = [
        {"id": "exposure", "name": msg("scanning.web.exposure.step.name"), "status": "completed" if complete else "partial",
         "detail": msg("scanning.web.exposure.step.detail", hosts=len(scope["hosts"]), pages=len(checked_pages(checked)), answered=len(answered),
                       count=len(findings))},
        *(runs[key].step() for key in ("nuclei", "testssl", "httpx") if key in runs),
        *([versions[0]] if versions else []),
        {"id": "review", "name": msg("scanning.steps.review"), "status": "pending", "detail": msg("scanning.web.steps.review.detail")},
    ]
    limitations: list[Message] = [
        msg("scanning.web.exposure.limitations.scope"),
        *([msg("scanning.web.limitations.blocked", hosts=", ".join(blocked))] if blocked else []),
        *(msg("scanning.web.limitations.tool_skipped", tool=IMAGES[key]["name"]) for key, run in runs.items() if run.status == "skipped"),
        *(msg("scanning.web.limitations.tool_unreached", tool=IMAGES[key]["name"], hosts=", ".join(run.unreached)) if run.unreached
          else msg("scanning.web.limitations.tool_partial", tool=IMAGES[key]["name"]) for key, run in runs.items() if run.status == "partial"),
        msg("scanning.web.limitations.not_pentest")]
    return {"type": "dast_scan", "status": "completed" if complete else "incomplete", "source": domains.source_for(record),
            "target": roots[0], "variant": "exposure", "context": "",
            # What it checked: the scope's hosts and every page nuclei got an answer for. A nuclei finding is fixed only
            # on a page here, and only by another exposure check (`coverage`).
            "scope": {"hosts": scope["hosts"], "wildcards": [], "headers": [], "test_users": [], "coverage": "exposure",
                      "reached": probed[:REACHED_MAX], "probed": probed[:REACHED_MAX]},
            "steps": steps, "findings": findings, "coverage": examined, "owasp_coverage": [],
            "limitations": limitations,
            "summary": {"files": len({item["path"] for item in findings}), "dependencies": 0, "candidates": len(findings), "sast": 0, "secrets": 0,
                        "sca": 0, "iac": 0, "cicd": 0, "dast": len(findings), "severities": severities,
                        "priorities": {action: sum(1 for item in findings if item["priority"]["action"] == action) for action in ("act", "attend", "track")},
                        "kev": 0, "fixable": 0, "tools": summary_tools, "technologies": web_tools.technologies_of(technologies),
                        **({"folded": folded} if folded else {})}}


def exposure_pages(hosts: list[str], recheck=()) -> list[str]:
    """The URLs whose status the exposure check reads: each root (HTTPS and plain HTTP), the known paths on each host,
    and the in-scope pages of earlier findings (`recheck`), each page once."""
    urls = [*(f"https://{item}/" for item in hosts), *(f"http://{item}/" for item in hosts),
            *(f"https://{item}{path}" for item in hosts for path in known_paths()),
            *(url for item in recheck if (url := web_tools.in_scope_url(item, hosts, http=True)))]
    seen: dict[str, str] = {}
    for url in urls:
        if (page := domains.page_of(url)) and page not in seen:
            seen[page] = url
    return list(seen.values())


def checked_pages(urls: list[str]) -> list[str]:
    """The distinct pages among `urls`: what the exposure check's counter counts."""
    return sorted({page for url in urls if (page := domains.page_of(url))})
