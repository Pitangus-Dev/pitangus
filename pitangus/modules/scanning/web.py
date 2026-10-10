"""Passive web and API scans of a verified domain with ZAP: a spider (or an OpenAPI import) and the passive rules,
never an attack.

ZAP crawls the site and reads its responses (headers, cookies, information leaks); its active scanner, the AJAX
spider and form submissions stay off. In API mode it imports the definition instead of crawling, reduced beforehand
to its GET and HEAD operations (`openapi_spec`), so every request is one a browser could send.

Before it starts, the caller has confirmed the domain's proof and resolved every host of the scope to public
addresses only; the container gets those addresses pinned (`--add-host`) and a DNS server that answers nothing, so
ZAP never resolves a name on its own (no DNS rebinding between the check and the scan, and no host outside the
scope). The plan's context holds the scope's hosts and nothing else: links and redirects elsewhere are seen, not
followed. Wildcards (`*.example.com`) only widen that context; hosts reached through them don't resolve.

The plan reaches ZAP on its standard input and is written inside the container's memory-only home: the headers a
domain saved (API keys, tokens, cookies) go into it, never into a file on the host, the command line or the logs.
Whatever ZAP returns is scrubbed of those values before it is stored.

The container is the only engine that reaches the internet on purpose. It runs as the image's own user (ZAP's Java
needs a home from passwd), with no capabilities, no privilege escalation, a read-only root, memory and CPU caps and
an explicit heap. The residual risks are written down in docs/security.md.

The SARIF it writes goes through the same parser as `import-sarif`: a native scan and an import of the same site
share fingerprints, so neither duplicates the other.
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

from pitangus.modules.scanning import openapi_spec, sarif_import
from pitangus.modules.scanning.engines import IMAGES, _run, host_path, with_cause
from pitangus.modules.sources import domains
from pitangus.shared import log as logging_setup
from pitangus.shared.i18n import MARK, is_msg, msg
from pitangus.shared.model import Message, RunRecord

_log = logging_setup.get("web")
SPIDER_MINUTES = 2
EXTRA_SPIDER_MINUTES = 1   # each listed host besides the domain's own
PASSIVE_MINUTES = 5
TIMEOUT = 15 * 60
# Under the container's 3 GB: zap.sh would otherwise take a quarter of the host's memory.
HEAP = "-Xmx1536m"
# ZAP keeps its configuration and session (HSQLDB) in $HOME/.ZAP; the image's user is uid 1000.
HOME = "/home/zap:rw,noexec,nosuid,nodev,size=512m,uid=1000,gid=1000,mode=0700"
PLAN = "/home/zap/plan.yaml"   # in that tmpfs: the plan carries the saved headers
WORK = "/zap/wrk"
REPORT = "zap.json"
SPEC = "spec.json"
CONTEXT = "pitangus"
SEVERITIES = ("critical", "high", "medium", "low", "info")
SCRUB_MIN = 6               # shorter header values aren't secrets, and scrubbing them would mangle the findings
REDACTED = "[redacted]"


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
    return url if same and not parts.query and not parts.fragment else f"https://{host}/"


def host_pattern(host: str) -> str:
    return f"https://{re.escape(host)}(?:[/?].*)?"


def wildcard_pattern(wildcard: str) -> str:
    """`*.example.com` → any subdomain of example.com (one label or more), never example.com itself."""
    return f"https://(?:[a-z0-9-]+\\.)+{re.escape(wildcard.removeprefix('*.'))}(?:[/?].*)?"


def plan(host: str, url: str, *, hosts=(), wildcards=(), headers=(), api: dict | None = None) -> dict:
    """The Automation Framework plan: inside a context of the scope's hosts only, a spider per listed host (plus the
    OpenAPI import in API mode) and the passive rules; with `headers`, a replacer that adds them to requests for
    those hosts only."""
    extra = [item for item in hosts if item != host]
    patterns = [host_pattern(host), *(host_pattern(item) for item in extra), *(wildcard_pattern(item) for item in wildcards)]
    jobs: list[dict[str, Any]] = []
    if headers:
        scope = patterns[0] if len(patterns) == 1 else "(?:" + "|".join(patterns) + ")"
        jobs.append({"type": "replacer", "parameters": {"deleteAllRules": True},
                     "rules": [{"description": f"pitangus header {index + 1}", "url": scope, "matchType": "req_header",
                                "matchString": name, "matchRegex": False, "replacementString": value, "tokenProcessing": False}
                               for index, (name, value) in enumerate(headers)]})
    # The spec adds the documented endpoints to the crawl, it doesn't replace it: a site and its API are one target.
    jobs.append({"type": "spider", "parameters": {"context": CONTEXT, "url": url, "maxDuration": SPIDER_MINUTES, "maxDepth": 5,
                                                  "threadCount": 2, "postForm": False, "acceptCookies": True}})
    jobs += [{"type": "spider", "parameters": {"context": CONTEXT, "url": f"https://{item}/", "maxDuration": EXTRA_SPIDER_MINUTES,
                                               "maxDepth": 5, "threadCount": 2, "postForm": False, "acceptCookies": True}}
             for item in extra]
    if api is not None:
        jobs.append({"type": "openapi", "parameters": {"apiFile": api["file"], "context": CONTEXT, "targetUrl": api["target"]}})
    jobs += [{"type": "passiveScan-wait", "parameters": {"maxDuration": PASSIVE_MINUTES}},
             {"type": "report", "parameters": {"template": "sarif-json", "reportDir": WORK, "reportFile": "zap"}}]
    start = list(dict.fromkeys([url, *(f"https://{item}/" for item in extra), *([api["target"]] if api is not None else [])]))
    return {"env": {"contexts": [{"name": CONTEXT, "urls": start, "includePaths": patterns}],
                    "parameters": {"failOnError": True, "failOnWarning": False, "progressToStdout": True}},
            "jobs": jobs}


def plan_text(host: str, url: str, **options) -> str:
    # JSON is YAML: serialized, never assembled, so nothing in a host, a URL or a header can add a key or a job.
    return json.dumps(plan(host, url, **options), indent=2) + "\n"


def run_zap(text: str, pins: dict[str, str], work: Path, *, timeout: int = TIMEOUT) -> subprocess.CompletedProcess:
    """ZAP over a fresh work folder only it writes to (its user isn't ours): the plan in through standard input
    (into its memory-only home), the SARIF out. `pins`: every host it may reach, with its checked address."""
    work.chmod(0o777)
    # `umask 077`: the copy of the plan in the tmpfs is readable by ZAP's user only.
    command = ["sh", "-c", f'umask 077 && cat > {PLAN} && exec zap.sh "$@"', "zap.sh", HEAP, "-cmd", "-silent", "-autorun", PLAN]
    return _run("zap", command, None, network=True, mounts=["-v", f"{host_path(work)}:{WORK}:rw", "--tmpfs", HOME],
                timeout=timeout, hosts=pins, pinned_only=True, image_user=True, stdin=text)


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


def coverage_key(api: dict | None, headers) -> str:
    """What a scan looked at, for the registry: a scan only marks fixed what a scan like it had seen (an anonymous
    crawl can't vouch for pages behind a login, nor one definition for another's endpoints)."""
    return ("api:" + api["sha256"][:16] if api else "baseline") + ("+headers" if headers else "")


def scan_domain(record: dict, address, *, data_dir: Path, progress=None, scope: dict | None = None,
                headers=(), api: dict | None = None) -> RunRecord:
    """One passive scan of a verified domain. `address`: the root's checked address, or {host: address} for every
    host of `scope` (`domains.scan_scope`). `headers`: (name, value) pairs to add to the scope's requests. `api`: the
    parsed definition (`openapi_spec.parse`) plus its `source`, for API mode."""
    host, url = record["host"], start_url(record)
    scope = scope or {"hosts": [host], "wildcards": []}
    pins = dict(address) if isinstance(address, dict) else {host: address}
    if any(item not in pins for item in scope["hosts"]):
        raise WebScanError(msg("scanning.web.errors.failed"))
    headers = list(headers)
    secrets = secret_parts(headers)
    extra = [item for item in scope["hosts"] if item != host]

    def report(level: str, message) -> None:
        if progress:
            progress(level, message)

    meta = IMAGES["zap"]
    target = openapi_spec.target_url(api, host, scope["hosts"]) if api else ""
    if api:
        report("info", msg("scanning.web.progress.starting_api", version=meta["version"], count=api["endpoints"], target=target))
    else:
        report("info", msg("scanning.web.progress.starting", version=meta["version"], host=host, minutes=SPIDER_MINUTES))
    if extra or scope["wildcards"]:
        report("info", msg("scanning.web.progress.scope", hosts=", ".join([*extra, *scope["wildcards"]])))
    if headers:
        report("info", msg("scanning.web.progress.headers", count=len(headers), names=", ".join(name for name, _ in headers)))
    started = time.time()
    work = data_dir / "work"
    work.mkdir(parents=True, exist_ok=True)
    timeout = TIMEOUT + 60 * EXTRA_SPIDER_MINUTES * len(extra)
    with TemporaryDirectory(prefix="web-", dir=work) as temporary:
        # ZAP's user must write in it, so it is open to everyone; its private parent keeps other local users out.
        shared = Path(temporary) / "wrk"
        shared.mkdir()
        options: dict[str, Any] = {"hosts": scope["hosts"], "wildcards": scope["wildcards"], "headers": headers}
        if api:
            (shared / SPEC).write_text(openapi_spec.for_zap(api, target), encoding="utf-8")
            (shared / SPEC).chmod(0o644)
            options["api"] = {"file": f"{WORK}/{SPEC}", "target": target}
        try:
            completed = run_zap(plan_text(host, url, **options), pins, shared, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise WebScanError(msg("scanning.web.errors.timeout", minutes=timeout // 60)) from exc
        except OSError as exc:
            raise WebScanError(msg("scanning.web.errors.failed")) from exc
        document = _read(shared / REPORT)
    completed = subprocess.CompletedProcess(completed.args, completed.returncode, scrub(completed.stdout or "", secrets),
                                            scrub(completed.stderr or "", secrets))
    if document is None:
        _log.warning("zap_failed", extra={"reason": f"{host}: exit {completed.returncode}"})
        raise WebScanError(with_cause(msg("scanning.web.errors.failed"), _plan_failure(completed)))
    findings, version, results = findings_from(scrub(document, secrets), host, scope=scope)
    coverage = coverage_key(api, headers)
    for finding in findings:
        # The import's generic advice names the next import; here, the next scan is what proves a fix.
        if is_msg(finding.get("remediation")) and finding["remediation"][MARK] == "scanning.sarif.remediation":
            finding["remediation"] = msg("scanning.web.remediation", tool=finding["tool"])
        finding.setdefault("web", {})["coverage"] = coverage
    complete = completed.returncode == 0
    duration = round(time.time() - started, 1)
    severities = {level: sum(1 for item in findings if item["severity"] == level) for level in SEVERITIES}
    report("ok" if complete else "warn", msg("scanning.progress.engine", engine=meta["name"],
                                             detail=msg("scanning.web.detail", count=len(findings), results=results)))
    tool = {"name": "zap", "version": version or meta["version"], "image": meta["image"], "duration_s": duration}
    if api:
        first = {"id": "dast", "name": msg("scanning.web.steps.api.name"), "status": "completed" if complete else "partial",
                 "detail": msg("scanning.web.steps.api.detail", count=api["endpoints"], target=target, findings=len(findings)), "tool": tool}
    else:
        first = {"id": "dast", "name": msg("scanning.web.steps.passive.name"), "status": "completed" if complete else "partial",
                 "detail": msg("scanning.web.steps.passive.detail", host=host, minutes=SPIDER_MINUTES, count=len(findings)), "tool": tool}
    steps: list[dict[str, Any]] = [
        first,
        {"id": "active", "name": msg("scanning.web.steps.active.name"), "status": "not_tested",
         "detail": msg("scanning.web.steps.active.detail")},
        {"id": "review", "name": msg("scanning.steps.review"), "status": "pending", "detail": msg("scanning.web.steps.review.detail")},
    ]
    limitations: list[Message] = [msg("scanning.web.limitations.passive"),
                   msg("scanning.web.limitations.headers") if headers else msg("scanning.web.limitations.unauthenticated"),
                   msg("scanning.web.limitations.api", count=api["endpoints"]) if api
                   else msg("scanning.web.limitations.spider", minutes=SPIDER_MINUTES),
                   *([msg("scanning.web.limitations.wildcards")] if scope["wildcards"] else []),
                   msg("scanning.web.limitations.not_pentest")]
    scanned: dict[str, Any] = {"hosts": scope["hosts"], "wildcards": scope["wildcards"], "headers": [name for name, _ in headers],
                               "coverage": coverage}
    result: RunRecord = {
        "type": "dast_scan", "status": "completed" if complete else "incomplete",
        "source": domains.source_for(record), "target": target or url, "variant": "api" if api else "baseline", "context": "",
        "scope": scanned, "steps": steps, "findings": findings, "owasp_coverage": [], "limitations": limitations,
        "summary": {"files": len({item["path"] for item in findings}), "dependencies": 0, "candidates": len(findings),
                    "sast": 0, "secrets": 0, "sca": 0, "iac": 0, "cicd": 0, "dast": len(findings),
                    "severities": severities,
                    "priorities": {action: sum(1 for item in findings if item["priority"]["action"] == action)
                                   for action in ("act", "attend", "track")},
                    "kev": 0, "fixable": 0,
                    "tools": [{"name": "ZAP", "version": tool["version"], "status": "completed" if complete else "inconclusive"}]}}
    if api:
        result["api"] = {"sha256": api["sha256"], "endpoints": api["endpoints"], "source": api.get("source", "upload")}
    return result
