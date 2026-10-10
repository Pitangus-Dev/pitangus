"""Passive web scans of a verified domain with ZAP: a spider and the passive rules, never an attack.

ZAP crawls the site and reads its responses (headers, cookies, information leaks); its active scanner, the AJAX
spider and form submissions stay off. Before it starts, the caller has confirmed the domain's DNS proof and resolved
the host to public addresses only; the container gets that address pinned (`--add-host`), so ZAP never resolves the
name again (no DNS rebinding between the check and the scan). The plan's context includes that host and nothing
else: links and redirects elsewhere are seen, not followed.

The container is the only engine that reaches the internet on purpose. Docker can't limit where a bridge network goes
without a proxy, so ZAP could in principle reach any address; the plan is what keeps it on the host. That residual
risk is written down in docs/security.md. It runs as the image's own user (ZAP's Java needs a home from passwd), with
no capabilities, no privilege escalation, a read-only root, memory and CPU caps and an explicit heap.

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

from pitangus.modules.scanning import sarif_import
from pitangus.modules.scanning.engines import IMAGES, _run, host_path, with_cause
from pitangus.modules.sources import domains
from pitangus.shared import log as logging_setup
from pitangus.shared.i18n import MARK, is_msg, msg
from pitangus.shared.model import RunRecord

_log = logging_setup.get("web")
SPIDER_MINUTES = 2
PASSIVE_MINUTES = 5
TIMEOUT = 15 * 60
# Under the container's 3 GB: zap.sh would otherwise take a quarter of the host's memory.
HEAP = "-Xmx1536m"
# ZAP keeps its configuration and session (HSQLDB) in $HOME/.ZAP; the image's user is uid 1000.
HOME = "/home/zap:rw,noexec,nosuid,nodev,size=512m,uid=1000,gid=1000,mode=0700"
WORK = "/zap/wrk"
REPORT = "zap.json"
CONTEXT = "pitangus"
SEVERITIES = ("critical", "high", "medium", "low", "info")


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


def plan(host: str, url: str) -> dict:
    """The Automation Framework plan: spider and passive rules inside a context of `https://<host>` only."""
    scope = f"https://{re.escape(host)}(?:[/?].*)?"
    return {
        "env": {"contexts": [{"name": CONTEXT, "urls": [url], "includePaths": [scope]}],
                "parameters": {"failOnError": True, "failOnWarning": False, "progressToStdout": True}},
        "jobs": [
            {"type": "spider", "parameters": {"context": CONTEXT, "url": url, "maxDuration": SPIDER_MINUTES, "maxDepth": 5,
                                              "threadCount": 2, "postForm": False, "acceptCookies": True}},
            {"type": "passiveScan-wait", "parameters": {"maxDuration": PASSIVE_MINUTES}},
            {"type": "report", "parameters": {"template": "sarif-json", "reportDir": WORK, "reportFile": "zap"}},
        ],
    }


def plan_text(host: str, url: str) -> str:
    # JSON is YAML: serialized, never assembled, so nothing in the host or the URL can add a key or a job.
    return json.dumps(plan(host, url), indent=2) + "\n"


def run_zap(host: str, url: str, address: str, work: Path) -> subprocess.CompletedProcess:
    """ZAP over a fresh work folder only it writes to (its user isn't ours): the plan in, the SARIF out."""
    (work / "zap.yaml").write_text(plan_text(host, url), encoding="utf-8")
    (work / "zap.yaml").chmod(0o644)
    work.chmod(0o777)
    return _run("zap", ["zap.sh", HEAP, "-cmd", "-silent", "-autorun", f"{WORK}/zap.yaml"], None, network=True,
                mounts=["-v", f"{host_path(work)}:{WORK}:rw", "--tmpfs", HOME], timeout=TIMEOUT, hosts={host: address},
                image_user=True)


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


def findings_from(document: dict, host: str) -> tuple[list, str | None, int]:
    """The SARIF's web findings on `host`, as `import-sarif` would store them; also ZAP's version and the results
    read. Anything about another host is dropped: the scan vouches only for the domain."""
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
                same = (urlsplit(finding["path"]).hostname or "").lower() == host
            except ValueError:
                same = False
            if finding["scanner"] == "dast" and same and finding["fingerprint"] not in seen:
                seen.add(finding["fingerprint"])
                findings.append(finding)
    return findings, version, results


def scan_domain(record: dict, address: str, *, data_dir: Path, progress=None) -> RunRecord:
    """One passive scan of a verified domain already pinned to `address` (`domains.public_address`)."""
    host, url = record["host"], start_url(record)

    def report(level: str, message) -> None:
        if progress:
            progress(level, message)

    meta = IMAGES["zap"]
    report("info", msg("scanning.web.progress.starting", version=meta["version"], host=host, minutes=SPIDER_MINUTES))
    started = time.time()
    work = data_dir / "work"
    work.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="web-", dir=work) as temporary:
        # ZAP's user must write in it, so it is open to everyone; its private parent keeps other local users out.
        shared = Path(temporary) / "wrk"
        shared.mkdir()
        try:
            completed = run_zap(host, url, address, shared)
        except subprocess.TimeoutExpired as exc:
            raise WebScanError(msg("scanning.web.errors.timeout", minutes=TIMEOUT // 60)) from exc
        except OSError as exc:
            raise WebScanError(msg("scanning.web.errors.failed")) from exc
        document = _read(shared / REPORT)
    if document is None:
        _log.warning("zap_failed", extra={"reason": f"{host}: exit {completed.returncode}"})
        raise WebScanError(with_cause(msg("scanning.web.errors.failed"), _plan_failure(completed)))
    findings, version, results = findings_from(document, host)
    for finding in findings:
        # The import's generic advice names the next import; here, the next scan is what proves a fix.
        if is_msg(finding.get("remediation")) and finding["remediation"][MARK] == "scanning.sarif.remediation":
            finding["remediation"] = msg("scanning.web.remediation", tool=finding["tool"])
    complete = completed.returncode == 0
    duration = round(time.time() - started, 1)
    severities = {level: sum(1 for item in findings if item["severity"] == level) for level in SEVERITIES}
    report("ok" if complete else "warn", msg("scanning.progress.engine", engine=meta["name"],
                                             detail=msg("scanning.web.detail", count=len(findings), results=results)))
    tool = {"name": "zap", "version": version or meta["version"], "image": meta["image"], "duration_s": duration}
    steps: list[dict[str, Any]] = [
        {"id": "dast", "name": msg("scanning.web.steps.passive.name"), "status": "completed" if complete else "partial",
         "detail": msg("scanning.web.steps.passive.detail", host=host, minutes=SPIDER_MINUTES, count=len(findings)), "tool": tool},
        {"id": "active", "name": msg("scanning.web.steps.active.name"), "status": "not_tested",
         "detail": msg("scanning.web.steps.active.detail")},
        {"id": "review", "name": msg("scanning.steps.review"), "status": "pending", "detail": msg("scanning.web.steps.review.detail")},
    ]
    return {"type": "dast_scan", "status": "completed" if complete else "incomplete",
            "source": domains.source_for(record), "target": url, "variant": "baseline", "context": "",
            "steps": steps, "findings": findings, "owasp_coverage": [],
            "limitations": [msg("scanning.web.limitations.passive"), msg("scanning.web.limitations.unauthenticated"),
                            msg("scanning.web.limitations.spider", minutes=SPIDER_MINUTES),
                            msg("scanning.web.limitations.not_pentest")],
            "summary": {"files": len({item["path"] for item in findings}), "dependencies": 0, "candidates": len(findings),
                        "sast": 0, "secrets": 0, "sca": 0, "iac": 0, "cicd": 0, "dast": len(findings),
                        "severities": severities,
                        "priorities": {action: sum(1 for item in findings if item["priority"]["action"] == action)
                                       for action in ("act", "attend", "track")},
                        "kev": 0, "fixable": 0,
                        "tools": [{"name": "ZAP", "version": tool["version"], "status": "completed" if complete else "inconclusive"}]}}
