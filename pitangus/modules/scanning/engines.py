"""External scanners in containers pinned by digest, each covering one area.

- Trivy: dependencies of any ecosystem, infrastructure configuration
  (Dockerfile, Kubernetes, Terraform) and secrets. Needs network only to fetch its
  vulnerability database, which is cached; sends nothing from the repository.
- OSV-Scanner: dependencies against the OSV database (which includes Dependabot's GitHub
  Advisory Database) and more manifest formats (.NET, Gradle, uv…). Downloads the advisory
  databases and compares locally; what matches Trivy is merged into a single finding.
- Betterleaks: high-precision secrets. No network.
- Opengrep: multi-language SAST with our own rules (`rules/`). No network.
- Checkov and zizmor: infrastructure as code and CI/CD pipelines (`config_scanners`). No network.

Each container runs with no capabilities, no privilege escalation, the
snapshot mounted read-only and **with the same UID and GID as the app**: on Linux,
root without capabilities can't enter the app's 0700 folders and the engines
would return zero findings without warning (on macOS, Docker Desktop hides this). If Docker or an image is missing,
the step is declared `not_tested` with the reason: a run is never faked.

Secret values are never stored: only rule, file and line.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from functools import cmp_to_key, partial
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import tomllib
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pitangus.shared import db, log as logging_setup, paths, settings
from pitangus.shared.i18n import catalog, is_msg, msg
from pitangus.shared.masking import mask
from pitangus.modules.intel import data_sources
from pitangus.modules.intel.advisories import compare_versions, cvss3_base_score, is_malicious, mark_malicious, prioritize, severity_from_score
from pitangus.modules.intel.advisories import fingerprint as sca_fingerprint
from pitangus.modules.intel.packages import dependency_fingerprint
from pitangus.modules.scanning import dependency_coverage, dependency_graph, engine_contract, engine_switches, repo_controls, sast_merge, secret_coverage, secret_filter, secret_identity, secret_location, secret_rules, vendored
from pitangus.modules.scanning.engine_contract import Contract
from pitangus.modules.scanning.dependency_merge import unique_by_fingerprint
from pitangus.modules.scanning.folding import absorbed
from pitangus.modules.sources.repositories import MAX_FILE
from pitangus.shared.model import EngineResult, Finding, Message

RULES_DIR = paths.RULES_DIR
THIRD_PARTY_RULES_DIR = paths.THIRD_PARTY_RULES_DIR
OPENGREP_JOBS = 2
ENGINE_TMPFS = "1g"
# Opengrep's release binary unpacks its bundled runtime into /tmp and runs it from there; so does katana's browser
# driver (go-rod's leakless helper).
EXEC_FROM_TMP = {"opengrep", "katana"}
IMAGES = {
    "trivy": {"name": "Trivy", "version": "0.75.0",
              "image": "aquasec/trivy@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa"},
    # Dependencies against the OSV database (includes Dependabot's GitHub Advisory Database) and more manifest formats.
    "osv-scanner": {"name": "OSV-Scanner", "version": "2.6.0",
                    "image": "ghcr.io/google/osv-scanner@sha256:afd838850ac1a0fcc15ff4a041dc9ba11123c3f0d2666217a5f0fcf9222b55fa"},
    "betterleaks": {"name": "Betterleaks", "version": "1.9.0",
                    "image": "ghcr.io/betterleaks/betterleaks@sha256:e3b95b0db6c2735db17165c009b0ad6d9cef34fb4578659232b98f69d7346cac"},
    "opengrep": {"name": "Opengrep", "version": "1.30.0", "image": "localhost/pitangus/opengrep:1.30.0"},
    # Second opinion on container images: it disagrees with Trivy mostly on system packages.
    "grype": {"name": "Grype", "version": "0.120.0",
              "image": "anchore/grype@sha256:5c88961f4130e830542d441c7ed6c78baa28e799163abac53d2be4923fb5ab7d"},
    # Infrastructure as code and pipelines: nearly twice as many rules as Trivy for Terraform and CloudFormation.
    "checkov": {"name": "Checkov", "version": "3.3.19",
                "image": "bridgecrew/checkov@sha256:d3e96adafdb315ca82e792ca8708c01adae85292800fb064c8b309b3d0cb7b80"},
    # GitHub Actions in depth: template injection, dangerous triggers, permissions and unpinned actions.
    "zizmor": {"name": "zizmor", "version": "1.30.1",
               "image": "ghcr.io/zizmorcore/zizmor@sha256:a2eb396d886c053073405c7a980f2139ba2248ec172243cfa3841e57196e8101"},
    # Passive web scans of verified domains (scanning/web.py): Java, ~1.2 GB, Docker runner only.
    "zap": {"name": "ZAP", "version": "2.17.0",
            "image": "ghcr.io/zaproxy/zaproxy:2.17.0@sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2"},
    # Hosts related to a verified domain, from passive sources (scanning/discovery.py): ~25 MB, Docker runner only.
    "subfinder": {"name": "subfinder", "version": "2.16.0",
                  "image": "projectdiscovery/subfinder:v2.16.0@sha256:c0f4683f91e8e30fbb5bf45051ef45e245ef48424b0d5bc99f8a72cb45163ea9"},
    # The rest of a passive web scan (scanning/web_tools.py), Docker runner only: a crawler whose URLs feed ZAP and
    # nuclei, nuclei with detection-only templates, TLS checks and technology fingerprints.
    "katana": {"name": "katana", "version": "1.7.0",
               "image": "projectdiscovery/katana:v1.7.0@sha256:4e9fce12c507e1ca455baf493e14b899db5f2e0ed22ba62591aa42300487a947"},
    "nuclei": {"name": "nuclei", "version": "3.11.1",
               "image": "projectdiscovery/nuclei:v3.11.1@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb"},
    # The testssl.sh project's own image (moved from drwetter/ to the testssl organization): the 3.2 branch, multi-arch.
    "testssl": {"name": "testssl.sh", "version": "3.2",
                "image": "ghcr.io/testssl/testssl.sh:3.2@sha256:51918b1e954df0acee8c08d3ad5ce306710e4fefe49ed0e0f92728ecf9e7ff34"},
    "httpx": {"name": "httpx", "version": "1.12.0",
              "image": "projectdiscovery/httpx:v1.12.0@sha256:f8275a7c6aaec187249df9eaf4ad9196f4677adfc6a51a47b4aaa1d4db4f8ffc"},
}
# Engines that reach the internet for a domain instead of reading a snapshot. Those of the light exposure check (roots and
# known paths, scanning/web.scan_exposure) are always pulled and listed; the rest, the full DAST, only with
# PITANGUS_DAST_ENABLED (experimental).
WEB_ENGINES = frozenset({"zap", "subfinder", "katana", "nuclei", "testssl", "httpx"})
EXPOSURE_ENGINES = frozenset({"nuclei", "testssl", "httpx"})
# Languages with our own rules and the extensions that identify them in the snapshot.
RULE_LANGUAGES = {
    "JavaScript": {".js", ".jsx", ".mjs", ".cjs"}, "TypeScript": {".ts", ".tsx"}, "Python": {".py"},
    "Java": {".java"}, "Go": {".go"}, "PHP": {".php"}, "Ruby": {".rb"}, "C#": {".cs"},
}
# Server-side views (Razor, ERB, JSP) are templates Opengrep can't parse: the XSS rules for C#, Ruby and Java never see
# them, so the step names them as not analyzed.
OTHER_LANGUAGES = {"Kotlin": {".kt", ".kts"}, "Rust": {".rs"}, "Swift": {".swift"}, "Scala": {".scala"},
                   "Dart": {".dart"}, "C/C++": {".c", ".h", ".cpp", ".cc", ".hpp"}, "Vue": {".vue"}, "Svelte": {".svelte"},
                   "Razor": {".cshtml", ".razor"}, "ERB": {".erb"}, "JSP": {".jsp"}}
SEVERITY_LABEL = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "medium",
                  "ERROR": "high", "WARNING": "medium", "INFO": "low"}
CONFIDENCE = {"HIGH": 8, "MEDIUM": 6, "LOW": 4}
_docker_state: dict[str, bool] = {}


_own_mounts: dict[str, object] = {"at": None, "mounts": {}}


def in_container() -> bool:
    return Path("/.dockerenv").exists()


def own_mounts() -> dict[str, str]:
    """This container's mounts as the daemon sees them: {internal path: host path}.

    Docker is asked instead of trusting `${PWD}` in compose, which arrives empty in PowerShell or cmd
    (Windows). That way it works the same on macOS (Apple Silicon and Intel), Linux, Windows and WSL.
    Outside a container, or if Docker doesn't answer, returns {} (and retries a minute later)."""
    at = _own_mounts["at"]
    if at is not None and (_own_mounts["mounts"] or time.monotonic() - at < 60):
        return dict(_own_mounts["mounts"])
    mounts: dict[str, str] = {}
    binary, identity = shutil.which("docker"), os.environ.get("HOSTNAME", "")
    if binary and re.fullmatch(r"[0-9a-f]{12,64}", identity) and in_container():
        try:
            completed = subprocess.run([binary, "inspect", identity, "--format", "{{json .Mounts}}"],
                                       capture_output=True, text=True, timeout=8)
            rows = json.loads(completed.stdout or "[]") if completed.returncode == 0 else []
        except (OSError, subprocess.TimeoutExpired, ValueError):
            rows = []
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and row.get("Type") == "bind" and isinstance(row.get("Source"), str) \
                    and isinstance(row.get("Destination"), str):
                mounts[row["Destination"].rstrip("/")] = row["Source"]
    _own_mounts.update(at=time.monotonic(), mounts=mounts)
    return dict(mounts)


def _host_pairs() -> list[tuple[str, str]]:
    detected = own_mounts()
    pairs = []
    for inside, configured in ((settings.text("PITANGUS_DATA_DIR"), settings.text("PITANGUS_HOST_DATA_DIR")),
                               (str(RULES_DIR), settings.text("PITANGUS_HOST_RULES_DIR"))):
        if not inside:
            continue
        outside = detected.get(str(Path(inside)).rstrip("/")) or (configured if _usable(inside, configured) else None)
        if outside:
            pairs.append((inside, outside))
    return pairs


def _usable(inside: str, outside: str | None) -> bool:
    # `${PWD}/data` with an empty PWD becomes `/data`: the same as the internal path, it doesn't point at the host.
    return bool(outside and outside.strip() and outside.rstrip("/") not in (inside.rstrip("/"), "/data", "/rules"))


def host_path(path: Path) -> str:
    """A path as the Docker daemon sees it.

    When the app runs in a container, the volumes it requests for sibling
    containers are resolved on the host, not inside the app. The host path is
    found by asking Docker for this container's mounts; if that isn't possible,
    PITANGUS_HOST_DATA_DIR and PITANGUS_HOST_RULES_DIR are used.
    """
    resolved = path.resolve()
    if runner() == "local":
        return str(resolved)
    for inside, outside in _host_pairs():
        try:
            return str(Path(outside) / resolved.relative_to(Path(inside).resolve()))
        except ValueError:
            continue
    return str(resolved)


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def cause(completed: subprocess.CompletedProcess | None) -> str:
    """The last useful line of the engine's or Docker's stderr, to say *why* it failed.

    It is trimmed, stripped of colors and rendered as free text (shared/render.py: no value an engine quoted stays), and
    the host data folder is shortened: what the panel shows helps diagnose without exposing a value."""
    if completed is None:
        return ""
    lines = [line.strip() for line in _ANSI.sub("", completed.stderr or "").splitlines() if line.strip()]
    return _clean_cause(lines[-1]) if lines else ""


def _clean_cause(line: str) -> str:
    host = settings.text("PITANGUS_HOST_DATA_DIR")
    if len(host) > 1:
        line = line.replace(host, "<datos>")
    return mask(" ".join(line.split())[:240])


def config_cause(completed: subprocess.CompletedProcess) -> str:
    """Why an engine rejected its configuration: the first error line (a Go panic ends with its stack, not its cause)."""
    lines = [line.strip() for line in _ANSI.sub("", completed.stderr or "").splitlines() if line.strip()]
    first = next((line for line in lines if re.search(r"panic:|FTL|FATAL|error", line, re.IGNORECASE)), None)
    return _clean_cause(first) if first else cause(completed)


def with_cause(message, completed: subprocess.CompletedProcess | None):
    reason = cause(completed)
    if not reason:
        return message
    return msg("scanning.engines.with_cause", message=message.rstrip(".") if isinstance(message, str) else message, cause=reason)


def joined(items, key: str = "scanning.join.comma"):
    """Folds strings or messages into one message, two at a time, with `key` ({{first}} and {{second}})."""
    items = [item for item in items if item]
    if all(isinstance(item, str) for item in items) and key == "scanning.join.comma":
        return ", ".join(items)
    result = items[0] if items else ""
    for item in items[1:]:
        result = msg(key, first=result, second=item)
    return result


def and_list(items):
    """«A», «A and B», «A, B and C», in the reader's language."""
    items = list(items)
    if len(items) <= 1:
        return items[0] if items else ""
    return msg("scanning.join.and", rest=joined(items[:-1]), last=items[-1])


def host_mount_problem() -> dict | None:
    """Inside the container, the engines mount the *host's* data folder. If it couldn't be
    found (neither by asking Docker nor from the environment), the engines would fail with no explanation."""
    inside = settings.text("PITANGUS_DATA_DIR")
    if not inside or not in_container():
        return None
    if any(pair[0] == inside for pair in _host_pairs()):
        return None
    return msg("scanning.engines.host_mount_problem")


_last_image_error: dict[str, str] = {}


DOCKER_SOCKET = Path("/var/run/docker.sock")


def socket_problem() -> dict | None:
    """Typical on Linux and WSL: the socket belongs to the `docker` group, not root, and the container isn't in it."""
    try:
        if not DOCKER_SOCKET.exists() or os.access(DOCKER_SOCKET, os.R_OK | os.W_OK):
            return None
        gid = DOCKER_SOCKET.stat().st_gid
    except OSError:
        return None
    return msg("scanning.engines.socket_problem", gid=gid)


RECHECK_SECONDS = 60  # a Docker that wasn't answering is asked again after this (it may have been starting)


def docker_available() -> bool:
    checked = _docker_state.get("at")
    stale = checked is not None and not _docker_state.get("ok") and time.monotonic() - checked > RECHECK_SECONDS
    if "ok" not in _docker_state or stale:
        binary = shutil.which("docker")
        try:
            completed = subprocess.run([binary, "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True,
                                       timeout=8) if binary else None
        except (OSError, subprocess.TimeoutExpired):
            completed = None
        # Without access to the socket, `docker info` can exit 0 with no server version: that isn't a usable Docker.
        _docker_state["ok"] = bool(completed) and completed.returncode == 0 and bool(completed.stdout.strip())
        _docker_state["why"] = socket_problem() or cause(completed) if not _docker_state["ok"] else ""
        _docker_state["at"] = time.monotonic()
        _runner_state.pop("auto", None)  # the runner choice follows what Docker answers now
    return _docker_state["ok"]


def docker_problem():
    """Why Docker isn't available, in one sentence; empty if it is."""
    return "" if docker_available() else (_docker_state.get("why") or msg("scanning.engines.docker_unresponsive"))


def image_available(key: str) -> bool:
    binary = shutil.which("docker")
    try:
        completed = subprocess.run([binary, "image", "inspect", IMAGES[key]["image"]], capture_output=True, text=True,
                                   timeout=15) if binary else None
    except (OSError, subprocess.TimeoutExpired):
        return False
    _last_image_error[key] = cause(completed)
    return bool(completed) and completed.returncode == 0


# The local runner runs the same pinned engines installed in the worker image (the `worker-standalone` target), for
# platforms without a Docker socket. Each engine's arguments are the ones its image's entrypoint takes.
BINARIES = {"trivy": "trivy", "osv-scanner": "osv-scanner", "betterleaks": "betterleaks", "opengrep": "opengrep",
            "grype": "grype", "checkov": "checkov", "zizmor": "zizmor"}
_runner_state: dict[str, str] = {}


def runner() -> str:
    """"docker" (a sibling container per engine) or "local" (the engines installed next to the worker).
    PITANGUS_ENGINE_RUNNER decides; `auto` prefers Docker and falls back to installed engines."""
    choice = settings.text("PITANGUS_ENGINE_RUNNER")
    if choice in ("docker", "local"):
        return choice
    if "auto" not in _runner_state:
        installed = any(shutil.which(binary) for binary in BINARIES.values())
        _runner_state["auto"] = "local" if installed and not docker_available() else "docker"
    return _runner_state["auto"]


def engine_ready(key: str) -> bool:
    if runner() == "local":
        return key in BINARIES and shutil.which(BINARIES[key]) is not None
    return docker_available() and image_available(key)


def engines_available() -> bool:
    """Whether this process can run engines at all (Docker answers, or at least one engine is installed)."""
    if runner() == "local":
        return any(shutil.which(binary) for binary in BINARIES.values())
    return docker_available()


def engines_problem():
    """Why no engine can run, in one sentence; empty if some can."""
    if engines_available():
        return ""
    return msg("scanning.engines.none_installed") if runner() == "local" else docker_problem()


def enabled(key: str, switches: dict[str, dict] | None = None) -> bool:
    """Whether engine `key` runs, under `switches` (engine_switches.resolve) or, without them, the environment and the
    defaults alone (what `make engines` sees)."""
    return engine_switches.is_on(switches if switches is not None else engine_switches.resolve(None), key)


def switched_off(key: str, switches: dict[str, dict]) -> EngineResult | None:
    """The result of an engine turned off (in the panel, or pinned off by the server): not run (disabled), never a clean
    run. Like any engine that didn't look, it fixes nothing it found before (findings/registry.py)."""
    reason = engine_switches.off_reason(switches, key, IMAGES[key]["name"])
    return None if reason is None else {**_result(key, "not_tested", reason), "disabled": True}


# What a scan does with a published image that isn't on this machine. A one-shot scan (`pitangus scan`, the GitHub
# Action, the pre-commit hook: no worker, no panel) pulls it by its digest, as it always did; an analysis the server's
# worker runs (engine_switches.server_analysis) never does, since a pull can take minutes: it declares the engine not
# run and the worker prepares the image.
declaring_missing_images = engine_switches.server_analysis


def unavailable(key: str, without_docker):
    """None if engine `key` can run; else the reason, in the terms of the runner in use. A published image that isn't
    here is pulled by its digest in a one-shot scan, and only declared (being prepared) in the server's analyses."""
    if runner() == "local":
        return None if engine_ready(key) else msg("scanning.engines.not_installed", engine=IMAGES[key]["name"], binary=BINARIES[key])
    if not docker_available():
        return without_docker
    if "@sha256:" in IMAGES[key]["image"] and not image_available(key):
        if engine_switches.in_server_analysis():
            return msg("scanning.engines.image_missing", engine=IMAGES[key]["name"])
        if (problem := pull_image(key)) is not None:
            return msg("scanning.engines.image_pull_failed", engine=IMAGES[key]["name"], image=IMAGES[key]["image"], cause=problem)
    return None


def engine_status(data_dir: Path | None = None) -> list[dict]:
    """Which engines are ready (images in the host's Docker, or installed binaries). For `make doctor` and `engines`;
    `data_dir`: whose panel switches count (without it, the environment and the defaults)."""
    local = runner() == "local"
    switches = engine_switches.resolve(data_dir)
    listed = {key: meta for key, meta in IMAGES.items()
              if key not in WEB_ENGINES or (not local and (key in EXPOSURE_ENGINES or enabled("zap", switches)))}
    return [{"tool": key, "name": meta["name"], "version": meta["version"], "image": shutil.which(BINARIES[key]) or BINARIES[key] if local else meta["image"],
             "ready": engine_ready(key), "built_locally": local or "@sha256:" not in meta["image"], "enabled": enabled(key, switches)}
            for key, meta in listed.items()]


def pulled_images() -> list[str]:
    """The published images `make engines` pulls (scripts/engine-images.sh applies the same rule to this file without
    Python, so from the environment and the defaults only: the panel prepares what it turns on): no engine turned off,
    no full-DAST tool without PITANGUS_DAST_ENABLED, the exposure check's unless pinned off."""
    switches = engine_switches.resolve(None)
    return [meta["image"] for key, meta in IMAGES.items() if "@sha256:" in meta["image"] and enabled(key, switches)]


def pull_image(key: str):
    """Pulls one published image by its digest; None when it's there afterwards, else why not."""
    binary = shutil.which("docker")
    if "@sha256:" not in IMAGES[key]["image"]:
        return None if image_available(key) else msg("scanning.engines.action.build")
    if not binary:
        return msg("scanning.engines.action.no_docker")
    try:
        completed = subprocess.run([binary, "pull", "--quiet", IMAGES[key]["image"]], capture_output=True, text=True, timeout=3600)
    except (OSError, subprocess.TimeoutExpired):
        completed = None
    return None if completed is not None and completed.returncode == 0 else with_cause(msg("scanning.engines.action.pull_failed"), completed)


def image_readiness() -> dict[str, bool]:
    """Every engine's image (or installed binary) on this worker's server: what the panel shows next to each switch."""
    if runner() == "local":
        return {key: key in BINARIES and shutil.which(BINARIES[key]) is not None for key in IMAGES}
    if not docker_available():
        return dict.fromkeys(IMAGES, False)
    return {key: image_available(key) for key in IMAGES}


def prepare(key: str):
    """Gets every image switch `key` needs onto this server ("Prepare engine"): None when they're all there, else why
    not. With installed engines there is nothing to download."""
    if runner() == "local":
        return None if all(engine_ready(image) for image in engine_switches.BY_KEY[key].images) else \
            msg("scanning.engines.action.not_installed")
    if problem := docker_problem():
        return problem
    for image in engine_switches.BY_KEY[key].images:
        if not image_available(image) and (problem := pull_image(image)) is not None:
            return problem
    return None


def pull_engines(report=None, data_dir: Path | None = None) -> list[dict]:
    """Pulls the missing published images by digest; Opengrep's is built with `make build`.

    `make engines` pulls from the host (with progress); this is for those who don't use make."""
    if runner() == "local":  # installed with the image: nothing to download
        return [{**row, "action": msg("scanning.engines.action.none") if row["ready"] else msg("scanning.engines.action.not_installed")}
                for row in engine_status(data_dir)]
    binary = shutil.which("docker")
    results = []
    for row in engine_status(data_dir):
        if not row["enabled"]:
            results.append({**row, "action": msg("scanning.engines.action.disabled")})
            continue
        if report and not (row["ready"] or row["built_locally"] or not binary):
            report(msg("scanning.engines.pulling", name=row["name"], version=row["version"]))
        if row["ready"] or row["built_locally"] or not binary:
            results.append({**row, "action": msg("scanning.engines.action.none") if row["ready"]
                            else msg("scanning.engines.action.build") if row["built_locally"] else msg("scanning.engines.action.no_docker")})
            continue
        problem = pull_image(row["tool"])
        results.append({**row, "ready": problem is None, "action": msg("scanning.engines.action.pulled") if problem is None else problem})
    return results


@dataclass(frozen=True)
class ScanContext:
    """What every engine of a scan may need: the snapshot, the data folder (caches), the KEV/EPSS feeds, the secret
    detection settings of this repository and whether the person allowed queries that leave the machine."""
    root: Path
    data_dir: Path
    feeds: dict
    secret_settings: dict | None = None
    allow_osv_upload: bool = False
    # Which engines are on for this scan (engine_switches.resolve), read once when it starts; None: read them when run.
    switches: dict | None = None


class Engine(Protocol):
    """An engine a scan runs. `key` names it in IMAGES (version, image, how it's installed); `required`: without its
    result the run is incomplete; `progress`: the message said before it runs; `merged`: its progress line waits for
    the merge with other engines, which completes its detail."""
    key: str
    required: bool
    progress: str
    merged: bool

    def run(self, context: ScanContext) -> EngineResult: ...


@dataclass(frozen=True)
class EngineStep:
    """An `Engine` made of a function: how most engines are declared (`scanning/repository.py`, CODE_ENGINES)."""
    key: str
    call: Callable[[ScanContext], EngineResult]
    progress: str
    required: bool = True
    merged: bool = False

    def run(self, context: ScanContext) -> EngineResult:
        return self.call(context)


def run_engines(engines: Sequence[Engine], context: ScanContext, report: Callable[[str, object], None]) -> dict[str, EngineResult]:
    """Runs each engine in order and reports it; returns their results by key. An engine that fails to run says so in
    its result (`inconclusive`), never by raising; one that didn't finish opens nothing (engine_contract.settled)."""
    results: dict[str, EngineResult] = {}
    switches = context.switches if context.switches is not None else engine_switches.resolve(context.data_dir)
    for engine in engines:
        off = switched_off(engine.key, switches)
        if off is None:  # one turned off isn't announced as running, nor run: its result says so
            report("info", msg(engine.progress, version=IMAGES[engine.key]["version"]))
        result = results[engine.key] = engine_contract.settled(off if off is not None else engine.run(context))
        if not engine.merged:
            report_done(report, result)
    return results


def names_engine(detail, name: str | None) -> bool:
    """Whether a message opens with the engine `name` as its subject ("Trivy exceeded the time limit", "{{engine}}: not
    run"), read from its catalog source, through a leading message parameter ("{{first}} {{second}}"): a line that
    shows it needs no "Engine:" label, or the name would appear twice."""
    if not name or not is_msg(detail):
        return False
    params = detail.get("params") or {}
    entries = catalog("en")
    source = (entries.get(detail["$t"]) or entries.get(f"{detail['$t']}_other") or "").lstrip()
    lead = re.match(r"\{\{\s*(\w+)\s*\}\}", source)
    if lead:
        return params.get(lead[1]) == name if lead[1] == "engine" else names_engine(params.get(lead[1]), name)
    return re.match(rf"{re.escape(name)}\b", source) is not None


def labelled(name: str, detail):
    """`detail` as one line about the engine `name`, which it names once."""
    return detail if names_engine(detail, name) else msg("scanning.progress.engine", engine=name, detail=detail)


def report_done(report: Callable[[str, object], None], result: EngineResult) -> None:
    report("ok" if result["status"] != "inconclusive" else "warn",
           labelled(result.get("name") or IMAGES[result["tool"]]["name"], result.get("detail")))


def _result(key: str, status: str, detail, findings: list | None = None, started: float | None = None) -> EngineResult:
    meta = IMAGES[key]
    return {"tool": key, "name": meta["name"], "version": meta["version"], "image": meta["image"],
            "status": status, "detail": detail, "findings": findings or [],
            "duration_s": round(time.time() - started, 1) if started else None}


def engine_user() -> list[str]:
    """`--user` with this process's UID and GID, and a writable HOME for engines that keep state."""
    if not hasattr(os, "getuid"):
        return []
    return ["--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp"]


def writable_cache(preferred: Path) -> Path:
    """The engine's cache if this user can write to it; otherwise (e.g. engines running as root in an
    earlier version created it), a new one next to it. The old one can be deleted by hand."""
    preferred.mkdir(parents=True, exist_ok=True)
    blocked = not os.access(preferred, os.W_OK | os.X_OK) or any(
        not os.access(entry, os.W_OK) for entry in list(preferred.iterdir())[:50])
    if not blocked:
        return preferred
    fallback = preferred.with_name(f"{preferred.name}-{os.getuid() if hasattr(os, 'getuid') else 'user'}")
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def _filtered(command: list[str], *, timeout: int, keep: Callable[[str], str | None], env: dict[str, str] | None = None,
              cwd: str | None = None, new_session: bool = False, on_timeout: Callable[[subprocess.Popen], None]) -> tuple[int, str, str]:
    """(exit code, stdout, stderr) of `command`, its stderr filtered line by line as it arrives: only what `keep`
    returns of each line is kept (None: nothing). An engine's debug log (the files it read) can run to hundreds of
    megabytes and carries what it matched: what isn't kept is never held. `on_timeout` stops whatever it started."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
                               errors="replace", env=env, cwd=cwd, start_new_session=new_session)
    out: list[str] = []
    kept: list[str] = []

    def drain_stdout() -> None:
        out.append(process.stdout.read())

    def drain_stderr() -> None:
        for line in process.stderr:
            if (text := keep(line)) is not None:
                kept.append(text)
    readers = [threading.Thread(target=drain_stdout, daemon=True), threading.Thread(target=drain_stderr, daemon=True)]
    for reader in readers:
        reader.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        on_timeout(process)
        process.wait()
        raise
    finally:
        for reader in readers:
            reader.join(timeout=60)
        for stream in (process.stdout, process.stderr):
            stream.close()
    return process.returncode, "".join(out), "".join(kept)


def _run(key: str, arguments: list[str], snapshot: Path | None, *, network: bool = False,
         mounts: list[str] | None = None, timeout: int = 900, env: dict[str, str] | None = None,
         secret_env: dict[str, str] | None = None, hosts: dict[str, str] | None = None,
         image_user: bool = False, stdin: str | None = None, pinned_only: bool = False,
         entrypoint: str | None = None, keep: Callable[[str], str | None] | None = None) -> subprocess.CompletedProcess:
    """The engine's ephemeral container. `secret_env` travels through the Docker client's environment
    (`-e NAME` with no value), never on the command line, so it doesn't show in `ps` or in the logs.
    `hosts`: names the container resolves to a fixed address ({name: address}), already checked by the caller;
    `pinned_only`: those are the only names it resolves (its DNS server is its own loopback, where nothing answers).
    `image_user`: run as the image's own user (ZAP's Java takes its home from passwd), never with a snapshot.
    `stdin`: text handed to the container on its standard input (secrets that must never land in a file).
    `entrypoint`: the program to start instead of the image's own (a shell that reads that input first).
    `keep`: what of each stderr line is kept, as it arrives (`_filtered`)."""
    if image_user and snapshot is not None:
        raise ValueError("an engine running as its image's user never mounts a snapshot")
    if pinned_only and not hosts:
        raise ValueError("pinned_only needs the pinned hosts")
    if runner() == "local":
        if stdin is not None or pinned_only or entrypoint is not None:
            raise ValueError("standard input and pinned-only resolution need the Docker runner")
        return _run_local(key, arguments, snapshot, mounts=mounts, timeout=timeout, env=env, secret_env=secret_env, network=network,
                          keep=keep)
    environment = [part for name, value in (env or {}).items() for part in ("-e", f"{name}={value}")]
    environment += [part for name in (secret_env or {}) for part in ("-e", name)]
    source = ["-v", f"{host_path(snapshot)}:/src:ro"] if snapshot is not None else []
    docker = shutil.which("docker")
    name = f"pitangus-{key}-{uuid.uuid4().hex[:12]}"
    command = [docker, "run", "--rm", *(["-i"] if stdin is not None else []), "--name", name, "--label", "pitangus.engine=1",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               # Only /tmp (HOME) and the mounted folders are writable; the tmpfs counts against --memory.
               "--read-only", "--tmpfs", f"/tmp:rw,{'exec' if key in EXEC_FROM_TMP else 'noexec'},nosuid,nodev,size={ENGINE_TMPFS}",
               *([] if image_user else engine_user()), "--pids-limit", "512", "--memory", "3g", "--cpus", "2",
               "--network", "bridge" if network else "none",
               *[part for host, address in (hosts or {}).items() for part in ("--add-host", f"{host}:{address}")],
               *(["--dns", "127.0.0.1"] if pinned_only else []),
               # An image built here has no digest: never let Docker fetch that name from a registry instead.
               *([] if "@sha256:" in IMAGES[key]["image"] else ["--pull", "never"]),
               *source, *environment, *(mounts or []), *(["--entrypoint", entrypoint] if entrypoint else []),
               IMAGES[key]["image"], *arguments]
    process_env = {**os.environ, **(secret_env or {})} if secret_env else None

    def remove(process: subprocess.Popen | None = None) -> None:
        # The timeout only kills the docker client: the engine container would keep its CPU and memory.
        if process is not None:
            process.kill()
        try:
            subprocess.run([docker, "rm", "--force", name], capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            pass
    if keep is not None and stdin is None:
        code, stdout, stderr = _filtered(command, timeout=timeout, keep=keep, env=process_env, on_timeout=remove)
        return subprocess.CompletedProcess(command, code, stdout, stderr)
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=process_env, input=stdin)
    except subprocess.TimeoutExpired:
        remove()
        raise


_log = logging_setup.get("engines")
_netns_state: dict[str, list[str]] = {}


def network_isolation() -> list[str]:
    """The prefix that runs a local engine in its own, empty network namespace (`unshare`), or [] where the platform
    doesn't allow it: most containers without extra privileges have no user namespaces. Asked once per process."""
    if "prefix" not in _netns_state:
        found: list[str] = []
        binary = shutil.which("unshare")
        for mapping in ("--map-current-user", "--map-root-user") if binary else ():
            prefix = [binary, "--user", mapping, "--net", "--"]
            try:
                if subprocess.run([*prefix, "true"], capture_output=True, timeout=10).returncode == 0:
                    found = prefix
                    break
            except (OSError, subprocess.TimeoutExpired):
                break
        if not found:
            _log.warning("local_engines_share_the_network", extra={"reason": "unshare --user --net is not allowed here"})
        _netns_state["prefix"] = found
    return _netns_state["prefix"]


def _run_local(key: str, arguments: list[str], snapshot: Path | None, *, mounts: list[str] | None, timeout: int,
               env: dict[str, str] | None, secret_env: dict[str, str] | None, network: bool = False,
               keep: Callable[[str], str | None] | None = None) -> subprocess.CompletedProcess:
    """The engine installed next to the worker, with the same arguments as its container. Container paths (/src,
    /cache, /rules…) become the real folders, and back in its output, so parsers see what they always saw.

    It gets a fresh HOME and only PATH from this process: never the database URL, the master key or any other
    setting. An engine that needs no network gets an empty network namespace where the platform allows it
    (`network_isolation`); elsewhere it runs with its offline flags. Pinned names (`hosts`) need the Docker runner.
    """
    binary = shutil.which(BINARIES[key])
    if binary is None:
        raise OSError(f"{BINARIES[key]} is not installed")
    paths = {"/src": str(Path(snapshot).resolve())} if snapshot is not None else {}
    parts = list(mounts or [])
    for flag, spec in zip(parts[::2], parts[1::2]):
        if flag == "-v":
            source, destination = spec.split(":")[:2]
            paths[destination] = source
    order = sorted(paths, key=len, reverse=True)

    def local(value: str) -> str:
        for inside in order:
            if value == inside or value.startswith(inside + "/"):
                return paths[inside] + value[len(inside):]
        return value

    def back(text: str) -> str:
        for inside in order:
            text = text.replace(paths[inside], inside)
        return text

    with tempfile.TemporaryDirectory(prefix=f"engine-{key}-") as home:
        environment = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "HOME": home, "TMPDIR": home,
                       "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONUTF8": "1", **{name: local(value) for name, value in (env or {}).items()},
                       **(secret_env or {})}
        # `ulimit -c 0`: a crashing engine never dumps repository contents to disk. Through sh rather than preexec_fn,
        # which isn't safe in a process with threads (the worker has them); "$@" passes the arguments untouched.
        isolated = [] if network else network_isolation()
        command = [*isolated, "/bin/sh", "-c", 'ulimit -c 0 && exec "$0" "$@"', binary, *(local(argument) for argument in arguments)]
        if keep is not None:
            # The real folders show in its log: the filter sees the lines as they will be read, with container paths.
            returncode, stdout, stderr = _filtered(command, timeout=timeout, keep=lambda line: keep(back(line)), env=environment,
                                                   cwd=home, new_session=True,
                                                   on_timeout=lambda process: os.killpg(process.pid, signal.SIGKILL))
        else:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment,
                                       cwd=home, start_new_session=True)
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)  # the engine and anything it started
                process.communicate()
                raise
            returncode = process.returncode
    # Report files an engine writes (Betterleaks' /out) also name the real folders.
    if "/out" in paths:
        for report in Path(paths["/out"]).glob("*.json"):
            if report.stat().st_size < 50_000_000:
                report.write_text(back(report.read_text(encoding="utf-8", errors="replace")), encoding="utf-8")
    return subprocess.CompletedProcess([BINARIES[key], *arguments], returncode, back(stdout), back(stderr))


def _relative(path: str) -> str:
    return re.sub(r"^/src/", "", path or "")


def _stable(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


SEVERITY_NAME = {"critical": msg("scanning.severity.critical"), "high": msg("scanning.severity.high"),
                 "medium": msg("scanning.severity.medium"), "low": msg("scanning.severity.low"), "info": msg("scanning.severity.info")}


SECRET_SEVERITY = "critical"  # an exposed secret is always critical, whatever the engine or the rule says


def _base(scanner: str, rule: str, title, path: str, line: int, severity: str, *, reason,
          remediation, cwe: list[int], owasp: str, confidence: int, digest: str, tool: str) -> Finding:
    if scanner == "secrets":
        severity = SECRET_SEVERITY
    action = "act" if severity == "critical" else "attend" if severity == "high" else "track"
    factors = [msg("scanning.priority.static_severity", severity=SEVERITY_NAME.get(severity, severity)),
               msg("scanning.priority.confirm_reachability")]
    # A secret in tests, docs or examples is still a secret, but rarely the one in production: attended, not acted on now.
    if scanner == "secrets" and secret_filter.outside_code(path):
        action = "attend"
        factors.append(msg("scanning.priority.secret_outside_code"))
    return {"finding_id": digest[:16], "fingerprint": digest, "scanner": scanner, "tool": tool, "rule_id": rule,
            "title": title[:200] if isinstance(title, str) else title, "path": path, "line": line, "severity": severity,
            "confidence": confidence, "verdict": "candidate", "cwe": cwe, "owasp": [owasp], "cve": [], "ghsa": [],
            "package": None, "advisory": None, "kev": None, "epss": None,
            "priority": {"action": action, "factors": factors},
            "reason": reason, "remediation": remediation}


# --- Opengrep ---------------------------------------------------------------------

def snapshot_languages(snapshot: Path) -> dict:
    """Which languages the repository has, and which of them have our own rules."""
    present: dict[str, int] = {}
    for path in snapshot.rglob("*"):
        if not path.is_file():
            continue
        for table in (RULE_LANGUAGES, OTHER_LANGUAGES):
            for language, extensions in table.items():
                if path.suffix.lower() in extensions:
                    present[language] = present.get(language, 0) + 1
    return {"covered": {name: count for name, count in present.items() if name in RULE_LANGUAGES},
            "uncovered": {name: count for name, count in present.items() if name not in RULE_LANGUAGES}}


def _rule_texts(value, limit: int = 2000) -> dict | str:
    """A Pitangus rule text in its own languages (`metadata.title` / `metadata.fix` as {en, es}), or "" if absent."""
    from pitangus.shared.i18n import inline
    if not isinstance(value, dict):
        return ""
    return inline({locale: text[:limit] for locale, text in value.items() if isinstance(text, str)})


def _rule_id(check_id: str) -> str:
    """Opengrep prefixes each rule id with the dotted path of the rules folder ("rules." in a container, the whole real
    path when the engine runs locally). Our ids start at "appsec.", so the fingerprint is the same either way."""
    start = check_id.find("appsec.")
    return check_id[start:] if start >= 0 else check_id.removeprefix("rules.")


# An inline suppression at the end of a line (`# nosemgrep`, `// nosemgrep: rule-id`): left out of the snippet, so adding
# one doesn't change the finding it silences.
NOSEM_COMMENT = re.compile(r"\s*(?:#|//|/\*|--|<!--|')\s*nosem(?:grep)?\b.*$", re.IGNORECASE)


def _owasp(value) -> str:
    """The OWASP Top 10 category of a rule: ours write one (`A05:2025`); others a list across editions
    (`A1:2017-Injection`, `A03:2021-Injection`), of which the latest edition is kept."""
    items = value if isinstance(value, list) else [value] if value else []
    found = sorted(((int(match.group(2)), f"A{int(match.group(1)):02d}:{match.group(2)}")
                    for item in items if (match := re.match(r"A(\d{1,2}):(\d{4})", str(item)))), reverse=True)
    return found[0][1] if found else "A05:2025"


def parse_opengrep(payload: dict, *, silenced: bool = False) -> list[Finding]:
    """Opengrep's findings; with `silenced`, the matches a `nosemgrep` comment silences instead (it runs with
    `--disable-nosem`, which reports them flagged `is_ignored`)."""
    findings, seen = [], set()
    lines_of: dict[tuple[str, str, str], list[int]] = {}  # identical snippets of one rule in one file, by line
    results = sorted(payload.get("results", []), key=lambda item: (str(item.get("path", "")), int((item.get("start") or {}).get("line") or 1)))
    for result in results:
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        rule = _rule_id(str(result.get("check_id", "")))
        path = _relative(result.get("path", ""))
        line = int((result.get("start") or {}).get("line") or 1)
        snippet = " ".join(NOSEM_COMMENT.sub("", str(extra.get("lines", ""))).split())[:200]
        severity = "critical" if str(metadata.get("severity", "")).upper() == "CRITICAL" \
            else SEVERITY_LABEL.get(str(extra.get("severity", "")).upper(), "medium")
        # Ours list numbers; other rule sets write `CWE-79: …`, alone or in a list.
        raw_cwe = metadata.get("cwe", [])
        cwe = [int(found.group(1)) for item in (raw_cwe if isinstance(raw_cwe, list) else [raw_cwe])
               if (found := re.match(r"(?:CWE-)?(\d+)\b", str(item)))]
        title = _rule_texts(metadata.get("title"), 200) or str(metadata.get("shortDescription") or "")[:200] \
            or f"{metadata.get('category', 'sast').capitalize()}: {rule.rsplit('.', 1)[-1].replace('-', ' ')}"
        # A rule without its own fix text: never its message, which interpolates what the result matched (code).
        remediation = _rule_texts(metadata.get("fix")) or msg("scanning.opengrep.no_fix", rule=rule)
        finding = _base(
            "sast", rule, title, path, line, severity, tool="opengrep",
            reason=msg("scanning.opengrep.reason", path=path, line=line), remediation=remediation,
            cwe=cwe, owasp=_owasp(metadata.get("owasp")),
            confidence=CONFIDENCE.get(str(metadata.get("confidence", "MEDIUM")).upper(), 6),
            # The fingerprint uses the snippet, not the line: moving code must not reopen tickets.
            digest=_stable("sast", rule, path, snippet))
        # The same line copied elsewhere in the file is another finding: the first keeps the plain fingerprint, the next
        # ones carry their order. Two matches of the same rule on the same line are still one.
        lines = lines_of.setdefault((rule, path, snippet), [])
        if line not in lines:
            lines.append(line)
        if (order := lines.index(line)) > 0:
            digest = _stable("sast", rule, path, snippet, f"#{order + 1}")
            finding = {**finding, "fingerprint": digest, "finding_id": digest[:16], "family": finding["fingerprint"]}
        finding["snippet"] = str(extra.get("lines", ""))[:2000]  # what the canonical identity reads (findings/canonical.py)
        if bool(extra.get("is_ignored")) != silenced:
            continue
        if finding["fingerprint"] not in seen:
            seen.add(finding["fingerprint"])
            findings.append(finding)
    return findings


MINIFIED_SUFFIXES = {".js", ".mjs", ".cjs", ".css"}


def minified_files(snapshot: Path, limit: int = 200) -> list[str]:
    """Compiled or minified JavaScript and CSS: endless lines that SAST can't make sense of.

    They stay in the snapshot (a bundle may carry an embedded key and Betterleaks must see it);
    they are only excluded from Opengrep.
    """
    found = []
    for path in sorted(snapshot.rglob("*")):
        if len(found) >= limit:
            break
        if path.suffix.lower() not in MINIFIED_SUFFIXES or not path.is_file() or path.is_symlink():
            continue
        try:
            with path.open("rb") as handle:
                head = handle.read(512_000)
        except OSError:
            continue
        lines = head.split(b"\n")
        if max((len(line) for line in lines), default=0) > 3000 or len(head) / max(1, len(lines)) > 500:
            found.append(path.relative_to(snapshot).as_posix())
    return found


def _rules_for(snapshot: Path) -> Path:
    """The rules as the engine can mount them. With compose they come mounted from the host; with the app launched
    by `docker run` (CI) they exist only inside its image, and the engine (a sibling container) wouldn't see them.
    In that case they are copied next to the snapshot, which is in the mounted data folder. With the third-party rules
    on (PITANGUS_THIRD_PARTY_RULES), both sets go there, each in its own folder."""
    if settings.flag("PITANGUS_THIRD_PARTY_RULES") and THIRD_PARTY_RULES_DIR.is_dir():
        target = snapshot.parent / "opengrep-rules-all"
        if not target.exists():
            (target / "pitangus").mkdir(parents=True)
            for rule in RULES_DIR.glob("*.yml"):
                shutil.copy2(rule, target / "pitangus" / rule.name)
            shutil.copytree(THIRD_PARTY_RULES_DIR, target / "gitlab")
        return target
    if not in_container() or any(Path(inside).resolve() == RULES_DIR.resolve() for inside, _ in _host_pairs()):
        return RULES_DIR
    target = snapshot.parent / "opengrep-rules"
    if not target.exists():
        shutil.copytree(RULES_DIR, target)
    return target


# What each engine always writes when it read its input (engine_contract): the exit codes of a run that worked, the
# shape of its JSON and a field it never leaves out.
OPENGREP = Contract("Opengrep", frozenset({0, 1}), (dict,), lambda payload: isinstance(payload.get("results"), list)
                    and isinstance(payload.get("paths"), dict))
BETTERLEAKS = Contract("Betterleaks", frozenset({0}), (list,))
TRIVY = Contract("Trivy", frozenset({0}), (dict,), lambda payload: "SchemaVersion" in payload)
OSV = Contract("OSV-Scanner", frozenset({0, 1}), (dict,), lambda payload: isinstance(payload.get("results"), list))
OSV_SCANNED = re.compile(r"^Scanned (\S+) file", re.M)
OSV_FAILED = re.compile(r"^Error during extraction: \([^)]*\) (\S+?):", re.M)


# Opengrep's default ignore list leaves out `build/`, `dist/`, `vendor/`, `node_modules/`, `test/`, `tests/` and `*.min.js`
# wherever they are, without listing them. Ours replaces it (a `.semgrepignore` at the root wins over the defaults): the
# snapshot already holds only what SAST should read (sources/repositories.set_apart), minified files are left out by
# their content (`minified_files`), and only test code stays out, on purpose, each folder listed unexamined (`tests`).
TEST_FOLDERS = ("test", "tests")
SEMGREPIGNORE = "# Written by Pitangus (scanning/engines.py): replaces Opengrep's default list.\n" + "".join(
    f"{folder}/\n" for folder in TEST_FOLDERS) + "*_test.go\n"


def test_code(snapshot: Path) -> dict[str, str]:
    """What the `.semgrepignore` leaves out of SAST: the outermost test folders ("src/test/") and Go test files."""
    found: dict[str, str] = {}
    for directory, folders, files in os.walk(snapshot):
        relative = Path(directory).relative_to(snapshot)
        for folder in [folder for folder in folders if folder in TEST_FOLDERS]:
            found[(relative / folder).as_posix() + "/"] = "tests"
            folders.remove(folder)
        found.update({(relative / name).as_posix(): "tests" for name in files if name.endswith("_test.go")})
    return found


def run_opengrep(snapshot: Path) -> EngineResult:
    started = time.time()
    if runner() == "local":
        if not engine_ready("opengrep"):
            return _result("opengrep", "not_tested", unavailable("opengrep", None))
    elif not docker_available():
        return _result("opengrep", "not_tested", msg("scanning.opengrep.no_docker", problem=docker_problem()))
    elif not image_available("opengrep"):
        reason = _last_image_error.get("opengrep", "")
        # "No such image" means it hasn't been built yet; anything else is a problem with Docker.
        if not reason or "no such image" in reason.lower():
            return _result("opengrep", "not_tested", msg("scanning.opengrep.image_missing"))
        return _result("opengrep", "not_tested", msg("scanning.opengrep.image_error", cause=reason))
    languages = snapshot_languages(snapshot)
    compiled = minified_files(snapshot)
    excludes = [part for path in compiled for part in ("--exclude", path)]
    tests = test_code(snapshot)
    try:
        (snapshot / ".semgrepignore").write_text(SEMGREPIGNORE, encoding="utf-8")
        # Taint across the functions of a file (the rules' README promises it); every file the snapshot keeps, not
        # only the ones under Opengrep's default 1 MB; two jobs, so a batch on several workers doesn't starve the host.
        completed = _run("opengrep", ["scan", "--config", "/rules", "--json", "--quiet", "--taint-intrafile", "--disable-nosem",
                                      "--max-target-bytes", str(MAX_FILE), "--jobs", str(OPENGREP_JOBS), *excludes, "/src"], snapshot,
                         mounts=["-v", f"{host_path(_rules_for(snapshot))}:/rules:ro"])
        # 0: no findings · 1: findings. Any other code (2 fatal, 7 invalid configuration…) means it didn't scan.
        payload, failure = engine_contract.verdict(OPENGREP, completed.returncode, completed.stdout)
        if failure:
            return engine_contract.failed(_result("opengrep", "inconclusive", with_cause(failure, completed), started=started), failure)
    except subprocess.TimeoutExpired:
        return engine_contract.failed(_result("opengrep", "inconclusive", msg("scanning.opengrep.timeout"), started=started), msg("scanning.opengrep.timeout"))
    except (OSError, ValueError):
        unreadable = msg("scanning.engines.unreadable", engine="Opengrep")
        return engine_contract.failed(_result("opengrep", "inconclusive", unreadable, started=started), unreadable)
    # A third-party rule that saw what one of ours saw on the same line is folded into ours (scanning/sast_merge.py);
    # third-party code copied into the repository is listed apart as excluded, with why (scanning/vendored.py).
    # A rule that starts off (rule_set.dormant_rules) reports nothing, not even as excluded: the run records it as off.
    from pitangus.modules.scanning.rule_set import dormant_rules
    dormant = set(dormant_rules())
    # Silenced in the code: listed as excluded with why, never as fixed, and they reopen if the comment goes away. With
    # PITANGUS_IGNORE_REPO_SUPPRESSIONS a `nosemgrep` comment silences nothing (repo_controls).
    loud = repo_controls.ignored()
    reported = [*parse_opengrep(payload), *(parse_opengrep(payload, silenced=True) if loud else [])]
    findings, in_vendored = vendored.withhold(sast_merge.merge([item for item in reported if item["rule_id"] not in dormant]), snapshot)
    silenced = [] if loud else [{**item, "excluded_reason": msg("scanning.opengrep.silenced_reason")}
                                for item in sast_merge.merge(parse_opengrep(payload, silenced=True)) if item["rule_id"] not in dormant]
    errors = [item for item in payload.get("errors", []) if isinstance(item, dict)]
    covered = ", ".join(f"{name} ({count})" for name, count in sorted(languages["covered"].items())) \
        or msg("scanning.opengrep.no_covered_language")
    uncovered = ", ".join(sorted(languages["uncovered"]))
    parts = [msg("scanning.opengrep.detail", rulesets=sum(1 for _ in RULES_DIR.glob("*.yml")), languages=covered,
                 candidates=len(findings))]
    if uncovered:
        parts.append(msg("scanning.opengrep.uncovered", languages=uncovered))
    if compiled:
        parts.append(msg("scanning.opengrep.minified", count=len(compiled)))
    if tests:
        parts.append(msg("scanning.opengrep.tests", count=len(tests)))
    if errors:
        parts.append(msg("scanning.opengrep.errors", count=len(errors)))
    if silenced:
        parts.append(msg("scanning.opengrep.silenced", count=len(silenced)))
    if in_vendored:
        parts.append(msg("scanning.opengrep.vendored", count=len(in_vendored)))
    if dormant:
        parts.append(msg("scanning.opengrep.opt_in", count=len(dormant), rules=", ".join(sorted(dormant))))
    # What it skipped on its own (too large, unreadable): said, never silently left out. Exclusions are deliberate.
    skipped = [item for item in (payload.get("paths") or {}).get("skipped") or []
               if isinstance(item, dict) and not any(word in str(item.get("reason") or "") for word in ("exclude", "ignore"))]
    if skipped:
        parts.append(msg("scanning.opengrep.skipped", count=len(skipped)))
    detail = joined(parts, "scanning.join.sentences")
    status = "partial" if (errors or uncovered or skipped) else "completed"
    # What it didn't read, or didn't finish reading (a rule that timed out on a file reports an error with its path), can't
    # prove a finding there went away (findings/registry.covers). Opengrep lists skipped files only with --verbose.
    unexamined = sorted({_relative(str(item.get("path") or "")) for item in [*skipped, *errors] if item.get("path")})
    # Coverage: every file but those it didn't read (skipped, a rule that errored or timed out on it, a minified file
    # left out of SAST). A file in a folder it excludes by default holds none of its findings.
    reasons = {**tests, **dict.fromkeys(compiled, "minified"), **{_relative(str(item.get("path"))): "skipped" for item in skipped if item.get("path")},
               **{_relative(str(item.get("path"))): engine_contract.reason(item.get("type")) for item in errors if item.get("path")}}
    result = {**_result("opengrep", status, detail, findings, started), "unexamined": unexamined, "silenced": silenced, "vendored": in_vendored,
              "coverage": engine_contract.coverage("*", reasons)}
    # An error tied to no file is a rule that didn't load (or the run itself): every file went without that rule, so
    # nothing this run doesn't report is proven gone.
    unloaded = [item for item in errors if not item.get("path")]
    if unloaded:
        failure = msg("scanning.opengrep.rules_not_loaded", count=len(unloaded))
        if engine_contract.enforced():
            return engine_contract.recorded({**result, "status": "inconclusive", "detail": joined([detail, failure], "scanning.join.sentences")},
                                            failure, finished=True)
        return engine_contract.recorded(result, failure, finished=True)
    return engine_contract.recorded(result, None)


# --- Trivy ----------------------------------------------------------------------------

def _pick_fixed(fixed: str | None, installed: str) -> str | None:
    """The nearest fixed version above the installed one, by version order (9.0.80 → 9.0.90, not 10.1.25). Each
    candidate without its constraint operator (RubyGems writes `~> 6.1.7, >= 6.1.7.1`); None when none is above the
    installed version: a fix is never offered below what is installed."""
    candidates = [re.sub(r"^[~^<>=!\s]+", "", item).strip() for item in str(fixed or "").split(",")]
    later = [item for item in candidates if item and compare_versions(item, installed) > 0]
    return min(later, key=cmp_to_key(compare_versions)) if later else None


def _trivy_vulnerability(entry: dict, target: str, ecosystem: str, feeds: dict, packages: dict | None = None,
                         system: bool = False) -> dict:
    identifier = str(entry.get("VulnerabilityID", ""))
    name, installed = str(entry.get("PkgName", "")), str(entry.get("InstalledVersion", ""))
    fixed = _pick_fixed(entry.get("FixedVersion"), installed)
    scores = entry.get("CVSS") or {}
    vector = score = None
    for source in ("nvd", "ghsa", "redhat"):
        block = scores.get(source) or {}
        if block.get("V3Vector"):
            vector, score = block["V3Vector"], cvss3_base_score(block["V3Vector"]) or block.get("V3Score")
            break
    # A package of the image's system: the distribution rates it for its own build (as Grype does), not NVD's generic
    # score; the same CVE then has one severity whichever engine saw it.
    label = str(entry.get("Severity") or "").upper()
    severity = severity_from_score(None, label) if system and label in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else severity_from_score(score, label)
    cves = [identifier] if identifier.startswith("CVE-") else [item for item in entry.get("VendorIDs", []) or [] if str(item).startswith("CVE-")]
    # Its other names: the GHSA among VendorIDs too, so another engine's report of the advisory under that one joins it.
    ghsas = sorted({str(item) for item in [identifier, *(entry.get("VendorIDs", []) or [])] if str(item).startswith("GHSA-")})
    kev = next((feeds.get("kev", {}).get(cve) for cve in cves if feeds.get("kev", {}).get(cve)), None)
    epss = next((feeds.get("epss", {}).get(cve) for cve in cves if feeds.get("epss", {}).get(cve)), None)
    priority = prioritize(severity, score, kev, epss, fixed)
    summary = str(entry.get("Title") or "").strip() or identifier
    cwe = [int(match.group(1)) for item in entry.get("CweIDs", []) or [] if (match := re.fullmatch(r"CWE-(\d+)", str(item)))]
    references = [url for url in entry.get("References", []) or [] if isinstance(url, str) and url.startswith("https://")][:8]
    remediation = (msg("scanning.sca.upgrade", package=name, installed=installed, fixed=fixed, target=target)
                   if fixed else msg("scanning.sca.no_fix", package=name))
    meta = (packages or {}).get(entry.get("PkgID")) or {}
    dev = bool(meta.get("Dev"))
    if dev:
        # Dev dependency: never reaches production, but runs on developer machines and in CI (supply chain).
        priority["factors"].append(msg("scanning.priority.dev_dependency"))
        if not kev and priority["action"] == "act":
            priority["action"] = "attend"
        elif not kev:
            priority["action"] = "track"
        remediation = msg("scanning.sca.dev_remediation", remediation=remediation)
    relationship = meta.get("Relationship")
    digest = dependency_fingerprint({identifier, *cves, *ghsas}, identifier, ecosystem, name, installed)
    previous = sca_fingerprint("sca", identifier, ecosystem, name, installed)
    finding = {"finding_id": digest[:16], "fingerprint": digest, **({"previous_fingerprint": previous} if previous != digest else {}),
            "scanner": "sca", "tool": "trivy", "rule_id": identifier,
            "title": f"{name} {installed}: {summary}"[:200], "path": target, "line": 1, "severity": severity,
            "confidence": 8 if score is not None else 6, "verdict": "candidate", "cwe": cwe, "owasp": ["A03:2025"],
            "cve": cves, "ghsa": ghsas,
            "package": {"ecosystem": ecosystem, "name": name, "version": installed, "fixed_version": fixed, "introduced": None,
                        "dev": dev, "direct": relationship == "direct" if relationship else None},
            "advisory": {"id": identifier, "aliases": cves + ghsas, "summary": summary,
                         "details": str(entry.get("Description") or "")[:2000], "cvss_vector": vector,
                         "cvss_score": score, "published": entry.get("PublishedDate"),
                         "modified": entry.get("LastModifiedDate"), "references": references},
            "kev": kev, "epss": {"score": epss[0], "percentile": epss[1]} if epss else None,
            "source": data_sources.from_trivy(entry),
            "priority": priority, "reason": summary, "remediation": remediation}
    if is_malicious({"id": identifier, "aliases": cves + ghsas, "cwe": cwe, "summary": entry.get("Title"), "details": entry.get("Description")}):
        mark_malicious(finding)
    return finding


def _trivy_misconfiguration(entry: dict, target: str) -> dict:
    cause = entry.get("CauseMetadata") or {}
    line = int(cause.get("StartLine") or 1)
    rule = str(entry.get("AVDID") or entry.get("ID") or "misconfig")
    severity = SEVERITY_LABEL.get(str(entry.get("Severity", "")).upper(), "medium")
    resource = str(cause.get("Resource") or cause.get("Provider") or "")
    finding = _base("iac", rule, f"{entry.get('Title', rule)}", target, line, severity, tool="trivy",
                    # The check's description, never its message, which quotes the configuration it read.
                    reason=str(entry.get("Description") or entry.get("Title") or rule).strip(),
                    remediation=str(entry.get("Resolution") or "").strip() or msg("scanning.iac.review_reference"),
                    cwe=[], owasp="A02:2025", confidence=8,
                    digest=_stable("iac", rule, target, resource or str(line)))
    # Line range: lets the same issue be recognized when Checkov flags it on the resource block.
    finding["end_line"] = max(line, int(cause.get("EndLine") or line))
    finding["resource"] = str(cause.get("Resource") or "")[:300]
    return finding


def _trivy_secret(entry: dict, target: str, custom: dict | None = None) -> dict:
    line = int(entry.get("StartLine") or 1)
    rule = str(entry.get("RuleID") or "secret")
    if rule in (custom or {}):
        return _custom_secret(custom[rule], rule, target, line, tool="trivy", confidence=8)
    # The value is never stored: Trivy already redacts it, and here it isn't even read.
    category = entry.get("Category")
    return _base("secrets", rule, (SECRET_TITLES.get(rule) or msg("scanning.secrets.exposed_titled", title=str(entry.get("Title") or rule))),
                 target, line, SECRET_SEVERITY, tool="trivy",
                 reason=msg("scanning.secrets.trivy_reason", category=str(category), path=target, line=line) if category
                 else msg("scanning.secrets.trivy_reason_generic", path=target, line=line),
                 remediation=msg("scanning.secrets.rotate"),
                 cwe=[798], owasp="A04:2025", confidence=8, digest=_stable("secrets", rule, target, str(line)))


MAX_PACKAGES = 20_000


def trivy_packages(payload: dict, *, system: bool = False) -> list[dict]:
    """Packages with their version (not just the vulnerable ones), from Trivy.

    By default, application packages: against them, advisories published later are checked daily without
    rescanning (see advisory_watch). With `system`, an image's operating system packages, which only go
    to the SBOM (their advisories depend on the distribution version and arrive on rescan).
    Besides name and version it keeps what an SBOM asks for: purl, licenses and whether it's a direct dependency."""
    packages, seen = [], set()
    wanted = "os-pkgs" if system else "lang-pkgs"
    for result in payload.get("Results", []) or []:
        if result.get("Class") != wanted:
            continue
        ecosystem = str(result.get("Type") or "").lower()
        target = _relative(str(result.get("Target", "")))
        for item in result.get("Packages") or []:
            name, version = str(item.get("Name") or ""), str(item.get("Version") or "")
            key = (ecosystem, name, version, target)
            if not name or not version or key in seen:
                continue
            seen.add(key)
            package = {"ecosystem": ecosystem, "name": name, "version": version, "path": target}
            purl = str((item.get("Identifier") or {}).get("PURL") or "")
            if purl.startswith("pkg:"):
                package["purl"] = purl[:500]
            licenses = [str(entry)[:100] for entry in item.get("Licenses") or [] if entry][:5]
            if licenses:
                package["licenses"] = licenses
            if item.get("Relationship") in ("direct", "indirect"):
                package["direct"] = item["Relationship"] == "direct"
            packages.append(package)
            if len(packages) >= MAX_PACKAGES:
                return packages
    return packages


def _trivy_claim(entry: dict, target: str) -> secret_location.Claim:
    """What Trivy said about a secret (secret_location): its byte offset in the file, its line with one `*` per byte of
    every secret on it (`Match`, a window of it on a long line) and, over several lines, each line masked (`Code`)."""
    match = entry.get("Match") if isinstance(entry.get("Match"), str) else ""
    masked = match.encode("utf-8", "surrogateescape")
    rule = str(entry.get("RuleID") or "secret")
    try:
        first = int(entry.get("StartLine") or 0)
        last = max(first, int(entry.get("EndLine") or first))
    except (TypeError, ValueError):
        first = last = 0
    code = {int(line["Number"]): line["Content"].encode("utf-8", "surrogateescape")
            for line in ((entry.get("Code") or {}).get("Lines") or []) if isinstance(entry.get("Code"), dict) and isinstance(line, dict)
            and line.get("IsCause") and not line.get("Truncated") and isinstance(line.get("Number"), int) and isinstance(line.get("Content"), str)}
    layer = entry.get("Layer") if isinstance(entry.get("Layer"), dict) else {}
    offset = entry.get("Offset") if isinstance(entry.get("Offset"), int) and not isinstance(entry.get("Offset"), bool) else None
    return secret_location.Claim(rule, target, first, last, ("trivy", rule, match), partial(secret_location.trivy_spots, masked),
                                 partial(secret_location.trivy_block, masked, code, first), offset=offset,
                                 layer=str(layer.get("DiffID") or layer.get("Digest") or "") or None)


def named(finding: Finding, read: secret_location.Read, value: secret_identity.Names | None = None, earlier: str | None = None) -> None:
    """`finding` named by its value (`value`, by default the one read) when it was read for sure, with `earlier` (its
    name by the formula before) among its value's former names; unlinkable otherwise (secret_location)."""
    value = value if value is not None else read.names
    if value is not None:
        secret_identity.assign(finding, secret_identity.Names(value.identity, [*value.formers, *([earlier] if earlier else [])]))
        if read.span:
            finding["span"] = read.span
    elif read.unlinkable:
        secret_identity.assign_unlinkable(finding, read.unlinkable)
        if read.spent:
            finding["over_budget"] = True   # declared in the run's limitations (repository.scan_repository)
    else:
        secret_identity.assign_unlinkable(finding, secret_identity.unlinkable(finding["rule_id"], finding["path"], None))


def parse_trivy(payload: dict, feeds: dict, custom: dict | None = None, root: Path | None = None,
                screened: Counter | None = None) -> list[Finding]:
    """`root`: the snapshot Trivy read, to give each secret its identity (scanning/secret_identity.py) and to judge whether
    it can be a secret at all (secret_filter): what can't is left out and counted in `screened`."""
    findings: list[Finding | None] = []
    reported: list[tuple[int, str, dict]] = []
    for result in payload.get("Results", []) or []:
        target = _relative(str(result.get("Target", "")))
        ecosystem = str(result.get("Type") or "").lower() or "unknown"
        packages = {item.get("ID"): item for item in result.get("Packages") or [] if item.get("ID")}
        for entry in result.get("Vulnerabilities") or []:
            findings.append(_trivy_vulnerability(entry, target, ecosystem, feeds, packages, system=result.get("Class") == "os-pkgs"))
        for entry in result.get("Misconfigurations") or []:
            if str(entry.get("Status", "FAIL")).upper() == "FAIL":
                findings.append(_trivy_misconfiguration(entry, target))
        for entry in result.get("Secrets") or []:
            if isinstance(entry, dict):
                reported.append((len(findings), target, entry))
                findings.append(None)
    reads = secret_location.resolve(root, [_trivy_claim(entry, target) for _, target, entry in reported])
    secrets = []
    for (position, target, entry), read in zip(reported, reads):
        if read.duplicate:
            continue
        # Trivy masks every secret on the line in `Match`: what comes before the first `*` is this one's context.
        match = entry.get("Match")
        context = secret_context(match.split("*", 1)[0]) if isinstance(match, str) and "*" in match else None
        # A type marker (a service account's `type` field) is judged with its object: the text around it in the snapshot.
        around = secret_filter.around(root, target, entry.get("Offset")) if secret_filter.marker(read.value) else None
        if reason := secret_filter.verdict(str(entry.get("RuleID") or ""), target, "", read.value, around):
            if screened is not None:
                screened[reason] += 1
            continue
        finding = _trivy_secret(entry, target, custom)
        named(finding, read)
        secrets.append((position, (finding, context, (target, int(entry.get("StartLine") or 1)))))
    for (position, _), finding in zip(secrets, with_secret_identities([item for _, item in secrets])):
        findings[position] = finding
    return unique_by_fingerprint([finding for finding in findings if finding is not None])


# What Trivy keeps in its cache and updates on its own: the folder, the command that downloads only it, the flag that
# stops a scan updating it. The misconfiguration checks bundle has no download-only command: a config scan of an empty
# folder fetches it and finds nothing.
CHECKS_TARGET = "tmp/checks-refresh"
TRIVY_DATABASES = (("db", ["image", "--download-db-only"], "--skip-db-update"),
                   ("java-db", ["image", "--download-java-db-only"], "--skip-java-db-update"),
                   ("policy", ["config", f"/cache/{CHECKS_TARGET}"], "--skip-check-update"))
CHECKS_TTL = timedelta(hours=24)   # how long Trivy itself keeps a checks bundle before fetching it again
REFRESH_DIR = "refresh"            # where a database is downloaded before it replaces the live one


def _trivy_database_fresh(cache_dir: Path, folder: str) -> bool | None:
    """Whether one of Trivy's databases is in the cache and not due yet (its own metadata says when: `NextUpdate` for
    the advisory databases, a day after `DownloadedAt` for the checks bundle); None when it has never been downloaded."""
    try:
        metadata = json.loads((cache_dir / folder / "metadata.json").read_text(encoding="utf-8"))
        # Trivy writes nanoseconds: Python reads up to microseconds.
        def moment(value) -> datetime:
            return datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", str(value or "")).replace("Z", "+00:00"))
        due = moment(metadata["NextUpdate"]) if metadata.get("NextUpdate") else moment(metadata["DownloadedAt"]) + CHECKS_TTL
    except (OSError, ValueError, AttributeError, KeyError, TypeError):
        return None
    return due > datetime.now(timezone.utc)


@contextmanager
def _trivy_refresh_lock(data_dir: Path | None):
    """One refresh at a time across workers and replicas (a PostgreSQL advisory lock); a CLI scan has no database and
    no other worker."""
    if data_dir is None or not settings.text("PITANGUS_DATABASE_URL"):
        yield
        return
    with db.transaction(data_dir) as connection:
        db.lock(connection, "trivy-databases")
        yield


def _database_complete(cache_dir: Path, folder: str) -> bool:
    """A downloaded database worth swapping in: current metadata and some content besides it."""
    files = [path for path in (cache_dir / folder).rglob("*") if path.is_file() and path.name != "metadata.json"]
    return bool(_trivy_database_fresh(cache_dir, folder)) and any(path.stat().st_size > 0 for path in files)


def _swap_in(new: Path, live: Path) -> None:
    """`new` takes the place of `live` with two renames on the same disk; if the second fails, `live` comes back. A scan
    reading the old files keeps them open until it ends."""
    former = live.with_name(f"{live.name}.old-{uuid.uuid4().hex[:8]}")
    if live.exists():
        live.rename(former)
    try:
        new.rename(live)
    except OSError:
        if former.exists():
            former.rename(live)
        raise
    shutil.rmtree(former, ignore_errors=True)


def _refresh_database(cache_dir: Path, folder: str, command: list[str]) -> bool:
    """Downloads one database into a folder of its own and swaps it in only when it arrived whole. A download that
    fails, is cut short or runs out of space (the Java database is larger than the engine's in-memory /tmp: its
    temporary files go to the disk) never touches the database in use."""
    staging = cache_dir / REFRESH_DIR / f"{folder}-{uuid.uuid4().hex[:12]}"
    (staging / "tmp").mkdir(parents=True)
    (staging / CHECKS_TARGET).mkdir(parents=True, exist_ok=True)
    try:
        completed = _run("trivy", [*command, "--cache-dir", "/cache", "--quiet"], None, network=True, env={"TMPDIR": "/cache/tmp"},
                         mounts=["-v", f"{host_path(staging)}:/cache"], timeout=900)
        if completed.returncode != 0 or not _database_complete(staging, folder):
            _log.warning("trivy_db_refresh_failed", extra={"reason": f"{folder}: exit {completed.returncode}"})
            return False
        _swap_in(staging / folder, cache_dir / folder)
        return True
    except (subprocess.TimeoutExpired, OSError) as exc:
        _log.warning("trivy_db_refresh_failed", extra={"reason": f"{folder}: {type(exc).__name__}"})
        return False
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def trivy_databases(cache_dir: Path, data_dir: Path | None) -> list[str]:
    """Refreshes Trivy's databases and its checks bundle once, under a lock, and returns the flags that keep each scan
    from updating them. Several scans updating the same cache at once replaced the file another was reading (one died
    with SIGBUS, others with "mapfs file copy error"). The Java database is only refreshed once Trivy has downloaded it
    (it does so the first time it meets a JAR)."""
    due = [(folder, command) for folder, command, _ in TRIVY_DATABASES
           if (fresh := _trivy_database_fresh(cache_dir, folder)) is False or (fresh is None and folder != "java-db")]
    if due:
        with _trivy_refresh_lock(data_dir):
            # What a refresh that died left behind: nobody else refreshes while this one holds the lock.
            shutil.rmtree(cache_dir / REFRESH_DIR, ignore_errors=True)
            for folder, command in due:
                if _trivy_database_fresh(cache_dir, folder):
                    continue  # another worker refreshed it while this one waited
                _refresh_database(cache_dir, folder, command)
            shutil.rmtree(cache_dir / REFRESH_DIR, ignore_errors=True)
    # A database that is there (even stale, if the refresh failed) is never replaced by the scan itself; one that never
    # downloaded is left to Trivy, which can't skip a database it doesn't have.
    return [skip for folder, _, skip in TRIVY_DATABASES if _trivy_database_fresh(cache_dir, folder) is not None]


TRIVY_IGNORE_FILES = (".trivyignore.yaml", ".trivyignore")   # the repository's own, at its top: the first one there is read


def trivy_ignore_file(root: Path | None) -> Path | None:
    """The repository's Trivy ignore file, when it is honoured (repo_controls): never one Trivy finds on its own."""
    if root is None or repo_controls.ignored():
        return None
    for name in TRIVY_IGNORE_FILES:
        path = root / name
        if path.is_file() and not path.is_symlink() and path.stat().st_size <= repo_controls.READ_MAX:
            return path
    return None


def _trivy_fs(snapshot: Path, cache_dir: Path, scanners: str, config_dir: Path | None, *,
              network: bool = True, skips: tuple[str, ...] = (), offline: bool = False, target: str | None = None,
              timeout: int = 900, ignore: Path | None = None) -> subprocess.CompletedProcess:
    """`offline`: no remote dependency resolution (`--offline-scan`); `target`: one file of the snapshot instead of all.
    With the secret scanner, its log at debug level names each file that scanner read (secret_coverage.read_trivy):
    only those lines and what `--quiet` would print are kept. `ignore`: the repository's ignore file (`trivy_ignore_file`),
    read with every result it suppresses reported apart (`--show-suppressed`, `trivy_suppressed`); without one, Trivy
    reads none, wherever it runs from."""
    ignoring = (["--ignorefile", f"/ignore/{ignore.name}", "--show-suppressed"] if ignore is not None
                else ["--ignorefile", ""])
    # Include dev dependencies (flagged as such) and the full package list, to tell which ones they are.
    secret_config = ["--secret-config", "/cfg/trivy-secret.yaml"] if config_dir else []
    listing = "secret" in scanners.split(",")
    # Its cache in memory, per scan, as for images: the shared one is a file one scan locks; the folder keeps the databases.
    return _run("trivy", ["fs", "--scanners", scanners, *secret_config, *skips, *ignoring, *(["--offline-scan"] if offline else []),
                          "--cache-backend", "memory", "--include-dev-deps", "--list-all-pkgs",
                          "--cache-dir", "/cache", "--format", "json", "--debug" if listing else "--quiet",
                          "--timeout", f"{max(1, timeout // 60 - 1)}m", f"/src/{target}" if target else "/src"], snapshot, network=network,
                mounts=["-v", f"{host_path(cache_dir)}:/cache",
                        *(["-v", f"{host_path(config_dir)}:/cfg:ro"] if config_dir else []),
                        *(["-v", f"{host_path(ignore)}:/ignore/{ignore.name}:ro"] if ignore is not None else [])], timeout=timeout,
                keep=secret_coverage.keep_trivy() if listing else None)


def _trivy_listed(completed: subprocess.CompletedProcess) -> tuple[set[str], subprocess.CompletedProcess]:
    """(the files Trivy's secret scanner read, the run with its stderr as `--quiet` leaves it)."""
    read, rest = secret_coverage.read_trivy(completed.stderr or "")
    return read, subprocess.CompletedProcess(completed.args, completed.returncode, completed.stdout, rest)


# Trivy 0.75 ends the whole run, without output, when a remote repository refuses to resolve one manifest ("remote
# Maven repository returned 429 Too Many Requests for …"); other statuses it skips. Only these manifests resolve remotely.
TRIVY_RESOLUTION_FAILED = re.compile(r"\bremote \S+ repository returned\b")
REMOTE_MANIFESTS = frozenset({"pom.xml"})
MAX_RESOLUTIONS = 40   # manifests resolved one by one after such a failure; the rest stay unexamined
RESOLUTION_TIMEOUT = 300


def resolution_failed(completed: subprocess.CompletedProcess) -> bool:
    return completed.returncode != 0 and not (completed.stdout or "").strip() and bool(TRIVY_RESOLUTION_FAILED.search(completed.stderr or ""))


def remote_manifests(snapshot: Path) -> list[str]:
    return sorted(path.relative_to(snapshot).as_posix() for path in snapshot.rglob("*")
                  if path.name.lower() in REMOTE_MANIFESTS and path.is_file() and not path.is_symlink())


def _resolve_apart(snapshot: Path, cache_dir: Path, scanners: str, config_dir: Path | None, skips: tuple[str, ...],
                   manifests: list[str], ignore: Path | None = None) -> tuple[subprocess.CompletedProcess, dict[str, str]]:
    """After a resolution failure: the run again without remote resolution, which covers everything else (other
    manifests, infrastructure, secrets); then each manifest that resolves remotely on its own, replacing what the offline
    run read from it. Returns the merged run and the manifests whose resolution still failed: only their dependencies go
    unexamined, and what the offline run guessed for them is left out (a manifest not examined opens nothing)."""
    offline = _trivy_fs(snapshot, cache_dir, scanners, config_dir, skips=skips, offline=True, ignore=ignore)
    payload, failure = engine_contract.verdict(TRIVY, offline.returncode, offline.stdout)
    if failure:
        return offline, {}
    failed: dict[str, str] = {}
    resolved: list[dict] = []
    for index, relative in enumerate(manifests):
        alone = None
        if index < MAX_RESOLUTIONS:
            try:
                probe = _trivy_fs(snapshot, cache_dir, "vuln", None, skips=skips, target=relative, timeout=RESOLUTION_TIMEOUT, ignore=ignore)
                alone, _ = engine_contract.verdict(TRIVY, probe.returncode, probe.stdout)
            except subprocess.TimeoutExpired:
                alone = None
        if alone is None:
            failed[relative] = "resolution_failed"
            continue
        # A single file's results are named after the file alone.
        resolved += [{**result, "Target": relative} for result in alone.get("Results") or [] if isinstance(result, dict)
                     and result.get("Class") == "lang-pkgs"]
    redone = set(manifests)
    kept = [result for result in payload.get("Results") or [] if not (isinstance(result, dict) and result.get("Class") == "lang-pkgs"
                                                                      and _relative(str(result.get("Target") or "")) in redone)]
    return subprocess.CompletedProcess(offline.args, 0, json.dumps({**payload, "Results": kept + resolved}), offline.stderr), failed


def run_trivy(snapshot: Path, cache_dir: Path, feeds: dict, secret_settings: dict | None = None, data_dir: Path | None = None) -> EngineResult:
    """`secret_settings`: the organization's secret detection settings (secret_rules), applied through
    `--secret-config`. If Trivy rejects them, it runs again without secret detection so dependencies and IaC are
    still analyzed, and the step says secrets were not covered by Trivy."""
    started = time.time()
    if problem := unavailable("trivy", msg("scanning.trivy.no_docker")):
        return _result("trivy", "not_tested", problem)
    cache_dir = writable_cache(cache_dir)
    rejected = None
    unresolved: dict[str, str] = {}
    ignore = trivy_ignore_file(snapshot)
    try:
        skips = tuple(trivy_databases(cache_dir, data_dir))
        with tempfile.TemporaryDirectory(prefix="trivy-config-", dir=snapshot.parent) as folder:
            # Always a generated configuration: its built-in allow rules and skip patterns off (secret_rules).
            config_dir, scanners = Path(folder), "vuln,misconfig,secret"
            (config_dir / "trivy-secret.yaml").write_text(secret_rules.trivy_secret_config(secret_settings or secret_rules.empty()), encoding="utf-8")
            completed = _trivy_fs(snapshot, cache_dir, scanners, config_dir, skips=skips, ignore=ignore)
            if config_dir and completed.returncode != 0 and not completed.stdout.strip() and "secret config" in completed.stderr.lower():
                reason = config_cause(completed)
                rejected = msg("scanning.trivy.secret_config_rejected_cause", cause=reason) if reason \
                    else msg("scanning.trivy.secret_config_rejected")
                config_dir, scanners = None, "vuln,misconfig"
                completed = _trivy_fs(snapshot, cache_dir, scanners, None, skips=skips, ignore=ignore)
            if resolution_failed(completed) and (manifests := remote_manifests(snapshot)):
                completed, unresolved = _resolve_apart(snapshot, cache_dir, scanners, config_dir, skips, manifests, ignore)
            read, completed = _trivy_listed(completed)
        payload, contract = engine_contract.verdict(TRIVY, completed.returncode, completed.stdout)
        if contract:
            failure = msg("scanning.trivy.failed_download") if completed.returncode != 0 and not completed.stdout.strip() \
                and "download" in completed.stderr.lower() else contract
            return engine_contract.failed(_result("trivy", "inconclusive", with_cause(failure, completed), started=started), contract)
    except subprocess.TimeoutExpired:
        timeout = msg("scanning.trivy.timeout")
        return engine_contract.failed(_result("trivy", "inconclusive", timeout, started=started), timeout)
    except (OSError, ValueError):
        unreadable = msg("scanning.engines.unreadable", engine="Trivy")
        return engine_contract.failed(_result("trivy", "inconclusive", unreadable, started=started), unreadable)
    screened: Counter = Counter()
    findings = parse_trivy(payload, feeds, secret_rules.custom_rules(secret_settings), root=snapshot, screened=screened)
    kept, allowed = split_inline([finding for finding in findings if finding["scanner"] == "secrets"], snapshot)
    findings = [*(finding for finding in findings if finding["scanner"] != "secrets"), *kept]
    listed = trivy_suppressed(payload, feeds, secret_rules.custom_rules(secret_settings), snapshot, ignore)
    allowed += [finding for finding in listed if finding["scanner"] == "secrets"]
    suppressed = [finding for finding in listed if finding["scanner"] != "secrets"]
    inline = _trivy_inline(snapshot, cache_dir, feeds, skips, ignore, [finding for finding in findings if finding["scanner"] == "iac"]) \
        if "misconfig" in scanners else None
    if inline is not None and inline != "unknown":
        found, hidden = inline
        findings = [*(finding for finding in findings if finding["scanner"] != "iac"), *found]
        suppressed += hidden
    kinds = {"sca": 0, "iac": 0, "secrets": 0}
    for finding in findings:
        kinds[finding["scanner"]] = kinds.get(finding["scanner"], 0) + 1
    coverage = trivy_coverage(snapshot, payload, completed.stderr or "", unresolved)
    gaps = {**coverage["unexamined"], **(coverage.get("by_scanner") or {}).get("sca", {})}
    targets = [_relative(str(result.get("Target") or "")) for result in payload.get("Results", []) or []]
    # What it examined: a manifest it couldn't (dependency_coverage) is said apart, never counted as examined.
    manifests = [target for result, target in zip(payload.get("Results", []) or [], targets) if result.get("Class") == "lang-pkgs" and target not in gaps]
    configs = [target for result, target in zip(payload.get("Results", []) or [], targets) if result.get("Class") == "config"]
    dev = sum(1 for finding in findings if (finding.get("package") or {}).get("dev"))
    counts = {"manifests": len(manifests), "configs": len(configs), "sca": kinds["sca"], "iac": kinds["iac"], "secrets": kinds["secrets"]}
    detail = msg("scanning.trivy.detail_dev", dev=dev, **counts) if dev else msg("scanning.trivy.detail", **counts)
    if not feeds.get("kev") or not feeds.get("epss"):
        detail = joined([detail, msg("scanning.trivy.no_feeds")], "scanning.join.sentences")
    if rejected:
        detail = joined([detail, rejected], "scanning.join.sentences")
    if unresolved:
        detail = joined([detail, msg("scanning.trivy.unresolved", count=len(unresolved), manifests=", ".join(sorted(unresolved)))],
                        "scanning.join.sentences")
    said = {**dependency_coverage.without_lockfile(snapshot, trivy_inventoried(payload)), **gaps}   # why, for the step only
    detail = joined([detail, *dependency_coverage.gaps_detail({unit: why for unit, why in said.items() if unit not in unresolved},
                                                              trivy_unversioned(payload, snapshot)), screened_detail(screened)],
                    "scanning.join.sentences")
    result = {**_result("trivy", "partial" if rejected else "completed", detail, findings, started), "packages": trivy_packages(payload),
              "screened": dict(screened)}
    result = _withhold(result, secret_settings, lambda reference: trivy_secrets(snapshot, cache_dir, reference))
    # Its secret scanner: every file of the snapshot its log doesn't name as read (all of them when it didn't run).
    if gaps := secret_gaps(snapshot, read if "secret" in scanners else set(), secret_settings):
        coverage = {**coverage, "by_scanner": {**(coverage.get("by_scanner") or {}), "secrets": gaps}}
    result = _declare_inline({**result, "coverage": coverage}, allowed)
    result = declare_suppressed(result, suppressed)
    if inline == "unknown":
        result = controls_unknown(result)
    coverage = result["coverage"]
    # Who requires what, for the fix guide of every dependency finding (Trivy's or OSV-Scanner's). Used while the scan
    # runs and dropped before the run is stored.
    result = {**result, "graph": dependency_graph.graphs(payload.get("Results") or [], _relative),
              "coverage": coverage}
    return engine_contract.recorded(result, None)


# Lockfiles Trivy reads: one of them missing from its results wasn't read (a malformed one is dropped without a word).
TRIVY_LOCKFILES = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "poetry.lock", "pipfile.lock",
    "uv.lock", "pdm.lock", "go.mod", "cargo.lock", "composer.lock", "gemfile.lock", "pom.xml", "gradle.lockfile",
    "packages.lock.json", "mix.lock", "pubspec.lock", "conan.lock", "package.resolved", "podfile.lock", "requirements.txt"})
INFRASTRUCTURE_MARKERS = ("apiVersion:", "AWSTemplateFormatVersion", "deploymentTemplate.json")
TRIVY_LOGGED_FILE = re.compile(r'\b(?:ERROR|WARN)\b.*?\bfile_path="([^"]+)"')


# How many packages each JSON lockfile lists, by its own format (npm's root package, "", isn't one).
JSON_PACKAGES = {
    "package-lock.json": lambda data: len([key for key in data.get("packages") or {} if key]) + len(data.get("dependencies") or {}),
    "composer.lock": lambda data: len(data.get("packages") or []) + len(data.get("packages-dev") or []),
    "pipfile.lock": lambda data: len(data.get("default") or {}) + len(data.get("develop") or {}),
    "packages.lock.json": lambda data: sum(len(group or {}) for group in (data.get("dependencies") or {}).values()),
    "package.resolved": lambda data: len(data.get("pins") or (data.get("object") or {}).get("pins") or []),
}
JSON_PACKAGES["npm-shrinkwrap.json"] = JSON_PACKAGES["package-lock.json"]
TOML_PACKAGES = frozenset({"poetry.lock", "cargo.lock", "uv.lock", "pdm.lock"})


def _without_packages(path: Path) -> bool:
    """A lockfile that, by its own format, lists no package at all: Trivy gives it no result, yet it was read (0
    packages), unlike a malformed one Trivy drops without a word. Unsure is "with packages": then it stays unexamined."""
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False
    if not content.strip():
        return True
    name = path.name.lower()
    try:
        if name in JSON_PACKAGES:
            data = json.loads(content)
            return isinstance(data, dict) and JSON_PACKAGES[name](data) == 0
        if name in TOML_PACKAGES:
            return not tomllib.loads(content).get("package")
    except (ValueError, TypeError, AttributeError):
        return False
    if name == "go.mod":
        return not re.search(r"(?m)^\s*require\b", content)
    if name == "yarn.lock":
        return all(not line.strip() or line.lstrip().startswith("#") for line in content.splitlines())
    if name == "requirements.txt":   # Trivy reads only exact pins: the rest are packages without a version (dependency_coverage)
        return not any(dependency_coverage.PINNED.match(line.strip()) for line in content.splitlines())
    return False


def _infrastructure(path: Path) -> str | None:
    """How Trivy reports an infrastructure file: "file" (its own result), "module" (Terraform: its folder's result) or
    None when it isn't one."""
    name, suffix = path.name.lower(), path.suffix.lower()
    if suffix in (".tf", ".tfvars"):
        return "module"
    if name in ("dockerfile", "containerfile") or name.endswith(".dockerfile"):
        return "file"
    if suffix in (".yml", ".yaml", ".json"):
        found = dependency_coverage.read(path)   # in any encoding: one Trivy can't decode is still one it should have read
        return "file" if found and any(marker in found[0][:4000] for marker in INFRASTRUCTURE_MARKERS) else None
    return None


def trivy_unversioned(payload: dict, snapshot: Path | None = None) -> dict[str, list[str]]:
    """The packages each manifest's result left without a resolved version, by name (dependency_coverage.unversioned):
    Trivy keeps a dependency whose version comes from a parent POM or a property that didn't resolve with an empty one
    (404, 5xx or no network, and still exit 0). With `snapshot`, also the requirements it left out for not being pinned."""
    found: dict[str, set[str]] = {}
    for result in payload.get("Results") or []:
        if not isinstance(result, dict) or result.get("Class") != "lang-pkgs":
            continue
        entries = [(str(item.get("Name") or ""), str(item.get("Version") or ""),
                    item.get("Relationship") in ("root", "workspace") or dependency_coverage.local_name(str(item.get("Name") or "")))
                   for item in result.get("Packages") or [] if isinstance(item, dict)]
        if names := dependency_coverage.unversioned(entries):
            found.setdefault(_relative(str(result.get("Target") or "")), set()).update(names)
    for path in (snapshot.rglob("requirements.txt") if snapshot else ()):
        text = dependency_coverage.read(path) if path.is_file() and not path.is_symlink() else None
        if text and (names := dependency_coverage.unpinned_requirements(text[0])):
            found.setdefault(path.relative_to(snapshot).as_posix(), set()).update(names)
    return {target: sorted(names) for target, names in sorted(found.items())}


def trivy_inventoried(payload: dict) -> set[str]:
    """The files Trivy's own output listed at least one package for in this run (its packages, and the ones its
    advisories name): a lockfile that gave none resolved nothing, whatever it holds (dependency_coverage.without_lockfile)."""
    listing: dict[str, list[tuple[str, bool]]] = {}
    for result in payload.get("Results") or []:
        if not isinstance(result, dict) or result.get("Class") != "lang-pkgs":
            continue
        entries = listing.setdefault(_relative(str(result.get("Target") or "")), [])
        entries += [(str(item.get("Name") or ""), item.get("Relationship") in ("root", "workspace")
                     or dependency_coverage.local_name(str(item.get("Name") or ""))) for item in result.get("Packages") or [] if isinstance(item, dict)]
        entries += [(str(item.get("PkgName") or ""), False) for item in result.get("Vulnerabilities") or [] if isinstance(item, dict)]
    return dependency_coverage.inventoried(listing)


def trivy_coverage(snapshot: Path, payload: dict, log: str, unresolved: dict[str, str] | None = None) -> dict:
    """Which of the files Trivy reads it did read. Its results and its log, checked against what the snapshot holds: a
    lockfile or an infrastructure file without a result, or one its log says it couldn't parse, wasn't examined (only
    that file: the rest of Trivy's run still counts), and one in an encoding it doesn't decode says so. For its
    dependency scanner only (their secrets were still read): a manifest whose remote resolution failed (`unresolved`),
    one whose packages were left without a resolved version, and every folder it inventoried no package from
    (`dependencies`, dependency_coverage.folders): a manifest left without its lockfile is one of those, whatever its
    package manager."""
    targets = {_relative(str(result.get("Target") or "")) for result in payload.get("Results") or [] if isinstance(result, dict)}
    logged = {_relative(match) for match in TRIVY_LOGGED_FILE.findall(log)}
    reasons: dict[str, str] = dict.fromkeys(logged, "parse_error")
    for path in snapshot.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(snapshot).as_posix()
        kind = "lockfile" if path.name.lower() in TRIVY_LOCKFILES else _infrastructure(path)
        if kind is None or relative in reasons or relative in (unresolved or {}):
            continue
        folder = str(Path(relative).parent) if "/" in relative else "."
        if relative not in targets and not (kind == "module" and folder in targets) \
                and not (kind == "lockfile" and _without_packages(path)):
            reasons[relative] = "not_read" if dependency_coverage.readable(path) else dependency_coverage.ENCODING
    inventoried = trivy_inventoried(payload)
    dependencies = {**dict.fromkeys(trivy_unversioned(payload, snapshot), dependency_coverage.UNVERSIONED), **(unresolved or {})}
    return {**engine_contract.coverage("*", reasons, by_scanner={"sca": {unit: why for unit, why in dependencies.items() if unit not in reasons}}),
            "dependencies": dependency_coverage.folders(snapshot, inventoried)}


def trivy_secrets(snapshot: Path, cache_dir: Path, settings: dict | None, screened: Counter | None = None,
                  gaps: dict[str, str] | None = None, allowed: list[dict] | None = None,
                  controls: Path | None = None) -> list[dict] | None:
    """Secret detection alone (the unfiltered reference run, the credential files); None when it failed. Without
    network: it needs no vulnerability database. What isn't a secret is counted in `screened` (secret_filter).
    `gaps`: filled with the files it didn't read (secret_gaps), when it finished; `allowed`: with the secrets an
    inline comment or the repository's ignore file allows (`split_inline`, `trivy_suppressed`), which it never returns.
    `controls`: the repository's top folder, where its ignore file is (by default `snapshot`)."""
    ignore = trivy_ignore_file(controls or snapshot)
    try:
        with tempfile.TemporaryDirectory(prefix="trivy-config-", dir=snapshot.parent) as folder:
            config_dir = Path(folder)
            (config_dir / "trivy-secret.yaml").write_text(secret_rules.trivy_secret_config(settings or secret_rules.empty()), encoding="utf-8")
            completed = _trivy_fs(snapshot, cache_dir, "secret", config_dir, network=False, ignore=ignore)
        read, completed = _trivy_listed(completed)
        payload, failure = engine_contract.verdict(TRIVY, completed.returncode, completed.stdout)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None
    if failure:
        return None
    if gaps is not None:
        gaps.update(secret_gaps(snapshot, read, settings))
    kept, inline = split_inline(parse_trivy(payload, {}, secret_rules.custom_rules(settings), root=snapshot, screened=screened), snapshot)
    if allowed is not None:
        allowed.extend([*inline, *trivy_suppressed(payload, {}, secret_rules.custom_rules(settings), snapshot, ignore)])
    return kept


def _withhold(result: dict, settings: dict | None, reference) -> dict:
    """With settings that filter, adds `withheld`: the secrets only an unfiltered run (`reference`) sees
    (secret_rules.withheld). If that run fails, `withheld` is None and the step partial: the scan is then incomplete,
    so a secret that stopped appearing is never taken as fixed."""
    if result["status"] != "completed" or not secret_rules.filters(settings):
        return result
    unfiltered = reference(secret_rules.unfiltered(settings))
    if unfiltered is None:
        return {**result, "status": "partial", "withheld": None,
                "detail": joined([result["detail"], msg("scanning.secret_rules.withheld.unknown")], "scanning.join.sentences")}
    kept = {finding["fingerprint"] for finding in result["findings"]}
    return {**result, "withheld": [secret_rules.withheld(finding, settings) for finding in unfiltered
                                   if finding["scanner"] == "secrets" and finding["fingerprint"] not in kept]}


# --- OSV-Scanner ---------------------------------------------------------------------

def parse_osv_scanner(payload: dict, feeds: dict) -> list[Finding]:
    """One finding per advisory and package. OSV groups the identifiers of the same advisory in `groups`
    (GHSA, PYSEC, CVE…); one from each group becomes the primary and the rest become aliases."""
    from pitangus.modules.intel.advisories import dependency_finding, is_malicious, mark_malicious, summarize_advisory
    from pitangus.modules.scanning.dependency_merge import stable_fingerprint
    findings = []
    for result in payload.get("results") or []:
        path = _relative(str((result.get("source") or {}).get("path") or ""))
        for entry in result.get("packages") or []:
            package = entry.get("package") or {}
            name, version, ecosystem = str(package.get("name") or ""), str(package.get("version") or ""), str(package.get("ecosystem") or "")
            if not name or not version:
                continue
            vulnerabilities = {item.get("id"): item for item in entry.get("vulnerabilities") or [] if isinstance(item, dict) and item.get("id")}
            groups = entry.get("groups") or [{"ids": [identifier]} for identifier in vulnerabilities]
            for group in groups:
                ids = [item for item in group.get("ids") or [] if item in vulnerabilities]
                if not ids:
                    continue
                main = next((item for item in ids if item.startswith("GHSA-")), ids[0])
                aliases = set(group.get("aliases") or []) | set(ids)
                for item in ids:
                    aliases |= set(vulnerabilities[item].get("aliases") or [])
                advisory = {**vulnerabilities[main], "aliases": sorted(aliases - {main})}
                finding = dependency_finding({"ecosystem": ecosystem, "name": name, "version": version, "path": path}, advisory, feeds)
                # The group is one advisory: malware when any of its records says so (a GHSA titled one way, its PYSEC
                # described another).
                if not finding.get("malicious") and any(is_malicious(summarize_advisory(vulnerabilities[item])) for item in ids if item != main):
                    mark_malicious(finding)
                digest = stable_fingerprint(main, aliases, ecosystem, name, version)
                finding.pop("previous_fingerprint", None)  # OSV-Scanner already used this fingerprint
                finding.update(fingerprint=digest, finding_id=digest[:16], tool="osv-scanner")
                findings.append(finding)
    return unique_by_fingerprint(findings)


def run_osv_scanner(snapshot: Path, cache_dir: Path, feeds: dict, *, resolve: bool = False) -> EngineResult:
    """OSV-Scanner with the advisory databases downloaded locally: the dependency list never leaves this machine.

    Only with `resolve` (the user allowed external queries) does it resolve transitive dependencies of
    manifests without a lockfile, which queries deps.dev. Call analysis stays off: in Rust it would
    run the repository's build scripts."""
    started = time.time()
    if problem := unavailable("osv-scanner", msg("scanning.osv.no_docker")):
        return _result("osv-scanner", "not_tested", problem)
    cache_dir = writable_cache(cache_dir)
    # Every package, not only the vulnerable ones: one left without a version leaves its manifest unexamined.
    arguments = ["scan", "source", "-r", "--format", "json", "--all-packages", "--offline-vulnerabilities", "--download-offline-databases",
                 "--allow-no-lockfiles", "--no-call-analysis=go", "--no-call-analysis=rust", *([] if resolve else ["--no-resolve"]), "/src"]
    try:
        completed = _osv(arguments, snapshot, cache_dir, honoured=not repo_controls.ignored())
        log = completed.stderr or ""
        # 0: no advisories · 1: advisories. Any other code is an engine error.
        payload, contract = engine_contract.verdict(OSV, osv_exit(completed.returncode, log), completed.stdout)
        if contract:
            return engine_contract.failed(_result("osv-scanner", "inconclusive", with_cause(contract, completed), started=started), contract)
    except subprocess.TimeoutExpired:
        timeout = msg("scanning.osv.timeout")
        return engine_contract.failed(_result("osv-scanner", "inconclusive", timeout, started=started), timeout)
    except (OSError, ValueError):
        unreadable = msg("scanning.engines.unreadable", engine="OSV-Scanner")
        return engine_contract.failed(_result("osv-scanner", "inconclusive", unreadable, started=started), unreadable)
    findings = parse_osv_scanner(payload, feeds)
    suppressed: list[Finding] | None = []
    if not repo_controls.ignored() and (configs := OSV_LOADED.findall(log)):
        suppressed = _osv_suppressed(arguments, snapshot, cache_dir, feeds, findings, configs)
    packages = sum(1 for result in payload.get("results") or [] for entry in result.get("packages") or [] if entry.get("vulnerabilities"))
    coverage = osv_coverage(payload, log, snapshot, resolve=resolve)
    manifests = {_relative(str((result.get("source") or {}).get("path") or "")) for result in payload.get("results") or []} - set(coverage["unexamined"])
    failed = [unit for unit, why in coverage["unexamined"].items() if why == "parse_error"]
    unread = msg("scanning.osv.unread", count=len(failed), files=", ".join(failed)) if failed else None
    said = {**dependency_coverage.without_lockfile(snapshot, osv_inventoried(payload)), **coverage["unexamined"]}   # why, for the step only
    gaps = dependency_coverage.gaps_detail(said, osv_unversioned(payload, snapshot, osv_resolved(log) if resolve else set()))
    manifests -= {""}
    detail = joined([msg("scanning.osv.detail_resolved" if resolve else "scanning.osv.detail", manifests=len(manifests), packages=packages,
                         advisories=len(findings)) if manifests else None if said else msg("scanning.osv.no_manifests"),
                     unread, *gaps], "scanning.join.sentences")
    result = {**_result("osv-scanner", "completed", detail, findings, started), "coverage": coverage}
    result = controls_unknown(result) if suppressed is None else declare_suppressed(result, suppressed)
    return engine_contract.recorded(result, None)


# OSV-Scanner loads an `osv-scanner.toml` from each scanned folder on its own (ignored advisories, packages left out) and
# says so in its log, without saying what it filtered out.
OSV_LOADED = re.compile(r"Loaded filter from: /src/(\S+)")


def _osv(arguments: list[str], snapshot: Path, cache_dir: Path, *, honoured: bool) -> subprocess.CompletedProcess:
    """OSV-Scanner over the snapshot; not `honoured`, with an empty configuration of Pitangus' own that replaces every
    `osv-scanner.toml` of the repository."""
    if honoured:
        return _run("osv-scanner", arguments, snapshot, network=True, timeout=1800,
                    env={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/cache"}, mounts=["-v", f"{host_path(cache_dir)}:/cache"])
    with tempfile.TemporaryDirectory(prefix="osv-config-", dir=snapshot.parent) as folder:
        (Path(folder) / "osv-scanner.toml").write_text("", encoding="utf-8")
        return _run("osv-scanner", [*arguments[:-1], "--config", "/cfg/osv-scanner.toml", arguments[-1]], snapshot, network=True,
                    timeout=1800, env={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/cache"},
                    mounts=["-v", f"{host_path(cache_dir)}:/cache", "-v", f"{host_path(Path(folder))}:/cfg:ro"])


def _osv_suppressed(arguments: list[str], snapshot: Path, cache_dir: Path, feeds: dict, honoured: list[Finding],
                    configs: list[str]) -> list[Finding] | None:
    """The advisories the repository's `osv-scanner.toml` files filtered out: what a run without them reports and the
    run with them doesn't, each excluded and declared with the file of its folder (or the first one loaded). None when
    that run failed: which ones they hid is unknown."""
    try:
        completed = _osv(arguments, snapshot, cache_dir, honoured=False)
        payload, failure = engine_contract.verdict(OSV, osv_exit(completed.returncode, completed.stderr or ""), completed.stdout)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None
    if failure:
        return None
    _, hidden, _ = repo_controls.split(parse_osv_scanner(payload, feeds), honoured, lambda finding: finding["fingerprint"])
    by_folder = {config.rpartition("/")[0]: config for config in configs}

    def control(finding: Finding) -> Message:
        return file_control(by_folder.get(finding["path"].rpartition("/")[0], configs[0]))
    return [repo_suppressed(finding, control(finding)) for finding in hidden]


def osv_exit(code: int | None, log: str) -> int | None:
    """OSV-Scanner 2.6 exits 127 when the only lockfiles it found couldn't be extracted, and still writes its JSON:
    a failure of those files, not of the run, when every error its log reports is one of them."""
    errors = [line for line in log.splitlines() if re.search(r"\b(?:error|fatal|panic|failed)\b", line, re.IGNORECASE)]
    return 0 if code == 127 and errors and all(OSV_FAILED.match(line) for line in errors) else code


OSV_FOUND = re.compile(r"^Scanned (\S+) file and found (\d+) packages?", re.M)
OSV_UNRESOLVED = re.compile(r"\bfailed resolution for (\S+?):")


def osv_resolved(log: str) -> set[str]:
    """The requirements files OSV-Scanner resolved against deps.dev (when allowed to): every one it scanned that its log
    doesn't name as failed (then it falls back to guessing from the ranges)."""
    failed = {_relative("/" + path.lstrip("/")) for path in OSV_UNRESOLVED.findall(log)}
    return {_relative(path) for path in OSV_SCANNED.findall(log) if dependency_coverage.requirements_file(path)} - failed


def osv_unversioned(payload: dict, snapshot: Path | None = None, resolved: set[str] | frozenset[str] = frozenset()) -> dict[str, list[str]]:
    """The packages each manifest's result left without a version (dependency_coverage.unversioned): OSV-Scanner lists
    them with an empty one (a version from a parent POM or a property it didn't resolve, a requirement without a pin)
    and, unless it resolved the file (`resolved`), guesses a requirement's range as its lower bound. A Git dependency is
    pinned by its commit."""
    found: dict[str, set[str]] = {}
    for result in payload.get("results") or []:
        if not isinstance(result, dict):
            continue
        path = _relative(str((result.get("source") or {}).get("path") or ""))
        entries = [(str(package.get("name") or ""), str(package.get("version") or package.get("commit") or ""),
                    dependency_coverage.local_name(str(package.get("name") or "")))
                   for package in (entry.get("package") or {} for entry in result.get("packages") or [] if isinstance(entry, dict))]
        names = set(dependency_coverage.unversioned(entries))
        if snapshot is not None and dependency_coverage.requirements_file(path) and path not in resolved \
                and (text := dependency_coverage.read(snapshot / path)):
            names |= set(dependency_coverage.unpinned_requirements(text[0]))
        if names and path:
            found.setdefault(path, set()).update(names)
    return {path: sorted(names) for path, names in sorted(found.items())}


def osv_inventoried(payload: dict) -> set[str]:
    """The files OSV-Scanner's own output listed at least one package for in this run (dependency_coverage)."""
    listing: dict[str, list[tuple[str, bool]]] = {}
    for result in payload.get("results") or []:
        if not isinstance(result, dict):
            continue
        entries = listing.setdefault(_relative(str((result.get("source") or {}).get("path") or "")), [])
        entries += [(name, dependency_coverage.local_name(name)) for name in
                    (str((entry.get("package") or {}).get("name") or "") for entry in result.get("packages") or [] if isinstance(entry, dict))]
    return dependency_coverage.inventoried(listing)


def osv_coverage(payload: dict, log: str, snapshot: Path | None = None, *, resolve: bool = False) -> dict:
    """What OSV-Scanner read, from its log (it names each lockfile it scanned and each it couldn't extract) and its
    results. A file it couldn't extract is unexamined, that file only, as is one it read nothing from because it isn't
    UTF-8, and one whose packages were left without a version. With `snapshot`, what it examined is said by folder
    (`dependencies`): a folder of the repository it inventoried nothing from is unexamined, so nothing it found there
    before is taken as fixed. Without it, with nothing scanned, nothing is examined (never "every manifest")."""
    failed = {_relative("/" + path.lstrip("/")): "parse_error" for path in OSV_FAILED.findall(log)}
    scanned = {_relative(path) for path in OSV_SCANNED.findall(log)} | {
        _relative(str((result.get("source") or {}).get("path") or "")) for result in payload.get("results") or [] if isinstance(result, dict)}
    if snapshot is not None:
        empty = {_relative(path) for path, count in OSV_FOUND.findall(log) if count == "0"}
        failed |= {path: dependency_coverage.ENCODING for path in sorted(empty - set(failed))
                   if (snapshot / path).is_file() and not dependency_coverage.readable(snapshot / path)}
    unversioned = osv_unversioned(payload, snapshot, osv_resolved(log) if resolve else set())
    failed |= {path: dependency_coverage.UNVERSIONED for path in unversioned if path not in failed}
    inventoried = osv_inventoried(payload)
    scanned -= set(failed) | {""}
    if snapshot is not None:
        # By folder (dependency_coverage.folders): a folder it inventoried nothing from is unexamined, whatever it read
        # or didn't (a manifest without its lockfile, of any package manager); one no longer in the repository holds
        # nothing it could have seen.
        return {**engine_contract.coverage("*", failed), "dependencies": dependency_coverage.folders(snapshot, inventoried)}
    if scanned:
        return engine_contract.coverage("*", failed)
    return engine_contract.coverage([], failed, reason="none_readable" if failed else "no_manifests")


# --- Betterleaks -------------------------------------------------------------------------

# Names of the most common Betterleaks rules; the rest use their identifier.
SECRET_TITLES = {
    "jwt": msg("scanning.secrets.titles.jwt"), "generic-api-key": msg("scanning.secrets.titles.generic_api_key"),
    "private-key": msg("scanning.secrets.titles.private_key"), "aws-access-token": msg("scanning.secrets.titles.aws_access_token"),
    "aws-secret-access-key": msg("scanning.secrets.titles.aws_secret_access_key"), "github-pat": msg("scanning.secrets.titles.github_pat"),
    "github-fine-grained-pat": msg("scanning.secrets.titles.github_fine_grained_pat"),
    "github-app-token": msg("scanning.secrets.titles.github_app_token"), "github-oauth": msg("scanning.secrets.titles.github_oauth"),
    "gitlab-pat": msg("scanning.secrets.titles.gitlab_pat"), "slack-bot-token": msg("scanning.secrets.titles.slack_bot_token"),
    "slack-webhook-url": msg("scanning.secrets.titles.slack_webhook_url"),
    "stripe-access-token": msg("scanning.secrets.titles.stripe_access_token"), "gcp-api-key": msg("scanning.secrets.titles.gcp_api_key"),
    "openai-api-key": msg("scanning.secrets.titles.openai_api_key"), "anthropic-api-key": msg("scanning.secrets.titles.anthropic_api_key"),
    "twilio-api-key": msg("scanning.secrets.titles.twilio_api_key"), "sendgrid-api-token": msg("scanning.secrets.titles.sendgrid_api_token"),
    "npm-access-token": msg("scanning.secrets.titles.npm_access_token"), "pypi-upload-token": msg("scanning.secrets.titles.pypi_upload_token"),
    "azure-ad-client-secret": msg("scanning.secrets.titles.azure_ad_client_secret"),
    "heroku-api-key": msg("scanning.secrets.titles.heroku_api_key"),
}


def secret_title(rule: str) -> dict:
    return SECRET_TITLES.get(rule) or msg("scanning.secrets.exposed_rule", rule=rule)


SECRET_CONTEXT = 30  # characters before a secret that identify it (Trivy keeps 30 around a secret on long lines)


def secret_context(prefix: str | None) -> str | None:
    """What precedes a secret on its line (`GITHUB_TOKEN = "`), other secrets masked: identifies where it lives
    without a trace of its value. None when unknown."""
    if prefix is None:
        return None
    return " ".join(prefix.split())[-SECRET_CONTEXT:]


LEAD_WINDOW = 256  # characters read before a secret to find its context: bounded, whatever the line's length


def masked_lead(text: str, start: int, spans: list[tuple[int, int]]) -> str:
    """The text before offset `start` on a line (at most LEAD_WINDOW characters), with every span in `spans`
    (the secrets found on that line) masked by `*`."""
    start = min(start, len(text))
    begin = max(0, start - LEAD_WINDOW)
    lead = list(text[begin:start])
    for span_start, span_end in spans:
        for position in range(max(span_start, begin), min(span_end, start)):
            lead[position - begin] = "*"
    return "".join(lead)


def with_secret_identities(items: list[tuple[Finding, str | None, tuple]]) -> list[Finding]:
    """Secrets' fingerprints without their line number: rule, file, what precedes each on its line and, among identical
    ones, their order in the file (`items`: finding, context, position). A line added above a secret no longer makes
    it look fixed and new. The former, line-based fingerprint stays in `previous_fingerprint` so the registry carries
    state and triage over (findings/registry.py). Without a context, a secret keeps the line-based one."""
    result, seen = [finding for finding, _, _ in items], {}
    for index in sorted(range(len(items)), key=lambda position: items[position][2]):
        finding, context, _ = items[index]
        if context is None:
            continue
        identity = (finding["rule_id"], finding["path"], context)
        order = seen[identity] = seen.get(identity, -1) + 1
        digest = _stable("secrets", finding["rule_id"], finding["path"], "context", context, str(order))
        result[index] = {**finding, "fingerprint": digest, "finding_id": digest[:16], "previous_fingerprint": finding["fingerprint"],
                         # Identical secrets in one file share it; each copy is still counted (identity.family_counts).
                         "family": _stable("secrets", finding["rule_id"], finding["path"], "context", context)}
    return unlinkable_fingerprints(result)


def unlinkable_fingerprints(findings: list[Finding]) -> list[Finding]:
    """An unlinkable secret (secret_location) is known by its own name only: its fingerprint is that name and its copy's
    order (copies are counted), never what any value in its place would share (its rule, file and context)."""
    copies: Counter = Counter()
    for finding in findings:
        if finding.get("unlinkable"):
            order = copies[finding["identity"]]
            copies[finding["identity"]] += 1
            digest = _stable("secrets", "unlinkable", finding["identity"], str(order))
            finding.update(fingerprint=digest, finding_id=digest[:16], family=finding["identity"])
            finding.pop("previous_fingerprint", None)
            finding.pop("previous_fingerprints", None)
    return findings


def _betterleaks_lines_of(entry: dict) -> tuple[int, int]:
    """(first line, last line) of a Betterleaks entry; the last is the first when it isn't after it within MULTILINE."""
    try:
        first = int(entry.get("StartLine") or 0)
        last = int(entry.get("EndLine") or first)
    except (TypeError, ValueError):
        return 0, 0
    return first, last if first <= last <= first + MULTILINE else first


def _betterleaks_lines(entries: list[dict], root: Path | None) -> dict[str, dict[int, bytes]]:
    """The raw lines of the snapshot each entry spans, by file, never outside the snapshot; none for a file that can't
    be read."""
    wanted: dict[str, set[int]] = {}
    for entry in entries:
        first, last = _betterleaks_lines_of(entry)
        if first >= 1:
            wanted.setdefault(_relative(str(entry.get("File", ""))), set()).update(range(first, last + 1))
    raw: dict[str, dict[int, bytes]] = {}
    if root is None:
        return raw
    base = root.resolve()
    for path, numbers in wanted.items():
        found: dict[int, bytes] = {}
        try:
            target = (root / path).resolve()
            target.relative_to(base)
            with target.open("rb") as handle:
                for number, text in enumerate(handle, 1):
                    if number in numbers:
                        found[number] = text
                    if number >= max(numbers):
                        break
        except (OSError, ValueError):
            pass
        raw[path] = found
    return raw


def _line_text(line: bytes) -> str:
    # surrogateescape, as secret_identity reads a value: an invalid byte is one character either way.
    return line.decode("utf-8", "surrogateescape").rstrip("\r\n")


def _betterleaks_occurrences(text: str, match: str, size: int) -> list[tuple[int, int]]:
    """Every place on `text` a redacted match of `size` bytes can be (character offsets [start, end)): where its lead
    (`password = "`) starts and the next `size` bytes read as the match (secret_filter.value_from_match). None without a
    lead to look for."""
    lead = match.split("REDACTED", 1)[0]
    if not lead.strip() or len(lead) > 200 or "\n" in match or not 0 < size <= secret_filter.MATCH_MAX * 4:
        return []
    spots, at = [], text.find(lead)
    while at >= 0:
        end, count = at, 0
        while end < len(text) and count < size:
            count += len(text[end].encode("utf-8", "surrogateescape"))
            end += 1
        if count == size and secret_filter.value_from_match(match, text[at:end]):
            spots.append((at, end))
        at = text.find(lead, at + 1)
    return spots


def _betterleaks_char_columns(entries: list[dict], raw: dict[str, dict[int, bytes]]) -> list[dict]:
    """Betterleaks' columns count bytes (its locateMatch: "1-based byte offset"), the snapshot's lines are read as
    text: each entry's StartColumn/EndColumn become character columns of the lines they point at, exactly, so a secret
    after a non-ASCII character (`ñ`, `·`, a minified bundle's strings) is read where it is. Unreadable lines keep them.

    Past the first fragment of a long line (about 125 KB) Betterleaks counts from the fragment instead of the line, so
    its columns land nowhere or on another match of the same shape. On each line, an entry whose columns land on a match
    keeps it; the others take, nearest to where they point, the matches of their shape no entry holds: each match is read
    once while there are as many entries as matches, whatever the columns say."""
    def chars(line: bytes, offset: int) -> int:
        return len(line[:max(0, offset)].decode("utf-8", "surrogateescape"))

    result = list(entries)
    held: dict[tuple, set[tuple[int, int]]] = {}
    astray: dict[tuple, list[tuple[int, int, int]]] = {}
    for index, entry in enumerate(entries):
        try:
            start, end = int(entry.get("StartColumn") or 0), int(entry.get("EndColumn") or 0)
        except (TypeError, ValueError):
            continue
        path = _relative(str(entry.get("File", "")))
        first, last = _betterleaks_lines_of(entry)
        lines = raw.get(path, {})
        if start < 1 or first not in lines or last not in lines:
            continue
        begin, finish = chars(lines[first], start - 1), chars(lines[last], end)
        result[index] = {**entry, "StartColumn": begin + 1, "EndColumn": finish}
        match = str(entry.get("Match") or "")
        if last == first and "REDACTED" in match:
            key = (path, first, str(entry.get("RuleID") or ""), match)
            spot, taken = (begin, finish), held.setdefault(key, set())
            if spot not in taken and secret_filter.value_from_match(match, _line_text(lines[first])[begin:finish]):
                taken.add(spot)
            else:
                astray.setdefault(key, []).append((begin, index, end - start + 1))
    for key, items in astray.items():
        path, number, _, match = key
        text, taken = _line_text(raw[path][number]), held[key]
        for near, index, size in sorted(items):
            spots = _betterleaks_occurrences(text, match, size)
            free = [spot for spot in spots if spot not in taken] or spots
            if free:
                spot = min(free, key=lambda item: (abs(item[0] - near), item[0]))
                taken.add(spot)
                result[index] = {**result[index], "StartColumn": spot[0] + 1, "EndColumn": spot[1]}
    return result


def _betterleaks_span(entry: dict) -> tuple[int, int] | None:
    """Where a Betterleaks match starts on its first line and ends on its last, as 0-based offsets [start, end):
    Betterleaks counts columns from 1 and includes the last one, on every line (checked with 1.9.0; Gitleaks 8 counted
    from 2 after the first line)."""
    try:
        line, start, end = int(entry.get("StartLine") or 0), int(entry.get("StartColumn") or 0), int(entry.get("EndColumn") or 0)
    except (TypeError, ValueError):
        return None
    if line < 1 or start < 1:
        return None
    return start - 1, max(start - 1, end)


def _betterleaks_contexts(payload: list, root: Path | None) -> dict[int, str]:
    """The context of each Betterleaks entry (by its position in `payload`) read from the snapshot: the line before
    the match with every other match on it masked, plus the redacted match's own lead (`api_key = "`)."""
    if root is None:
        return {}
    wanted: dict[str, dict[int, list[tuple[int, tuple[int, int]]]]] = {}
    for index, entry in enumerate(payload):
        span = _betterleaks_span(entry) if isinstance(entry, dict) else None
        if span:
            wanted.setdefault(_relative(str(entry.get("File", ""))), {}).setdefault(int(entry["StartLine"]), []).append((index, span))
    contexts: dict[int, str] = {}
    base = root.resolve()
    for path, lines in wanted.items():
        try:
            target = (root / path).resolve()
            target.relative_to(base)  # never outside the snapshot
            with target.open("r", encoding="utf-8", errors="replace") as handle:
                for number, text in enumerate(handle, 1):
                    if number > max(lines):
                        break
                    spans = [span for _, span in lines.get(number, [])]
                    for index, (start, _) in lines.get(number, []):
                        match = str(payload[index].get("Match") or "")
                        lead = match.split("REDACTED", 1)[0] if "REDACTED" in match else ""
                        contexts[index] = masked_lead(text, start, spans) + lead
        except (OSError, ValueError):
            continue
    return contexts


def _custom_secret(rule: dict, rule_id: str, path: str, line: int, *, tool: str, confidence: int) -> dict:
    """A finding from a custom rule: its description (as written, one language) as the title."""
    return _base("secrets", rule_id, rule["description"], path, line, SECRET_SEVERITY, tool=tool,
                 reason=msg("scanning.secrets.custom_reason", rule=rule["id"], path=path, line=line),
                 remediation=msg("scanning.secrets.rotate"), cwe=[798], owasp="A04:2025", confidence=confidence,
                 digest=_stable("secrets", rule_id, path, str(line)))


# Betterleaks reads a file in chunks of 100 000 bytes and then up to 25 000 more looking for a place to cut; when it finds
# none it cuts in the middle of a line, short or long, and counts the rest's columns from the cut without saying so. In a
# file no bigger than one chunk its columns count from the line's start (checked with 1.9.0:
# test_secret_location.RealEnginesTests.test_columns_count_from_the_line).
BETTERLEAKS_ONE_PIECE = 100_000


def _betterleaks_claim(entry: dict) -> secret_location.Claim:
    """What Betterleaks said about a secret (secret_location): its redacted `Match`, its length in bytes (its columns,
    1-based and inclusive, differ by it even where they count from a fragment of a long line) and its `Entropy`."""
    rule, match = str(entry.get("RuleID") or "secret"), str(entry.get("Match") or "")
    try:
        first, start, end = int(entry.get("StartLine") or 0), int(entry.get("StartColumn") or 0), int(entry.get("EndColumn") or 0)
        last = max(first, int(entry.get("EndLine") or first))
    except (TypeError, ValueError):
        first = last = start = end = 0
    value = entry.get("Entropy")
    reported = float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None
    column = start - 1 + len(match.split("REDACTED", 1)[0].encode("utf-8", "surrogateescape")) if start >= 1 else None
    if first == last:
        size = end - start + 1
        return secret_location.Claim(rule, _relative(str(entry.get("File", ""))), first, last, ("betterleaks", rule, match, size, reported),
                                     partial(secret_location.betterleaks_spots, match, size, reported, value_span=secret_filter.value_span),
                                     None, column=column, column_reach=BETTERLEAKS_ONE_PIECE)
    return secret_location.Claim(rule, _relative(str(entry.get("File", ""))), first, last, ("betterleaks", rule, match, reported), None,
                                 partial(secret_location.betterleaks_block, match, reported, start - 1, end, secret_filter.value_span),
                                 column=column, column_reach=BETTERLEAKS_ONE_PIECE)


def _betterleaks_identities(read: secret_location.Read) -> tuple[secret_identity.Names | None, str | None]:
    """A secret's names, those of its value where it was verified (secret_location), and its identity by the formula
    before (the whole match, key and quotes included, read at that same place), a former name of that value only;
    remove in 0.15 (see secret_identity's docstring)."""
    if read.names is None:
        return None, None
    return read.names, secret_identity.identity(read.match) if read.match else None


def _betterleaks_screen(entries: list[dict], texts: dict[str, dict[int, str]], reads: list[secret_location.Read]) -> dict[int, str]:
    """Why each entry that isn't a secret isn't one (secret_filter.verdict), by its position in `entries`: its value,
    read where it was verified (`reads`), judged with what precedes it on its line, and forgotten. Without its value
    only its path and line are judged."""
    reasons: dict[int, str] = {}
    for index, entry in enumerate(entries):
        path = _relative(str(entry.get("File", "")))
        line, read, value = texts.get(path, {}).get(_betterleaks_lines_of(entry)[0]) or "", reads[index], None
        if read.names is not None and len(read.match or "") <= secret_filter.MATCH_MAX:
            value = read.value
            if read.span and read.span[0] == read.span[2]:
                line = line[:read.span[3]]  # this match's key, not another one's with the same value further on
        if reason := secret_filter.verdict(str(entry.get("RuleID") or ""), path, line, value):
            reasons[index] = reason
    return reasons


MULTILINE = 200  # lines a match may span and still be read for its value (a private key fits)


def screened_detail(screened: Counter) -> Message | None:
    """What the secret filter set aside, by reason (secret_filter.REASONS), or None when nothing."""
    if not screened:
        return None
    reasons = [msg(f"scanning.secret_filter.reasons.{reason}", count=screened[reason]) for reason in secret_filter.REASONS if screened.get(reason)]
    return msg("scanning.secret_filter.screened", count=sum(screened.values()), reasons=and_list(reasons))


def parse_betterleaks(payload: list, custom: dict | None = None, root: Path | None = None,
                      screened: Counter | None = None) -> list[Finding]:
    """`root`: the snapshot, to read what precedes each secret on its line (Betterleaks redacts the whole match) and to
    judge whether a match can be a secret at all (secret_filter): what can't is left out and counted in `screened`."""
    entries = [entry for entry in payload or [] if isinstance(entry, dict)]
    reads = secret_location.resolve(root, [_betterleaks_claim(entry) for entry in entries])
    kept = [index for index in range(len(entries)) if not reads[index].duplicate]
    entries, reads = [entries[index] for index in kept], [reads[index] for index in kept]
    raw = _betterleaks_lines(entries, root)
    texts = {path: {number: _line_text(line) for number, line in lines.items()} for path, lines in raw.items()}
    set_aside = _betterleaks_screen(entries, texts, reads)
    if screened is not None:
        screened.update(set_aside.values())
    kept = [index for index in range(len(entries)) if index not in set_aside]
    entries, reads = [entries[index] for index in kept], [reads[index] for index in kept]
    # The columns Betterleaks gave, as characters: only for the context of its fingerprint (what 0.13 stored it by).
    contexts = _betterleaks_contexts(_betterleaks_char_columns(entries, raw), root)
    items = []
    for index, entry in enumerate(entries):
        rule = str(entry.get("RuleID") or "secret")
        path = _relative(str(entry.get("File", "")))
        line = int(entry.get("StartLine") or 1)
        entropy = float(entry.get("Entropy") or 0)
        if rule in (custom or {}):
            finding = _custom_secret(custom[rule], rule, path, line, tool="betterleaks", confidence=8 if entropy >= 3.5 else 6)
        else:
            # The value never reaches the finding: betterleaks runs with --redact and the context stops where the secret starts.
            finding = _base("secrets", rule, secret_title(rule), path, line, SECRET_SEVERITY, tool="betterleaks",
                            reason=msg("scanning.secrets.betterleaks_reason", rule=rule, path=path, line=line, entropy=f"{entropy:.1f}"),
                            remediation=msg("scanning.secrets.rotate"),
                            cwe=[798], owasp="A04:2025", confidence=8 if entropy >= 3.5 else 6,
                            digest=_stable("secrets", rule, path, str(line)))
        value, earlier = _betterleaks_identities(reads[index])
        named(finding, reads[index], value, earlier)
        finding = _validated(finding, entry.get("ValidationStatus"))
        items.append((finding, secret_context(contexts.get(index)), (path, line, int(entry.get("StartColumn") or 0))))
    return with_secret_identities(items)


def _betterleaks_report(snapshot: Path, settings: dict | None, started: float, *, validate: bool = False,
                        read: set[str] | None = None, inline: list[int] | None = None,
                        ignore_inline: bool = False, nested: bool = False) -> tuple[list | None, dict | None]:
    """(report, None), or (None, the step's result) when Betterleaks didn't produce its report: the run
    didn't finish (engine_contract). `validate`: Betterleaks asks each secret's provider whether it is active, the only
    time its container gets a network. `read`: filled with the files its log says it read (secret_coverage); `inline`:
    with how many matches an inline comment (`gitleaks:allow`) allowed. `ignore_inline`: those comments allow nothing.
    `nested`: the folder above `snapshot` is scanned, which holds nothing else (sources/repositories.secrets_scan_root):
    Betterleaks loads `.gitleaksignore` and `.betterleaksignore` from the top of what it scans, whatever its flags say,
    so no committed file sits there. Its paths come back as if `snapshot` had been scanned."""
    # The report is written next to the snapshot: it's the only folder both containers see.
    # The settings go in a separate folder, mounted read-only.
    # Never inside the folder it scans (`nested`: the one above `snapshot`).
    scanned = snapshot.parent if nested else snapshot
    with tempfile.TemporaryDirectory(prefix="betterleaks-", dir=scanned.parent) as output, \
            tempfile.TemporaryDirectory(prefix="betterleaks-config-", dir=scanned.parent) as config:
        arguments = ["dir", "/src", "--report-format", "json", "--report-path", "/out/report.json",
                     "--no-banner", "--exit-code", "0", "--redact", "--no-color", "--log-level", "trace",
                     *(["--ignore-gitleaks-allow"] if ignore_inline else [])]
        mounts = ["-v", f"{host_path(Path(output))}:/out"]
        # Always a generated configuration, even without settings: the opt-in rules stay off (secret_rules.OPT_IN_RULES).
        (Path(config) / "betterleaks.toml").write_text(secret_rules.betterleaks_toml(settings or secret_rules.empty(),
                                                                                  f"/src/{snapshot.name}/" if nested else "/src/"),
                                                         encoding="utf-8")
        arguments[2:2] = ["--config", "/cfg/betterleaks.toml"]
        mounts += ["-v", f"{host_path(Path(config))}:/cfg:ro"]
        if validate:
            arguments += ["--validation", "--validation-timeout", "10s", "--validation-workers", "4"]
        try:
            completed = _run("betterleaks", arguments, scanned, network=validate, mounts=mounts,
                             timeout=600, keep=secret_coverage.keep_betterleaks())
            if inline is not None:
                inline.append(secret_coverage.allowed_inline(completed.stderr or ""))
            listed, rest = secret_coverage.read_betterleaks(completed.stderr or "", root=f"/src/{snapshot.name}" if nested else "/src")
            completed = subprocess.CompletedProcess(completed.args, completed.returncode, completed.stdout, rest)
            if read is not None:
                read.update(listed)
            report = Path(output) / "report.json"
            payload, contract = engine_contract.verdict(BETTERLEAKS, completed.returncode, report.read_text(encoding="utf-8") if report.is_file() else "")
        except subprocess.TimeoutExpired:
            timeout = msg("scanning.engines.timeout", engine="Betterleaks")
            return None, engine_contract.failed(_result("betterleaks", "inconclusive", timeout, started=started), timeout)
        except (OSError, ValueError):
            unreadable = msg("scanning.betterleaks.unreadable")
            return None, engine_contract.failed(_result("betterleaks", "inconclusive", unreadable, started=started), unreadable)
    if contract is None:
        return (_unnested(payload, snapshot.name) if nested else payload), None
    # With settings, a run that wrote nothing may be the settings' fault: said so.
    detail = with_cause(contract, completed)
    if settings and "config" in (completed.stderr or "").lower():
        reason = config_cause(completed)
        detail = msg("scanning.betterleaks.config_failed_cause", cause=reason) if reason else msg("scanning.betterleaks.config_failed")
    return None, engine_contract.failed(_result("betterleaks", "inconclusive", detail, started=started), contract)


def _unnested(payload: list, folder: str) -> list:
    """A report of the folder above `folder` with its paths as if `folder` had been scanned (`/src/<folder>/a` → `/src/a`)."""
    inside = f"/src/{folder}/"
    for entry in payload or []:
        if isinstance(entry, dict):
            for key in ("File", "Fingerprint"):
                if isinstance(entry.get(key), str) and entry[key].startswith(inside):
                    entry[key] = "/src/" + entry[key][len(inside):]
    return payload


def secret_validation() -> bool:
    """Whether secrets are checked against their providers (PITANGUS_SECRET_VALIDATION): off unless enabled."""
    return settings.flag("PITANGUS_SECRET_VALIDATION")


# What Betterleaks' validation says about a secret, as Pitangus words it, and what it does to its priority: an active
# one is acted on now; a revoked one is still in the code and its history, so it stays, tracked; the rest keep theirs.
VALIDATION = {"valid": ("active", "act"), "invalid": ("revoked", "track"), "revoked": ("revoked", "track"),
              "unknown": ("unknown", None), "error": ("unknown", None), "needs_validation": ("unknown", None)}


def _validated(finding: Finding, status: object) -> Finding:
    state, action = VALIDATION.get(str(status or ""), (None, None))
    if state is None:
        return finding
    priority = finding.get("priority") or {"action": "attend", "factors": []}
    finding["validation"] = state
    finding["priority"] = {"action": action or priority["action"],
                           "factors": [msg(f"scanning.secrets.validation.{state}"), *priority.get("factors", [])]}
    return finding


def run_betterleaks(snapshot: Path, settings: dict | None = None, *, nested: bool = False) -> EngineResult:
    """`settings`: the organization's secret detection settings (secret_rules). With them, Betterleaks gets a generated
    `--config` mounted read-only; if it rejects it, the step is inconclusive, never clean. `nested`: `snapshot` is the
    only folder in the one Betterleaks scans (`_betterleaks_report`)."""
    started = time.time()
    if problem := unavailable("betterleaks", msg("scanning.betterleaks.no_docker")):
        return _result("betterleaks", "not_tested", problem)
    read: set[str] = set()
    inline: list[int] = []
    ignore_inline = inline_allow_ignored()
    payload, failure = _betterleaks_report(snapshot, settings, started, validate=secret_validation(), read=read, inline=inline,
                                           ignore_inline=ignore_inline, nested=nested)
    if failure:
        return failure
    screened: Counter = Counter()
    findings = parse_betterleaks(payload, secret_rules.custom_rules(settings), snapshot, screened)
    detail = msg("scanning.betterleaks.detail_configured", secrets=len(findings), **secret_rules.counts(settings)) if settings \
        else msg("scanning.betterleaks.detail", secrets=len(findings))
    detail = joined([detail, screened_detail(screened)], "scanning.join.sentences")

    def reference(unfiltered: dict | None) -> list[dict] | None:
        report, failed = _betterleaks_report(snapshot, unfiltered, started, ignore_inline=ignore_inline, nested=nested)
        return None if failed else parse_betterleaks(report, secret_rules.custom_rules(unfiltered), snapshot)
    # Every file of the snapshot its log doesn't name as read is unexamined by it, whatever made it pass over it.
    result = {**_withhold(_result("betterleaks", "completed", detail, findings, started), settings, reference),
              "coverage": engine_contract.coverage("*", secret_gaps(snapshot, read, settings)), "screened": dict(screened)}
    if not ignore_inline:
        result = _ignore_file_allowed(result, snapshot)
    if sum(inline) and not ignore_inline:
        result = _inline_allowed(result, snapshot, settings, started, nested=nested)
    return engine_contract.recorded(result, None)


def inline_allow_ignored() -> bool:
    """Whether `gitleaks:allow` comments in the code and the repository's ignore files allow nothing (repo_controls):
    off, they are honoured and every match they allow is declared (`_inline_allowed`)."""
    return repo_controls.ignored()


def _inline_allowed(result: dict, snapshot: Path, settings: dict | None, started: float, *, nested: bool = False) -> dict:
    """The matches a `gitleaks:allow` / `betterleaks:allow` comment allowed: a decision written in the code, honoured,
    and never silent. Betterleaks runs once more ignoring those comments; what only that run sees is excluded with its
    file and line (`suppressed_inline` in the coverage, the step and the run's limitations), never fixed and never
    with its value. If that run fails, which matches they were is unknown: the step is partial, nothing is fixed."""
    report, failed = _betterleaks_report(snapshot, settings, started, ignore_inline=True, nested=nested)
    if failed:
        return {**result, "status": "partial", "withheld": None,
                "detail": joined([result["detail"], msg("scanning.secrets.inline.unknown")], "scanning.join.sentences")}
    kept = {finding["fingerprint"] for finding in [*result["findings"], *(result.get("withheld") or [])]}
    return _declare_inline(result, [_allowed_inline(finding) for finding in parse_betterleaks(report, secret_rules.custom_rules(settings), snapshot)
                                    if finding["fingerprint"] not in kept])


IGNORE_FILES = (".gitleaksignore", ".betterleaksignore")   # where an owner lists the matches Betterleaks should allow
IGNORE_FILE_MAX = 1_000_000


def ignore_file_entries(snapshot: Path) -> dict[tuple[str, str, int], str]:
    """The matches the repository's own ignore files allow, {(path, rule, line): file}, from the files at its root (the
    only ones Betterleaks loads when it scans a repository). An entry is a Betterleaks fingerprint, `path:rule:line`
    (a commit before it is ignored), its path as Betterleaks names it (`/src/a/.env`) or relative to the repository."""
    entries: dict[tuple[str, str, int], str] = {}
    for name in IGNORE_FILES:
        path = snapshot / name
        if path.is_symlink() or not path.is_file():
            continue
        try:
            with path.open("rb") as handle:
                text = handle.read(IGNORE_FILE_MAX).decode("utf-8", "replace")
        except OSError:
            continue
        for raw in text.splitlines():
            entry = raw.strip()
            if not entry or entry.startswith("#"):
                continue
            head, _, rest = entry.partition(":")
            if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head) and rest.count(":") >= 2:
                entry = rest
            parts = entry.rsplit(":", 2)
            if len(parts) != 3 or not parts[2].isdigit():
                continue
            file = parts[0].removeprefix("/src/").removeprefix("./")
            entries.setdefault((file, parts[1], int(parts[2])), name)
    return entries


def _ignore_file_allowed(result: dict, snapshot: Path) -> dict:
    """The secrets the repository's `.gitleaksignore` / `.betterleaksignore` allow: the owner's decision, honoured by
    Pitangus as Betterleaks would, and never silent (Betterleaks itself never sees those files: `_betterleaks_report`).
    Each one is excluded with its file and line, declared like an inline comment's (`_declare_inline`), never fixed and
    never with its value. With PITANGUS_IGNORE_REPO_SUPPRESSIONS they allow nothing, as the comments."""
    return ignore_entries_allowed(result, ignore_file_entries(snapshot))


def ignore_entries_allowed(result: dict, entries: dict[tuple[str, str, int], str]) -> dict:
    """`_ignore_file_allowed` with the entries already read: the files sit at the repository's top, which the main
    snapshot doesn't hold (they go with the secret-only files), so the code scan reads them first
    (repository.scan_repository)."""
    if not entries or inline_allow_ignored() or result.get("status") not in ("completed", "partial"):
        return result
    kept, allowed = [], []
    for finding in result.get("findings") or []:
        listed = entries.get((finding["path"], str(finding.get("rule_id") or ""), int(finding.get("line") or 0)))
        if listed is None:
            kept.append(finding)
            continue
        allowed.append({**finding, "inline_allowed": True,
                        "excluded_reason": msg("scanning.secrets.ignore_file.excluded", file=listed, path=finding["path"],
                                               line=finding["line"])})
    return _declare_inline({**result, "findings": kept}, allowed)


INLINE_SHOWN = 5   # places an inline comment allowed that a step names; the run keeps them all
INLINE_ALLOW = re.compile(r"\b(?:gitleaks|betterleaks):allow\b")


def _allowed_inline(finding: Finding) -> Finding:
    return {**finding, "inline_allowed": True,
            "excluded_reason": msg("scanning.secrets.inline.excluded", path=finding["path"], line=finding["line"])}


def _declare_inline(result: dict, allowed: list[Finding], detail: str = "scanning.secrets.inline.detail") -> dict:
    """`result` with the matches an inline comment allowed excluded (`withheld`), listed by file and line in its coverage
    (`suppressed_inline`) and its detail."""
    if not allowed:
        return result
    places = sorted({f"{finding['path']}:{finding['line']}" for finding in allowed})
    coverage = result.get("coverage") or engine_contract.coverage("*")
    return {**result, "withheld": None if result.get("withheld", []) is None else [*(result.get("withheld") or []), *allowed],
            "coverage": {**coverage, "suppressed_inline": sorted({*(coverage.get("suppressed_inline") or []), *places})},
            "detail": joined([result["detail"], msg(detail, count=len(places),
                                                    places=", ".join(places[:INLINE_SHOWN]) + ("…" if len(places) > INLINE_SHOWN else ""))],
                             "scanning.join.sentences")}


def repo_suppressed(finding: Finding, control: Message) -> Finding:
    """A result the repository suppressed (repo_controls), by `control` (the comment or file that did): excluded,
    declared with its rule, file and line, never fixed."""
    return {**finding, "inline_allowed": True,
            "excluded_reason": msg("scanning.repo_controls.excluded", rule=str(finding.get("rule_id") or ""), path=finding["path"],
                                   line=int(finding.get("line") or 0), control=control)}


def declare_suppressed(result: dict, suppressed: list[Finding]) -> dict:
    """`result` with what the repository's own comments and files suppressed excluded and declared (`_declare_inline`)."""
    return _declare_inline(result, suppressed, "scanning.repo_controls.detail")


def controls_unknown(result: dict) -> dict:
    """`result` when the run without the repository's suppressions failed: which results they hid is unknown, so the step
    is partial and the scan fixes nothing (`withheld` None)."""
    return {**result, "status": "partial", "withheld": None,
            "detail": joined([result["detail"], msg("scanning.repo_controls.unknown")], "scanning.join.sentences")}


def comment_control(marker: str) -> Message:
    return msg("scanning.repo_controls.comment", marker=marker)


def file_control(file: str) -> Message:
    return msg("scanning.repo_controls.file", file=file)


# Files an infrastructure engine reads (Trivy's misconfiguration scanner, Checkov): only those are looked at for comments.
CONFIG_SUFFIXES = frozenset({".tf", ".tfvars", ".hcl", ".json", ".yaml", ".yml", ".template", ".bicep", ".tpl", ".dockerfile",
                             ".containerfile"})


def config_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    return name.startswith(("dockerfile", "containerfile")) or any(name.endswith(suffix) for suffix in CONFIG_SUFFIXES)


TRIVY_INLINE = {b"trivy:ignore": b"trivy_ignore"}


def trivy_suppressed(payload: dict, feeds: dict, custom: dict | None, root: Path, ignore: Path | None) -> list[Finding]:
    """What the repository's ignore file suppressed, as Trivy reports it apart (`--show-suppressed`): each one excluded and
    declared, never fixed."""
    if ignore is None:
        return []
    fields = {"vulnerability": "Vulnerabilities", "misconfiguration": "Misconfigurations", "secret": "Secrets"}
    results = []
    for result in payload.get("Results") or []:
        if not isinstance(result, dict):
            continue
        shaped: dict = {key: result.get(key) for key in ("Target", "Class", "Type", "Packages")}
        for item in result.get("ExperimentalModifiedFindings") or []:
            field = fields.get(str((item or {}).get("Type") or "").lower()) if isinstance(item, dict) else None
            if field and str(item.get("Status") or "").lower() == "ignored" and isinstance(item.get("Finding"), dict):
                shaped.setdefault(field, []).append(item["Finding"])
        if any(field in shaped for field in fields.values()):
            results.append(shaped)
    control = file_control(ignore.name)
    return [repo_suppressed(finding, control) for finding in parse_trivy({"Results": results}, feeds, custom, root=root)] if results else []


def _trivy_inline(snapshot: Path, cache_dir: Path, feeds: dict, skips: tuple[str, ...], ignore: Path | None,
                  honoured: list[Finding]) -> tuple[list[Finding], list[Finding]] | str | None:
    """The misconfigurations a `trivy:ignore` comment hides: Trivy honours them without a word, so it runs once more on a
    view of the snapshot where they are inert. (every misconfiguration, the ones a comment hid as excluded; with
    PITANGUS_IGNORE_REPO_SUPPRESSIONS none is excluded), "unknown" when that run failed, None without such comments."""
    marks = repo_controls.marked(snapshot, tuple(TRIVY_INLINE), repo_controls.files(snapshot, config_file))
    if not marks:
        return None
    try:
        with repo_controls.view(snapshot, rewrite={path: repo_controls.inert((snapshot / path).read_bytes(), TRIVY_INLINE)
                                                   for path in marks}) as copy:
            completed = _trivy_fs(copy, cache_dir, "misconfig", None, skips=skips, ignore=ignore)
        payload, failure = engine_contract.verdict(TRIVY, completed.returncode, completed.stdout)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return "unknown"
    if failure:
        return "unknown"
    full = [finding for finding in parse_trivy(payload, feeds, root=snapshot) if finding["scanner"] == "iac"]
    kept, hidden, extra = repo_controls.split(full, honoured, lambda finding: finding["fingerprint"])
    if repo_controls.ignored():
        return [*full, *extra], []
    return [*kept, *extra], [repo_suppressed(finding, comment_control("trivy:ignore")) for finding in hidden]


def split_inline(findings: list[Finding], root: Path | None) -> tuple[list[Finding], list[Finding]]:
    """(the secrets no inline comment allows, those one does): Trivy has no inline comments of its own, so a
    `gitleaks:allow` / `betterleaks:allow` on a secret's lines, the owner's decision, is honoured for it as Betterleaks
    honours it, unless PITANGUS_SECRETS_IGNORE_INLINE_ALLOW. Only the lines' comment is looked at: no value is kept."""
    if root is None or inline_allow_ignored():
        return findings, []
    wanted: dict[str, set[int]] = {}
    for finding in findings:
        first = int(finding.get("line") or 0)
        last = (finding.get("span") or [first, 0, first])[2] if finding.get("span") else first
        wanted.setdefault(finding["path"], set()).update(range(first, max(first, min(last, first + MULTILINE)) + 1))
    marked: set[tuple[str, int]] = set()
    base = root.resolve()
    for path, numbers in wanted.items():
        try:
            target = (root / path).resolve()
            target.relative_to(base)
            with target.open("rb") as handle:
                for number, line in enumerate(handle, 1):
                    if number in numbers and INLINE_ALLOW.search(line.decode("utf-8", "replace")):
                        marked.add((path, number))
                    if number >= max(numbers):
                        break
        except (OSError, ValueError):
            continue
    kept, allowed = [], []
    for finding in findings:
        first = int(finding.get("line") or 0)
        last = (finding.get("span") or [first, 0, first])[2] if finding.get("span") else first
        hit = any((finding["path"], number) in marked for number in range(first, max(first, last) + 1))
        (allowed if hit else kept).append(_allowed_inline(finding) if hit else finding)
    return kept, allowed


def secret_gaps(snapshot: Path, read: set[str], settings: dict | None) -> dict[str, str]:
    """The files of `snapshot` a secret engine didn't read (secret_coverage), as units to declare unexamined, and those it
    read whose bytes it can't read as text (`encoding`: UTF-16 left as it was, a code page that isn't ASCII's, bytes that
    decode as nothing). An empty file holds nothing to read, whatever the engine did with it."""
    files = secret_coverage.committed(snapshot)
    empty = {path for path in files if path not in read and (snapshot / path).stat().st_size == 0}
    gaps = secret_coverage.unread(files, read | empty, allowed=secret_rules.allowed_path(settings))
    gaps.update(secret_coverage.unreadable(snapshot, [path for path in files if path not in gaps]))
    return secret_coverage.declared(files, gaps)


def merge_secrets(*groups: list[Finding]) -> list[Finding]:
    """The same secret seen by two engines: the first engine's finding is kept and the other is noted on it, its
    fingerprint among the kept one's former names (the registry never takes it for a fix).

    Never within one engine: several secrets can share a line (a minified file, a bundle). Across engines, on the same
    line: when both carry an identity (the value's HMAC, secret_identity.py) only if it is the same; otherwise, in the identity modes
    before v2, on the same line when the rules find the same secret (`TRIVY_SAME_SECRET`) or each engine saw a single
    secret on that line. With PITANGUS_IDENTITY_MODE=v2 nothing is joined without an identity."""
    from pitangus.modules.scanning.secret_builtin_rules import TRIVY_SAME_SECRET
    guess = settings.text("PITANGUS_IDENTITY_MODE") != "v2"

    def valued(finding: Finding) -> bool:
        return bool(finding.get("identity")) and not finding.get("unlinkable")
    kept: list[Finding] = []
    for group in groups:
        lines = Counter((finding["path"], finding["line"]) for finding in group)
        taken: set[int] = set()
        for finding in group:
            where = (finding["path"], finding["line"])
            others = [index for index, item in enumerate(kept)
                      if (item["path"], item["line"]) == where and item["tool"] != finding["tool"] and index not in taken]
            # An unlinkable secret is named by its lines, not its value: never joined by its identity.
            match = next((index for index in others if valued(finding) and kept[index].get("identity") == finding["identity"]
                          and valued(kept[index])), None)
            if match is None and guess:
                alike = [index for index in others if not (valued(finding) and valued(kept[index]))]
                rule = str(finding.get("rule_id") or "")
                match = next((index for index in alike if rule in (kept[index].get("rule_id"), TRIVY_SAME_SECRET.get(str(kept[index].get("rule_id") or "")))
                              or TRIVY_SAME_SECRET.get(rule) == kept[index].get("rule_id")), None)
                if match is None and len(alike) == 1 and lines[where] == 1:
                    match = alike[0]
            if match is None:
                kept.append(finding)
            else:
                taken.add(match)
                absorbed(kept[match], finding)
    return kept

