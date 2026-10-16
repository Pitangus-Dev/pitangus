"""Hosts related to a registered domain, from passive sources only: subfinder in a container, then DNS.

subfinder asks public datasets (certificate transparency logs, passive DNS, web archives) for names under the
domain's host. It never sends a request to those hosts, and it runs with no API keys: sources that need one are
skipped. That still sends the domain's name to those third parties, so it only runs where web scans are on
(PITANGUS_DAST_ENABLED). The container is hardened like every engine's (no capabilities, no privilege escalation,
read-only root, our own uid, memory, CPU and process caps), on the default bridge since its sources are on the
internet, with a hard timeout.

Every name it answers is checked again here: a valid host name strictly under the domain, then resolved (A/AAAA)
with the same guard as the probes (`domains.public_address`). Only names whose every address is public are kept:
one pointing at a private, loopback, link-local or metadata address never reaches the list. What it finds grants
nothing: a host joins a scan only when the domain's DNS proof covers it and someone puts it in scope.
"""

from __future__ import annotations

import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path

from pitangus.modules.scanning import engine_switches
from pitangus.modules.scanning.engines import _run, docker_problem, image_available, runner, with_cause
from pitangus.modules.sources import domains
from pitangus.modules.sources.domains import DomainError
from pitangus.shared.i18n import MARK, is_msg, msg

MAX_MINUTES = 1        # subfinder's own budget for the whole enumeration
SOURCE_SECONDS = 20    # per source
TIMEOUT = 75           # the container, whatever subfinder does
RESPONSE_BYTES = 5_000_000  # read from each source
MAX_NAMES = 2000       # names read from its output
RESOLVE_WORKERS = 16
RESOLVE_SECONDS = 30   # all the lookups of a round


class DiscoveryError(ValueError):
    """A discovery that couldn't run; `message` is a catalog message."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


def unavailable(data_dir: Path | None = None):
    """Why discovery can't run here, or None. It belongs to the full web scan (its switch, engine_switches)."""
    if off := engine_switches.mode_off(engine_switches.resolve(data_dir), "dast", "scanning.discovery.disabled"):
        return off
    if runner() == "local":
        return msg("scanning.discovery.needs_docker")
    if problem := docker_problem():
        return msg("scanning.discovery.no_docker", reason=problem)
    if not image_available("subfinder"):
        return msg("scanning.discovery.image_missing")
    return None


def arguments(host: str) -> list[str]:
    # No -all (slow sources), no -active (it would resolve inside the container), no config or keys mounted.
    return ["-d", host, "-silent", "-oJ", "-duc", "-nc", "-timeout", str(SOURCE_SECONDS), "-max-time", str(MAX_MINUTES),
            "-rsr", str(RESPONSE_BYTES)]


def names(output: str, root: str) -> list[str]:
    """The valid host names strictly under `root` in subfinder's JSON lines, without repeats, sorted."""
    found: set[str] = set()
    for line in output.splitlines()[:MAX_NAMES]:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        value = entry.get("host") if isinstance(entry, dict) else None
        if not isinstance(value, str) or len(value) > 253:
            continue
        name = value.strip().lower().rstrip(".")
        if name != root and name.endswith("." + root) and domains.valid_host(name):
            found.add(name)
    return sorted(found)


def _lookup(name: str) -> str:
    """kept · private · unresolved."""
    try:
        domains.public_address(name)
    except DomainError as exc:
        private = is_msg(exc.message) and exc.message[MARK] == "sources.domains.check.private_address"
        return "private" if private else "unresolved"
    return "kept"


def resolve(candidates: list[str]) -> tuple[list[str], dict]:
    """The names that resolve to public addresses only, and how many were dropped and why. A lookup still pending at
    RESOLVE_SECONDS counts as unresolved."""
    outcome: dict[str, str] = {}
    pool = ThreadPoolExecutor(max_workers=RESOLVE_WORKERS, thread_name_prefix="pitangus-resolve")
    try:
        futures = {pool.submit(_lookup, name): name for name in candidates}
        done, _ = wait(futures, timeout=RESOLVE_SECONDS)
        for future in done:
            outcome[futures[future]] = future.result()
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    kept = sorted(name for name, result in outcome.items() if result == "kept")
    private = sum(1 for result in outcome.values() if result == "private")
    return kept, {"found": len(candidates), "kept": len(kept), "private": private, "unresolved": len(candidates) - len(kept) - private}


def discover(host: str) -> dict:
    """One round for `host`: {"hosts": [...], "counts": {found, kept, private, unresolved}}. Raises DiscoveryError."""
    if not domains.valid_host(host):
        raise DiscoveryError(msg("scanning.discovery.failed"))
    try:
        completed = _run("subfinder", arguments(host), None, network=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        raise DiscoveryError(msg("scanning.discovery.timeout", seconds=TIMEOUT)) from exc
    except (OSError, ValueError) as exc:
        raise DiscoveryError(msg("scanning.discovery.failed")) from exc
    output = completed.stdout or ""
    if completed.returncode != 0 and not output.strip():
        raise DiscoveryError(with_cause(msg("scanning.discovery.failed"), completed))
    kept, counts = resolve(names(output, host))
    return {"hosts": kept, "counts": counts}
