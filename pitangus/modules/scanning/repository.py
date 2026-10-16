"""Passive snapshot analysis: bounded SAST, redacted secrets and OSV SCA."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from pitangus.modules.scanning.inventory import collect as collect_inventory
from pitangus.modules.scanning.unused_deps import analyze as unused_dependencies
from pitangus.modules.intel.advisories import MAX_DETAILS, dependency_finding, fetch_advisory, load_feeds
from pitangus.modules.scanning.coverage import RULE_LANGUAGE_IDS, owasp_coverage
from pitangus.modules.scanning.config_engines import merge_repository, run_checkov, run_zizmor
from pitangus.modules.scanning.dependency_merge import merge_dependencies, unique_by_fingerprint
from pitangus.modules.scanning.dependency_graph import annotate as annotate_dependency_graph
from pitangus.modules.scanning import declared_ranges
from pitangus.modules.scanning import engine_contract, rule_set, secret_identity, secret_rules
from pitangus.modules.scanning.policies import run_policies
from pitangus.modules.scanning.vendored import is_vendored
from pitangus.modules.scanning.engines import ignore_entries_allowed, ignore_file_entries, RULE_LANGUAGES, SECRET_SEVERITY, Engine, EngineStep, ScanContext, report_done, run_engines, SEVERITY_NAME, and_list, engines_available, joined as join_messages, host_mount_problem, run_osv_scanner, runner, socket_problem, merge_secrets, run_betterleaks, run_opengrep, screened_detail, run_trivy, masked_lead, secret_context, trivy_secrets, with_secret_identities
from pitangus.modules.sources.repositories import secrets_root, secrets_scan_root
from pitangus.shared import coverage_units
from pitangus.shared.i18n import msg
from pitangus.shared.masking import sanitize_record
from pitangus.shared.model import RunRecord
from pitangus.version import USER_AGENT


SECRET_RULES = (
    ("GitHub token", re.compile(r"\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36,}\b")),
    ("OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9_-]{30,}\b")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    # Signature included: a full JWT in code or docs is a reusable credential.
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("clave privada", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("Stripe secret key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
)
# Titles of the internal secret patterns (the name above is part of the rule id and must not change).
SECRET_TITLES = {
    "GitHub token": msg("scanning.internal.secret_titles.github_token"),
    "OpenAI API key": msg("scanning.internal.secret_titles.openai_api_key"),
    "AWS access key ID": msg("scanning.internal.secret_titles.aws_access_key_id"),
    "JSON Web Token": msg("scanning.internal.secret_titles.jwt"),
    "clave privada": msg("scanning.internal.secret_titles.private_key"),
    "Stripe secret key": msg("scanning.internal.secret_titles.stripe_secret_key"),
    "Slack token": msg("scanning.internal.secret_titles.slack_token"),
    "Google API key": msg("scanning.internal.secret_titles.google_api_key"),
}
CODE_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml", ".env", ".md", ".txt", ".html", ".xml",
                   ".rst", ".ipynb", ".pem", ".key", ".toml", ".ini", ".cfg", ".conf", ".properties", ".sh", ".tf"}


def _finding(scanner: str, rule: str, title, path: str, line: int, severity: str,
             reason, cwe: int, owasp: str, *, cve: list[str] | None = None,
             ghsa: list[str] | None = None) -> dict:
    fingerprint = hashlib.sha256(f"{scanner}|{rule}|{path}|{line}".encode()).hexdigest()
    if scanner == "secrets":
        severity = SECRET_SEVERITY
    action = "attend" if severity in ("critical", "high") else "track"
    return {"finding_id": fingerprint[:16], "fingerprint": fingerprint, "scanner": scanner, "rule_id": rule,
            "title": title, "path": path, "line": line, "severity": severity,
            "confidence": 6, "verdict": "candidate", "cwe": [cwe] if cwe else [], "owasp": [owasp],
            "cve": cve or [], "ghsa": ghsa or [], "reason": reason, "package": None, "advisory": None,
            "kev": None, "epss": None,
            "priority": {"action": action, "factors": [msg("scanning.priority.internal_pattern", severity=SEVERITY_NAME.get(severity, severity))]},
            "remediation": msg("scanning.internal.remediation")}


def _secret_candidates(path: Path, relative: str) -> list[dict]:
    try:
        content = path.read_text(encoding="utf-8")
    except (UnicodeError, OSError):
        return []
    items = []
    for number, line in enumerate(content.splitlines(), 1):
        spans = [found.span() for _, pattern in SECRET_RULES for found in pattern.finditer(line)]
        for name, pattern in SECRET_RULES:
            if found := pattern.search(line):
                finding = _finding("secrets", name.upper().replace(" ", "-"), SECRET_TITLES[name], relative, number,
                                   SECRET_SEVERITY, msg("scanning.internal.secret_reason"), 798, "A04:2025")
                secret_identity.assign(finding, secret_identity.names(found.group(0)))
                finding["span"] = [number, found.start(), number, found.end()]
                items.append((finding, secret_context(masked_lead(line, found.start(), spans)), (number, found.start())))
    return with_secret_identities(items)


def _dependencies(root: Path) -> tuple[list[dict], list[str]]:
    result = []
    manifests = []
    for lock in root.rglob("package-lock.json"):
        if any(part in {"node_modules", ".git", ".venv"} for part in lock.relative_to(root).parts):
            continue
        if len(result) >= 250:
            break
        try:
            data = json.loads(lock.read_text(encoding="utf-8"))
            packages = data.get("packages", {}) if isinstance(data, dict) else None   # `[]`, `"…"`: valid JSON all the same
            if not isinstance(packages, dict):
                continue
            manifests.append(str(lock.relative_to(root)))
            for package_path, metadata in packages.items():
                if not isinstance(metadata, dict) or "node_modules/" not in package_path:
                    continue
                name = package_path.rsplit("node_modules/", 1)[1]
                version = metadata.get("version")
                if isinstance(version, str) and re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version):
                    result.append({"name": name, "version": version, "ecosystem": "npm", "path": str(lock.relative_to(root))})
                if len(result) >= 250:
                    break
        except (OSError, ValueError, UnicodeError):
            continue
    for manifest in root.rglob("requirements.txt"):
        if any(part in {"node_modules", ".git", ".venv"} for part in manifest.relative_to(root).parts):
            continue
        try:
            lines = manifest.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            continue
        manifests.append(str(manifest.relative_to(root)))
        for line in lines:
            match = re.fullmatch(r"\s*([A-Za-z0-9_.-]+)==(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)\s*", line)
            if match and len(result) < 250:
                result.append({"name": match[1], "version": match[2], "ecosystem": "PyPI", "path": str(manifest.relative_to(root))})
    unique = {(item["ecosystem"], item["name"], item["version"]): item for item in result}
    return list(unique.values()), manifests


def _query_osv(dependencies: list[dict]) -> list[dict]:
    request = Request("https://api.osv.dev/v1/querybatch",
                      data=json.dumps({"queries": [{"package": {"ecosystem": item["ecosystem"], "name": item["name"]},
                                                      "version": item["version"]} for item in dependencies]}).encode(),
                      headers={"Content-Type": "application/json", "User-Agent": USER_AGENT}, method="POST")
    with urlopen(request, timeout=15) as response:
        body = response.read(2_000_001)
    if len(body) > 2_000_000:
        raise ValueError("OSV response too large")
    data = json.loads(body)
    if not isinstance(data.get("results"), list) or len(data["results"]) != len(dependencies):
        raise ValueError("Invalid OSV response")
    return data["results"]


# The engines of a code scan, in the order they run. Each is looked up here when it runs (so a test can replace one).
# `required`: without its result the run is incomplete. `merged`: its progress line waits for the merge below.
# Adding an engine: its image in engines.IMAGES, its run_* function, a line here and, if it overlaps others, its merge.
CODE_ENGINES: tuple[EngineStep, ...] = (
    EngineStep("opengrep", lambda context: run_opengrep(context.root), "scanning.progress.opengrep"),
    EngineStep("betterleaks", lambda context: run_betterleaks(context.root, context.secret_settings), "scanning.progress.betterleaks"),
    EngineStep("trivy", lambda context: run_trivy(context.root, context.data_dir / "trivy-cache", context.feeds, context.secret_settings, context.data_dir),
               "scanning.progress.trivy"),
    EngineStep("osv-scanner", lambda context: run_osv_scanner(context.root, context.data_dir / "osv-cache", context.feeds,
                                                              resolve=context.allow_osv_upload),
               "scanning.progress.osv", merged=True),
    EngineStep("checkov", lambda context: run_checkov(context.root), "scanning.progress.checkov", required=False, merged=True),
    EngineStep("zizmor", lambda context: run_zizmor(context.root), "scanning.progress.zizmor", required=False, merged=True),
)
REQUIRED_ENGINES = frozenset(engine.key for engine in CODE_ENGINES if engine.required)
FOLDERS_SHOWN = 5


# Every engine reads the snapshot but the secret scanners, which also read what `set_apart` moved out of it: Trivy only
# with its secret scanner, so its other scanners leave those folders unexamined.
SECRET_ENGINES = frozenset({"betterleaks"})
SECRET_ONLY_SCANNERS = {"trivy": ("sca", "iac")}


def _left_out_reasons(left_out) -> dict[str, str]:
    """What the snapshot left out, {unit: why}: listed by path alone before reasons were kept (`left_out`)."""
    if isinstance(left_out, dict):
        return {str(unit): str(why) for unit, why in left_out.items()}
    return dict.fromkeys((str(unit) for unit in left_out or ()), "left_out")


def _unexamined(left_out, tools: list[dict], credentials: dict[str, dict[str, str]],
                apart: dict[str, str] | None = None) -> dict[str, list[str]]:
    """What this scan didn't analyze, by path: left out of the snapshot ("*"), skipped by one engine (its key) or by one
    of its scanners only (`engine:scanner`), credential files included when a secret scanner couldn't read them. The
    units an engine's coverage declares unexamined count here too, so the rules before the coverage contract never fix
    what the engine said it didn't read. `apart`: the folders only the secret scanners read ({"dist/": "generated"}),
    unexamined (with everything under them) for every other engine and scanner."""
    found = {"*": sorted(_left_out_reasons(left_out))} if left_out else {}
    for tool in tools:
        declared = (tool.get("coverage") or {}).get("unexamined") or {}
        if paths := sorted({*(tool.get("unexamined") or []), *declared}):
            found[tool["tool"]] = paths
    found.update({f"{tool['tool']}:{scanner}": sorted(units) for tool in tools
                  for scanner, units in ((tool.get("coverage") or {}).get("by_scanner") or {}).items()})
    for engine, paths in credentials.items():
        found[engine] = sorted({*found.get(engine, []), *paths})
    for tool in tools if apart else ():
        if tool["tool"] in SECRET_ENGINES:
            continue
        for key in ([f"{tool['tool']}:{scanner}" for scanner in SECRET_ONLY_SCANNERS[tool["tool"]]]
                    if tool["tool"] in SECRET_ONLY_SCANNERS else [tool["tool"]]):
            found[key] = sorted({*found.get(key, []), *(apart or {})})
    return found


def _coverage(left_out, tools: list[dict], credentials: dict[str, dict[str, str]],
              apart: dict[str, str] | None = None) -> dict[str, dict]:
    """What each engine examined (engine_contract.coverage), with the files the snapshot left out unexamined for all of
    them, the files of the secret-only copy a secret scanner didn't read unexamined for it (each with why), and the
    folders only the secret scanners read (`apart`, each with why) unexamined for the others."""
    found = {}
    for tool in tools:
        if not tool.get("coverage"):
            continue
        name, spec = tool["tool"], dict(tool["coverage"])
        unexamined = {**_left_out_reasons(left_out), **spec.get("unexamined", {}), **credentials.get(name, {})}
        if apart and name in SECRET_ONLY_SCANNERS:
            scoped = spec.get("by_scanner") or {}
            spec["by_scanner"] = {**scoped, **{scanner: dict(sorted({**scoped.get(scanner, {}), **apart}.items()))
                                               for scanner in SECRET_ONLY_SCANNERS[name]}}
        elif apart and name not in SECRET_ENGINES:
            unexamined.update(apart)
        found[name] = {**spec, "unexamined": dict(sorted(unexamined.items()))}
    return found


def _inline_places(withheld: list[dict], engine: str | None = None) -> list[str]:
    """Where a `gitleaks:allow` comment allowed a secret (file:line, never the value), in the code and the secret-only
    copy alike; by `engine` (also when it saw the same secret as another), or by either."""
    return sorted({f"{item['path']}:{item['line']}" for item in withheld if item.get("inline_allowed")
                   and (engine is None or engine in (item.get("tool"), *(item.get("also_detected_by") or [])))})


def _with_inline(coverage: dict[str, dict], withheld: list[dict]) -> dict[str, dict]:
    """Each secret engine's coverage with every match an inline comment allowed (`suppressed_inline`): read, and
    declared."""
    for engine in ("betterleaks", "trivy"):
        if (places := _inline_places(withheld, engine)) and engine in coverage:
            coverage[engine] = {**coverage[engine], "suppressed_inline": places}
    return coverage


def scan_credentials(root: Path, data_dir: Path, secret_settings: dict | None, *, engines: bool,
                     apart: dict[str, str] | None = None) -> dict:
    """What only the secret scanners read (`secrets_root`): the credential files (`.env`, `.npmrc`, `id_rsa`…), the
    dependency and build output folders the other engines don't read (`apart`) and every other committed file they don't
    read (hidden folders, binaries). Read by Betterleaks and Trivy's secret scanner only (by the internal patterns
    without Docker), and removed when they finish, whatever happened. A scanner that failed leaves them unexamined for
    it (the folders as such), one that finished the files its log doesn't name as read (secret_coverage): nothing it
    saw there before is fixed."""
    folder = secrets_root(root)
    if not folder.is_dir():
        return {"findings": [], "withheld": [], "unexamined": {}, "files": 0}
    try:
        files = sorted(path.relative_to(folder).as_posix() for path in folder.rglob("*") if path.is_file())
        if not engines:
            return {"findings": [item for name in files for item in _secret_candidates(folder / name, name)], "withheld": [],
                    "unexamined": {}, "files": len(files)}
        # Betterleaks scans the folder above, which holds nothing else: no committed file sits where it loads its
        # control files from (`.gitleaksignore`, `.betterleaksignore`), so only Pitangus honours them, never silently.
        betterleaks = engine_contract.settled(run_betterleaks(folder, secret_settings, nested=True))
        screened = Counter(betterleaks.get("screened") or {})
        trivy_gaps: dict[str, str] = {}
        trivy_allowed: list[dict] = []
        trivy = trivy_secrets(folder, data_dir / "trivy-cache", secret_settings, screened, gaps=trivy_gaps, allowed=trivy_allowed, controls=root)
        # Read while the files are there: the values to mask wherever else they appear (shared/masking.py).
        values = secret_identity.values(folder, [*betterleaks["findings"], *(betterleaks.get("withheld") or []), *(trivy or [])])
    finally:
        shutil.rmtree(secrets_scan_root(root), ignore_errors=True)
    units = dict.fromkeys(sorted({*(name for name in files if not any(name.startswith(prefix) for prefix in apart or {})), *(apart or {})}),
                          "not_read")
    gaps = {"betterleaks": units if betterleaks["status"] != "completed" else (betterleaks.get("coverage") or {}).get("unexamined") or {},
            "trivy": units if trivy is None else trivy_gaps}
    unexamined = {engine: dict(found) for engine, found in gaps.items() if found}
    return {"findings": merge_secrets(betterleaks["findings"], trivy or []),
            "withheld": merge_secrets(betterleaks.get("withheld") or [], trivy_allowed),
            "unexamined": unexamined, "files": len(files), "screened": dict(screened), "values": values}


def scan_repository(root: Path, source: dict, *, allow_osv_upload: bool = False,
                    context: str = "", data_dir: Path | None = None, progress=None,
                    replay: Sequence[Engine] | None = None, feeds: dict | None = None) -> RunRecord:
    """`replay`: engines that stand in for CODE_ENGINES (one per key) and need no Docker: the demo replays recorded
    engine outputs through them. `feeds`: the KEV/EPSS feeds already at hand, instead of loading them."""
    def report(level: str, message) -> None:
        if progress is not None:
            progress(level, message)

    files = sorted(path for path in root.rglob("*") if path.is_file() and not path.is_symlink())
    findings, withheld = [], []
    credentials: dict = {"findings": [], "withheld": [], "unexamined": {}, "files": 0}
    if replay is not None:  # recorded engine outputs: no credential file is read, and none stays on disk
        shutil.rmtree(secrets_scan_root(root), ignore_errors=True)
    snapshot = dict(source.get("snapshot") or {})
    # Kept once, for the registry, not in the source record too.
    left_out = _left_out_reasons(snapshot.pop("unexamined", None) or {})
    apart = {str(folder): str(why) for folder, why in (snapshot.pop("apart", None) or {}).items()}
    if "snapshot" in source:
        source = {**source, "snapshot": snapshot}
    detail = msg("scanning.repository.snapshot.copied", files=len(files))
    if "secret_only" in snapshot:
        # What the code engines don't read went to the secret pass: only size and budget leave a file out.
        skipped = snapshot.get("skipped_too_large", 0) + snapshot.get("skipped_over_budget", 0)
        if skipped:
            counts = {"skipped": skipped, "too_large": snapshot.get("skipped_too_large", 0)}
            detail = (msg("scanning.repository.snapshot.left_out_budget", detail=detail, over_budget=snapshot["skipped_over_budget"], **counts)
                      if snapshot.get("skipped_over_budget") else msg("scanning.repository.snapshot.left_out", detail=detail, **counts))
        if snapshot["secret_only"]:
            detail = msg("scanning.repository.snapshot.secret_only", detail=detail, count=snapshot["secret_only"])
    elif skipped := (snapshot.get("skipped", 0) + snapshot.get("skipped_not_analyzable", 0)
                     + snapshot.get("skipped_too_large", 0) + snapshot.get("skipped_over_budget", 0)):
        counts = {"skipped": skipped, "not_analyzable": snapshot.get("skipped_not_analyzable", 0),
                  "too_large": snapshot.get("skipped_too_large", 0)}
        detail = (msg("scanning.repository.snapshot.skipped_budget", detail=detail, over_budget=snapshot["skipped_over_budget"], **counts)
                  if snapshot.get("skipped_over_budget") else msg("scanning.repository.snapshot.skipped", detail=detail, **counts))
    if snapshot.get("credential_files"):
        detail = msg("scanning.repository.snapshot.credentials", detail=detail, count=snapshot["credential_files"])
    if apart:
        detail = msg("scanning.repository.snapshot.apart", detail=detail, count=len(apart), folders=", ".join(list(apart)[:FOLDERS_SHOWN]))
    if committed := sum((snapshot.get("committed") or {}).values()):
        # What the commit holds that the copy doesn't (export-ignore, LFS objects, submodules, links): declared, by path.
        detail = msg("scanning.repository.snapshot.not_held", detail=detail, count=committed,
                     paths=", ".join(sorted(unit for unit, why in left_out.items() if why != "left_out")[:FOLDERS_SHOWN]))
    if snapshot.get("transcoded"):
        detail = msg("scanning.repository.snapshot.transcoded", detail=detail, count=snapshot["transcoded"])
    if snapshot.get("local_only_count"):
        detail = msg("scanning.repository.snapshot.local_only", detail=detail, count=snapshot["local_only_count"],
                     folders=", ".join((snapshot.get("local_only") or [])[:FOLDERS_SHOWN]))
    steps = [{"id": "snapshot", "name": msg("scanning.repository.steps.snapshot"),
              "status": "partial" if snapshot.get("truncated") else "completed", "detail": detail}]
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    engines = replay is not None or engines_available()
    docker = replay is None and runner() == "docker"
    if feeds is None:
        feeds = load_feeds(data_dir or Path("data")) if (engines or allow_osv_upload) else {"kev": {}, "epss": {}}
    tools: list[dict] = []
    applied: dict | None = None  # which engines and rules this scan ran with (rule_set)
    dependency_graph: dict = {}
    misconfigured = None if engines or not docker else socket_problem()
    if misconfigured:
        # Docker is there, but this container can't use it: this isn't a deliberately engine-less scan.
        report("warn", misconfigured)
    if engines:
        # Each engine runs in its container pinned by digest; the step keeps version, image and duration.
        mount_problem = host_mount_problem() if docker else None
        if mount_problem:
            report("warn", mount_problem)
        # The defaults plus this repository's own entries apply to both secret engines.
        secret_settings = secret_rules.for_scan(data_dir, source.get("uid") or source.get("id") or source.get("name"))
        applied = rule_set.code(secret_settings)
        ignore_entries: dict = {}
        if replay is None:
            # The repository's `.gitleaksignore` / `.betterleaksignore` go with the secret-only files, removed once read:
            # their entries are read first, for the code's matches too.
            ignore_entries = ignore_file_entries(secrets_root(root))
            credentials = scan_credentials(root, data_dir or Path("data"), secret_settings, engines=True, apart=apart)
        results = run_engines(CODE_ENGINES if replay is None else replay, ScanContext(root, data_dir or Path("data"), feeds, secret_settings, allow_osv_upload), report)
        results["betterleaks"] = ignore_entries_allowed(results["betterleaks"], ignore_entries)
        sast, secrets_betterleaks, trivy = results["opengrep"], results["betterleaks"], results["trivy"]
        dependency_graph = trivy.pop("graph", None) or {}  # only for this scan: never stored with the run
        osv, checkov, zizmor = results["osv-scanner"], results["checkov"], results["zizmor"]
        tools = list(results.values())
        # An engine that didn't run isn't "zero findings": it's said plainly and the run is incomplete.
        failed = [results[engine.key]["name"] for engine in CODE_ENGINES if engine.required and results[engine.key]["status"] == "inconclusive"]
        if failed:
            report("warn", msg("scanning.progress.engines_failed", engines=", ".join(failed)))
        findings.extend(sast["findings"])
        trivy_secrets = [item for item in trivy["findings"] if item["scanner"] == "secrets"]
        findings.extend(merge_secrets(secrets_betterleaks["findings"], trivy_secrets))
        findings.extend(credentials["findings"])
        trivy_withheld = trivy.get("withheld") or []
        # What the repository's own comments and files suppressed in the other engines (repo_controls): excluded too.
        withheld = (merge_secrets(secrets_betterleaks.get("withheld") or [], [item for item in trivy_withheld if item["scanner"] == "secrets"])
                    + credentials["withheld"] + [item for item in trivy_withheld if item["scanner"] != "secrets"]
                    + (sast.get("silenced") or []) + (sast.get("vendored") or [])
                    + [item for engine in (results["osv-scanner"], results["checkov"], results["zizmor"]) for item in engine.get("withheld") or []])
        # Trivy wins (its fingerprints hold the triage already done); OSV-Scanner adds what Trivy doesn't see
        # and confirms what matches, without repeating the advisory even if it names it with another identifier.
        dependencies_found, dependency_merge = merge_dependencies([item for item in trivy["findings"] if item["scanner"] == "sca"],
                                                                  ("osv-scanner", osv["findings"]))
        findings.extend(dependencies_found)
        if osv["status"] == "completed" and osv["findings"]:
            osv["detail"] = msg("scanning.repository.osv_merged", detail=osv["detail"], joined=dependency_merge["joined"],
                                new=dependency_merge["new"])
        report_done(report, osv)
        # What Trivy and Checkov (or zizmor and Checkov) both see stays a single finding with both engines.
        configuration, joined = merge_repository([item for item in trivy["findings"] if item["scanner"] == "iac"],
                                                 checkov["findings"], zizmor["findings"])
        findings.extend(configuration)
        if checkov["status"] == "completed" and checkov["findings"]:
            checkov["detail"] = msg("scanning.repository.checkov_merged", detail=checkov["detail"], joined=joined["joined"],
                                    new=joined["checkov_new"])
        report_done(report, checkov)
        report_done(report, zizmor)
        for tool in tools:
            steps.append({"id": tool["tool"], "name": f"{tool['name']} {tool['version']}", "status": tool["status"],
                          "detail": tool["detail"], "tool": {"name": tool["tool"], "version": tool["version"],
                                                            "image": tool["image"], "duration_s": tool["duration_s"]}})
    else:
        report("warn", msg("scanning.progress.no_docker"))
        credentials = scan_credentials(root, data_dir or Path("data"), None, engines=False, apart=apart)
        findings.extend(credentials["findings"])
        for path in files:
            relative = path.relative_to(root).as_posix()
            if path.suffix in CODE_EXTENSIONS or path.name.startswith(".env"):
                findings.extend(_secret_candidates(path, relative))
        # No SAST without Opengrep: a few checks of our own would look like coverage they aren't.
        steps.extend([
            {"id": "sast", "name": msg("scanning.repository.steps.no_sast.name"), "status": "not_tested",
             "detail": msg("scanning.repository.steps.no_sast.detail")},
            {"id": "secrets", "name": msg("scanning.repository.steps.internal_secrets.name"), "status": "partial",
             "detail": msg("scanning.repository.steps.internal_secrets.detail",
                           candidates=sum(item["scanner"] == "secrets" for item in findings))},
        ])
    # Access policies no code engine reads (Supabase row level security, Firebase rules): our own reader, with or without
    # Docker, declaring what it read like every engine.
    policies = run_policies(root)
    findings.extend(policies["findings"])
    tools.append(policies)
    steps.append({"id": policies["tool"], "name": f"{policies['name']} {policies['version']}", "status": policies["status"],
                  "detail": policies["detail"], "tool": {"name": policies["tool"], "version": policies["version"], "image": None,
                                                         "duration_s": policies["duration_s"]}})
    report_done(report, policies)
    # Registry invariant: one fingerprint, one finding. No engine or merge may slip in a duplicate.
    findings = unique_by_fingerprint(findings)
    seen = {item["fingerprint"] for item in findings}
    withheld = [item for item in withheld if item["fingerprint"] not in seen]
    sast_count = sum(item["scanner"] == "sast" for item in findings)
    secret_count = sum(item["scanner"] == "secrets" for item in findings)
    engine_sca = [tool["name"] for tool in tools if tool["tool"] in ("trivy", "osv-scanner") and tool["status"] == "completed"]
    trivy_sca = engines and bool(engine_sca)
    dependencies, manifests = _dependencies(root)
    dependency_scope = (msg("scanning.repository.sca.scope_first", versions=len(dependencies)) if len(dependencies) >= 250
                        else msg("scanning.repository.sca.scope", versions=len(dependencies)))
    if trivy_sca:
        report("info", msg("scanning.progress.feeds"))
        sca_count = sum(item["scanner"] == "sca" for item in findings)
        sca_status = "partial"
        joined = sum(1 for item in findings if item["scanner"] == "sca" and item.get("also_detected_by"))
        sca_detail = (msg("scanning.repository.sca.engines_confirmed", engines=and_list(engine_sca), advisories=sca_count, confirmed=joined)
                      if joined else msg("scanning.repository.sca.engines", engines=and_list(engine_sca), advisories=sca_count))
    elif not manifests:
        sca_status, sca_detail = "not_tested", msg("scanning.repository.sca.no_manifests")
    elif not dependencies:
        sca_status, sca_detail = "inconclusive", msg("scanning.repository.sca.no_versions")
    elif not allow_osv_upload:
        sca_status, sca_detail = "not_tested", msg("scanning.repository.sca.osv_not_allowed", scope=dependency_scope)
    else:
        try:
            responses = _query_osv(dependencies)
            # querybatch only returns identifiers: each advisory's details are what bring the value.
            identifiers = []
            for item in responses:
                for vulnerability in item.get("vulns", []):
                    identifier = vulnerability.get("id", "")
                    if re.fullmatch(r"[A-Za-z0-9-]{5,80}", identifier) and identifier not in identifiers:
                        identifiers.append(identifier)
            details = {identifier: fetch_advisory(identifier) for identifier in identifiers[:MAX_DETAILS]}
            seen = set()
            for dependency, item in zip(dependencies, responses):
                for vulnerability in item.get("vulns", []):
                    identifier = vulnerability.get("id", "")
                    advisory = details.get(identifier)
                    if advisory:
                        finding = dependency_finding(dependency, advisory, feeds)
                    elif re.fullmatch(r"[A-Za-z0-9-]{5,80}", identifier):
                        finding = _finding("sca", identifier, f"{dependency['name']} {dependency['version']}: {identifier}",
                                           dependency["path"], 1, "medium",
                                           msg("scanning.repository.sca.osv_without_detail", advisory=identifier),
                                           1104, "A03:2025", cve=[identifier] if identifier.startswith("CVE-") else [],
                                           ghsa=[identifier] if identifier.startswith("GHSA-") else [])
                        finding["package"] = {"ecosystem": dependency["ecosystem"], "name": dependency["name"],
                                              "version": dependency["version"], "fixed_version": None, "introduced": None}
                    else:
                        continue
                    if finding["fingerprint"] in seen:
                        continue
                    seen.add(finding["fingerprint"])
                    findings.append(finding)
            sca_findings = [item for item in findings if item["scanner"] == "sca"]
            packages = {(item["package"] or {}).get("name") for item in sca_findings}
            fixed = sum(1 for item in sca_findings if (item.get("package") or {}).get("fixed_version"))
            in_kev = sum(1 for item in sca_findings if item.get("kev"))
            parts = [msg("scanning.repository.sca.osv_detail", scope=dependency_scope, advisories=len(sca_findings),
                         packages=len(packages), fixed=fixed, kev=in_kev)]
            if not feeds.get("kev") or not feeds.get("epss"):
                parts.append(msg("scanning.repository.sca.no_feeds"))
            if len(identifiers) > MAX_DETAILS:
                parts.append(msg("scanning.repository.sca.detailed_subset", detailed=MAX_DETAILS, total=len(identifiers)))
            sca_detail = join_messages(parts, "scanning.join.sentences")
            sca_status = "partial"
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, KeyError, TypeError):
            sca_status, sca_detail = "inconclusive", msg("scanning.repository.sca.osv_failed")
    # Who brings in each vulnerable package, from the graph Trivy resolved (for the fix guide), whichever engine found it;
    # and, while the snapshot exists, the ranges its lockfile declares.
    annotate_dependency_graph(findings, dependency_graph, declared_ranges.reader(root))
    steps.append({"id": "sca", "name": msg("scanning.repository.steps.sca", engines=" + ".join(engine_sca) if trivy_sca else "OSV"),
                  "status": sca_status, "detail": sca_detail})
    steps.append({"id": "review", "name": msg("scanning.steps.review"), "status": "pending",
                  "detail": msg("scanning.repository.steps.review")})
    iac_tools = tuple(tool["name"] for tool in tools if tool["tool"] in ("trivy", "checkov") and tool["status"] == "completed")
    iac_ran = engines and bool(iac_tools)
    cicd_tools = tuple(tool["name"] for tool in tools if tool["tool"] in ("checkov", "zizmor") and tool["status"] == "completed")
    sast_ran = engines and any(tool["tool"] == "opengrep" and tool["status"] in ("completed", "partial") for tool in tools)
    iac_files = sum(1 for path in files if path.name.lower() in ("dockerfile", "containerfile") or path.suffix.lower() in (".tf", ".tfvars", ".bicep")
                    or (path.suffix.lower() in (".yml", ".yaml", ".json") and any(marker in path.read_text(encoding="utf-8", errors="ignore")[:4000]
                                                                                 for marker in ("apiVersion:", "AWSTemplateFormatVersion", "services:",
                                                                                                "deploymentTemplate.json"))))
    pipelines = sum(1 for path in files if ".github/workflows/" in path.relative_to(root).as_posix()
                    or path.name in ("action.yml", "action.yaml", ".gitlab-ci.yml", "bitbucket-pipelines.yml", "azure-pipelines.yml")
                    or path.relative_to(root).as_posix() == ".circleci/config.yml")
    suffixes = {path.suffix.lower() for path in files}
    languages = frozenset(RULE_LANGUAGE_IDS[name] for name, extensions in RULE_LANGUAGES.items() if extensions & suffixes)
    coverage = owasp_coverage(findings, sast_ran=bool(sast_ran), sca_status=sca_status, iac_ran=bool(iac_ran),
                              iac_files=iac_files, secrets_ran=True, engines=bool(engines), iac_tools=iac_tools,
                              cicd_tools=cicd_tools if engines else (), pipeline_files=pipelines, languages=languages)
    source = {**source, "sha256": digest.hexdigest()}
    declared = " ".join(str(context).split())[:400]
    severities = {level: sum(1 for item in findings if item["severity"] == level)
                  for level in ("critical", "high", "medium", "low", "info")}
    priorities = {action: sum(1 for item in findings if (item.get("priority") or {}).get("action") == action)
                  for action in ("act", "attend", "track")}
    truncated = bool(snapshot.get("truncated"))
    # What the secret engines set aside as not secrets, in the code and in the credential files: counted, never silent.
    screened = Counter(credentials.get("screened") or {})
    for tool in tools:
        screened.update(tool.get("screened") or {})
    # No code and no value anywhere in the run (shared/masking.py): every snippet dropped, its identity pinned from it
    # first; every other text (a step's detail, an engine's error) rendered as text; and each value a secret engine
    # detected, read where it pointed, replaced wherever it shows, before anything stores, prints or sends it. Each finding declares first the units it lives in (its file; a
    # dependency's, its project: manifest and lockfile), which the registry compares with what each engine examined
    # (shared/coverage_units).
    for item in [*findings, *withheld]:
        coverage_units.declare(item)
    detected = secret_identity.values(root, [*findings, *withheld])
    for path, found in (credentials.get("values") or {}).items():  # the secrets-only copy is gone: read before it was
        detected.setdefault(path, set()).update(found)
    return sanitize_record({"type": "repository_scan",
            # Without Docker no engine ran: the internal rules aren't enough to call the repository reviewed.
            "status": "incomplete" if not engines or sca_status == "inconclusive" or truncated or misconfigured or any(
                tool["tool"] in REQUIRED_ENGINES and tool["status"] == "inconclusive" for tool in tools)
                # Allowlisted secrets not identified: one that stopped appearing may only be silenced.
                or any("withheld" in tool and tool["withheld"] is None for tool in tools) else "completed",
            "source": source, "target": source["name"], "variant": "code", "context": declared,
            "steps": steps, "findings": findings,
            "owasp_coverage": coverage, "inventory": collect_inventory(root), "unused_dependencies": unused_dependencies(root),
            # Versioned packages (from Trivy): the daily advisory watch checks them without rescanning.
            "dependencies": next((tool.get("packages") or [] for tool in tools if tool["tool"] == "trivy"), []),
            "summary": {"files": len(files), "dependencies": len(dependencies),
                                                    "candidates": len(findings), "sast": sast_count,
                                                    "secrets": secret_count, "sca": sum(item["scanner"] == "sca" for item in findings),
                                                    "severities": severities, "priorities": priorities,
                                                    "kev": sum(1 for item in findings if item.get("kev")),
                                                    "fixable": sum(1 for item in findings if (item.get("package") or {}).get("fixed_version")),
                                                    "iac": sum(item["scanner"] == "iac" for item in findings),
                                                    "cicd": sum(item["scanner"] == "cicd" for item in findings),
                                                    "tools": [{"name": tool["tool"], "version": tool["version"], "status": tool["status"],
                                                               **({"contract": tool["contract"]} if tool.get("contract") else {})} for tool in tools],
                                                    "planned": 3, "executed": 2 + (sca_status == "partial"),
                                                    "confirmed": 0},
            "limitations": ([msg("scanning.repository.limitations.truncated", files=snapshot.get("skipped_over_budget", 0))]
                            if snapshot.get("truncated") else [])
                           + [msg("scanning.repository.limitations.no_execution"),
                              msg("scanning.repository.limitations.sast_rules") if engines
                              else msg("scanning.repository.limitations.no_docker"),
                              msg("scanning.repository.limitations.sca_cap"), msg("scanning.repository.limitations.osv_not_exploit"),
                              msg("scanning.repository.limitations.no_ai_dast")]
                           + ([msg("scanning.secret_rules.withheld.limitation", count=secrets_withheld)] if (secrets_withheld := sum(
                               1 for item in withheld if item["scanner"] == "secrets" and not item.get("inline_allowed"))) else [])
                           + ([msg("scanning.secrets.inline.limitation", count=len(inline),
                                  places=", ".join(inline[:FOLDERS_SHOWN * 2]) + ("…" if len(inline) > FOLDERS_SHOWN * 2 else ""))]
                              if (inline := _inline_places([item for item in withheld if item["scanner"] == "secrets"])) else [])
                           + ([msg("scanning.repo_controls.limitation", count=len(controlled),
                                  places=", ".join(controlled[:FOLDERS_SHOWN * 2]) + ("…" if len(controlled) > FOLDERS_SHOWN * 2 else ""))]
                              if (controlled := _inline_places([item for item in withheld if item["scanner"] != "secrets"])) else [])
                           + ([msg("scanning.opengrep.silenced_limitation", count=silenced)] if (silenced := sum(
                               1 for item in withheld if item["scanner"] != "secrets" and not is_vendored(item)
                               and not item.get("inline_allowed"))) else [])
                           + ([msg("scanning.opengrep.vendored_limitation", count=in_vendored)] if (in_vendored := sum(
                               1 for item in withheld if is_vendored(item))) else [])
                           + ([msg("scanning.secret_filter.limitation", detail=screened_detail(screened))] if screened else [])
                           + ([msg("scanning.secrets.over_budget", count=over_budget)] if (over_budget := sum(
                               1 for item in [*findings, *withheld] if item.get("over_budget"))) else []),
            **({"excluded_findings": withheld} if withheld else {}),
            **({"unexamined": unexamined} if (unexamined := _unexamined(left_out, tools, credentials["unexamined"], apart)) else {}),
            **({"coverage": coverage} if (coverage := _with_inline(_coverage(left_out, tools, credentials["unexamined"], apart), withheld)) else {}),
            # Which engines and rules ran, so the registry never takes what a configuration change hid for a fix.
            **({"configuration": applied} if applied else {}),
            "scanned_at": datetime.now(timezone.utc).isoformat()}, detected)
