"""A fictional organization for screenshots and for trying every view: `pitangus demo --full`.

Lapis Labs (`lapis-labs`) is made up. The demo builds it entirely offline: five repositories with a month of scans, a
pull request review, a container image, a verified web domain under a reserved name (scope, weekly schedule, test user,
detected technologies, two passive scans), an unverified domain and two members. Nothing contacts anything: every
finding comes from engine outputs recorded against Pitangus's own vulnerable samples (`tests/fixtures`,
`tests/engine-outputs`), replayed through the same parsers, merges, registry and triage as a real scan; later scans
leave some of them out, so trends, fixes, MTTR and due dates have something to show. KEV and EPSS come from the feeds
already downloaded, if any.

Everything is marked: runs are requested by `demo` and their source carries `demo: true`, domains are registered by
`demo` (never verified or scanned for real: `sources.domains.is_demo`), members say "(demo)". Run ids are stable, so
running it again adds nothing. Slack and Jira are left out: saving them contacts their servers.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from pitangus.shared.i18n import is_msg, MARK, msg, t

ORG = "lapis-labs"
DEMO = "demo"
SOURCE_PREFIX = "local:demo/"
SCAN_HOUR = 9  # UTC hour of the day the demo scans "ran"
SHOP = "tienda.example.com"
SHOP_API = f"api.{SHOP}"
PENDING = "soporte.example.net"
IMAGE = f"registry.example.com/{ORG}/checkout-api:1.8.2"
MEMBERS = (("ana.demo", "Ana Morales (demo)"), ("tomas.demo", "Tomás Rivera (demo)"))
# Fraction of findings fixed along the month, and of findings that only show up in later scans.
FIXED_SHARE, LATE_SHARE = 0.22, 0.12


@dataclass(frozen=True)
class Repository:
    name: str
    files: tuple[str, ...]                   # sample files (fixtures/) in its snapshot
    days: tuple[int, ...]                    # days ago of each full scan, oldest first
    opengrep: tuple[str, ...] = ()           # files of tests/fixtures/opengrep.json it keeps
    gitleaks: bool = False
    trivy: tuple[tuple[str, tuple[str, ...]], ...] = ()  # (recorded output, targets kept; empty keeps all)
    osv: bool = False
    checkov: bool = False
    zizmor: bool = False
    pull: dict = field(default_factory=dict)  # a pull request that adds these files: {"number", "files", "days", "branch"}

    @property
    def full_name(self) -> str:
        return f"{ORG}/{self.name}"

    @property
    def source_id(self) -> str:
        return SOURCE_PREFIX + self.full_name


REPOSITORIES = (
    Repository("checkout-api", ("app.py", "config.py", "Dockerfile"), (29, 22, 15, 8, 2), opengrep=("app.py",), gitleaks=True,
               trivy=(("fixtures/trivy.json", ("Dockerfile", "config.py")), ("engine-outputs/trivy-deps.json", ()))),
    Repository("storefront-web", ("index.php", "app.js", "package.json", "package-lock.json"), (27, 20, 13, 6, 1),
               opengrep=("index.php", "app.js"), trivy=(("fixtures/trivy.json", ("package-lock.json",)),),
               pull={"number": 57, "files": ("component.jsx",), "days": 0, "branch": "feature/product-reviews"}),
    Repository("payments-service", ("App.cs", "App.java"), (26, 19, 12, 5), opengrep=("App.cs", "App.java"), osv=True),
    Repository("platform-infra", (), (24, 17, 10, 3), trivy=(("engine-outputs/trivy-iac.json", ()),), checkov=True, zizmor=True),
    Repository("fulfillment-worker", ("main.go", "app.rb"), (21, 14, 7), opengrep=("main.go", "app.rb")),
)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)


def run_id(*parts) -> str:
    """Stable per piece of demo data: running the demo again finds it and adds nothing."""
    return hashlib.sha256(":".join(["pitangus-demo", *map(str, parts)]).encode()).hexdigest()[:32]


def _moment(days: float, hour: int = SCAN_HOUR) -> datetime:
    """`days` ago at `hour` UTC, never later than an hour ago."""
    return min((_now() - timedelta(days=days)).replace(hour=hour), _now() - timedelta(hours=1))


def _share(finding: dict) -> float:
    return int(finding["fingerprint"][:8], 16) / 0x1_0000_0000


def present(finding: dict, index: int, scans: int) -> bool:
    """Whether a finding shows up in scan `index` of `scans`: most do in all of them; some are fixed along the way and
    some only appear later (stable per fingerprint)."""
    if scans < 2:
        return True
    share, steps = _share(finding), scans - 1
    if share < FIXED_SHARE:
        return index < 1 + int(share / FIXED_SHARE * steps)
    if share < FIXED_SHARE + LATE_SHARE:
        return index >= 1 + int((share - FIXED_SHARE) / LATE_SHARE * steps)
    return True


def _exists(data_dir: Path, identifier: str) -> bool:
    from pitangus.modules.runs.store import find_runs
    return bool(find_runs(data_dir, ids=[identifier], limit=1))


def _marked(record: dict) -> dict:
    return {**record, "source": {**record["source"], "demo": True}, "requested_by": DEMO,
            "limitations": [*record.get("limitations", []), msg("demo.limitation")]}


def _save(data_dir: Path, record: Any, identifier: str, moment: datetime, minutes: int = 4) -> Any:
    from pitangus.modules.runs.store import save_repository_scan
    record = {**_marked(record), "started_at": moment.isoformat(), "finished_at": (moment + timedelta(minutes=minutes)).isoformat(),
              "progress": []}
    return save_repository_scan(data_dir, record, run_id=identifier, created_at=moment.isoformat(), quiet=True)


# --- recorded engine outputs ------------------------------------------------------------------------------------


class Recordings:
    """The recorded engine outputs, read once."""

    def __init__(self, root: Path):
        self.root = root
        if not (root / "fixtures" / "opengrep.json").is_file() or not (root / "engine-outputs").is_dir():
            raise FileNotFoundError(t("cli.demo.no_recordings", path=str(root)))

    def json(self, name: str):
        return json.loads((self.root / name).read_text(encoding="utf-8"))

    def text(self, name: str, replacements: dict[str, str] | None = None) -> str:
        value = (self.root / "engine-outputs" / name).read_text(encoding="utf-8")
        for old, new in (replacements or {}).items():
            value = value.replace(old, new)
        return value


def _replayed(key: str, findings: list, **extra) -> dict:
    from pitangus.modules.scanning.engines import IMAGES
    meta = IMAGES[key]
    return {"tool": key, "name": meta["name"], "version": meta["version"], "image": meta["image"], "status": "completed",
            "detail": msg("demo.replayed", count=len(findings)), "findings": findings, "duration_s": None, **extra}


def _code_outputs(recordings: Recordings, repository: Repository, root: Path, feeds: dict, opengrep_files: tuple[str, ...]) -> dict:
    """Every finding each engine recorded for this repository, by engine, plus Trivy's package list."""
    from pitangus.modules.scanning.config_engines import parse_checkov, parse_zizmor
    from pitangus.modules.scanning.engines import parse_gitleaks, parse_opengrep, parse_osv_scanner, parse_trivy, trivy_packages
    opengrep = recordings.json("fixtures/opengrep.json")
    kept = {"results": [item for item in opengrep["results"] if Path(item["path"]).name in opengrep_files]}
    trivy: dict[str, list] = {"Results": []}
    for name, targets in repository.trivy:
        trivy["Results"] += [item for item in recordings.json(name).get("Results") or [] if not targets or item.get("Target") in targets]
    return {
        "opengrep": parse_opengrep(kept) if opengrep_files else [],
        "gitleaks": parse_gitleaks(recordings.json("fixtures/gitleaks.json"), None, root) if repository.gitleaks else [],
        "trivy": parse_trivy(trivy, feeds), "packages": trivy_packages(trivy),
        "osv-scanner": parse_osv_scanner(recordings.json("engine-outputs/osv-scanner.json"), feeds) if repository.osv else [],
        "checkov": parse_checkov(recordings.json("engine-outputs/checkov-repo.json")) if repository.checkov else [],
        "zizmor": parse_zizmor(recordings.json("engine-outputs/zizmor.json")) if repository.zizmor else [],
    }


def _engines(outputs: dict, keep) -> tuple:
    """Engines that answer with the recorded findings `keep` lets through, in the order of a real code scan."""
    from pitangus.modules.scanning.engines import EngineStep
    from pitangus.modules.scanning.repository import CODE_ENGINES

    def step(engine):
        def call(_context):
            found = [item for item in outputs[engine.key] if keep(item)]
            return _replayed(engine.key, found, **({"packages": outputs["packages"]} if engine.key == "trivy" else {}))
        return EngineStep(engine.key, call, engine.progress, required=engine.required, merged=engine.merged)
    return tuple(step(engine) for engine in CODE_ENGINES)


def _snapshot(fixtures: Path, files: tuple[str, ...], folder: Path) -> tuple[Path, dict]:
    from pitangus.modules.sources.repositories import snapshot_directory
    source, head = folder / "src", folder / "head"
    source.mkdir(parents=True)
    head.mkdir()
    for name in files:
        found = next((path for path in (fixtures / "sast-samples" / name, fixtures / "scanner-samples" / name) if path.is_file()), None)
        if found:
            shutil.copy2(found, source / name)
    return head, snapshot_directory(source, head)


def _code_scan(data_dir: Path, recordings: Recordings, fixtures: Path, repository: Repository, feeds: dict,
               files: tuple[str, ...], opengrep_files: tuple[str, ...], keep) -> Any:
    from pitangus.modules.scanning.repository import scan_repository
    with TemporaryDirectory(prefix="demo-", dir=data_dir / "work") as temporary:
        root, stats = _snapshot(fixtures, files, Path(temporary))
        outputs = _code_outputs(recordings, repository, root, feeds, opengrep_files)
        source = {"id": repository.source_id, "name": repository.full_name, "provider": "local", "branch": "main",
                  "files": stats["files"], "snapshot": stats}
        return scan_repository(root, source, context=t("demo.org.context"), data_dir=data_dir, replay=_engines(outputs, keep), feeds=feeds)


def seed_repositories(data_dir: Path, recordings: Recordings, fixtures: Path, feeds: dict) -> dict:
    """Each repository's month of full scans, oldest first (the registry is the film: order matters)."""
    created = {"runs": 0, "pull_requests": 0}
    for repository in REPOSITORIES:
        scans = len(repository.days)
        for index, days in enumerate(repository.days):
            identifier = run_id(repository.full_name, index)
            if _exists(data_dir, identifier):
                continue
            record = _code_scan(data_dir, recordings, fixtures, repository, feeds, repository.files, repository.opengrep,
                                lambda item, index=index, scans=scans: present(item, index, scans))
            _save(data_dir, record, identifier, _moment(days, SCAN_HOUR + REPOSITORIES.index(repository)))
            created["runs"] += 1
        if repository.pull:
            created["pull_requests"] += seed_pull_request(data_dir, recordings, fixtures, repository, feeds)
    return created


def seed_pull_request(data_dir: Path, recordings: Recordings, fixtures: Path, repository: Repository, feeds: dict) -> int:
    """A pull request review: the PR adds files, and what they bring is what it introduces (judged against the latest
    full scan, like a real review). Nothing is posted anywhere."""
    from pitangus.modules.pullrequests import review as pr_review
    from pitangus.modules.runs.store import load_run
    pull = repository.pull
    identifier = run_id(repository.full_name, "pr", pull["number"])
    if _exists(data_dir, identifier):
        return 0
    baseline = load_run(data_dir, run_id(repository.full_name, len(repository.days) - 1))
    scans = len(repository.days)
    scan = _code_scan(data_dir, recordings, fixtures, repository, feeds, repository.files + pull["files"],
                      repository.opengrep + pull["files"], lambda item: present(item, scans - 1, scans))
    changed = dict.fromkeys(pull["files"])
    outcome = pr_review.classify(scan["findings"], changed, {item["fingerprint"] for item in baseline["findings"]})
    verdict = pr_review.verdict(outcome["introduced"], "high")
    introduced: list[Any] = outcome["introduced"]
    summary = {**scan["summary"], "candidates": len(introduced),
               "severities": {level: sum(1 for item in introduced if item["severity"] == level) for level in ("critical", "high", "medium", "low", "info")},
               "priorities": {level: sum(1 for item in introduced if (item.get("priority") or {}).get("action") == level) for level in ("act", "attend", "track")},
               "kev": sum(1 for item in introduced if item.get("kev")),
               "fixable": sum(1 for item in introduced if (item.get("package") or {}).get("fixed_version")),
               "preexisting": len(outcome["preexisting"]), "changed_files": len(changed)}
    head_sha = hashlib.sha1(identifier.encode()).hexdigest()
    request = {"number": pull["number"], "title": t("demo.pull.title"), "url": None, "author": MEMBERS[0][0], "head_sha": head_sha,
               "head_ref": pull["branch"], "base_ref": "main"}
    not_posted = msg("demo.pull.not_posted")
    record = {**scan, "type": "pr_review", "target": f"{repository.full_name}#{pull['number']}", "variant": "pull_request",
              "pull_request": request, "findings": introduced, "summary": summary,
              "unused_dependencies": {"new": [], "before": [], "ecosystems": []},
              "review": {"baseline_run": baseline["id"], "verdict": verdict, "delivery": {"comment": not_posted, "status": not_posted},
                         "gate": "high"}}
    _save(data_dir, record, identifier, _moment(pull["days"], SCAN_HOUR + 5), minutes=3)
    return 1


# --- container image --------------------------------------------------------------------------------------------


def seed_image(data_dir: Path, recordings: Recordings, feeds: dict) -> int:
    """checkout-api's image: its packages and configuration come from Trivy's recorded output, its build history and
    Checkov's verdict on it from theirs. No Grype output was recorded, so the analysis says it is incomplete."""
    from pitangus.modules.scanning.config_engines import dockerfile_from_history, parse_checkov
    from pitangus.modules.scanning.engines import parse_trivy, trivy_packages
    from pitangus.modules.scanning.image import parse_reference, scan_image
    identifier = run_id("image", IMAGE)
    if _exists(data_dir, identifier):
        return 0
    image = parse_reference(IMAGE)
    history = recordings.json("engine-outputs/image-history.json")
    exposed: dict[str, dict] = {port: {} for step in history if step.startswith("EXPOSE") for port in ("22/tcp", "8080/tcp") if port in step}
    metadata: dict[str, Any] = {"ImageConfig": {"history": [{"created_by": step} for step in history], "architecture": "amd64",
                                "config": {"User": "root", "ExposedPorts": exposed}}}
    payload = {"Results": [item for item in recordings.json("fixtures/trivy.json").get("Results") or [] if item.get("Class") == "lang-pkgs"]}
    findings = parse_trivy(payload, feeds)
    trivy = {**_replayed("trivy", findings), "packages": trivy_packages(payload), "system_packages": []}
    _, step_of = dockerfile_from_history(history, metadata["ImageConfig"]["config"])
    checkov = _replayed("checkov", parse_checkov(recordings.json("engine-outputs/checkov-image.json"), image=image, step_of=step_of))
    from pitangus.modules.scanning.engines import IMAGES
    grype: dict[str, Any] = {"tool": "grype", "name": IMAGES["grype"]["name"], "version": IMAGES["grype"]["version"], "image": IMAGES["grype"]["image"],
             "status": "not_tested", "detail": msg("demo.no_grype"), "findings": [], "duration_s": None}
    record = scan_image(image, data_dir=data_dir, context=t("demo.org.image_context"), replay={"trivy": (trivy, metadata), "grype": grype,
                                                                                                "checkov": checkov}, feeds=feeds)
    _save(data_dir, record, identifier, _moment(9, SCAN_HOUR + 6), minutes=6)
    return 1


# --- web domains ------------------------------------------------------------------------------------------------

# The recorded web outputs name the sites they were recorded against; the demo moves them to its reserved names and
# documentation addresses (RFC 5737).
WEB_NAMES = {"edge.pitangus.test": SHOP_API, "app.example.com": SHOP_API, "pitangus.dev": SHOP,
             "192.168.215.4": "203.0.113.20", "172.67.153.40": "203.0.113.10"}
WEB_SCANS = ((18, (SHOP,)), (4, (SHOP, SHOP_API)))  # days ago, hosts in scope


def _web_scan(recordings: Recordings, domain: dict, hosts: tuple[str, ...], index: int) -> dict:
    """A passive scan built from ZAP, nuclei, testssl.sh, katana and httpx outputs recorded against real sites, moved
    to the demo's hosts. Same parsers and merge as `scanning.web.scan_domain`; the second scan leaves some of the
    first one's findings out (fixed) and adds the API host."""
    from pitangus.modules.scanning import web_merge, web_seeds, web_tools
    from pitangus.modules.scanning.engines import IMAGES
    from pitangus.modules.scanning.web import coverage_key, findings_from, start_url
    from pitangus.modules.sources import domains
    names = list(hosts)
    scope = {"hosts": names, "wildcards": []}
    url = start_url(domain)
    keep = (lambda item: present(item, index, len(WEB_SCANS)))

    def recorded(name: str) -> str:
        return recordings.text(name, WEB_NAMES)

    zap = [item for item in findings_from(json.loads(recorded("zap-2.17.sarif")), domain["host"], scope=scope)[0] if keep(item)]
    if SHOP_API in names:
        zap += findings_from(json.loads(recorded("zap.sarif")), domain["host"], scope=scope)[0]
    for finding in zap:
        remediation = finding.get("remediation")
        if is_msg(remediation) and remediation[MARK] == "scanning.sarif.remediation":
            finding["remediation"] = msg("scanning.web.remediation", tool=finding["tool"])
    nuclei, detected = web_tools.parse_nuclei(recorded("nuclei-3.11.jsonl"), names)
    tls = web_tools.parse_testssl(json.loads(recorded("testssl-3.2.json")), SHOP)
    if SHOP_API in names:
        more, found = web_tools.parse_nuclei(recorded("nuclei-3.11-edge.jsonl"), names)
        nuclei, detected = nuclei + more, detected + found
        tls += web_tools.parse_testssl(json.loads(recorded("testssl-3.2-edge.json")), SHOP_API)
    nuclei, tls = [item for item in nuclei if keep(item)], [item for item in tls if keep(item)]
    exposed = web_tools.parse_httpx(recorded("httpx-1.12.jsonl"), names)
    katana = web_tools.parse_katana(recorded("katana-1.7.jsonl") + "\n" + (recorded("katana-1.7-edge.jsonl") if SHOP_API in names else ""), names)
    inventory, counts = web_seeds.merge({"katana": katana, "zap": web_seeds.zap_urls(recorded("zap-2.17-urls.txt"), names)})
    runs = {"katana": web_tools.ToolRun("katana", "completed", msg("demo.replayed", count=len(katana))),
            "nuclei": web_tools.ToolRun("nuclei", "completed", msg("demo.replayed", count=len(nuclei)), findings=nuclei),
            "testssl": web_tools.ToolRun("testssl", "completed", msg("demo.replayed", count=len(tls)), findings=tls),
            "httpx": web_tools.ToolRun("httpx", "completed", msg("demo.replayed", count=len(exposed)))}
    findings, folded = web_merge.merge([*zap, *nuclei, *tls])
    coverage = coverage_key(None, [])
    for finding in findings:
        finding.setdefault("web", {})["coverage"] = coverage
    meta = IMAGES["zap"]
    severities = {level: sum(1 for item in findings if item["severity"] == level) for level in ("critical", "high", "medium", "low", "info")}
    steps = [runs["katana"].step(),
             {"id": "dast", "name": msg("scanning.web.steps.passive.name"), "status": "completed",
              "detail": msg("demo.replayed", count=len(zap)),
              "tool": {"name": "zap", "version": meta["version"], "image": meta["image"], "duration_s": None}},
             {"id": "dast-inventory", "name": msg("scanning.web.steps.inventory.name"), "status": "completed",
              "detail": msg("scanning.web.steps.inventory.detail", count=len(inventory), katana=counts.get("katana", 0), robots=0, sitemap=0,
                            zap=counts.get("zap", 0), openapi=0)},
             *(runs[key].step() for key in ("nuclei", "testssl", "httpx")),
             {"id": "dast-merge", "name": msg("scanning.web.steps.merge.name"), "status": "completed",
              "detail": msg("scanning.web.steps.merge.detail", count=folded) if folded else msg("scanning.web.steps.merge.none")},
             {"id": "active", "name": msg("scanning.web.steps.active.name"), "status": "not_tested", "detail": msg("scanning.web.steps.active.detail")},
             {"id": "review", "name": msg("scanning.steps.review"), "status": "pending", "detail": msg("scanning.web.steps.review.detail")}]
    from pitangus.modules.scanning.web import AJAX_MINUTES, SPIDER_MINUTES
    return {"type": "dast_scan", "status": "completed", "logins": [], "source": domains.source_for(domain), "target": url, "variant": "baseline",
            "context": "", "scope": {"hosts": names, "wildcards": [], "headers": [], "test_users": [], "coverage": coverage},
            "steps": steps, "findings": findings, "owasp_coverage": [],
            "limitations": [msg("scanning.web.limitations.passive"), msg("scanning.web.limitations.unauthenticated"),
                            msg("scanning.web.limitations.spider", minutes=SPIDER_MINUTES), msg("scanning.web.limitations.ajax", minutes=AJAX_MINUTES),
                            msg("scanning.web.limitations.nuclei"), msg("scanning.web.limitations.not_pentest")],
            "summary": {"files": len({item["path"] for item in findings}), "dependencies": 0, "candidates": len(findings), "sast": 0, "secrets": 0,
                        "sca": 0, "iac": 0, "cicd": 0, "dast": len(findings), "severities": severities,
                        "priorities": {action: sum(1 for item in findings if item["priority"]["action"] == action) for action in ("act", "attend", "track")},
                        "kev": 0, "fixable": 0,
                        "tools": [{"name": "ZAP", "version": meta["version"], "status": "completed"},
                                  *({"name": key, "version": IMAGES[key]["version"], "status": "completed"} for key in runs)],
                        "technologies": web_tools.technologies_of(detected, exposed)},
            "web_inventory": {"sources": counts, "count": len(inventory), "urls": inventory}}


def seed_domains(data_dir: Path, recordings: Recordings) -> dict:
    """The shop's verified domain with everything around it, and a second domain still waiting for its proof."""
    from pitangus.modules.sources import domain_scope, domains, test_users
    created = {"domains": 0, "web_runs": 0}
    shop = domains.find_domain(data_dir, SHOP)
    if shop is None:
        shop = domains.register_domain(data_dir, f"https://{SHOP}/", "web", t("demo.org.domain_context"), by=domains.DEMO_BY)
        created["domains"] += 1
    if not domains.is_demo(shop):
        return created  # someone registered that name by hand: it isn't the demo's to fill
    if not shop["verified_at"]:
        shop = domains.vouch_demo(data_dir, shop["id"], at=_moment(25))
        discovered = [SHOP_API, f"static.{SHOP}", f"staging.{SHOP}"]
        domain_scope.discovery_finished(data_dir, shop["id"], discovered, {"found": len(discovered), "kept": len(discovered), "private": 0,
                                                                            "unresolved": 0}, now=_moment(24))
        for host in (SHOP_API, f"static.{SHOP}"):
            domain_scope.set_state(data_dir, shop["id"], host, "in_scope", by=DEMO)
    if not test_users.list_users(data_dir, shop["id"]):
        # A made-up account with a random password, sealed like any other; nothing ever signs in with it.
        test_users.save(data_dir, shop, {"method": "password", "name": t("demo.test_user.name"), "username": f"shopper@{SHOP}",
                                         "password": secrets.token_urlsafe(18), "login_url": f"https://{SHOP}/login",
                                         "notes": t("demo.test_user.notes")}, by=DEMO)
    if not shop["schedule"]:
        users = [user["id"] for user in test_users.list_users(data_dir, shop["id"])][:1]
        domains.set_schedule(data_dir, shop["id"], {"frequency": "weekly", "weekdays": [1], "time": "09:00", "timezone": "America/Bogota",
                                                    "test_users": users, "use_headers": False})
    for index, (days, hosts) in enumerate(WEB_SCANS):
        identifier = run_id("web", SHOP, index)
        if _exists(data_dir, identifier):
            continue
        _save(data_dir, _web_scan(recordings, domains.get_domain(data_dir, shop["id"]), hosts, index), identifier,
              _moment(days, SCAN_HOUR + 3), minutes=22)
        created["web_runs"] += 1
    if domains.find_domain(data_dir, PENDING) is None:
        domains.register_domain(data_dir, f"https://{PENDING}/", "web", t("demo.org.pending_context"), by=domains.DEMO_BY)
        created["domains"] += 1
    return created


# --- people and decisions ---------------------------------------------------------------------------------------


def seed_members(data_dir: Path) -> int | None:
    """Two members invited without a password (they can't sign in). None when there is no administrator yet: the
    first account must be the one who installs Pitangus."""
    from pitangus.modules.identity.auth import Users
    users = Users(data_dir)
    if not any(user["role"] == "admin" for user in users.list()):
        return None
    created = 0
    for username, name in MEMBERS:
        if users.get(username) is None:
            users.create(username, None, role="member", display_name=name)
            created += 1
    return created


def _admin(data_dir: Path) -> str:
    from pitangus.modules.identity.auth import Users
    return next((user["username"] for user in Users(data_dir).list() if user["role"] == "admin"), DEMO)


TRIAGE = (  # repository, rule id fragment, decision, by (None: an administrator), days until the acceptance expires
    ("checkout-api", "flask-debug-true", "false_positive", MEMBERS[0][0], None),
    ("payments-service", "weak-cipher", "accepted", None, 60),
    ("fulfillment-worker", "sql-string-building", "in_progress", MEMBERS[1][0], None),
)


def seed_triage(data_dir: Path) -> int:
    """A few decisions, as people would make them: a false positive, an accepted risk and work in progress."""
    from pitangus.modules.findings import registry, triage
    decided = 0
    for name, rule, status, by, expires in TRIAGE:
        key = SOURCE_PREFIX + f"{ORG}/{name}"
        state: Any = registry.view(data_dir, key, status="open")
        chosen = next((item for item in state["findings"] if rule in item["rule_id"]), None)
        if chosen is None or chosen["fingerprint"] in triage.load_asset(data_dir, key):
            continue
        expiry = (_now() + timedelta(days=expires)).date().isoformat() if expires else None
        triage.decide(data_dir, state, [chosen["fingerprint"]], status, reason=t(f"demo.triage.{status}"), expires_at=expiry,
                      user={"username": by or _admin(data_dir), "role": "admin"})
        decided += 1
    return decided


def seed(data_dir: Path, *, fixtures: Path, recordings: Path, report=print) -> dict:
    """The whole organization; each piece is skipped when it is already there."""
    from pitangus.modules.intel.advisories import cached_feeds
    (data_dir / "work").mkdir(parents=True, exist_ok=True)
    recorded = Recordings(recordings)
    feeds = cached_feeds(data_dir)
    result: dict[str, Any] = {"repositories": seed_repositories(data_dir, recorded, fixtures, feeds)}
    report(t("cli.demo.full_repositories", count=len(REPOSITORIES), runs=result["repositories"]["runs"],
             reviews=result["repositories"]["pull_requests"]))
    result["image"] = seed_image(data_dir, recorded, feeds)
    report(t("cli.demo.full_image", reference=IMAGE))
    result["domains"] = seed_domains(data_dir, recorded)
    report(t("cli.demo.full_domains", verified=SHOP, pending=PENDING))
    result["members"] = seed_members(data_dir)
    report(t("cli.demo.full_members_skipped") if result["members"] is None else t("cli.demo.full_members", count=len(MEMBERS)))
    result["triage"] = seed_triage(data_dir)
    if not feeds.get("kev") and not feeds.get("epss"):
        report(t("cli.demo.full_no_feeds"))
    report(t("cli.demo.full_integrations"))
    return result
