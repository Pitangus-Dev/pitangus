"""Known vulnerabilities of the versions a site shows: what httpx names with a version (Flask 2.2.3, jQuery 3.4.1),
looked up in the OSV advisory databases Pitangus already keeps for dependency scans.

Only products in `PRODUCTS` are looked up: each maps to one package whose advisories describe that product (Flask →
PyPI `flask`). A name httpx guesses for something else, or a version that isn't at least `major.minor`, is left alone.
Web servers and runtimes (Apache httpd, nginx, OpenSSL, PHP, IIS…) aren't packages in OSV, and the local copy of NVD
(`intel_cves`) keeps no CPE ranges, so there is nothing local to match them against: they are listed as not looked up.

The lookup is OSV-Scanner offline on a CycloneDX SBOM of those packages, exactly as the daily advisory watch does: the
databases are downloaded (or reused from `data/osv-cache`), the package list never leaves this machine. Nothing
reaches the scanned site.

A version read from a response isn't proof: a header can lie, a CDN can rewrite it, a backport can fix a version that
still says otherwise. Each finding says so, with a lower confidence, and its remediation is the advisory's own fixed
version and references, never an invented one.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import time
from pathlib import Path

from pitangus.modules.intel import cve_db
from pitangus.modules.intel.advisories import compare_versions
from pitangus.modules.scanning import engines
from pitangus.modules.scanning.dependency_merge import purl
from pitangus.modules.scanning.engines import _stable, joined
from pitangus.shared.i18n import msg
from pitangus.shared.model import Finding

TOOL = "httpx + OSV"
KEY = "osv-scanner"
STEP = "dast-versions"
TIMEOUT = 10 * 60          # a lookup takes seconds once OSV's databases are downloaded (data/osv-cache)
CONFIDENCE = 5
ADVISORIES_MAX = 30       # listed in a finding's evidence
REFERENCES_MAX = 8
# What httpx calls a product (lowercase) → the OSV ecosystem and package whose advisories are that product's.
PRODUCTS: dict[str, tuple[str, str]] = {
    # Python
    "flask": ("PyPI", "flask"), "django": ("PyPI", "django"), "werkzeug": ("PyPI", "werkzeug"), "tornado": ("PyPI", "tornado"),
    "gunicorn": ("PyPI", "gunicorn"), "aiohttp": ("PyPI", "aiohttp"),
    # JavaScript, on the server or in the page
    "express": ("npm", "express"), "next.js": ("npm", "next"), "nuxt.js": ("npm", "nuxt"),
    "jquery": ("npm", "jquery"), "jquery ui": ("npm", "jquery-ui"), "jquery migrate": ("npm", "jquery-migrate"),
    "bootstrap": ("npm", "bootstrap"), "angularjs": ("npm", "angular"), "lodash": ("npm", "lodash"), "moment.js": ("npm", "moment"),
    "underscore.js": ("npm", "underscore"), "handlebars": ("npm", "handlebars"), "dompurify": ("npm", "dompurify"),
    "vue.js": ("npm", "vue"), "react": ("npm", "react"), "axios": ("npm", "axios"),
}
# Products httpx often names with a version that OSV has no package for: said, not looked up.
NOT_PACKAGES = frozenset({"apache http server", "apache", "nginx", "openresty", "openssl", "php", "iis", "microsoft-iis",
                          "litespeed", "tomcat", "apache tomcat", "jetty", "caddy", "envoy", "varnish", "openssh", "lighttpd"})
VERSION = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}(?:\.[0-9]{1,6}){0,2}")
RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
ACTIONS = {"act": 2, "attend": 1, "track": 0}
ZAP_JS_LIBRARIES = "10003"   # ZAP's (retire.js) vulnerable JavaScript library rule


def readiness():
    """None if OSV-Scanner can run here, else why not (the step says so and the scan goes on without it)."""
    if problem := engines.unavailable(KEY, engines.docker_problem() or None):
        return problem
    if engines.runner() == "local" or engines.image_available(KEY):
        return None
    return msg("scanning.web.tools.image_missing", tool=engines.IMAGES[KEY]["name"])


def candidates(detected: list[dict]) -> tuple[list[dict], list[str]]:
    """The products to look up ({product, ecosystem, name, version, hosts}) and those with a version that can't be
    ("nginx 1.27.5"), from httpx's rows ({name, version, host})."""
    found: dict[tuple[str, str, str], dict] = {}
    skipped: set[str] = set()
    for item in detected:
        product = " ".join(str(item.get("name") or "").split())
        version = str(item.get("version") or "")
        key = product.lower()
        if not product or not VERSION.fullmatch(version):
            continue
        if key in PRODUCTS:
            ecosystem, name = PRODUCTS[key]
            entry = found.setdefault((ecosystem, name, version), {"product": product, "ecosystem": ecosystem, "name": name,
                                                                  "version": version, "hosts": set()})
            entry["hosts"].add(str(item.get("host") or ""))
        elif key in NOT_PACKAGES:
            skipped.add(f"{product} {version}")
    rows = [{**entry, "hosts": sorted(host for host in entry["hosts"] if host)} for entry in found.values()]
    return sorted(rows, key=lambda row: (row["name"], row["version"])), sorted(skipped)


def sbom(packages: list[dict]) -> dict:
    components = [{"type": "library", "name": item["name"], "version": item["version"], "purl": reference}
                  for item in packages if (reference := purl(item))]
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components}


def lookup(packages: list[dict], data_dir: Path, *, run=None) -> dict | None:
    """OSV-Scanner's JSON for those packages, offline; None if it couldn't run."""
    document = sbom(packages)
    if not document["components"]:
        return {"results": []}
    work = data_dir / "work"
    work.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="web-versions-", dir=work) as folder:
        root = Path(folder)
        (root / "bom.cdx.json").write_text(json.dumps(document), encoding="utf-8")
        cache_dir = engines.writable_cache(data_dir / "osv-cache")
        arguments = ["scan", "source", "-L", "/src/bom.cdx.json", "--format", "json", "--offline-vulnerabilities",
                     "--download-offline-databases", "--no-resolve"]
        try:
            completed = (run or engines._run)("osv-scanner", arguments, root, network=True, timeout=TIMEOUT,
                                              env={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/cache"},
                                              mounts=["-v", f"{engines.host_path(cache_dir)}:/cache"])
        except (subprocess.TimeoutExpired, OSError, ValueError):
            return None
    # 0: no advisories · 1: advisories. Any other code is an engine error.
    if completed.returncode not in (0, 1):
        return None
    if not (completed.stdout or "").strip():
        return {"results": []}
    try:
        payload = json.loads(completed.stdout)
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def _seen_by_zap(package: dict, zap: list[Finding]) -> bool:
    """ZAP's vulnerable JavaScript library rule already reported this library at this version."""
    if package["ecosystem"] != "npm":
        return False
    version = re.compile(rf"(?<![0-9.]){re.escape(package['version'])}(?![0-9])")
    names = {package["name"], package["product"].lower(), package["name"].replace("-", " ")}
    for finding in zap:
        if not str(finding.get("rule_id") or "").startswith(ZAP_JS_LIBRARIES) or "zap" not in str(finding.get("tool") or "").lower():
            continue
        said = json.dumps([finding.get("path"), finding.get("title"), finding.get("reason"), finding.get("web")], default=str).lower()
        if version.search(said) and any(name in said for name in names):
            return True
    return False


def _highest(versions: list[str]) -> str | None:
    found = None
    for version in versions:
        if found is None or compare_versions(version, found) > 0:
            found = version
    return found


def findings_from(packages: list[dict], advisories: list[Finding]) -> list[Finding]:
    """One finding per product and version with advisories: every CVE, the worst severity, the version that closes
    them all (when each has a fix) and the advisories' references."""
    by_package: dict[tuple[str, str], list[Finding]] = {}
    for advisory in advisories:
        affected = advisory.get("package") or {}
        by_package.setdefault((str(affected.get("name") or "").lower(), str(affected.get("version") or "")), []).append(advisory)
    findings: list[Finding] = []
    for package in packages:
        found = sorted(by_package.get((package["name"].lower(), package["version"])) or [],
                       key=lambda item: (-RANK.get(item.get("severity"), 0), str(item.get("rule_id"))))
        if not found:
            continue
        severity = found[0]["severity"]
        fixes = [str((item.get("package") or {}).get("fixed_version") or "") for item in found]
        unfixed = sum(1 for fix in fixes if not fix)
        fixed = _highest([fix for fix in fixes if fix])
        cves = sorted({cve for item in found for cve in item.get("cve") or []})
        ghsas = sorted({ghsa for item in found for ghsa in item.get("ghsa") or []})
        references: list[str] = []
        for item in found:
            for url in (item.get("advisory") or {}).get("references") or []:
                if url not in references and len(references) < REFERENCES_MAX:
                    references.append(url)
        # Language-neutral: identifiers, CVSS severity label and the fixed version as OSV publishes them.
        evidence = "; ".join(
            " ".join([str(item.get("rule_id")), *(f"({cve})" for cve in (item.get("cve") or [])[:3]), str(item.get("severity")).upper(),
                      *([f"→ {(item.get('package') or {}).get('fixed_version')}"] if (item.get("package") or {}).get("fixed_version") else [])])
            for item in found[:ADVISORIES_MAX])
        priority = max((item.get("priority") or {"action": "track", "factors": []} for item in found),
                       key=lambda value: ACTIONS.get(value.get("action"), 0))
        kev = next((item.get("kev") for item in found if item.get("kev")), None)
        probabilities = [value for item in found if (value := item.get("epss"))]
        hosts = package["hosts"] or [""]
        path = f"https://{hosts[0]}/"
        product, version = package["product"], package["version"]
        if fixed and not unfixed:
            remediation = msg("scanning.web.versions.remediation", product=product, version=version, fixed=fixed)
        elif fixed:
            remediation = msg("scanning.web.versions.remediation_partial", product=product, version=version, fixed=fixed, count=unfixed)
        else:
            remediation = msg("scanning.web.versions.no_fix", product=product, version=version)
        digest = _stable("dast", "versions", package["ecosystem"].lower(), package["name"].lower(), version)
        findings.append({
            "finding_id": digest[:16], "fingerprint": digest, "scanner": "dast", "tool": TOOL,
            "rule_id": f"exposed-version:{package['ecosystem'].lower()}/{package['name']}",
            "title": msg("scanning.web.versions.title", product=product, version=version), "path": path, "line": 1,
            "severity": severity, "confidence": CONFIDENCE, "verdict": "candidate", "cwe": [1395], "owasp": ["A03:2025"],
            "cve": cves, "ghsa": ghsas,
            "package": {"ecosystem": package["ecosystem"], "name": package["name"], "version": version, "fixed_version": fixed,
                        "introduced": None},
            "advisory": None, "kev": kev, "epss": max(probabilities, key=lambda value: value["score"], default=None),
            "priority": {"action": priority.get("action", "track"),
                         "factors": [msg("scanning.web.versions.factor"), *(priority.get("factors") or [])]},
            "reason": msg("scanning.web.versions.reason", product=product, version=version, hosts=", ".join(package["hosts"]),
                          count=len(found), ids=", ".join(cves or [str(item.get("rule_id")) for item in found][:ADVISORIES_MAX])),
            "remediation": remediation,
            "web": {"method": "GET", "evidence": evidence[:2000], **({"references": references} if references else {})},
        })
    return findings


def check(detected: list[dict], data_dir: Path, zap: list[Finding], *, ready, run=None, signals=None) -> tuple[dict, list[Finding], str]:
    """The step and the findings for httpx's detections; also the tool's status for the run's summary
    (`completed` or `inconclusive`). `ready`: None if OSV-Scanner can run here, else why not. KEV and EPSS come
    from the local copy (`cve_db.signals`): nothing is downloaded for them."""
    started = time.time()
    packages, servers = candidates(detected)
    note = [msg("scanning.web.versions.not_looked_up", products=", ".join(servers))] if servers else []

    def step(status: str, detail) -> dict:
        return {"id": STEP, "name": msg("scanning.web.versions.name"), "status": status,
                "detail": joined([detail, *note], "scanning.join.sentences"),
                "tool": {"name": "osv-scanner", "version": engines.IMAGES["osv-scanner"]["version"],
                         "image": engines.IMAGES["osv-scanner"]["image"], "duration_s": round(time.time() - started, 1)}}

    if not packages:
        return step("completed", msg("scanning.web.versions.none")), [], "completed"
    if ready is not None:
        return step("skipped", ready), [], "inconclusive"
    payload = lookup(packages, data_dir, run=run)
    if payload is None:
        return step("partial", msg("scanning.web.versions.failed")), [], "inconclusive"
    cves = {cve for finding in engines.parse_osv_scanner(payload, {}) for cve in finding.get("cve") or []}
    feeds = (signals or (lambda identifiers: cve_db.signals(data_dir, identifiers)))(cves)
    findings = []
    for finding in findings_from(packages, engines.parse_osv_scanner(payload, feeds)):
        affected = finding.get("package") or {}
        package = next(item for item in packages if (item["name"], item["version"]) == (affected.get("name"), affected.get("version")))
        if not _seen_by_zap(package, zap):
            findings.append(finding)
    names = ", ".join(f"{item['product']} {item['version']}" for item in packages)
    return step("completed", msg("scanning.web.versions.detail", count=len(findings), products=names)), findings, "completed"
