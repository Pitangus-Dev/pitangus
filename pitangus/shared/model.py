"""The shapes the domain passes around: a finding, an engine's result and a run record.

They are TypedDicts over the plain dicts the code has always used, and that the database stores as JSONB: they give
readers and mypy names and types, never a conversion. `Required` marks what every reader relies on; the rest may be
missing (older runs, other engines).
"""

from __future__ import annotations

from typing import Any, Required, TypedDict

# Plain text, or an i18n message ({"$t": key, ...}) rendered in each reader's language (shared/i18n).
Message = str | dict[str, Any]


class DependencyPath(TypedDict, total=False):
    """Who requires a transitive package, from the graph Trivy resolves out of the lockfile (scanning/dependency_graph.py)."""
    name: str                  # the package that requires it
    version: str
    direct: str                # the direct dependency at the top of the chain: what the project can update
    direct_version: str
    chain: list[str]           # from the direct dependency down to `name`
    requires: str              # the range `name` declares for the package, when the lockfile keeps it (declared_ranges.py)
    direct_requires: str       # the range the project's manifest declares for `direct`, when known
    direct_dev: bool


class Package(TypedDict, total=False):
    ecosystem: str
    name: str
    version: str
    fixed_version: str | None
    introduced: str | None
    dev: bool
    direct: bool | None
    introduced_by: list[DependencyPath]  # transitive only: those whose range rejects the fix first, then the shortest chains
    introduced_by_more: bool             # more packages bring it in than `introduced_by` lists
    also_in: list[str]         # other files with the same version (a monorepo's lockfiles): one finding, several places


class Advisory(TypedDict, total=False):
    id: str
    aliases: list[str]
    summary: Message
    details: str
    cvss_vector: str | None
    cvss_score: float | None
    published: str | None
    modified: str | None
    references: list[str]


class Priority(TypedDict, total=False):
    action: Required[str]  # act · attend · track
    factors: list[Message]


class Finding(TypedDict, total=False):
    finding_id: Required[str]
    fingerprint: Required[str]
    previous_fingerprint: str  # the former formula's, so the registry carries state over (findings/identity.py)
    previous_fingerprints: list[str]  # others it was known by: an earlier formula, a report folded into this one
    family: str               # its fingerprint without the copy's order, shared by identical copies (findings/identity.py)
    identity: str             # its canonical identity: what the problem is, whichever engine (findings/canonical.py)
    value_formers: list[str]  # a secret named by its value: the only names it had (another key, an earlier formula)
    identity_version: int
    count: int                # how many places a family is in (PITANGUS_IDENTITY_MODE=v2)
    instances: list[dict[str, Any]]
    snippet: str              # the matched code an adapter hands over for its identity; dropped before storing (masking.CODE)
    resource: str             # the configured resource's address, when the engine gives one
    also_at: list[dict[str, Any]]  # other places the same report is in, before canonical grouping
    validation: str           # a secret its provider says is active, revoked or unknown (PITANGUS_SECRET_VALIDATION)
    span: list[int]           # where a secret's value is (line, start, end line, end; 0-based columns): never the value
    over_budget: bool         # a secret not looked for: secret_location's budget ran out, so it is unlinkable
    scanner: Required[str]     # sast · secrets · sca · iac · cicd · image-config · dast (imported from a web scanner)
    tool: str
    rule_id: Required[str]
    title: Message
    path: Required[str]
    # The coverage units it lives in (shared/coverage_units): its file, or a dependency's project (manifest + lockfile)
    units: list[str]
    line: int
    severity: Required[str]    # critical · high · medium · low · info
    confidence: int
    verdict: str
    cwe: list[int]
    owasp: list[str]
    cve: list[str]
    ghsa: list[str]
    package: Package | None
    advisory: Advisory | None
    kev: dict[str, Any] | None
    epss: dict[str, Any] | None
    source: dict[str, Any] | None
    web: dict[str, Any]       # a dynamic finding's method, parameter and bounded evidence; never headers or cookies
    priority: Priority
    reason: Message
    remediation: Message
    also_detected_by: list[str]
    related_rules: list[str]   # equivalent rules of the engines that also reported it
    malicious: bool
    excluded_by: str | None
    excluded_reason: Message | None
    # Added when a run is served, never stored with it.
    triage: dict[str, Any]
    ticket: dict[str, Any]
    fix: dict[str, Any]
    lifecycle: dict[str, Any]
    verification: dict[str, Any]
    guidance: list[dict[str, Any]]  # OWASP pages for it (findings/references.py)


class EngineResult(TypedDict, total=False):
    tool: Required[str]
    name: str
    version: str
    image: str | None          # None: built into Pitangus (the policy reader)
    status: Required[str]      # completed · inconclusive · not_tested
    detail: Message
    findings: list[Finding]
    duration_s: float | None
    packages: list[dict[str, Any]]
    system_packages: list[dict[str, Any]]
    withheld: list[Finding] | None
    graph: dict[str, Any]      # Trivy only: the lockfiles' dependency graphs, used during the scan, never stored
    coverage: dict[str, Any]   # what it examined and what not, and why (engine_contract.coverage)
    contract: dict[str, Any]   # the engine contract's verdict (engine_contract.recorded)
    disabled: bool             # an optional engine the operator didn't turn on
    screened: dict[str, int]   # secret engines: matches set aside as not secrets, by reason (secret_filter.REASONS)


class RunRecord(TypedDict, total=False):
    schema_version: str
    id: str
    type: Required[str]        # repository_scan · image_scan · pr_review · advisory_watch · …
    status: str                # queued · running · completed · incomplete · failed
    created_at: str
    started_at: str
    finished_at: str
    requested_by: str
    source: dict[str, Any]
    target: str
    variant: str
    context: str
    trigger: dict[str, Any]
    pull_request: dict[str, Any]
    review: dict[str, Any]
    scope: dict[str, Any]      # dast_scan: hosts, wildcards, header names (never values) and coverage key
    api: dict[str, Any]        # dast_scan in API mode: the definition's SHA-256, operations and source
    logins: list[dict[str, Any]]  # dast_scan with test users: each one's sign-in check (name, status, reason)
    steps: list[dict[str, Any]]
    findings: list[Finding]
    excluded_findings: list[Finding]
    # Code scans: files it didn't analyze, for the registry ("*": left out of the snapshot; an engine: skipped by it;
    # "engine:scanner": skipped by that scanner of the engine only)
    unexamined: dict[str, list[str]]
    # What each engine examined, by unit (engine_contract.coverage): {engine: {"examined": "*" | [...], "unexamined": {unit: why},
    # "by_scanner": {scanner: {unit: why}}}}
    coverage: dict[str, dict[str, Any]]
    # Which engines were on and which rules each applied (scanning/rule_set): {"engines": {engine: spec}}
    configuration: dict[str, Any]
    summary: dict[str, Any]
    owasp_coverage: list[Any]
    limitations: list[Message]
    progress: list[dict[str, Any]]
    dependencies: list[dict[str, Any]]
    system_packages: list[dict[str, Any]]
    inventory: dict[str, Any]
    web_inventory: dict[str, Any]  # dast_scan: the in-scope URLs its crawler found (no query strings)
    unused_dependencies: list[Any]
