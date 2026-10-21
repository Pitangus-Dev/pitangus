"""Code sources (GitHub App and tokens), domains and AI provider keys. Jira is `jira.py`."""

from __future__ import annotations

import html
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, model_validator

from pitangus.app.api.deps import ApiError, Context, Policy, body, documented, guard
from pitangus.app.api.deps import problem
from pitangus.app.api.schemas import AS_RETURNED, MANY, Open
from pitangus.app.api.security import public_url
from pitangus.modules.integrations import code_tokens
from pitangus.modules.integrations.ai_providers import PROVIDERS, ProviderError, check_provider, forget_provider_key, provider_status
from pitangus.modules.integrations.github import (REQUIRED_PERMISSIONS, GitHubAppError, app_installations, app_permissions,
                                                  config as github_config, forget as forget_installation, forget_app, forget_catalog,
                                                  install_url, installation_details, permission_review, save_credentials, verify_app)
from pitangus.modules.integrations import github_manifest
from pitangus.modules.integrations.installations import clear_github, github_connections, github_installations, save_github
from pitangus.modules.scanning import egress, engine_switches, openapi_spec
from pitangus.modules.sources import assets as source_assets
from pitangus.modules.sources import domain_headers, domain_scope, domains, test_users
from pitangus.modules.sources.assets import with_scan_branches
from pitangus.modules.sources.domains import DomainError
from pitangus.modules.sources.repositories import SourceError, find_source, list_repositories, source_page, unavailable
from pitangus.modules.runs.jobs import BusyError
from pitangus.shared import log as logging_setup, settings
from pitangus.shared.i18n import MARK, is_msg, msg, t, text

router = APIRouter(tags=["sources"])


# --- responses ---------------------------------------------------------------------------------------------------

class SourceRow(Open):
    id: str
    uid: str | None = None
    name: str
    provider: str
    private: bool | None = None
    branch: str | None = None
    default_branch: str | None = None
    scan_branch: str | None = None
    archived: bool | None = None
    installation_id: int | None = None
    account: str | None = None


class SourcePage(Open):
    """A page of repositories (or the one asked for by `id`), with the connected accounts and providers."""
    sources: list[SourceRow] = Field(max_length=100)  # a page (per_page 1–100), or the one asked for
    total: int
    page: int | None = None
    per_page: int | None = None
    partial: bool | None = None
    accounts: list[str] | None = Field(None, max_length=MANY)
    providers: dict[str, dict[str, Any]] | None = None


class CodeConnection(Open):
    provider: str
    connected: bool
    repositories: int | None = None


class ProviderStatus(Open):
    id: str
    configured: bool
    env: str | None = None
    owner: str | None = None
    last4: str | None = None
    saved_at: str | None = None


class ProviderKeys(Open):
    providers: list[ProviderStatus] = Field(max_length=len(PROVIDERS))


class ProviderCheck(Open):
    status: str


class GitHubStatus(Open):
    """What the GitHub App needs, whether it's connected, its installations and, read live, their permissions."""
    configured: bool
    connected: bool
    missing: list[str] = Field(max_length=10)  # what the App still needs, of a handful
    app_id: str | None = None
    slug: str | None = None
    name: str | None = None
    owner: str | None = None
    html_url: str | None = None
    source: str | None = None
    public_url: str
    installation: dict[str, Any] | None
    installations: list[dict[str, Any]] = Field(max_length=MANY)
    required_permissions: dict[str, str]
    permissions: dict[str, Any] | None = None
    events: list[str] | None = Field(None, max_length=MANY)
    available_installations: list[dict[str, Any]] | None = Field(None, max_length=MANY)


class InstallLink(BaseModel):
    url: str


def server_port(request: Request) -> int:
    return request.app.state.port


# --- Code -----------------------------------------------------------------------------------------------------------

def _page(page: str | None, per_page: str | None) -> tuple[int, int] | None:
    try:
        page_number, size = int(page or "1"), int(per_page or "25")
    except ValueError:
        return None
    return (page_number, size) if 1 <= size <= 100 and 1 <= page_number and page_number * size <= 10_000 else None


@router.get("/api/sources", response_model=SourcePage, **AS_RETURNED)
def sources(source_id: str | None = Query(None, alias="id"), q: str | None = None, account: str | None = None,
            provider: str | None = None, page: str | None = None, per_page: str | None = None, refresh: str | None = None,
            context: Context = Depends(guard())) -> Any:
    """A page of repositories (`q`, `account`, `provider`, `page` from 1, `per_page` 1–100) or one of them (`id`)."""
    # An empty parameter counts as absent, and they are read as text: `id` answers whatever the others say.
    tokens = code_tokens.current()
    installations = github_installations(context.data_dir)
    if source_id:
        found = find_source(tokens, installations, source_id)
        return context.render({"sources": with_scan_branches(context.data_dir, [found] if found else []), "total": 1 if found else 0})
    paged, query, account, provider = _page(page, per_page), q or "", account or None, provider or None
    if paged is None or len(query) > 100 or (account is not None and len(account) > 100) or provider not in (None, "github", "gitlab", "local"):
        raise ApiError(400, msg("api.invalid_search"))
    if provider and (reason := unavailable(provider)):
        raise ApiError(400, reason)
    if refresh == "1":
        for installation in installations:
            forget_catalog(installation)
    listing = source_page(tokens, installations, query=query, account=account, provider=provider, page=paged[0], per_page=paged[1])
    return context.render({**listing, "sources": with_scan_branches(context.data_dir, listing["sources"])})


class CodeTokenIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["github", "gitlab"]
    token: Any


class CodeDisconnectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["github", "gitlab"]
    disconnect: Any


@router.post("/api/integrations/code", openapi_extra=documented(CodeTokenIn, CodeDisconnectIn), response_model=CodeConnection, **AS_RETURNED)
def connect_code(context: Context = Depends(guard(Policy(admin=True, action="connect-code", body=1024))),
                 data: CodeTokenIn | CodeDisconnectIn = Depends(body(CodeTokenIn | CodeDisconnectIn,
                                                                     msg("integrations.code.invalid_provider")))) -> Any:
    """Connects a GitHub token (sealed in the vault), or disconnects one with `disconnect: true`.

    GitLab is in development: it is refused, though a token saved before can still be disconnected."""
    if isinstance(data, CodeDisconnectIn):
        if data.disconnect is not True:
            raise ApiError(400, msg("api.invalid_request"))
        code_tokens.disconnect(data.provider)
        return {"provider": data.provider, "connected": False}
    if reason := unavailable(data.provider):
        raise ApiError(400, reason)
    token = data.token
    if (not isinstance(token, str) or not 8 <= len(token) <= 512
            or any(character.isspace() or ord(character) < 33 or ord(character) > 126 for character in token)):
        raise ApiError(400, msg("integrations.code.invalid_token"))
    try:
        repositories = list_repositories(data.provider, token)
    except SourceError as exc:
        raise ApiError(400, msg("integrations.code.auth_failed")) from exc
    code_tokens.connect(data.provider, token)
    return {"provider": data.provider, "connected": True, "repositories": len(repositories)}


# --- Domains --------------------------------------------------------------------------------------------------------
# A registered domain whose proof is current (DNS TXT, a well-known file or a meta tag) is the asset `domain:<host>`
# that `import-sarif` accepts for findings of web scanners (ZAP, Nuclei, Strix…) and that passive web and API scans
# reach. Everything here is for administrators, and the outgoing lookups (DNS, one HTTPS GET or HEAD to an address
# checked as public, no redirects) count against the progressive lock-out.

class DomainHeader(Open):
    """A saved request header: its name, the last four characters of a long value and when it was saved."""
    name: str
    last4: str | None = None
    saved_at: str | None = None


class DomainSchedule(Open):
    """When the passive web scan runs on its own: daily, on `weekdays` (1 Monday … 7 Sunday) or on `month_days`
    (1–28), at `time` (HH:MM) in `timezone` (IANA), at most once a day. `next_run_at` (UTC) is the moment the
    scheduler queues it; `last_run_at` and `last_run_id` say what it did last and `note`, when that slot was skipped,
    why. The scan signs in as `test_users` (ids, at most 3) and sends the saved headers with `use_headers`."""
    frequency: Literal["daily", "weekly", "monthly"]
    weekdays: list[int] = Field(default_factory=list, max_length=7)
    month_days: list[int] = Field(default_factory=list, max_length=28)
    time: str
    timezone: str
    test_users: list[str] = Field(default_factory=list, max_length=test_users.PER_SCAN)
    use_headers: bool = False
    next_run_at: str | None = None
    last_run_at: str | None = None
    last_run_id: str | None = None
    note: str | None = None


class DomainTestUser(Open):
    """A saved test user, as administrators see it: never its password or TOTP seed. `login_url` null means the root
    of the host it applies to; `check_url` is a page only a signed-in user sees, asked for after signing in to confirm
    it worked; `last_used_at` is when a scan last signed in with it."""
    id: str
    name: str
    method: Literal["password", "password_totp"]
    username: str
    applies_to: str
    login_url: str | None = None
    check_url: str | None = None
    notes: str | None = None
    created_by: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    last_used_at: str | None = None


class DomainRow(Open):
    """A registered domain. `verified` means its proof is current (`verified_until` lies ahead) and `proof_method`
    says which one (only `dns` covers subdomains). What proves it (`txt_name`, `txt_value`, `verify_token`,
    `verify_file_url`, `verify_meta`), the saved `headers` and the `test_users` are only answered to administrators;
    everyone gets how many there are (`header_count`, `test_user_count`). `runs` and `open`
    say what was scanned or imported against it; `schedule` is null (off) or when its passive web scan runs on its
    own."""
    id: str
    host: str
    url: str
    kind: str
    context: str
    key: str
    verified: bool
    expired: bool
    registered_at: str | None = None
    registered_by: str | None = None
    verified_at: str | None = None
    verified_until: str | None = None
    checked_at: str | None = None
    proof_method: Literal["dns", "file", "meta"] | None = None
    txt_name: str | None = None
    txt_value: str | None = None
    verify_token: str | None = None
    verify_file_url: str | None = None
    verify_meta: str | None = None
    schedule: DomainSchedule | None = None
    last_scan: dict[str, Any] | None = None
    headers: list[DomainHeader] | None = Field(None, max_length=domain_headers.LIMIT)
    header_count: int = 0
    session_check: str | None = None
    test_users: list[DomainTestUser] | None = Field(None, max_length=test_users.LIMIT)
    test_user_count: int = 0
    runs: int = 0
    open: int = 0


class Egress(Open):
    """The public addresses web scans leave from, for sites that filter by IP: declared by the server
    (`source` setting, PITANGUS_EGRESS_IPS), detected once by an administrator (`detected`, with `detected_at`), or
    unknown (no `ips`)."""
    ips: list[str] = Field(default_factory=list, max_length=settings.ADDRESSES_LIMIT)
    source: Literal["setting", "detected"] | None = None
    detected_at: str | None = None


class DomainPage(Open):
    """`dast`: whether the full passive web scan is on (Settings → Analysis engines); `egress`: where they leave from."""
    items: list[DomainRow] = Field(max_length=domains.LIMIT)
    total: int
    limit: int
    dast: bool = False
    egress: Egress | None = None


class DomainCheck(Open):
    """The probe before registering: `public` is false when the name resolves to a private or reserved address (and
    nothing was sent), null when it doesn't resolve; `https` and `reachable` mean a valid certificate and an answer."""
    host: str
    reachable: bool
    status: Literal["reachable", "dns_error", "private_address", "tls_error", "unreachable"]
    detail: str
    http_status: int | None = None
    https: bool = False
    public: bool | None = None


class DomainRemoved(Open):
    id: str
    host: str
    runs_kept: int


class DomainHeaders(Open):
    domain_id: str
    headers: list[DomainHeader] = Field(max_length=domain_headers.LIMIT)
    limit: int


class DomainSessionCheck(Open):
    domain_id: str
    session_check: str | None = None


class DomainTestUsers(Open):
    """The domain's test users after a change; `limit` per domain, `per_scan` a scan may sign in with."""
    domain_id: str
    test_users: list[DomainTestUser] = Field(max_length=test_users.LIMIT)
    limit: int
    per_scan: int


ADMIN_ONLY = ("txt_name", "txt_value", "verify_token", "verify_file_url", "verify_meta", "session_check")
SPEC_BASE64 = (openapi_spec.MAX_BYTES + 2) // 3 * 4
SCAN_BODY = SPEC_BASE64 + 16_000  # a definition in base64 plus the rest of the request


def _domain_rows(context: Context, records: list[dict]) -> list[dict]:
    """Rows for the reader: what was scanned or imported against each domain, its latest web scan, and what proves
    it and the saved headers for administrators only."""
    from pitangus.modules.findings import registry as findings_registry
    from pitangus.modules.runs.store import find_runs
    admin = (context.user or {}).get("role") == "admin"
    accounts = test_users.counts(context.data_dir)
    counted: dict[str, int] = {}
    latest: dict[str, dict] = {}
    for row in find_runs(context.data_dir, assets=[record["key"] for record in records]):
        key = row.get("asset_key") or source_assets.asset_key(row)
        counted[key] = counted.get(key, 0) + 1
        if row.get("type") == "dast_scan" and key not in latest:  # newest first
            latest[key] = {name: row.get(name) for name in ("id", "status", "created_at", "finished_at", "variant")}
        technologies = (row.get("summary") or {}).get("technologies") if row.get("type") == "dast_scan" else None
        if technologies is not None and key in latest and "technologies" not in latest[key]:
            # What the newest scan that fingerprinted the hosts saw, and when.
            latest[key]["technologies"] = {"items": technologies, "run_id": row.get("id"), "created_at": row.get("created_at")}
    rows = []
    for record in records:
        runs = counted.get(record["key"], 0)
        shown = {name: value for name, value in record.items() if admin or name not in ADMIN_ONLY}
        saved = domain_headers.list_headers(record["id"]) if admin else []
        rows.append({**shown, "runs": runs, "last_scan": latest.get(record["key"]),
                     "headers": saved if admin else None, "header_count": len(saved) if admin else domain_headers.count(record["id"]),
                     "test_users": test_users.list_users(context.data_dir, record["id"]) if admin else None,
                     "test_user_count": accounts.get(record["id"], 0),
                     "open": findings_registry.summarize(context.data_dir, record["key"])["open"] if runs else 0})
    return rows


@router.get("/api/domains", response_model=DomainPage, **AS_RETURNED)
def domain_list(context: Context = Depends(guard())) -> Any:
    """The registered domains (at most `limit`), with whether each one's proof is current and its scheduled scan."""
    records = domains.list_domains(context.data_dir)
    return context.render({"items": _domain_rows(context, records), "total": len(records), "limit": domains.LIMIT,
                           "dast": engine_switches.enabled("dast", context.data_dir), "egress": egress.current(context.data_dir)})


@router.post("/api/domains/egress", response_model=Egress, **AS_RETURNED,
             responses={409: {"description": "Declared by the server"}, 429: {"description": "Too many attempts"},
                        502: {"description": "The echo service failed"}})
def domain_egress_detect(context: Context = Depends(guard(Policy(admin=True, action="detect-egress", body=64)))) -> Any:
    """Asks a public echo service (https://api.ipify.org) once for the address this server is seen from, and keeps
    it for the panel to show to site owners who filter by IP. Only on this explicit request, and only when the server
    doesn't declare PITANGUS_EGRESS_IPS. One HTTPS GET, no redirects, 10 seconds and 64 bytes at most."""
    _attempt(context, f"egress-detect:{context.user['username']}")
    try:
        found = egress.detect(context.data_dir, by=context.user["username"])
    except egress.EgressError as exc:
        declared = is_msg(exc.message) and exc.message[MARK] == "scanning.egress.declared"
        raise ApiError(409 if declared else 502, exc.message) from exc
    context.state.auth.throttle.succeeded(f"egress-detect:{context.user['username']}")
    context.state.log.info("egress_detected", extra={"user": context.user["username"], "reason": ", ".join(found["ips"])})
    return context.render(found)


class DomainIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: StrictStr = Field(max_length=300)
    kind: Literal["web", "api", "surface"] = "web"
    context: StrictStr = Field("", max_length=domains.CONTEXT_LIMIT)


class DomainIdIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain_id: StrictStr = Field(pattern="^[0-9a-f]{24}$")


class DomainVerifyIn(BaseModel):
    """`method`: dns (the TXT record, the default), file (`/.well-known/pitangus-verify.txt`) or meta (the
    homepage's `<meta name="pitangus-verify">`). Only a DNS proof lets scans include subdomains."""
    model_config = ConfigDict(extra="forbid")
    domain_id: StrictStr = Field(pattern="^[0-9a-f]{24}$")
    method: Literal["dns", "file", "meta"] = "dns"


class DomainCheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: StrictStr = Field(max_length=300)


class DomainHeaderIn(BaseModel):
    """`save` adds or replaces a header (by name, case-insensitive); `remove` deletes it (no `value`)."""
    model_config = ConfigDict(extra="forbid")
    domain_id: StrictStr = Field(pattern="^[0-9a-f]{24}$")
    op: Literal["save", "remove"]
    name: StrictStr = Field(min_length=1, max_length=64)
    value: StrictStr | None = Field(None, max_length=domain_headers.VALUE_MAX + 64)

    @model_validator(mode="after")
    def _value(self):
        if (self.op == "save") != (self.value is not None):
            raise ValueError("value goes with save only")
        return self


class TotpIn(BaseModel):
    """The TOTP seed in base32, as an authenticator app shows it, and its settings (30 s, 6 digits, SHA1 by default)."""
    model_config = ConfigDict(extra="forbid")
    secret: StrictStr = Field(min_length=16, max_length=300)
    digits: StrictInt = 6
    period: StrictInt = 30
    algorithm: Literal["SHA1", "SHA256", "SHA512"] = "SHA1"


class DomainTestUserIn(BaseModel):
    """`save` adds a test user (no `id`) or changes one: a password or a TOTP seed left out keeps the saved one.
    `remove` deletes it (`id` only). `password_totp` needs `totp` when added or switched to."""
    model_config = ConfigDict(extra="forbid")
    domain_id: StrictStr = Field(pattern="^[0-9a-f]{24}$")
    op: Literal["save", "remove"]
    id: StrictStr | None = Field(None, pattern="^[0-9a-f]{24}$")
    name: StrictStr | None = Field(None, min_length=1, max_length=test_users.NAME_MAX)
    method: Literal["password", "password_totp"] | None = None
    username: StrictStr | None = Field(None, min_length=1, max_length=test_users.USERNAME_MAX)
    password: StrictStr | None = Field(None, min_length=1, max_length=test_users.PASSWORD_MAX)
    totp: TotpIn | None = None
    login_url: StrictStr | None = Field(None, max_length=test_users.URL_MAX)
    check_url: StrictStr | None = Field(None, max_length=test_users.URL_MAX)
    notes: StrictStr | None = Field(None, max_length=test_users.NOTES_MAX)
    applies_to: StrictStr | None = Field(None, max_length=260)

    @model_validator(mode="after")
    def _fields(self):
        if self.op == "remove" and (self.id is None or any(value is not None for value in (
                self.name, self.method, self.username, self.password, self.totp, self.login_url, self.check_url, self.notes,
                self.applies_to))):
            raise ValueError("remove takes the id only")
        if self.op == "save" and (self.name is None or self.method is None or self.username is None):
            raise ValueError("save needs a name, a method and a username")
        if self.method == "password" and self.totp is not None:
            raise ValueError("a TOTP seed goes with password_totp only")
        return self


class ScheduleIn(BaseModel):
    """`weekdays` (1 Monday … 7 Sunday) go with weekly, `month_days` (1–28) with monthly; `time` is HH:MM in
    `timezone`, an IANA name (the browser's, by default)."""
    model_config = ConfigDict(extra="forbid")
    frequency: Literal["daily", "weekly", "monthly"]
    weekdays: list[Annotated[StrictInt, Field(ge=1, le=7)]] = Field(default_factory=list, max_length=7)
    month_days: list[Annotated[StrictInt, Field(ge=1, le=28)]] = Field(default_factory=list, max_length=28)
    time: StrictStr = Field(pattern="^([01][0-9]|2[0-3]):[0-5][0-9]$")
    timezone: StrictStr = Field(min_length=1, max_length=64)
    test_users: list[Annotated[StrictStr, Field(pattern="^[0-9a-f]{24}$")]] = Field(default_factory=list, max_length=test_users.PER_SCAN)
    use_headers: StrictBool = False

    @model_validator(mode="after")
    def _days(self):
        if self.frequency == "weekly" and not self.weekdays:
            raise ValueError("weekly takes at least one weekday")
        if self.frequency == "monthly" and not self.month_days:
            raise ValueError("monthly takes at least one day of the month")
        return self


class DomainScheduleIn(BaseModel):
    """`schedule`: the rule, or null to turn the scheduled scan off."""
    model_config = ConfigDict(extra="forbid")
    domain_id: StrictStr = Field(pattern="^[0-9a-f]{24}$")
    schedule: ScheduleIn | None


class SpecIn(BaseModel):
    """An OpenAPI 3.x or Swagger 2.0 definition, JSON or YAML, at most 5 MB once decoded."""
    model_config = ConfigDict(extra="forbid")
    filename: StrictStr = Field(min_length=1, max_length=200)
    content_base64: StrictStr = Field(min_length=4, max_length=SPEC_BASE64)


class DomainScanIn(BaseModel):
    """A passive scan of a verified domain. `mode`: web (crawl) or api (an OpenAPI definition: `spec`, uploaded, or
    `spec_url`, on a host of the scope). `use_scope`: include the hosts saved in the domain's scope (read again when
    the scan starts); or `hosts`: subdomains listed for this scan only (`name` or `*.name`, at most 20). Both need a
    DNS proof. `use_headers`: send the domain's saved headers to the scope's hosts. `test_users`: ids of the domain's
    test users to sign in as (at most 3), each with its own crawl; each must sign in on a host of that scope."""
    model_config = ConfigDict(extra="forbid")
    domain_id: StrictStr = Field(pattern="^[0-9a-f]{24}$")
    mode: Literal["web", "api", "exposure"] = "web"
    hosts: list[Annotated[StrictStr, Field(max_length=260)]] = Field(default_factory=list, max_length=domains.SCOPE_LIMIT)
    use_scope: bool = False
    use_headers: bool = False
    test_users: list[Annotated[StrictStr, Field(pattern="^[0-9a-f]{24}$")]] = Field(default_factory=list, max_length=test_users.PER_SCAN)
    spec: SpecIn | None = None
    spec_url: StrictStr | None = Field(None, max_length=2000)

    @model_validator(mode="after")
    def _spec(self):
        if self.use_scope and self.hosts:
            raise ValueError("use_scope or hosts, not both")
        if self.mode == "web" and (self.spec is not None or self.spec_url is not None):
            raise ValueError("a definition goes with api mode only")
        if self.mode == "api" and (self.spec is None) == (self.spec_url is None):
            raise ValueError("api mode takes either spec or spec_url")
        if self.mode == "exposure" and (self.spec is not None or self.spec_url is not None or self.use_headers or self.test_users):
            raise ValueError("the exposure check is anonymous: no definition, headers or test users")
        return self


def _attempt(context: Context, scope: str) -> None:
    """Counts an outgoing lookup against the progressive lock-out (DNS and HTTPS probes aren't free to repeat)."""
    wait = context.state.auth.throttle.reserve(scope)
    if wait:
        raise ApiError(429, msg("sources.domains.too_many_attempts", seconds=wait), retry_in=wait)


def _known(context: Context, domain_id: str) -> dict:
    try:
        return domains.get_domain(context.data_dir, domain_id)
    except DomainError as exc:
        raise ApiError(404, exc.message) from exc


@router.post("/api/domains", response_model=DomainRow, openapi_extra=documented(DomainIn), **AS_RETURNED)
def domain_register(context: Context = Depends(guard(Policy(admin=True, action="register-domain", body=2048))),
                    data: DomainIn = Depends(body(DomainIn, msg("sources.domains.invalid_request")))) -> Any:
    """Registers an HTTPS domain and answers the ways to prove control of it. Nothing is tested."""
    try:
        record = domains.register_domain(context.data_dir, data.url, data.kind, data.context, by=context.user["username"])
    except DomainError as exc:
        raise ApiError(400, exc.message) from exc
    context.state.log.info("domain_registered", extra={"user": context.user["username"], "reason": record["host"]})
    if engine_switches.enabled("dast", context.data_dir):
        context.state.jobs.enqueue_discovery(domain=record)
    return context.render(_domain_rows(context, [record])[0])


@router.post("/api/domains/verify", response_model=DomainRow, openapi_extra=documented(DomainVerifyIn), **AS_RETURNED,
             responses={404: {"description": "Unknown domain"}, 429: {"description": "Too many attempts"}})
def domain_verify(context: Context = Depends(guard(Policy(admin=True, action="verify-domain", body=256))),
                  data: DomainVerifyIn = Depends(body(DomainVerifyIn, msg("sources.domains.invalid_request")))) -> Any:
    """Asks for the proof once: the TXT record (dns), the well-known file (file) or the homepage's meta tag (meta).
    Seen, the domain is an asset for 90 days; a daily re-check of the same proof extends or withdraws it."""
    _known(context, data.domain_id)
    _attempt(context, f"domain-verify:{data.domain_id}")
    try:
        record = domains.verify_domain(context.data_dir, data.domain_id, data.method)
    except DomainError as exc:
        raise ApiError(400, exc.message) from exc
    context.state.auth.throttle.succeeded(f"domain-verify:{data.domain_id}")
    context.state.log.info("domain_verified", extra={"user": context.user["username"], "reason": f"{record['host']} ({data.method})"})
    return context.render(_domain_rows(context, [record])[0])


def _probe(context: Context, url: str) -> dict:
    _attempt(context, f"domain-check:{context.user['username']}")
    try:
        result = domains.check_reachability(url)
    except DomainError as exc:
        raise ApiError(400, exc.message) from exc
    if result["reachable"]:
        context.state.auth.throttle.succeeded(f"domain-check:{context.user['username']}")
    return context.render(result)


@router.post("/api/domains/probe", response_model=DomainCheck, openapi_extra=documented(DomainCheckIn), **AS_RETURNED,
             responses={429: {"description": "Too many attempts"}})
def domain_probe(context: Context = Depends(guard(Policy(admin=True, action="probe-domain", body=1024))),
                 data: DomainCheckIn = Depends(body(DomainCheckIn, msg("sources.domains.invalid_request")))) -> Any:
    """Checks a URL before registering it: whether its name resolves to public addresses only (nothing is sent
    otherwise) and whether it answers over HTTPS with a valid certificate. One HEAD to the already-resolved address,
    no redirects. Only a hint: a domain that doesn't answer can still be registered."""
    return _probe(context, data.url)


@router.post("/api/domains/check", response_model=DomainCheck, openapi_extra=documented(DomainCheckIn), **AS_RETURNED,
             responses={429: {"description": "Too many attempts"}})
def domain_check(context: Context = Depends(guard(Policy(admin=True, action="check-domain", body=1024))),
                 data: DomainCheckIn = Depends(body(DomainCheckIn, msg("sources.domains.invalid_request")))) -> Any:
    """The same probe as `/api/domains/probe` (kept for earlier panels)."""
    return _probe(context, data.url)


@router.post("/api/domains/remove", response_model=DomainRemoved, openapi_extra=documented(DomainIdIn), **AS_RETURNED,
             responses={404: {"description": "Unknown domain"}})
def domain_remove(context: Context = Depends(guard(Policy(admin=True, action="remove-domain", body=256))),
                  data: DomainIdIn = Depends(body(DomainIdIn, msg("sources.domains.invalid_request")))) -> Any:
    """Removes a domain's configuration: saved headers, test users, related hosts (its scope) and scheduled scan. What
    was scanned or imported against it (runs, findings, their triage and tickets) stays as evidence, and links back if
    the same host is added again (the asset key comes from the host)."""
    from pitangus.modules.runs.store import count_runs
    record = _known(context, data.domain_id)
    kept = count_runs(context.data_dir, assets=[record["key"]])
    domains.remove_domain(context.data_dir, data.domain_id)
    context.state.log.warning("domain_removed", extra={"user": context.user["username"], "reason": f"{record['host']}: {kept} runs kept"})
    return {"id": record["id"], "host": record["host"], "runs_kept": kept}


@router.post("/api/domains/headers", response_model=DomainHeaders, openapi_extra=documented(DomainHeaderIn), **AS_RETURNED,
             responses={404: {"description": "Unknown domain"}})
def domain_headers_route(context: Context = Depends(guard(Policy(admin=True, action="domain-headers", body=6000))),
                         data: DomainHeaderIn = Depends(body(DomainHeaderIn, msg("sources.domains.headers.invalid_request")))) -> Any:
    """Saves or removes a request header that web scans of the domain may send (API keys, bearer tokens, session
    cookies). Stored encrypted; never answered back: the list carries names, the last four characters of long values
    and when each was saved."""
    record = _known(context, data.domain_id)
    try:
        if data.op == "save":
            listed = domain_headers.save(record["id"], data.name, data.value, by=context.user["username"])
        else:
            listed = domain_headers.remove(record["id"], data.name)
    except domain_headers.HeaderError as exc:
        raise ApiError(400, exc.message) from exc
    # The header's name only: its value never reaches a log line.
    context.state.log.warning("domain_header_changed", extra={"user": context.user["username"],
                                                              "reason": f"{record['host']}: {data.op} {data.name}"})
    return context.render({"domain_id": record["id"], "headers": listed, "limit": domain_headers.LIMIT})


class DomainSessionCheckIn(BaseModel):
    """`url`: an HTTPS page of the domain that only opens signed in; empty removes it."""
    model_config = ConfigDict(extra="forbid")
    domain_id: StrictStr = Field(pattern="^[0-9a-f]{24}$")
    url: StrictStr = Field(max_length=test_users.URL_MAX + 64)


@router.post("/api/domains/session-check", response_model=DomainSessionCheck, openapi_extra=documented(DomainSessionCheckIn),
             **AS_RETURNED, responses={404: {"description": "Unknown domain"}})
def domain_session_check_route(context: Context = Depends(guard(Policy(admin=True, action="domain-session-check", body=4000))),
                               data: DomainSessionCheckIn = Depends(body(DomainSessionCheckIn, msg("sources.domains.headers.invalid_request")))) -> Any:
    """Saves the page that proves the saved headers still carry a session: a scan that sends them asks for it before
    and after, and without a 2xx the scan is incomplete and marks nothing fixed."""
    record = _known(context, data.domain_id)
    try:
        saved = domain_headers.set_check(context.data_dir, record, data.url)
    except domain_headers.HeaderError as exc:
        raise ApiError(400, exc.message) from exc
    context.state.log.warning("domain_session_check_changed", extra={"user": context.user["username"],
                                                                     "reason": f"{record['host']}: {'set' if saved else 'removed'}"})
    return context.render({"domain_id": record["id"], "session_check": saved})


@router.post("/api/domains/test-users", response_model=DomainTestUsers, openapi_extra=documented(DomainTestUserIn), **AS_RETURNED,
             responses={404: {"description": "Unknown domain or test user"}})
def domain_test_users_route(context: Context = Depends(guard(Policy(admin=True, action="domain-test-users", body=12_000))),
                            data: DomainTestUserIn = Depends(body(DomainTestUserIn, msg("sources.domains.test_users.invalid_request")))) -> Any:
    """Saves or removes an account web scans of the domain may sign in with (username and password, plus a TOTP seed
    for `password_totp`). The username, password and seed are stored encrypted; the password and the seed are never
    answered back."""
    record = _known(context, data.domain_id)
    try:
        if data.op == "save":
            fields = data.model_dump(exclude={"domain_id", "op"}, exclude_none=True)
            name = test_users.save(context.data_dir, record, fields, by=context.user["username"])["name"]
        else:
            name = next((user["name"] for user in test_users.list_users(context.data_dir, record["id"]) if user["id"] == data.id), "")
            test_users.remove(context.data_dir, record["id"], data.id)
    except test_users.TestUserError as exc:
        missing = is_msg(exc.message) and exc.message[MARK] == "sources.domains.test_users.not_found"
        raise ApiError(404 if missing else 400, exc.message) from exc
    # The test user's name only: neither its username nor anything secret reaches a log line.
    context.state.log.warning("domain_test_user_changed", extra={"user": context.user["username"],
                                                                 "reason": f"{record['host']}: {data.op} {name}"})
    return context.render({"domain_id": record["id"], "test_users": test_users.list_users(context.data_dir, record["id"]),
                           "limit": test_users.LIMIT, "per_scan": test_users.PER_SCAN})


@router.post("/api/domains/schedule", response_model=DomainRow, openapi_extra=documented(DomainScheduleIn), **AS_RETURNED,
             responses={404: {"description": "Unknown domain or test user"},
                        409: {"description": "No saved headers, or a test user signing in outside the saved scope"}})
def domain_schedule(context: Context = Depends(guard(Policy(admin=True, action="schedule-domain", body=1024))),
                    data: DomainScheduleIn = Depends(body(DomainScheduleIn, msg("sources.domains.invalid_request")))) -> Any:
    """Sets when the domain's passive web scan runs on its own (daily, on some weekdays or on some days of the month,
    at a time in a timezone), or turns it off. The answer carries `schedule.next_run_at`, computed here: never on the
    local day of the domain's last web scan, so a scan launched just before doesn't repeat that day. The periodic task
    queues it within five minutes of that moment (only with the full web scan on); scheduled scans crawl the
    domain's own host and the hosts saved in its scope, signed in as the rule's `test_users` (each must sign in on one
    of those hosts) and with the saved headers if `use_headers`. When it runs, a test user deleted or now outside the
    scope, or headers no longer saved, are left out with a note; a domain whose proof lapsed is skipped with the reason."""
    from datetime import datetime
    from pitangus.modules.runs.store import find_runs
    record = _known(context, data.domain_id)
    if data.schedule is not None:
        if data.schedule.use_headers and not domain_headers.count(record["id"]):
            raise ApiError(409, msg("scanning.web.errors.no_headers"))
        if data.schedule.test_users:
            try:
                scope = domains.scan_scope(record, domain_scope.saved_hosts(context.data_dir, record))
                test_users.check_selection(context.data_dir, record, list(data.schedule.test_users), scope)
            except DomainError as exc:
                raise ApiError(409, exc.message) from exc
            except test_users.TestUserError as exc:
                missing = is_msg(exc.message) and exc.message[MARK] == "sources.domains.test_users.not_found"
                raise ApiError(404 if missing else 409, exc.message) from exc
    last = find_runs(context.data_dir, types=["dast_scan"], assets=[record["key"]], limit=1)
    try:
        record = domains.set_schedule(context.data_dir, data.domain_id, data.schedule.model_dump() if data.schedule else None,
                                      last_scan_at=datetime.fromisoformat(last[0]["created_at"]) if last else None)
    except DomainError as exc:
        raise ApiError(400, exc.message) from exc
    rule = record["schedule"]
    context.state.log.info("domain_schedule_changed", extra={"user": context.user["username"], "reason": f"{record['host']}: "
                                                             + (f"{rule['frequency']} {rule['time']} {rule['timezone']}" if rule else "off")})
    return context.render(_domain_rows(context, [record])[0])


class RelatedHost(Open):
    """A host under the domain: `state` says whether its scans reach it; `origin` whether discovery found it or
    someone added it; `last_seen` is the last discovery that found it."""
    host: str
    state: Literal["in_scope", "out_of_scope"]
    origin: Literal["discovered", "manual"]
    first_seen: str | None = None
    last_seen: str | None = None
    changed_by: str | None = None


class DiscoveryCounts(Open):
    found: int = 0
    kept: int = 0
    private: int = 0
    unresolved: int = 0
    new: int = 0
    capped: int = 0


class Discovery(Open):
    """The last discovery round: `note` says why it failed or couldn't run; `available` is false when this server
    doesn't run discovery at all (web scans off), with the reason in `unavailable`."""
    status: Literal["idle", "queued", "running", "done", "failed"]
    requested_at: str | None = None
    finished_at: str | None = None
    note: str | None = None
    counts: DiscoveryCounts | None = None
    available: bool = False
    unavailable: str | None = None


class DomainScope(Open):
    """The domain's related hosts and its saved scope. `covered`: its proof lets them in (a current DNS proof);
    otherwise `reason` says what's missing and nothing can be put in scope. `in_scope` counts the hosts saved in
    (at most `scope_limit`); at most `limit` hosts are kept."""
    domain_id: str
    root: str
    covered: bool
    reason: str | None = None
    hosts: list[RelatedHost] = Field(max_length=domain_scope.HOSTS_LIMIT)
    in_scope: int
    limit: int
    scope_limit: int
    discovery: Discovery


class DomainScopeIn(BaseModel):
    """`set` puts a listed host in or out of scope (`host`, `state`); `add` lists a host under the domain by hand, in
    scope; `remove` forgets a host added by hand; `exclude_all` puts every host out of scope."""
    model_config = ConfigDict(extra="forbid")
    domain_id: StrictStr = Field(pattern="^[0-9a-f]{24}$")
    op: Literal["set", "add", "remove", "exclude_all"]
    host: StrictStr | None = Field(None, max_length=253)
    state: Literal["in_scope", "out_of_scope"] | None = None

    @model_validator(mode="after")
    def _fields(self):
        if (self.op != "exclude_all") != (self.host is not None) or (self.op == "set") != (self.state is not None):
            raise ValueError("set takes host and state; add and remove take host; exclude_all takes neither")
        return self


def _scope_view(context: Context, domain_id: str) -> dict:
    shown = domain_scope.view(context.data_dir, domain_id)
    off = engine_switches.mode_off(engine_switches.resolve(context.data_dir), "dast", "scanning.discovery.disabled")
    shown["discovery"] = {**shown["discovery"], "available": off is None, "unavailable": off}
    return context.render(shown)


@router.get("/api/domains/scope", response_model=DomainScope, **AS_RETURNED, responses={404: {"description": "Unknown domain"}})
def domain_scope_read(domain_id: str = Query(pattern="^[0-9a-f]{24}$"), context: Context = Depends(guard())) -> Any:
    """The hosts related to a domain (found by discovery or added by hand), which of them its scans reach, whether its
    proof lets any in, and the last discovery round."""
    _known(context, domain_id)
    return _scope_view(context, domain_id)


@router.post("/api/domains/scope", response_model=DomainScope, openapi_extra=documented(DomainScopeIn), **AS_RETURNED,
             responses={404: {"description": "Unknown domain"},
                        409: {"description": "The domain's proof doesn't cover subdomains (only a current DNS proof does)"}})
def domain_scope_change(context: Context = Depends(guard(Policy(admin=True, action="domain-scope", body=512))),
                        data: DomainScopeIn = Depends(body(DomainScopeIn, msg("sources.domains.invalid_request")))) -> Any:
    """Saves the domain's scope, one host at a time: its scans (by hand or scheduled) reach the hosts saved in it.
    Nothing is sent to any host here."""
    record = _known(context, data.domain_id)
    user = context.user["username"]
    try:
        if data.op == "set":
            domain_scope.set_state(context.data_dir, record["id"], data.host, data.state or "", by=user)
        elif data.op == "add":
            domain_scope.add_host(context.data_dir, record["id"], data.host, by=user)
        elif data.op == "remove":
            domain_scope.remove_host(context.data_dir, record["id"], data.host)
        else:
            domain_scope.exclude_all(context.data_dir, record["id"], by=user)
    except DomainError as exc:
        raise ApiError(409 if exc.message == domain_scope.coverage_reason(record) else 400, exc.message) from exc
    context.state.log.info("domain_scope_changed", extra={"user": user, "reason": f"{record['host']}: {data.op} {data.host or ''} {data.state or ''}".strip()})
    return _scope_view(context, record["id"])


@router.post("/api/domains/discover", status_code=202, response_model=DomainScope, openapi_extra=documented(DomainIdIn), **AS_RETURNED,
             responses={404: {"description": "Unknown domain"},
                        409: {"description": "Web scans off on this server, a demo domain, or a discovery already queued or running"}})
def domain_discover(context: Context = Depends(guard(Policy(admin=True, action="discover-domain", body=256))),
                    data: DomainIdIn = Depends(body(DomainIdIn, msg("sources.domains.invalid_request")))) -> Any:
    """Queues a search for hosts related to the domain in passive sources (certificate transparency, passive DNS,
    archives) with subfinder. Nothing reaches the domain's hosts; found hosts that resolve to public addresses are
    listed out of scope. Only with the full web scan on: the domain's name goes to those sources."""
    record = _known(context, data.domain_id)
    if domains.is_demo(record):
        raise ApiError(409, msg("sources.domains.discovery.demo", host=record["host"]))
    if off := engine_switches.mode_off(engine_switches.resolve(context.data_dir), "dast", "scanning.discovery.disabled"):
        raise ApiError(409, off)
    if not context.state.jobs.enqueue_discovery(domain=record):
        raise ApiError(409, msg("sources.domains.discovery.busy"))
    context.state.log.info("domain_discovery_requested", extra={"user": context.user["username"], "reason": record["host"]})
    return _scope_view(context, record["id"])


class QueuedDomainScan(Open):
    """`run_id` is the queued run (also in `run`, with its status)."""
    run_id: str
    run: dict[str, Any]
    domain: DomainRow


def _scan_options(context: Context, record: dict, data: DomainScanIn | None) -> dict:
    """Everything the request asks for, validated before anything is queued; the worker checks it all again."""
    import base64
    import binascii
    from pitangus.shared import vault
    if data is None:
        return {"mode": "web"}
    try:
        scope = domains.scan_scope(record, domain_scope.saved_hosts(context.data_dir, record) if data.use_scope else list(data.hosts))
    except DomainError as exc:
        needs_dns = is_msg(exc.message) and exc.message[MARK] == "sources.domains.scope.needs_dns"
        raise ApiError(409 if needs_dns else 400, exc.message) from exc
    for host in scope["hosts"]:
        try:
            domains.public_address(host)
        except DomainError as exc:
            raise ApiError(409, msg("scanning.web.errors.address", host=host, reason=exc.message)) from exc
    if data.use_headers and not domain_headers.count(record["id"]):
        raise ApiError(409, msg("scanning.web.errors.no_headers"))
    try:
        chosen = test_users.check_selection(context.data_dir, record, list(data.test_users), scope)
    except test_users.TestUserError as exc:
        outside = is_msg(exc.message) and exc.message[MARK] == "sources.domains.test_users.not_in_scope"
        raise ApiError(409 if outside else 400, exc.message) from exc
    options: dict[str, Any] = {"mode": data.mode, "use_headers": data.use_headers}
    if data.use_scope:
        options["use_scope"] = True
    else:
        options["hosts"] = [*scope["hosts"][1:], *scope["wildcards"]]
    if chosen:
        options["test_users"] = [user["id"] for user in chosen]
    try:
        if data.spec is not None:
            try:
                raw = base64.b64decode(data.spec.content_base64, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise openapi_spec.SpecError(msg("scanning.web.spec.not_base64")) from exc
            parsed = openapi_spec.parse(raw, data.spec.filename)
            options.update(spec=vault.seal({key: parsed[key] for key in ("document", "version", "server", "sha256", "endpoints")}, "dast-spec"),
                           spec_sha256=parsed["sha256"], spec_endpoints=parsed["endpoints"])
        elif data.spec_url is not None:
            openapi_spec.check_url(data.spec_url, scope["hosts"])
            options["spec_url"] = data.spec_url.strip()
    except openapi_spec.SpecError as exc:
        raise ApiError(400, exc.message) from exc
    return options


def launch_domain_scan(context: Context, domain_id: str, *, trigger: dict | None = None, data: DomainScanIn | None = None) -> dict:
    """Queues a passive web or API scan of a verified domain; the worker checks everything again before it starts."""
    from pitangus.app.api.repositories import QUEUE_LIMIT
    # The full DAST (ZAP, katana) is experimental and off unless enabled; the light exposure check is always available.
    switches = engine_switches.resolve(context.data_dir)
    if (data is None or data.mode != "exposure") and (off := engine_switches.mode_off(switches, "dast", "scanning.web.errors.disabled")):
        raise ApiError(409, off)
    if data is not None and data.mode == "exposure" and engine_switches.uncovered(switches, ("exposure",)):
        raise ApiError(409, msg("scanning.switches.uncovered", what=msg("scanning.switches.capability.exposure")))
    record = _known(context, domain_id)
    if domains.is_demo(record):  # before any DNS lookup: nothing leaves the machine for demo data
        raise ApiError(409, msg("sources.domains.demo", host=record["host"]))
    if not record["verified"]:
        raise ApiError(409, msg("sources.domains.not_verified", host=record["host"]))
    try:
        domains.public_address(record["host"])
    except DomainError as exc:
        raise ApiError(409, msg("scanning.web.errors.address", host=record["host"], reason=exc.message)) from exc
    options = _scan_options(context, record, data)
    if context.state.jobs.pending() >= QUEUE_LIMIT:
        raise ApiError(429, msg("api.queue_full"))
    try:
        queued = context.state.jobs.enqueue_dast_scan(domain=record, requested_by=context.user["username"], trigger=trigger, options=options)
    except BusyError as exc:
        raise ApiError(409, exc.message) from exc
    context.state.log.warning("dast_scan_launched", extra={"user": context.user["username"],
                                                           "reason": f"{record['host']} ({options['mode']}, {len(options.get('hosts') or [])} extra hosts, "
                                                                     f"{len(options.get('test_users') or [])} test users)"})
    return {"run": queued, "domain": record}


@router.post("/api/domains/scans", status_code=202, response_model=QueuedDomainScan, openapi_extra=documented(DomainScanIn),
             **AS_RETURNED, responses={404: {"description": "Unknown domain"},
                                       409: {"description": "Web scans off, a demo domain, domain not verified, a host private, subdomains "
                                                             "without a DNS proof, no saved headers, a test user signing in "
                                                             "outside the scope, or one already running"},
                                       429: {"description": "Queue full"}})
def domain_scan(context: Context = Depends(guard(Policy(admin=True, action="scan-domain", body=SCAN_BODY))),
                data: DomainScanIn = Depends(body(DomainScanIn, msg("sources.domains.invalid_request")))) -> Any:
    """Queues a passive scan of a verified domain with ZAP, never an attack: a crawl (web) or the GET and HEAD
    operations of an OpenAPI definition (api), optionally over listed subdomains, with the domain's saved headers and
    signed in as some of its test users.
    Off unless the full web scan is on (Settings → Analysis engines); one at a time."""
    launched = launch_domain_scan(context, data.domain_id, data=data)
    return context.render({"run_id": launched["run"]["id"], "run": launched["run"], "domain": _domain_rows(context, [launched["domain"]])[0]})


# --- AI providers ---------------------------------------------------------------------------------------------------

class ProviderKeyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Any
    action: Literal["remove"]


class ProviderIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Any


@router.get("/api/providers", response_model=Annotated[list[ProviderStatus], Field(max_length=len(PROVIDERS))], **AS_RETURNED)
def providers(context: Context = Depends(guard())) -> Any:
    return context.render(provider_status())


@router.post("/api/providers/keys", openapi_extra=documented(ProviderKeyIn), response_model=ProviderKeys, **AS_RETURNED)
def provider_keys(context: Context = Depends(guard(Policy(admin=True, action="save-ai-key", body=768))),
                  data: ProviderKeyIn = Depends(body(ProviderKeyIn, msg("integrations.ai.invalid_request")))) -> Any:
    """Removes a key saved by an earlier version. AI isn't used yet, so new keys can't be saved."""
    try:
        forget_provider_key(data.provider)
    except ProviderError as exc:
        raise ApiError(400, problem(exc)) from exc
    except (ValueError, TypeError) as exc:
        raise ApiError(400, msg("integrations.ai.invalid_request")) from exc
    return context.render({"providers": provider_status()})


@router.post("/api/providers/check", openapi_extra=documented(ProviderIn), response_model=ProviderCheck, **AS_RETURNED)
def provider_check(context: Context = Depends(guard(Policy(action="check-provider"))),
                   data: ProviderIn = Depends(body(ProviderIn, msg("integrations.code.invalid_provider")))) -> Any:
    try:
        return context.render(check_provider(data.provider))
    except (ValueError, TypeError) as exc:
        raise ApiError(400, msg("integrations.code.invalid_provider")) from exc


# --- GitHub App -----------------------------------------------------------------------------------------------------

LANDING_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"


def _landing(locale: str, port: int, title, detail) -> Response:
    """Minimal return page: no scripts, and a link back to the panel."""
    page = (f"<!doctype html><html lang={locale}><meta charset=utf-8><title>Pitangus</title>"
            "<style>body{font:15px system-ui,sans-serif;background:#0a0a0a;color:#eee;max-width:560px;margin:15vh auto;padding:0 20px}"
            "a{color:#fff}</style>"
            f"<h1>{html.escape(text(title, locale))}</h1><p>{html.escape(text(detail, locale))}</p>"
            f"<p><a href=\"{html.escape(public_url(port))}/#/integrations\">{html.escape(t('integrations.github.landing.back', locale))}</a></p>")
    return Response(page.encode("utf-8"), status_code=200,
                    headers={"content-type": "text/html; charset=utf-8", "content-security-policy": LANDING_CSP})


def github_status(data_dir, port: int, *, live: bool = False) -> dict:
    state = github_config()
    records = github_connections(data_dir)
    status = {**state, "connected": bool(records), "installation": records[0] if records else None,
              "installations": records, "public_url": public_url(port), "required_permissions": REQUIRED_PERMISSIONS}
    if live and state["configured"]:
        # Permissions change on GitHub without notice: read them there, not from what was stored when connecting.
        try:
            declared = app_permissions()
            current = []
            for record in records:
                try:
                    granted = installation_details(record["installation_id"]).get("permissions", {})
                    current.append({**record, "permissions": granted, "permission_review": permission_review(declared, granted)})
                except GitHubAppError:
                    current.append(record)
            status["installations"] = current
            status["installation"] = current[0] if current else None
            reviews = [row["permission_review"] for row in current if row.get("permission_review")]
            if reviews:
                summary = dict(reviews[0])
                for field in ("excess", "missing", "pending_acceptance"):
                    summary[field] = sorted({name for review in reviews for name in review[field]})
                status["permissions"] = summary
            else:
                status["permissions"] = permission_review(declared, declared)
        except GitHubAppError:
            status["permissions"] = None
    return status


def _attach(context: Context, installation_id: int) -> dict | None:
    """Stores an installation of OUR App: the id is checked with GitHub, never taken as given."""
    chosen = next((row for row in app_installations() if row["installation_id"] == installation_id), None)
    if chosen is None:
        return None
    details = installation_details(chosen["installation_id"])
    save_github(context.data_dir, chosen["installation_id"], details, (context.user or {}).get("username"))
    return chosen


@router.get("/api/integrations/github", response_model=GitHubStatus, **AS_RETURNED)
def github(context: Context = Depends(guard()), port: int = Depends(server_port)) -> Any:
    return context.render(github_status(context.data_dir, port, live=True))


class GitHubAppIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    app_id: Any
    private_key: Any


@router.post("/api/integrations/github/app", openapi_extra=documented(GitHubAppIn), response_model=GitHubStatus, **AS_RETURNED)
def github_app_credentials(context: Context = Depends(guard(Policy(admin=True, action="save-github-app", body=20_000))),
                           data: GitHubAppIn = Depends(body(GitHubAppIn, msg("api.invalid_request"))),
                           port: int = Depends(server_port)) -> Any:
    """App ID and private key pasted by an administrator: checked with GitHub and stored encrypted."""
    if github_config()["source"] == "environment":
        raise ApiError(409, msg("integrations.github.env_managed_change"))
    previous_app = github_config().get("app_id")
    try:
        verified = verify_app(data.app_id, data.private_key)
    except GitHubAppError as exc:
        raise ApiError(400, problem(exc)) from exc
    save_credentials(verified)
    if previous_app != verified["app_id"]:
        clear_github(context.data_dir)
    logging_setup.get("github").info("github_app_saved", extra={"user": context.user["username"], "reason": f"{verified['owner']}/{verified['slug']}"})
    return context.render({**github_status(context.data_dir, port, live=True), "events": verified["events"]})


class GitHubManifestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=github_manifest.NAME_MAX)
    organization: str | None = Field(None, max_length=39)
    any_account: bool = False


class GitHubManifest(Open):
    """Where the panel posts the manifest (`url`, with the state) and the manifest itself, as JSON text."""
    url: str
    manifest: str


@router.post("/api/integrations/github/manifest", openapi_extra=documented(GitHubManifestIn), response_model=GitHubManifest, **AS_RETURNED)
def github_manifest_start(request: Request, context: Context = Depends(guard(Policy(admin=True, action="create-github-app", body=512))),
                          data: GitHubManifestIn = Depends(body(GitHubManifestIn, msg("api.invalid_request")))) -> Any:
    """Starts creating the App on GitHub. GitHub sends the browser back to the origin the panel is open on (already
    checked against the allowed origins by the CSRF check)."""
    if github_config()["source"] == "environment":
        raise ApiError(409, msg("integrations.github.env_managed_change"))
    try:
        return github_manifest.start(context.data_dir, base_url=request.headers["origin"], user=context.user["username"],
                                     name=data.name, organization=data.organization, any_account=data.any_account)
    except GitHubAppError as exc:
        raise ApiError(400, problem(exc)) from exc


# GitHub's return after creating the App. Like /oauth/callback, it carries no session (SameSite=Strict cookie): the
# single-use state, created by an administrator, is what authorizes it.
@router.get(github_manifest.RETURN_PATH, response_class=Response, responses={200: {"content": {"text/html": {}}}, 303: {}})
def github_manifest_return(request: Request, code: str = "", state: str = "", context: Context = Depends(guard(Policy(public=True))),
                           port: int = Depends(server_port)) -> Response:
    locale = context.locale
    throttle = context.state.auth.throttle
    scope = f"github-manifest:{request.client.host if request.client else ''}"
    if throttle.reserve(scope):
        return _landing(locale, port, msg("integrations.github.landing.too_many"), msg("integrations.github.manifest.retry_later"))
    if github_config()["source"] == "environment":
        return _landing(locale, port, msg("integrations.github.manifest.not_created"), msg("integrations.github.env_managed_change"))
    previous_app = github_config().get("app_id")
    try:
        verified, user = github_manifest.finish(context.data_dir, code, state)
    except GitHubAppError as exc:
        return _landing(locale, port, msg("integrations.github.manifest.not_created"), exc.message)  # its catalog message
    throttle.succeeded(scope)
    save_credentials(verified)
    if previous_app != verified["app_id"]:
        clear_github(context.data_dir)
    logging_setup.get("github").info("github_app_created", extra={"user": user, "reason": f"{verified['owner']}/{verified['slug']}"})
    return RedirectResponse("/#/integrations", status_code=303)


class GitHubActionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["install", "detect", "connect", "disconnect", "forget_app"]
    installation_id: StrictInt = Field(None, gt=0)  # only to connect (required) or disconnect one installation

    @model_validator(mode="after")
    def _installation_scope(self):
        if "installation_id" in self.model_fields_set:
            if self.action not in ("disconnect", "connect"):
                raise ValueError("installation_id")
        elif self.action == "connect":
            raise ValueError("installation_id")
        return self


@router.post("/api/integrations/github", openapi_extra=documented(GitHubActionIn), response_model=GitHubStatus | InstallLink, **AS_RETURNED)
def github_action(context: Context = Depends(guard(Policy(admin=True, action="connect-github", body=256))),
                  data: GitHubActionIn = Depends(body(GitHubActionIn, msg("integrations.github.invalid_action"))),
                  port: int = Depends(server_port)) -> Any:
    action, data_dir = data.action, context.data_dir
    if action in ("disconnect", "forget_app"):
        if action == "forget_app" and github_config()["source"] == "environment":
            raise ApiError(409, msg("integrations.github.env_managed_remove"))
        installation_id = data.installation_id
        if installation_id is not None and installation_id not in github_installations(data_dir):
            raise ApiError(404, msg("integrations.github.not_connected"))
        to_forget = [installation_id] if installation_id is not None else github_installations(data_dir)
        clear_github(data_dir, installation_id)
        for current in to_forget:
            forget_installation(current)
        if action == "forget_app":
            forget_app()
        return context.render(github_status(data_dir, port))
    try:
        if action == "install":
            return {"url": install_url()}
        if action == "connect":
            if _attach(context, data.installation_id) is None:
                raise ApiError(404, msg("integrations.github.foreign_installation"))
            return context.render(github_status(data_dir, port, live=True))
        rows = app_installations()
        if not rows:
            raise ApiError(404, msg("integrations.github.not_installed"))
        connected = set(github_installations(data_dir))
        status = github_status(data_dir, port, live=True)
        status["available_installations"] = [{**row, "connected": row["installation_id"] in connected} for row in rows]
        return context.render(status)
    except GitHubAppError as exc:
        raise ApiError(400, problem(exc)) from exc


# Optional return after installing (the App's Setup URL). The SameSite=Strict cookie does not travel from github.com,
# so nothing is connected here: it hands the installation to the panel, where the administrator's session confirms it
# with one click and the server checks it belongs to our App (`connect`). No GitHub call from this public route.
@router.get("/oauth/callback", response_class=Response, responses={200: {"content": {"text/html": {}}}, 303: {}})
def github_callback(installation_id: str = "", context: Context = Depends(guard(Policy(public=True))),
                    port: int = Depends(server_port)) -> Response:
    if not installation_id.isdigit() or len(installation_id) > 19 or int(installation_id) == 0:
        return _landing(context.locale, port, msg("integrations.github.landing.no_installation"), msg("integrations.github.landing.no_installation_detail"))
    return RedirectResponse(f"/#/integrations?installation={int(installation_id)}", status_code=303)
