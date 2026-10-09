"""Code sources (GitHub App and tokens), domains and AI provider keys. Jira is `jira.py`."""

from __future__ import annotations

import html
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, model_validator

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
from pitangus.modules.sources import assets as source_assets
from pitangus.modules.sources import domains
from pitangus.modules.sources.assets import with_scan_branches
from pitangus.modules.sources.domains import DomainError
from pitangus.modules.sources.repositories import SourceError, find_source, list_repositories, source_page, unavailable
from pitangus.shared import log as logging_setup
from pitangus.shared.i18n import msg, t, text

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
# A registered domain whose DNS TXT proof is current is the asset `domain:<host>` that `import-sarif` accepts for
# findings of web scanners (ZAP, Nuclei…). Nothing here scans anything: the only outgoing traffic is one DNS TXT
# lookup when verifying and one single-hop HTTPS HEAD when an administrator probes a domain before adding it, both
# behind the administrator role and the progressive lock-out.

class DomainRow(Open):
    """A registered domain. `verified` means its TXT proof is current (`verified_until` lies ahead); the TXT record
    itself (`txt_name`, `txt_value`) is only answered to administrators. `runs` and `open` say what was imported
    against it."""
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
    txt_name: str | None = None
    txt_value: str | None = None
    runs: int = 0
    open: int = 0


class DomainPage(Open):
    items: list[DomainRow] = Field(max_length=domains.LIMIT)
    total: int
    limit: int


class DomainCheck(Open):
    host: str
    reachable: bool
    status: str
    detail: str
    http_status: int | None = None


class DomainRemoved(Open):
    id: str
    host: str
    runs_deleted: int


def _domain_rows(context: Context, records: list[dict]) -> list[dict]:
    """Rows for the reader: what was imported against each domain, and the TXT record for administrators only."""
    from pitangus.modules.findings import registry as findings_registry
    from pitangus.modules.runs.store import find_runs
    admin = (context.user or {}).get("role") == "admin"
    counted: dict[str, int] = {}
    for row in find_runs(context.data_dir, assets=[record["key"] for record in records]):
        counted[row.get("asset_key") or source_assets.asset_key(row)] = counted.get(row.get("asset_key") or source_assets.asset_key(row), 0) + 1
    rows = []
    for record in records:
        runs = counted.get(record["key"], 0)
        shown = {name: value for name, value in record.items() if admin or name not in ("txt_name", "txt_value")}
        rows.append({**shown, "runs": runs, "open": findings_registry.summarize(context.data_dir, record["key"])["open"] if runs else 0})
    return rows


@router.get("/api/domains", response_model=DomainPage, **AS_RETURNED)
def domain_list(context: Context = Depends(guard())) -> Any:
    """The registered domains (at most `limit`), with whether each one's TXT proof is current."""
    records = domains.list_domains(context.data_dir)
    return context.render({"items": _domain_rows(context, records), "total": len(records), "limit": domains.LIMIT})


class DomainIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: StrictStr = Field(max_length=300)
    kind: Literal["web", "api", "surface"] = "web"
    context: StrictStr = Field("", max_length=domains.CONTEXT_LIMIT)


class DomainIdIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain_id: StrictStr = Field(pattern="^[0-9a-f]{24}$")


class DomainCheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: StrictStr = Field(max_length=300)


def _attempt(context: Context, scope: str) -> None:
    """Counts an outgoing lookup against the progressive lock-out (DNS and HTTPS probes aren't free to repeat)."""
    wait = context.state.auth.throttle.reserve(scope)
    if wait:
        raise ApiError(429, msg("sources.domains.too_many_attempts", seconds=wait), retry_in=wait)


@router.post("/api/domains", response_model=DomainRow, openapi_extra=documented(DomainIn), **AS_RETURNED)
def domain_register(context: Context = Depends(guard(Policy(admin=True, action="register-domain", body=2048))),
                    data: DomainIn = Depends(body(DomainIn, msg("sources.domains.invalid_request")))) -> Any:
    """Registers an HTTPS domain and answers the TXT record that proves control of it. Nothing is tested."""
    try:
        record = domains.register_domain(context.data_dir, data.url, data.kind, data.context, by=context.user["username"])
    except DomainError as exc:
        raise ApiError(400, exc.message) from exc
    context.state.log.info("domain_registered", extra={"user": context.user["username"], "reason": record["host"]})
    return context.render(_domain_rows(context, [record])[0])


@router.post("/api/domains/verify", response_model=DomainRow, openapi_extra=documented(DomainIdIn), **AS_RETURNED,
             responses={404: {"description": "Unknown domain"}, 429: {"description": "Too many attempts"}})
def domain_verify(context: Context = Depends(guard(Policy(admin=True, action="verify-domain", body=256))),
                  data: DomainIdIn = Depends(body(DomainIdIn, msg("sources.domains.invalid_request")))) -> Any:
    """Looks the domain's TXT record up once. Seen, the domain is an asset for 90 days; a daily re-check extends or
    withdraws the proof."""
    try:
        domains.get_domain(context.data_dir, data.domain_id)
    except DomainError as exc:
        raise ApiError(404, exc.message) from exc
    _attempt(context, f"domain-verify:{data.domain_id}")
    try:
        record = domains.verify_domain(context.data_dir, data.domain_id)
    except DomainError as exc:
        raise ApiError(400, exc.message) from exc
    context.state.auth.throttle.succeeded(f"domain-verify:{data.domain_id}")
    context.state.log.info("domain_verified", extra={"user": context.user["username"], "reason": record["host"]})
    return context.render(_domain_rows(context, [record])[0])


@router.post("/api/domains/check", response_model=DomainCheck, openapi_extra=documented(DomainCheckIn), **AS_RETURNED,
             responses={429: {"description": "Too many attempts"}})
def domain_check(context: Context = Depends(guard(Policy(admin=True, action="check-domain", body=1024))),
                 data: DomainCheckIn = Depends(body(DomainCheckIn, msg("sources.domains.invalid_request")))) -> Any:
    """Whether the domain answers over HTTPS: one HEAD to its already-resolved public address, no redirects. Only a
    hint before registering; a domain that doesn't answer can still be registered."""
    _attempt(context, f"domain-check:{context.user['username']}")
    try:
        result = domains.check_reachability(data.url)
    except DomainError as exc:
        raise ApiError(400, exc.message) from exc
    if result["reachable"]:
        context.state.auth.throttle.succeeded(f"domain-check:{context.user['username']}")
    return context.render(result)


@router.post("/api/domains/remove", response_model=DomainRemoved, openapi_extra=documented(DomainIdIn), **AS_RETURNED,
             responses={404: {"description": "Unknown domain"}})
def domain_remove(context: Context = Depends(guard(Policy(admin=True, action="remove-domain", body=256))),
                  data: DomainIdIn = Depends(body(DomainIdIn, msg("sources.domains.invalid_request")))) -> Any:
    """Removes a domain. What was imported against it (runs, findings, their triage and tickets) goes with it, like a
    repository that left the installation: the panel says so before asking."""
    from pitangus.modules.runs import assets as run_assets
    from pitangus.modules.runs.store import find_runs
    try:
        record = domains.get_domain(context.data_dir, data.domain_id)
    except DomainError as exc:
        raise ApiError(404, exc.message) from exc
    deleted = run_assets.purge(context.data_dir, record["key"]) if find_runs(context.data_dir, assets=[record["key"]], limit=1) else 0
    domains.remove_domain(context.data_dir, data.domain_id)
    context.state.log.warning("domain_removed", extra={"user": context.user["username"], "reason": f"{record['host']}: {deleted} runs"})
    return {"id": record["id"], "host": record["host"], "runs_deleted": deleted}


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
        return _landing(locale, port, msg("integrations.github.manifest.not_created"), problem(exc))
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
