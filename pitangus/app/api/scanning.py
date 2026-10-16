"""Secret detection settings (Betterleaks and Trivy), organization defaults and per repository: anyone signed in reads
them (without the patterns unless an admin), an admin changes them. And which analysis engines run (Settings → Analysis
engines): only an admin sees and changes them."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field

from pitangus.app.api.deps import ApiError, Context, Policy, body as json_model, documented, guard
from pitangus.modules.findings import registry as findings_registry
from pitangus.modules.findings.exclusions import ASSET_KEY
from pitangus.modules.scanning import engine_switches, secret_rules
from pitangus.modules.scanning.engines import IMAGES
from pitangus.modules.scanning.secret_builtin_rules import DEFAULT_SECRET_RULES, OPT_IN_RULES, TRIVY_EQUIVALENTS
from pitangus.modules.runs.assets import overview as assets_overview
from pitangus.shared.i18n import msg

router = APIRouter(tags=["scanning"])

# Loose caps against oversized input; the precise limits (and their localized errors) are in secret_rules.
_TEXT = 2_000


class SecretAllowlist(BaseModel):
    """Regexes are matched against the detected secret; paths are globs relative to the repository root."""
    model_config = ConfigDict(extra="forbid")
    regexes: list[str] = Field(default_factory=list, max_length=200)
    paths: list[str] = Field(default_factory=list, max_length=200)
    stopwords: list[str] = Field(default_factory=list, max_length=200)


class SecretRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=200)
    description: str = Field(max_length=_TEXT)
    regex: str = Field(max_length=_TEXT)
    keywords: list[str] = Field(default_factory=list, max_length=50)


class SecretConfigIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowlist: SecretAllowlist
    rules: list[SecretRule] = Field(max_length=100)
    disabled_rules: list[str] = Field(max_length=400)
    enabled_rules: list[str] = Field(default_factory=list, max_length=10)  # opt-in built-ins turned on
    reason: str = Field(max_length=_TEXT)


class SecretHistoryEntry(BaseModel):
    at: str
    by: str
    reason: str | None
    changes: dict[str, dict[str, Annotated[list[str], Field(max_length=secret_rules.CHANGES_SHOWN)]]] = Field(default_factory=dict)


class SecretLimits(BaseModel):
    rules: int
    entries: int
    regex: int
    description: int
    keywords: int


class SecretAllowlistView(BaseModel):
    regexes: list[str] = Field(max_length=secret_rules.MAX_ENTRIES)
    paths: list[str] = Field(max_length=secret_rules.MAX_ENTRIES)
    stopwords: list[str] = Field(max_length=secret_rules.MAX_ENTRIES)


class SecretRuleView(BaseModel):
    id: str
    description: str
    regex: str
    keywords: list[str] = Field(max_length=secret_rules.MAX_KEYWORDS)


class SecretConfig(BaseModel):
    allowlist: SecretAllowlistView
    rules: list[SecretRuleView] = Field(max_length=secret_rules.MAX_RULES)
    disabled_rules: list[str] = Field(max_length=secret_rules.MAX_DISABLED)
    enabled_rules: list[str] = Field(default_factory=list, max_length=10)
    reason: str | None
    by: str | None
    at: str | None
    history: list[SecretHistoryEntry] = Field(max_length=secret_rules.HISTORY)
    limits: SecretLimits


class AssetSecretConfigIn(SecretConfigIn):
    key: str = Field(max_length=200)


class SecretCounts(BaseModel):
    rules: int
    disabled: int
    enabled: int = 0
    allowlist: int


class AssetSecretConfig(SecretConfig):
    """A repository's own entries, added to the defaults (`defaults` counts them) in its scans."""
    key: str
    defaults: SecretCounts


class BuiltinRule(BaseModel):
    id: str
    trivy: str | None
    opt_in: bool = False  # off unless turned on (secret_builtin_rules.OPT_IN_RULES)


class BuiltinRules(BaseModel):
    engine: str
    version: str
    rules: list[BuiltinRule] = Field(max_length=len(DEFAULT_SECRET_RULES))


HIDDEN = "••••••"
SENSITIVE = ("regexes", "stopwords")  # an allowlisted pattern may contain a real secret


def _view(settings: dict) -> dict:
    return {**settings, "history": list(reversed(settings["history"])), "limits": secret_rules.LIMITS}


def _redacted(view: dict) -> dict:
    """What a non-admin may see: the shape and counts, never the patterns themselves."""
    allowlist = {name: [HIDDEN] * len(items) if name in SENSITIVE else items for name, items in view["allowlist"].items()}
    rules = [{**rule, "regex": HIDDEN, "keywords": []} for rule in view["rules"]]
    history = [{**entry, "changes": {name: ({kind: [HIDDEN] * len(items) for kind, items in change.items()} if name in SENSITIVE else change)
                                     for name, change in (entry.get("changes") or {}).items()}} for entry in view["history"]]
    return {**view, "allowlist": allowlist, "rules": rules, "history": history}


@router.get("/api/secrets/config", response_model=SecretConfig)
def config(context: Context = Depends(guard())) -> dict:
    """What secret detection applies to every repository scan; only admins see (and change) the patterns."""
    view = _view(secret_rules.get(context.data_dir))
    return view if (context.user or {}).get("role") == "admin" else _redacted(view)


@router.post("/api/secrets/config", response_model=SecretConfig)
def save_config(body: SecretConfigIn,
                context: Context = Depends(guard(Policy(admin=True, action="save-secret-rules", body=200_000)))) -> dict:
    """Replaces the settings; takes effect from the next scan. A reason is required and kept in the history."""
    try:
        saved = secret_rules.save(context.data_dir, body.model_dump(exclude={"reason"}), reason=body.reason, user=context.user)
    except secret_rules.SecretRulesError as exc:
        raise ApiError(400, exc.message, **({"field": exc.field} if exc.field else {})) from exc
    return _view(saved)


def _asset_key(key: str) -> str:
    # Images don't run the repository secret engines: their settings would never apply.
    if not ASSET_KEY.fullmatch(key) or key.startswith("image:"):
        raise ApiError(400, msg("api.invalid_repository"))
    return key


def _asset_view(context: Context, key: str, settings: dict) -> dict:
    view = {**_view(settings), "key": key, "defaults": secret_rules.counts(secret_rules.get(context.data_dir))}
    return view if (context.user or {}).get("role") == "admin" else _redacted(view)


@router.get("/api/assets/secrets", response_model=AssetSecretConfig)
def asset_config(key: str = Query(max_length=200), context: Context = Depends(guard())) -> dict:
    """A repository's own secret detection entries (empty: it uses the defaults as they are)."""
    key = _asset_key(key)
    return _asset_view(context, key, secret_rules.get(context.data_dir, key))


@router.post("/api/assets/secrets", response_model=AssetSecretConfig)
def save_asset_config(body: AssetSecretConfigIn,
                      context: Context = Depends(guard(Policy(admin=True, action="save-asset-secret-rules", body=200_000)))) -> dict:
    """Replaces a repository's own entries; they add to the defaults from its next scan. A reason is required."""
    key = _asset_key(body.key)
    state = findings_registry.load(context.data_dir, key)
    name = state["name"] or next((row["name"] for row in assets_overview(context.data_dir) if row["key"] == key), None)
    if name is None and not state["findings"]:
        raise ApiError(404, msg("api.repository_not_found"))
    try:
        saved = secret_rules.save(context.data_dir, body.model_dump(exclude={"reason", "key"}), reason=body.reason,
                                  user=context.user, asset=key, name=name)
    except secret_rules.SecretRulesError as exc:
        raise ApiError(400, exc.message, **({"field": exc.field} if exc.field else {})) from exc
    return _asset_view(context, key, saved)


@router.get("/api/secrets/builtin-rules", response_model=BuiltinRules)
def builtin_rules(context: Context = Depends(guard())) -> dict:
    """Betterleaks' default rules (what can be turned off), with the Trivy rule that is turned off with each, if any."""
    return {"engine": "betterleaks", "version": IMAGES["betterleaks"]["version"],
            "rules": [{"id": rule, "trivy": TRIVY_EQUIVALENTS.get(rule), "opt_in": rule in OPT_IN_RULES} for rule in DEFAULT_SECRET_RULES]}


# --- Analysis engines ---------------------------------------------------------------------------------------------

class EngineSwitchRow(BaseModel):
    """One engine (or the full web scan, `dast`) as it stands: on or off, why (`source`: pinned by the server's
    environment variable `setting`, chosen in the panel, or the default), who changed it last, and its images on the
    worker's server (`image`: unknown until a worker reports)."""
    key: str
    name: str
    version: str
    group: Literal["code", "secrets", "infrastructure", "images", "web"]
    covers: list[str] = Field(max_length=10)
    requires: str | None
    enabled: bool
    default: bool
    locked: bool
    source: Literal["server", "workspace", "default"]
    setting: str
    changed_by: str | None
    changed_at: str | None
    image: Literal["ready", "missing", "preparing", "unknown", "built_in"]
    image_problem: str | None


class EngineSwitchChange(BaseModel):
    engine: str
    enabled: bool
    by: str | None
    at: str | None


class EngineSwitches(BaseModel):
    engines: list[EngineSwitchRow] = Field(max_length=len(engine_switches.SWITCHES))
    # Kinds of check no engine that is on makes (engine_switches.CAPABILITIES)
    uncovered: list[str] = Field(max_length=len(engine_switches.CAPABILITIES))
    images_checked_at: str | None
    history: list[EngineSwitchChange] = Field(max_length=engine_switches.HISTORY_SHOWN)


class EngineSwitchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    engine: str = Field(max_length=40)
    enabled: bool


class EnginePrepareIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    engine: str = Field(max_length=40)


def _engines_view(context: Context) -> dict:
    switches = engine_switches.resolve(context.data_dir)
    images = engine_switches.image_status(context.data_dir)
    rows = []
    for switch in engine_switches.SWITCHES:
        state, meta, image = switches[switch.key], IMAGES[switch.images[0]], images["engines"][switch.key]
        rows.append({"key": switch.key, "name": meta["name"], "version": meta["version"], "group": switch.group,
                     "covers": list(switch.covers), "requires": switch.requires, "enabled": state["enabled"],
                     "default": switch.default, "locked": state["locked"], "source": state["source"], "setting": switch.setting,
                     "changed_by": state["by"], "changed_at": state["at"], "image": image["status"], "image_problem": image["problem"]})
    return context.render({"engines": rows, "uncovered": engine_switches.uncovered(switches),
                           "images_checked_at": images["checked_at"], "history": engine_switches.history(context.data_dir)})


@router.get("/api/engines", response_model=EngineSwitches)
def engines(context: Context = Depends(guard(Policy(admin=True)))) -> dict:
    """Which analysis engines run in every scan, and whether each one's images are on the worker's server."""
    return _engines_view(context)


@router.post("/api/engines", response_model=EngineSwitches, openapi_extra=documented(EngineSwitchIn))
def switch_engine(context: Context = Depends(guard(Policy(admin=True, action="engine-switch", body=512))),
                  body: EngineSwitchIn = Depends(json_model(EngineSwitchIn, msg("api.invalid_parameters")))) -> dict:
    """Turns an engine on or off from the next scan; kept in the history. One the server pins (its environment variable
    is set) can't be changed here. Off, its step says «not run (disabled)» and what it found before stays open. On, its
    missing images are queued for download at once."""
    try:
        engine_switches.set_switch(context.data_dir, body.engine, body.enabled, user=context.user)
    except engine_switches.SwitchError as exc:
        raise ApiError(409 if body.engine in engine_switches.BY_KEY else 400, exc.message) from exc
    if body.enabled:
        # Turned on: its images (and those of what it lets run, katana with the full web scan) are prepared right away.
        switches, images = engine_switches.resolve(context.data_dir), engine_switches.image_status(context.data_dir)["engines"]
        for switch in engine_switches.SWITCHES:
            if body.engine in (switch.key, switch.requires) and engine_switches.is_on(switches, switch.key) \
                    and images[switch.key]["status"] in ("missing", "unknown"):
                context.state.jobs.prepare_engine(switch.key, by=context.user["username"], automatic=True)
    return _engines_view(context)


@router.post("/api/engines/prepare", response_model=EngineSwitches, openapi_extra=documented(EnginePrepareIn))
def prepare_engine(context: Context = Depends(guard(Policy(admin=True, action="prepare-engine", body=512))),
                   body: EnginePrepareIn = Depends(json_model(EnginePrepareIn, msg("api.invalid_parameters")))) -> dict:
    """Queues the download of an engine's images, pinned by digest, on the worker's server (the worker also does it on its
    own for every engine that is on; this retries at once). Until they are there, scans declare that engine not run."""
    if body.engine not in engine_switches.BY_KEY:
        raise ApiError(400, msg("scanning.switches.errors.unknown"))
    context.state.jobs.prepare_engine(body.engine, by=context.user["username"])  # once while one is under way
    return _engines_view(context)
