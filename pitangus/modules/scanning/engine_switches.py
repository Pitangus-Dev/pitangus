"""Which analysis engines run: the workspace's switches (Settings → Analysis engines) and the environment that can pin them.

Precedence, the same everywhere an engine is about to run or be offered: a `PITANGUS_<ENGINE>_ENABLED` set in the
server's environment wins and locks the switch (the panel shows it fixed by the server); otherwise the workspace's
choice (document `engine-switches`) applies; otherwise the default (every engine on but Checkov, Grype and the full web
scan). An engine turned off is declared "not run (disabled)" in every run, never a clean pass: what it found before
stays open and is never fixed (findings/registry, `engine_off`).

The engines' images are the worker's business (the API may have no Docker): it records which are on this server
(document `engine-images`) and pulls by digest the images of every engine that is on and lacks them: when one is
turned on, on its own every few minutes (an upgrade may change a digest) and when an administrator asks ("Prepare
engine"). A scan never pulls one mid-run.
"""

from __future__ import annotations

import contextvars
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pitangus.shared import db, documents, settings
from pitangus.shared import log as logging_setup
from pitangus.shared.i18n import msg, text

DOCUMENT = "engine-switches"
IMAGES_DOCUMENT = "engine-images"
HISTORY_MAX = 100
HISTORY_SHOWN = 20
# A preparation that never reported back (the worker died mid-pull; pulls time out at an hour) stops counting as one.
PREPARING_STALE = timedelta(hours=2)
# After a failed automatic preparation (offline, registry down), the worker waits this long before trying again on its
# own; "Prepare engine" retries at once.
RETRY_AFTER = timedelta(hours=1)
_log = logging_setup.get("engines")


@dataclass(frozen=True)
class Switch:
    key: str                  # the engine's key in engines.IMAGES, or "dast" (the full web scan: ZAP and subfinder)
    setting: str              # the environment variable that pins it
    default: bool
    group: str                # code, secrets, infrastructure, images, web: what the panel groups it under
    images: tuple[str, ...]   # the engines.IMAGES keys it needs
    covers: tuple[str, ...]   # the kinds of check it takes part in (CAPABILITIES)
    requires: str | None = None


SWITCHES: tuple[Switch, ...] = (
    Switch("opengrep", "PITANGUS_OPENGREP_ENABLED", True, "code", ("opengrep",), ("sast",)),
    Switch("trivy", "PITANGUS_TRIVY_ENABLED", True, "code", ("trivy",), ("dependencies", "secrets", "iac", "images")),
    Switch("osv-scanner", "PITANGUS_OSV_SCANNER_ENABLED", True, "code", ("osv-scanner",), ("dependencies",)),
    Switch("betterleaks", "PITANGUS_BETTERLEAKS_ENABLED", True, "secrets", ("betterleaks",), ("secrets",)),
    Switch("checkov", "PITANGUS_CHECKOV_ENABLED", False, "infrastructure", ("checkov",), ("iac", "pipelines")),
    Switch("zizmor", "PITANGUS_ZIZMOR_ENABLED", True, "infrastructure", ("zizmor",), ("pipelines",)),
    Switch("grype", "PITANGUS_GRYPE_ENABLED", False, "images", ("grype",), ("images",)),
    Switch("httpx", "PITANGUS_HTTPX_ENABLED", True, "web", ("httpx",), ("exposure",)),
    Switch("testssl", "PITANGUS_TESTSSL_ENABLED", True, "web", ("testssl",), ("exposure",)),
    Switch("nuclei", "PITANGUS_NUCLEI_ENABLED", True, "web", ("nuclei",), ("exposure",)),
    Switch("dast", "PITANGUS_DAST_ENABLED", False, "web", ("zap", "subfinder"), ("dast",)),
    Switch("katana", "PITANGUS_KATANA_ENABLED", True, "web", ("katana",), ("dast",), requires="dast"),
)
BY_KEY = {switch.key: switch for switch in SWITCHES}
GROUPS = ("code", "secrets", "infrastructure", "images", "web")
# Which switch an image belongs to (ZAP and subfinder are the full web scan's).
SWITCH_OF = {image: switch.key for switch in SWITCHES for image in switch.images}
# The kinds of check a scan makes and the engines that make them. One left with no engine on is said in the panel and in
# every run it concerns: nothing checks it, which is never the same as "nothing found". The full web scan is a mode the
# operator turns on, not a check that goes missing.
CAPABILITIES = {capability: tuple(switch.key for switch in SWITCHES if capability in switch.covers)
                for capability in ("sast", "dependencies", "secrets", "iac", "pipelines", "images", "exposure")}


# Whether this is an analysis the server's worker runs (a job), or a one-shot scan with no server behind it (`pitangus
# scan`, the GitHub Action, the pre-commit hook). The wording of a step depends on it (the panel exists only for the
# former), and so does what a missing image means (engines.unavailable).
_server_analysis: contextvars.ContextVar[bool] = contextvars.ContextVar("pitangus_server_analysis", default=False)


@contextmanager
def server_analysis():
    token = _server_analysis.set(True)
    try:
        yield
    finally:
        _server_analysis.reset(token)


def in_server_analysis() -> bool:
    return _server_analysis.get()


class SwitchError(ValueError):
    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _stored(data_dir: Path | None) -> dict:
    if data_dir is None:
        return {}
    try:
        stored = documents.load(data_dir, DOCUMENT, {})
    except db.DatabaseNotConfigured:  # a scan without a database (tests, a bare CLI): the environment and the defaults
        return {}
    return stored if isinstance(stored, dict) else {}


def resolve(data_dir: Path | None) -> dict[str, dict]:
    """Every switch as it stands: {key: {enabled, locked, source (server, workspace or default), setting, by, at}}."""
    chosen = _stored(data_dir).get("engines")
    chosen = chosen if isinstance(chosen, dict) else {}
    found = {}
    for switch in SWITCHES:
        entry = chosen.get(switch.key) if isinstance(chosen.get(switch.key), dict) else None
        base = {"setting": switch.setting, "by": (entry or {}).get("by"), "at": (entry or {}).get("at")}
        if settings.is_set(switch.setting):
            found[switch.key] = {**base, "enabled": settings.flag(switch.setting), "locked": True, "source": "server"}
        elif entry is not None and isinstance(entry.get("enabled"), bool):
            found[switch.key] = {**base, "enabled": entry["enabled"], "locked": False, "source": "workspace"}
        else:
            found[switch.key] = {**base, "enabled": switch.default, "locked": False, "source": "default"}
    return found


def all_on() -> dict[str, dict]:
    """Every switch on: for replaying recorded engine outputs (the demo), which show what was recorded."""
    return {switch.key: {"setting": switch.setting, "by": None, "at": None, "enabled": True, "locked": False, "source": "default"}
            for switch in SWITCHES}


def is_on(switches: dict[str, dict], engine: str) -> bool:
    """Whether `engine` (an engines.IMAGES key, or a switch's) runs under `switches`; one without a switch always does."""
    key = SWITCH_OF.get(engine, engine)
    switch = BY_KEY.get(key)
    if switch is None:
        return True
    return bool(switches[key]["enabled"]) and (switch.requires is None or bool(switches[switch.requires]["enabled"]))


def enabled(engine: str, data_dir: Path | None) -> bool:
    return is_on(resolve(data_dir), engine)


def off_reason(switches: dict[str, dict], engine: str, name: str):
    """Why `engine` (named `name`) won't run, for its step: turned off in the panel, or by the server's environment
    (then its variable is named, since the panel can't change it). A one-shot scan has no panel: its step names the
    variable that turns the engine on. None if it runs."""
    if is_on(switches, engine):
        return None
    state = switches[SWITCH_OF.get(engine, engine)]
    if not state["enabled"] and state["locked"]:
        return msg("scanning.engines.disabled_by_server", engine=name, setting=state["setting"])
    if not in_server_analysis():
        return msg("scanning.engines.disabled_here", engine=name, setting=state["setting"])
    return msg("scanning.engines.disabled", engine=name)


def mode_off(switches: dict[str, dict], key: str, message: str):
    """Why a feature that needs switch `key` (the full web scan, say) is unavailable: catalog `message` when the panel
    turned it off, `message`_by_server (naming the variable) when the server pinned it off; None if it's on."""
    state = switches[key]
    if state["enabled"]:
        return None
    return msg(f"{message}_by_server", setting=state["setting"]) if state["locked"] else msg(message)


def uncovered(switches: dict[str, dict], capabilities=None) -> list[str]:
    """The kinds of check (of `capabilities`, or all) no engine that is on makes."""
    return [capability for capability, keys in CAPABILITIES.items()
            if (capabilities is None or capability in capabilities) and not any(switches[key]["enabled"] for key in keys)]


def uncovered_limitations(switches: dict[str, dict], capabilities) -> list[dict]:
    """One limitation per kind of check of a scan that no engine made because every engine for it is off."""
    return [msg("scanning.switches.uncovered", what=msg(f"scanning.switches.capability.{capability}"))
            for capability in uncovered(switches, capabilities)]


def set_switch(data_dir: Path, key: str, on: bool, *, user: dict) -> dict:
    """Turns an engine on or off for every scan from the next one; the change is kept in the history and logged."""
    switch = BY_KEY.get(key)
    if switch is None:
        raise SwitchError(msg("scanning.switches.errors.unknown"))
    if settings.is_set(switch.setting):
        raise SwitchError(msg("scanning.switches.errors.locked", setting=switch.setting))
    by = str(user.get("username") or "")[:200]
    with documents.lock(data_dir, DOCUMENT):
        stored = _stored(data_dir)
        engines = {name: entry for name, entry in (stored.get("engines") or {}).items() if name in BY_KEY and isinstance(entry, dict)}
        before = resolve(data_dir)[key]["enabled"]
        entry = {"enabled": bool(on), "by": by, "at": _now()}
        engines[key] = entry
        history = [item for item in stored.get("history") or [] if isinstance(item, dict)]
        history = [*history, {"engine": key, "enabled": bool(on), "was": before, "by": by, "at": entry["at"]}][-HISTORY_MAX:]
        documents.save(data_dir, DOCUMENT, {"engines": engines, "history": history})
    _log.info("engine_switched", extra={"user": by, "reason": f"{key} {'on' if on else 'off'} (was {'on' if before else 'off'})"})
    return resolve(data_dir)[key]


def history(data_dir: Path) -> list[dict]:
    """The latest changes, newest first."""
    items = [item for item in _stored(data_dir).get("history") or [] if isinstance(item, dict) and item.get("engine") in BY_KEY]
    return [{"engine": item["engine"], "enabled": item.get("enabled") is True, "by": item.get("by"), "at": item.get("at")}
            for item in reversed(items[-HISTORY_SHOWN:])]


# --- Images ------------------------------------------------------------------------------------------------------

def _images_state(data_dir: Path) -> dict:
    stored = documents.load(data_dir, IMAGES_DOCUMENT, {})
    return stored if isinstance(stored, dict) else {}


def record_images(data_dir: Path, ready: dict[str, bool], *, runner: str) -> None:
    """What the worker found on its server: {image key: present}. Read by the panel; a scan checks again itself."""
    with documents.edit(data_dir, IMAGES_DOCUMENT, {}) as state:
        state.update({"checked_at": _now(), "runner": runner, "images": {key: bool(value) for key, value in ready.items()}})


def _since(entry) -> timedelta | None:
    try:
        return datetime.now(timezone.utc) - datetime.fromisoformat(str((entry or {}).get("at")))
    except (ValueError, TypeError):  # unreadable, or without a timezone: not a moment to count from
        return None


def _preparing(entry) -> bool:
    age = _since(entry)
    return entry is not None and age is not None and age < PREPARING_STALE


def prepare_requested(data_dir: Path, key: str, *, by: str, enqueue: Callable[[], None], automatic: bool = False) -> bool:
    """Marks switch `key`'s images as being prepared and, in the same transaction, queues the job (`enqueue`): once, while
    one is under way. `automatic` (the worker or a switch turned on, not the button) also waits RETRY_AFTER after a
    failure. Whether it queued one."""
    if key not in BY_KEY:
        raise SwitchError(msg("scanning.switches.errors.unknown"))
    by = by[:200]
    with documents.edit(data_dir, IMAGES_DOCUMENT, {}) as state:
        if _preparing((state.get("preparing") or {}).get(key)):
            return False
        failed = (state.get("failed") or {}).get(key)
        if automatic and failed is not None and (age := _since(failed)) is not None and age < RETRY_AFTER:
            return False
        state.setdefault("preparing", {})[key] = {"by": by, "at": _now()}
        (state.get("failed") or {}).pop(key, None)
        enqueue()
    _log.info("engine_prepare_requested", extra={"user": by, "reason": key})
    return True


def missing_images(switches: dict[str, dict], ready: dict[str, bool], pinned: set[str]) -> list[str]:
    """The switches that are on and lack one of their published (`pinned`) images: what the worker prepares on its own."""
    return [switch.key for switch in SWITCHES if is_on(switches, switch.key)
            and any(image in pinned and not ready.get(image) for image in switch.images)]


def prepare_finished(data_dir: Path, key: str, *, ready: dict[str, bool], runner: str, problem=None) -> None:
    with documents.edit(data_dir, IMAGES_DOCUMENT, {}) as state:
        (state.get("preparing") or {}).pop(key, None)
        state.setdefault("images", {}).update({image: bool(value) for image, value in ready.items()})
        state.update({"checked_at": _now(), "runner": runner})
        failed = state.setdefault("failed", {})
        if problem is None:
            failed.pop(key, None)
        else:
            failed[key] = {"at": _now(), "problem": problem}


def image_status(data_dir: Path) -> dict:
    """Each switch's images on the worker's server: {key: {status, problem}}, status one of ready, missing, preparing,
    unknown (no worker has reported yet) and built_in (the worker runs installed engines; nothing to download)."""
    state = _images_state(data_dir)
    images, preparing, failed = state.get("images") or {}, state.get("preparing") or {}, state.get("failed") or {}
    found = {}
    for switch in SWITCHES:
        problem = (failed.get(switch.key) or {}).get("problem")
        if _preparing(preparing.get(switch.key)):
            status = "preparing"
        elif not state.get("checked_at") or any(image not in images for image in switch.images):
            status = "unknown"
        elif all(images[image] for image in switch.images):
            status = "built_in" if state.get("runner") == "local" else "ready"
        else:
            status = "missing"
        found[switch.key] = {"status": status, "problem": problem}
    return {"checked_at": state.get("checked_at"), "runner": state.get("runner"), "engines": found}
