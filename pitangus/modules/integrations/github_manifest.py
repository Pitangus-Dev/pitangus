"""Creating the GitHub App from the panel (GitHub's manifest flow): two clicks instead of copying values by hand.

The panel posts a manifest (name, permissions, return address) to GitHub, the administrator confirms there and
GitHub sends the browser back with a one-time code that this server exchanges for the App's ID and private key. The
App is still theirs: it is created on their account, and its key only travels from GitHub to this server.

- **state**: random, tied to the administrator who started the flow, single-use and valid for an hour (as long as
  GitHub's code). Only its SHA-256 is stored, in PostgreSQL, so any instance of the API can finish the flow.
- The return carries no session (the cookie is SameSite=Strict and the navigation comes from github.com): the state
  is what proves that an administrator of this instance started it.
- No webhook: the panel polls pull requests itself, so the instance needn't be reachable from the internet.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request

from pitangus.modules.integrations.github import (API, APP_ID, OWNER, REQUIRED_PERMISSIONS, WEB, GitHubAppError,
                                                  verify_app)
from pitangus.shared import documents, http
from pitangus.shared.i18n import msg
from pitangus.version import USER_AGENT

DOCUMENT = "github_manifest_states"
STATE_TTL = 3600
MAX_PENDING = 20
# GitHub's limit for an App's name.
NAME_MAX = 34
RETURN_PATH = "/github/app-created"
SETUP_PATH = "/oauth/callback"
HOMEPAGE = "https://pitangus.dev"
NAME = re.compile(r"[^\x00-\x1f\x7f]{1,34}")
CODE = re.compile(r"[A-Za-z0-9_-]{1,100}")
STATE = re.compile(r"[A-Za-z0-9_-]{32,100}")


def _digest(state: str) -> str:
    return hashlib.sha256(state.encode()).hexdigest()


def start(data_dir: Path, *, base_url: str, user: str, name: str, organization: str | None = None,
          any_account: bool = False) -> dict:
    """The GitHub form to post the manifest to (`url`, with the state) and the manifest itself, as GitHub wants it."""
    name, organization = name.strip(), (organization or "").strip()
    if not NAME.fullmatch(name):
        raise GitHubAppError(msg("integrations.github.manifest.invalid_name", max=NAME_MAX))
    if organization and not OWNER.fullmatch(organization):
        raise GitHubAppError(msg("integrations.github.manifest.invalid_organization"))
    state, now = secrets.token_urlsafe(32), time.time()
    with documents.edit(data_dir, DOCUMENT, {}) as pending:
        for key in [key for key, entry in pending.items() if entry.get("expires", 0) <= now]:
            del pending[key]
        # Abandoned attempts can't pile up: the oldest goes first.
        for key in sorted(pending, key=lambda key: pending[key]["expires"])[:max(0, len(pending) - MAX_PENDING + 1)]:
            del pending[key]
        pending[_digest(state)] = {"user": user, "expires": now + STATE_TTL}
    base_url = base_url.rstrip("/")
    manifest = {
        "name": name, "url": base_url if base_url.startswith("https://") else HOMEPAGE,
        "redirect_url": base_url + RETURN_PATH, "setup_url": base_url + SETUP_PATH, "setup_on_update": True,
        "public": any_account, "request_oauth_on_install": False,
        "default_permissions": dict(REQUIRED_PERMISSIONS), "default_events": [],
    }
    form = f"{WEB}/organizations/{quote(organization)}/settings/apps/new" if organization else f"{WEB}/settings/apps/new"
    return {"url": f"{form}?state={state}", "manifest": json.dumps(manifest)}


def finish(data_dir: Path, code: str, state: str) -> tuple[dict, str]:
    """Exchanges GitHub's code for the App and checks it; returns it (as `verify_app` does) and who started the flow.

    The state is spent before calling GitHub, so the same return can't be replayed.
    """
    if not CODE.fullmatch(code or "") or not STATE.fullmatch(state or ""):
        raise GitHubAppError(msg("integrations.github.manifest.invalid_return"))
    with documents.edit(data_dir, DOCUMENT, {}) as pending:
        entry = pending.pop(_digest(state), None)
    if not entry or entry.get("expires", 0) <= time.time():
        raise GitHubAppError(msg("integrations.github.manifest.expired"))
    created = _convert(code)
    app_id, pem = str(created.get("id") or ""), created.get("pem")
    if not APP_ID.fullmatch(app_id) or not isinstance(pem, str):
        raise GitHubAppError(msg("integrations.github.unexpected_app"))
    return verify_app(app_id, pem), entry["user"]


def _convert(code: str) -> dict:
    """GitHub answers the App with its key, client secret and webhook secret; only the ID and the key are kept."""
    request = Request(f"{API}/app-manifests/{quote(code)}/conversions", data=b"", method="POST", headers={
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": USER_AGENT})
    try:
        with http.opener().open(request, timeout=15) as response:
            payload = json.loads(response.read(200_000))
    except HTTPError as exc:
        if exc.code in (404, 422):
            raise GitHubAppError(msg("integrations.github.manifest.code_rejected")) from exc
        raise GitHubAppError(msg("integrations.github.rejected_app", code=exc.code)) from exc
    except (URLError, TimeoutError, OSError, ValueError, UnicodeDecodeError) as exc:
        raise GitHubAppError(msg("integrations.github.unreachable")) from exc
    if not isinstance(payload, dict):
        raise GitHubAppError(msg("integrations.github.unexpected_app"))
    return payload
