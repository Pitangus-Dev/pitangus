"""First steps, worked out from the real state (nothing is ticked by hand): the Summary shows them until they are done."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from pitangus.app.api.deps import Context, guard
from pitangus.app.demo import DEMO_SOURCE_ID
from pitangus.modules.findings.kinds import FULL_SCANS, IMPORT_RUNS
from pitangus.modules.integrations import code_tokens, notifications
from pitangus.modules.integrations.installations import github_installations
from pitangus.modules.pullrequests import watch as pr_watch
from pitangus.modules.runs.store import find_runs
from pitangus.shared import settings

router = APIRouter(tags=["onboarding"])


class Onboarding(BaseModel):
    mfa: bool  # this person's account has TOTP on
    github: bool  # the GitHub App installed, or a GitHub token (panel or environment)
    analyzed: bool  # a finished scan or import of your own (the demo doesn't count; an incomplete scan does)
    demo: bool
    watching: bool  # a repository's pull requests and branch watched, or pull requests reviewed (e.g. by the Action)
    alerts: bool  # a Slack, Teams or webhook channel
    admin: bool


def _demo(row: dict) -> bool:
    """Demo data: the bundled samples or the fictional organization (`pitangus demo --full`)."""
    source = row.get("source") or {}
    return source.get("id") == DEMO_SOURCE_ID or source.get("demo") is True


FINISHED = ("completed", "incomplete")  # an incomplete scan still analyzed the code: only failed or cancelled ones didn't


def _github(data_dir) -> bool:
    try:
        tokens = code_tokens.current()
    except Exception:  # noqa: BLE001 — an unreadable vault only leaves the token out
        tokens = {}
    return bool(github_installations(data_dir)) or bool(tokens.get("github")) or settings.is_set("GITHUB_TOKEN")


@router.get("/api/onboarding", response_model=Onboarding)
def onboarding(context: Context = Depends(guard())) -> dict:
    """Each step from the state it stands for, wherever it was done (this card, Integrations, Pull requests, the
    account page, the CLI): nothing is ticked by clicking."""
    user, data_dir = context.user, context.data_dir
    finished = [row for row in find_runs(data_dir, types=FULL_SCANS + IMPORT_RUNS + ("pr_review",), statuses=FINISHED) if not _demo(row)]
    try:
        alerts = bool(notifications.channels())
    except Exception:  # noqa: BLE001 — without a readable vault the step simply stays pending
        alerts = False
    watched = any(config.get("enabled") for config in pr_watch.load(data_dir, reviews=False)["repositories"].values())
    return {
        "mfa": bool((user.get("totp") or {}).get("enabled")),
        "github": _github(data_dir),
        "analyzed": any(row["type"] in FULL_SCANS + IMPORT_RUNS for row in finished),
        "demo": bool(find_runs(data_dir, types=FULL_SCANS, assets=[DEMO_SOURCE_ID], limit=1)),
        "watching": watched or any(row["type"] == "pr_review" for row in finished),
        "alerts": alerts, "admin": user.get("role") == "admin"}
