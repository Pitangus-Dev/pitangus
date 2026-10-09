"""Triage decisions as the panel sends them: on one run (or one asset's state), or on a selection that spans several
assets, one part per asset, each applied to its own asset's state. Every decision that lands also reaches the Jira
issues linked to those findings (`jira_sync.on_triage`)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from pitangus.modules.findings import triage
from pitangus.modules.findings.kinds import FINDING_RUNS
from pitangus.modules.runs import jira_sync
from pitangus.modules.runs import registry as run_registry
from pitangus.modules.sources.assets import asset_key
from pitangus.shared.i18n import msg
from pitangus.shared.model import RunRecord

# Assets in one request: each brings at least one finding, and the findings of all of them stay within MAX_BATCH.
MAX_SELECTIONS = triage.MAX_BATCH


class TriageRefused(ValueError):
    """A decision that can't land: `status` (400, 403, 404) and a catalog `message`."""

    def __init__(self, status: int, message: dict):
        super().__init__(message)
        self.status, self.message = status, message


def _apply(data_dir: Path, run_id: str, fingerprints: Any, status: str, *, reason, note, expires_at, user: dict) -> dict:
    try:
        record = cast(RunRecord, run_registry.resolve(data_dir, run_id))
    except (ValueError, OSError):
        raise TriageRefused(404, msg("runs.triage.not_found")) from None
    if record.get("type") not in (*FINDING_RUNS, "asset_state"):
        raise TriageRefused(400, msg("runs.triage.not_findings"))
    try:
        updated = triage.decide(data_dir, record, fingerprints, status, reason=reason, note=note, expires_at=expires_at, user=user)
    except triage.TriageForbidden as exc:
        raise TriageRefused(403, exc.message) from exc
    except triage.TriageError as exc:
        raise TriageRefused(400, exc.message) from exc
    key = asset_key(record)
    expiry = (triage.load_asset(data_dir, key).get(fingerprints[0]) or {}).get("expires_at") if status == "accepted" else None
    jira_sync.on_triage(data_dir, key, fingerprints, status, by=user.get("display_name") or user["username"], reason=reason, expires_at=expiry)
    return {"run_id": run_id, "summary": updated["summary"]}


def decide(data_dir: Path, selections: list[tuple[str, Any]], status: str, *, reason=None, note=None, expires_at=None,
           user: dict) -> list[dict]:
    """Applies one decision to each selection ([(run_id, fingerprints)]), one after another: each lands or fails on
    its own. Returns each one's outcome in the same order, {"run_id", "summary"} or {"run_id", "error"}; when none
    lands, raises the first failure instead, so a single selection fails as a whole, as before."""
    total = sum(len(prints) if isinstance(prints, list) else 0 for _, prints in selections)
    if (not 1 <= len(selections) <= MAX_SELECTIONS or total > triage.MAX_BATCH
            or len({run_id for run_id, _ in selections}) != len(selections)):
        raise TriageRefused(400, msg("findings.triage.errors.invalid_fingerprints", max=triage.MAX_BATCH))
    outcomes: list[dict] = []
    first: TriageRefused | None = None
    for run_id, prints in selections:
        try:
            outcomes.append(_apply(data_dir, run_id, prints, status, reason=reason, note=note, expires_at=expires_at, user=user))
        except TriageRefused as exc:
            first = first or exc
            outcomes.append({"run_id": run_id, "error": exc.message})
    if first is not None and all("error" in item for item in outcomes):
        raise first
    return outcomes
