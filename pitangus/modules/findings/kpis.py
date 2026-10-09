"""The Findings tiles: the pending work among what a view lists (a run, an asset's state or several assets)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pitangus.modules.findings import triage
from pitangus.shared.model import RunRecord


def is_active(finding: Mapping[str, Any]) -> bool:
    """Still work to do: neither fixed (by a scan or by hand) nor dismissed in triage."""
    return (finding.get("lifecycle") or {}).get("status") != "fixed" and triage.is_active(finding)


def count(findings: Sequence[Mapping[str, Any]]) -> dict:
    """The tiles over every finding listed (before any cap): only the pending work counts."""
    active = [item for item in findings if is_active(item)]

    def of(predicate) -> int:
        return sum(1 for item in active if predicate(item))
    return {"active": len(active), "dismissed": len(findings) - len(active),
            "only_excluded": bool(findings) and all((item.get("lifecycle") or {}).get("status") == "excluded" for item in findings),
            "has_sla": any(item.get("sla") for item in findings),
            "overdue": of(lambda item: (item.get("sla") or {}).get("state") == "overdue"),
            "soon": of(lambda item: (item.get("sla") or {}).get("state") == "soon"),
            "act": of(lambda item: (item.get("priority") or {}).get("action") == "act"),
            "attend": of(lambda item: (item.get("priority") or {}).get("action") == "attend"),
            "critical": of(lambda item: item.get("severity") == "critical"),
            "high": of(lambda item: item.get("severity") == "high"),
            "kev": of(lambda item: bool(item.get("kev"))),
            "fixable": of(lambda item: bool((item.get("package") or {}).get("fixed_version")))}


def summarized(record: RunRecord) -> RunRecord:
    """The record with its tiles in `summary.kpis`."""
    return {**record, "summary": {**(record.get("summary") or {}), "kpis": count(record.get("findings") or [])}}
