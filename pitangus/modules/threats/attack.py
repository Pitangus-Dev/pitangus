"""MITRE ATT&CK Enterprise, bundled: every technique and sub-technique with its name and tactics, and the revoked and
deprecated IDs. Generated from MITRE's official STIX data by scripts/attack-catalog.py (`make attack-catalog`), pinned
to one release; never fetched at run time. MITRE's copyright and license travel inside the file.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path

FILE = Path(__file__).with_name("attack-enterprise.json")


@cache
def data() -> dict:
    return json.loads(FILE.read_text(encoding="utf-8"))


def version() -> str:
    return data()["version"]


def technique(key: str) -> tuple[str, list[str]] | None:
    """(English name, tactic IDs in kill-chain order) of a live technique, or None."""
    entry = data()["techniques"].get(key)
    return (entry[0], list(entry[1])) if entry else None


def state(key: str) -> tuple[str, str | None]:
    """("live" | "revoked" | "deprecated" | "unknown", the replacement of a revoked one when MITRE names it)."""
    catalog = data()
    if key in catalog["techniques"]:
        return "live", None
    if key in catalog["revoked"]:
        return "revoked", catalog["revoked"][key]
    if key in catalog["deprecated"]:
        return "deprecated", None
    return "unknown", None


def tactics() -> dict[str, str]:
    """Tactic ID → English name, in the matrix's order."""
    return dict(data()["tactics"])
