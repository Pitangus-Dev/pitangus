"""MITRE ATT&CK Enterprise, bundled: every technique and sub-technique with its name, tactics and platforms (MITRE's
`x_mitre_platforms`), and the revoked and deprecated IDs. Generated from MITRE's official STIX data by
scripts/attack-catalog.py (`make attack-catalog`), pinned to one release; never fetched at run time. MITRE's copyright
and license travel inside the file.

attack-es.json is ours: the Spanish names of the tactics and techniques, shown under MITRE's English ones.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path

FILE = Path(__file__).with_name("attack-enterprise.json")
TRANSLATIONS = {"es": Path(__file__).with_name("attack-es.json")}


@cache
def data() -> dict:
    return json.loads(FILE.read_text(encoding="utf-8"))


@cache
def translations(locale: str | None) -> dict:
    """{"tactics": {id: name}, "techniques": {id: name}} in that language, or empty ones for English."""
    path = TRANSLATIONS.get(locale or "")
    return json.loads(path.read_text(encoding="utf-8")) if path else {"tactics": {}, "techniques": {}}


def version() -> str:
    return data()["version"]


def technique(key: str) -> tuple[str, list[str]] | None:
    """(English name, tactic IDs in kill-chain order) of a live technique, or None."""
    entry = data()["techniques"].get(key)
    return (entry[0], list(entry[1])) if entry else None


def platforms(key: str) -> list[str]:
    """The platforms MITRE lists for a live technique, in the matrix's order (empty if it isn't one)."""
    entry = data()["techniques"].get(key)
    return list(entry[2]) if entry else []


def counts() -> dict[str, int]:
    """Live techniques, split into techniques and sub-techniques, and the revoked and deprecated IDs."""
    catalog = data()
    subtechniques = sum("." in key for key in catalog["techniques"])
    return {"total": len(catalog["techniques"]), "techniques": len(catalog["techniques"]) - subtechniques,
            "subtechniques": subtechniques, "revoked": len(catalog["revoked"]), "deprecated": len(catalog["deprecated"])}


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
