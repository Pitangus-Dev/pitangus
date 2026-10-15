#!/usr/bin/env python3
"""Writes pitangus/modules/threats/attack-enterprise.json: every MITRE ATT&CK Enterprise technique and sub-technique
(ID, name, tactics), plus the revoked IDs with their replacement and the deprecated ones, from MITRE's official STIX
data. Pitangus never fetches ATT&CK at run time: this file is the catalog, refreshed on purpose.

The release is pinned (VERSION, COMMIT, SHA256): to move to a new one, change the three, run
`make attack-catalog` and review the diff. MITRE's license asks to reproduce its copyright designation and license
in any copy; both go inside the file (and docs/third-party-notices.md names it).
Usage: python3 scripts/attack-catalog.py [--from enterprise-attack-19.2.json]
"""

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "pitangus" / "modules" / "threats" / "attack-enterprise.json"
VERSION = "19.2"
COMMIT = "6cda5ad8462c79e14fbb872f4e09059b18e0cfc4"  # tag v19.2 of mitre-attack/attack-stix-data
SHA256 = "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4"
REPOSITORY = "https://github.com/mitre-attack/attack-stix-data"
PATH = f"enterprise-attack/enterprise-attack-{VERSION}.json"
URL = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{COMMIT}/{PATH}"
LICENSE_URL = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{COMMIT}/LICENSE.txt"
COPYRIGHT = "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310 (fixed https URL)
        return response.read()


def external_id(item: dict) -> str | None:
    return next((ref.get("external_id") for ref in item.get("external_references") or [] if ref.get("source_name") == "mitre-attack"), None)


def build(bundle: dict, license_text: str) -> dict:
    objects = bundle["objects"]
    # Tactics in the matrix's own order (the kill chain), so a technique's first tactic is its earliest one.
    matrix = next(item for item in objects if item.get("type") == "x-mitre-matrix" and not item.get("revoked"))
    by_id = {item["id"]: item for item in objects if item.get("type") == "x-mitre-tactic"}
    live = [by_id[ref] for ref in matrix["tactic_refs"]]
    tactics = {item["x_mitre_shortname"]: external_id(item) for item in live}
    rank = {external_id(item): index for index, item in enumerate(live)}
    patterns = {item["id"]: item for item in objects if item.get("type") == "attack-pattern" and external_id(item)}
    revoked_by = {item["source_ref"]: item["target_ref"] for item in objects
                  if item.get("type") == "relationship" and item.get("relationship_type") == "revoked-by"}
    techniques, revoked, deprecated = {}, {}, {}
    for stix_id, item in patterns.items():
        key = external_id(item)
        if item.get("revoked"):
            replacement = patterns.get(revoked_by.get(stix_id, ""))
            revoked[key] = external_id(replacement) if replacement else None
        elif item.get("x_mitre_deprecated"):
            deprecated[key] = item["name"]
        else:
            phases = [phase["phase_name"] for phase in item.get("kill_chain_phases") or [] if phase.get("kill_chain_name") == "mitre-attack"]
            techniques[key] = [item["name"], sorted({tactics[phase] for phase in phases if phase in tactics}, key=rank.__getitem__)]
    # An ID can be revoked in one object and live in another (rare): the live one wins.
    revoked = {key: value for key, value in revoked.items() if key not in techniques}
    for key, value in revoked.items():  # follow a chain of revocations to the live technique
        seen = {key}
        while value in revoked and value not in seen:
            seen.add(value)
            value = revoked[value]
        revoked[key] = value if value in techniques else None
    deprecated = {key: value for key, value in deprecated.items() if key not in techniques}
    order = lambda key: tuple(int(part) for part in key[1:].split("."))  # noqa: E731
    return {
        "source": REPOSITORY, "file": PATH, "version": VERSION, "commit": COMMIT, "sha256": SHA256,
        "copyright": COPYRIGHT, "license": license_text.strip(),
        "tactics": {external_id(item): item["name"] for item in live},
        "techniques": {key: techniques[key] for key in sorted(techniques, key=order)},
        "revoked": {key: revoked[key] for key in sorted(revoked, key=order)},
        "deprecated": {key: deprecated[key] for key in sorted(deprecated, key=order)},
    }


def main() -> None:
    source = sys.argv[sys.argv.index("--from") + 1] if "--from" in sys.argv else None
    raw = Path(source).read_bytes() if source else fetch(URL)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != SHA256:
        raise SystemExit(f"unexpected SHA-256 {digest} for {PATH}; expected {SHA256}")
    license_text = fetch(LICENSE_URL).decode("utf-8")
    catalog = build(json.loads(raw), license_text)
    TARGET.write_text(json.dumps(catalog, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"{TARGET.relative_to(ROOT)}: ATT&CK v{VERSION}, {len(catalog['techniques'])} techniques, "
          f"{len(catalog['revoked'])} revoked, {len(catalog['deprecated'])} deprecated")


if __name__ == "__main__":
    main()
