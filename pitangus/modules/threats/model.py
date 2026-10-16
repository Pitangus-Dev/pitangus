"""Threat modeling: a model of the system, STRIDE per element and evidence from the scans.

The team builds the model — components, data flows and trust boundaries — helped
by a **proposal** drawn from the inventory of the scanned repositories (which
frameworks, databases and services the code uses). The proposal is an editable
starting point, not the truth.

Our own visible STRIDE rules are applied to the model, like the SAST rules: each
threat says which rule generates it, why it applies to that element, what
mitigates it and which CWE it relates to. What sets it apart from a generic list
is the **evidence**: if a linked repository has open findings with one of those
CWEs — in the component's folder, if one was given — the threat shows up *with
evidence* and links to them: a signal to review, not a confirmation.

Exports to OWASP Threat Dragon (JSON v2) and to an OWASP pytm script, for anyone
who wants to carry on in those tools.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from pitangus.modules.threats import diagram as threat_diagram
from pitangus.modules.threats import methods as threat_methods
from pitangus.modules.threats.problems import KEPT, KEPT_LIMIT, Item, Problems, pointer
from pitangus.modules.threats import report as threat_report
from pitangus.modules.findings import triage
from pitangus.shared import documents
from pitangus.shared.i18n import default_locale, localize, msg, t, text


class ModelError(ValueError):
    """A validation error; `message` is a language-neutral message, str() renders it in the default locale.
    `problems`: every problem found, when the whole model was read (see problems.py)."""

    def __init__(self, message, problems: list[dict] | None = None):
        super().__init__(message)
        self.message, self.problems = message, problems or []

    def __str__(self) -> str:
        return text(self.message)


KINDS = {
    "actor": msg("threats.kinds.actor"), "web_app": msg("threats.kinds.web_app"), "api": msg("threats.kinds.api"),
    "service": msg("threats.kinds.service"), "function": msg("threats.kinds.function"), "database": msg("threats.kinds.database"),
    "cache": msg("threats.kinds.cache"), "queue": msg("threats.kinds.queue"), "storage": msg("threats.kinds.storage"),
    "external": msg("threats.kinds.external"), "identity": msg("threats.kinds.identity"), "custom": msg("threats.kinds.custom"),
}
PROCESSES = {"web_app", "api", "service", "function"}
STORES = {"database", "cache", "queue", "storage"}
CLASSIFICATIONS = {"public": 1, "internal": 2, "confidential": 3, "pii": 3, "credentials": 4, "payment": 4}
CLASSIFICATION_LABELS = {"public": msg("threats.classifications.public"), "internal": msg("threats.classifications.internal"),
                         "confidential": msg("threats.classifications.confidential"), "pii": msg("threats.classifications.pii"),
                         "credentials": msg("threats.classifications.credentials"), "payment": msg("threats.classifications.payment")}
PROTOCOLS = ("https", "http", "grpc", "websocket", "sql", "amqp", "redis", "smtp", "sftp", "other")
DECISIONS = ("mitigated", "accepted", "not_applicable")
ID = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
FOLDER = re.compile(r"[A-Za-z0-9_.\- /@+]{0,200}")
CANVAS = 100_000  # canvas coordinates: plenty for any diagram
LIMITS = {"components": 60, "flows": 150, "boundaries": 20}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _text(value, limit: int, field, *, required: bool = False) -> str:
    if value is None or value == "":
        if required:
            raise ModelError(msg("threats.errors.field_required", field=field))
        return ""
    if not isinstance(value, str) or len(value) > limit:
        raise ModelError(msg("threats.errors.field_too_long", field=field, limit=limit))
    cleaned = " ".join(value.split())
    if any(ord(character) < 32 for character in cleaned):
        raise ModelError(msg("threats.errors.control_characters", field=field))
    return cleaned


def _folder(value, field) -> str:
    """Repository folder holding a component's code: relative, no "..", ending in "/"."""
    if value in (None, ""):
        return ""
    if not isinstance(value, str) or not FOLDER.fullmatch(value):
        raise ModelError(msg("threats.errors.folder_relative", field=field))
    clean = value.strip().removeprefix("./").strip("/")
    if any(part in ("", ".", "..") for part in clean.split("/")) and clean:
        raise ModelError(msg("threats.errors.folder_segments", field=field))
    return f"{clean}/" if clean else ""


def _number(value, low: float, high: float):
    return round(float(value), 1) if isinstance(value, (int, float)) and not isinstance(value, bool) and low <= value <= high else None


def _position(raw) -> dict | None:
    """Where a component sits on the editor canvas. Optional: without it, components are laid out in columns."""
    if not isinstance(raw, dict):
        return None
    x, y = _number(raw.get("x"), -CANVAS, CANVAS), _number(raw.get("y"), -CANVAS, CANVAS)
    return {"x": x, "y": y} if x is not None and y is not None else None


def _size(raw) -> dict | None:
    """Size of a component resized in the editor; without it, the panel uses the standard size."""
    if not isinstance(raw, dict):
        return None
    width, height = _number(raw.get("width"), 120, 800), _number(raw.get("height"), 50, 600)
    return {"width": width, "height": height} if width and height else None


def _box(raw) -> dict | None:
    if not isinstance(raw, dict):
        return None
    position = _position(raw)
    width, height = _number(raw.get("width"), 80, 20_000), _number(raw.get("height"), 60, 20_000)
    return {**position, "width": width, "height": height} if position and width and height else None


# ------------------------------------------------------------ validation

# Our lists are suggestions: a team's own protocol, component type or data class is kept as written (cleaned and
# bounded). Pitangus only reasons about the values it knows (encryption by protocol, rules by type, sensitivity by
# class); the others get no automatic checks. Closed on purpose: ids, references, colors (palette tokens), the
# method and its modules, and the ordinal scales (severity, likelihood, impact, difficulty), which sort and score.
PROTOCOL_LIMIT, DATA_LIMIT = 24, 40
KIND_ALIASES = {"webapp": "web_app", "web": "web_app", "frontend": "web_app", "user": "actor", "db": "database",
                "lambda": "function", "serverless": "function", "bucket": "storage", "idp": "identity"}
DATA_ALIASES = {"personal": "pii", "personal_data": "pii", "secrets": "credentials", "secret": "credentials",
                "pci": "payment", "card": "payment", "cards": "payment", "private": "confidential", "sensitive": "confidential"}
MODEL_KEYS = {"name", "description", "methodology", "custom_modules", "components", "flows", "boundaries", "legend", "repositories",
              "repository_refs", "assumptions", "level_equivalents", "manual_threats", "pasta", "attack_trees", "attack_mappings"}
STORED_KEYS = {"id", "created_at", "created_by", "updated_at", "updated_by", "decisions"}
COMPONENT_KEYS = {"id", "name", "kind", "custom_kind", "custom_base", "description", "technology", "asset", "asset_ref", "path",
                  "position", "size", "data", "internet_facing", "authenticates", "encrypted_at_rest", "color", "origin"}
FLOW_KEYS = {"id", "source", "target", "name", "protocol", "description", "data", "authenticated", "encrypted"}
BOUNDARY_KEYS = {"id", "name", "components", "description", "box", "color"}
DESCRIPTION_LIMIT = 1000  # a flow's or a boundary's description (a component's: 400, shown on the canvas)
# Field synonyms read as ours, with an info (documented in the JSON Schema): what assistants and other tools write.
MODEL_ALIASES = {"title": "name", "approach": "methodology", "method": "methodology", "methodology_name": "methodology",
                 "modules": "custom_modules", "trust_boundaries": "boundaries", "data_flows": "flows", "dataflows": "flows",
                 "elements": "components", "threats_manual": "manual_threats", "team_threats": "manual_threats",
                 "trees": "attack_trees", "mappings": "attack_mappings", "attack_techniques": "attack_mappings", "techniques": "attack_mappings"}
COMPONENT_ALIASES = {"type": "kind", "title": "name", "label": "name", "tech": "technology", "stack": "technology",
                     "data_classes": "data", "data_classification": "data", "classification": "data"}
FLOW_ALIASES = {"from": "source", "to": "target", "source_id": "source", "target_id": "target", "src": "source", "dst": "target",
                "destination": "target", "label": "name", "title": "name", "data_classes": "data", "data_classification": "data",
                "classification": "data"}
BOUNDARY_ALIASES = {"members": "components", "component_ids": "components", "elements": "components", "contains": "components",
                    "title": "name", "label": "name"}


def _key(value: str) -> str:
    return "_".join(value.strip().lower().replace("-", "_").split())


def _protocol(value, problems: Problems, path: str, identifier, *, encryption_given: bool = False) -> str:
    if value in (None, ""):
        problems.warning(path, msg("threats.problems.protocol_missing"), identifier)
        return "other"
    if not isinstance(value, str):
        problems.error(path, msg("threats.problems.not_text", field="protocol"), identifier)
        return "other"
    if value.strip().lower() in PROTOCOLS:
        return value.strip().lower()
    label = problems.text(value, PROTOCOL_LIMIT, path, msg("threats.fields.protocol"), identifier=identifier)
    # A protocol is a short token on the diagram's arrows: letters, digits and a few separators, nothing else.
    token = " ".join(re.sub(r"[^\w .+/:#()-]", "", label).split())
    if token != label:
        problems.warning(path, msg("threats.problems.cleaned", field=msg("threats.fields.protocol")), identifier)
        label = token
    if not label:
        return "other"
    # Pitangus can't tell whether the team's own protocol is encrypted: it matters only when the flow doesn't say.
    if encryption_given:
        problems.info(path, msg("threats.problems.custom_protocol_set", value=label), identifier)
    else:
        problems.warning(path, msg("threats.problems.custom_protocol", value=label), identifier)
    return label


def _data(value, problems: Problems, path: str, identifier) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, str):  # "pii, credentials": one class per comma
        problems.info(path, msg("threats.problems.text_as_list", field="data"), identifier)
        value = [part for part in value.split(",") if part.strip()]
    if not isinstance(value, list):
        problems.error(path, msg("threats.problems.not_a_list", field="data"), identifier)
        return []
    items: dict[str, str] = {}
    for index, item in enumerate(value[:30]):
        if not isinstance(item, str):
            problems.error(f"{path}/{index}", msg("threats.problems.not_text", field="data"), identifier)
            continue
        key = DATA_ALIASES.get(_key(item), _key(item))
        if key in CLASSIFICATIONS:
            items.setdefault(key, key)
            continue
        label = problems.text(item, DATA_LIMIT, f"{path}/{index}", msg("threats.fields.data"), identifier=identifier)
        if label:
            problems.warning(f"{path}/{index}", msg("threats.problems.custom_data", value=label), identifier)
            items.setdefault(label.lower(), label)
    if len(value) > 30:
        problems.warning(path, msg("threats.problems.truncated_list", field="data", limit=30), identifier)
    known = sorted(item for item in items.values() if item in CLASSIFICATIONS)
    return known + sorted((item for item in items.values() if item not in CLASSIFICATIONS), key=str.lower)


def _color(value, problems: Problems, path: str, identifier) -> str:
    """Color picked in the editor: a palette token or nothing (automatic, by kind)."""
    if value in (None, ""):
        return ""
    if value not in threat_diagram.COLORS:
        problems.warning(path, msg("threats.problems.unknown_color", value=str(value)[:40], allowed=", ".join(threat_diagram.COLORS)), identifier)
        return ""
    return value


def _legend(raw, components: list[dict], problems: Problems, path: str = "/legend") -> dict:
    """Team labels for manual colors ({tone: label}); labels of colors no component uses are dropped."""
    if raw in (None, {}):
        return {}
    if not isinstance(raw, dict):
        problems.error(path, msg("threats.errors.invalid_legend"))
        return {}
    for tone in raw:
        if tone not in threat_diagram.COLORS:
            problems.warning(path + pointer(tone), msg("threats.problems.unknown_color", value=str(tone)[:40], allowed=", ".join(threat_diagram.COLORS)))
    used = set(threat_diagram.legend_tones({"components": components})[1])
    labels = {tone: problems.text(raw[tone], 40, path + pointer(tone), msg("threats.fields.legend_label", color=threat_diagram.COLOR_NAMES[tone]))
              for tone in threat_diagram.COLORS if tone in raw}
    return {tone: label for tone, label in labels.items() if label and tone in used}


def _items(payload: dict, key: str, problems: Problems, path: str) -> list:
    raw = payload.get(key)
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        problems.error(path, msg("threats.problems.not_a_list", field=key))
        return []
    return raw


def _component(item: Item, identifier: str, known_assets: set[str], problems: Problems) -> dict:
    kind, custom_kind = item.get("kind"), ""
    if kind in (None, ""):
        problems.warning(item.at("kind"), msg("threats.problems.kind_missing"), identifier)
        kind = "service"
    elif not isinstance(kind, str):
        problems.error(item.at("kind"), msg("threats.problems.not_text", field="kind"), identifier)
        kind = "service"
    elif KIND_ALIASES.get(_key(kind), _key(kind)) in KINDS:
        kind = KIND_ALIASES.get(_key(kind), _key(kind))
    else:
        custom_kind = problems.text(kind, 80, item.at("kind"), msg("threats.fields.custom_kind"), identifier=identifier)
        problems.warning(item.at("kind"), msg("threats.problems.custom_kind", value=custom_kind), identifier)
        kind = "custom"
    if item.get("name") in (None, ""):
        problems.warning(item.at("name"), msg("threats.problems.name_from_id"), identifier)
        name = identifier
    else:
        name = problems.text(item.get("name"), 80, item.at("name"), msg("threats.fields.component_name"), required=True, identifier=identifier)
    base = ""
    if kind == "custom":
        custom_kind = custom_kind or problems.text(item.get("custom_kind"), 80, item.at("custom_kind"), msg("threats.fields.custom_kind"), identifier=identifier) or name
        base = problems.choice(item.get("custom_base"), tuple(KINDS.keys() - {"custom"}), "service", item.at("custom_base"), "custom_base", identifier, aliases=KIND_ALIASES)
    asset = item.get("asset")
    if asset not in (None, "") and (not isinstance(asset, str) or asset not in known_assets):
        problems.error(item.at("asset"), msg("threats.errors.unknown_asset", id=identifier), identifier)
        asset = None
    try:
        folder = _folder(item.get("path"), msg("threats.fields.folder", id=identifier))
    except ModelError as exc:
        problems.warning(item.at("path"), exc.message, identifier)
        folder = ""
    return item.keep({
        "id": identifier, "name": name, "kind": kind, "custom_kind": custom_kind, "custom_base": base,
        "description": problems.text(item.get("description"), 400, item.at("description"), msg("threats.fields.description"), identifier=identifier),
        "technology": problems.text(item.get("technology"), 80, item.at("technology"), msg("threats.fields.technology"), identifier=identifier),
        "asset": asset or None, "asset_ref": problems.text(item.get("asset_ref"), 200, item.at("asset_ref"), msg("threats.fields.asset_ref"), identifier=identifier),
        "path": folder, "position": _position(item.get("position")), "size": _size(item.get("size")),
        "data": _data(item.get("data"), problems, item.at("data"), identifier),
        "internet_facing": problems.flag(item.get("internet_facing"), item.at("internet_facing"), "internet_facing", identifier),
        "authenticates": problems.flag(item.get("authenticates"), item.at("authenticates"), "authenticates", identifier),
        "encrypted_at_rest": problems.flag(item.get("encrypted_at_rest"), item.at("encrypted_at_rest"), "encrypted_at_rest", identifier),
        "color": _color(item.get("color"), problems, item.at("color"), identifier),
        "origin": item.get("origin") if item.get("origin") in ("suggested", "manual") else "manual"})


def _flow(item: Item, identifier: str, ids: set[str], problems: Problems) -> dict | None:
    ends_ok = True
    for end in ("source", "target"):
        value = item.get(end)
        if not isinstance(value, str) or value not in ids:
            problems.error(item.at(end), msg("threats.problems.dangling", field=end, value=str(value)[:40]), identifier)
            ends_ok = False
    if ends_ok and item.get("source") == item.get("target"):
        problems.error(item.at("target"), msg("threats.errors.flow_ends", id=identifier), identifier)
        ends_ok = False
    explicit = isinstance(item.get("encrypted"), bool)
    protocol = _protocol(item.get("protocol"), problems, item.at("protocol"), identifier, encryption_given=explicit)
    entry = {"id": identifier, "source": item.get("source"), "target": item.get("target"),
             "name": problems.text(item.get("name"), 80, item.at("name"), msg("threats.fields.flow_name"), identifier=identifier), "protocol": protocol,
             "description": problems.text(item.get("description"), DESCRIPTION_LIMIT, item.at("description"), msg("threats.fields.description"), multiline=True, identifier=identifier),
             "data": _data(item.get("data"), problems, item.at("data"), identifier),
             "authenticated": problems.flag(item.get("authenticated"), item.at("authenticated"), "authenticated", identifier),
             "encrypted": problems.flag(item.get("encrypted"), item.at("encrypted"), "encrypted", identifier) or protocol in ("https", "sftp")}
    return item.keep(entry) if ends_ok else None


def inspect(payload, *, known_assets: set[str], problems: Problems | None = None) -> tuple[dict, Problems]:
    """Reads a model and returns it normalized, with every problem found (it never stops at the first)."""
    problems = problems if problems is not None else Problems()
    if not isinstance(payload, dict):
        problems.error("", msg("threats.errors.invalid_model"))
        return {}, problems
    top = problems.read(payload, MODEL_KEYS | STORED_KEYS, "", aliases=MODEL_ALIASES, limit=KEPT_LIMIT * 5)
    payload = top.values
    model = {"name": problems.text(top.get("name"), 80, top.at("name"), msg("threats.fields.name"), required=True),
             "description": problems.text(top.get("description"), 1000, top.at("description"), msg("threats.fields.description"))}
    components, ids = [], set()
    for index, raw in enumerate(_items(payload, "components", problems, top.at("components"))):
        path = top.at("components") + pointer(index)
        if not isinstance(raw, dict):
            problems.error(path, msg("threats.errors.invalid_component"))
            continue
        item = problems.read(raw, COMPONENT_KEYS, path, raw.get("id"), aliases=COMPONENT_ALIASES)
        identifier = item.get("id")
        if not isinstance(identifier, str) or not ID.fullmatch(identifier) or identifier in ids:
            problems.error(item.at("id"), msg("threats.problems.duplicate_id" if identifier in ids else "threats.errors.component_id", value=str(identifier)[:40]),
                           identifier)
            continue
        ids.add(identifier)
        components.append(_component(item, identifier, known_assets, problems))
    flows, flow_ids = [], set()
    for index, raw in enumerate(_items(payload, "flows", problems, top.at("flows"))):
        path = top.at("flows") + pointer(index)
        if not isinstance(raw, dict):
            problems.error(path, msg("threats.errors.invalid_flow"))
            continue
        item = problems.read(raw, FLOW_KEYS, path, raw.get("id"), aliases=FLOW_ALIASES)
        identifier = item.get("id")
        if not isinstance(identifier, str) or not ID.fullmatch(identifier) or identifier in flow_ids:
            problems.error(item.at("id"), msg("threats.problems.duplicate_id" if identifier in flow_ids else "threats.errors.flow_id", value=str(identifier)[:40]), identifier)
            continue
        if identifier in ids:  # threats, tree steps and techniques point at an element by its id alone
            problems.error(item.at("id"), msg("threats.errors.flow_id_taken", id=identifier), identifier)
            continue
        flow_ids.add(identifier)
        entry = _flow(item, identifier, ids, problems)
        if entry:
            flows.append(entry)
    boundaries, boundary_ids, placed = [], set(), {}
    for index, raw in enumerate(_items(payload, "boundaries", problems, top.at("boundaries"))):
        path = top.at("boundaries") + pointer(index)
        if not isinstance(raw, dict):
            problems.error(path, msg("threats.errors.invalid_boundary"))
            continue
        item = problems.read(raw, BOUNDARY_KEYS, path, raw.get("id"), aliases=BOUNDARY_ALIASES)
        identifier = item.get("id")
        if not isinstance(identifier, str) or not ID.fullmatch(identifier) or identifier in boundary_ids:
            problems.error(item.at("id"), msg("threats.problems.duplicate_id" if identifier in boundary_ids else "threats.errors.boundary_id", value=str(identifier)[:40]), identifier)
            continue
        boundary_ids.add(identifier)
        members = item.get("components") or []
        if not isinstance(members, list):
            problems.error(item.at("components"), msg("threats.problems.not_a_list", field="components"), identifier)
            members = []
        kept = []
        for position, member in enumerate(members):
            where = item.at("components") + pointer(position)
            if not isinstance(member, str) or member not in ids:
                problems.error(where, msg("threats.problems.dangling", field="components", value=str(member)[:40]), identifier)
            elif member in placed and placed[member] != identifier:
                problems.warning(where, msg("threats.problems.second_boundary", value=member, boundary=placed[member]), identifier)
            elif member not in kept:
                kept.append(member)
                placed[member] = identifier
        if item.get("name") in (None, ""):
            problems.warning(item.at("name"), msg("threats.problems.name_from_id"), identifier)
            name = identifier
        else:
            name = problems.text(item.get("name"), 80, item.at("name"), msg("threats.fields.boundary_name"), required=True, identifier=identifier)
        boundaries.append(item.keep({"id": identifier, "name": name, "components": kept,
                                     "description": problems.text(item.get("description"), DESCRIPTION_LIMIT, item.at("description"), msg("threats.fields.description"),
                                                                  multiline=True, identifier=identifier),
                                     "box": _box(item.get("box")), "color": _color(item.get("color"), problems, item.at("color"), identifier)}))
    too_many = {"components": msg("threats.errors.too_many_components", limit=LIMITS["components"]),
                "flows": msg("threats.errors.too_many_flows", limit=LIMITS["flows"]),
                "boundaries": msg("threats.errors.too_many_boundaries", limit=LIMITS["boundaries"])}
    for key, items in (("components", components), ("flows", flows), ("boundaries", boundaries)):
        if len(items) > LIMITS[key]:
            problems.error(top.at(key), too_many[key])
    repositories = payload.get("repositories") or []
    if not isinstance(repositories, list) or len(repositories) > 50 or any(not isinstance(item, str) for item in repositories):
        problems.error(top.at("repositories"), msg("threats.errors.invalid_repositories"))
        repositories = []
    elif any(item not in known_assets for item in repositories):
        problems.error(top.at("repositories"), msg("threats.errors.unknown_repository"))
        repositories = [item for item in repositories if item in known_assets]
    # The repositories the components use belong to the project even if nobody added them by hand.
    model["repositories"] = list(dict.fromkeys([*repositories, *(item["asset"] for item in components if item.get("asset") and not item["asset"].startswith("domain:"))]))
    references = payload.get("repository_refs") or []
    if not isinstance(references, list) or len(references) > 50:
        problems.error(top.at("repository_refs"), msg("threats.errors.invalid_repository_refs"))
        references = []
    model["repository_refs"] = list(dict.fromkeys(value for index, item in enumerate(references)
                                                  if (value := problems.text(item, 200, top.at("repository_refs") + pointer(index), msg("threats.fields.repository_ref"), required=True))))
    model["assumptions"] = threat_methods.assumptions(payload.get("assumptions"), problems, top.at("assumptions"))
    # What is specific to the chosen approach: hand-written threats, trees, ATT&CK techniques, PASTA stages.
    extras = threat_methods.validate(payload, elements=ids | flow_ids, problems=problems, top=top)
    model["level_equivalents"] = threat_methods.equivalents(payload.get("level_equivalents"), problems, top.at("level_equivalents"))
    model["legend"] = _legend(payload.get("legend"), components, problems, top.at("legend"))
    return top.keep({**model, "components": components, "flows": flows, "boundaries": boundaries, **extras}), problems


def _raise(problems: Problems) -> None:
    errors = problems.errors
    if errors:
        raise ModelError(errors[0]["message"], problems.listing())


def validate(payload: dict, *, known_assets: set[str]) -> dict:
    """Normalizes a model coming from the panel; any error stops it (ModelError carries every problem)."""
    model, problems = inspect(payload, known_assets=known_assets)
    _raise(problems)
    return model


def _restored(entry: dict) -> dict:
    """An object as the person wrote it: its custom properties go back next to our fields. One that shares a name with
    ours (a STRIDE model's own category, say) stays under custom_properties, where the importer reads it again."""
    kept = entry.get(KEPT) or {}
    own = {key: _restored_value(value) for key, value in entry.items() if key != KEPT}
    clashing = {key: value for key, value in kept.items() if key in own}
    return {**{key: value for key, value in kept.items() if key not in own}, **own, **({KEPT: clashing} if clashing else {})}


def _restored_value(value):
    if isinstance(value, list):
        return [_restored(item) if isinstance(item, dict) else item for item in value]
    return value


def to_portable(model: dict, assets: dict[str, dict] | None = None) -> dict:
    """Editable format: no local IDs, decisions or scan evidence; the fields Pitangus kept without using, back where
    they were."""
    assets = assets or {}
    def label(identifier: str) -> str:
        return assets.get(identifier, {}).get("name") or identifier

    fields = ("name", "description", "methodology", "components", "flows", "boundaries")
    portable = {key: model[key] for key in fields if key in model}
    for key in ("assumptions", "level_equivalents"):
        if model.get(key):
            portable[key] = model[key]
    if model.get("legend"):
        portable["legend"] = model["legend"]
    if model.get("methodology") == "custom":
        portable["custom_modules"] = model.get("custom_modules", ["manual", "elements"])
    allowed = _portable_sections(model)
    for section in ("manual_threats", "pasta", "attack_trees", "attack_mappings"):
        if section in allowed:
            portable[section] = model.get(section) or ({} if section == "pasta" else [])
    portable["repository_refs"] = list(dict.fromkeys([*(model.get("repository_refs") or []),
                                                        *(label(item) for item in model.get("repositories") or [])]))
    portable["components"] = []
    for component in model.get("components") or []:
        entry = {key: value for key, value in component.items() if key != "asset"}
        entry["asset_ref"] = label(component["asset"]) if component.get("asset") else component.get("asset_ref") or ""
        portable["components"].append(entry)
    if isinstance(portable.get("pasta"), dict):
        portable["pasta"] = _restored(portable["pasta"])
    if model.get(KEPT):
        portable[KEPT] = model[KEPT]
    return {"format": "pitangus-threat-model", "version": 1, "model": _restored(portable)}


def inspect_portable(document) -> tuple[dict | None, list[dict]]:
    """Reads the portable format without trusting asset IDs or linking them automatically. Returns the model (None
    when there are errors) and every problem, with paths into `document` as written."""
    problems = Problems()
    if not isinstance(document, dict):
        problems.error("", msg("threats.errors.not_an_object"))
        return None, problems.listing()
    if "format" in document or "version" in document:
        # Files exported before the rename to Pitangus carry the old format name.
        if document.get("format") not in ("pitangus-threat-model", "tamandua-threat-model"):
            problems.error("/format", msg("threats.errors.unsupported_format"))
        if document.get("version") != 1:
            problems.error("/version", msg("threats.errors.unsupported_format"))
        problems.keys(document, {"format", "version", "model"}, "")
        raw = document.get("model")
        problems.base = "/model"
    else:
        raw = document
    if not isinstance(raw, dict):
        problems.error("", msg("threats.errors.model_not_an_object"))
        return None, problems.listing()
    repositories = raw.get("repositories") or []
    references = raw.get("repository_refs") or []
    if not isinstance(repositories, list):
        problems.error("/repositories", msg("threats.errors.refs_not_a_list"))
        repositories = []
    if not isinstance(references, list):
        problems.error("/repository_refs", msg("threats.errors.refs_not_a_list"))
        references = []
    components = raw.get("components") or []
    detached = components
    if isinstance(components, list):
        detached = [{**item, "asset": None, "asset_ref": item.get("asset_ref") or item.get("asset") or ""} if isinstance(item, dict) else item
                    for item in components]
    clean = {**raw, "components": detached, "repositories": [], "repository_refs": [*references, *repositories]}
    imported, problems = inspect(clean, known_assets=set(), problems=problems)
    if imported:
        allowed = _portable_sections(imported)
        labels = {"manual_threats": msg("threats.sections.manual_threats"), "attack_trees": msg("threats.sections.attack_trees"),
                  "attack_mappings": msg("threats.sections.attack_mappings"), "pasta": msg("threats.sections.pasta")}
        for section, label in labels.items():
            value = imported.get(section)
            if isinstance(value, dict):
                value = {key: item for key, item in value.items() if key != KEPT}
            if value and section not in allowed:
                if imported["methodology"] == "custom":  # Custom is full freedom: a section it brings turns its module on
                    module = {"manual_threats": "manual", "attack_trees": "trees", "attack_mappings": "attack", "pasta": "pasta"}[section]
                    imported["custom_modules"] = [*imported["custom_modules"], module]
                    problems.info(pointer(section), msg("threats.problems.module_added", section=label))
                    continue
                method = threat_methods.METHODOLOGIES[imported["methodology"]]
                problems.error(pointer(section), msg("threats.errors.section_not_allowed", method=method, section=label))
        if imported["methodology"] != "custom" and raw.get("custom_modules") not in (None, [], ["manual", "elements"]):
            problems.warning("/custom_modules", msg("threats.problems.custom_modules_ignored"))
    if problems.errors:
        return None, problems.listing()
    # Positions that don't fit their boundaries (small or overlapping boxes): re-laying out beats drawing them wrong.
    if not geometry_fits(imported):
        imported = {**imported, "components": [{**item, "position": None} for item in imported["components"]],
                    "boundaries": [{**item, "box": None} for item in imported["boundaries"]]}
        imported["relayout"] = True
    return imported, problems.listing()


def from_portable(document: dict) -> dict:
    """Imports a model; ModelError (with every problem) if it has errors. Warnings don't stop it."""
    imported, problems = inspect_portable(document)
    if imported is None:
        first = next(item for item in problems if item["severity"] == "error")
        raise ModelError(first["message"], problems)
    return imported


def workspace_values(data_dir: Path) -> dict:
    """The team's own values already used in this workspace's models, offered next to ours in the editor."""
    seen: dict[str, dict[str, str]] = {key: {} for key in ("protocols", "kinds", "data", "categories", "techniques", "severities", "levels", "statuses")}

    def add(group: str, value) -> None:
        if isinstance(value, str) and value.strip() and len(seen[group]) < 100:
            seen[group].setdefault(value.strip().lower(), value.strip())
    for name in documents.names(data_dir, "threat-models/"):
        model = documents.load(data_dir, name)
        if not isinstance(model, dict):
            continue
        for component in model.get("components") or []:
            if component.get("kind") == "custom":
                add("kinds", component.get("custom_kind"))
            for item in component.get("data") or []:
                if item not in CLASSIFICATIONS:
                    add("data", item)
        for flow in model.get("flows") or []:
            if flow.get("protocol") not in PROTOCOLS:
                add("protocols", flow.get("protocol"))
            for item in flow.get("data") or []:
                if item not in CLASSIFICATIONS:
                    add("data", item)
        for threat in model.get("manual_threats") or []:
            add("categories", threat.get("category"))
            if threat.get("severity") not in threat_methods.SEVERITIES:
                add("severities", threat.get("severity"))
            for key in ("likelihood", "impact"):
                if threat.get(key) not in (None, *threat_methods.LEVELS):
                    add("levels", threat.get(key))
        for tree in model.get("attack_trees") or []:
            for node in tree.get("nodes") or []:
                if node.get("difficulty") not in (None, *threat_methods.LEVELS):
                    add("levels", node.get("difficulty"))
        for mapping in model.get("attack_mappings") or []:
            if not isinstance(mapping.get("technique"), str) or threat_methods.attack.technique(mapping["technique"]) is None:
                add("techniques", mapping.get("technique"))
            if mapping.get("status") not in threat_methods.MAPPING_STATUS:
                add("statuses", mapping.get("status"))
    return {group: sorted(values.values(), key=str.lower) for group, values in seen.items()}


def geometry_fits(model: dict) -> bool:
    """Are a model's positions and boxes consistent? Every placed component inside its boundary's box, and no box
    overlapping another (unless it contains it entirely). Without positions, there is nothing to check."""
    components = {item["id"]: item for item in model.get("components", [])}
    if not any(item.get("position") for item in components.values()):
        return True
    if not all(item.get("position") for item in components.values()):
        return False
    boxes = {item["id"]: item["box"] for item in model.get("boundaries", []) if item.get("box")}
    for boundary in model.get("boundaries", []):
        box = boxes.get(boundary["id"])
        if box is None and boundary["components"]:
            return False
        for member in boundary["components"]:
            point, (width, height) = components[member]["position"], _node_size(components[member])
            if not (box["x"] <= point["x"] and point["x"] + width <= box["x"] + box["width"]
                    and box["y"] <= point["y"] and point["y"] + height - 16 <= box["y"] + box["height"]):
                return False
    ids = list(boxes)
    for index, first in enumerate(ids):
        for second in ids[index + 1:]:
            a, b = boxes[first], boxes[second]
            overlap = a["x"] < b["x"] + b["width"] and b["x"] < a["x"] + a["width"] and a["y"] < b["y"] + b["height"] and b["y"] < a["y"] + a["height"]
            inside = lambda outer, inner: (outer["x"] <= inner["x"] and outer["y"] <= inner["y"] and inner["x"] + inner["width"] <= outer["x"] + outer["width"]
                                           and inner["y"] + inner["height"] <= outer["y"] + outer["height"])
            if overlap and not inside(a, b) and not inside(b, a):
                return False
    return True


def _portable_sections(model: dict) -> set[str]:
    """A method's own sections; the diagram is shared by all of them."""
    method = model.get("methodology") or "stride"
    if method == "custom":
        modules = set(model.get("custom_modules", ["manual", "elements"]))
        return {section for module, section in (("manual", "manual_threats"), ("trees", "attack_trees"),
                                                ("attack", "attack_mappings"), ("pasta", "pasta")) if module in modules}
    return {
        "stride": {"manual_threats"},
        "linddun": {"manual_threats"},
        "pasta": {"manual_threats", "pasta", "attack_trees"},
        "attack_trees": {"manual_threats", "attack_trees"},
        "attack": {"manual_threats", "attack_mappings"},
    }.get(method, set())


# ------------------------------------------------------------ storage

def _name(model_id: str) -> str:
    if not isinstance(model_id, str) or not re.fullmatch(r"[0-9a-f]{24}", model_id):
        raise ModelError(msg("threats.errors.not_found"))
    return f"threat-models/{model_id}"


def load(data_dir: Path, model_id: str) -> dict:
    model = documents.load(data_dir, _name(model_id))
    if model is None:
        raise ModelError(msg("threats.errors.not_found"))
    return model


def _write(data_dir: Path, model: dict) -> None:
    documents.save(data_dir, _name(model["id"]), model)


def list_models(data_dir: Path) -> list[dict]:
    rows = []
    for name in documents.names(data_dir, "threat-models/"):
        model = documents.load(data_dir, name)
        if not isinstance(model, dict):
            continue
        rows.append({key: model.get(key) for key in ("id", "name", "description", "updated_at", "updated_by", "created_at")}
                    | {"components": len(model.get("components", [])), "flows": len(model.get("flows", [])),
                       "repositories": len(model.get("repositories") or []),
                       "methodology": model.get("methodology") or "stride"})
    return sorted(rows, key=lambda row: row.get("updated_at") or "", reverse=True)


def save(data_dir: Path, model: dict, *, by: str, model_id: str | None = None) -> dict:
    with documents.lock(data_dir, "threat-models"):
        if model_id is None:
            stored = {"id": secrets.token_hex(12), "created_at": _now(), "created_by": by, "decisions": {}}
        else:
            stored = load(data_dir, model_id)
        stored.update(model, updated_at=_now(), updated_by=by)
        _write(data_dir, stored)
    return stored


def delete(data_dir: Path, model_id: str) -> None:
    load(data_dir, model_id)  # 404 if it doesn't exist
    documents.delete(data_dir, _name(model_id))


def decide(data_dir: Path, model_id: str, threat_id: str, status: str, reason, *, by: str) -> dict:
    if status not in (*DECISIONS, "open"):
        raise ModelError(msg("threats.errors.invalid_decision"))
    if not isinstance(threat_id, str) or not re.fullmatch(r"[0-9a-f]{16}", threat_id):
        raise ModelError(msg("threats.errors.invalid_threat"))
    reason = _text(reason, 500, msg("threats.fields.reason"))
    if status != "open" and len(reason) < 10:
        raise ModelError(msg("threats.errors.reason_required"))
    with documents.lock(data_dir, "threat-models"):
        model = load(data_dir, model_id)
        if threat_id not in {item["id"] for item in threats(model)}:
            raise ModelError(msg("threats.errors.threat_not_in_model"))
        decisions = model.setdefault("decisions", {})
        if status == "open":
            decisions.pop(threat_id, None)
        else:
            decisions[threat_id] = {"status": status, "reason": reason, "by": by, "at": _now()}
        _write(data_dir, model)
    return model


# ------------------------------------------------------------ proposal

# Dependency signature → component it suggests. Exact names or prefixes ending in "/".
NEXT_APP, BROWSER_APP, ORM_DATABASE = msg("threats.suggest.nextjs_app"), msg("threats.suggest.browser_app"), msg("threats.suggest.orm_database")
SIGNATURES = [
    (("next",), "web_app", NEXT_APP, "Next.js"),
    (("react", "vue", "@angular/core", "svelte", "solid-js"), "web_app", BROWSER_APP, None),
    (("express", "fastify", "koa", "@nestjs/core", "@hapi/hapi", "hono"), "api", msg("threats.suggest.node_api"), None),
    (("django", "flask", "fastapi", "starlette", "tornado"), "api", msg("threats.suggest.python_api"), None),
    (("github.com/gin-gonic/gin", "github.com/labstack/echo/v4", "github.com/gofiber/fiber/v2"), "api", msg("threats.suggest.go_api"), None),
    (("axum", "actix-web", "rocket", "warp", "poem"), "api", msg("threats.suggest.rust_api"), None),
    (("clap", "typer", "click", "commander", "yargs", "github.com/spf13/cobra"), "function", msg("threats.suggest.cli"), None),
    (("pg", "postgres", "psycopg2", "psycopg2-binary", "psycopg", "asyncpg", "github.com/lib/pq", "github.com/jackc/pgx/v5"), "database", "PostgreSQL", "PostgreSQL"),
    (("mysql", "mysql2", "pymysql", "mysqlclient"), "database", "MySQL", "MySQL"),
    (("mongoose", "mongodb", "pymongo", "motor"), "database", "MongoDB", "MongoDB"),
    (("sqlx", "diesel", "tokio-postgres", "sea-orm", "rusqlite"), "database", msg("threats.suggest.rust_database"), None),
    (("@prisma/client", "prisma", "sequelize", "typeorm", "drizzle-orm", "sqlalchemy", "knex"), "database", ORM_DATABASE, None),
    (("redis", "ioredis", "github.com/redis/go-redis/v9"), "cache", "Redis", "Redis"),
    (("bull", "bullmq", "amqplib", "kafkajs", "celery", "pika", "kombu"), "queue", msg("threats.suggest.job_queue"), None),
    (("@aws-sdk/client-s3", "aws-sdk", "boto3", "@google-cloud/storage", "cloudinary", "@azure/storage-blob"), "storage", msg("threats.suggest.object_storage"), None),
    (("stripe",), "external", msg("threats.suggest.stripe"), "Stripe"),
    (("@sendgrid/mail", "nodemailer", "resend", "postmark"), "external", msg("threats.suggest.email"), None),
    (("twilio",), "external", msg("threats.suggest.twilio"), "Twilio"),
    (("openai", "@anthropic-ai/sdk", "anthropic", "@google/generative-ai", "langchain", "ollama-rs", "async-openai", "ollama"), "external", msg("threats.suggest.llm"), None),
    (("@supabase/supabase-js",), "external", "Supabase", "Supabase"),
    (("firebase", "firebase-admin"), "external", "Firebase", "Firebase"),
    (("next-auth", "@auth/core", "@clerk/nextjs", "@auth0/nextjs-auth0", "passport", "keycloak-js", "authlib"), "identity", msg("threats.suggest.identity"), None),
]
SERVICE_IMAGES = {"postgres": ("database", "PostgreSQL"), "mysql": ("database", "MySQL"), "mariadb": ("database", "MariaDB"),
                  "mongo": ("database", "MongoDB"), "redis": ("cache", "Redis"), "rabbitmq": ("queue", "RabbitMQ"),
                  "kafka": ("queue", "Kafka"), "minio": ("storage", "MinIO"), "elasticsearch": ("database", "Elasticsearch")}
PAYMENT = {"stripe"}


def _slug(text: str, used: set[str]) -> str:
    plain = "".join(character for character in unicodedata.normalize("NFKD", text) if not unicodedata.combining(character))
    base = re.sub(r"[^a-z0-9]+", "-", plain.lower()).strip("-")[:30] or "c"
    candidate, index = base, 2
    while candidate in used:
        candidate, index = f"{base}-{index}", index + 1
    used.add(candidate)
    return candidate


def suggest(name: str, repositories: list[dict], *, locale: str | None = None) -> dict:
    """Initial proposal from the inventory of the latest scans. Everything is marked as suggested.

    The proposal becomes the team's own editable content, so it is written in the requester's language."""
    locale = locale or default_locale()
    say = lambda value: text(value, locale)  # noqa: E731
    next_app, browser_app, orm_database = say(NEXT_APP), say(BROWSER_APP), say(ORM_DATABASE)
    used: set[str] = set()
    user = t("threats.suggest.user", locale)
    components = [{"id": _slug(user, used), "name": user, "kind": "actor", "internet_facing": True, "origin": "suggested"}]
    flows, app_ids, backends = [], [], []
    found: dict[tuple[str, str], dict] = {}
    via: set[tuple[str, str]] = set()
    for repository in repositories:
        inventory = repository.get("inventory") or {}
        names = {item for values in (inventory.get("packages") or {}).values() for item in values}
        # Without an inventory (old scans), the packages from dependency findings are used.
        names |= {(item.get("package") or {}).get("name") for item in repository.get("findings", []) if item.get("package")}
        names.discard(None)
        found_in = inventory.get("found_in") or {}
        short = repository["name"].split("/")[-1]
        matched = []
        for packages, kind, label, technology in SIGNATURES:
            hit = sorted(names.intersection(packages))
            if hit:
                where = found_in.get(hit[0])
                matched.append((kind, say(label), technology or hit[0],
                                t("threats.suggest.detected_by", locale, packages=", ".join(hit[:3]), where=f"{short}/{where}" if where else short),
                                where.rsplit("/", 1)[0] + "/" if where and "/" in where else "", ", ".join(hit[:3])))
        for image in inventory.get("services") or []:
            if image in SERVICE_IMAGES:
                kind, label = SERVICE_IMAGES[image]
                where = found_in.get(f"image:{image}")
                matched.append((kind, label, label, t("threats.suggest.image_in", locale, image=image, where=f"{short}/{where}" if where else short),
                                "", image))
        has_process = any(item[0] in PROCESSES for item in matched)
        if not has_process:
            read = ", ".join(inventory.get("manifests") or []) or t("threats.suggest.no_manifest", locale)
            matched.append(("api", t("threats.suggest.service", locale, name=short), None,
                            t("threats.suggest.no_framework", locale, name=short, read=read[:200]), "", ""))
        # An ORM is how the code talks to the database, not another database: with a concrete engine, they merge.
        orm = next((item for item in matched if item[1] == orm_database), None)
        engines = [item for item in matched if item[0] == "database" and item[1] != orm_database]
        merged_orm = None
        if orm and engines:
            matched = [item for item in matched if item is not orm and item is not engines[0]]
            kind, label, technology, provenance, folder, _ = engines[0]
            merged_orm = (kind, label, t("threats.suggest.via", locale, technology=technology, orm=orm[2]),
                          t("threats.suggest.accessed_with", locale, provenance=provenance, packages=orm[5]), folder, "")
            matched.append(merged_orm)
        # Next.js already is the web app: it isn't duplicated with a "browser application".
        if any(item[1] == next_app for item in matched):
            matched = [item for item in matched if item[1] != browser_app]
        several = len(repositories) > 1
        for entry in matched:
            kind, label, technology, provenance, folder, _ = entry
            key = (kind, label if kind not in PROCESSES else f"{label}:{repository['id']}")
            if key in found:
                # Another hint for the same component: it adds to its provenance instead of being lost.
                existing = found[key]
                if provenance and provenance not in existing["description"]:
                    existing["description"] = f"{existing['description']}; {provenance}"[:400]
                if entry is merged_orm and key not in via:
                    existing["technology"] = technology
                    via.add(key)
                continue
            if entry is merged_orm:
                via.add(key)
            # With several repositories each process names its own: two "Python API" would be indistinguishable.
            shown = f"{label} · {short}" if several and kind in PROCESSES and short not in label else label
            component = {"id": _slug(shown, used), "name": shown, "kind": kind, "technology": technology or "",
                         "description": provenance[:400],
                         "origin": "suggested", "asset": repository["id"] if kind in PROCESSES else None,
                         "path": folder if kind in PROCESSES else "",
                         "internet_facing": kind in ("web_app", "api") and kind != "service",
                         "authenticates": kind in PROCESSES,
                         "data": ["payment"] if technology and technology.lower() in PAYMENT else
                                 ["pii", "credentials"] if kind in ("database", "identity") else
                                 ["internal"] if kind in STORES else []}
            found[key] = component
            components.append(component)
            (app_ids if kind == "web_app" else backends if kind in PROCESSES else []).append(component["id"])
    front = app_ids or backends[:1]
    user = components[0]["id"]
    for target in front:
        flows.append({"source": user, "target": target, "protocol": "https", "data": ["pii", "credentials"], "authenticated": False})
    servers = backends or app_ids
    for app in app_ids:
        for backend in backends:
            flows.append({"source": app, "target": backend, "protocol": "https", "data": ["pii"], "authenticated": True})
    for component in components:
        if component["kind"] in STORES:
            protocol = {"database": "sql", "cache": "redis", "queue": "amqp", "storage": "https"}[component["kind"]]
            for server in servers:
                flows.append({"source": server, "target": component["id"], "protocol": protocol, "data": component["data"], "authenticated": True})
        elif component["kind"] in ("external", "identity"):
            for server in servers[:1]:
                flows.append({"source": server, "target": component["id"], "protocol": "https", "data": component["data"] or ["internal"], "authenticated": True})
    flow_ids: set[str] = {component["id"] for component in components}
    for flow in flows:
        flow["id"] = _slug(f"{flow['source']}-{flow['target']}", flow_ids)
        flow["name"] = ""
    boundaries = [{"id": "internet", "name": t("threats.suggest.boundary_internet", locale), "components": [c["id"] for c in components if c["kind"] in ("actor", "external", "identity")]},
                  {"id": "aplicacion", "name": t("threats.suggest.boundary_application", locale), "components": [c["id"] for c in components if c["kind"] in PROCESSES]},
                  {"id": "datos", "name": t("threats.suggest.boundary_data", locale), "components": [c["id"] for c in components if c["kind"] in STORES]}]
    sources = "; ".join(f"{item['name']} ({', '.join((item.get('inventory') or {}).get('manifests') or []) or t('threats.suggest.no_manifests', locale)})"
                        for item in repositories)
    return {"name": name, "description": t("threats.suggest.description", locale, sources=sources[:880]),
            "components": components, "flows": flows, "boundaries": [item for item in boundaries if item["components"]]}


NODE_W, ROW, PAD = 184, 124, 36  # same measurements as the panel's editor


def merge_proposal(model: dict, proposal: dict) -> tuple[dict, dict]:
    """Adds to a model what is proposed from new repositories, without duplicating what is already there.

    A proposed component is the same as an existing one if kind and repository match (processes) or
    kind and name (actors, stores, third parties). New ones go inside their boundary if it is already
    drawn, or to the right of what is drawn: the layout the team made is kept.
    """
    merged = json.loads(json.dumps(model))
    components = merged.setdefault("components", [])
    flows = merged.setdefault("flows", [])
    boundaries = merged.setdefault("boundaries", [])
    used = {item["id"] for item in components}
    same: dict[str, str] = {}
    added = []

    def key(item: dict) -> tuple:
        return (item["kind"], item.get("asset")) if item["kind"] in PROCESSES and item.get("asset") else (item["kind"], item["name"].lower())
    existing = {key(item): item["id"] for item in components}
    for item in proposal.get("components", []):
        if key(item) in existing:
            same[item["id"]] = existing[key(item)]
            continue
        new = {**item, "id": _slug(item["name"], used)}
        same[item["id"]] = new["id"]
        existing[key(new)] = new["id"]
        components.append(new)
        added.append(new["id"])
    pairs = {(flow["source"], flow["target"]) for flow in flows}
    flow_ids = {flow["id"] for flow in flows} | {item["id"] for item in components}
    new_flows = 0
    for flow in proposal.get("flows", []):
        source, target = same.get(flow["source"]), same.get(flow["target"])
        if not source or not target or source == target or (source, target) in pairs:
            continue
        pairs.add((source, target))
        flows.append({**flow, "id": _slug(f"{source}-{target}", flow_ids), "source": source, "target": target})
        new_flows += 1
    placed = {member for boundary in boundaries for member in boundary["components"]}
    by_name = {boundary["name"].lower(): boundary for boundary in boundaries}
    boundary_ids = {boundary["id"] for boundary in boundaries}
    drawn = any(item.get("position") for item in components)
    right = max([item["position"]["x"] + NODE_W for item in components if item.get("position")]
                + [boundary["box"]["x"] + boundary["box"]["width"] for boundary in boundaries if boundary.get("box")] or [0]) + 80
    for proposed in proposal.get("boundaries", []):
        members = [same[member] for member in proposed["components"] if same.get(member) in added and same[member] not in placed]
        if not members:
            continue
        # A proposal may come in another language than the model: its boundary id is stable.
        target = by_name.get(proposed["name"].lower()) or next((item for item in boundaries if item["id"] == proposed["id"]), None)
        if target is None:
            target = {"id": _slug(proposed["id"], boundary_ids), "name": proposed["name"], "components": []}
            if drawn:
                target["box"] = {"x": right - PAD, "y": 40, "width": NODE_W + PAD * 2, "height": 70}
                right += NODE_W + PAD * 2 + 60
            boundaries.append(target)
            by_name[target["name"].lower()] = target
        for member in members:
            target["components"].append(member)
            placed.add(member)
            if drawn:
                component = next(item for item in components if item["id"] == member)
                box = target.get("box")
                if box:
                    inside = [item["position"]["y"] for item in components if item["id"] in target["components"] and item.get("position")]
                    component["position"] = {"x": box["x"] + PAD, "y": (max(inside) + ROW) if inside else box["y"] + 50}
                    box["height"] = max(box["height"], component["position"]["y"] - box["y"] + ROW)
    for member in added:  # no boundary: to the right of what is drawn
        component = next(item for item in components if item["id"] == member)
        if drawn and not component.get("position"):
            component["position"] = {"x": right, "y": 90}
            right += NODE_W + 60
    return merged, {"components": len(added), "flows": new_flows}


# ------------------------------------------------------------ STRIDE

STRIDE = {"S": msg("threats.stride.s"), "T": msg("threats.stride.t"), "R": msg("threats.stride.r"), "I": msg("threats.stride.i"),
          "D": msg("threats.stride.d"), "E": msg("threats.stride.e")}

# Each rule: id, base severity, STRIDE category, what it applies to and the CWEs that evidence it (texts: threats.rules.*).
RULES = [
    threat_methods.rule("TM-S01", "high", "S", "internet_process_unauthenticated", [306, 287]),
    threat_methods.rule("TM-S02", "high", "S", "identity", [287, 345, 347, 384, 613]),
    threat_methods.rule("TM-S03", "medium", "S", "inbound_from_external", [345, 347]),
    threat_methods.rule("TM-S04", "medium", "S", "web_app", [352]),
    threat_methods.rule("TM-T01", "high", "T", "process", [74, 77, 78, 79, 89, 94, 95, 611, 643, 917, 943, 1336]),
    threat_methods.rule("TM-T02", "medium", "T", "process", [1104, 1395, 937, 1035], evidence={"scanners": ("sca",), "any_cwe": True}),
    threat_methods.rule("TM-T03", "high", "T", "store_written_unauthenticated", [306, 284]),
    threat_methods.rule("TM-T04", "medium", "T", "flow_unencrypted_boundary", [319, 295]),
    threat_methods.rule("TM-R01", "low", "R", "process_sensitive", [778, 223, 117]),
    threat_methods.rule("TM-I01", "medium", "I", "process", [200, 209, 213, 532, 538, 540, 798, 312, 359],
                         mitigations=3, evidence={"scanners": ("sast", "secrets", "iac"), "any_cwe_for": ("secrets",)}),
    threat_methods.rule("TM-I02", "medium", "I", "store_sensitive_unencrypted", [311, 312]),
    threat_methods.rule("TM-I03", "high", "I", "store_credentials", [256, 257, 261, 327, 328, 759, 760, 916]),
    threat_methods.rule("TM-I04", "medium", "I", "flow_unencrypted_boundary", [319]),
    threat_methods.rule("TM-I05", "medium", "I", "flow_to_external_sensitive", [359, 201]),
    threat_methods.rule("TM-I06", "medium", "I", "storage", [732, 552]),
    threat_methods.rule("TM-D01", "medium", "D", "internet_process", [400, 770, 1333, 799]),
    threat_methods.rule("TM-D02", "low", "D", "external", [400]),
    threat_methods.rule("TM-E01", "high", "E", "process_authenticated", [285, 639, 862, 863, 269, 915]),
    threat_methods.rule("TM-E02", "high", "E", "process_calls_out", [918]),
]
SEVERITY_ORDER = ("critical", "high", "medium", "low")


def severity_rank(value) -> int:
    """Where a severity sorts: ours in order, a team's own level (without an equivalent) after them."""
    return SEVERITY_ORDER.index(value) if value in SEVERITY_ORDER else len(SEVERITY_ORDER)


def _index(model: dict) -> tuple[dict, dict]:
    components = {item["id"]: item for item in model.get("components", [])}
    boundary_of = {member: boundary["id"] for boundary in model.get("boundaries", []) for member in boundary["components"]}
    return components, boundary_of


def _kind(component: dict) -> str:
    """Custom kinds keep a base role for the rules and the external formats."""
    return (component.get("custom_base") or "service") if component["kind"] == "custom" else component["kind"]


def _targets(model: dict, rules: list[dict] | None = None) -> list[tuple[dict, dict | None, dict | None]]:
    """(rule, component, flow) for every rule that applies. The conditions are here, in plain sight."""
    components, boundary_of = _index(model)
    flows = model.get("flows", [])
    inbound = {cid: [flow for flow in flows if flow["target"] == cid] for cid in components}
    outbound = {cid: [flow for flow in flows if flow["source"] == cid] for cid in components}
    result = []
    for rule in RULES if rules is None else rules:
        applies = rule["applies"]
        if applies.startswith("flow_"):
            for flow in flows:
                crosses = boundary_of.get(flow["source"]) != boundary_of.get(flow["target"])
                sensitive = any(CLASSIFICATIONS.get(item, 2) >= 3 for item in flow["data"])
                target = components[flow["target"]]
                if ((applies == "flow_unencrypted_boundary" and crosses and not flow["encrypted"] and set(flow["data"]) - {"public"})
                        or (applies == "flow_to_external_sensitive" and _kind(target) == "external" and sensitive)
                        or (applies == "flow_personal_to_external" and _kind(target) == "external" and "pii" in flow["data"])):
                    result.append((rule, None, flow))
            continue
        for component in components.values():
            kind = _kind(component)
            process = kind in PROCESSES
            sensitive = any(CLASSIFICATIONS.get(item, 2) >= 3 for item in component["data"]) or any(
                CLASSIFICATIONS.get(item, 2) >= 3 for flow in inbound[component["id"]] + outbound[component["id"]] for item in flow["data"])
            # Personal data (LINDDUN): it stores it, or it comes in or goes out through some flow.
            personal = "pii" in component["data"] or any("pii" in flow["data"] for flow in inbound[component["id"]] + outbound[component["id"]])
            match = {
                "process": process,
                "web_app": kind == "web_app",
                "identity": kind == "identity",
                "external": kind == "external",
                "storage": kind == "storage",
                "internet_process": process and component["internet_facing"],
                "internet_process_unauthenticated": process and component["internet_facing"] and not component["authenticates"],
                "process_authenticated": process and component["authenticates"],
                "process_sensitive": process and sensitive,
                "process_calls_out": process and any(_kind(components[flow["target"]]) in ("external", "service", "api", "identity") for flow in outbound[component["id"]]),
                "inbound_from_external": process and any(_kind(components[flow["source"]]) == "external" for flow in inbound[component["id"]]),
                "store_written_unauthenticated": kind in STORES and any(not flow["authenticated"] for flow in inbound[component["id"]]),
                "store_sensitive_unencrypted": kind in STORES and not component["encrypted_at_rest"] and any(CLASSIFICATIONS.get(item, 2) >= 3 for item in component["data"]),
                "store_credentials": kind in STORES and "credentials" in component["data"],
                "store_personal": kind in STORES and "pii" in component["data"],
                "store_personal_unencrypted": kind in STORES and "pii" in component["data"] and not component["encrypted_at_rest"],
                "process_personal": process and personal,
                "process_personal_facing_actor": process and personal and any(_kind(components[flow["source"]]) == "actor" for flow in inbound[component["id"]]),
            }.get(applies, False)
            if match:
                result.append((rule, component, None))
    return result


def _severity(model: dict, rule: dict, component: dict | None, flow: dict | None) -> str:
    """Rule's base severity: one level up if exposed with critical data, one down if internal and low-sensitivity."""
    components, _ = _index(model)
    if flow is not None:
        data = flow["data"]
        exposure = 3 if any(components[end]["internet_facing"] or _kind(components[end]) in ("actor", "external") for end in (flow["source"], flow["target"])) else 2
    else:
        related = [f for f in model.get("flows", []) if component["id"] in (f["source"], f["target"])]
        data = component["data"] + [item for f in related for item in f["data"]]
        exposure = 3 if component["internet_facing"] or _kind(component) in ("external", "identity") else 2 if related else 1
    impact = max([CLASSIFICATIONS.get(item, 2) for item in data] or [2])
    level = SEVERITY_ORDER.index(rule["base"])
    if exposure == 3 and impact >= 4:
        level -= 1
    elif exposure == 1 or impact <= 1:
        level += 1
    return SEVERITY_ORDER[max(0, min(level, len(SEVERITY_ORDER) - 1))]


def _scopes_near(model: dict, component: dict | None, flow: dict | None) -> set[tuple[str, str]]:
    """(repository, folder) whose code implements or touches the element; empty folder = whole repository."""
    components, _ = _index(model)
    if component is not None and _kind(component) in PROCESSES:
        return {(component["asset"], component.get("path") or "")} if component.get("asset") else set()
    if flow is not None:
        ends = [components[flow["source"]], components[flow["target"]]]
    else:
        ends = [component] + [components[f["source"] if f["target"] == component["id"] else f["target"]]
                              for f in model.get("flows", []) if component["id"] in (f["source"], f["target"])]
    return {(item["asset"], item.get("path") or "") for item in ends if item.get("asset")}


def threats(model: dict, findings_by_asset: dict[str, list[dict]] | None = None, *, locale: str | None = None) -> list[dict]:
    """The model's threats with their severity, scan evidence and team decision, rendered for `locale`."""
    decisions = model.get("decisions", {})
    rows = []
    method = model.get("methodology") or "stride"
    families = ([threat_methods.RULE_BASED[method]] if method in threat_methods.RULE_BASED else
                [item for item in ("stride", "linddun") if item in model.get("custom_modules", [])] if method == "custom" else [])
    for family in families:
      rules = RULES if family == "stride" else threat_methods.LINDDUN_RULES
      categories = STRIDE if family == "stride" else threat_methods.LINDDUN
      for rule, component, flow in _targets(model, rules):
        element = flow["id"] if flow else component["id"]
        threat_id = hashlib.sha256(f"{rule['id']}|{element}".encode()).hexdigest()[:16]
        evidence = []
        policy = rule.get("evidence") or {}
        # By default only first-party code is evidence; a vulnerability in a dependency is attributed to TM-T02.
        scanners = policy.get("scanners", ("sast", "secrets", "iac"))
        scopes = sorted(_scopes_near(model, component, flow))
        for asset, folder in scopes:
            for finding in (findings_by_asset or {}).get(asset, []):
                scanner = finding.get("scanner")
                if scanner not in scanners:
                    continue
                # Only the component's code: in a monorepo, the backend is no evidence of frontend threats.
                if folder and not str(finding.get("path") or "").startswith(folder):
                    continue
                if (policy.get("any_cwe") or scanner in policy.get("any_cwe_for", ())
                        or set(finding.get("cwe") or []) & set(rule["cwe"])):
                    evidence.append({"asset": asset, "run_id": finding.get("run_id"), "fingerprint": finding["fingerprint"],
                                     "title": finding["title"], "severity": finding["severity"],
                                     "location": f"{finding.get('path')}:{finding.get('line')}", "cwe": finding.get("cwe")})
        decision = decisions.get(threat_id)
        status = decision["status"] if decision else "evidenced" if evidence else "open"
        # Marked mitigated or not applicable, yet the scans still find it: it goes back to «with evidence» until they
        # don't (the decision is kept, and returns by itself once the evidence is gone).
        contradicted = bool(decision and evidence and decision["status"] in ("mitigated", "not_applicable"))
        if contradicted:
            status = "evidenced"
        severity = _severity(model, rule, component, flow)
        if evidence:
            worst = min((SEVERITY_ORDER.index(item["severity"]) for item in evidence if item["severity"] in SEVERITY_ORDER), default=3)
            severity = SEVERITY_ORDER[min(SEVERITY_ORDER.index(severity), worst)]
        components, _ = _index(model)
        label = (f"{components[flow['source']]['name']} → {components[flow['target']]['name']}" if flow else component["name"])
        rows.append({"id": threat_id, "rule": rule["id"], "stride": rule["stride"], "category": categories[rule["stride"]], "framework": family,
                     "title": rule["title"], "why": rule["why"], "mitigations": rule["mitigations"], "cwe": rule["cwe"],
                     "element": element, "element_type": "flow" if flow else "component", "element_name": label,
                     "severity": severity, "status": status, "decision": decision, "contradicted": contradicted,
                     "evidence": evidence[:20], "evidence_count": len(evidence),
                     "evidence_scope": [{"asset": asset, "path": folder or None} for asset, folder in scopes]})
    if method != "custom" or "manual" in model.get("custom_modules", ["manual", "elements"]):
        rows += _manual_rows(model, decisions)
    rows = localize(rows, locale or default_locale())
    order = {"evidenced": 0, "open": 1, "accepted": 2, "mitigated": 3, "not_applicable": 4}
    return sorted(rows, key=lambda row: (order[row["status"]], severity_rank(row["severity"]), row["stride"], row["element_name"]))


def _manual_rows(model: dict, decisions: dict) -> list[dict]:
    """Threats written by the team: same decision cycle as the rule-based ones."""
    components, _ = _index(model)
    flows = {flow["id"]: flow for flow in model.get("flows", [])}
    # A category code of the approach ("S", "Dd") is shown with its name; anything else, as is.
    names = threat_methods.LINDDUN if model.get("methodology") == "linddun" else STRIDE
    equivalent = (model.get("level_equivalents") or {}).get("severity") or {}
    rows = []
    for item in model.get("manual_threats", []):
        threat_id = hashlib.sha256(f"manual|{item['id']}".encode()).hexdigest()[:16]
        element = item.get("element") or ""
        flow = flows.get(element)
        name = (f"{components[flow['source']]['name']} → {components[flow['target']]['name']}" if flow
                else components[element]["name"] if element in components else msg("threats.threat.whole_system"))
        decision = decisions.get(threat_id)
        rows.append({"id": threat_id, "rule": "TEAM", "stride": item.get("category") or "", "category": names.get(item.get("category") or "", item.get("category") or msg("threats.threat.no_category")),
                     "framework": "manual", "manual_id": item["id"], "title": item["title"], "why": item.get("scenario") or "",
                     "mitigations": [item["mitigation"]] if item.get("mitigation") else [], "cwe": [],
                     "element": element, "element_type": "flow" if flow else "component" if element in components else "system",
                     "element_name": name, "status": decision["status"] if decision else "open",
                     # A team's own severity sorts as its equivalent, if it has one, and keeps its name.
                     "severity": item["severity"] if item["severity"] in SEVERITY_ORDER else equivalent.get(item["severity"], item["severity"]),
                     "severity_label": None if item["severity"] in SEVERITY_ORDER else item["severity"],
                     "decision": decision, "contradicted": False, "evidence": [], "evidence_count": 0, "evidence_scope": [],
                     "likelihood": item.get("likelihood"), "impact": item.get("impact"), "owner": item.get("owner") or "",
                     "custom_properties": item.get(KEPT) or {}})
    return rows


def evidence_index(data_dir: Path, assets: set[str]) -> dict[str, list[dict]]:
    """Active findings from the latest full scan of each linked repository."""
    from pitangus.modules.runs.store import find_runs, load_run
    latest: dict[str, dict] = {}
    from pitangus.modules.sources.assets import asset_key
    for row in find_runs(data_dir, types=("repository_scan",), statuses=("completed", "incomplete")):
        key = asset_key(row)
        source = (row.get("source") or {}).get("id")
        match = key if key in assets else source if source in assets else None
        if match and match not in latest:
            latest[match] = row
    result = {}
    for asset, row in latest.items():
        try:
            record = triage.annotate(data_dir, load_run(data_dir, row["id"]))
        except (ValueError, OSError):
            continue
        result[asset] = [{**item, "run_id": record["id"]} for item in record["findings"] if triage.is_active(item)]
    return result


def _category_key(row: dict) -> str:
    return f"{row.get('framework') or 'stride'}:{row['stride']}"


def summary(rows: list[dict]) -> dict:
    return {"total": len(rows),
            "by_status": {status: sum(1 for row in rows if row["status"] == status)
                          for status in ("evidenced", "open", "accepted", "mitigated", "not_applicable")},
            # By approach and category: LINDDUN's D and I are not STRIDE's.
            "by_stride": {key: sum(1 for row in rows if _category_key(row) == key) for key in dict.fromkeys(_category_key(row) for row in rows)},
            "by_severity": {level: sum(1 for row in rows if row["severity"] == level and row["status"] in ("evidenced", "open"))
                            for level in SEVERITY_ORDER}}


# ------------------------------------------------------------ exports

def to_threat_dragon(model: dict, rows: list[dict], *, locale: str | None = None) -> dict:
    """OWASP Threat Dragon v2: a STRIDE diagram with actors, processes, stores, flows and boundaries."""
    locale = locale or default_locale()
    rows = localize(rows, locale)
    shapes = {"actor": ("actor", "tm.Actor"), "external": ("actor", "tm.Actor"), "identity": ("actor", "tm.Actor"),
              **dict.fromkeys(STORES, ("store", "tm.Store")), **dict.fromkeys(PROCESSES, ("process", "tm.Process"))}
    status = {"evidenced": "Open", "open": "Open", "accepted": "Open", "mitigated": "Mitigated", "not_applicable": "NA"}
    by_element: dict[str, list[dict]] = {}
    for number, row in enumerate(rows, 1):
        privacy = row.get("framework") == "linddun" or (row.get("framework") == "manual" and model.get("methodology") == "linddun")
        by_element.setdefault(row["element"], []).append({
            "id": row["id"], "number": number, "title": row["title"],
            "type": (LINDDUN_EN if privacy else STRIDE_EN).get(row["stride"], row["category"]),
            "status": status[row["status"]], "severity": {"critical": "High", "high": "High", "medium": "Medium", "low": "Low"}.get(row["severity"], "Low"),
            "description": row["why"] + (" " + t("threats.exports.evidence", locale, count=row["evidence_count"]) if row["evidence_count"] else ""),
            "mitigation": "; ".join(row["mitigations"]), "modelType": "LINDDUN" if privacy else "STRIDE", "score": ""})
    layout = _layout(model)
    cells = []
    for boundary in model.get("boundaries", []):
        box = layout["boundaries"].get(boundary["id"])
        if box:
            cells.append({"id": f"b-{boundary['id']}", "shape": "trust-boundary-box", "zIndex": -1,
                          "position": {"x": box["x"], "y": box["y"]}, "size": {"width": box["width"], "height": box["height"]},
                          "attrs": {"label": {"text": boundary["name"]}},
                          "data": {"type": "tm.BoundaryBox", "name": boundary["name"], "description": boundary.get("description", ""),
                                   "isTrustBoundary": True, "hasOpenThreats": False}})
    for component in model.get("components", []):
        shape, kind = shapes[_kind(component)]
        position = layout["nodes"][component["id"]]
        items = by_element.get(component["id"], [])
        cells.append({"id": component["id"], "shape": shape, "zIndex": 1,
                      "position": {"x": position["x"], "y": position["y"]}, "size": {"width": 160, "height": 80},
                      "attrs": {"text": {"text": component["name"]}},
                      "data": {"type": kind, "name": component["name"], "description": component.get("description", ""),
                               "outOfScope": False, "reasonOutOfScope": "", "threats": items,
                               "hasOpenThreats": any(item["status"] == "Open" for item in items),
                               "isEncrypted": component.get("encrypted_at_rest", False), "isWebApplication": _kind(component) == "web_app",
                               "providesAuthentication": _kind(component) == "identity"}})
    for flow in model.get("flows", []):
        items = by_element.get(flow["id"], [])
        cells.append({"id": flow["id"], "shape": "flow", "zIndex": 2, "source": {"cell": flow["source"]}, "target": {"cell": flow["target"]},
                      "labels": [flow["name"] or flow["protocol"].upper()],
                      "data": {"type": "tm.Flow", "name": flow["name"] or flow["protocol"].upper(), "description": flow.get("description", ""),
                               "protocol": flow["protocol"],
                               "isEncrypted": flow["encrypted"], "isPublicNetwork": False, "outOfScope": False,
                               "reasonOutOfScope": "", "threats": items, "hasOpenThreats": any(item["status"] == "Open" for item in items)}})
    return {"version": "2.2.0", "summary": {"title": model["name"], "owner": model.get("updated_by", ""),
                                            "description": model.get("description", ""), "id": 0},
            "detail": {"contributors": [], "reviewer": "", "threatTop": len(rows), "threatMax": len(rows),
                       "diagrams": [{"id": 0, "title": model["name"], "diagramType": "LINDDUN" if model.get("methodology") == "linddun" else "STRIDE",
                                     "placeholder": "", "thumbnail": "",
                                     "version": "2.2.0", "cells": cells}]}}


STRIDE_EN = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation", "I": "Information disclosure",
             "D": "Denial of service", "E": "Elevation of privilege"}
LINDDUN_EN = {"L": "Linking", "I": "Identifying", "Nr": "Non-repudiation", "D": "Detecting", "Dd": "Data disclosure",
              "U": "Unawareness", "Nc": "Non-compliance"}


def _layout(model: dict) -> dict:
    return threat_diagram.layout(model)


def _node_size(component: dict) -> tuple[float, float]:
    return threat_diagram.node_size(component)


def to_svg(model: dict, *, locale: str | None = None) -> str:
    """Exports only the current diagram as a self-contained SVG, with no code or scripts."""
    locale = locale or default_locale()
    return threat_diagram.to_svg(model, localize(KINDS, locale), locale=locale)


def to_pytm(model: dict, *, locale: str | None = None) -> str:
    """Equivalent OWASP pytm script, for anyone who wants to keep modeling as code."""
    locale = locale or default_locale()
    def name(value: str) -> str:
        return json.dumps(value, ensure_ascii=False)
    variables = {item["id"]: "c_" + item["id"].replace("-", "_") for item in model.get("components", [])}
    boundary_vars = {item["id"]: "b_" + item["id"].replace("-", "_") for item in model.get("boundaries", [])}
    member_of = {member: boundary["id"] for boundary in model.get("boundaries", []) for member in boundary["components"]}
    classes = {"actor": "Actor", "external": "ExternalEntity", "identity": "ExternalEntity", "web_app": "Server",
               "api": "Server", "service": "Process", "function": "Lambda", **dict.fromkeys(STORES, "Datastore")}
    comment = lambda value: "# " + " ".join(value.split())  # noqa: E731
    lines = ["#!/usr/bin/env python3", comment(t("threats.exports.pytm_generated", locale, name=name(model["name"]))),
             comment(t("threats.exports.pytm_requires", locale)),
             "from pytm import TM, Actor, Boundary, Dataflow, Datastore, ExternalEntity, Lambda, Process, Server", "",
             f"tm = TM({name(model['name'])})", f"tm.description = {name(model.get('description') or model['name'])}",
             "tm.isOrdered = True", ""]
    for item in model.get("assumptions") or []:
        lines.append(comment(t("threats.exports.pytm_assumption", locale, text=item["text"])))
    if model.get("assumptions"):
        lines.append("")
    for boundary in model.get("boundaries", []):
        lines.append(f"{boundary_vars[boundary['id']]} = Boundary({name(boundary['name'])})")
        if boundary.get("description"):
            lines.append(f"{boundary_vars[boundary['id']]}.description = {name(boundary['description'])}")
    lines.append("")
    for component in model.get("components", []):
        variable = variables[component["id"]]
        lines.append(f"{variable} = {classes[_kind(component)]}({name(component['name'])})")
        if component["id"] in member_of:
            lines.append(f"{variable}.inBoundary = {boundary_vars[member_of[component['id']]]}")
        if _kind(component) in STORES:
            lines.append(f"{variable}.isEncrypted = {component.get('encrypted_at_rest', False)}")
        if _kind(component) in PROCESSES:
            lines.append(f"{variable}.authenticatesSource = {component.get('authenticates', False)}")
    lines.append("")
    for flow in model.get("flows", []):
        label = flow["name"] or flow["protocol"].upper()
        variable = "f_" + flow["id"].replace("-", "_")
        lines += [f"{variable} = Dataflow({variables[flow['source']]}, {variables[flow['target']]}, {name(label)})",
                  f"{variable}.protocol = {name(flow['protocol'].upper())}",
                  f"{variable}.isEncrypted = {flow['encrypted']}"]
        if flow.get("description"):
            lines.append(f"{variable}.description = {name(flow['description'])}")
    lines += ["", 'if __name__ == "__main__":', "    tm.process()", ""]
    return "\n".join(lines)


def to_markdown(model: dict, rows: list[dict], *, locale: str | None = None) -> str:
    return threat_report.to_markdown(model, rows, locale=locale)
