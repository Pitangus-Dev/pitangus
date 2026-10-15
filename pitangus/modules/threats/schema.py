"""JSON Schema (draft 2020-12) of the portable threat model, built from the same lists the importer uses.

`make openapi` writes it to web/src/examples/threat-models/schema.json (the panel offers it for download and builds
the AI prompt from it); a test checks the file is current. A document that validates against it imports without
errors. Open fields (protocol, kind, data) list our values under `examples`: any other short text is kept as the
team's own value, with a warning that Pitangus has no automatic checks for it. The importer is more lenient than the
schema: `x-pitangus-aliases` lists the field synonyms it reads as ours, `x-pitangus-synonyms` the value synonyms of
a closed list, and any other field is kept as written and exported back.
"""

from __future__ import annotations

from pitangus.modules.threats import attack
from pitangus.modules.threats import diagram as threat_diagram
from pitangus.modules.threats import methods as threat_methods
from pitangus.modules.threats import model as tm

ID_PATTERN = "^[a-z0-9][a-z0-9-]{0,39}$"
TECHNIQUE_PATTERN = "^T[0-9]{4}(\\.[0-9]{3})?$"


def _text(limit: int, description: str | None = None) -> dict:
    return {"type": "string", "maxLength": limit, **({"description": description} if description else {})}


def _object(properties: dict, required: tuple[str, ...] = ()) -> dict:
    return {"type": "object", "properties": properties, "required": list(required), "additionalProperties": False}


def _id(description: str) -> dict:
    return {"type": "string", "pattern": ID_PATTERN, "description": description}


def _aliased(definition: dict, aliases: dict[str, str]) -> dict:
    return {**definition, "x-pitangus-aliases": dict(sorted(aliases.items()))}


def _synonyms(definition: dict, synonyms: dict[str, str]) -> dict:
    return {**definition, "x-pitangus-synonyms": dict(sorted(synonyms.items()))}


def build() -> dict:
    kinds = list(tm.KINDS)
    levels = list(threat_methods.LEVELS)
    data = {"type": "array", "maxItems": 30, "items": {"type": "string", "maxLength": tm.DATA_LIMIT, "examples": list(tm.CLASSIFICATIONS)},
            "description": "Data classes. Known: " + ", ".join(tm.CLASSIFICATIONS) + ". Any other short text is kept as your own class: it counts as internal data and no privacy or credential rules apply to it."}
    reference = {"type": "string", "description": "The id of a component or flow of this model"}
    component = _aliased(_object({
        "id": _id("Unique among components and flows: lowercase letters, digits and hyphens"),
        "name": _text(80), "description": _text(400), "technology": _text(80),
        "kind": {"type": "string", "maxLength": 80, "examples": kinds,
                 "description": "Known: " + ", ".join(kinds) + ". Any other value is kept as your own type (custom_kind), analyzed as custom_base."},
        "custom_kind": _text(80, "Name of your own type when kind is custom"),
        "custom_base": {"enum": [kind for kind in kinds if kind != "custom"], "description": "The role a custom type is analyzed as (default service)"},
        "asset_ref": _text(200, "A repository or domain to link later; never linked automatically"),
        "path": _text(200, "Folder of the component's code in its repository, e.g. services/api/"),
        "data": data, "internet_facing": {"type": "boolean"}, "authenticates": {"type": "boolean"}, "encrypted_at_rest": {"type": "boolean"},
        "color": {"enum": list(threat_diagram.COLORS)}, "origin": {"enum": ["suggested", "manual"]},
        "position": {"type": ["object", "null"]}, "size": {"type": ["object", "null"]},
    }, ("id", "name", "kind")), tm.COMPONENT_ALIASES)
    flow = _aliased(_object({
        "id": _id("Unique among components and flows"), "source": reference, "target": reference, "name": _text(80),
        "description": _text(tm.DESCRIPTION_LIMIT, "What travels and why; plain text, line breaks allowed"),
        "protocol": {"type": "string", "maxLength": tm.PROTOCOL_LIMIT, "examples": list(tm.PROTOCOLS),
                     "description": "Known: " + ", ".join(tm.PROTOCOLS) + ". Any other short text is kept as your own protocol; Pitangus can't tell whether it's encrypted, so set encrypted."},
        "data": data, "authenticated": {"type": "boolean"}, "encrypted": {"type": "boolean"},
    }, ("id", "source", "target", "protocol")), tm.FLOW_ALIASES)
    boundary = _aliased(_object({"id": _id("Unique among boundaries"), "name": _text(80),
                                 "components": {"type": "array", "items": reference, "description": "Component ids; a component belongs to one boundary at most"},
                                 "description": _text(tm.DESCRIPTION_LIMIT, "What the boundary separates; plain text, line breaks allowed"),
                                 "box": {"type": ["object", "null"]}, "color": {"enum": list(threat_diagram.COLORS)}}, ("id", "name")), tm.BOUNDARY_ALIASES)
    level = _synonyms({"enum": [*levels, None]}, threat_methods.LEVEL_ALIASES)
    manual = _aliased(_object({"id": _id("Unique among team threats"), "title": _text(160), "category": _text(40, "Free text, e.g. a STRIDE or LINDDUN category"),
                               "element": reference, "severity": _synonyms({"enum": list(threat_methods.SEVERITIES)}, threat_methods.SEVERITY_ALIASES),
                               "scenario": _text(1500, "How the attack happens; a description written under a synonym is joined here"),
                               "mitigation": _text(1500), "likelihood": level, "impact": level, "owner": _text(80)}, ("id", "title")), threat_methods.MANUAL_ALIASES)
    node = _aliased(_object({"id": _id("Unique within its tree"), "parent": {"type": ["string", "null"], "description": "The id of another step of the same tree, or null for a path"},
                             "text": _text(200), "gate": _synonyms({"enum": ["and", "or"], "description": "Case doesn't matter"}, threat_methods.GATE_ALIASES),
                             "element": reference, "difficulty": level, "mitigated": {"type": "boolean"}}, ("id", "text")), threat_methods.NODE_ALIASES)
    tree = _aliased(_object({"id": _id("Unique among trees"), "goal": _text(200, "The attacker's goal; a name written under a synonym is joined in front of it"),
                             "nodes": {"type": "array", "maxItems": threat_methods.LIMITS["tree_nodes"], "items": {"$ref": "#/$defs/attack_tree_node"}}}, ("id", "goal")), threat_methods.TREE_ALIASES)
    mapping = _aliased(_object({"technique": {"type": "string", "pattern": TECHNIQUE_PATTERN, "examples": list(threat_methods.TECHNIQUES),
                                              "description": f"A MITRE ATT&CK Enterprise technique or sub-technique ID (ATT&CK v{attack.version()}, bundled: any of them is recognized). "
                                                             "A revoked, deprecated or unknown ID is kept, with a warning.",
                                              "x-pitangus-attack-version": attack.version()},
                                "element": reference, "status": _synonyms({"enum": list(threat_methods.MAPPING_STATUS)}, threat_methods.STATUS_ALIASES),
                                "note": _text(600)}, ("technique",)), threat_methods.MAPPING_ALIASES)
    assumption = _aliased(_object({"id": _id("Unique among assumptions; optional, given when missing"),
                                   "text": _text(1000, "What the model takes for granted; plain text, line breaks allowed")}, ("text",)),
                          threat_methods.ASSUMPTION_ALIASES)
    model = _aliased(_object({
        "name": _text(80), "description": _text(1000),
        "methodology": {"enum": list(threat_methods.METHODOLOGIES)},
        "custom_modules": {"type": "array", "items": {"enum": sorted(threat_methods.CUSTOM_MODULES)}, "description": "Only with methodology custom"},
        "components": {"type": "array", "maxItems": tm.LIMITS["components"], "items": {"$ref": "#/$defs/component"}},
        "flows": {"type": "array", "maxItems": tm.LIMITS["flows"], "items": {"$ref": "#/$defs/flow"}},
        "boundaries": {"type": "array", "maxItems": tm.LIMITS["boundaries"], "items": {"$ref": "#/$defs/boundary"}},
        "legend": {"type": "object", "propertyNames": {"enum": list(threat_diagram.COLORS)}, "additionalProperties": _text(40)},
        "repository_refs": {"type": "array", "maxItems": 50, "items": _text(200)},
        "level_equivalents": {"type": "object", "description": "Where your own levels sort among ours, e.g. {\"severity\": {\"Severe\": \"high\"}}; without one they go after the known levels",
                              "properties": {"severity": {"type": "object", "additionalProperties": {"enum": list(threat_methods.SEVERITIES)}},
                                             **{field: {"type": "object", "additionalProperties": {"enum": levels}} for field in ("likelihood", "impact", "difficulty")}},
                              "additionalProperties": False},
        "assumptions": {"type": "array", "maxItems": threat_methods.LIMITS["assumptions"], "items": {"$ref": "#/$defs/assumption"},
                        "description": "What the model takes for granted (e.g. the cloud provider's share of the work). Plain strings are accepted too"},
        "manual_threats": {"type": "array", "maxItems": threat_methods.LIMITS["manual_threats"], "items": {"$ref": "#/$defs/manual_threat"}},
        "attack_trees": {"type": "array", "maxItems": threat_methods.LIMITS["attack_trees"], "items": {"$ref": "#/$defs/attack_tree"}},
        "attack_mappings": {"type": "array", "maxItems": threat_methods.LIMITS["attack_mappings"], "items": {"$ref": "#/$defs/attack_mapping"}},
        "pasta": _aliased(_object({key: _text(4000) for key, _ in threat_methods.PASTA_STAGES}), threat_methods.PASTA_ALIASES),
    }, ("name",)), tm.MODEL_ALIASES)
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://pitangus.dev/schemas/threat-model-v1.json",
        "title": "Pitangus threat model (portable format, version 1)",
        "description": "Ids, references (source, target, element, parent, boundary components) and types are strict: an error stops the import. "
                       "Protocol, component kind and data classes accept your own values; ATT&CK accepts any well-formed technique ID. "
                       "The importer also reads the synonyms listed under x-pitangus-aliases (fields) and x-pitangus-synonyms (values) as ours, "
                       "and keeps any other field as written, exporting it back.",
        **_object({"format": {"const": "pitangus-threat-model"}, "version": {"const": 1}, "model": {"$ref": "#/$defs/model"}},
                  ("format", "version", "model")),
        "$defs": {"model": model, "component": component, "flow": flow, "boundary": boundary, "assumption": assumption, "manual_threat": manual,
                  "attack_tree": tree, "attack_tree_node": node, "attack_mapping": mapping},
    }
