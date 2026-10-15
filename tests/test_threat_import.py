"""Importing threat models: every problem at once, the team's own values kept, and one contract (schema, prompt, validator)."""

import ast
import glob
import json
import os
import re
import unittest
from pathlib import Path
from unittest.mock import patch

from pitangus.modules.identity.auth import Users
from pitangus.modules.threats import attack
from pitangus.modules.threats import methods as threat_methods
from pitangus.modules.threats import model as tm
from pitangus.modules.threats import report as threat_report
from pitangus.modules.threats import schema as threat_schema
from pitangus.modules.threats.problems import Problems
from pitangus.shared.i18n import localize
from test_auth import PASSWORD, HttpCase

EXAMPLES = Path(__file__).resolve().parents[1] / "web/src/examples/threat-models"
# A real model written by an AI assistant: descriptions on flows, boundaries and threats, component_id, assumptions,
# trees with a name and a goal, ATT&CK status "potential" and sub-techniques outside our suggestions.
ASSISTANT = Path(__file__).resolve().parent / "fixtures/threat-model-from-assistant.json"
TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


def schema_errors(value, node: dict, root: dict, path: str = "") -> list[str]:
    """The subset of JSON Schema 2020-12 our schema uses; enough to check the examples against it."""
    if "$ref" in node:
        node = root["$defs"][node["$ref"].split("/")[-1]]
    errors = []
    if "const" in node and value != node["const"]:
        errors.append(f"{path}: const")
    if "enum" in node and value not in node["enum"]:
        errors.append(f"{path}: enum {value!r}")
    if "type" in node:
        kinds = node["type"] if isinstance(node["type"], list) else [node["type"]]
        if not any(isinstance(value, TYPES[kind]) and not (kind != "boolean" and isinstance(value, bool)) for kind in kinds):
            return [f"{path}: type"]
    if isinstance(value, str):
        if len(value) > node.get("maxLength", 10**9):
            errors.append(f"{path}: maxLength")
        if "pattern" in node and not re.search(node["pattern"], value):
            errors.append(f"{path}: pattern")
    if isinstance(value, list):
        if len(value) > node.get("maxItems", 10**9):
            errors.append(f"{path}: maxItems")
        for index, item in enumerate(value):
            errors += schema_errors(item, node.get("items", {}), root, f"{path}/{index}")
    if isinstance(value, dict):
        errors += [f"{path}: required {key}" for key in node.get("required", []) if key not in value]
        properties = node.get("properties", {})
        for key, item in value.items():
            if "propertyNames" in node:
                errors += schema_errors(key, node["propertyNames"], root, f"{path}/{key} (name)")
            if key in properties:
                errors += schema_errors(item, properties[key], root, f"{path}/{key}")
            elif node.get("additionalProperties") is False:
                errors.append(f"{path}/{key}: additional")
            elif isinstance(node.get("additionalProperties"), dict):
                errors += schema_errors(item, node["additionalProperties"], root, f"{path}/{key}")
    return errors


def user_case() -> dict:
    """The «Custom» example as the user's AI assistant wrote it: a Wi-Fi link and real ATT&CK sub-techniques."""
    document = json.loads((EXAMPLES / "es/custom.json").read_text(encoding="utf-8"))
    model = document["model"]
    model["flows"][0]["protocol"] = "wifi"
    target = model["components"][0]["id"]
    model["attack_mappings"] += [{"technique": key, "element": target} for key in ("T1552.001", "T1557", "T1565.001", "T1499", "T1552.004")]
    return document


class ImportProblemsTests(unittest.TestCase):
    def test_real_attack_sub_techniques_import_without_problems(self):
        imported, problems = tm.inspect_portable(user_case())
        self.assertIsNotNone(imported)
        self.assertEqual({item["severity"] for item in problems}, {"warning"})  # only the Wi-Fi link, whose encryption isn't said
        self.assertEqual(imported["flows"][0]["protocol"], "wifi")
        techniques = [item["technique"] for item in imported["attack_mappings"]]
        self.assertTrue({"T1552.001", "T1557", "T1565.001", "T1499", "T1552.004"} <= set(techniques))
        self.assertEqual({item["path"] for item in problems}, {"/model/flows/0/protocol"})

    def test_every_error_comes_back_at_once_with_its_location(self):
        document = user_case()
        model = document["model"]
        model["flows"][1]["target"] = "nowhere"
        model["components"][1]["kind"] = 7
        model["components"].append(dict(model["components"][2]))
        model["attack_mappings"].append({"technique": "TA0001"})
        imported, problems = tm.inspect_portable(document)
        self.assertIsNone(imported)
        errors = [item for item in problems if item["severity"] == "error"]
        self.assertEqual([item["path"] for item in errors], ["/model/components/1/kind", f"/model/components/{len(model['components']) - 1}/id",
                                                             "/model/flows/1/target", f"/model/attack_mappings/{len(model['attack_mappings']) - 1}/technique"])
        self.assertEqual(problems[:len(errors)], errors)  # errors first, then the warnings
        self.assertTrue(any(item["severity"] == "warning" for item in problems))
        with self.assertRaises(tm.ModelError) as raised:
            tm.from_portable(document)
        self.assertEqual(len(raised.exception.problems), len(problems))

    def test_dangling_references_stay_errors(self):
        base = json.loads((EXAMPLES / "en/stride.json").read_text(encoding="utf-8"))
        for section, change in (("flows", {"source": "ghost"}), ("boundaries", {"components": ["ghost"]}),
                                ("manual_threats", {"element": "ghost"})):
            with self.subTest(section=section):
                document = json.loads(json.dumps(base))
                document["model"][section][0].update(change)
                imported, problems = tm.inspect_portable(document)
                self.assertIsNone(imported)
                self.assertIn("ghost", localize(next(item for item in problems if item["severity"] == "error"), "en")["message"])

    def test_labels_are_bounded_and_carry_no_markup(self):
        document = json.loads((EXAMPLES / "en/stride.json").read_text(encoding="utf-8"))
        component = document["model"]["components"][0]
        component["name"] = '<img src=x onerror=alert(1)>Customer‮' + "x" * 200
        document["model"]["flows"][0]["protocol"] = "<b>Wi-Fi 6E</b> over a very long description"
        document["model"]["components"][1]["data"] = ["Health records <script>", "PII"]
        imported, problems = tm.inspect_portable(document)
        self.assertEqual(imported["components"][0]["name"], ("Customer" + "x" * 200)[:80])
        self.assertEqual(imported["flows"][0]["protocol"], "Wi-Fi 6E over a very lon"[:tm.PROTOCOL_LIMIT])
        self.assertEqual(imported["components"][1]["data"], ["pii", "Health records"])
        self.assertTrue(all(item["severity"] == "warning" for item in problems))
        self.assertTrue(all("<" not in json.dumps(imported[key]) for key in ("components", "flows")))

    def test_unknown_fields_and_values_are_warned_not_rejected(self):
        document = json.loads((EXAMPLES / "en/stride.json").read_text(encoding="utf-8"))
        model = document["model"]
        model["owner"] = "security"
        model["components"][0]["kind"] = "Mainframe"
        model["components"][1]["internet_facing"] = "true"
        model["manual_threats"][0]["severity"] = "Bananas"
        imported, problems = tm.inspect_portable(document)
        self.assertEqual((imported["components"][0]["kind"], imported["components"][0]["custom_kind"], imported["components"][0]["custom_base"]),
                         ("custom", "Mainframe", "service"))
        self.assertTrue(imported["components"][1]["internet_facing"])
        self.assertEqual(imported["manual_threats"][0]["severity"], "Bananas")  # the team's own level, kept as a new option
        self.assertEqual(sorted(item["path"] for item in problems), ["/model/components/0/kind", "/model/components/1/internet_facing",
                                                                    "/model/manual_threats/0/severity", "/model/owner"])
        severity = {item["path"]: item["severity"] for item in problems}
        self.assertEqual((severity["/model/owner"], severity["/model/components/1/internet_facing"], severity["/model/manual_threats/0/severity"],
                          severity["/model/components/0/kind"]), ("info", "info", "info", "warning"))  # kept: harmless; an own kind gets no rules: it matters
        self.assertEqual(imported["custom_properties"], {"owner": "security"})
        self.assertEqual(tm.to_portable(imported)["model"]["owner"], "security")

    def test_problems_are_capped(self):
        document = {"name": "Big", "components": [{"id": f"c{index}", "name": "C", "kind": "service", "extra": 1} for index in range(60)],
                    "flows": [{"id": f"f{index}", "source": "c0", "target": "c1", "protocol": "own", "x": 1} for index in range(150)]}
        _, problems = tm.inspect_portable(document)
        self.assertEqual(len(problems), 200)
        self.assertIn("more", localize(problems[-1], "en")["message"])


class CustomValuesTests(unittest.TestCase):
    def test_own_values_round_trip_through_edit_export_diagram_and_reports(self):
        imported = tm.from_portable(user_case())
        imported["components"][0] = {**imported["components"][0], "kind": "Mainframe", "data": ["pii", "Health records"]}
        edited = tm.validate(imported, known_assets=set())  # what the panel sends back when saving
        self.assertEqual(edited["components"][0]["custom_kind"], "Mainframe")
        self.assertEqual(edited["flows"][0]["protocol"], "wifi")
        again = tm.from_portable(json.loads(json.dumps(tm.to_portable(edited))))
        for key in ("components", "flows", "attack_mappings"):
            self.assertEqual(again[key], edited[key])
        rows = tm.threats(edited)
        svg = tm.to_svg(edited, locale="en")
        self.assertIn("· WIFI", svg)
        markdown = tm.to_markdown({**edited, "updated_at": "", "updated_by": "x"}, rows, locale="en")
        for value in ("WIFI", "Health records", "Mainframe", "T1552.001 Credentials In Files"):
            self.assertIn(value, markdown)
        pdf = threat_report.render_pdf({**edited, "id": "a" * 24, "updated_at": "", "updated_by": "x"}, rows, version="test", locale="en")
        self.assertTrue(pdf.startswith(b"%PDF-"))
        ast.parse(tm.to_pytm(edited))
        dragon = tm.to_threat_dragon(edited, rows)
        self.assertIn("wifi", json.dumps(dragon))

    def test_unknown_data_classes_count_as_internal(self):
        base = tm.validate({"name": "M", "components": [{"id": "db", "name": "DB", "kind": "database", "data": ["Telemetry"]}]}, known_assets=set())
        self.assertEqual(base["components"][0]["data"], ["Telemetry"])
        rules = {row["rule"] for row in tm.threats(base)}
        self.assertNotIn("TM-I03", rules)  # no credential rules for a class Pitangus doesn't know


class AssistantModelTests(unittest.TestCase):
    """The model an AI assistant wrote for a user: before, 55 warnings and most of its data dropped."""

    def document(self) -> dict:
        return json.loads(ASSISTANT.read_text(encoding="utf-8"))

    def test_it_imports_without_errors_or_warnings(self):
        imported, problems = tm.inspect_portable(self.document())
        self.assertIsNotNone(imported)
        self.assertEqual([item for item in problems if item["severity"] != "info"], [])
        self.assertTrue(all(item["code"] and item["path"].startswith("/model/") for item in problems))
        # The synonyms it used are read as ours; identical notes share a code so the panel can group them.
        codes = {item["code"] for item in problems if item["path"].endswith("/component_id")}
        self.assertEqual(len(codes), 1)
        self.assertEqual(sum(1 for item in problems if item["path"].endswith("/component_id")), 12)

    def test_descriptions_assumptions_and_links_survive_import_edit_export_and_reports(self):
        imported = tm.from_portable(self.document())
        self.assertEqual([item["element"] for item in imported["manual_threats"]][:3], ["dispositivo", "broker", "app-movil"])
        self.assertTrue(imported["manual_threats"][0]["scenario"].startswith("Un atacante extrae el certificado"))
        self.assertEqual(imported["flows"][6]["description"], "Telemetría cada 5 segundos con certificado de cliente.")
        self.assertEqual(imported["boundaries"][1]["description"], "Oficinas con acceso por VPN y SSO.")
        self.assertEqual([item["id"] for item in imported["assumptions"]], ["a1", "a2", "a3", "a4"])
        self.assertEqual(imported["attack_trees"][0]["goal"], "Tomar el control de un vehículo: Enviar comandos remotos a un vehículo ajeno")
        self.assertEqual({item["status"] for item in imported["attack_mappings"]}, {"relevant"})
        # The panel sends the model back as it got it, edited.
        imported["assumptions"].append({"id": "a5", "text": "El WAF bloquea\\nlo obvio."})
        imported["flows"][0]["description"] = "Editado en el panel"
        edited = tm.validate(json.loads(json.dumps(imported)), known_assets=set())
        self.assertEqual(edited["assumptions"][-1]["text"], "El WAF bloquea\\nlo obvio.")
        self.assertEqual(edited["flows"][0]["description"], "Editado en el panel")
        again = tm.from_portable(json.loads(json.dumps(tm.to_portable(edited))))
        for key in ("components", "flows", "boundaries", "assumptions", "manual_threats", "attack_trees", "attack_mappings"):
            self.assertEqual(again[key], edited[key], key)
        rows = tm.threats(edited)
        own = {row["manual_id"]: row for row in rows if row["framework"] == "manual"}
        self.assertEqual(own["t01"]["element_name"], "Dispositivo telemático")
        markdown = tm.to_markdown({**edited, "updated_at": "", "updated_by": "x"}, rows, locale="es")
        for value in ("## Supuestos (5)", "1. La nube del proveedor (AWS)", "Fronteras de confianza", "Oficinas con acceso por VPN y SSO.",
                      "Telemetría cada 5 segundos", "Un atacante extrae el certificado", "T1552.004 Private Keys"):
            self.assertIn(value, markdown)
        pdf = threat_report.render_pdf({**edited, "id": "a" * 24, "updated_at": "", "updated_by": "x"}, rows, version="test", locale="es")
        self.assertTrue(pdf.startswith(b"%PDF-"))
        dragon = json.dumps(tm.to_threat_dragon(edited, rows), ensure_ascii=False)
        self.assertIn("Oficinas con acceso por VPN y SSO.", dragon)
        script = tm.to_pytm(edited)
        ast.parse(script)
        self.assertIn("Supuesto: La nube del proveedor", script)

    def test_unknown_fields_are_kept_and_exported_back_in_place(self):
        document = self.document()
        model = document["model"]
        model["components"][0]["owner_team"] = {"name": "Plataforma", "slack": "#plataforma"}
        model["flows"][0]["latency_ms"] = 120
        model["attack_trees"][0]["nodes"][0]["cost"] = "bajo"
        model["review"] = {"date": "2026-10-01"}
        imported, problems = tm.inspect_portable(document)
        self.assertEqual({item["severity"] for item in problems if item["path"] in ("/model/components/0/owner_team", "/model/review")}, {"info"})
        exported = tm.to_portable(tm.validate(json.loads(json.dumps(imported)), known_assets=set()))["model"]
        self.assertEqual(exported["components"][0]["owner_team"], {"name": "Plataforma", "slack": "#plataforma"})
        self.assertEqual(exported["flows"][0]["latency_ms"], 120)
        self.assertEqual(exported["attack_trees"][0]["nodes"][0]["cost"], "bajo")
        self.assertEqual(exported["review"], {"date": "2026-10-01"})
        self.assertNotIn("custom_properties", json.dumps(exported))

    def test_custom_properties_are_bounded_and_a_likely_typo_is_a_warning(self):
        document = self.document()
        document["model"]["manual_threats"][0]["sevirity"] = "high"
        imported, problems = tm.inspect_portable(document)
        found = {item["path"]: item for item in problems}
        self.assertEqual(imported["manual_threats"][0]["custom_properties"], {"sevirity": "high"})
        document["model"]["flows"][0]["blob"] = "x" * 9000  # too large to keep: an error, never a silent drop
        rejected, errors = tm.inspect_portable(document)
        self.assertIsNone(rejected)
        self.assertEqual([item["path"] for item in errors if item["severity"] == "error"], ["/model/flows/0/blob"])
        typo = localize(found["/model/manual_threats/0/sevirity"], "en")
        self.assertEqual(typo["severity"], "warning")
        self.assertIn("severity", typo["message"])


class AliasTests(unittest.TestCase):
    def read(self, **sections) -> tuple[dict, list[dict]]:
        base = {"name": "M", "methodology": "custom", "custom_modules": ["manual", "trees", "attack", "pasta"],
                "components": [{"id": "api", "name": "API", "kind": "api"}, {"id": "db", "name": "DB", "kind": "database"}],
                "flows": [{"id": "f1", "source": "api", "target": "db", "protocol": "sql"}]}
        return tm.inspect_portable({**base, **sections})

    def test_field_synonyms_are_read_as_ours_with_an_info(self):
        imported, problems = self.read(
            flows=[{"id": "f1", "from": "api", "to": "db", "protocol": "sql", "Description": "Consultas"}],
            boundaries=[{"id": "b", "title": "Datos", "members": ["db"]}],
            manual_threats=[{"id": "t1", "name": "Robo", "element_id": "db", "mitigations": ["Cifrar", "Rotar claves"]},
                            {"id": "t2", "title": "Fuga", "flow_id": "f1", "description": "Por la red", "scenario": "Sin TLS"}],
            attack_trees=[{"id": "t", "title": "Meta", "nodes": [{"id": "n", "label": "Paso", "type": "AND", "component_id": "api"}]}],
            attack_mappings=[{"technique_id": "t1190", "component": "api", "notes": "Expuesta", "status": "Possible"}, "T1110"],
            pasta={"business_objectives": "Ventas", "stage_7": "Riesgo"})
        self.assertIsNotNone(imported, problems)
        self.assertEqual({item["severity"] for item in problems}, {"info"})
        self.assertEqual((imported["flows"][0]["source"], imported["flows"][0]["description"]), ("api", "Consultas"))
        self.assertEqual((imported["boundaries"][0]["name"], imported["boundaries"][0]["components"]), ("Datos", ["db"]))
        first, second = imported["manual_threats"]
        self.assertEqual((first["title"], first["element"], first["mitigation"]), ("Robo", "db", "- Cifrar\n- Rotar claves"))
        self.assertEqual((second["element"], second["scenario"]), ("f1", "Por la red\n\nSin TLS"))
        node = imported["attack_trees"][0]["nodes"][0]
        self.assertEqual((imported["attack_trees"][0]["goal"], node["text"], node["gate"], node["element"]), ("Meta", "Paso", "and", "api"))
        self.assertEqual([(item["technique"], item["element"], item["status"]) for item in imported["attack_mappings"]],
                         [("T1190", "api", "relevant"), ("T1110", "", "relevant")])
        self.assertEqual(imported["pasta"], {"objectives": "Ventas", "risk": "Riesgo"})

    def test_a_dangling_reference_under_a_synonym_is_an_error_where_it_was_written(self):
        imported, problems = self.read(manual_threats=[{"id": "t1", "title": "x", "component_id": "ghost"}])
        self.assertIsNone(imported)
        self.assertEqual([item["path"] for item in problems if item["severity"] == "error"], ["/manual_threats/0/component_id"])

    def test_a_synonym_that_contradicts_our_field_is_kept_not_used(self):
        imported, problems = self.read(manual_threats=[{"id": "t1", "title": "x", "element": "api", "component_id": "db"}])
        self.assertEqual(imported["manual_threats"][0]["element"], "api")
        self.assertEqual(imported["manual_threats"][0]["custom_properties"], {"component_id": "db"})
        self.assertEqual([item["severity"] for item in problems if item["path"].endswith("component_id")], ["warning"])

    def test_value_synonyms(self):
        cases = [("severity", threat_methods.SEVERITY_ALIASES, threat_methods.SEVERITIES), ("likelihood", threat_methods.LEVEL_ALIASES, threat_methods.LEVELS),
                 ("status", threat_methods.STATUS_ALIASES, threat_methods.MAPPING_STATUS), ("gate", threat_methods.GATE_ALIASES, ("and", "or"))]
        for field, aliases, allowed in cases:
            for alias, value in aliases.items():
                with self.subTest(field=field, alias=alias):
                    self.assertIn(value, allowed)
                    problems = Problems()
                    self.assertEqual(problems.choice(alias.upper(), allowed, None, "/x", field, aliases=aliases), value)
                    self.assertEqual([item["severity"] for item in problems.items], ["info"])
        for value, expected in (("HIGH", "high"), ("Not-Applicable", "not_applicable"), ("OR", "or")):
            problems = Problems()
            self.assertEqual(problems.choice(value, ("high", "not_applicable", "or"), None, "/x", "f"), expected)
            self.assertEqual(problems.items, [])  # only case or hyphens: nothing to say


class OwnValuesTests(unittest.TestCase):
    """Saved means shown: the team's own values become options; only a template's own vocabulary is strict."""

    def base(self, **model) -> dict:
        return {"name": "M", "components": [{"id": "api", "name": "API", "kind": "api"}, {"id": "db", "name": "DB", "kind": "database"}],
                "flows": [{"id": "f1", "source": "api", "target": "db", "protocol": "sql"}], **model}

    def test_own_levels_and_statuses_are_kept_shown_and_sorted(self):
        document = self.base(methodology="custom", custom_modules=["manual", "attack"], level_equivalents={"severity": {"Grave": "critical"}},
                             manual_threats=[{"id": "a", "title": "Leve", "severity": "Molesto"}, {"id": "b", "title": "Seria", "severity": "Grave", "likelihood": "Casi seguro"},
                                             {"id": "c", "title": "Normal", "severity": "low"}],
                             attack_mappings=[{"technique": "T1190", "element": "api", "status": "En revisión"}])
        imported, problems = tm.inspect_portable(document)
        self.assertEqual({item["severity"] for item in problems}, {"info"})
        rows = [row for row in tm.threats(imported) if row["framework"] == "manual"]
        # «Grave» sorts as critical (its equivalent), «Molesto» after every known level; both keep their names.
        self.assertEqual([(row["title"], row["severity"], row["severity_label"]) for row in rows],
                         [("Seria", "critical", "Grave"), ("Normal", "low", None), ("Leve", "Molesto", "Molesto")])
        markdown = tm.to_markdown({**imported, "updated_at": "", "updated_by": "x"}, tm.threats(imported), locale="en")
        for value in ("### Grave · Seria", "### Molesto · Leve", "likelihood: Casi seguro", "| En revisión |",
                      "1 team threat has a severity of the team's own with no equivalent level"):
            self.assertIn(value, markdown)
        pdf = threat_report.render_pdf({**imported, "id": "a" * 24, "updated_at": "", "updated_by": "x"}, tm.threats(imported), version="t", locale="en")
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertEqual(tm.to_portable(imported)["model"]["level_equivalents"], {"severity": {"Grave": "critical"}})

    def test_a_templates_own_vocabulary_is_strict_and_nothing_is_lost(self):
        imported, problems = tm.inspect_portable(self.base(methodology="stride", manual_threats=[
            {"id": "a", "title": "x", "category": "Information Disclosure"}, {"id": "b", "title": "y", "category": "Negocio"}]))
        self.assertEqual([item["category"] for item in imported["manual_threats"]], ["I", ""])
        self.assertEqual(imported["manual_threats"][1]["custom_properties"], {"category": "Negocio"})
        warning = next(localize(item, "en")["message"] for item in problems if item["severity"] == "warning")
        self.assertIn("use the Custom approach", warning)
        exported = tm.to_portable(imported)["model"]["manual_threats"][1]
        self.assertEqual((exported["category"], exported["custom_properties"]), ("", {"category": "Negocio"}))
        # Imported as Custom, the same file keeps its own category as the category.
        again = tm.from_portable({**tm.to_portable(imported)["model"], "methodology": "custom"})
        self.assertEqual(again["manual_threats"][1]["custom_properties"], {"category": "Negocio"})
        trees, problems = tm.inspect_portable(self.base(methodology="attack_trees", attack_trees=[
            {"id": "t", "goal": "g", "nodes": [{"id": "n", "parent": None, "text": "x", "gate": "XOR"}]}]))
        node = trees["attack_trees"][0]["nodes"][0]
        self.assertEqual((node["gate"], node["custom_properties"]), ("or", {"gate": "XOR"}))
        self.assertEqual([item["severity"] for item in problems], ["warning"])
        pasta, problems = tm.inspect_portable(self.base(methodology="pasta", pasta={"objectives": "o", "stage_8": "extra"}))
        self.assertEqual(pasta["pasta"]["custom_properties"], {"stage_8": "extra"})
        self.assertEqual([item["severity"] for item in problems], ["warning"])
        markdown = tm.to_markdown({**pasta, "updated_at": "", "updated_by": "x"}, tm.threats(pasta), locale="en")
        self.assertIn("### Stage 8\n\nextra", markdown)

    def test_custom_sections_and_properties_are_in_the_reports(self):
        imported = tm.from_portable(self.base(methodology="custom", risk_register=[{"id": "r1", "risk": "Robo", "owner": "Ana"}],
                                              reviewed="2026-10-01", components=[{"id": "api", "name": "API", "kind": "api", "sla": "99.9"},
                                                                                 {"id": "db", "name": "DB", "kind": "database"}]))
        markdown = tm.to_markdown({**imported, "updated_at": "", "updated_by": "x"}, tm.threats(imported), locale="en")
        for value in ("· Model properties", "| Reviewed | 2026-10-01 |", "· Risk register", "| Id | Risk | Owner |", "| r1 | Robo | Ana |",
                      "· Custom properties", "| API | sla | 99.9 |"):
            self.assertIn(value, markdown)
        # They are appendices, after the analysis, and capped: a long section doesn't push the threats down.
        self.assertLess(markdown.index("· Components\n"), markdown.index("· Risk register"))
        big = tm.from_portable(self.base(methodology="custom", risk_register=[{"id": f"r{index}"} for index in range(45)]))
        markdown = tm.to_markdown({**big, "updated_at": "", "updated_by": "x"}, tm.threats(big), locale="en")
        self.assertIn("And 15 more: the full list is in the panel", markdown)
        self.assertNotIn("| r40 |", markdown)
        pdf = threat_report.render_pdf({**imported, "id": "a" * 24, "updated_at": "", "updated_by": "x"}, tm.threats(imported), version="t", locale="en")
        self.assertTrue(pdf.startswith(b"%PDF-"))


class AttackCatalogTests(unittest.TestCase):
    def test_the_bundled_catalog_is_pinned_and_carries_mitre_terms(self):
        data = attack.data()
        self.assertEqual((data["version"], data["source"]), ("19.2", "https://github.com/mitre-attack/attack-stix-data"))
        self.assertRegex(data["sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("The MITRE Corporation", data["copyright"])
        self.assertIn("royalty-free license", data["license"])
        self.assertGreater(len(data["techniques"]), 600)
        for key, (name, tactics) in data["techniques"].items():
            self.assertRegex(key, threat_schema.TECHNIQUE_PATTERN)
            self.assertTrue(name and tactics and set(tactics) <= set(data["tactics"]), key)

    def test_lookups_include_sub_techniques_revoked_and_unknown(self):
        self.assertEqual(attack.technique("T1552.004"), ("Private Keys", ["TA0006"]))
        self.assertEqual(threat_methods.technique_tactics("T1565.001"), ["TA0040"])
        self.assertEqual(localize(threat_methods.technique_label("T1552.001"), "es"), "Credentials In Files")  # MITRE's name, as published
        self.assertEqual(localize(threat_methods.technique_label("T1110"), "es"), "Fuerza bruta")  # ours, interpreted
        self.assertEqual(attack.state("T1562"), ("revoked", "T1685"))
        self.assertEqual(attack.state("T1043")[0], "deprecated")
        self.assertEqual(attack.state("T9999"), ("unknown", None))
        _, problems = tm.inspect_portable({"name": "M", "methodology": "attack", "attack_mappings": [
            {"technique": "T1562"}, {"technique": "T1043"}, {"technique": "T9999"}, {"technique": "T1552.004"}]})
        messages = {item["path"]: (item["severity"], localize(item, "en")["message"]) for item in problems}
        self.assertEqual(messages["/attack_mappings/0/technique"][0], "warning")
        self.assertIn("replaced by T1685 (Disable or Modify Tools)", messages["/attack_mappings/0/technique"][1])
        self.assertIn("deprecated in ATT&CK v19.2", messages["/attack_mappings/1/technique"][1])
        self.assertIn("isn't in ATT&CK v19.2", messages["/attack_mappings/2/technique"][1])
        self.assertNotIn("/attack_mappings/3/technique", messages)

    def test_our_suggestions_are_live_techniques(self):
        self.assertEqual(set(threat_methods.TECHNIQUES), set(threat_methods.CURATED))
        for keys in threat_methods.SUGGESTIONS.values():
            self.assertTrue(set(keys) <= set(threat_methods.TECHNIQUES))
        self.assertEqual(set(threat_methods.TACTICS), set(attack.tactics()))
        catalog = threat_methods.catalog()
        self.assertEqual(catalog["attack"]["version"], attack.version())
        self.assertIn("T1552.004", catalog["attack"]["techniques"])

    def test_the_refresh_script_reproduces_the_bundled_file(self):
        source = (Path(__file__).resolve().parents[1] / "scripts/attack-catalog.py").read_text(encoding="utf-8")
        data = attack.data()
        for value in (data["version"], data["commit"], data["sha256"]):
            self.assertIn(value, source)


class ContractTests(unittest.TestCase):
    def test_the_schema_file_is_current(self):
        written = json.loads((EXAMPLES / "schema.json").read_text(encoding="utf-8"))
        self.assertEqual(written, threat_schema.build(), "run make openapi")

    def test_the_schema_lists_what_the_importer_knows(self):
        schema = threat_schema.build()
        defs = schema["$defs"]
        self.assertEqual(defs["flow"]["properties"]["protocol"]["examples"], list(tm.PROTOCOLS))
        self.assertEqual(defs["component"]["properties"]["kind"]["examples"], list(tm.KINDS))
        self.assertEqual(defs["component"]["properties"]["data"]["items"]["examples"], list(tm.CLASSIFICATIONS))
        self.assertEqual(defs["model"]["properties"]["methodology"]["enum"], list(threat_methods.METHODOLOGIES))
        self.assertEqual(defs["manual_threat"]["properties"]["severity"]["enum"], list(threat_methods.SEVERITIES))
        self.assertEqual(defs["attack_mapping"]["properties"]["status"]["enum"], list(threat_methods.MAPPING_STATUS))
        self.assertEqual(set(defs["attack_mapping"]["properties"]["technique"]["examples"]), set(threat_methods.TECHNIQUES))
        self.assertEqual(set(defs["model"]["properties"]["pasta"]["properties"]), {key for key, _ in threat_methods.PASTA_STAGES})
        self.assertEqual(set(defs["component"]["properties"]), tm.COMPONENT_KEYS - {"asset"})  # never exported: links are local
        self.assertEqual(set(defs["flow"]["properties"]), tm.FLOW_KEYS)
        self.assertEqual(set(defs["boundary"]["properties"]), tm.BOUNDARY_KEYS)
        self.assertEqual(set(defs["manual_threat"]["properties"]), threat_methods.MANUAL_KEYS)
        self.assertEqual(set(defs["attack_mapping"]["properties"]), threat_methods.MAPPING_KEYS)
        self.assertEqual(set(defs["model"]["properties"]), tm.MODEL_KEYS - {"repositories"})
        for key in threat_methods.TECHNIQUES:
            self.assertRegex(key, defs["attack_mapping"]["properties"]["technique"]["pattern"])
        self.assertEqual(set(defs["flow"]["properties"]), tm.FLOW_KEYS)
        self.assertEqual(set(defs["assumption"]["properties"]), threat_methods.ASSUMPTION_KEYS)

    def test_every_synonym_the_importer_reads_is_in_the_schema(self):
        defs = threat_schema.build()["$defs"]
        nodes = defs["attack_tree_node"]
        for definition, aliases in ((defs["model"], tm.MODEL_ALIASES), (defs["component"], tm.COMPONENT_ALIASES), (defs["flow"], tm.FLOW_ALIASES),
                                    (defs["boundary"], tm.BOUNDARY_ALIASES), (defs["assumption"], threat_methods.ASSUMPTION_ALIASES),
                                    (defs["manual_threat"], threat_methods.MANUAL_ALIASES), (defs["attack_tree"], threat_methods.TREE_ALIASES),
                                    (nodes, threat_methods.NODE_ALIASES), (defs["attack_mapping"], threat_methods.MAPPING_ALIASES),
                                    (defs["model"]["properties"]["pasta"], threat_methods.PASTA_ALIASES)):
            self.assertEqual(definition["x-pitangus-aliases"], aliases)
            self.assertTrue(set(aliases.values()) <= set(definition["properties"]), aliases)
            self.assertFalse(set(aliases) & set(definition["properties"]))
        self.assertEqual(defs["manual_threat"]["properties"]["severity"]["x-pitangus-synonyms"], threat_methods.SEVERITY_ALIASES)
        self.assertEqual(defs["manual_threat"]["properties"]["likelihood"]["x-pitangus-synonyms"], threat_methods.LEVEL_ALIASES)
        self.assertEqual(defs["attack_mapping"]["properties"]["status"]["x-pitangus-synonyms"], threat_methods.STATUS_ALIASES)
        self.assertEqual(nodes["properties"]["gate"]["x-pitangus-synonyms"], threat_methods.GATE_ALIASES)

    def test_examples_match_the_schema_and_import_cleanly(self):
        schema = threat_schema.build()
        paths = sorted(glob.glob(str(EXAMPLES / "*/*.json"))) + sorted(glob.glob(str(EXAMPLES / "minimal.*.json")))
        self.assertEqual(len(paths), 14)
        for path in paths:
            with self.subTest(path=Path(path).name):
                document = json.loads(Path(path).read_text(encoding="utf-8"))
                self.assertEqual(schema_errors(document, schema, schema), [])
                imported, problems = tm.inspect_portable(document)
                self.assertIsNotNone(imported)
                self.assertEqual(problems, [])

    def test_the_prompt_is_built_from_the_schema(self):
        source = (Path(__file__).resolve().parents[1] / "web/src/features/threats/import-contract.ts").read_text(encoding="utf-8")
        self.assertIn("examples/threat-models/schema.json", source)
        self.assertIn("examples/threat-models/minimal.en.json", source)
        for locale in ("en", "es"):
            catalog = json.loads((Path(__file__).resolve().parents[1] / f"web/src/shared/i18n/locales/{locale}/threats.json").read_text(encoding="utf-8"))
            prompt = catalog["importer"]["ai_prompt"]
            for param in ("protocols", "kinds", "classifications", "methodologies", "severities", "statuses", "technique_pattern", "minimal", "example"):
                self.assertIn("{{" + param + "}}", prompt, (locale, param))


class ImportRouteTests(HttpCase):
    def test_validate_lists_problems_and_import_accepts_warnings(self):
        with patch.dict(os.environ, {"PITANGUS_REQUIRE_TOTP": "none"}):
            Users(self.data_dir).create("operadora", PASSWORD, role="admin")
            _, _, cookies = self.post("/api/auth/login", "login", {"username": "operadora", "password": PASSWORD})
            cookie = cookies[0].split("; ")[0]
            document = user_case()
            status, preview, _ = self.post("/api/threat-models/validate", "validate-threat-model", document, cookie)
            self.assertEqual(status, 200, preview)
            self.assertTrue(preview["problems"])
            self.assertEqual({item["severity"] for item in preview["problems"]}, {"warning"})
            self.assertTrue(all(isinstance(item["message"], str) for item in preview["problems"]))
            status, imported, _ = self.post("/api/threat-models/import", "import-threat-model", document, cookie)
            self.assertEqual(status, 200, imported)
            broken = json.loads(json.dumps(document))
            broken["model"]["flows"][0]["source"] = "ghost"
            broken["model"]["flows"][1]["id"] = "Not An Id"
            status, rejected, _ = self.post("/api/threat-models/validate", "validate-threat-model", broken, cookie)
            self.assertEqual(status, 400)
            errors = [item for item in rejected["problems"] if item["severity"] == "error"]
            self.assertEqual([item["path"] for item in errors], ["/model/flows/0/source", "/model/flows/1/id"])
            self.assertEqual(rejected["error"], errors[0]["message"])
            status, catalog, _ = self.call("GET", "/api/threat-models", headers={"Cookie": cookie})
            self.assertEqual(status, 200)
            self.assertIn("wifi", catalog["workspace"]["protocols"])
            self.assertIn("T1552.001", catalog["workspace"]["techniques"])


if __name__ == "__main__":
    unittest.main()
