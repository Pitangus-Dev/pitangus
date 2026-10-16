"""Pitangus stores no code (0.14.1), tested as a property.

A random value placed anywhere in scanned code (a string, a comment, a name, a key, an operand; on the line an engine
matched or around it) appears in nothing Pitangus persists or sends: the database (every table: runs, registry, outbox,
…), the stored report and SARIF, the Jira issue, the notifications, the prompt it builds and the logs. Findings go
through the real parsers (Opengrep, Trivy's configuration checks, zizmor, an imported SARIF with its snippet, context
region and message) and the real scan. The oracle is the value itself: 24 random characters nobody else writes. The
data migration strips what earlier versions stored the same way, idempotently, and never changes a status.
"""

import json
import random
import string
import tempfile
import unittest
from pathlib import Path

from hypothesis import HealthCheck, example, given, settings, strategies as st
from sqlalchemy import select

from pitangus.modules.findings import canonical, registry
from pitangus.modules.scanning.config_engines import parse_zizmor
from pitangus.modules.scanning.engines import EngineStep, parse_opengrep, parse_trivy
from pitangus.shared import db
from test_secret_masking import SCALE, _captured_logs, _outputs, _replayed

B62 = string.ascii_letters + string.digits
# Where a value can sit in code: the template has `{}` where it goes.
PLACES = {
    "string": 'cur.execute("SELECT * FROM t WHERE k=\'{}\' AND id=" + q)',
    "comment": "cur.execute(sql + q)  # owner {}",
    "name": "cur.execute(sql_{} + q)",
    "key": 'cur.execute({{"{}": q}})',
    "operand": "cur.execute(sql) if q == {} else None",
}
WORKFLOW = """on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo {} | docker login -u x --password-stdin
"""


def _value(seed: int) -> str:
    chooser = random.Random(seed)
    while True:
        value = "".join(chooser.choice(B62) for _ in range(chooser.randint(24, 32)))
        if any(ch.isdigit() for ch in value) and any(ch.isupper() for ch in value) and any(ch.islower() for ch in value):
            return value


def _engines(path: str, lines: list[str], value: str, workflow_report: list) -> tuple:
    """Opengrep matching line 3 (its message quoting what it matched, as third-party rules do), Trivy's configuration
    check on the same file quoting it in its message and its code, and zizmor on the workflow."""
    from pitangus.modules.scanning.repository import CODE_ENGINES
    line = lines[2]
    opengrep = {"results": [{"check_id": "rules.appsec.python.sqli", "path": f"/src/{path}", "start": {"line": 3}, "end": {"line": 4},
                             "extra": {"lines": "\n".join(lines[2:4]), "message": f"Matched {line.strip()}", "severity": "ERROR",
                                       "metadata": {"cwe": [89], "confidence": "HIGH", "category": "security"}}}]}
    trivy = {"Results": [{"Target": path, "Class": "config", "Misconfigurations": [{
        "AVDID": "AVD-PY-0001", "Title": "Query built from input", "Description": "Queries must not be built by concatenation.",
        "Message": f"Query '{line.strip()}' is built from input {value}", "Resolution": "Use parameters.", "Severity": "HIGH",
        "CauseMetadata": {"StartLine": 3, "EndLine": 4, "Resource": "", "Code": {"Lines": [{"Number": 3, "Content": line}]}}}]}]}
    parsers = {"opengrep": lambda context: parse_opengrep(opengrep), "trivy": lambda context: parse_trivy(trivy, {}, None, context.root),
               "zizmor": lambda context: parse_zizmor(workflow_report, context.root)}

    def step(engine):
        return EngineStep(engine.key, lambda context: _replayed(engine.key, parsers.get(engine.key, lambda _: [])(context)),
                          engine.progress, required=engine.required, merged=engine.merged)
    return tuple(step(engine) for engine in CODE_ENGINES)


def _zizmor_report(workflow: str) -> list:
    start = workflow.index("  build:")
    return [{"ident": "excessive-permissions", "desc": "overly broad permissions", "url": "https://docs.zizmor.sh/audits/",
             "determinations": {"severity": "Medium", "confidence": "High"},
             "locations": [{"symbolic": {"key": {"Local": {"verbatim_path": ".github/workflows/ci.yml"}}, "annotation": "this job uses write-all permissions",
                                         "kind": "Primary", "route": {"route": [{"Key": "jobs"}, {"Key": "build"}]}},
                            "concrete": {"location": {"start_point": {"row": 3}, "end_point": {"row": 6},
                                                      "offset_span": {"start": start, "end": len(workflow)}}}}]}]


def _sarif(path: str, lines: list[str], value: str) -> dict:
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL", "rules": [{"id": "py/sql-injection", "shortDescription": {"text": "SQL injection"}}]}},
                                          "results": [{"ruleId": "py/sql-injection", "level": "error", "message": {"text": f"This query uses {lines[2].strip()}"},
                                                       "locations": [{"physicalLocation": {"artifactLocation": {"uri": path},
                                                                      "region": {"startLine": 3, "snippet": {"text": lines[2]}},
                                                                      "contextRegion": {"startLine": 1, "endLine": 5, "snippet": {"text": "\n".join(lines)}}}}]}]}]}


def everything(data_dir: Path) -> str:
    """Every row of every table, as text."""
    import pitangus.modules.findings.tables  # noqa: F401 - the tables register in db.metadata
    import pitangus.modules.integrations.tables  # noqa: F401
    import pitangus.modules.runs.tables  # noqa: F401
    rows = []
    with db.transaction(data_dir) as connection:
        for table in db.metadata.sorted_tables:
            try:
                rows += [dict(row._mapping) for row in connection.execute(select(table)).all()]
            except Exception:  # noqa: BLE001 - a table this schema doesn't create
                continue
    return json.dumps(rows, ensure_ascii=False, default=str)


class NoCodeAnywhereTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.examples = 0

    def check(self, seed: int, place: str, mode: str):
        from pitangus.modules.runs.imports import import_sarif
        from pitangus.modules.scanning.repository import scan_repository
        self.examples += 1
        value = _value(seed)
        path = "app/db.py"
        lines = ["import os", f"OWNER = '{value}'  # {value}", PLACES[place].format(value), f"    return {value}", "print('done')"]
        workflow = WORKFLOW.format(value)
        data_dir = Path(self.directory.name) / f"data-{self.examples}"
        root = data_dir / "snapshot"
        (root / "app").mkdir(parents=True)
        (root / path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / ".github" / "workflows" / "ci.yml").write_text(workflow, encoding="utf-8")
        key = f"github#{self.examples}"
        source = {"id": "github:org/api", "uid": key, "name": "org/api", "provider": "github", "commit": "a" * 40}
        with _captured_logs() as logs:
            scan = scan_repository(root, source, data_dir=data_dir, replay=_engines(path, lines, value, _zizmor_report(workflow)),
                                   feeds={"kev": {}, "epss": {}})
            self.assertEqual({item["scanner"] for item in scan["findings"]} >= {"sast", "iac", "cicd"}, True)
            outputs = _outputs(data_dir, scan, key, mode)
            import_sarif(data_dir, _sarif(path, lines, value), asset=key, commit="b" * 40, requested_by="tester")
        outputs["database"] = everything(data_dir)
        outputs["logs"] = "\n".join(logs)
        self.assertIn("app/db.py", outputs["database"])   # the location stays
        for name, text in outputs.items():
            if name.startswith("cli prompt") or name == "scan":
                continue   # in the terminal, from the scan in memory; the CLI reads the folder only when asked (test_code_view)
            self.assertNotIn(value, text, f"{name}: {place}/{mode}")
            self.assertNotIn(value[:12], text, f"{name}: {place}/{mode}")
        stored = registry.load(data_dir, key)["findings"]
        self.assertTrue(stored)
        for entry in stored.values():
            self.assertNotIn("snippet", entry["finding"])
            self.assertTrue(canonical.identity_of(entry["finding"]))

    @settings(max_examples=6 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    @given(st.integers(0, 2**32), st.sampled_from(sorted(PLACES)), st.sampled_from(["v1", "v2"]))
    @example(1, "string", "v2")
    @example(2, "comment", "v1")
    @example(3, "key", "v2")
    def test_a_value_in_scanned_code_is_persisted_nowhere(self, seed, place, mode):
        self.check(seed, place, mode)


class DropStoredCodeMigrationTests(unittest.TestCase):
    def test_stored_code_goes_identities_and_statuses_stay_and_it_is_idempotent(self):
        from sqlalchemy import insert
        from pitangus.app import data_migrations as migrations
        from pitangus.modules.integrations.tables import outbox
        from pitangus.modules.runs.store import _persist, artifact, load_run
        value = _value(7)
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory)
            base = {"title": "t", "confidence": 8, "verdict": "candidate", "cve": [], "ghsa": [], "owasp": [], "package": None,
                    "advisory": None, "kev": None, "epss": None, "priority": {"action": "attend", "factors": []}, "reason": "r", "remediation": "m"}
            stored = [{**base, "fingerprint": "a" * 64, "finding_id": "a" * 16, "scanner": "sast", "tool": "opengrep", "rule_id": "x",
                       "path": "app.py", "line": 3, "severity": "high", "cwe": [89], "snippet": f"cur.execute('{value}' + q)"},
                      {**base, "fingerprint": "b" * 64, "finding_id": "b" * 16, "scanner": "cicd", "tool": "zizmor", "rule_id": "y",
                       "path": ".github/workflows/ci.yml", "line": 4, "severity": "medium", "cwe": [732],
                       "snippet": "jobs:\n  build:\n# this job uses write-all permissions"}]
            before = {item["fingerprint"]: canonical.identity_of(item) for item in stored}
            record = {"schema_version": "0.3.0", "id": "f" * 32, "created_at": "2026-10-01T00:00:00+00:00", "type": "repository_scan",
                      "status": "completed", "target": "org/api", "source": {"id": "github:org/api", "uid": "github#1", "name": "org/api",
                                                                             "provider": "github", "commit": "c" * 40},
                      "findings": stored, "steps": [], "owasp_coverage": [], "limitations": [], "context": "",
                      "summary": {"files": 1, "dependencies": 0, "candidates": 2, "severities": {}, "priorities": {}, "kev": 0, "fixable": 0, "tools": []}}
            sarif = {"runs": [{"results": [{"locations": [{"physicalLocation": {"region": {"snippet": {"text": value}},
                                                                                  "contextRegion": {"snippet": {"text": value}}}}]}]}]}
            _persist(data_dir, record, f"report with {value}", sarif)
            registry._save(data_dir, {"asset": "github#1", "name": "org/api", "applied": [], "findings": {
                item["fingerprint"]: {"status": "fixed" if item["scanner"] == "cicd" else "open", "finding": item} for item in stored}})
            with db.transaction(data_dir) as connection:
                connection.execute(insert(outbox).values(tenant_id=db.TENANT, id="1" * 32, channel_id="jira",
                                                         payload={"type": "create", "finding": {"snippet": value, "path": "app.py"}}))
            self.assertGreater(migrations._drop_stored_code(data_dir), 0)
            text = everything(data_dir) + artifact(data_dir, "f" * 32, "report.md").decode()
            self.assertNotIn(value, text)
            self.assertNotIn('"snippet"', text)
            self.assertNotIn("contextRegion", text)
            entries = registry.load(data_dir, "github#1")["findings"]
            self.assertEqual({digest: entry["status"] for digest, entry in entries.items()}, {"a" * 64: "open", "b" * 64: "fixed"})
            self.assertEqual({digest: canonical.identity_of(entry["finding"]) for digest, entry in entries.items()}, before)
            self.assertEqual({item["fingerprint"]: canonical.identity_of(item) for item in load_run(data_dir, "f" * 32)["findings"]}, before)
            self.assertEqual({item["fingerprint"]: (item["path"], item["line"]) for item in load_run(data_dir, "f" * 32)["findings"]},
                             {"a" * 64: ("app.py", 3), "b" * 64: (".github/workflows/ci.yml", 4)})
            snapshot = everything(data_dir)
            self.assertEqual(migrations._drop_stored_code(data_dir), 0)
            self.assertEqual(everything(data_dir), snapshot)


if __name__ == "__main__":
    unittest.main()
