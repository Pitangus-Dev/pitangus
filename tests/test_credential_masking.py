"""No credential value persisted or shown, however it is written (shared/masking.py), tested as a property.

A value is written in a form a credential takes in code, configuration, a URL or an engine's error (quoted or not:
YAML, INI, .env, TOML, JSON, XML, SQL, a connection call, a command line; a URL's path, query, fragment or matrix
parameter; stderr), sometimes encoded (base32, `\\uXXXX`) or split (`"".join([...])`), and reported by an engine that
reads it (Opengrep, zizmor, an imported SARIF of secrets or of CWE-798, a web scanner's SARIF, an engine that failed
with it on stderr). No secret engine detects it: only its context says it is a credential. Through the real parsers,
importers, scan and store, the value appears in no database row and no output (prompts from the CLI and from the
panel's route, SARIF, JSON, Markdown, the PDF's text, the Jira issue, the notifications, the logs). Masking keeps every
identity, and a web finding's identity is the same for its URL as reported and as stored.
"""

import base64
import json
import os
import random
import string
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

from hypothesis import HealthCheck, example, given, settings, strategies as st
from sqlalchemy import select

from pitangus.modules.findings import canonical, registry
from pitangus.modules.scanning import sarif_import
from pitangus.modules.scanning.config_engines import parse_zizmor
from pitangus.modules.scanning.engines import EngineStep, parse_opengrep, with_cause
from pitangus.shared import db, web_keys
from pitangus.shared.i18n import msg
from pitangus.shared.masking import mask, mask_url, sanitize_finding, sanitize_record
from value_oracle import fragments, leaked

from test_secret_masking import _captured_logs, _pdf_text, _replayed

PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

B62 = string.ascii_letters + string.digits
SYMBOLS = "!#%&*+-.=?@^_~"


def _value(kind: str, seed: int) -> str:
    rng = random.Random(seed)
    pick = lambda alphabet, count: "".join(rng.choice(alphabet) for _ in range(count))  # noqa: E731
    if kind == "github":
        return "ghp_" + pick(B62, 36)
    if kind == "aws":
        return "AKIA" + pick(string.ascii_uppercase + string.digits, 16)
    if kind == "jwt":
        part = lambda size: base64.urlsafe_b64encode(rng.randbytes(size)).decode().rstrip("=")  # noqa: E731
        return "eyJ" + part(18) + "." + part(24) + "." + part(32)
    if kind == "hex":
        return pick("0123456789abcdef", rng.randint(32, 48))
    if kind == "random":
        return pick(B62, rng.randint(24, 40))
    if kind == "urlsafe":  # Python's secrets.token_urlsafe(), as session and reset tokens are made
        return base64.urlsafe_b64encode(rng.randbytes(32)).decode().rstrip("=")
    if kind == "passphrase":  # one case only, long: crAPI's password is 19 lowercase letters
        return pick(string.ascii_lowercase, rng.randint(16, 24))
    return pick(string.ascii_letters, 3) + pick(B62 + SYMBOLS, rng.randint(6, 14)) + pick(string.digits, 1) + pick(SYMBOLS, 1)


# Shaped like a token: what a URL path segment is masked by. A random run is told from words by its shape
# (masking.token_shaped); measured on random base64url runs, 43 characters miss about 3 in a million and 22 characters
# about 5 in 10,000, so the generated ones are 43 long, as `token_urlsafe()` makes them.
TOKENS = ("github", "aws", "jwt", "hex", "urlsafe")
KINDS = (*TOKENS, "random", "password", "passphrase")

# Forms: (file, the line with `{}` where the written value goes). A YAML form fits a workflow (zizmor reads it).
FORMS = {
    "yaml": ("config.yml", "password: {}"),
    "yaml_dotted": ("app.yml", "container.credentials.password: {}"),
    "yaml_quoted": ("config.yaml", 'password: "{}"'),
    "ini": ("app.ini", "password={}"),
    "env": (".env", "DB_PASSWORD={}"),
    "env_export": ("deploy.sh", "export API_TOKEN={}"),
    "toml": ("settings.toml", 'secret = "{}"'),
    "json": ("config.json", '{{"apiKey": "{}"}}'),
    "es_properties": ("app.properties", "contraseña = {}"),
    "es_yaml": ("es.yml", "clave: {}"),
    "xml": ("web.xml", "<password>{}</password>"),
    "sql": ("schema.sql", "ALTER USER app WITH PASSWORD '{}';"),
    "jdbc": ("Db.java", 'Connection conn = DriverManager.getConnection(url, "sa", "{}");'),
    "psycopg": ("db.py", 'conn = psycopg2.connect(host=host, password="{}")'),
    "mysql_cli": ("restore.sh", "mysql -u root -p{} app < dump.sql"),
    "join": ("app.py", 'password = "".join(["{}", "{}"])'),
}
YAML_FORMS = ("yaml", "yaml_dotted", "yaml_quoted", "es_yaml")
QUOTED_FORMS = ("yaml_quoted", "toml", "json", "jdbc", "psycopg")   # strings that read `\uXXXX` escapes
BARE_FORMS = ("yaml", "ini", "env", "env_export", "es_properties", "es_yaml", "mysql_cli")  # base32 fits unquoted
URL_FORMS = {
    "url_path": "https://app.local/reset/{}/confirm",
    "url_query": "https://app.local/login?next=/home&token={}",
    "url_fragment": "https://app.local/callback#state=1&access_token={}",
    "url_matrix": "https://app.local/app;jsessionid={}/home",
}
STDERR_FORMS = {
    "stderr_kv": "level=error msg=\"login rejected\" password={}",
    "stderr_url": "fatal: unable to access 'https://ci:{}@git.local/org/repo.git/': The requested URL returned error: 403",
    "stderr_shape": "An error occurred (InvalidClientTokenId) when calling GetCallerIdentity with key {}",
}
ENGINES = {
    "opengrep": tuple(FORMS),
    "zizmor": YAML_FORMS,
    "sarif_secrets": tuple(form for form in FORMS if form != "join"),
    "sarif_798": tuple(FORMS),
    "web": tuple(URL_FORMS),
    "stderr": tuple(STDERR_FORMS),
}


def _written(value: str, encoding: str, form: str) -> str:
    if encoding == "base32":
        return base64.b32encode(value.encode()).decode()
    if encoding == "uescape":
        return "".join(f"\\u{ord(character):04x}" for character in value)
    if form in URL_FORMS or form == "stderr_url":
        return quote(value, safe="")
    return value


@st.composite
def cases(draw):
    engine = draw(st.sampled_from(sorted(ENGINES)))
    form = draw(st.sampled_from(ENGINES[engine]))
    kinds = TOKENS if form == "url_path" else ("aws", "github", "jwt") if form == "stderr_shape" else KINDS
    value = _value(draw(st.sampled_from(kinds)), draw(st.integers(0, 2**32)))
    encodings = ["raw", *(["uescape"] if form in QUOTED_FORMS else []), *(["base32"] if form in BARE_FORMS else [])]
    return value, draw(st.sampled_from(encodings)), form, engine, draw(st.sampled_from([798, 16]))


def _line(value: str, encoding: str, form: str) -> tuple[str, str, list[str]]:
    """The file, the line holding the value as written, and every piece of it the line shows."""
    written = _written(value, encoding, form)
    if form in URL_FORMS:
        return "", URL_FORMS[form].format(written), [written]
    if form in STDERR_FORMS:
        return "", STDERR_FORMS[form].format(written), [written]
    path, template = FORMS[form]
    if form == "join":
        cut = len(written) // 2
        return path, template.format(written[:cut], written[cut:]), [written[:cut], written[cut:]]
    return path, template.format(written), [written]


def _forbidden(value: str, pieces: list[str]) -> set[str]:
    """The value and its pieces that must not show: those with a fragment (value_oracle). A piece made only of symbols,
    common words and numbers of up to three digits may stay (shared/render.py)."""
    return {item for item in (value, *pieces) if len(item) >= 6 and fragments(item)}


WORKFLOW = """on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: registry.local/app:1
      credentials:
        username: deploy
        {line}
    steps:
      - run: make test
"""


def _zizmor_report(text: str, path: str, ident: str) -> list:
    """zizmor pointing at the container block (its offsets in the file, as zizmor reports them)."""
    start = text.index("    container:")
    end = text.index("    steps:")
    row = text[:start].count("\n")
    return [{"ident": ident, "desc": "credentials in a container", "url": "https://docs.zizmor.sh/audits/",
             "determinations": {"confidence": "High", "severity": "High"},
             "locations": [{"symbolic": {"key": {"Local": {"verbatim_path": f"/src/{path}"}}, "annotation": "credentials are hard-coded",
                                         "route": {"route": [{"Key": "jobs"}, {"Key": "build"}, {"Key": "container"}]}, "kind": "Primary"},
                            "concrete": {"location": {"start_point": {"row": row, "column": 4}, "end_point": {"row": text[:end].count("\n") - 1, "column": 0},
                                                      "offset_span": {"start": start, "end": end}}}}]}]


def _code_engines(reports: dict, failing: dict | None = None) -> tuple:
    """The code engines answering with these reports through their real parsers; `failing`: {engine: (message, stderr)}
    for an engine that failed, its error going through `with_cause` as an adapter's does."""
    from pitangus.modules.scanning.repository import CODE_ENGINES
    parsers = {"opengrep": lambda context: parse_opengrep(reports.get("opengrep") or {"results": []}),
               "zizmor": lambda context: parse_zizmor(reports.get("zizmor") or [], context.root)}

    def answer(key, context):
        if failing and key in failing:
            message, stderr = failing[key]
            cause = with_cause(msg("scanning.contract.exit_code", engine=key, code=1), subprocess.CompletedProcess([key], 1, "", stderr))
            raw = msg("scanning.engines.with_cause", message=msg("scanning.contract.empty", engine=key), cause=message)
            return {**_replayed(key, []), "status": "inconclusive", "detail": raw, "contract": {"blind": True, "cause": cause}}
        return _replayed(key, parsers.get(key, lambda _: [])(context))
    return tuple(EngineStep(engine.key, lambda context, key=engine.key: answer(key, context), engine.progress, required=engine.required,
                            merged=engine.merged) for engine in CODE_ENGINES)


def _sarif(tool: str, rule: dict, result: dict) -> dict:
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": tool, "version": "1.0.0", "rules": [rule]}}, "results": [result]}]}


def _gitleaks(path: str, line: str) -> dict:
    """Gitleaks' SARIF: the line it matched as the snippet, the commit and its author as partial fingerprints."""
    return _sarif("gitleaks", {"id": "generic-api-key", "shortDescription": {"text": "Generic API Key"}},
                  {"ruleId": "generic-api-key", "message": {"text": f"generic-api-key has detected secret for file {path}."},
                   "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}, "region": {"startLine": 3, "snippet": {"text": line}}}}],
                   "partialFingerprints": {"commitSha": "3f2a" * 10, "email": "dev@example.com", "author": "dev"}})


def _semgrep_798(path: str, line: str) -> dict:
    """Semgrep's CWE-798 rule, its message interpolating what it matched."""
    return _sarif("Semgrep OSS", {"id": "java.lang.security.audit.hardcoded-password", "shortDescription": {"text": "Hard-coded password"},
                                  "properties": {"tags": ["CWE-798: Use of Hard-coded Credentials", "security"], "precision": "high"}},
                  {"ruleId": "java.lang.security.audit.hardcoded-password", "level": "error",
                   "message": {"text": f"A hard-coded credential was found: {line.strip()}"},
                   "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}, "region": {"startLine": 3, "snippet": {"text": line}}}}]})


def _zap(url: str, value: str) -> dict:
    """ZAP's SARIF about a URL carrying a credential: its evidence the bare value, its message the URL."""
    return _sarif("ZAP", {"id": "10024", "shortDescription": {"text": "Information Disclosure - Sensitive Information in URL"},
                          "properties": {"solution": "Do not pass sensitive information in URIs."}},
                  {"ruleId": "10024", "level": "note", "message": {"text": f"The URL contains potentially sensitive information: {url}"},
                   "locations": [{"physicalLocation": {"artifactLocation": {"uri": url}, "region": {"startLine": 1, "snippet": {"text": value}}}}],
                   "properties": {"param": "token"}, "webRequest": {"method": "GET", "target": url}})


def _rows(data_dir: Path) -> str:
    """Every row of every table, as text."""
    shown = []
    with db.transaction(data_dir) as connection:
        for table in db.metadata.sorted_tables:
            shown += [str(tuple(row)) for row in connection.execute(select(table)).all()]
    return "\n".join(shown)


def _outputs(data_dir: Path, record: dict, key: str, mode: str, *, cli_from: str) -> dict[str, str]:
    """Everything a run reaches, as text. `cli_from`: whose findings the CLI renders ("scan": a local scan's own
    record; "saved": an import, which the CLI only shows once stored)."""
    from pitangus.modules.findings.ai_prompt import prompt
    from pitangus.modules.findings.fix_guide import attach
    from pitangus.modules.integrations import notifications
    from pitangus.modules.reporting import technical
    from pitangus.modules.runs import jira_brief, local
    from pitangus.modules.runs.store import (artifact, load_run, render_profile_report, render_repository_report,
                                             render_repository_sarif, render_tickets, save_and_apply)
    out = {}
    with patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": mode}):
        saved, _ = save_and_apply(data_dir, record, quiet=True)
    out["rows"] = _rows(data_dir)
    out["stored run"] = json.dumps(load_run(data_dir, saved["id"]), ensure_ascii=False)
    out["stored report"] = artifact(data_dir, saved["id"], "report.md").decode()
    out["stored sarif"] = artifact(data_dir, saved["id"], "findings.sarif").decode()
    entries = registry.load(data_dir, key)["findings"]
    out["registry"] = json.dumps(entries, ensure_ascii=False)
    among = [entry["finding"] for entry in entries.values() if entry.get("finding")]
    shown = record if cli_from == "scan" else saved
    for locale in ("en", "es"):
        out[f"api prompt {locale}"] = "\n".join(prompt(attach([dict(item)], among=among)[0], locale) for item in among)
        result = {"name": "org/api", "target": "org/api", "status": shown["status"], "comparison": None, "findings": shown["findings"],
                  "resolved": [], "gate": local.verdict(shown["findings"], "high"), "exit_code": 1, "excluded": {"patterns": [], "findings": 0},
                  "engines": {"ran": [], "failed": []}, "not_analyzed": [], "fail_on": "high", "scan": shown}
        for name, render in (("prompt", local.render_prompt), ("json", local.render_json), ("sarif", local.render_sarif),
                             ("text", local.render_text), ("markdown", local.render_markdown)):
            out[f"cli {name} {locale}"] = render(result, locale=locale)
        out[f"report {locale}"] = render_repository_report(saved, locale=locale)
        out[f"sarif {locale}"] = json.dumps(render_repository_sarif(saved, locale=locale), ensure_ascii=False)
        out[f"profile {locale}"] = render_profile_report(saved, "soc2", locale=locale)
        out[f"tickets {locale}"] = json.dumps(render_tickets(saved, locale=locale), ensure_ascii=False, default=str)
        by_print = {item["fingerprint"]: item for item in saved["findings"]}
        out[f"jira {locale}"] = json.dumps([jira_brief.brief([{"fingerprint": item["fingerprint"], "severity": item["severity"]}], by_print, asset=key,
                                                             source=saved.get("source"), first_seen={}, days={}, panel_url="https://pitangus.local",
                                                             locale=locale) for item in saved["findings"]], ensure_ascii=False, default=str)
        message = notifications.findings_message(saved, saved["findings"], locale)
        out[f"notifications {locale}"] = json.dumps([notifications.render(kind, message, locale) for kind in ("slack", "teams", "webhook")],
                                                    ensure_ascii=False, default=str)
        out[f"technical pdf {locale}"] = _pdf_text(technical, saved, locale)
    return out


class NoCredentialAnywhereTests(unittest.TestCase):
    """For a value in any credential form, through any engine: nowhere in storage or output."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.examples = 0

    def _repository(self, data_dir: Path, source: dict, files: dict[str, str], replay: tuple) -> dict:
        from pitangus.modules.scanning.repository import scan_repository
        root = data_dir / "snapshot"
        for path, text in files.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text, encoding="utf-8")
        if not files:
            root.mkdir(parents=True, exist_ok=True)
            (root / "README.md").write_text("# api\n", encoding="utf-8")
        return scan_repository(root, source, data_dir=data_dir, replay=replay, feeds={"kev": {}, "epss": {}})

    def _imported(self, document: dict, source: dict) -> dict:
        from pitangus.modules.runs.imports import _record
        parsed = sarif_import.parse(document)[0]
        return _record(parsed, source, scope="full", commit=None, branch=None, requested_by="test", now=datetime.now(timezone.utc).isoformat())

    def check(self, case: tuple, mode: str):
        value, encoding, form, engine, cwe = case
        self.examples += 1
        path, line, pieces = _line(value, encoding, form)
        data_dir = Path(self.directory.name) / f"data-{self.examples}"
        key = f"github#{self.examples}"
        source = {"id": "github:org/api", "uid": key, "name": "org/api", "provider": "github"}
        with _captured_logs() as logs:
            cli_from = "scan"
            if engine == "opengrep":
                lines = ["# settings", "", line, "# end"]
                report = {"results": [{"check_id": "rules.config.credential-in-config", "path": f"/src/{path}", "start": {"line": 3}, "end": {"line": 3},
                                       "extra": {"lines": line, "message": f"Matched {line.strip()}", "severity": "ERROR",
                                                 "metadata": {"cwe": [cwe], "confidence": "HIGH", "category": "security"}}}]}
                record = self._repository(data_dir, source, {path: "\n".join(lines) + "\n"}, _code_engines({"opengrep": report}))
                self.assertTrue(record["findings"], "the finding is still reported")
            elif engine == "zizmor":
                workflow = WORKFLOW.format(line=line)
                where = ".github/workflows/ci.yml"
                ident = "hardcoded-container-credentials" if cwe == 798 else "template-injection"
                record = self._repository(data_dir, source, {where: workflow}, _code_engines({"zizmor": _zizmor_report(workflow, where, ident)}))
                self.assertTrue(any(item["tool"] == "zizmor" for item in record["findings"]), "zizmor's finding is still reported")
            elif engine == "stderr":
                record = self._repository(data_dir, source, {}, _code_engines({}, {"checkov": (line, f"Traceback...\n{line}\n")}))
                self.assertIn("inconclusive", [step["status"] for step in record["steps"] if step["id"] == "checkov"], "the engine failed")
            else:
                document = (_gitleaks(path, line) if engine == "sarif_secrets" else _semgrep_798(path, line) if engine == "sarif_798"
                            else _zap(line, pieces[0]))
                record, cli_from = self._imported(document, source), "saved"
                self.assertTrue(record["findings"], "the import still has its finding")
            outputs = _outputs(data_dir, record, key, mode, cli_from=cli_from)
            if cli_from == "scan":
                outputs["scan"] = json.dumps(record, ensure_ascii=False)
        outputs["logs"] = "\n".join(logs)
        for name, text in outputs.items():
            for item in _forbidden(value, pieces):
                self.assertNotIn(item, text, f"{name}: {case}")
            self.assertEqual(leaked(value, text, numbers=8), [], f"{name}: {case}")

    @settings(max_examples=60 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    @given(cases(), st.sampled_from(["v1", "shadow", "v2"]))
    # The seeds of the validation: zizmor's unquoted container password, Semgrep's CWE-798 on a JDBC connection, a
    # gitleaks snippet, an AWS key on an engine's stderr, a JWT and a session id in a URL's path; and the extra forms:
    # base32, `\uXXXX` escapes and a value joined from a list.
    @example(("HarborLights-2024!", "raw", "yaml_dotted", "zizmor", 798), "v2")
    @example(("HarborLights-2024!", "raw", "yaml", "zizmor", 94), "v2")
    @example(("QuarryStone#77x", "raw", "jdbc", "sarif_798", 798), "v2")
    @example(("QuarryStone#77x", "raw", "jdbc", "opengrep", 16), "v1")
    @example(("ghp_" + "Zq9xK2mP7vL4wR8tY1nB" * 2 + "Ab12", "raw", "env", "sarif_secrets", 798), "v2")
    @example(("AKIAQX7RZ2KD9LMNP4TW", "raw", "stderr_shape", "stderr", 798), "v2")  # gitleaks:allow
    @example(("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1rwW1gFWFOEjXk", "raw", "url_path", "web", 798), "v2")  # gitleaks:allow
    @example(("8F2A9C0D1E3B4A5F6C7D8E9F0A1B2C3D", "raw", "url_matrix", "web", 798), "shadow")
    @example(("HarborLights-2024!", "base32", "yaml", "opengrep", 16), "v2")
    @example(("QuarryStone#77x", "uescape", "json", "sarif_798", 798), "v2")
    @example(("QuarryStone#77x", "raw", "join", "opengrep", 16), "v2")
    @example(("correcthorsebatterystaple", "raw", "es_properties", "opengrep", 16), "v2")
    @example(("AKIA" + "FJCIWBUIKNFYFZST", "raw", "url_path", "web", 798), "v1")   # nightly: an AWS key id of letters only
    def test_a_credential_in_any_form_shows_nowhere(self, case, mode):
        self.check(case, mode)


class MaskingPropertiesTests(unittest.TestCase):
    """Masking by context, idempotence and identities, on many more examples than the end-to-end test."""

    @settings(max_examples=300 * SCALE, deadline=None)
    @given(cases())
    @example(("AKIA" + "QXHYOLSVQTIHIIVN", "raw", "url_path", "web", 798))
    @example(("eXAFAxjb-u=#.99@", "raw", "join", "opengrep", 798))   # nightly: a piece of symbols, a word and a short number
    def test_every_form_is_masked_and_masking_is_idempotent(self, case):
        value, encoding, form, _, _ = case
        _, line, pieces = _line(value, encoding, form)
        masked = mask(line)
        for item in _forbidden(value, pieces):
            self.assertNotIn(item, masked, line)
        self.assertEqual(leaked(value, masked), [], line)
        self.assertEqual(mask(masked), masked)

    @settings(max_examples=200 * SCALE, deadline=None)
    @given(st.sampled_from(sorted(URL_FORMS)), st.sampled_from(TOKENS), st.integers(0, 2**32), st.sampled_from(["zap", "nuclei"]),
           st.sampled_from(["baseline", "exposure"]))
    def test_a_web_findings_identity_is_the_same_for_its_url_as_reported_and_as_stored(self, form, kind, seed, tool, coverage):
        url = URL_FORMS[form].format(quote(_value(kind, seed), safe=""))
        finding = {"fingerprint": "f" * 64, "scanner": "dast", "tool": tool, "rule_id": "10024", "path": url, "line": 1,
                   "web": {"evidence": "", "coverage": coverage}, "instances": [{"path": url}]}
        stored = sanitize_finding(finding)   # as in `v1`: its identity pinned before its URL is rendered
        self.assertEqual(stored["path"], mask_url(url))
        self.assertEqual(mask_url(stored["path"]), stored["path"])
        self.assertEqual(canonical.identity_of(stored), canonical.identity_of(finding))
        # `v2`: the family's identity, pinned before rendering. Across scans: the URL stored earlier, known by its key
        # (`registry.web_known`), and the one reported now give one identity.
        family = sanitize_finding(canonical.collapse([finding])[0])
        known = [(tool, "10024", web_keys.of_instance(item), coverage) for item in family["instances"]]
        self.assertEqual(canonical.collapse([finding], known)[0]["fingerprint"], family["fingerprint"])
        self.assertEqual(canonical.collapse([family], known)[0]["fingerprint"], family["fingerprint"])

    @settings(max_examples=200 * SCALE, deadline=None)
    @given(cases(), st.sampled_from(["sast", "secrets", "cicd"]))
    def test_a_finding_keeps_its_identity_and_no_snippet(self, case, scanner):
        value, encoding, form, _, cwe = case
        path, line, _ = _line(value, encoding, form)
        finding = {"fingerprint": "a" * 64, "scanner": scanner, "tool": "semgrep", "rule_id": "r", "path": path or "a.txt", "line": 3,
                   "cwe": [cwe], "snippet": line, "title": "t"}
        stored = sanitize_finding(finding)
        self.assertEqual(canonical.identity_of(stored), canonical.identity_of(finding))
        self.assertNotIn("snippet", stored)
        self.assertEqual(sanitize_finding(stored), stored)

    def test_context_masking_stays_fast_on_adversarial_text(self):
        import time
        for text in ("password: " * 5000, "[" * 50000, "getConnection(" * 4000, '"".join([' + '"a", ' * 8000 + "])", "https://a/" + "b;c=d/" * 7000,
                     "key: " + "Ab9#" * 12000, "<password>" * 5000, "x.password" * 5000 + ": v", "mysql " * 8000 + " -pX", "a=" * 25000):
            started = time.monotonic()
            mask(text)
            self.assertLess(time.monotonic() - started, 5, text[:20])

    def test_code_keeps_its_structure(self):
        """Punctuation, operators and the words of the lexicon stay, wherever they are; any other word goes (shared/render.py)."""
        for text, shown in (("def login(username: str, password: str):", None), ("credentials:", None), ("if password == stored:", None),
                            ("import os", None), ("cursor.execute(sql, (user_id,))", None),
                            ('os.system("rm -rf " + path)', 'os.system("rm -*** " + path)'),
                            ("password: ${{ secrets.DB }}", None), ("password: ${{ secrets.Hx7Lp2Qz }}", "password: ${{ secrets.*** }}"),
                            ("https://app.local/users/550e8400-e29b-41d4-a716-446655440000", "https://app.local/users/***-***-***-***-***"),
                            ("https://github.com/org/repo/commit/" + "3f2a" * 10, "https://github.com/org/repo/commit/***"),
                            ("https://app.local/assets/index-BkL9x2a1.js", "https://app.local/assets/index-***.js"),
                            ("https://blog.local/2023-10-12/how-to-configure-https-on-nginx", "https://blog.local/***-10-12/how-to-configure-https-on-nginx"),
                            ("https://app.local/search?q=%3Cscript%3E&page=2", "https://app.local/search?***=***&page=***"),
                            ('return render_template_string(request.args.get("name"))', None),
                            ('return render_template_string(request.args.get("Vb9Rt4Kw"))', 'return render_template_string(request.args.get("***"))')):
            self.assertEqual(mask(text), shown or text)
            self.assertEqual(mask(mask(text)), mask(text))


class RecordTextTests(unittest.TestCase):
    """Every text of a run, whatever its key, is masked: steps, progress, limitations, details, causes, summaries."""

    @settings(max_examples=100 * SCALE, deadline=None)
    @given(st.sampled_from(sorted(STDERR_FORMS)), st.sampled_from(("aws", "github", "jwt")), st.integers(0, 2**32),
           st.sampled_from(["steps", "progress", "limitations", "summary", "delivery", "anything"]))
    def test_an_engines_stderr_in_any_field_is_masked(self, form, kind, seed, field):
        value = _value(kind, seed)
        _, line, pieces = _line(value, "raw", form)
        cause = with_cause(msg("scanning.contract.exit_code", engine="trivy", code=1), subprocess.CompletedProcess(["trivy"], 1, "", line))
        raw = msg("scanning.engines.with_cause", message="failed", cause=line)
        nested = {"steps": [{"id": "trivy", "detail": raw, "tool": {"image": "ghcr.io/x@sha256:" + "ab12" * 16}}],
                  "progress": [{"at": "2026-01-01T00:00:00+00:00", "level": "error", "message": raw}],
                  "limitations": [raw, line], "summary": {"tools": [{"name": "trivy", "contract": {"blind": True, "cause": cause}}]},
                  "delivery": {"comment": {"$t": "runs.delivery.error", "params": {"reason": line}}}, "anything": {"deep": [[line]]}}[field]
        record = {"id": "f" * 32, "type": "repository_scan", "status": "failed", "source": {"id": "github:org/api", "sha256": "ab12" * 16},
                  "findings": [], field: nested}
        stored = sanitize_record(record)
        for item in _forbidden(value, pieces):
            self.assertNotIn(item, json.dumps(stored, ensure_ascii=False))
        self.assertEqual(stored["source"], record["source"])  # identifiers and digests keep their value
        self.assertEqual(sanitize_record(stored), stored)

    def test_progress_saved_while_running_is_masked(self):
        from pitangus.modules.runs.store import load_run, save_record
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        data_dir = Path(directory.name)
        key = "AKIA" + "QX7RZ2KD9LMNP4TW"
        record = {"id": "e" * 32, "type": "repository_scan", "status": "running", "created_at": datetime.now(timezone.utc).isoformat(),
                  "source": {"id": "github:org/api", "uid": "github#1", "name": "org/api", "provider": "github"}, "target": "org/api",
                  "progress": [{"at": "x", "level": "error", "message": f"fatal: password=HarborLights-2024! key {key}"}],
                  "limitations": [msg("scanning.engines.with_cause", message="failed", cause=f"token {key}")]}
        save_record(data_dir, record)
        text = json.dumps(load_run(data_dir, "e" * 32))
        self.assertNotIn(key, text)
        self.assertNotIn("HarborLights-2024!", text)


class StoredCredentialsMigrationTests(unittest.TestCase):
    """`mask_stored_credentials` masks what earlier masking left (unquoted values, connection arguments, URLs, every
    text of a run, a credential's snippet), and every finding keeps its identity."""

    def setUp(self):
        from pitangus.app import data_migrations as migrations
        from pitangus.shared import documents
        self.migrations = migrations
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name) / "data"
        self.data_dir.mkdir()
        position = [migration.name for migration in migrations.MIGRATIONS].index("mask_stored_credentials")
        documents.save(self.data_dir, migrations.VERSION_DOCUMENT, {"version": position, "history": []})

    def test_stored_runs_registry_and_outbox_are_masked_and_keep_their_identities(self):
        from pitangus.modules.integrations.tables import outbox
        from pitangus.modules.runs.store import _persist, artifact, load_run, render_repository_report, render_repository_sarif
        password, connection, aws, jwt = "HarborLights-2024!", "QuarryStone#77x", "AKIAQX7RZ2KD9LMNP4TW", _value("jwt", 7)  # gitleaks:allow
        base = {"title": "A finding", "confidence": 8, "cwe": [], "owasp": [], "cve": [], "ghsa": [], "verdict": "candidate",
                "priority": {"action": "attend", "factors": []}, "remediation": "Fix it.", "package": None, "advisory": None, "reason": "Why."}
        zizmor = {**base, "fingerprint": "a" * 64, "finding_id": "a" * 16, "scanner": "cicd", "tool": "zizmor", "rule_id": "template-injection",
                  "path": ".github/workflows/ci.yml", "line": 5, "severity": "high", "cwe": [94],
                  "snippet": f"container: image: x credentials: username: u password: {password}\ncredentials are hard-coded"}
        semgrep = {**base, "fingerprint": "b" * 64, "finding_id": "b" * 16, "scanner": "sast", "tool": "Semgrep OSS", "rule_id": "hardcoded-password",
                   "path": "Db.java", "line": 3, "severity": "high", "cwe": [798], "snippet": f'getConnection(url,"sa","{connection}")',
                   "reason": {"$t": "scanning.sarif.reason", "params": {"tool": "Semgrep OSS", "message": f'getConnection(url,"sa","{connection}")'}}}
        gitleaks = {**base, "fingerprint": "c" * 64, "finding_id": "c" * 16, "scanner": "secrets", "tool": "gitleaks", "rule_id": "generic-api-key",
                    "path": ".env", "line": 1, "severity": "critical", "snippet": f"DB_PASSWORD={password}"}
        # A web finding as v2 stores it (its identity computed before masking), and one stored without an identity
        # (v1), whose identity reads its URL masked.
        web = {**base, "fingerprint": "d" * 64, "finding_id": "d" * 16, "scanner": "dast", "tool": "zap", "rule_id": "10024",
               "path": f"https://app.local/reset/{jwt}", "line": 1, "severity": "low", "web": {"evidence": jwt},
               "instances": [{"path": f"https://app.local/reset/{jwt}"}]}
        web["identity"] = canonical.identity_of(web)
        legacy = {**base, "fingerprint": "e" * 64, "finding_id": "e" * 16, "scanner": "dast", "tool": "zap", "rule_id": "10098",
                  "path": f"https://app.local/app;jsessionid={aws}/home", "line": 1, "severity": "low", "web": {"evidence": "Access-Control-Allow-Origin: *"}}
        stored = [zizmor, semgrep, gitleaks, web, legacy]
        before = {item["fingerprint"]: canonical.identity_of(item) for item in stored}
        record = {"schema_version": "0.3.0", "id": "f" * 32, "created_at": datetime.now(timezone.utc).isoformat(), "type": "sarif_import",
                  "status": "completed", "target": "org/api", "source": {"id": "github:org/api", "uid": "github#1", "name": "org/api", "provider": "github"},
                  "findings": stored, "steps": [{"id": "trivy", "name": "Trivy", "status": "inconclusive",
                                                 "detail": msg("scanning.engines.with_cause", message="failed", cause=f"invalid key {aws}")}],
                  "progress": [{"at": "x", "level": "error", "message": f"password={password}"}],
                  "limitations": [f"engine said: token {aws}"], "owasp_coverage": [], "context": "",
                  "summary": {"files": 3, "dependencies": 0, "candidates": 4, "severities": {}, "priorities": {}, "kev": 0, "fixable": 0, "tools": []}}
        _persist(self.data_dir, record, render_repository_report(record), render_repository_sarif(record))
        registry._save(self.data_dir, {"asset": "github#1", "name": "org/api", "applied": [], "findings": {
            item["fingerprint"]: {"status": "open", "finding": item} for item in stored}})
        with db.transaction(self.data_dir) as connection_:
            connection_.execute(outbox.insert().values(tenant_id=db.TENANT, id="o1", channel_id="webhook", status="pending", attempts=0,
                                                       payload={"text": f"fatal: password={password} at https://app.local/reset/{jwt}"},
                                                       created_at=datetime.now(timezone.utc), next_attempt_at=datetime.now(timezone.utc)))

        self.assertIn("mask_stored_credentials", self.migrations.upgrade(self.data_dir))
        run = load_run(self.data_dir, "f" * 32)
        entries = registry.load(self.data_dir, "github#1")["findings"]
        texts = [json.dumps(run), json.dumps(entries), artifact(self.data_dir, "f" * 32, "report.md").decode(),
                 artifact(self.data_dir, "f" * 32, "findings.sarif").decode(), _rows(self.data_dir)]
        for text in texts:
            for value in (password, connection, aws, jwt):
                self.assertNotIn(value, text)
        for item in [*run["findings"], *(entry["finding"] for entry in entries.values())]:
            self.assertEqual(canonical.identity_of(item), before[item["fingerprint"]], item["fingerprint"])
            self.assertNotIn("snippet", item)
        self.assertEqual(self.migrations._mask_stored_credentials(self.data_dir), 0)  # idempotent


if __name__ == "__main__":
    unittest.main()
