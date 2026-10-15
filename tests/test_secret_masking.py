"""No secret value anywhere (shared/masking.py), tested as a property.

For every secret an engine detects, its value and the ways it is written encoded appear in no persisted field and in
no output: the stored run and registry, the CLI's prompt, JSON, SARIF, text and Markdown, the prompt the panel serves,
the Markdown, SARIF and PDF reports, the Jira issue, the notifications and the logs. Findings go through the real
parsers and the real scan (scan_repository with replayed engines). Masking never changes a finding's fingerprint or
identity, and is idempotent. Text shaped like a credential is masked even when no engine fired.
"""

import base64
import json
import logging
import os
import random
import string
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

from hypothesis import HealthCheck, example, given, settings, strategies as st

from pitangus.modules.scanning.secret_location import entropy
from pitangus.modules.findings import canonical, registry
from pitangus.modules.scanning import engines
from pitangus.modules.scanning.engines import EngineStep, parse_betterleaks, parse_opengrep, parse_trivy
from pitangus.shared.masking import NO_SNIPPET_CWES, mask, mask_code, sanitize_finding, variants
from value_oracle import fragments, leaked

PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

B62 = string.ascii_letters + string.digits
SYMBOLS = "!#%&*+-.=?@^_~"


def _secret(kind: str, seed: int) -> str:
    """A secret of `kind`, random as real ones are (a seed, so every example is reproducible)."""
    rng = random.Random(seed)
    pick = lambda alphabet, count: "".join(rng.choice(alphabet) for _ in range(count))  # noqa: E731
    if kind == "github":
        return "ghp_" + pick(B62, 36)
    if kind == "slack":
        return f"xoxb-{pick(string.digits, 12)}-{pick(string.digits, 12)}-{pick(B62, 24)}"
    if kind == "aws":
        return "AKIA" + pick(string.ascii_uppercase + string.digits, 16)
    if kind == "hex":
        return pick("0123456789abcdef", rng.randint(16, 40))
    if kind == "jwt":
        part = lambda size: base64.urlsafe_b64encode(rng.randbytes(size)).decode().rstrip("=")  # noqa: E731
        return "eyJ" + part(18) + "." + part(24) + "." + part(32)
    # a password someone chose: letters, digits and symbols
    return pick(string.ascii_letters, 3) + pick(B62 + SYMBOLS, rng.randint(6, 14)) + pick(string.digits, 1) + pick(SYMBOLS, 1)


ENCODINGS = {"raw": lambda value: value, "url": lambda value: quote(value, safe=""),
             "base64": lambda value: base64.b64encode(value.encode()).decode(), "hex": lambda value: value.encode().hex()}

# Vulnerable constructs a secret can sit in: (file, the line with `{}` where the secret goes, rule, CWE). "split" puts it
# in two adjacent literals.
CONSTRUCTS = {
    "eval": ("app.py", 'eval(request.args["q"])  # token {}', "appsec.python.eval", 95),
    "sqli": ("db.py", "cursor.execute(\"SELECT * FROM users WHERE k='{}' AND id=\" + uid)", "appsec.python.sqli", 89),
    "verify": ("client.py", 'requests.get(url, verify=False, headers={{"X-Token": "{}"}})', "appsec.python.verify-false", 295),
    "password": ("App.java", 'String password = "{}";', "java.hardcoded-password", 798),
    "supabase": ("lib/db.ts", 'const supabase = createClient(SUPABASE_URL, "{}")', "supabase-service-role-key", 798),
    "curl": ("deploy.sh", 'curl -H "Authorization: token {}" https://api.example.com/v1', "appsec.shell.curl-insecure", 319),
    "dsn": ("settings.py", 'DATABASE_URL = "postgres://app:{}@db:5432/app"', "appsec.python.hardcoded-dsn", 798),
    "sql": ("schema.sql", "CREATE USER app IDENTIFIED BY '{}';", "appsec.sql.hardcoded-password", 798),
    "split": ("config.js", 'const token = "{}" + "{}";', "appsec.js.hardcoded-token", 798),
}


def _place(construct: str, value: str) -> tuple[str, str, list[str]]:
    """The file, the line holding `value` and the pieces of it the file shows (two for a split value)."""
    path, template, _, _ = CONSTRUCTS[construct]
    if construct == "split":
        cut = len(value) // 2
        return path, template.format(value[:cut], value[cut:]), [value[:cut], value[cut:]]
    return path, template.format(value), [value]


def _replayed(key: str, findings: list) -> dict:
    meta = engines.IMAGES[key]
    return {"tool": key, "name": meta["name"], "version": meta["version"], "image": meta["image"], "status": "completed",
            "detail": "replayed", "findings": findings, "duration_s": None, "coverage": {"*": {"examined": True}}}


def _engines(reports: dict) -> tuple:
    """The code engines answering with these reports, parsed by their real parsers against the snapshot."""
    from pitangus.modules.scanning.repository import CODE_ENGINES
    parsers = {"opengrep": lambda context: parse_opengrep(reports["opengrep"]),
               "betterleaks": lambda context: parse_betterleaks(reports.get("betterleaks") or [], None, context.root),
               "trivy": lambda context: parse_trivy(reports.get("trivy") or {"Results": []}, {}, None, context.root)}

    def step(engine):
        return EngineStep(engine.key, lambda context: _replayed(engine.key, parsers.get(engine.key, lambda _: [])(context)),
                          engine.progress, required=engine.required, merged=engine.merged)
    return tuple(step(engine) for engine in CODE_ENGINES)


def _reports(path: str, lines: list[str], number: int, detected: str, rule: str, cwe: int, engine: str) -> dict:
    """Opengrep matching line `number`, its message interpolating what it matched (as third-party rules do), and the
    secret engine pointing at `detected` on it."""
    line = lines[number - 1]
    start = line.index(detected)
    opengrep = {"results": [{"check_id": f"rules.{rule}", "path": f"/src/{path}", "start": {"line": number}, "end": {"line": number},
                             "extra": {"lines": line, "message": f"Matched {line.strip()}", "severity": "ERROR",
                                       "metadata": {"cwe": [cwe], "confidence": "HIGH", "category": "security"}}}]}
    if engine == "betterleaks":
        return {"opengrep": opengrep, "betterleaks": [{"RuleID": "generic-api-key", "File": f"/src/{path}", "StartLine": number, "EndLine": number,
                                                      "StartColumn": start + 1, "EndColumn": start + len(detected), "Match": "REDACTED",
                                                      "Entropy": entropy(detected)}]}
    offset = len("".join(item + "\n" for item in lines[:number - 1]).encode()) + len(line[:start].encode())
    return {"opengrep": opengrep, "trivy": {"Results": [{"Target": path, "Class": "secret", "Secrets": [
        {"RuleID": "generic-api-key", "Category": "Generic", "Severity": "CRITICAL", "Title": "Generic API key", "StartLine": number,
         "EndLine": number, "Match": line[:start] + "*" * len(detected.encode()) + line[start + len(detected):], "Offset": offset}]}]}}


@contextmanager
def _captured_logs():
    records: list[str] = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage() + " " + " ".join(str(value) for value in record.__dict__.values()))
    handler, root = Capture(level=logging.DEBUG), logging.getLogger()
    # Once any earlier test in the process has run log.configure(), the "pitangus" logger stops propagating to the root:
    # capture on it too then, or the logs the product writes would never reach the handler.
    owner = logging.getLogger("pitangus")
    loggers = [root] if owner.propagate else [root, owner]
    levels = [logger.level for logger in loggers]
    for logger in loggers:
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        for logger, level in zip(loggers, levels):
            logger.removeHandler(handler)
            logger.setLevel(level)


def _pdf_text(technical, record: dict, locale: str) -> str:
    """The text the technical PDF lays out (each paragraph handed to the PDF library)."""
    shown: list[str] = []
    real = technical.Paragraph

    def paragraph(text, *args, **options):
        shown.append(str(text))
        return real(text, *args, **options)
    with patch.object(technical, "Paragraph", side_effect=paragraph):
        technical.render_technical_pdf(record, version="0.14", locale=locale)
    return "\n".join(shown)


def _outputs(data_dir: Path, scan: dict, key: str, mode: str) -> dict[str, str]:
    """Everything a finding reaches, as text."""
    from pitangus.modules.findings.ai_prompt import prompt
    from pitangus.modules.findings.fix_guide import attach
    from pitangus.modules.integrations import notifications
    from pitangus.modules.reporting import technical
    from pitangus.modules.runs import jira_brief, local
    from pitangus.modules.runs.store import (artifact, load_run, render_profile_report, render_repository_report,
                                             render_repository_sarif, render_tickets, save_and_apply)
    out = {"scan": json.dumps(scan, ensure_ascii=False)}
    with patch.dict(os.environ, {"PITANGUS_IDENTITY_MODE": mode}):
        saved, _ = save_and_apply(data_dir, scan, quiet=True)
    out["stored run"] = json.dumps(load_run(data_dir, saved["id"]), ensure_ascii=False)
    out["stored report"] = artifact(data_dir, saved["id"], "report.md").decode()
    out["stored sarif"] = artifact(data_dir, saved["id"], "findings.sarif").decode()
    entries = registry.load(data_dir, key)["findings"]
    out["registry"] = json.dumps(entries, ensure_ascii=False)
    among = [entry["finding"] for entry in entries.values() if entry.get("finding")]
    for locale in ("en", "es"):
        # /api/findings/prompt: the registry's finding with its fix guide, as the route builds it
        out[f"api prompt {locale}"] = "\n".join(prompt(attach([dict(item)], among=among)[0], locale) for item in among)
        result = {"name": "org/api", "target": "org/api", "status": scan["status"], "comparison": None, "findings": scan["findings"],
                  "resolved": [], "gate": local.verdict(scan["findings"], "high"), "exit_code": 1, "excluded": {"patterns": [], "findings": 0},
                  "engines": {"ran": [], "failed": []}, "not_analyzed": [], "fail_on": "high", "scan": scan}
        out[f"cli prompt {locale}"] = local.render_prompt(result, locale=locale)
        out[f"cli json {locale}"] = local.render_json(result, locale=locale)
        out[f"cli sarif {locale}"] = local.render_sarif(result, locale=locale)
        out[f"cli text {locale}"] = local.render_text(result, locale=locale)
        out[f"cli markdown {locale}"] = local.render_markdown(result, locale=locale)
        out[f"report {locale}"] = render_repository_report(saved, locale=locale)
        out[f"sarif {locale}"] = json.dumps(render_repository_sarif(saved, locale=locale), ensure_ascii=False)
        out[f"profile {locale}"] = render_profile_report(saved, "soc2", locale=locale)
        tickets = render_tickets(saved, locale=locale)
        out[f"tickets {locale}"] = json.dumps(tickets, ensure_ascii=False, default=str)
        by_print = {item["fingerprint"]: item for item in saved["findings"]}
        issues = [jira_brief.brief([{"fingerprint": item["fingerprint"], "severity": item["severity"]}], by_print, asset=key,
                                   source=saved.get("source"), first_seen={}, days={}, panel_url="https://pitangus.local", locale=locale)
                  for item in saved["findings"]]
        out[f"jira {locale}"] = json.dumps(issues, ensure_ascii=False, default=str)
        message = notifications.findings_message(saved, saved["findings"], locale)
        out[f"notifications {locale}"] = json.dumps([notifications.render(kind, message, locale) for kind in ("slack", "teams", "webhook")],
                                                    ensure_ascii=False, default=str)
        out[f"technical pdf {locale}"] = _pdf_text(technical, saved, locale)
    return out


class NoSecretAnywhereTests(unittest.TestCase):
    """For every detected secret: neither its value nor its encodings in any field or output."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.examples = 0

    def check(self, kind: str, seed: int, encoding: str, construct: str, engine: str, mode: str):
        self.examples += 1
        secret = _secret(kind, seed)
        written = ENCODINGS["url"](secret) if construct == "dsn" else ENCODINGS[encoding](secret)
        path, line, pieces = _place(construct, written)
        lines = ["import os", "", line, "print('done')"]
        _, _, rule, cwe = CONSTRUCTS[construct]
        data_dir = Path(self.directory.name) / f"data-{self.examples}"
        root = data_dir / "snapshot"
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        key = f"github#{self.examples}"
        source = {"id": "github:org/api", "uid": key, "name": "org/api", "provider": "github"}
        from pitangus.modules.scanning.repository import scan_repository
        with _captured_logs() as logs:
            scan = scan_repository(root, source, data_dir=data_dir,
                                   replay=_engines(_reports(path, lines, 3, pieces[0], rule, cwe, engine)), feeds={"kev": {}, "epss": {}})
            self.assertTrue(any(item["scanner"] == "sast" for item in scan["findings"]), "the vulnerable construct is still found")
            outputs = _outputs(data_dir, scan, key, mode)
        outputs["logs"] = "\n".join(logs)
        # What has a fragment (value_oracle): a piece made only of symbols, common words and numbers of up to three
        # digits may stay (shared/render.py).
        forbidden = {item for item in (secret, written, *pieces) if len(item) >= 6 and fragments(item)}
        forbidden |= {variant for item in (secret, written) for variant in variants(item) if len(variant) >= 8 and fragments(variant)}
        for name, text in outputs.items():
            for value in forbidden:
                self.assertNotIn(value, text, f"{name}: {kind}/{encoding}/{construct}/{engine}")
            self.assertEqual(leaked(secret, text, numbers=8), [], f"{name}: {kind}/{encoding}/{construct}/{engine}")

    @settings(max_examples=40 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    @given(st.sampled_from(["github", "slack", "aws", "hex", "jwt", "password"]), st.integers(0, 2**32),
           st.sampled_from(sorted(ENCODINGS)), st.sampled_from(sorted(CONSTRUCTS)), st.sampled_from(["betterleaks", "trivy"]),
           st.sampled_from(["v1", "shadow", "v2"]))
    # The seeds of the validation: a PAT next to an eval, an AWS key on an SQL injection's line, a Slack token next to
    # verify=False, a Supabase service role key and a hard-coded Java password, a password inside SQL, a 28-character hex
    # in a curl header, a URL-encoded password in a DSN, a token split across two literals.
    @example("github", 1, "raw", "eval", "betterleaks", "v2")
    @example("password", 77, "raw", "split", "betterleaks", "v1")   # nightly: a piece `8?Es?8!` (a word and short numbers)
    @example("aws", 2, "raw", "sqli", "trivy", "v2")
    @example("slack", 3, "raw", "verify", "betterleaks", "shadow")
    @example("jwt", 4, "raw", "supabase", "betterleaks", "v2")
    @example("password", 5, "raw", "password", "trivy", "v1")
    @example("password", 6, "raw", "sql", "betterleaks", "v2")
    @example("hex", 28, "raw", "curl", "trivy", "v2")
    @example("password", 7, "url", "dsn", "betterleaks", "v2")
    @example("github", 8, "raw", "split", "betterleaks", "v2")
    @example("jwt", 100001, "base64", "sqli", "trivy", "v1")  # nightly: base64 of text reads as words in pieces
    @example("hex", 1, "raw", "sqli", "trivy", "v1")  # nightly: Trivy's mask after the `*` of a SELECT
    @example("aws", 244958782, "base64", "sqli", "trivy", "v1")
    def test_a_detected_secret_shows_nowhere(self, kind, seed, encoding, construct, engine, mode):
        self.check(kind, seed, encoding, construct, engine, mode)


class CredentialShapeTests(unittest.TestCase):
    """What looks like a credential is masked with no engine having fired."""

    @settings(max_examples=150 * SCALE, deadline=None)
    @given(st.sampled_from(["github", "slack", "aws", "hex", "jwt", "password"]), st.integers(0, 2**32),
           st.sampled_from(["password", "supabase", "curl", "dsn", "sql", "split"]))
    @example("hex", 28, "curl")
    @example("password", 7, "dsn")
    @example("password", 6, "sql")
    @example("password", 1270, "split")   # nightly: a piece of symbols and short letters (`!hR*2#`)
    def test_credential_shaped_literals_are_masked(self, kind, seed, construct):
        secret = _secret(kind, seed)
        written = quote(secret, safe="") if construct == "dsn" else secret
        if (kind == "password" or (kind == "hex" and len(secret) < 32)) and construct == "supabase":
            return  # a password or a short hex is a credential by where it is (a header, a credential's name), not by its shape
        _, line, pieces = _place(construct, written)
        masked = mask(line)
        for piece in {secret, written, *pieces} - {""}:
            # A piece made only of symbols, common words and short numbers may stay (shared/render.py): no fragment.
            self.assertEqual(leaked(piece, masked), [], line)
            if fragments(piece):
                self.assertNotIn(piece, masked, line)
        self.assertEqual(mask(masked), masked)  # idempotent

    @settings(max_examples=150 * SCALE, deadline=None)
    @given(st.sampled_from(["github", "slack", "aws", "jwt"]), st.integers(0, 2**32), st.sampled_from(["eval", "sqli", "verify"]))
    def test_provider_tokens_aws_keys_and_jwts_are_masked_wherever_they_are(self, kind, seed, construct):
        secret = _secret(kind, seed)
        _, line, _ = _place(construct, secret)
        self.assertNotIn(secret, mask(line))

    def test_words_and_references_stay_readable(self):
        # Free text keeps its common words and the structure of its URLs (a word that isn't common goes, in a URL too);
        # code its names made of common words.
        self.assertEqual(mask("See https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
                         "See https://***.owasp.org/***/Cross_Site_Scripting_Prevention_Cheat_Sheet.html")
        self.assertEqual(mask("The requested URL returned error: 403"), "The requested URL returned error: 403")
        self.assertEqual(mask_code("cursor.execute(sql, (user_id,))"), "cursor.execute(sql, (user_id,))")


    def test_masking_stays_fast_on_adversarial_text(self):
        import time
        for text in ("a" * 50_000, "token" * 10_000, "x-token-" * 6_000, "--token" * 7_000, "eyJ" * 15_000, "password '" * 5_000,
                     '"a" + ' * 8_000, "Authorization: " * 3_000, "AKIA" * 12_000):
            started = time.monotonic()
            mask(text)
            self.assertLess(time.monotonic() - started, 5, text[:20])


class IdentityTests(unittest.TestCase):
    """Masking changes no fingerprint and no identity: before and after, the same finding."""

    @settings(max_examples=100 * SCALE, deadline=None)
    @given(st.sampled_from(["github", "aws", "hex", "jwt", "password"]), st.integers(0, 2**32), st.sampled_from(sorted(CONSTRUCTS)))
    def test_the_same_finding_before_and_after_masking_has_the_same_fingerprint_and_identity(self, kind, seed, construct):
        path, line, pieces = _place(construct, _secret(kind, seed))
        _, _, rule, cwe = CONSTRUCTS[construct]
        report = {"results": [{"check_id": rule, "path": f"/src/{path}", "start": {"line": 3},
                               "extra": {"lines": line, "message": "m", "severity": "ERROR", "metadata": {"cwe": [cwe]}}}]}
        finding = parse_opengrep(report)[0]
        masked = sanitize_finding(finding, pieces)
        # A hard-coded credential keeps no snippet; any other finding keeps it masked.
        self.assertNotEqual(masked.get("snippet"), finding["snippet"])
        self.assertEqual("snippet" in masked, cwe not in NO_SNIPPET_CWES)
        self.assertEqual((masked["fingerprint"], canonical.identity_of(masked)), (finding["fingerprint"], canonical.identity_of(finding)))
        self.assertEqual(sanitize_finding(masked, pieces), masked)  # idempotent
        # A run masked before grouping into families groups exactly as the unmasked one.
        families = lambda items: sorted((item["fingerprint"], item["count"]) for item in canonical.collapse(items))  # noqa: E731
        self.assertEqual(families([masked, {**masked, "line": 9}]), families([finding, {**finding, "line": 9}]))

    def test_the_reason_never_carries_the_code(self):
        line = 'eval(x)  # ghp_' + "A1b2C3d4" * 5
        finding = parse_opengrep({"results": [{"check_id": "r", "path": "/src/a.py", "start": {"line": 1}, "extra": {"lines": line}}]})[0]
        from pitangus.shared.i18n import text
        self.assertNotIn("eval", text(finding["reason"], "en") + text(finding["reason"], "es"))
        legacy = {**finding, "reason": {"$t": "scanning.opengrep.reason", "params": {"snippet": line, "path": "a.py", "line": 1}}}
        self.assertNotIn("snippet", sanitize_finding(legacy)["reason"]["params"])


class StoredFindingsMigrationTests(unittest.TestCase):
    """The data migration masks what is already stored, and every finding keeps its identity."""

    def setUp(self):
        from pitangus.app import data_migrations as migrations
        from pitangus.shared import documents
        self.migrations = migrations
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name) / "data"
        self.data_dir.mkdir()
        position = [migration.name for migration in migrations.MIGRATIONS].index("mask_stored_secrets")
        documents.save(self.data_dir, migrations.VERSION_DOCUMENT, {"version": position, "history": []})

    def test_stored_runs_and_registry_are_masked_and_keep_their_identities(self):
        from pitangus.modules.runs.store import _persist, artifact, load_run, render_repository_report, render_repository_sarif
        token, password = "ghp_" + "Zq9" * 12, "Xk7#pq!2Lm"
        base = {"title": "A finding", "confidence": 8, "cwe": [], "owasp": ["A05:2025"], "cve": [], "ghsa": [], "verdict": "candidate",
                "priority": {"action": "attend", "factors": []}, "remediation": "Fix it.", "package": None, "advisory": None, "reason": "Why."}
        code = {**base, "fingerprint": "a" * 64, "finding_id": "a" * 16, "scanner": "sast", "tool": "opengrep", "rule_id": "appsec.python.eval",
                "path": "app.py", "line": 3, "severity": "high", "snippet": f'eval(q)  # {token}',
                "reason": {"$t": "scanning.opengrep.reason", "params": {"snippet": f'eval(q)  # {token}', "path": "app.py", "line": 3}}}
        beside = {**base, "fingerprint": "b" * 64, "finding_id": "b" * 16, "scanner": "sast", "tool": "opengrep", "rule_id": "appsec.python.sqli",
                  "path": "db.py", "line": 7, "severity": "high", "snippet": f"run('{password}' + q)", "reason": "r"}
        secret = {**base, "fingerprint": "c" * 64, "finding_id": "c" * 16, "scanner": "secrets", "tool": "betterleaks", "rule_id": "generic-api-key",
                  "path": "db.py", "line": 7, "severity": "critical"}
        dependency = {**base, "fingerprint": "d" * 64, "finding_id": "d" * 16, "scanner": "sca", "tool": "trivy", "rule_id": "CVE-2026-1", "path": "go.mod",
                      "line": 1, "severity": "low", "package": {"ecosystem": "gomod", "name": "x", "version": "1"},
                      "advisory": {"references": ["https://github.com/x/y/commit/" + "3f2a" * 10]}}
        excluded = {**code, "fingerprint": "e" * 64, "finding_id": "e" * 16, "path": "fixtures/app.py", "excluded_by": "fixtures/**"}
        stored = [code, beside, secret, dependency]
        before = {item["fingerprint"]: canonical.identity_of(item) for item in [*stored, excluded]}
        record = {"schema_version": "0.3.0", "id": "f" * 32, "created_at": datetime.now(timezone.utc).isoformat(), "type": "repository_scan",
                  "status": "completed", "target": "org/api", "source": {"id": "github:org/api", "uid": "github#1", "name": "org/api", "provider": "github"},
                  "findings": stored, "excluded_findings": [excluded], "steps": [], "owasp_coverage": [], "limitations": [], "context": "",
                  "summary": {"files": 3, "dependencies": 1, "candidates": 4, "severities": {}, "priorities": {}, "kev": 0, "fixable": 0, "tools": []}}
        _persist(self.data_dir, record, render_repository_report(record), render_repository_sarif(record))
        registry._save(self.data_dir, {"asset": "github#1", "name": "org/api", "applied": [], "findings": {
            item["fingerprint"]: {"status": "open", "finding": item} for item in stored}})

        self.assertIn("mask_stored_secrets", self.migrations.upgrade(self.data_dir))
        run = load_run(self.data_dir, "f" * 32)
        entries = registry.load(self.data_dir, "github#1")["findings"]
        texts = [json.dumps(run), json.dumps(entries), artifact(self.data_dir, "f" * 32, "report.md").decode(),
                 artifact(self.data_dir, "f" * 32, "findings.sarif").decode()]
        for text in texts:
            self.assertNotIn(token, text)
            self.assertNotIn(password, text)  # a literal on a line where a secret was detected
            self.assertIn("3f2a" * 10, json.dumps(entries))  # public references are left alone
        for item in [*run["findings"], *run["excluded_findings"], *(entry["finding"] for entry in entries.values())]:
            self.assertEqual(canonical.identity_of(item), before[item["fingerprint"]], item["fingerprint"])
        self.assertNotIn("snippet", run["findings"][0]["reason"]["params"])
        self.assertEqual(self.migrations._mask_stored_secrets(self.data_dir), 0)  # idempotent


if __name__ == "__main__":
    unittest.main()
