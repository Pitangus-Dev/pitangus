"""Security policies written as configuration no code engine reads: Supabase row level security in SQL migrations, and
Firebase security rules (Firestore, Storage, Realtime Database).

What a generated backend most often gets wrong is not its code but these files: a table created without row level
security is readable and writable by anyone holding the public anon key; a rules file left in test mode opens the
whole database. Opengrep doesn't parse either language, so a small reader of our own does, and declares what it read
like any engine (engine_contract.coverage): a file it couldn't read is unexamined, never clean.

Each file is read as its own tool reads it, never by a pattern over its text: semicolons, spacing, comments and the
order of blocks don't change what a rules file allows, so they don't change the findings either; and a Supabase
project is its own folder, so one app of a monorepo never answers for another.
"""

from __future__ import annotations

import bisect
import json
import re
import time
import tomllib
from pathlib import Path, PurePosixPath

from pitangus.version import VERSION
from pitangus.modules.scanning import engine_contract
from pitangus.modules.scanning.engines import _stable
from pitangus.shared.i18n import msg
from pitangus.shared.model import EngineResult, Finding

TOOL = "policies"
FILE_MAX = 2_000_000
FILES_MAX = 2_000
STATEMENT_MAX = 400   # characters of a statement its identity reads (never stored)

# --- SQL (Supabase migrations) ---------------------------------------------------------------------------------------

IDENTIFIER = r'(?:"[^"]+"|[A-Za-z_][A-Za-z0-9_$]*)'
QUALIFIED = rf"(?:(?P<schema>{IDENTIFIER})\s*\.\s*)?(?P<table>{IDENTIFIER})"
CREATE = re.compile(rf"^create\s+(?:(?:global\s+|local\s+)?(?:temporary|temp|unlogged)\s+)?table\s+(?:if\s+not\s+exists\s+)?{QUALIFIED}", re.I)
ALTER_RLS = re.compile(rf"^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?{QUALIFIED}\s+(?P<action>enable|disable)\s+row\s+level\s+security", re.I)
DROP = re.compile(rf"^drop\s+table\s+(?:if\s+exists\s+)?{QUALIFIED}", re.I)
TEMPORARY = re.compile(r"^create\s+(?:(?:global|local)\s+)?(?:temporary|temp)\b", re.I)
DEFAULT_SCHEMA = "public"   # where an unqualified name lands (Supabase's search_path)
EXPOSED_SCHEMAS = frozenset({"public", "graphql_public"})   # what Supabase's API serves unless the project's config.toml says


def _name(value: str | None) -> str:
    text = (value or "").strip()
    return text[1:-1] if text.startswith('"') and text.endswith('"') else text.lower()


def sql_statements(text: str) -> list[tuple[int, str]]:
    """The statements of a SQL file with their first line: comments, string literals and dollar-quoted bodies (a
    function's code) left out, so a `;` or a keyword inside them is never taken for SQL."""
    statements, current, line, start_line, index = [], [], 1, 1, 0
    while index < len(text):
        character = text[index]
        if text.startswith("--", index):
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            chunk = text[index:len(text) if end < 0 else end + 2]
            line += chunk.count("\n")
            index += len(chunk)
            current.append(" ")
            continue
        dollar = re.match(r"\$[A-Za-z0-9_]*\$", text[index:index + 64])
        if dollar:
            tag = dollar.group(0)
            end = text.find(tag, index + len(tag))
            chunk = text[index:len(text) if end < 0 else end + len(tag)]
            line += chunk.count("\n")
            index += len(chunk)
            current.append(" $body$ ")
            continue
        if character == "'":
            end = index + 1
            while end < len(text) and not (text[end] == "'" and text[end + 1:end + 2] != "'"):
                end += 2 if text[end] == "'" else 1
            chunk = text[index:end + 1]
            line += chunk.count("\n")
            index = end + 1
            current.append("''")
            continue
        if character == ";":
            statement = " ".join("".join(current).split())
            if statement:
                statements.append((start_line, statement))
            current, index = [], index + 1
            continue
        if character == "\n":
            line += 1
        if not current or not "".join(current).strip():
            start_line = line
        current.append(character)
        index += 1
    statement = " ".join("".join(current).split())
    if statement:
        statements.append((start_line, statement))
    return statements


def supabase_project(relative: str) -> str | None:
    """The Supabase project a file belongs to: its folder up to the innermost `supabase` directory (a monorepo has one
    per app). None outside any."""
    parts = PurePosixPath(relative).parts[:-1]
    return next(("/".join(parts[:index + 1]) for index in range(len(parts) - 1, -1, -1) if parts[index].lower() == "supabase"), None)


def exposed_schemas(root: Path, project: str, unexamined: dict[str, str]) -> frozenset[str]:
    """The schemas the project's API serves: `[api] schemas` in its config.toml, Supabase's default without one."""
    path = root / project / "config.toml"
    if not path.is_file() or path.is_symlink():
        return EXPOSED_SCHEMAS
    relative = f"{project}/config.toml"
    text = _read(path, relative, unexamined)
    if text is None:
        return EXPOSED_SCHEMAS
    try:
        schemas = (tomllib.loads(text).get("api") or {}).get("schemas")
    except (tomllib.TOMLDecodeError, AttributeError):
        unexamined[relative] = "parse_error"
        return EXPOSED_SCHEMAS
    if not isinstance(schemas, list) or not all(isinstance(schema, str) for schema in schemas):
        return EXPOSED_SCHEMAS
    return frozenset(schemas)


def supabase_findings(root: Path, files: list[Path], unexamined: dict[str, str]) -> tuple[list[Finding], list[str]]:
    """Tables each Supabase project's migrations create in a schema its API serves and leave without row level
    security, read in migration order: enabling it in a later migration or another file of the same project counts,
    disabling it again undoes that, dropping the table ends it. A table is its project, schema and name: the same name
    in another project, or in another schema, is another table."""
    projects: dict[str, list[Path]] = {}
    for path in files:
        if path.suffix.lower() == ".sql" and (project := supabase_project(path.relative_to(root).as_posix())) is not None:
            projects.setdefault(project, []).append(path)
    findings, examined = [], []
    for project, paths in sorted(projects.items()):
        exposed = exposed_schemas(root, project, unexamined)
        created: dict[tuple[str, str], tuple[str, int, str]] = {}
        protected: set[tuple[str, str]] = set()
        for path in sorted(paths):
            relative = path.relative_to(root).as_posix()
            text = _read(path, relative, unexamined)
            if text is None:
                continue
            examined.append(relative)
            for line, statement in sql_statements(text):
                if (match := CREATE.match(statement)) and not TEMPORARY.match(statement):
                    created[_table(match)] = (relative, line, statement[:STATEMENT_MAX])
                elif match := ALTER_RLS.match(statement):
                    (protected.add if match.group("action").lower() == "enable" else protected.discard)(_table(match))
                elif match := DROP.match(statement):
                    created.pop(_table(match), None)
                    protected.discard(_table(match))
        findings += [_rls_finding(schema, table, *where) for (schema, table), where in sorted(created.items())
                     if (schema, table) not in protected and schema in exposed]
    return findings, examined


def _table(match: re.Match) -> tuple[str, str]:
    return _name(match.group("schema")) or DEFAULT_SCHEMA, _name(match.group("table"))


def _rls_finding(schema: str, table: str, path: str, line: int, statement: str) -> Finding:
    if schema == DEFAULT_SCHEMA:
        title, reason, fix = (msg("scanning.policies.rls.title", table=table), msg("scanning.policies.rls.reason", table=table, path=path),
                              msg("scanning.policies.rls.fix", table=table))
    else:
        title = msg("scanning.policies.rls.title", table=f"{schema}.{table}")
        reason = msg("scanning.policies.rls.reason_schema", table=table, schema=schema, path=path)
        fix = msg("scanning.policies.rls.fix_schema", table=table, schema=schema)
    return _finding("pitangus.supabase.table-without-rls", path, line, statement, f"{schema}.{table}", "high", [284], title, reason, fix)


# --- Firebase security rules ---------------------------------------------------------------------------------------

SERVICE = re.compile(r"\bservice\s+(cloud\.firestore|firebase\.storage)\b")
LEXEME = re.compile(r"""//[^\n]*|/\*.*?(?:\*/|\Z)|'(?:[^'\\\n]|\\.)*'?|"(?:[^"\\\n]|\\.)*"?""", re.S)
WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
OPERATIONS = re.compile(r"\s*([A-Za-z]+(?:\s*,\s*[A-Za-z]+)*)")
KEYWORD = re.compile(r"(?<![\w.])(?:allow|match|function)\b")   # what starts the next statement
FUNCTION = re.compile(r"\s*([A-Za-z_]\w*)\s*\(\s*\)\s*$")
RETURN = re.compile(r"\s*return\s+(.+?)\s*;?\s*$", re.S)
CALL = re.compile(r"([A-Za-z_]\w*)\(\)")
TEST_MODE = re.compile(r"request\.time<timestamp\.date\([^()]*\)")
SIGNED_IN = re.compile(r"request\.auth(?:\.uid)?!=null|null!=request\.auth(?:\.uid)?")
WILDCARD = re.compile(r"\{[A-Za-z_]\w*=\*\*\}")


def _blank(text: str) -> str:
    return re.sub(r"[^\n]", " ", text)


def _lexed(text: str) -> tuple[str, str]:
    """The file with its comments blanked (line breaks kept, so offsets keep their line), and the same with every string
    literal blanked too: the second is what the structure is read from, so no brace, semicolon or keyword inside a
    comment or a string is ever taken for one."""
    code = LEXEME.sub(lambda found: _blank(found.group(0)) if found.group(0)[0] == "/" else found.group(0), text)
    structure = LEXEME.sub(lambda found: _blank(found.group(0)) if found.group(0)[0] == "/" else re.sub(r"[^\n]", "_", found.group(0)), text)
    return code, structure


def _closing(structure: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(structure)):
        depth += {"{": 1, "}": -1}.get(structure[index], 0)
        if depth == 0:
            return index
    return None


def _expression_end(structure: str, start: int) -> int:
    """Where a condition ends: its `;`, the `}` closing its block, or the next statement when the `;` is missing (the
    rules compiler accepts that)."""
    depth, index = 0, start
    while index < len(structure):
        character = structure[index]
        if character in "([{":
            depth += 1
        elif character in ")]}":
            if depth == 0:
                return index
            depth -= 1
        elif depth == 0 and (character == ";" or (character.isalpha() and KEYWORD.match(structure, index))):
            return index
        index += 1
    return index


def _match_path(structure: str, start: int) -> tuple[int, int | None]:
    """The end of a `match` path (its `{var}` and `{var=**}` segments included) and the brace opening its block."""
    index = start
    while index < len(structure):
        character = structure[index]
        if character == "{" and index > start and structure[index - 1] == "/":
            closing = structure.find("}", index)
            if closing < 0:
                return index, None
            index = closing + 1
            continue
        if character == "{" or character.isspace() or character in ";}":
            break
        index += 1
    brace = index
    while brace < len(structure) and structure[brace].isspace():
        brace += 1
    return index, brace if brace < len(structure) and structure[brace] == "{" else None


def firebase_rules(text: str) -> tuple[list[dict], dict[str, str]] | None:
    """The `allow` statements of a Firestore or Storage rules file, each with its service, match path, operations,
    condition and line, and the file's argument-less functions (name → returned expression). None when its blocks
    don't balance: the rules compiler rejects such a file, so what it allows can't be told."""
    code, structure = _lexed(text)
    newlines = [index for index, character in enumerate(code) if character == "\n"]
    allows: list[dict] = []
    functions: dict[str, str] = {}
    stack: list[tuple[str, str]] = []
    index = 0
    while index < len(structure):
        character = structure[index]
        if character.isspace() or character == ";":
            index += 1
        elif character == "}":
            if not stack:
                return None
            stack.pop()
            index += 1
        elif not (word := WORD.match(structure, index)):
            index += 1
        elif word.group(0) == "service" or word.group(0) == "match":
            start = word.end()
            while start < len(structure) and structure[start].isspace():
                start += 1
            if word.group(0) == "service":
                opening = structure.find("{", start)
                if opening < 0:
                    return None
                stack.append(("service", " ".join(code[start:opening].split())))
            else:
                end, brace = _match_path(structure, start)
                if brace is None:
                    return None
                stack.append(("match", code[start:end]))
                opening = brace
            index = opening + 1
        elif word.group(0) == "function":
            opening = structure.find("{", word.end())
            closing = _closing(structure, opening) if opening >= 0 else None
            if closing is None:
                return None
            header, body = FUNCTION.match(code[word.end():opening]), RETURN.match(code[opening + 1:closing])
            if header and body:
                functions[header.group(1)] = body.group(1)
            index = closing + 1
        elif word.group(0) == "allow":
            listed = OPERATIONS.match(structure, word.end())
            index = listed.end() if listed else word.end()
            while index < len(structure) and structure[index].isspace():
                index += 1
            condition = ""
            if index < len(structure) and structure[index] == ":":
                start = index + 1
                if (keyword := re.compile(r"\s*if\b").match(structure, start)) is not None:
                    start = keyword.end()
                index = _expression_end(structure, start)
                condition = " ".join(code[start:index].split())
            service = next((name for kind, name in reversed(stack) if kind == "service"), "")
            allows.append({"service": service, "where": "".join(name for kind, name in stack if kind == "match"),
                           "operations": [part.strip() for part in (listed.group(1) if listed else "").split(",") if part.strip()],
                           "condition": condition, "line": bisect.bisect_left(newlines, word.start()) + 1})
        else:
            index = word.end()   # rules_version and anything else outside a statement
    return (allows, functions) if not stack else None


def _bare(condition: str) -> str:
    """A condition without spaces or the parentheses wrapping all of it: `( request.auth != null )` is
    `request.auth!=null`."""
    value = re.sub(r"\s+", "", condition)
    while value.startswith("(") and value.endswith(")") and _wraps(value):
        value = value[1:-1]
    return value


def _wraps(value: str) -> bool:
    depth = 0
    for index, character in enumerate(value):
        depth += {"(": 1, ")": -1}.get(character, 0)
        if depth == 0:
            return index == len(value) - 1
    return False


def _resolved(condition: str, functions: dict[str, str]) -> str:
    """The condition with a call to one of the file's argument-less functions (`isSignedIn()`) replaced by what it
    returns, as the rules engine evaluates it."""
    value = _bare(condition)
    for _ in range(8):
        call = CALL.fullmatch(value)
        if not call or call.group(1) not in functions:
            break
        value = _bare(functions[call.group(1)])
    return value


def firebase_rule_findings(relative: str, text: str) -> list[Finding] | None:
    """`allow` statements of a Firestore or Storage rules file that let anyone in: no condition or `if true` (open),
    only an expiry date (the console's test mode) or, on every document under a recursive wildcard, only being signed
    in. None when the file can't be read as rules (unbalanced blocks)."""
    parsed = firebase_rules(text)
    if parsed is None:
        return None
    allows, functions = parsed
    found: dict[str, Finding] = {}
    for allow in allows:
        condition = _resolved(allow["condition"], functions)
        where, operations = allow["where"] or "/", ",".join(allow["operations"])
        if not condition or condition == "true":
            kind, severity = "open", "critical"
        elif TEST_MODE.fullmatch(condition):
            kind, severity = "test-mode", "high"
        elif SIGNED_IN.fullmatch(condition) and WILDCARD.search(where):
            kind, severity = "any-signed-in", "medium"
        else:
            continue
        product = "storage" if allow["service"] == "firebase.storage" else "firestore"
        statement = f"allow {', '.join(allow['operations'])}" + (f": if {allow['condition']}" if allow["condition"] else "") + ";"
        finding = _finding(f"pitangus.firebase.{kind}", relative, allow["line"], statement, f"{product}:{where}:{operations}", severity, [284, 862],
                           msg(f"scanning.policies.firebase.{kind}.title", product=msg(f"scanning.policies.product.{product}")),
                           msg(f"scanning.policies.firebase.{kind}.reason", operations=operations, path=where, file=relative),
                           msg(f"scanning.policies.firebase.{kind}.fix"))
        # Two statements granting the same thing are one finding, whichever comes first in the file.
        kept = found.get(finding["fingerprint"])
        if kept is None or (finding["snippet"], finding["line"]) < (kept["snippet"], kept["line"]):
            found[finding["fingerprint"]] = finding
    return sorted(found.values(), key=lambda item: (item["line"], item["rule_id"], item["resource"]))


JSON_TOKEN = re.compile(r'"(?:[^"\\\n]|\\.)*"|//[^\n]*|/\*.*?(?:\*/|\Z)', re.S)
TRAILING_COMMA = re.compile(r'"(?:[^"\\\n]|\\.)*"|,(?=\s*[}\]])')
AFTER_KEY = re.compile(r"\s*:")
RTDB_SIGNED_IN = re.compile(r"auth(?:\.uid)?!==?null|null!==?auth(?:\.uid)?")
RTDB_TEST_MODE = re.compile(r"now<\d+")


class _Members(list):
    """An object's members in order, duplicates included, so each key keeps its place in the file."""


def realtime_rules(text: str) -> tuple[object, list[int]] | None:
    """Realtime Database rules as Firebase reads them: JSON that may carry `//` and `/* */` comments and trailing
    commas. Returns the document (objects as `_Members`) and the line of every key in document order; None when it
    still isn't JSON."""
    keys: list[int] = []

    def token(found: re.Match) -> str:
        value = found.group(0)
        if value[0] == '"':
            if AFTER_KEY.match(text, found.end()):
                keys.append(found.start())
            return value
        return _blank(value)

    clean = TRAILING_COMMA.sub(lambda found: found.group(0) if found.group(0)[0] == '"' else " ", JSON_TOKEN.sub(token, text))
    try:
        document = json.loads(clean, object_pairs_hook=_Members)
    except (ValueError, RecursionError):
        return None
    newlines = [index for index, character in enumerate(text) if character == "\n"]
    return document, [bisect.bisect_left(newlines, offset) + 1 for offset in keys]


def realtime_rule_findings(relative: str, text: str) -> list[Finding] | None:
    """`.read` or `.write` in Realtime Database rules set to true (that part of the database is open to anyone), to
    only a date (test mode), or at the root to only being signed in. None when the file isn't readable as rules."""
    parsed = realtime_rules(text)
    if parsed is None:
        return None
    document, lines = parsed
    findings: list[Finding] = []
    cursor = iter(lines)

    def walk(node, path: list[str]) -> None:
        if isinstance(node, _Members):
            last = {key: index for index, (key, _) in enumerate(node)}   # a repeated key: the last one counts, as in JSON
            for index, (key, value) in enumerate(node):
                line = next(cursor, 1)
                if last[key] == index and path[:1] == ["rules"] and key in (".read", ".write") and len(findings) <= 200:
                    _realtime_rule(relative, "/" + "/".join(path[1:]), key, value, line, findings)
                walk(value, [*path, key])
        elif isinstance(node, list):
            for item in node:
                walk(item, path)

    walk(document, [])
    return findings


def _realtime_rule(relative: str, where: str, key: str, value, line: int, findings: list[Finding]) -> None:
    rule = re.sub(r"\s+", "", value) if isinstance(value, str) else value
    if rule is True or rule == "true":
        kind, severity = "open", "critical"
    elif isinstance(rule, str) and RTDB_TEST_MODE.fullmatch(rule):
        kind, severity = "test-mode", "high"
    elif isinstance(rule, str) and RTDB_SIGNED_IN.fullmatch(rule) and where == "/":
        kind, severity = "any-signed-in", "medium"
    else:
        return
    operation = key[1:]
    findings.append(_finding(f"pitangus.firebase.{kind}", relative, line, f'"{key}": {json.dumps(value)}', f"database:{where}:{operation}", severity,
                             [284, 862], msg(f"scanning.policies.firebase.{kind}.title", product=msg("scanning.policies.product.database")),
                             msg(f"scanning.policies.firebase.{kind}.reason_database", operations=operation, path=where, file=relative),
                             msg(f"scanning.policies.firebase.{kind}.fix_database")))


# --- the engine -----------------------------------------------------------------------------------------------------

def _read(path: Path, relative: str, unexamined: dict[str, str]) -> str | None:
    try:
        if path.stat().st_size > FILE_MAX:
            unexamined[relative] = "too_large"
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        unexamined[relative] = "unreadable"
        return None


def _finding(rule: str, path: str, line: int, statement: str, resource: str, severity: str, cwe: list[int], title, reason, fix) -> Finding:
    digest = _stable("policies", rule, path, resource)
    return {"finding_id": digest[:16], "fingerprint": digest, "scanner": "iac", "tool": TOOL, "rule_id": rule, "title": title, "path": path,
            "line": line, "severity": severity, "confidence": 8, "verdict": "candidate", "cwe": cwe, "owasp": ["A01:2025"], "cve": [], "ghsa": [],
            "package": None, "advisory": None, "kev": None, "epss": None, "snippet": statement[:STATEMENT_MAX], "resource": resource,
            "priority": {"action": "act" if severity == "critical" else "attend", "factors": [msg("scanning.policies.factor")]},
            "reason": reason, "remediation": fix}


def run_policies(root: Path) -> EngineResult:
    """Every policy file of the snapshot, read; what it couldn't read is unexamined."""
    started = time.time()
    files = sorted(path for path in root.rglob("*") if path.is_file() and not path.is_symlink())[:FILES_MAX * 50]
    unexamined: dict[str, str] = {}
    findings, examined = supabase_findings(root, files, unexamined)
    for path in files:
        relative, name = path.relative_to(root).as_posix(), path.name.lower()
        if name.endswith(".rules.json"):
            text = _read(path, relative, unexamined)
            found = realtime_rule_findings(relative, text) if text is not None else None
        elif name.endswith(".rules"):
            text = _read(path, relative, unexamined)
            if text is None or not SERVICE.search(_lexed(text)[1]):
                continue
            found = firebase_rule_findings(relative, text)
        else:
            continue
        if text is None:
            continue
        if found is None:
            unexamined[relative] = "parse_error"
            continue
        examined.append(relative)
        findings += found
    detail = msg("scanning.policies.detail", files=len(examined), findings=len(findings)) if examined else msg("scanning.policies.none")
    # It reads every policy file the snapshot has: one it couldn't read is unexamined; one that's gone holds nothing.
    return {"tool": TOOL, "name": "Pitangus", "version": VERSION, "image": None, "status": "completed",
            "detail": detail, "findings": findings, "duration_s": round(time.time() - started, 1),
            "coverage": engine_contract.coverage("*", unexamined)}
