"""Access policies a generated backend gets wrong: Supabase tables without row level security, Firebase rules left open."""

import json
import os
import random
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hypothesis import HealthCheck, given, settings, strategies as st

from pitangus.modules.findings.canonical import identity_of
from pitangus.modules.scanning import policies

# The profiles of tests/test_invariants.py: the same examples on every run, many more and new ones every night.
PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1
PROPERTY = settings(max_examples=60 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow])


def snapshot(folder: str, files: dict[str, str]) -> Path:
    root = Path(folder) / "snapshot"
    for name, content in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(content)
    return root


class SupabaseTests(unittest.TestCase):
    def run_on(self, files):
        with tempfile.TemporaryDirectory() as folder:
            return policies.run_policies(snapshot(folder, files))

    def test_a_table_without_rls_in_any_migration_is_a_finding_at_its_create(self):
        result = self.run_on({
            "supabase/migrations/001_init.sql": "-- create table fake_comment (x int);\ncreate table public.profiles (id uuid primary key);\n"
                                                "create table if not exists \"Orders\" (id bigint);\ncreate table private.audit (id int);\n"
                                                "create temporary table scratch (x int);\n"
                                                "create function f() returns void as $$ create table inside_function (x int); $$ language sql;\n",
            "supabase/migrations/002_rls.sql": "alter table public.profiles enable row level security;\n",
        })
        self.assertEqual([(item["resource"], item["path"], item["line"]) for item in result["findings"]],
                         [("public.Orders", "supabase/migrations/001_init.sql", 3)])
        self.assertEqual(result["coverage"], {"examined": "*", "unexamined": {}})

    def test_rls_disabled_again_or_the_table_dropped_counts(self):
        result = self.run_on({
            "supabase/migrations/001.sql": "create table notes (id int); alter table notes enable row level security; create table tmp (id int);",
            "supabase/migrations/002.sql": "alter table only public.notes disable row level security; drop table if exists tmp;",
        })
        self.assertEqual([item["resource"] for item in result["findings"]], ["public.notes"])

    def test_sql_outside_a_supabase_project_is_not_read_as_one(self):
        self.assertEqual(self.run_on({"db/schema.sql": "create table users (id int);"})["findings"], [])

    def test_the_identity_is_the_table_never_the_line(self):
        first = self.run_on({"supabase/migrations/001.sql": "create table orders (id int);"})["findings"][0]
        moved = self.run_on({"supabase/migrations/001.sql": "\n\n-- orders\ncreate table orders (\n  id int\n);"})["findings"][0]
        self.assertEqual(identity_of(first), identity_of(moved))


class FirebaseTests(unittest.TestCase):
    def rules(self, text, name="firestore.rules"):
        with tempfile.TemporaryDirectory() as folder:
            return policies.run_policies(snapshot(folder, {name: text}))["findings"]

    def test_open_test_mode_and_any_signed_in_user_on_everything(self):
        found = self.rules("""rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /public/{doc} {
      allow read;
    }
    match /{document=**} {
      // allow read, write: if true;
      allow read, write: if request.time < timestamp.date(2026, 1, 1);
    }
    match /chats/{chat=**} {
      allow write: if request.auth != null;
    }
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}""")
        self.assertEqual([(item["rule_id"].rsplit(".", 1)[1], item["line"], item["severity"]) for item in found],
                         [("open", 5, "critical"), ("test-mode", 9, "high"), ("any-signed-in", 12, "medium")])
        self.assertIn("/databases/{database}/documents/public/{doc}", found[0]["resource"])

    def test_storage_rules_and_realtime_database_rules(self):
        storage = self.rules("service firebase.storage {\n  match /b/{bucket}/o {\n    match /{allPaths=**} {\n      allow read, write: if true;\n    }\n  }\n}",
                             name="storage.rules")
        self.assertEqual([item["resource"].split(":")[0] for item in storage], ["storage"])
        database = self.rules(json.dumps({"rules": {".read": True, "users": {"$uid": {".write": "$uid === auth.uid"}}, "logs": {".write": "true"}}}, indent=2),
                              name="database.rules.json")
        self.assertEqual(sorted(item["resource"] for item in database), ["database:/:read", "database:/logs:write"])

    def test_a_file_it_cannot_read_is_unexamined_never_clean(self):
        with tempfile.TemporaryDirectory() as folder:
            root = snapshot(folder, {"firestore.rules": "service cloud.firestore {}"})
            (root / "firestore.rules").write_bytes(b"\xff\xfe service cloud.firestore { allow read; }")
            result = policies.run_policies(root)
        self.assertEqual(result["coverage"]["unexamined"], {"firestore.rules": "unreadable"})



def run(files: dict[str, str | bytes]) -> dict:
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder) / "snapshot"
        for name, content in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_bytes(content if isinstance(content, bytes) else content.encode())
        return policies.run_policies(root)


def found(result: dict, prefix: str = "") -> set[tuple]:
    """What a run found, as identity and classification (never the line, which formatting moves), for the files under
    `prefix`, with the prefix taken off."""
    return {(item["rule_id"], item["resource"], item["severity"], item["path"].removeprefix(prefix), re.sub(r"\s+", "", item["snippet"]))
            for item in result["findings"] if item["path"].startswith(prefix)}


class SeedTests(unittest.TestCase):
    """The independent validation's reproductions (validation-val14/_repro), each one a case of a property below."""

    def test_rls_enabled_in_one_app_of_a_monorepo_never_covers_another(self):
        result = run({"a/supabase/migrations/20240101_init.sql": "create table public.profiles (id uuid primary key, name text);\n"
                                                                 "alter table public.profiles enable row level security;\n",
                      "b/supabase/migrations/20240101_init.sql": "create table profiles (id uuid primary key, secret text);\n"})
        self.assertEqual([(item["path"], item["resource"]) for item in result["findings"]],
                         [("b/supabase/migrations/20240101_init.sql", "public.profiles")])

    def test_a_table_is_its_schema_and_rls_counts_from_any_file_of_its_project(self):
        result = run({"apps/api/supabase/config.toml": '[api]\nschemas = ["public", "api"]\n',
                      "apps/api/supabase/migrations/001.sql": 'create table api.items (id int); create table "api"."Audit" (id int);\n'
                                                              "create table private.secrets (id int); create table items (id int);",
                      "apps/api/supabase/migrations/002.sql": "alter table public.items enable row level security;",
                      "apps/api/supabase/schemas/zz.sql": 'alter table only "api"."Audit" enable row level security;'})
        self.assertEqual([item["resource"] for item in result["findings"]], ["api.items"])
        self.assertEqual(result["findings"][0]["title"]["params"], {"table": "api.items"})

    def test_realtime_rules_with_comments_are_read_as_firebase_reads_them(self):
        result = run({"database.rules.json": '{\n  // test mode: open to everyone\n  "rules": {\n    ".read": true,\n    ".write": true,\n  }\n}\n'})
        self.assertEqual([(item["resource"], item["line"]) for item in result["findings"]], [("database:/:read", 4), ("database:/:write", 5)])
        signed_in = run({"database.rules.json": '{"rules":{".read":true,".write":"auth != null"}}'})["findings"]
        self.assertEqual([(item["rule_id"], item["resource"]) for item in signed_in],
                         [("pitangus.firebase.open", "database:/:read"), ("pitangus.firebase.any-signed-in", "database:/:write")])

    def test_the_line_of_a_realtime_rule_is_its_own(self):
        text = '{"rules": {\n  "users": {\n    ".read": "auth != null"\n  },\n  "logs": {\n    ".read": false,\n    ".write": true\n  }\n}}'
        self.assertEqual([(item["resource"], item["line"]) for item in run({"database.rules.json": text})["findings"]], [("database:/logs:write", 7)])

    def test_a_realtime_rules_file_that_isnt_json_is_unexamined_never_clean(self):
        result = run({"database.rules.json": '{"rules": {".read": true,, }'})
        self.assertEqual((result["findings"], result["coverage"]["unexamined"]), ([], {"database.rules.json": "parse_error"}))

    def test_rules_without_semicolons_any_signed_in_user_and_helper_functions(self):
        storage = run({"storage.rules": "rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /{allPaths=**} {\n"
                                        "      allow read, write: if request.auth.uid != null;\n    }\n  }\n}\n"})["findings"]
        self.assertEqual([(item["rule_id"], item["line"]) for item in storage], [("pitangus.firebase.any-signed-in", 5)])
        firestore = run({"firestore.rules": "service cloud.firestore {\n  function isSignedIn() { return request.auth != null; }\n"
                                            "  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read: if isSignedIn()\n"
                                            "      allow write: if true\n    }\n  }\n}"})["findings"]
        self.assertEqual([(item["rule_id"], item["snippet"]) for item in firestore],
                         [("pitangus.firebase.any-signed-in", "allow read: if isSignedIn();"), ("pitangus.firebase.open", "allow write: if true;")])

    def test_a_rules_file_whose_blocks_dont_balance_is_unexamined_never_clean(self):
        result = run({"firestore.rules": "service cloud.firestore {\n  match /{document=**} {\n    allow read: if true;\n"})
        self.assertEqual((result["findings"], result["coverage"]["unexamined"]), ([], {"firestore.rules": "parse_error"}))


# --- Firebase rules: formatting never changes what a file allows ------------------------------------------------------

SEGMENTS = ["/users/{userId}", "/public/{doc}", "/{document=**}", "/chats/{chat=**}", "/b/{bucket}/o", "/{allPaths=**}",
            "/posts/{postId}/comments/{commentId}"]
CONDITIONS = {None: None, "true": ["true"], "test": ["request.time", "<", "timestamp.date(2030,", "1,", "1)"],
              "auth": ["request.auth", "!=", "null"], "uid": ["request.auth.uid", "!=", "null"], "paren": ["(", "request.auth", "!=", "null", ")"],
              "owner": ["request.auth.uid", "==", "userId"], "fn": ["isSignedIn()"], "fn-owner": ["isOwner()"],
              "and": ["request.auth", "!=", "null", "&&", "request.auth.uid", "==", "userId"]}
EXPECTED = {None: "open", "true": "open", "test": "test-mode", "auth": "any-signed-in", "uid": "any-signed-in", "paren": "any-signed-in",
            "fn": "any-signed-in"}
FUNCTIONS = {"isSignedIn": ["request.auth", "!=", "null"], "isOwner": ["request.auth.uid", "==", "resource.data.owner"]}
SEVERITY = {"open": "critical", "test-mode": "high", "any-signed-in": "medium"}

allows = st.tuples(st.lists(st.sampled_from(["read", "write", "get", "list", "create", "update", "delete"]), min_size=1, max_size=3, unique=True),
                   st.sampled_from(sorted(CONDITIONS, key=str)))
blocks = st.recursive(
    st.fixed_dictionaries({"path": st.sampled_from(SEGMENTS), "allows": st.lists(allows, max_size=3), "children": st.just([])}),
    lambda children: st.fixed_dictionaries({"path": st.sampled_from(SEGMENTS), "allows": st.lists(allows, max_size=3),
                                            "children": st.lists(children, max_size=3)}),
    max_leaves=8)
rules_files = st.tuples(st.sampled_from(["cloud.firestore", "firebase.storage"]), st.lists(blocks, min_size=1, max_size=3))


def render_rules(service: str, tree: list[dict], rnd: random.Random | None) -> str:
    """A rules file for `tree`: canonical without `rnd`; with it, the same rules with random spacing and line breaks,
    comments holding braces, semicolons and keywords, the optional `;` dropped or kept, and sibling blocks and
    statements reordered."""
    def gap() -> str:
        if rnd is None:
            return " "
        space = rnd.choice([" ", "  ", "\n", "\t", "\n    "])
        return space + rnd.choice(["", "", "/* } allow read; { */ ", "// match /x { allow write: if true; }\n"])

    def end() -> str:
        return ";" if rnd is None or rnd.random() < 0.5 else ""

    def statement(operations, condition) -> str:
        text = "allow" + gap() + ("," + gap()).join(operations)
        if CONDITIONS[condition]:
            text += gap() + ":" + gap() + "if" + gap() + gap().join(CONDITIONS[condition])
        return text + end() + gap()

    def block(node) -> str:
        items = [statement(*allow) for allow in node["allows"]] + [block(child) for child in node["children"]]
        if rnd is not None:
            rnd.shuffle(items)
        return "match" + gap() + node["path"] + gap() + "{" + gap() + "".join(items) + "}" + gap()

    functions = ["function" + gap() + f"{name}()" + gap() + "{" + gap() + "return" + gap() + gap().join(body) + ";" + gap() + "}" + gap()
                 for name, body in FUNCTIONS.items()]
    items = functions + [block(node) for node in tree]
    if rnd is not None:
        rnd.shuffle(items)
    return "rules_version = '2';" + gap() + "service" + gap() + service + gap() + "{" + gap() + "".join(items) + "}" + gap()


def expected_rules(service: str, tree: list[dict]) -> set[tuple]:
    """What the rules in `tree` let anyone (or any signed-in user) do, from the rules themselves."""
    product, expected = "storage" if service == "firebase.storage" else "firestore", set()

    def visit(node, where: str) -> None:
        where += node["path"]
        for operations, condition in node["allows"]:
            kind = EXPECTED.get(condition)
            if kind == "any-signed-in" and not policies.WILDCARD.search(where):
                kind = None
            if kind:
                expected.add((f"pitangus.firebase.{kind}", f"{product}:{where}:{','.join(operations)}", SEVERITY[kind]))
        for child in node["children"]:
            visit(child, where)

    for node in tree:
        visit(node, "")
    return expected


class FirebaseRulesProperties(unittest.TestCase):
    @PROPERTY
    @given(rules_files, st.randoms(use_true_random=False))
    def test_spacing_comments_semicolons_and_block_order_never_change_the_findings(self, rules, rnd):
        service, tree = rules
        canonical = run({"firestore.rules": render_rules(service, tree, None)})
        varied = run({"firestore.rules": render_rules(service, tree, rnd)})
        self.assertEqual(varied["coverage"]["unexamined"], {})
        self.assertEqual(found(varied), found(canonical))
        self.assertEqual({item[:3] for item in found(canonical)}, expected_rules(service, tree))


# --- Realtime Database rules: comments and trailing commas never change what a file allows ---------------------------

RTDB_VALUES = [True, False, "true", "false", "auth != null", "auth.uid != null", "auth.uid === $uid", "now < 1700000000000", "now<1700000000000"]
rtdb_trees = st.recursive(
    st.dictionaries(st.sampled_from([".read", ".write"]), st.sampled_from(RTDB_VALUES), max_size=2),
    lambda children: st.dictionaries(st.sampled_from([".read", ".write", "users", "$uid", "posts", "logs"]),
                                     st.sampled_from(RTDB_VALUES) | children, max_size=4).map(
        lambda node: {key: value for key, value in node.items() if key.startswith(".") != isinstance(value, dict)}),
    max_leaves=10)


def render_json(node, rnd: random.Random | None) -> str:
    """JSON for `node`; with `rnd`, as Firebase also accepts it: comments (holding quotes, braces and commas) anywhere a
    space may go, and trailing commas."""
    def gap() -> str:
        return "" if rnd is None else rnd.choice(["", " ", "\n  ", ' // "x": true, }\n', " /* {\"y\": 1,] */ "])

    if not isinstance(node, dict):
        return json.dumps(node)
    members = [gap() + json.dumps(key) + gap() + ":" + gap() + render_json(value, rnd) + gap() for key, value in node.items()]
    trailing = "," if rnd is not None and members and rnd.random() < 0.5 else ""
    return "{" + gap() + ",".join(members) + trailing + gap() + "}"


def expected_realtime(rules: dict) -> set[tuple]:
    expected = set()

    def visit(node: dict, where: str) -> None:
        for key, value in node.items():
            if isinstance(value, dict):
                visit(value, f"{where.rstrip('/')}/{key}")
                continue
            rule = re.sub(r"\s+", "", value) if isinstance(value, str) else value
            kind = ("open" if rule is True or rule == "true" else "test-mode" if isinstance(rule, str) and rule.startswith("now<")
                    else "any-signed-in" if rule in ("auth!=null", "auth.uid!=null") and where == "/" else None)
            if kind:
                expected.add((f"pitangus.firebase.{kind}", f"database:{where}:{key[1:]}", SEVERITY[kind]))

    visit(rules, "/")
    return expected


class RealtimeRulesProperties(unittest.TestCase):
    @PROPERTY
    @given(rtdb_trees, st.randoms(use_true_random=False))
    def test_comments_and_trailing_commas_never_change_the_findings(self, rules, rnd):
        canonical = run({"database.rules.json": render_json({"rules": rules}, None)})
        varied = run({"database.rules.json": render_json({"rules": rules}, rnd)})
        self.assertEqual((varied["coverage"]["unexamined"], found(varied)), ({}, found(canonical)))
        self.assertEqual({item[:3] for item in found(canonical)}, expected_realtime(rules))


# --- Supabase: a table is its project, schema and name ---------------------------------------------------------------

TABLES = ["profiles", "orders", '"Orders"', "notes"]
SCHEMAS = ["", "public.", '"public".', "private.", "api."]
sql_operations = st.lists(st.tuples(st.sampled_from(["create", "enable", "disable", "drop"]), st.sampled_from(SCHEMAS), st.sampled_from(TABLES)),
                          max_size=10)
projects = st.tuples(sql_operations, st.integers(1, 3), st.booleans())   # statements, how many files, does config.toml serve `api`


def render_project(prefix: str, project) -> dict[str, str]:
    operations, files, serves_api = project
    sql = {"create": "create table {} (id int);", "enable": "alter table {} enable row level security;",
           "disable": "alter table if exists {} disable row level security;", "drop": "drop table if exists {};"}
    rendered = {f"{prefix}supabase/migrations/{index:03}_step.sql": "" for index in range(files)}
    names = sorted(rendered)
    for position, (operation, schema, table) in enumerate(operations):
        rendered[names[position * files // max(len(operations), 1)]] += sql[operation].format(schema + table) + "\n"
    if serves_api:
        rendered[f"{prefix}supabase/config.toml"] = '[api]\nschemas = ["public", "graphql_public", "api"]\n'
    return rendered


class SupabaseProperties(unittest.TestCase):
    @PROPERTY
    @given(projects, st.sampled_from(["apps/web/", "packages/db/", "x/y/z/"]))
    def test_moving_a_project_into_a_monorepo_folder_never_changes_its_findings(self, project, folder):
        self.assertEqual(found(run(render_project(folder, project)), folder), found(run(render_project("", project))))

    @PROPERTY
    @given(projects, projects, st.sampled_from([("a/", "b/"), ("b/", "a/"), ("", "apps/b/"), ("apps/a/", "")]))
    def test_rls_in_one_project_never_silences_a_table_of_another(self, mine, other, places):
        here, there = places
        operations, files, serves_api = other
        # The other project enables row level security on every table name there is, in every schema.
        other = ([*operations, *(("enable", schema, table) for schema in SCHEMAS for table in TABLES)], files, serves_api)
        alone = run(render_project(here, mine))
        together = run({**render_project(here, mine), **render_project(there, other)})
        self.assertEqual({item for item in found(together, here) if item[3].startswith("supabase/")}, found(alone, here))


# --- any policy file: what couldn't be read is unexamined, never examined ---------------------------------------------

POLICY_FILES = {
    "supabase/migrations/001.sql": "create table notes (id int);",
    "apps/b/supabase/migrations/001.sql": "create table orders (id int); alter table orders enable row level security;",
    "firestore.rules": "service cloud.firestore { match /{document=**} { allow read: if true } }",
    "storage.rules": "service firebase.storage { match /b/{bucket}/o { match /{allPaths=**} { allow write: if request.auth != null; } } }",
    "database.rules.json": '{"rules": {".read": true}}',
    "web/database.rules.json": '{"rules": {"logs": {".write": "now < 1700000000000"}}}',
}


def broken(name: str, mode: str) -> tuple[str | bytes, str]:
    """`name` damaged by `mode`, and the reason it must be unexamined for."""
    content = POLICY_FILES[name]
    if mode == "encoding":
        return b"\xff\xfe" + content.encode(), "unreadable"
    if mode == "size":
        return content + " " * 200, "too_large"
    if name.endswith(".rules"):
        return content[:content.rfind("}")], "parse_error"
    if name.endswith(".json"):
        return content[:-3], "parse_error"
    return b"\xc3\x28" + content.encode(), "unreadable"   # SQL has no syntax to break: an encoding it can't read


class UnreadableProperties(unittest.TestCase):
    @PROPERTY
    @given(st.sets(st.sampled_from(sorted(POLICY_FILES)), min_size=1), st.data())
    def test_a_policy_file_it_cannot_read_is_unexamined_and_reports_nothing(self, names, data):
        victim = data.draw(st.sampled_from(sorted(names)))
        mode = data.draw(st.sampled_from(["encoding", "size", "syntax"]))
        content, reason = broken(victim, mode)
        files = {name: POLICY_FILES[name] for name in names}
        size = max(len(text) for text in files.values()) + 50
        with patch.object(policies, "FILE_MAX", size):
            clean = run(files)
            damaged = run({**files, victim: content})
        self.assertEqual(damaged["coverage"]["unexamined"], {victim: reason})
        self.assertNotIn(victim, {item["path"] for item in damaged["findings"]})
        project = policies.supabase_project(victim)

        def untouched(result) -> set[tuple]:   # what no longer depends on the damaged file
            return {item for item in found(result) if item[3] != victim and (project is None or policies.supabase_project(item[3]) != project)}

        self.assertEqual(untouched(damaged), untouched(clean))
