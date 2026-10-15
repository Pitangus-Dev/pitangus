"""A finding's code, read when it is opened (runs/code_view.py): from the provider at the scanned commit, for whoever can
read the finding, every secret a secret engine reported in that file masked; never stored."""

import base64
import json
import os
import random
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from pitangus.modules.identity.auth import Users
from pitangus.modules.runs import code_view
from pitangus.modules.runs.store import load_run, save_repository_scan
from pitangus.modules.sources.permalinks import code_url
from pitangus.modules.sources.repositories import LinkedPath, _file_path, _github_file
from test_auth import PASSWORD, HttpCase
from test_dashboard import _scan

COMMIT = "a" * 40
TOKEN = "Zq8vN2rT6yLp4XbW9mKc3HdJ"   # a value nobody wrote in a catalog: 24 random characters  # gitleaks:allow
KEY = "sk_live_" + "Qx7Rt2Vb9Nm4Lp8Kd3Hs6Wf1"
FILE = "\n".join([
    "import os",                                   # 1
    "",                                            # 2
    f'API_KEY = "{KEY}"',                          # 3: a secret with its columns
    f"OTHER = '{TOKEN}'",                          # 4: a secret the registry knows, from another commit
    "def find(q):",                                # 5
    '    cur.execute("SELECT * FROM t WHERE id=" + q)',  # 6: the finding
    "    return cur.fetchall()",                   # 7
    "-----BEGIN RSA PRIVATE KEY-----",             # 8: a key the engine reported by its first line only
    "MIIEowIBAAKCAQEA" + TOKEN,                    # 9
    "-----END RSA PRIVATE KEY-----",               # 10
    "print('done')",                               # 11
]) + "\n"


def finding(fingerprint, scanner="sast", line=6, **extra):
    return {"finding_id": fingerprint[:16], "fingerprint": fingerprint, "scanner": scanner, "tool": "opengrep", "rule_id": "appsec.py.sqli",
            "title": "SQL built by concatenation", "path": "app/db.py", "line": line, "severity": "high", "confidence": 8, "verdict": "candidate",
            "cwe": [89], "owasp": ["A05:2025"], "cve": [], "ghsa": [], "package": None, "advisory": None, "kev": None, "epss": None,
            "priority": {"action": "attend", "factors": []}, "reason": "r", "remediation": "Use parameters.", **extra}


def secret(fingerprint, line, **extra):
    return finding(fingerprint, "secrets", line, tool="betterleaks", rule_id="generic-api-key", cwe=[798], **extra)


class WindowTests(unittest.TestCase):
    def test_the_lines_around_a_finding_with_every_secret_masked(self):
        secrets = code_view.secret_places([secret("1" * 64, 3, span=[3, 11, 3, 11 + len(KEY)]), secret("3" * 64, 8)], "app/db.py", certain=True)
        secrets += code_view.secret_places([secret("2" * 64, 4, span=[4, 9, 4, 33])], "app/db.py", certain=False)
        lines = code_view.window(FILE.encode(), finding("f" * 64, end_line=7), secrets)
        self.assertEqual([line["number"] for line in lines], list(range(3, 11)))
        shown = json.dumps(lines)
        self.assertNotIn(KEY, shown)
        self.assertNotIn(TOKEN, shown)
        by_number = {line["number"]: line for line in lines}
        self.assertEqual(by_number[3], {"number": 3, "text": f'API_KEY = "{code_view.SECRET_MASK}"', "focus": False, "masked": "span"})
        self.assertEqual(by_number[4]["masked"], "line")   # another commit's columns are never trusted: the whole line
        self.assertEqual([by_number[number].get("masked") for number in (8, 9, 10)], ["line"] * 3)   # the key's block to its end
        self.assertEqual([by_number[number]["focus"] for number in (5, 6, 7)], [False, True, True])
        self.assertEqual(by_number[6]["text"], '    cur.execute("SELECT * FROM t WHERE id=" + q)')

    def test_only_what_secret_engines_and_credential_weaknesses_report_is_masked(self):
        places = code_view.secret_places([finding("1" * 64, line=3), finding("2" * 64, line=4, cwe=[798]),
                                          secret("3" * 64, 9, path="other.py")], "app/db.py", certain=True)
        self.assertEqual(places, [(4, 4, None)])

    def test_a_window_is_bounded(self):
        text = "\n".join(f"x{index}" for index in range(500)).encode()
        lines = code_view.window(text, finding("f" * 64, line=100, end_line=400), [])
        self.assertEqual(len(lines), code_view.LINES_MAX)
        self.assertEqual(code_view.window(b"one\n", finding("f" * 64, line=9), []), [])
    def test_a_secret_never_shows_whatever_comes_before_it(self):
        # Engines count lines by "\n" alone and columns in characters of the bytes decoded with surrogateescape: a form
        # feed, a lone "\r", U+2028 or a truncated UTF-8 sequence before a secret never moves its mask.
        from pitangus.modules.findings.ai_prompt import code_text, prompt
        from pitangus.modules.runs.local import render_prompt
        tricky = [b"\x0c", b"\x0b", b"\r", b"\x1c", b"\x1d", b"\x1e", "\u0085".encode(), "\u2028".encode(),
                  "\u2029".encode(), b"\xe2\x82", b"\xff", b"\xc3", b"\xf0\x9f\x98", b"\r\n", b"\x80"]
        upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        rng = random.Random(1401)
        for attempt in range(400):
            value = "".join(rng.choice(upper) for _ in range(rng.randint(16, 40)))
            at = rng.randint(1, 30)
            rows = []
            for number in range(1, 40):
                row = b"".join(rng.choice([b"x = y ", b"call(z) ", b"  ", *([rng.choice(tricky)] * 2)]) for _ in range(rng.randint(0, 6)))
                rows.append(row + (f'k = "{value}"'.encode() + rng.choice([b"", b" #", rng.choice(tricky)]) if number == at else b""))
            raw = b"\n".join(rows) + rng.choice([b"", b"\n"])
            at = raw[:raw.index(value.encode())].count(b"\n") + 1   # a "\r\n" before it is a line too
            line = raw.split(b"\n")[at - 1].decode("utf-8", "surrogateescape")
            column = line.index(value)
            certain = attempt % 4 != 0
            hit = secret("1" * 64, at, span=[at, column, at, column + len(value)])
            sql = finding("f" * 64, line=max(1, at + rng.randint(-3, 3)))
            lines = code_view.window(raw, sql, code_view.secret_places([hit], "app/db.py", certain=certain))
            self.assertTrue(any(item["number"] == at and item.get("masked") for item in lines), attempt)
            self.assertFalse([item for item in lines if set(item["text"]) & set(upper)], attempt)
            pasted = prompt(sql, "en", code_text(lines, "en"))
            self.assertNotIn(value[:6], pasted)
            self.assertNotIn(value[-6:], pasted)
            if attempt % 10 == 0:   # the CLI's prompt, reading the folder
                with tempfile.TemporaryDirectory() as folder:
                    (Path(folder) / "app").mkdir()
                    (Path(folder) / "app" / "db.py").write_bytes(raw)
                    scan = {"findings": [sql, hit], "excluded_findings": []}
                    text = render_prompt({"findings": [sql], "comparison": None, "target": folder, "snapshot": "worktree",
                                          "scan": scan}, locale="en")
                    self.assertNotIn(value[:6], text)
                    self.assertNotIn(value[-6:], text)

    def test_overlapping_values_on_one_line_are_masked_as_one(self):
        raw = b'a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"\n'
        places = [(1, 1, (5, 31)), (1, 1, (10, 12))]
        self.assertEqual(code_view.window(raw, finding("f" * 64, line=1), places)[0]["text"], f'a = "{code_view.SECRET_MASK}"')

    def test_a_key_block_without_its_end_is_withheld_from_its_start(self):
        rows = ["x"] * 20 + ["-----BEGIN PRIVATE KEY-----"] + ["QUJDREVGR0hJSktMTU5PUA"] * 400 + ["-----END PRIVATE KEY-----", "y"]
        raw = "\n".join(rows).encode()
        lines = code_view.window(raw, finding("f" * 64, line=300), [(21, 21, None)])
        self.assertTrue(lines and all(item.get("masked") == "line" for item in lines))
        before = code_view.window(raw, finding("f" * 64, line=18), [(21, 21, None)])
        self.assertEqual([item.get("masked") for item in before], [None] * 6 + ["line"])
        ended = "\n".join(["-----BEGIN PRIVATE KEY-----", "QUJD", "-----END PRIVATE KEY-----", "z = 1", "w = 2"]).encode()
        self.assertEqual([item.get("masked") for item in code_view.window(ended, finding("f" * 64, line=4), [(1, 1, None)])],
                         ["line"] * 3 + [None, None])

    def test_lines_a_gitleaks_allow_comment_allowed_are_masked_too(self):
        record = {"coverage": {"betterleaks": {"suppressed_inline": ["app/db.py:4", "other.py:6"]}}}
        self.assertEqual(code_view.allowed_places(record, "app/db.py"), [(4, 4, None)])
        lines = code_view.window(FILE.encode(), finding("f" * 64), code_view.allowed_places(record, "app/db.py"))
        self.assertEqual({item["number"]: item.get("masked") for item in lines}[4], "line")

    def test_a_path_never_leaves_the_repository_and_a_permalink_names_the_commit(self):
        for path in ("../x", "a/../../b", "/etc/passwd", "a//b", "a\\b", "", "a/./b"):
            self.assertIsNone(_file_path(path), path)
        self.assertEqual(_file_path("src/a b?.py"), "src/a%20b%3F.py")
        source = {"id": "github:acme/api", "commit": COMMIT}
        self.assertEqual(code_url(source, "app/db.py", 6, 7), f"https://github.com/acme/api/blob/{COMMIT}/app/db.py#L6-L7")
        self.assertIsNone(code_url({"id": "local:api", "commit": COMMIT}, "app/db.py", 6))
        self.assertIsNone(code_url({"id": "github:acme/api"}, "app/db.py", 6))


class LocalPromptTests(unittest.TestCase):
    def test_the_cli_prompt_reads_the_scanned_folder_now_with_the_same_masking(self):
        from pitangus.modules.runs.local import render_prompt
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "app").mkdir()
            (Path(folder) / "app" / "db.py").write_text(FILE, encoding="utf-8")
            sql = finding("f" * 64)
            scan = {"findings": [sql, secret("1" * 64, 3, span=[3, 11, 3, 11 + len(KEY)]), secret("2" * 64, 4)],
                    "excluded_findings": [secret("3" * 64, 8)]}
            result = {"findings": [sql], "comparison": None, "target": folder, "snapshot": "worktree", "scan": scan}
            text = render_prompt(result, locale="en")
            self.assertIn('cur.execute("SELECT * FROM t WHERE id=" + q)', text)
            self.assertIn(f'API_KEY = "{code_view.SECRET_MASK}"', text)
            self.assertIn("```python", text)
            self.assertNotIn(KEY, text)
            self.assertNotIn(TOKEN, text)
            # A commit or the index was scanned: the folder may say something else, so no code.
            self.assertNotIn("```", render_prompt({**result, "snapshot": "index"}, locale="en"))
            self.assertNotIn("```", render_prompt({**result, "findings": [scan["findings"][1]]}, locale="en"))

    def test_the_cli_never_reads_a_credential_file_through_a_link(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / ".env").write_text(f"TOKEN={TOKEN}\n", encoding="utf-8")
            os.symlink(".env", Path(folder) / "config.txt")
            self.assertEqual(code_view.local_lines(Path(folder), finding("f" * 64, path="config.txt", line=1), [], certain=True), [])
            (Path(folder) / "plain.py").write_text("x = 1\n", encoding="utf-8")
            os.symlink("plain.py", Path(folder) / "alias.py")
            self.assertEqual(code_view.local_lines(Path(folder), finding("f" * 64, path="alias.py", line=1), [])[0]["text"], "x = 1")


class ProviderFileTests(unittest.TestCase):
    def test_a_link_is_never_read_and_a_file_is_its_own_bytes(self):
        def body(**item):
            return json.dumps(item).encode()
        data = b"print('hi')\n"
        content = base64.encodebytes(data).decode()
        self.assertEqual(_github_file(body(type="file", path="app/a.py", encoding="base64", content=content), "app/a.py"), data)
        with self.assertRaises(LinkedPath):   # the API followed a link to another file of the repository
            _github_file(body(type="file", path=".env", encoding="base64", content=content), "app/a.py")
        with self.assertRaises(LinkedPath):
            _github_file(body(type="symlink", path="app/a.py", target="../../etc/passwd"), "app/a.py")
        for other in (b"[]", body(type="submodule", path="app/a.py")):
            with self.assertRaises(FileNotFoundError):
                _github_file(other, "app/a.py")
        with self.assertRaises(ValueError):   # over 1 MB the API sends no content
            _github_file(body(type="file", path="app/a.py", encoding="none", content=""), "app/a.py")


class CodeApiTests(HttpCase):
    def saved(self, findings, *, commit=COMMIT, source_id="github:acme/api"):
        record = _scan("acme/api", findings, datetime.now(timezone.utc).isoformat())
        record["source"].update(id=source_id, uid="github#7", **({"commit": commit} if commit else {}))
        return save_repository_scan(self.data_dir, record)

    def signed_in(self):
        Users(self.data_dir).create("analista", PASSWORD)
        _, _, cookies = self.post("/api/auth/login", "login", {"username": "analista", "password": PASSWORD})
        return {"Cookie": cookies[0].split("; ")[0]}

    def test_a_reader_gets_the_code_with_secrets_masked_and_nobody_else_does(self):
        self.saved([secret("2" * 64, 4, span=[4, 9, 4, 33])])   # an earlier run of this commit: the registry still knows it
        run = self.saved([finding("f" * 64, end_line=7), secret("1" * 64, 3, span=[3, 11, 3, 11 + len(KEY)]), secret("3" * 64, 8)])
        stored = load_run(self.data_dir, run["id"])
        sql = next(item for item in stored["findings"] if item["scanner"] == "sast")["fingerprint"]
        key = next(item for item in stored["findings"] if item["scanner"] == "secrets")["fingerprint"]
        read: list[tuple] = []

        def reader(data_dir):
            def read_file(source, commit, path):
                read.append((source["id"], commit, path))
                return FILE.encode()
            return read_file
        url = f"/api/findings/code?run_id={run['id']}&fingerprint={sql}"
        with patch.object(code_view, "provider_reader", reader):
            self.assertEqual(self.call("GET", url)[0], 401)
            headers = self.signed_in()
            status, body, _ = self.call("GET", url, headers=headers)
            self.assertEqual(status, 200)
            self.assertEqual((body["status"], body["commit"], body["path"]), ("shown", COMMIT, "app/db.py"))
            self.assertEqual(read, [("github:acme/api", COMMIT, "app/db.py")])
            self.assertEqual(body["permalink"], f"https://github.com/acme/api/blob/{COMMIT}/app/db.py#L6-L7")
            self.assertNotIn(KEY, json.dumps(body))
            self.assertNotIn(TOKEN, json.dumps(body))
            masks = {line["number"]: line["masked"] for line in body["lines"]}
            self.assertEqual((masks[3], masks[4], masks[8], masks[9]), ("span", "line", "line", "line"))
            self.assertIn('    cur.execute("SELECT * FROM t WHERE id=" + q)', [line["text"] for line in body["lines"]])
            # The asset's view asks for it the same way.
            self.assertEqual(self.call("GET", f"/api/findings/code?run_id=asset:github%237&fingerprint={sql}", headers=headers)[1]["status"], "shown")
            # A secret's own finding: where it is, never its code; the provider isn't even asked.
            read.clear()
            status, body, _ = self.call("GET", f"/api/findings/code?run_id={run['id']}&fingerprint={key}", headers=headers)
            self.assertEqual((status, body["status"], body["reason"], body["lines"]), (200, "withheld", "secret", []))
            self.assertEqual(read, [])
            dotenv = self.saved([finding("8" * 64, path="config/.env.production")])
            print_ = load_run(self.data_dir, dotenv["id"])["findings"][0]["fingerprint"]
            self.assertEqual(self.call("GET", f"/api/findings/code?run_id={dotenv['id']}&fingerprint={print_}", headers=headers)[1]["status"], "withheld")
            self.assertEqual(read, [])
            self.assertEqual(self.call("GET", f"/api/findings/code?run_id={run['id']}&fingerprint={'d' * 64}", headers=headers)[0], 404)
            self.assertEqual(self.call("GET", f"/api/findings/code?run_id={'e' * 32}&fingerprint={sql}", headers=headers)[0], 404)
            self.assertEqual(self.call("GET", f"/api/findings/code?run_id={run['id']}&fingerprint=nothex", headers=headers)[0], 400)
        # Never stored: the run and the registry hold no line of it.
        self.assertNotIn("cur.execute", json.dumps(load_run(self.data_dir, run["id"])))

    def test_why_the_code_is_not_there(self):
        headers = self.signed_in()

        def failing(error):
            def reader(data_dir):
                def read_file(source, commit, path):
                    raise error
                return read_file
            return reader
        run = self.saved([finding("f" * 64)])
        sql = load_run(self.data_dir, run["id"])["findings"][0]["fingerprint"]
        url = f"/api/findings/code?run_id={run['id']}&fingerprint={sql}"
        for error, reason in ((FileNotFoundError("x"), "file_gone"), (PermissionError("x"), "repository_gone"),
                              (OSError("x"), "repository_unreachable"), (ValueError("x"), "repository_unreachable")):
            with patch.object(code_view, "provider_reader", failing(error)):
                status, body, _ = self.call("GET", url, headers=headers)
            self.assertEqual((status, body["status"], body["reason"]), (200, "unavailable", reason))
        with patch.object(code_view, "provider_reader", lambda data_dir: lambda *_: b"\0\x01binary"):
            self.assertEqual(self.call("GET", url, headers=headers)[1]["reason"], "binary")
        other = self.saved([finding("9" * 64, path="b.py")], commit=None)
        later = load_run(self.data_dir, other["id"])["findings"][0]["fingerprint"]
        self.assertEqual(self.call("GET", f"/api/findings/code?run_id={other['id']}&fingerprint={later}", headers=headers)[1]["reason"], "no_commit")

    def test_only_where_it_is_when_pitangus_did_not_read_that_place(self):
        headers = self.signed_in()
        read: list[tuple] = []

        def reader(data_dir):
            def read_file(source, commit, path):
                read.append(path)
                return FILE.encode()
            return read_file
        with patch.object(code_view, "provider_reader", reader):
            # An imported finding: its path, line and commit came with the import.
            imported = self.saved([finding("7" * 64, path="src/billing/core.py", line=4)])
            stored = load_run(self.data_dir, imported["id"])
            fake = save_repository_scan(self.data_dir, {**{key: value for key, value in stored.items() if key not in ("id", "created_at")},
                                                         "type": "sarif_import", "trigger": {"tool": "x"},
                                                         "findings": [finding("6" * 64, path="src/billing/core.py", line=11)]})
            print_ = load_run(self.data_dir, fake["id"])["findings"][0]["fingerprint"]
            status, body, _ = self.call("GET", f"/api/findings/code?run_id={fake['id']}&fingerprint={print_}", headers=headers)
            self.assertEqual((status, body["status"], body["reason"], body["lines"]), (200, "withheld", "imported", []))
            self.assertEqual(body["permalink"], f"https://github.com/acme/api/blob/{COMMIT}/src/billing/core.py#L11")
            # A secret this file had at another commit: its lines may have moved, so no code.
            self.saved([secret("2" * 64, 4, span=[4, 9, 4, 33])], commit="b" * 40)
            run = self.saved([finding("f" * 64)])
            sql = load_run(self.data_dir, run["id"])["findings"][0]["fingerprint"]
            body = self.call("GET", f"/api/findings/code?run_id={run['id']}&fingerprint={sql}", headers=headers)[1]
            self.assertEqual((body["status"], body["reason"]), ("withheld", "secret_other_commit"))
            self.assertEqual(read, [])
        # A symbolic link: never read under another name.
        def linked(data_dir):
            def read_file(source, commit, path):
                raise LinkedPath(path)
            return read_file
        clean = self.saved([finding("5" * 64, path="docs/x.py")])
        print_ = load_run(self.data_dir, clean["id"])["findings"][0]["fingerprint"]
        with patch.object(code_view, "provider_reader", linked):
            body = self.call("GET", f"/api/findings/code?run_id={clean['id']}&fingerprint={print_}", headers=headers)[1]
        self.assertEqual((body["status"], body["reason"], body["lines"]), ("withheld", "symlink", []))


if __name__ == "__main__":
    unittest.main()
