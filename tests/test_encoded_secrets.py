"""A secret re-encoded is detected or declared, never fixed.

The secret engines match bytes. A token written in UTF-16 (PowerShell 5's default) or UTF-32 is two or four bytes per
character, and Betterleaks still logs `scanning path` for it: a log line says the engine opened a file, not that a token
in it was where its patterns look. So what an engine read is judged by the bytes, never by the file's name: a file
whose bytes aren't UTF-8 text without zero bytes is declared unexamined (`encoding`) by the engines that match bytes,
and the snapshot rewrites a consistent UTF-16 or UTF-32 text as UTF-8 first, so they find what it holds. The encodings
here are drawn from every text codec Python knows; none of them is named by the mechanism.
"""

import codecs
import encodings.aliases
import os
import random
import tempfile
import unittest
from pathlib import Path

from hypothesis import HealthCheck, example, given, settings, strategies as st

from pitangus.modules.findings import registry
from pitangus.modules.scanning import engines
from pitangus.shared import encodings as text_encodings
from test_contracts_together import Registry, SecretEngines
from test_secret_pass_coverage import ALNUM, SCALE, SECRET_ENGINES, TOKEN, scan


def _text_codec(name: str) -> bool:
    try:
        return codecs.lookup(name)._is_text_encoding
    except LookupError:
        return False


CODECS = sorted({codecs.lookup(name).name for name in {*encodings.aliases.aliases.values(), "utf_16", "utf_32", "utf_16_be", "utf_32_le"}
                 if _text_codec(name)})


def _encoded(line: str, codec: str) -> bytes | None:
    try:
        return line.encode(codec)
    except (UnicodeError, LookupError):
        return None


class ReencodedSecretTests(Registry):
    @settings(max_examples=40 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
    @given(TOKEN, st.sampled_from(CODECS), st.sampled_from(["deploy.ps1", "src/app.js", "config/.env.local", "docs/notes.txt", "x.bin"]))
    @example("ghp_" + "Zq9xK2mP7vL4wR8tY1nBc3dE5fG6hJ8kL0aS", "utf-16", "deploy.ps1")
    @example("ghp_" + "Zq9xK2mP7vL4wR8tY1nBc3dE5fG6hJ8kL0aS", "utf-32", "src/app.js")
    @example("ghp_" + "Zq9xK2mP7vL4wR8tY1nBc3dE5fG6hJ8kL0aS", "utf-16-be", "docs/notes.txt")
    @example("ghp_" + "Zq9xK2mP7vL4wR8tY1nBc3dE5fG6hJ8kL0aS", "cp500", "deploy.ps1")
    def test_the_same_secret_in_any_encoding_is_found_or_its_file_declared_never_fixed(self, token, codec, path):
        self.setUp()
        line = f'$Token = "{token}"\n'
        encoded = _encoded(line, codec)
        if encoded is None:
            return
        files = {path: line.encode(), "app.py": b"x = 1\n"}
        first, _ = self.save(scan(files, SecretEngines()))
        found = {item["fingerprint"] for item in first["findings"] if item["scanner"] == "secrets" and item["path"] == path}
        self.assertTrue(found, path)
        second, changes = self.save(scan({**files, path: encoded}, SecretEngines()))
        self.assertFalse(found & set(changes["fixed_now"]), (codec, path))
        # UTF-16 and UTF-32 are read as the text they are: the same value, the same identity, still there.
        if text_encodings.as_utf8(encoded) is not None:
            self.assertTrue(found <= {item["fingerprint"] for item in second["findings"]}, (codec, path))
            self.assertEqual(changes["new"], [], codec)

    def test_a_secret_removed_from_a_utf16_file_is_fixed(self):
        chooser = random.Random(7)
        token = "ghp_" + "".join(chooser.choice(ALNUM) for _ in range(36))
        files = {"deploy.ps1": f'$Token = "{token}"\n'.encode("utf-16"), "app.py": b"x = 1\n"}
        first, _ = self.save(scan(files, SecretEngines()))
        found = {item["fingerprint"] for item in first["findings"] if item["path"] == "deploy.ps1"}
        self.assertTrue(found)
        _, changes = self.save(scan({**files, "deploy.ps1": '$Token = $env:TOKEN\n'.encode("utf-16")}, SecretEngines()))
        self.assertEqual(found, found & set(changes["fixed_now"]))


class EngineLevelTests(unittest.TestCase):
    """Without the snapshot (an engine run on a folder as it is): what it says it read in bytes that aren't text is
    `encoding`, for both engines, whatever the file is called."""

    @settings(max_examples=60 * SCALE, deadline=None)
    @given(st.sampled_from(CODECS), st.text(min_size=1, max_size=40), st.sampled_from(["a.ps1", "b.txt", "c", "d/e.json"]))
    def test_a_file_read_in_bytes_that_arent_text_is_declared(self, codec, text, name):
        data = _encoded(text, codec)
        if data is None:
            return
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_bytes(data)
            gaps = engines.secret_gaps(root, {name}, None)
        readable = text_encodings.readable(data)
        self.assertEqual(not gaps, readable or not data, (codec, data[:20], gaps))

    @settings(max_examples=80 * SCALE, deadline=None)
    @given(st.text(alphabet=st.characters(codec="utf-8", exclude_categories=("Cc", "Cs", "Cn")), min_size=1, max_size=200),
           st.sampled_from(["utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be"]))
    @example("\xad", "utf-16")   # nightly: a soft hyphen (a format character) is text
    def test_utf16_and_utf32_text_is_rewritten_as_the_same_text(self, text, codec):
        data = (text + "\n").encode(codec)
        rewritten = text_encodings.as_utf8(data)
        if text_encodings.readable(data):
            self.assertIsNone(rewritten)
        elif rewritten is not None or codec in ("utf-16", "utf-32"):   # with a BOM it is always recognised
            self.assertEqual(rewritten, (text + "\n").encode("utf-8"), codec)
        # Without a BOM and with few ASCII characters it may not be recognised: then it stays unreadable, so declared.

    def test_bytes_that_are_no_text_are_never_rewritten(self):
        self.assertIsNone(text_encodings.as_utf8(bytes(range(256)) * 4))
        self.assertIsNone(text_encodings.as_utf8(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + bytes(64)))


@unittest.skipUnless(engines.docker_available() and engines.image_available("betterleaks") and engines.image_available("trivy"),
                     "the engine images aren't available")
class RealEnginesTests(Registry):
    """The adversary's probe with the pinned images: a secret re-encoded to UTF-16, its value unchanged."""

    TOKEN = "ghp_" + "Zq9xK2mP7vL4wR8tY1nBc3dE5fG6hJ8kL0aS"

    def direct(self, snapshot: Path, data_dir: Path) -> tuple[dict, dict]:
        """The engines run on the folder as it is (no snapshot rewriting): what they can't read is declared."""
        betterleaks = engines.run_betterleaks(snapshot)
        gaps: dict = {}
        trivy = engines.trivy_secrets(snapshot, data_dir / "cache", None, gaps=gaps)
        found = engines.merge_secrets(betterleaks["findings"], trivy or [])
        from test_dashboard import _scan
        self.clock_ = getattr(self, "clock_", 0) + 1
        record = {**_scan("org/api", found, f"2026-10-14T{10 + self.clock_:02d}:00:00+00:00"), "coverage": {
            "betterleaks": betterleaks["coverage"], "trivy": {"examined": "*", "unexamined": gaps}}}
        record["summary"]["tools"] = [{"name": tool, "version": "1", "status": "completed"} for tool in SECRET_ENGINES]
        record["source"]["uid"] = "github#utf16"
        return self.save(record)

    def test_the_engines_on_a_utf16_file_declare_it_and_the_snapshot_reads_it(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("ADV_TMP")) as folder:
            snapshot = Path(folder) / "snapshot"
            snapshot.mkdir()
            (snapshot / "deploy.ps1").write_text(f'$Token = "{self.TOKEN}"\n', encoding="utf-8")
            first, _ = self.direct(snapshot, Path(folder))
            self.assertTrue(first["findings"])
            (snapshot / "deploy.ps1").write_bytes(f'$Token = "{self.TOKEN}"\n'.encode("utf-16"))
            _, changes = self.direct(snapshot, Path(folder))
            self.assertEqual(changes["fixed_now"], [])
            entries = registry.load(self.data_dir, "github#utf16")["findings"]
            self.assertTrue(all(entry["status"] == "open" for entry in entries.values()))
        # Through the snapshot, which rewrites it as UTF-8: both engines find the same value again.
        from test_secret_pass_coverage import RealEnginesTests as Real
        record = Real.real_scan(self, {"deploy.ps1": f'$Token = "{self.TOKEN}"\n'.encode("utf-16"), "app.py": b"x = 1\n"})
        tools = {engine for item in record["findings"] if item["path"] == "deploy.ps1" for engine in (item["tool"], *(item.get("also_detected_by") or []))}
        self.assertEqual(tools, set(SECRET_ENGINES))


if __name__ == "__main__":
    unittest.main()
