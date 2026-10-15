"""Settings: declared in one place, checked at start-up with a clear message, read when asked for."""

import base64
import os
import unittest
from unittest.mock import patch

from pitangus.shared import settings
from pitangus.shared.i18n import text


def problems(**environment) -> list[str]:
    base = {"PITANGUS_DATABASE_URL": "postgresql+psycopg://u:p@db/t"}
    return [text(problem, "en") for problem in settings.problems({**base, **environment})]


class SettingsTests(unittest.TestCase):
    def test_a_valid_environment_has_no_problems(self):
        self.assertEqual(problems(PITANGUS_PUBLIC_URL="https://pitangus.example.com", PITANGUS_PR_POLL_SECONDS="120",
                                  PITANGUS_EMBEDDED_WORKER="false", PITANGUS_LOG_LEVEL="debug",
                                  PITANGUS_MASTER_KEY=base64.b64encode(b"0123456789abcdef" * 2).decode()), [])

    def test_each_mistake_is_named(self):
        found = problems(PITANGUS_PR_POLL_SECONDS="5", PITANGUS_EMBEDDED_WORKER="maybe", PITANGUS_REQUIRE_TOTP="some",
                         PITANGUS_PUBLIC_URL="pitangus.example.com", PITANGUS_MASTER_KEY="short", PITANGUS_METRICS_TOKEN="abc")
        self.assertEqual(len(found), 6)
        for name in ("PITANGUS_PR_POLL_SECONDS", "PITANGUS_EMBEDDED_WORKER", "PITANGUS_REQUIRE_TOTP", "PITANGUS_PUBLIC_URL",
                     "PITANGUS_MASTER_KEY", "PITANGUS_METRICS_TOKEN"):
            self.assertTrue(any(name in problem for problem in found), name)
        self.assertNotIn("abc", " ".join(found).replace("PITANGUS_METRICS_TOKEN", ""))  # a secret's value is never echoed

    def test_the_database_url_is_required(self):
        self.assertIn("PITANGUS_DATABASE_URL", text(settings.problems({})[0], "en"))

    def test_values_are_read_when_asked_with_defaults_and_minimums(self):
        with patch.dict("os.environ", {"PITANGUS_PR_POLL_SECONDS": "10", "PITANGUS_ALLOWED_ORIGINS": " https://a.example/ ,https://b.example"}):
            self.assertEqual(settings.integer("PITANGUS_PR_POLL_SECONDS"), 60)
            self.assertEqual(settings.items("PITANGUS_ALLOWED_ORIGINS"), ["https://a.example", "https://b.example"])
            self.assertTrue(settings.flag("PITANGUS_EMBEDDED_WORKER"))  # default on
        with self.assertRaises(KeyError):
            settings.text("SOMETHING_NOT_DECLARED")

    def test_coverage_contract_and_canonical_identity_are_on_by_default(self):
        """Since 0.14 a finding is fixed only with its owner engine's proof, and identified by its problem; shadow and
        v1 remain choices, and an empty value is the default."""
        from pitangus.modules.findings import canonical
        from pitangus.modules.scanning import engine_contract
        self.assertEqual((settings.SETTINGS["PITANGUS_COVERAGE_MODE"].default, settings.SETTINGS["PITANGUS_IDENTITY_MODE"].default), ("on", "v2"))
        for value in (None, "", "  "):
            with patch.dict("os.environ"):
                for name in ("PITANGUS_COVERAGE_MODE", "PITANGUS_IDENTITY_MODE"):
                    if value is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = value
                self.assertEqual((engine_contract.mode(), engine_contract.enforced(), canonical.mode()), ("on", True, "v2"), value)
        with patch.dict("os.environ", {"PITANGUS_COVERAGE_MODE": "shadow", "PITANGUS_IDENTITY_MODE": "v1"}):
            self.assertEqual((engine_contract.mode(), engine_contract.enforced(), canonical.mode()), ("shadow", False, "v1"))
        self.assertEqual(problems(PITANGUS_COVERAGE_MODE="off", PITANGUS_IDENTITY_MODE="shadow"), [])
        self.assertEqual(len(problems(PITANGUS_COVERAGE_MODE="maybe", PITANGUS_IDENTITY_MODE="v3")), 2)

    def test_no_module_reads_the_environment_on_its_own(self):
        import pathlib
        import re
        allowed = {"shared/settings.py", "shared/paths.py", "modules/scanning/engines.py",  # engines: HOSTNAME, the child env
                   "modules/findings/fix_examples.py",  # example code shown to users
                   "modules/scanning/secret_filter.py"}  # the names a repository's code reads secrets through
        root = pathlib.Path(settings.__file__).resolve().parents[1]
        offenders = [str(path.relative_to(root)) for path in root.rglob("*.py")
                     if str(path.relative_to(root)) not in allowed and re.search(r"os\.environ|os\.getenv", path.read_text(encoding="utf-8"))]
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
