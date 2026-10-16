"""`make engines` pulls the images this server runs, and only those: scripts/engine-images.sh (shell, no Python) agrees
with engines.pulled_images() for any configuration, from the environment or from .env."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hypothesis import given, settings, strategies as st

from pitangus.modules.scanning import engines
from pitangus.modules.scanning.engines import EXPOSURE_ENGINES, IMAGES

ROOT = Path(__file__).resolve().parents[1]
PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

FLAGS = ("PITANGUS_CHECKOV_ENABLED", "PITANGUS_GRYPE_ENABLED", "PITANGUS_DAST_ENABLED", "PITANGUS_TRIVY_ENABLED",
         "PITANGUS_OSV_SCANNER_ENABLED", "PITANGUS_KATANA_ENABLED", "PITANGUS_NUCLEI_ENABLED")
VALUE = st.sampled_from([None, "", "1", "true", "YES", "On", "0", "no", "off", "maybe"])


def listed(environment: dict, env_file: str) -> list[str]:
    with tempfile.TemporaryDirectory() as folder:
        (Path(folder) / ".env").write_text(env_file)
        clean = {key: value for key, value in os.environ.items() if key not in FLAGS}
        clean.update({key: value for key, value in environment.items() if value is not None})
        completed = subprocess.run(["sh", str(ROOT / "scripts" / "engine-images.sh")], cwd=folder, env=clean,
                                   capture_output=True, text=True, check=True)
    return completed.stdout.split()


@unittest.skipUnless(shutil.which("sh") and shutil.which("awk"), "needs sh and awk")
class EngineImagesTests(unittest.TestCase):
    @settings(max_examples=40 * SCALE, deadline=None)
    @given(st.fixed_dictionaries(dict.fromkeys(FLAGS, VALUE)), st.fixed_dictionaries(dict.fromkeys(FLAGS, VALUE)))
    def test_the_script_pulls_what_the_server_runs(self, environment, from_file):
        env_file = "".join(f"{key}={value}\n" for key, value in from_file.items() if value is not None)
        # What the server would see: the variable if it's set to something, otherwise the line in .env (compose).
        effective = {key: environment[key] or from_file[key] or "" for key in FLAGS}
        with patch.dict(os.environ, effective):
            expected = engines.pulled_images()
            enabled = {key: engines.enabled(key) for key in IMAGES}
        self.assertEqual(listed(environment, env_file), expected)
        for key, meta in IMAGES.items():
            if not enabled[key]:
                self.assertNotIn(meta["image"], expected, key)
            if key in EXPOSURE_ENGINES and enabled[key]:
                self.assertIn(meta["image"], expected, key)

    def test_pull_skips_an_engine_turned_off(self):
        rows = [{"tool": key, "name": IMAGES[key]["name"], "version": "", "image": IMAGES[key]["image"], "ready": False,
                 "built_locally": False, "enabled": key != "checkov"} for key in ("checkov", "trivy")]
        with patch.object(engines, "engine_status", return_value=rows), patch.object(engines, "runner", return_value="docker"), \
                patch.object(engines.shutil, "which", return_value=None):
            actions = {row["tool"]: row["action"]["$t"] for row in engines.pull_engines()}
        self.assertEqual(actions, {"checkov": "scanning.engines.action.disabled", "trivy": "scanning.engines.action.no_docker"})

    def test_make_uses_the_script_and_names_today_s_engines(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        help_line = next(line for line in makefile.splitlines() if line.startswith("engines:"))
        self.assertIn("sh scripts/engine-images.sh", makefile)
        self.assertNotIn("Gitleaks", help_line)
        for name in ("Betterleaks", "httpx", "testssl.sh", "nuclei"):
            self.assertIn(name, help_line)


if __name__ == "__main__":
    unittest.main()
