"""Project and configuration paths in one place (each module used to compute its own)."""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # repository root (or /app in the container)
RULES_DIR = ROOT / "rules"
# Third-party Opengrep rules, apart from ours (rules/ is MIT, Pitangus'): each with its LICENSE and NOTICE.
THIRD_PARTY_RULES_DIR = ROOT / "third_party" / "gitlab-sast-rules" / "rules"
FIXTURES_DIR = ROOT / "fixtures"
# Config and secrets (encrypted vault). Tests redirect it to a temp dir with patch.object(paths, "CONFIG_DIR", …).
CONFIG_DIR = Path(os.environ.get("PITANGUS_CONFIG_DIR") or Path.home() / ".config" / "pitangus")
