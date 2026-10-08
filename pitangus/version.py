"""Product version: read by the API, the reports, the Makefile and CI."""

import re
from pathlib import Path

# Major.minor; release tags are v<VERSION> or v<VERSION>.<patch> (.github/workflows/release.yml checks it).
VERSION = "0.12"
STAMP = Path(__file__).with_name("RELEASE")


def release(stamp: Path = STAMP) -> str:
    """The exact version an image was built as (0.12.1), stamped by the Dockerfile; VERSION for other builds."""
    try:
        stamped = stamp.read_text(encoding="utf-8").strip()
    except OSError:
        return VERSION
    return stamped if re.fullmatch(re.escape(VERSION) + r"(?:\.\d+)?", stamped) else VERSION


RELEASE = release()
# How Pitangus identifies itself to external services (GitHub, OSV, NVD, Jira…).
USER_AGENT = f"Pitangus/{RELEASE}"
