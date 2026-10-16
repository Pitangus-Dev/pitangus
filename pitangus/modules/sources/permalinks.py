"""Where a finding is, on its provider: the file at the scanned commit, with its lines. What leaves Pitangus (a Jira
issue, a report) links there instead of carrying code."""

from __future__ import annotations

import re
from typing import Any, Mapping
from urllib.parse import quote

SHA = re.compile(r"[0-9a-f]{7,40}")


def code_url(source: Mapping[str, Any], path: str, line: int | None = None, end_line: int | None = None) -> str | None:
    """The file at the scanned commit on GitHub, anchored at its lines; None when the provider, the repository or the
    commit isn't known."""
    source_id = str(source.get("id") or "")
    repository = source_id.removeprefix("github:")
    commit = str(source.get("commit") or "")
    if not source_id.startswith("github:") or "/" not in repository or not SHA.fullmatch(commit) or not path:
        return None
    parts = str(path).split("/")
    if any(part in ("", ".", "..") for part in parts):
        return None
    anchor = ""
    if isinstance(line, int) and not isinstance(line, bool) and line > 0:
        anchor = f"#L{line}" + (f"-L{end_line}" if isinstance(end_line, int) and not isinstance(end_line, bool) and end_line > line else "")
    return f"https://github.com/{repository}/blob/{commit}/{'/'.join(quote(part) for part in parts)}{anchor}"
