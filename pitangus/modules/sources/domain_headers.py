"""Request headers a domain's web scans may carry (API keys, bearer tokens, session cookies).

They live encrypted in the vault, one entry per domain (`domain-headers:<id>`), and only leave it for the scan
that asked for them: the worker reads them right before ZAP starts and hands them to ZAP through its plan, which
travels on the container's standard input into a memory-only folder (never a file on the host). Nobody reads them
back: listings carry the name, the last four characters of long values and when they were saved. Every value read
is registered with the log filter, and the scan scrubs them from what ZAP returns.

Headers can stop authenticating while nobody looks (a cookie expires, a token is revoked) and the scan would then see
only the public pages. The domain's session check (`set_check`) is a page that only opens signed in: a scan that sends
the headers asks for it before and after, and without a 2xx the scan is incomplete and marks nothing fixed.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from pitangus.modules.sources import domains, test_users
from pitangus.shared import log as logging_setup
from pitangus.shared import vault
from pitangus.shared.i18n import msg, text

LIMIT = 10              # headers per domain
VALUE_MAX = 4096
NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}")
# Framing and routing belong to ZAP and the connection, never to a saved header.
DENIED = frozenset(("host", "content-length", "transfer-encoding", "connection", "keep-alive", "proxy-connection",
                    "proxy-authenticate", "proxy-authorization", "te", "trailer", "trailers", "upgrade", "expect",
                    "content-encoding", "http2-settings"))
ID = re.compile(r"[0-9a-f]{24}")


class HeaderError(ValueError):
    """`message` is what people read (rendered per reader); str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


def _entry(domain_id: str) -> str:
    if not isinstance(domain_id, str) or not ID.fullmatch(domain_id):
        raise HeaderError(msg("sources.domains.invalid_id"))
    return f"domain-headers:{domain_id}"


def check_name(name) -> str:
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise HeaderError(msg("sources.domains.headers.invalid_name"))
    if name.lower() in DENIED:
        raise HeaderError(msg("sources.domains.headers.denied_name", name=name))
    return name


def check_value(value) -> str:
    if not isinstance(value, str):
        raise HeaderError(msg("sources.domains.headers.invalid_value", max=VALUE_MAX))
    value = value.strip(" \t")
    # Visible ASCII, spaces and tabs only: no line breaks (header injection) and nothing a proxy would re-encode.
    if not value or len(value) > VALUE_MAX or any(not (32 <= ord(character) < 127 or character == "\t") for character in value):
        raise HeaderError(msg("sources.domains.headers.invalid_value", max=VALUE_MAX))
    return value


def _load(domain_id: str) -> dict:
    stored = vault.get(_entry(domain_id))
    headers = stored if isinstance(stored, dict) else {}
    for item in headers.values():
        if isinstance(item, dict) and isinstance(item.get("value"), str):
            logging_setup.register_secret(item["value"])
    return headers


def _shown(item: dict) -> dict:
    value = str(item.get("value") or "")
    return {"name": item.get("name"), "last4": value[-4:] if len(value) >= 12 else None, "saved_at": item.get("saved_at")}


def list_headers(domain_id: str) -> list[dict]:
    """Names, the last four characters of long values and when each was saved: never a value."""
    return [_shown(item) for _, item in sorted(_load(domain_id).items()) if isinstance(item, dict)]


def save(domain_id: str, name, value, *, by: str = "") -> list[dict]:
    """Adds a header or replaces the one with the same name (case-insensitive)."""
    name, value = check_name(name), check_value(value)
    headers = _load(domain_id)
    if name.lower() not in headers and len(headers) >= LIMIT:
        raise HeaderError(msg("sources.domains.headers.limit", max=LIMIT))
    headers[name.lower()] = {"name": name, "value": value, "saved_at": datetime.now(timezone.utc).isoformat(), "by": by[:200]}
    vault.put(_entry(domain_id), headers)
    logging_setup.register_secret(value)
    return list_headers(domain_id)


def remove(domain_id: str, name) -> list[dict]:
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise HeaderError(msg("sources.domains.headers.invalid_name"))
    headers = _load(domain_id)
    if headers.pop(name.lower(), None) is None:
        raise HeaderError(msg("sources.domains.headers.not_found", name=name))
    if headers:
        vault.put(_entry(domain_id), headers)
    else:
        vault.delete(_entry(domain_id))
    return list_headers(domain_id)


def values(domain_id: str) -> list[tuple[str, str]]:
    """(name, value) pairs for the scan that is about to start; the only reader of the values."""
    return [(item["name"], item["value"]) for _, item in sorted(_load(domain_id).items())
            if isinstance(item, dict) and isinstance(item.get("name"), str) and isinstance(item.get("value"), str)]


def set_check(data_dir: Path, record: dict, value) -> str | None:
    """Saves the domain's session check: an HTTPS page on it or one of its subdomains, as for a test user's check
    page; empty removes it. Answers what is saved."""
    try:
        url = test_users.check_login_url(value, record["host"], "sources.domains.headers.invalid_check")
    except test_users.TestUserError as exc:
        raise HeaderError(exc.message) from exc
    return domains.set_session_check(data_dir, record["id"], url)["session_check"]


def count(domain_id: str) -> int:
    return len(_load(domain_id))


def forget(domain_id: str) -> None:
    vault.delete(_entry(domain_id))
