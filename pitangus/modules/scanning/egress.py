"""The public addresses web scans leave from, for sites that filter by IP (a firewall or a WAF in front of them).

The operator declares them in PITANGUS_EGRESS_IPS. Without it, an administrator can ask once, on purpose, for the
address this server is seen from: one HTTPS GET to a public echo service (ECHO_URL), with no redirects, a short
timeout and a tiny read. The answer is kept in a settings document, never on disk. That address is the API's: when
the worker runs elsewhere, scans may leave from another one, which is why the setting comes first.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request

from pitangus.shared import documents, http, settings
from pitangus.shared.addresses import is_public
from pitangus.shared.i18n import msg

SETTING = "PITANGUS_EGRESS_IPS"
DOCUMENT = "egress"
ECHO_URL = "https://api.ipify.org"
TIMEOUT = 10        # seconds for the echo service
READ_MAX = 64       # bytes read from its answer: an IPv6 address in text is at most 45


class EgressError(ValueError):
    def __init__(self, message):
        super().__init__(str(message))
        self.message = message


def configured() -> list[str]:
    return settings.addresses(SETTING)


def current(data_dir: Path) -> dict:
    """What the panel shows: the declared addresses, else the one detected by an administrator, else nothing."""
    declared = configured()
    if declared:
        return {"ips": declared, "source": "setting", "detected_at": None}
    stored = documents.load(data_dir, DOCUMENT, {}) or {}
    if isinstance(stored.get("ip"), str):
        return {"ips": [stored["ip"]], "source": "detected", "detected_at": stored.get("at")}
    return {"ips": [], "source": None, "detected_at": None}


def _fetch() -> bytes:
    request = Request(ECHO_URL, headers={"Accept": "text/plain", "User-Agent": "Pitangus"})
    with http.opener().open(request, timeout=TIMEOUT) as response:  # noqa: S310 (a fixed https URL)
        return response.read(READ_MAX + 1)


def detect(data_dir: Path, *, by: str) -> dict:
    """Asks the echo service once and keeps the answer if it is one public address. Raises EgressError."""
    if configured():
        raise EgressError(msg("scanning.egress.declared", name=SETTING))
    try:
        raw = _fetch()
    except (URLError, OSError, ValueError) as exc:
        raise EgressError(msg("scanning.egress.unreachable")) from exc
    try:
        if len(raw) > READ_MAX:
            raise ValueError("too long")
        address = ipaddress.ip_address(raw.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError) as exc:
        raise EgressError(msg("scanning.egress.unexpected")) from exc
    if not is_public(address):
        raise EgressError(msg("scanning.egress.unexpected"))
    documents.save(data_dir, DOCUMENT, {"ip": str(address), "at": datetime.now(timezone.utc).isoformat(), "by": by})
    return current(data_dir)
