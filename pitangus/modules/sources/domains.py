"""Registry of HTTPS targets, with DNS TXT proof of control before they count as assets.

A domain becomes the asset `domain:<host>` once its TXT record (`_pitangus.<host>` = `pitangus-verify=<token>`) is
seen, and stays one for VERIFY_DAYS. The periodic `recheck` task looks the record up again: present, the proof is
extended; gone, the domain is no longer an asset until someone verifies it again. The TXT proves technical control
of the DNS zone, not authorization to test anything: that stays with whoever operates Pitangus.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import secrets
import socket
import ssl
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert

from pitangus.modules.sources.tables import domain_registry
from pitangus.shared import db, documents
from pitangus.shared import log as logging_setup
from pitangus.shared.db import TENANT
from pitangus.shared.i18n import msg, text
from pitangus.version import USER_AGENT

_log = logging_setup.get("domains")


class DomainError(ValueError):
    """`message` is what people read (rendered per reader); str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


KINDS = ("web", "api", "surface")
CONTEXT_LIMIT = 400
LIMIT = 20            # registered domains per workspace
VERIFY_DAYS = 90      # how long one sighting of the TXT record counts
RECHECK_SECONDS = 24 * 3600
ID = re.compile(r"[0-9a-f]{24}")
KEY_PREFIX = "domain:"


def asset_key(host: str) -> str:
    return f"{KEY_PREFIX}{host}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _row(row, now: datetime | None = None) -> dict:
    now = now or _now()
    verified = bool(row.verified_at and row.verified_until and row.verified_until > now)
    return {"id": row.id, "host": row.host, "url": row.url, "kind": row.kind, "context": row.context,
            "txt_name": row.txt_name, "txt_value": row.txt_value, "registered_by": row.registered_by,
            "registered_at": _iso(row.registered_at), "verified": verified, "verified_at": _iso(row.verified_at),
            "verified_until": _iso(row.verified_until), "checked_at": _iso(row.checked_at),
            "expired": bool(row.verified_at and not verified), "key": asset_key(row.host)}


def list_domains(data_dir: Path) -> list[dict]:
    """Every registered domain, oldest first."""
    with db.transaction(data_dir) as connection:
        rows = connection.execute(select(domain_registry).where(domain_registry.c.tenant_id == TENANT)
                                  .order_by(domain_registry.c.registered_at, domain_registry.c.id)).all()
    now = _now()
    return [_row(row, now) for row in rows]


def get_domain(data_dir: Path, domain_id: str) -> dict:
    if not isinstance(domain_id, str) or not ID.fullmatch(domain_id):
        raise DomainError(msg("sources.domains.invalid_id"))
    with db.transaction(data_dir) as connection:
        row = connection.execute(select(domain_registry).where(domain_registry.c.tenant_id == TENANT, domain_registry.c.id == domain_id)).first()
    if row is None:
        raise DomainError(msg("sources.domains.not_found"))
    return _row(row)


def find_domain(data_dir: Path, wanted: str) -> dict | None:
    """The domain named by its asset key (`domain:<host>`), its host or its id; None if there is none."""
    if not isinstance(wanted, str) or not wanted:
        return None
    needle = wanted.strip().lower()
    host = needle.removeprefix(KEY_PREFIX).rstrip(".")
    with db.transaction(data_dir) as connection:
        row = connection.execute(select(domain_registry).where(domain_registry.c.tenant_id == TENANT, domain_registry.c.host == host)).first() \
            or (connection.execute(select(domain_registry).where(domain_registry.c.tenant_id == TENANT, domain_registry.c.id == needle)).first()
                if ID.fullmatch(needle) else None)
    return _row(row) if row else None


def source_for(record: dict) -> dict:
    """The `source` a run against this domain carries (what `runs/imports.py` stores)."""
    return {"id": record["key"], "name": record["host"], "provider": "domain",
            "domain": {"id": record["id"], "host": record["host"], "url": record["url"], "kind": record["kind"]}}


def _host(url: str) -> tuple[str, str]:
    if not isinstance(url, str) or len(url) > 300:
        raise DomainError(msg("sources.domains.invalid_url"))
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise DomainError(msg("sources.domains.invalid_url_port")) from exc
    if (parsed.scheme != "https" or parsed.username or parsed.password or port is not None
            or parsed.fragment or parsed.query or not host or len(host) > 253):
        raise DomainError(msg("sources.domains.https_only"))
    labels = host.split(".")
    if (len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
            or not re.fullmatch(r"[a-z]{2,63}", labels[-1])
            or labels[-1] in {"local", "test", "invalid", "internal", "localhost"}):
        raise DomainError(msg("sources.domains.invalid_domain"))
    return host, f"https://{host}{parsed.path or '/'}"


def _declared_context(value) -> str:
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or len(value) > CONTEXT_LIMIT:
        raise DomainError(msg("sources.domains.context_length", max=CONTEXT_LIMIT))
    cleaned = " ".join(value.split())
    if any(ord(character) < 32 or ord(character) == 127 for character in cleaned):
        raise DomainError(msg("sources.domains.context_control"))
    return cleaned


def register_domain(data_dir: Path, url: str, kind: str = "web", context: str = "", *, by: str = "") -> dict:
    host, normalized = _host(url)
    if kind not in KINDS:
        raise DomainError(msg("sources.domains.invalid_kind"))
    declared = _declared_context(context)
    with db.transaction(data_dir) as connection:
        db.lock(connection, "domain-registry")
        rows = connection.execute(select(domain_registry.c.host).where(domain_registry.c.tenant_id == TENANT)).scalars().all()
        if host in rows:
            raise DomainError(msg("sources.domains.already_registered"))
        if len(rows) >= LIMIT:
            raise DomainError(msg("sources.domains.limit"))
        domain_id = secrets.token_hex(12)
        connection.execute(insert(domain_registry).values(
            tenant_id=TENANT, id=domain_id, host=host, url=normalized, kind=kind, context=declared,
            txt_name=f"_pitangus.{host}", txt_value=f"pitangus-verify={secrets.token_urlsafe(24)}", registered_by=by[:200]))
    return get_domain(data_dir, domain_id)


def lookup_txt(name: str) -> list[str] | None:
    """The TXT values published under `name`, or None when DNS couldn't be asked (a failure proves nothing)."""
    if not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_.-]{0,252})", name):
        return None
    try:
        result = subprocess.run(["dig", "+short", "+time=4", "+tries=1", "TXT", name], capture_output=True,
                                text=True, timeout=8, check=False, env={"PATH": "/usr/bin:/bin"})
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return [line.strip().strip('"').replace('" "', '') for line in result.stdout.splitlines()]


def _mark(data_dir: Path, domain_id: str, **values) -> dict:
    with db.transaction(data_dir) as connection:
        connection.execute(update(domain_registry).where(domain_registry.c.tenant_id == TENANT, domain_registry.c.id == domain_id).values(**values))
    return get_domain(data_dir, domain_id)


def verify_domain(data_dir: Path, domain_id: str, *, now: datetime | None = None) -> dict:
    """Looks the TXT record up once; seen, the domain counts as verified for VERIFY_DAYS from now."""
    record = get_domain(data_dir, domain_id)
    now = now or _now()
    values = lookup_txt(record["txt_name"])
    if values is None:
        raise DomainError(msg("sources.domains.dns_unavailable"))
    if record["txt_value"] not in values:
        _mark(data_dir, domain_id, checked_at=now)
        raise DomainError(msg("sources.domains.txt_missing"))
    return _mark(data_dir, domain_id, verified_at=now, verified_until=now + timedelta(days=VERIFY_DAYS), checked_at=now)


def recheck(data_dir: Path, *, now: datetime | None = None) -> dict:
    """The periodic re-verification: every domain with a proof is looked up again. Present, the proof is extended;
    gone, it is withdrawn (the TXT was removed: whoever controls the zone no longer vouches). DNS not answering
    changes nothing: the proof simply runs out at `verified_until`."""
    now = now or _now()
    outcome = {"kept": 0, "withdrawn": 0, "unanswered": 0}
    for record in list_domains(data_dir):
        if not record["verified_at"]:
            continue
        values = lookup_txt(record["txt_name"])
        if values is None:
            outcome["unanswered"] += 1
            continue
        if record["txt_value"] in values:
            _mark(data_dir, record["id"], verified_until=now + timedelta(days=VERIFY_DAYS), checked_at=now)
            outcome["kept"] += 1
        else:
            _mark(data_dir, record["id"], verified_at=None, verified_until=None, checked_at=now)
            outcome["withdrawn"] += 1
            _log.warning("domain_proof_withdrawn", extra={"reason": record["host"]})
    return outcome


def remove_domain(data_dir: Path, domain_id: str) -> dict:
    """Deletes the row and returns what it was (the caller purges the asset's runs, if any)."""
    record = get_domain(data_dir, domain_id)
    with db.transaction(data_dir) as connection:
        connection.execute(delete(domain_registry).where(domain_registry.c.tenant_id == TENANT, domain_registry.c.id == domain_id))
    return record


def import_document(data_dir: Path) -> int:
    """The `domains` document of earlier versions → one row per domain (data migration). Returns how many."""
    payload = documents.load(data_dir, "domains", None)
    if not isinstance(payload, list):
        return 0
    moved = 0
    with db.transaction(data_dir) as connection:
        db.lock(connection, "domain-registry")
        for entry in payload:
            if not isinstance(entry, dict) or not isinstance(entry.get("host"), str) or not ID.fullmatch(str(entry.get("id") or "")):
                continue
            verified_at = _moment(entry.get("verified_at")) if entry.get("verified") else None
            connection.execute(insert(domain_registry).values(
                tenant_id=TENANT, id=entry["id"], host=entry["host"], url=entry.get("url") or f"https://{entry['host']}/",
                kind=entry.get("kind") if entry.get("kind") in KINDS else "web", context=str(entry.get("context") or "")[:CONTEXT_LIMIT],
                txt_name=entry.get("txt_name") or f"_pitangus.{entry['host']}", txt_value=str(entry.get("txt_value") or ""),
                registered_at=_moment(entry.get("registered_at")) or _now(), verified_at=verified_at,
                verified_until=verified_at + timedelta(days=VERIFY_DAYS) if verified_at else None, checked_at=verified_at,
            ).on_conflict_do_nothing())
            moved += 1
    documents.delete(data_dir, "domains")
    return moved


def _moment(value) -> datetime | None:
    try:
        moment = datetime.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        return None
    return moment.replace(tzinfo=timezone.utc) if moment and moment.tzinfo is None else moment


def _is_public(address: str) -> bool:
    try:
        return ipaddress.ip_address(address.split("%")[0]).is_global
    except ValueError:
        return False


def check_reachability(url: str) -> dict:
    """Tells whether the target answers over HTTPS before registering it.

    Not a security test or a pentest: a single-hop HEAD, no redirects. It
    resolves the host and requires every address to be public before
    connecting, then connects to the already-resolved IP so the probe cannot
    end up at an internal address.
    """
    host, normalized = _host(url)
    path = urlsplit(normalized).path or "/"
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return {"host": host, "reachable": False, "status": "dns_error",
                "detail": msg("sources.domains.check.dns_error")}
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        return {"host": host, "reachable": False, "status": "dns_error",
                "detail": msg("sources.domains.check.dns_error")}
    if not all(_is_public(address) for address in addresses):
        return {"host": host, "reachable": False, "status": "private_address",
                "detail": msg("sources.domains.check.private_address")}
    ssl_context = ssl.create_default_context()
    try:
        with socket.create_connection((addresses[0], 443), timeout=6) as raw:
            with ssl_context.wrap_socket(raw, server_hostname=host) as secure:
                connection = http.client.HTTPSConnection(host, 443, timeout=6)
                connection.sock = secure
                connection.request("HEAD", path, headers={
                    "Host": host, "User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"})
                code = connection.getresponse().status
    except ssl.SSLCertVerificationError:
        return {"host": host, "reachable": False, "status": "tls_error",
                "detail": msg("sources.domains.check.tls_error")}
    except (OSError, http.client.HTTPException):
        return {"host": host, "reachable": False, "status": "unreachable",
                "detail": msg("sources.domains.check.unreachable")}
    return {"host": host, "reachable": True, "status": "reachable", "http_status": code,
            "detail": msg("sources.domains.check.reachable", code=code, address=addresses[0])}
