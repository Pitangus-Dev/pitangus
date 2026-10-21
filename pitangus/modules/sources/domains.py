"""Registry of HTTPS targets, with a proof of control before they count as assets.

A domain becomes the asset `domain:<host>` once one proof is seen, and stays one for VERIFY_DAYS:

* **dns**: the TXT record `_pitangus.<host>` = `pitangus-verify=<token>`, asked to the zone's own nameservers.
* **file**: `https://<host>/.well-known/pitangus-verify.txt` answering 200 with the token in its body.
* **meta**: `<meta name="pitangus-verify" content="<token>">` in the homepage (`https://<host>/`).

The periodic `recheck` task asks the same proof again: present, it is extended; gone, the domain is no longer an
asset until someone verifies it again. Only a DNS proof covers subdomains (whoever controls the zone controls them);
a file or a meta tag proves that exact host. HTTPS fetches go to an address already checked as public, with SNI and
certificate validation for the name, no redirects, short timeouts and a 64 KB cap. A proof shows technical control,
not authorization to test anything: that stays with whoever operates Pitangus.
"""

from __future__ import annotations

import http.client
import re
import secrets
import socket
import ssl
import subprocess
import time
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert

from pitangus.modules.sources import domain_schedule
from pitangus.modules.sources.domain_schedule import ScheduleError
from pitangus.modules.sources.tables import domain_registry
from pitangus.shared import db, documents
from pitangus.shared import log as logging_setup
from pitangus.shared.addresses import is_public
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
VERIFY_DAYS = 90      # how long one sighting of the proof counts
RECHECK_SECONDS = 24 * 3600
ID = re.compile(r"[0-9a-f]{24}")
KEY_PREFIX = "domain:"
PROOF_METHODS = ("dns", "file", "meta")
TOKEN_PREFIX = "pitangus-verify="  # gitleaks:allow
WELL_KNOWN = "/.well-known/pitangus-verify.txt"
META_NAME = "pitangus-verify"
BODY_LIMIT = 64 * 1024
FETCH_SECONDS = 10    # a whole HTTPS fetch, however slowly the server answers
SCOPE_LIMIT = 20      # hosts a scan may list
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
HOST_CHARACTERS = re.compile(r"[a-z0-9.-]{1,253}")


# Demo data (`pitangus demo --full`) registers its domains as this, under names reserved for documentation (RFC 2606).
DEMO_BY = "demo"
DEMO_ZONES = ("example.com", "example.net", "example.org")


def asset_key(host: str) -> str:
    return f"{KEY_PREFIX}{host}"


def is_demo(record: dict) -> bool:
    """A domain of the demo data: nobody can prove control of a reserved name, so its proof is never asked again and
    nothing scans it (no query leaves the machine on its behalf)."""
    host = str(record.get("host") or "")
    return record.get("registered_by") == DEMO_BY and any(host == zone or host.endswith("." + zone) for zone in DEMO_ZONES)


def vouch_demo(data_dir: Path, domain_id: str, *, at: datetime, method: str = "dns") -> dict:
    """Marks a demo domain as verified on `at`, as if its proof had been seen then. Only for `is_demo` domains."""
    record = get_domain(data_dir, domain_id)
    if not is_demo(record) or method not in PROOF_METHODS:
        raise DomainError(msg("sources.domains.invalid_request"))
    return _mark(data_dir, domain_id, verified_at=at, verified_until=at + timedelta(days=VERIFY_DAYS), checked_at=at,
                 proof_method=method, registered_at=min(at, _now()))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def token(record: dict) -> str:
    """The random part of the TXT value: what the file and the meta tag carry."""
    return str(record.get("txt_value") or "").removeprefix(TOKEN_PREFIX)


def _row(row, now: datetime | None = None) -> dict:
    now = now or _now()
    verified = bool(row.verified_at and row.verified_until and row.verified_until > now)
    secret = row.txt_value.removeprefix(TOKEN_PREFIX)
    return {"id": row.id, "host": row.host, "url": row.url, "kind": row.kind, "context": row.context,
            "txt_name": row.txt_name, "txt_value": row.txt_value, "registered_by": row.registered_by,
            "registered_at": _iso(row.registered_at), "verified": verified, "verified_at": _iso(row.verified_at),
            "verified_until": _iso(row.verified_until), "checked_at": _iso(row.checked_at),
            "expired": bool(row.verified_at and not verified), "key": asset_key(row.host),
            "proof_method": row.proof_method if row.verified_at else None, "session_check": row.session_check or None,
            "verify_token": secret, "verify_file_url": f"https://{row.host}{WELL_KNOWN}",
            "verify_meta": f'<meta name="{META_NAME}" content="{secret}">',
            "schedule": _schedule(row, now)}


def _schedule(row, now: datetime) -> dict | None:
    """The rule with when it runs next and what happened last time. A weekly schedule from before rules existed (no
    `schedule_rule` yet: the data migration writes it) reads as the weekday and time of its next run, in UTC."""
    if not row.schedule:
        return None
    rule = row.schedule_rule if isinstance(row.schedule_rule, dict) else domain_schedule.legacy(row.schedule_next_at, now=now)
    return {**domain_schedule.timing(rule), **domain_schedule.access(rule), "next_run_at": _iso(row.schedule_next_at), "last_run_at": _iso(row.schedule_last_at),
            "last_run_id": row.schedule_last_run, "note": row.schedule_note}


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


def valid_host(host: str) -> bool:
    """A public DNS name: letters, digits and hyphens per label, an alphabetic TLD that isn't a reserved one."""
    labels = host.split(".")
    return (len(labels) >= 2 and len(host) <= 253 and all(LABEL.fullmatch(label) for label in labels)
            and re.fullmatch(r"[a-z]{2,63}", labels[-1]) is not None
            and labels[-1] not in {"local", "test", "invalid", "internal", "localhost"})


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
    # Checked on the very string requests are sent to: letters, digits, dots and hyphens only; valid_host, its shape.
    if not HOST_CHARACTERS.fullmatch(host) or not valid_host(host):
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
            txt_name=f"_pitangus.{host}", txt_value=f"{TOKEN_PREFIX}{secrets.token_urlsafe(24)}", registered_by=by[:200]))
    return get_domain(data_dir, domain_id)


NAMESERVER = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}\.)+[a-z0-9-]{1,63}\.?")


def _dig(*args: str) -> list[str] | None:
    """`dig +short` lines, or None when it couldn't answer. Arguments are fixed or validated: no shell, fixed PATH."""
    try:
        result = subprocess.run(["dig", "+short", "+time=4", "+tries=1", *args], capture_output=True,
                                text=True, timeout=8, check=False, env={"PATH": "/usr/bin:/bin"})
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.splitlines() if result.returncode == 0 else None


def _nameservers(name: str) -> list[str]:
    """The authoritative nameservers of the zone that holds `name`: the closest parent with an NS record."""
    labels = name.split(".")
    for start in range(1, len(labels) - 1):
        servers = [line.strip().lower() for line in (_dig("NS", ".".join(labels[start:])) or [])]
        servers = [server for server in servers if NAMESERVER.fullmatch(server)]
        if servers:
            return servers[:4]
    return []


def lookup_txt(name: str) -> list[str] | None:
    """The TXT values published under `name`, or None when DNS couldn't be asked (a failure proves nothing).

    Asked to the zone's own nameservers first: a resolver that looked before the record existed keeps that "no such
    name" for the zone's negative TTL (30 minutes on Cloudflare), and the record would seem missing long after it was
    published. The local resolver is the fallback, for networks that only allow DNS through it."""
    if not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_.-]{0,252})", name):
        return None
    lines = None
    for server in _nameservers(name):
        lines = _dig(f"@{server}", "TXT", name)
        if lines is not None:
            break
    if lines is None:
        lines = _dig("TXT", name)
    if lines is None:
        return None
    return [line.strip().strip('"').replace('" "', '') for line in lines]


def set_session_check(data_dir: Path, domain_id: str, url: str) -> dict:
    """Saves the page that proves the saved headers still carry a session (already checked; empty clears it)."""
    return _mark(data_dir, domain_id, session_check=url)


def _mark(data_dir: Path, domain_id: str, **values) -> dict:
    with db.transaction(data_dir) as connection:
        connection.execute(update(domain_registry).where(domain_registry.c.tenant_id == TENANT, domain_registry.c.id == domain_id).values(**values))
    return get_domain(data_dir, domain_id)


class _MetaTags(HTMLParser):
    """The `content` of every `<meta name="pitangus-verify">`, however the page is written; nothing else is kept."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.found: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "meta":
            values = {str(name).lower(): value or "" for name, value in attrs}
            if values.get("name", "").strip().lower() == META_NAME:
                self.found.append(values.get("content", "").strip())

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)


def meta_tokens(page: bytes) -> list[str]:
    parser = _MetaTags()
    try:
        parser.feed(page[:BODY_LIMIT].decode("utf-8", errors="replace"))
        parser.close()
    except (AssertionError, ValueError):  # malformed markup: whatever was read so far counts
        pass
    return parser.found


def tls_context() -> ssl.SSLContext:
    """Certificate and name validation, and TLS 1.2 at least whatever the interpreter or OpenSSL defaults to."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def https_get(host: str, address: str, path: str, *, limit: int = BODY_LIMIT, seconds: int = FETCH_SECONDS,
              headers=()) -> tuple[int, bytes]:
    """One GET of `https://<host><path>` sent to `address` (already checked as public) with SNI and certificate
    validation for `host`. No redirects, no proxy, at most `limit` + 1 bytes (so a caller sees it was larger) and
    `seconds` in all; `headers`: (name, value) pairs to add (the domain's saved ones, already validated). Raises
    OSError, ssl.SSLError or http.client.HTTPException when it can't."""
    deadline = time.monotonic() + seconds
    ssl_context = tls_context()
    with socket.create_connection((address, 443), timeout=6) as raw:
        with ssl_context.wrap_socket(raw, server_hostname=host) as secure:
            connection = http.client.HTTPSConnection(host, 443, timeout=6)
            connection.sock = secure
            connection.request("GET", path, headers={**dict(headers), "Host": host, "User-Agent": USER_AGENT, "Accept": "*/*",
                                                     "Accept-Encoding": "identity", "Connection": "close"})
            response = connection.getresponse()
            body = b""
            while response.status == 200 and len(body) <= limit:
                if time.monotonic() > deadline:
                    raise TimeoutError("the body took too long")
                chunk = response.read(min(65536, limit + 1 - len(body)))
                if not chunk:
                    break
                body += chunk
            return response.status, body


def _fetch_proof(record: dict, method: str) -> tuple[bool | None, object]:
    """(present, reason) for the file or meta proof: None when the host couldn't be asked (that proves nothing)."""
    host = record["host"]
    path = WELL_KNOWN if method == "file" else "/"
    url = f"https://{host}{path}"
    try:
        address = public_address(host)
        status, body = https_get(host, address, path)
    except DomainError as exc:
        return None, exc.message
    except (OSError, ssl.SSLError, http.client.HTTPException):
        return None, msg("sources.domains.proof_unreachable", host=host)
    if 300 <= status < 400:
        return False, msg("sources.domains.redirected", url=url, code=status)
    if status >= 500:
        return None, msg("sources.domains.proof_unreachable", host=host)
    secret = token(record)
    if status == 200 and len(body) <= BODY_LIMIT and len(secret) >= 16:
        if method == "file" and secret.encode() in body:
            return True, None
        if method == "meta" and any(found in (secret, record["txt_value"]) for found in meta_tokens(body)):
            return True, None
    return False, (msg("sources.domains.file_missing", url=url) if method == "file"
                   else msg("sources.domains.meta_missing", host=host))


def proof_present(record: dict, method: str | None = None) -> tuple[bool | None, object]:
    """(present, reason): whether the domain's proof (`method`, else the one that verified it) is there right now.
    None: DNS or the host couldn't be asked, which proves nothing either way."""
    method = method or record.get("proof_method") or "dns"
    if method in ("file", "meta"):
        return _fetch_proof(record, method)
    values = lookup_txt(record["txt_name"])
    if values is None:
        return None, msg("sources.domains.dns_unavailable")
    return (True, None) if record["txt_value"] in values else (False, msg("sources.domains.txt_missing"))


def _gone(record: dict, method: str):
    key = {"file": "sources.domains.proof_gone_file", "meta": "sources.domains.proof_gone_meta"}.get(method, "sources.domains.proof_gone")
    return msg(key, host=record["host"])


def verify_domain(data_dir: Path, domain_id: str, method: str = "dns", *, now: datetime | None = None) -> dict:
    """Asks for the proof once (DNS TXT, the well-known file or the meta tag); seen, the domain counts as verified
    for VERIFY_DAYS from now, and the re-check asks that same proof again."""
    if method not in PROOF_METHODS:
        raise DomainError(msg("sources.domains.invalid_method"))
    record = get_domain(data_dir, domain_id)
    now = now or _now()
    present, reason = proof_present(record, method)
    if present is None:
        raise DomainError(reason)
    if not present:
        _mark(data_dir, domain_id, checked_at=now)
        raise DomainError(reason)
    return _mark(data_dir, domain_id, verified_at=now, verified_until=now + timedelta(days=VERIFY_DAYS), checked_at=now,
                 proof_method=method)


def confirm_control(data_dir: Path, domain_id: str, *, now: datetime | None = None) -> dict:
    """The domain, only if its proof is current and still published right now: what a scan that reaches it checks
    before it starts. A proof gone withdraws it, as `recheck` does; DNS or the host not answering proves nothing, so
    nothing starts either."""
    record = get_domain(data_dir, domain_id)
    if is_demo(record):
        raise DomainError(msg("sources.domains.demo", host=record["host"]))
    if not record["verified"]:
        raise DomainError(msg("sources.domains.not_verified", host=record["host"]))
    present, reason = proof_present(record)
    if present is None:
        raise DomainError(reason)
    if not present:
        _mark(data_dir, domain_id, verified_at=None, verified_until=None, checked_at=now or _now())
        _log.warning("domain_proof_withdrawn", extra={"reason": record["host"]})
        raise DomainError(_gone(record, record["proof_method"] or "dns"))
    return record


def recheck(data_dir: Path, *, now: datetime | None = None) -> dict:
    """The periodic re-verification: every domain with a proof asks the same proof again. Present, it is extended;
    gone, it is withdrawn (whoever controls the zone or the site no longer vouches). Not answering changes nothing:
    the proof simply runs out at `verified_until`."""
    now = now or _now()
    outcome = {"kept": 0, "withdrawn": 0, "unanswered": 0}
    for record in list_domains(data_dir):
        if not record["verified_at"] or is_demo(record):
            continue
        present, _ = proof_present(record)
        if present is None:
            outcome["unanswered"] += 1
            continue
        if present:
            _mark(data_dir, record["id"], verified_until=now + timedelta(days=VERIFY_DAYS), checked_at=now)
            outcome["kept"] += 1
        else:
            _mark(data_dir, record["id"], verified_at=None, verified_until=None, checked_at=now)
            outcome["withdrawn"] += 1
            _log.warning("domain_proof_withdrawn", extra={"reason": record["host"]})
    return outcome


def remove_domain(data_dir: Path, domain_id: str) -> dict:
    """Deletes the row (its test users go with it, by foreign key) and its saved headers, and returns what it was (the
    caller purges the asset's runs, if any)."""
    from pitangus.modules.sources import domain_headers
    record = get_domain(data_dir, domain_id)
    with db.transaction(data_dir) as connection:
        connection.execute(delete(domain_registry).where(domain_registry.c.tenant_id == TENANT, domain_registry.c.id == domain_id))
    domain_headers.forget(domain_id)
    return record


def scan_scope(record: dict, hosts=None) -> dict:
    """The hosts a scan of `record` may reach: its own host, plus the subdomains listed in `hosts` (at most
    SCOPE_LIMIT entries, `name` or `*.name`). Only a DNS proof covers subdomains; a file or meta proof keeps the scan
    on the registered host. Wildcards only widen ZAP's context: just the hosts named one by one are pinned to a
    checked address and crawled (the container resolves nothing else)."""
    root = record["host"]
    hosts = [] if hosts is None else hosts
    if not isinstance(hosts, list) or len(hosts) > SCOPE_LIMIT:
        raise DomainError(msg("sources.domains.scope.too_many", max=SCOPE_LIMIT))
    concrete, wildcards = [root], []
    for entry in hosts:
        if not isinstance(entry, str) or len(entry) > 260:
            raise DomainError(msg("sources.domains.scope.invalid_host", host=str(entry)[:80]))
        name = entry.strip().lower().rstrip(".")
        wildcard = name.startswith("*.")
        bare = name[2:] if wildcard else name
        if not valid_host(bare):
            raise DomainError(msg("sources.domains.scope.invalid_host", host=name[:80]))
        if bare != root and not bare.endswith("." + root):
            raise DomainError(msg("sources.domains.scope.outside", host=name, root=root))
        if (wildcard or bare != root) and (record.get("proof_method") or "dns") != "dns":
            raise DomainError(msg("sources.domains.scope.needs_dns", host=name, root=root))
        if wildcard and name not in wildcards:
            wildcards.append(name)
        elif not wildcard and bare not in concrete:
            concrete.append(bare)
    return {"hosts": concrete, "wildcards": wildcards}


def page_of(url: str) -> str | None:
    """A URL as a page a crawl reached: scheme, host and path, without query or fragment or a trailing slash, its
    repeated slashes as one. Two visits to one page with different parameters are the same page. None for what isn't an
    http(s) URL."""
    try:
        parts = urlsplit(str(url or ""))
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    port = f":{parts.port}" if parts.port and parts.port != (443 if parts.scheme == "https" else 80) else ""
    # Repeated slashes are one: `//.env` and `/.env` are the same request for every tool a scan runs.
    return f"{parts.scheme}://{parts.hostname.lower()}{port}{re.sub('/{2,}', '/', parts.path).rstrip('/') or '/'}"


def in_scope(host: str, scope: dict) -> bool:
    """`host` is one of the scope's hosts or a subdomain matched by one of its wildcards."""
    host = (host or "").lower().rstrip(".")
    return host in scope.get("hosts", []) or any(host.endswith(pattern[1:]) for pattern in scope.get("wildcards", []))


def set_schedule(data_dir: Path, domain_id: str, rule: dict | None, *, now: datetime | None = None,
                 last_scan_at: datetime | None = None) -> dict:
    """Sets the scheduled passive scan (`domain_schedule` rule) or turns it off (None). The next run is the rule's first
    moment after now, never on the local day of the domain's last scan (`last_scan_at`): at most one a day. Saving
    the same rule again keeps the next run, so a slot that is due but not yet queued isn't lost."""
    now = now or _now()
    record = get_domain(data_dir, domain_id)
    if rule is None:
        return _mark(data_dir, domain_id, schedule=None, schedule_rule=None, schedule_next_at=None, schedule_note=None)
    try:
        rule = domain_schedule.normalize(rule)
    except ScheduleError as exc:
        raise DomainError(exc.message) from exc
    current = record["schedule"]
    if current and current["next_run_at"] and domain_schedule.timing(current) == domain_schedule.timing(rule):
        # Same moments: only what the scan does may change, and a due slot isn't lost.
        if domain_schedule.access(current) == domain_schedule.access(rule):
            return record
        return _mark(data_dir, domain_id, schedule_rule=rule)
    not_on = domain_schedule.local_day(last_scan_at, rule) if last_scan_at else None
    return _mark(data_dir, domain_id, schedule=rule["frequency"], schedule_rule=rule, schedule_note=None,
                 schedule_next_at=domain_schedule.next_run(rule, now, not_on=not_on))


def due_scans(data_dir: Path, *, now: datetime | None = None, lock: bool = False) -> list[dict]:
    """Domains whose scheduled scan is due, the longest overdue first. `lock`: their rows stay locked until the
    caller's transaction ends (and rows another round holds are left out), so queuing a scan and moving the schedule
    on happen together or not at all."""
    now = now or _now()
    statement = select(domain_registry).where(
        domain_registry.c.tenant_id == TENANT, domain_registry.c.schedule.in_(domain_schedule.FREQUENCIES),
        domain_registry.c.schedule_next_at <= now).order_by(domain_registry.c.schedule_next_at, domain_registry.c.id)
    with db.transaction(data_dir) as connection:
        rows = connection.execute(statement.with_for_update(skip_locked=True) if lock else statement).all()
    return [_row(row, now) for row in rows]


def _rule(record: dict) -> dict:
    return {**domain_schedule.timing(record["schedule"]), **domain_schedule.access(record["schedule"])}


def schedule_queued(data_dir: Path, domain_id: str, run_id: str, *, now: datetime | None = None, note=None,
                    gone_users: list[str] | None = None) -> dict:
    """The scheduled scan was queued now: the next one is the rule's next moment on a later local day. `note` says what
    it left out; `gone_users`, test users deleted since they were chosen, leave the rule."""
    now = now or _now()
    rule = _rule(get_domain(data_dir, domain_id))
    if gone_users:
        rule["test_users"] = [user for user in rule["test_users"] if user not in gone_users]
    return _mark(data_dir, domain_id, schedule_last_at=now, schedule_last_run=run_id, schedule_note=note, schedule_rule=rule,
                 schedule_next_at=domain_schedule.next_run(rule, now, not_on=domain_schedule.local_day(now, rule)))


def schedule_skipped(data_dir: Path, domain_id: str, note, *, now: datetime | None = None) -> dict:
    """The scan was due and didn't start (`note` says why): it stays due, so the next round tries again."""
    return _mark(data_dir, domain_id, schedule_last_at=now or _now(), schedule_note=note)


def schedule_moved(data_dir: Path, domain_id: str, note, *, after: datetime, not_on, now: datetime | None = None) -> dict:
    """The slot is dropped (`note` says why) and the schedule moves on to its next moment after `not_on`."""
    rule = _rule(get_domain(data_dir, domain_id))
    return _mark(data_dir, domain_id, schedule_last_at=now or _now(), schedule_note=note, schedule_rule=rule,
                 schedule_next_at=domain_schedule.next_run(rule, after, not_on=not_on))


def adopt_schedule_rules(data_dir: Path) -> int:
    """Weekly schedules from before rules existed get theirs (data migration `scan_schedule_rules`): the weekday and
    time of their next run, in UTC, so they keep firing when they would have. Returns how many."""
    now = _now()
    moved = 0
    with db.transaction(data_dir) as connection:
        rows = connection.execute(select(domain_registry.c.id, domain_registry.c.schedule_next_at).where(
            domain_registry.c.tenant_id == TENANT, domain_registry.c.schedule.is_not(None),
            domain_registry.c.schedule_rule.is_(None)).with_for_update()).all()
        for row in rows:
            rule = domain_schedule.legacy(row.schedule_next_at, now=now)
            connection.execute(update(domain_registry).where(domain_registry.c.tenant_id == TENANT, domain_registry.c.id == row.id)
                               .values(schedule="weekly", schedule_rule=rule, schedule_next_at=row.schedule_next_at or now))
            moved += 1
    return moved


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


def public_address(host: str) -> str:
    """The address a scan of `host` is pinned to, once every address the name resolves to is public (no loopback,
    private, link-local or cloud metadata range). IPv4 first: Docker's default bridge often has no IPv6 route."""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise DomainError(msg("sources.domains.check.dns_error")) from exc
    addresses = sorted({info[4][0].split("%")[0] for info in infos}, key=lambda address: (":" in address, address))
    if not addresses:
        raise DomainError(msg("sources.domains.check.dns_error"))
    if not all(is_public(address) for address in addresses):
        raise DomainError(msg("sources.domains.check.private_address"))
    return addresses[0]


def check_reachability(url: str) -> dict:
    """Tells whether the target answers over HTTPS before registering it.

    Not a security test or a pentest: a single-hop HEAD, no redirects. It
    resolves the host and requires every address to be public before
    connecting, then connects to the already-resolved IP so the probe cannot
    end up at an internal address. `public` is None when the name doesn't resolve.
    """
    host, normalized = _host(url)
    path = urlsplit(normalized).path or "/"
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return {"host": host, "reachable": False, "status": "dns_error", "https": False, "public": None,
                "detail": msg("sources.domains.check.dns_error")}
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        return {"host": host, "reachable": False, "status": "dns_error", "https": False, "public": None,
                "detail": msg("sources.domains.check.dns_error")}
    if not all(is_public(address) for address in addresses):
        return {"host": host, "reachable": False, "status": "private_address", "https": False, "public": False,
                "detail": msg("sources.domains.check.private_address")}
    ssl_context = tls_context()
    try:
        with socket.create_connection((addresses[0], 443), timeout=6) as raw:
            with ssl_context.wrap_socket(raw, server_hostname=host) as secure:
                connection = http.client.HTTPSConnection(host, 443, timeout=6)
                connection.sock = secure
                connection.request("HEAD", path, headers={
                    "Host": host, "User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"})
                code = connection.getresponse().status
    except ssl.SSLCertVerificationError:
        return {"host": host, "reachable": False, "status": "tls_error", "https": False, "public": True,
                "detail": msg("sources.domains.check.tls_error")}
    except (OSError, http.client.HTTPException):
        return {"host": host, "reachable": False, "status": "unreachable", "https": False, "public": True,
                "detail": msg("sources.domains.check.unreachable")}
    return {"host": host, "reachable": True, "status": "reachable", "http_status": code, "https": True, "public": True,
            "detail": msg("sources.domains.check.reachable", code=code, address=addresses[0])}
