"""Test users: accounts a domain's web scans sign in with, saved once and picked per scan.

What identifies one for people (name, method, login page, notes, the host it applies to) is stored plain. The
username, password and TOTP seed are sealed together with the master key (AES-256-GCM, bound to the domain and the
row, so a sealed value can't be moved to another one) and never answered back: listings carry the username, the
method and dates, never a password or a seed. The worker opens them right before ZAP starts (`credentials`), which
registers them with the log filter; they reach ZAP through its environment, never through a file or the command line.

Two methods: `password` (username and password) and `password_totp` (plus the TOTP seed, with its digits, period and
algorithm). Codes sent by email and magic links need an inbox nobody here reads, so they aren't offered.
"""

from __future__ import annotations

import base64
import binascii
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert

from pitangus.modules.sources import domains
from pitangus.modules.sources.tables import domain_test_users
from pitangus.shared import db, vault
from pitangus.shared import log as logging_setup
from pitangus.shared.db import TENANT
from pitangus.shared.i18n import msg, text

LIMIT = 10              # test users per domain
PER_SCAN = 3            # test users one scan signs in with
METHODS = ("password", "password_totp")
NAME_MAX = 80
USERNAME_MAX = 256
PASSWORD_MAX = 1024
NOTES_MAX = 1000
URL_MAX = 2000
TOTP_DIGITS = (6, 7, 8)
TOTP_PERIODS = (15, 30, 60, 90, 120)
TOTP_ALGORITHMS = ("SHA1", "SHA256", "SHA512")
ID = re.compile(r"[0-9a-f]{24}")
BASE32 = re.compile(r"[A-Z2-7]+")


class TestUserError(ValueError):
    """`message` is what people read (rendered per reader); str() stays English, for logs."""

    def __init__(self, message):
        super().__init__(text(message, "en"))
        self.message = message


def _purpose(domain_id: str, user_id: str) -> str:
    return f"domain-test-user:{domain_id}:{user_id}"


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _id(value, error: str = "sources.domains.test_users.not_found") -> str:
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise TestUserError(msg(error))
    return value


def _line(value, limit: int, error: str, *, strip: bool = True) -> str:
    """One line of printable text: no control characters (no header or plan injection), and no `${`, which ZAP's
    Automation Framework would read as a variable and replace, so the account would sign in with something else."""
    if not isinstance(value, str):
        raise TestUserError(msg(error, max=limit))
    value = value.strip() if strip else value
    if not value or len(value) > limit or "${" in value or any(ord(character) < 32 or 127 <= ord(character) < 160 for character in value):
        raise TestUserError(msg(error, max=limit))
    return value


def check_name(value) -> str:
    return " ".join(_line(value, NAME_MAX, "sources.domains.test_users.invalid_name").split())


def check_notes(value) -> str:
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or len(value) > NOTES_MAX or any(ord(character) < 32 and character not in "\n\t" for character in value):
        raise TestUserError(msg("sources.domains.test_users.invalid_notes", max=NOTES_MAX))
    return value.strip()


def _under(host: str, root: str) -> bool:
    return host == root or host.endswith("." + root)


def check_applies_to(value, root: str) -> str:
    """The host the account belongs to: the domain's own (by default) or one of its subdomains."""
    if value is None or value == "":
        return root
    host = value.strip().lower().rstrip(".") if isinstance(value, str) else ""
    if not domains.valid_host(host):
        raise TestUserError(msg("sources.domains.test_users.invalid_host", host=str(value)[:80]))
    if not _under(host, root):
        raise TestUserError(msg("sources.domains.test_users.outside", host=host, root=root))
    return host


def check_login_url(value, root: str, error: str = "sources.domains.test_users.invalid_login_url") -> str:
    """Empty (the root of the host it applies to) or an HTTPS page on the domain or one of its subdomains. The same
    rule for the check page (`error` names which field it is)."""
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or len(value) > URL_MAX or any(ord(character) <= 32 or ord(character) == 127 for character in value.strip()) or "${" in value:
        raise TestUserError(msg(error))
    value = value.strip()
    try:
        parts = urlsplit(value)
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError as exc:
        raise TestUserError(msg(error)) from exc
    if parts.scheme != "https" or parts.username or parts.password or port is not None or not domains.valid_host(host):
        raise TestUserError(msg(error))
    if not _under(host, root):
        raise TestUserError(msg("sources.domains.test_users.outside", host=host, root=root))
    return value


def login_host(user: dict) -> str:
    return (urlsplit(user["login_url"]).hostname or "").lower().rstrip(".") if user.get("login_url") else user["applies_to"]


def reached_hosts(user: dict) -> list[str]:
    """Every host a test user's sign-in reaches: where it belongs, its login page and its check page."""
    check = (urlsplit(user["check_url"]).hostname or "").lower().rstrip(".") if user.get("check_url") else ""
    return list(dict.fromkeys(host for host in (user["applies_to"], login_host(user), check) if host))


def check_totp(value) -> dict:
    """The seed in base32 (spaces and case don't matter, as authenticator apps show it), at least 80 bits."""
    if not isinstance(value, dict):
        raise TestUserError(msg("sources.domains.test_users.totp_required"))
    seed = value.get("secret")
    seed = re.sub(r"[\s-]", "", seed).upper().rstrip("=") if isinstance(seed, str) else ""
    try:
        decoded = base64.b32decode(seed + "=" * (-len(seed) % 8)) if BASE32.fullmatch(seed or "-") and len(seed) <= 256 else b""
    except (binascii.Error, ValueError):
        decoded = b""
    if len(decoded) < 10:
        raise TestUserError(msg("sources.domains.test_users.invalid_totp"))
    digits, period, algorithm = value.get("digits", 6), value.get("period", 30), str(value.get("algorithm") or "SHA1").upper()
    if digits not in TOTP_DIGITS or period not in TOTP_PERIODS or algorithm not in TOTP_ALGORITHMS or isinstance(digits, bool) or isinstance(period, bool):
        raise TestUserError(msg("sources.domains.test_users.invalid_totp_options", digits="/".join(map(str, TOTP_DIGITS)),
                                periods="/".join(map(str, TOTP_PERIODS)), algorithms="/".join(TOTP_ALGORITHMS)))
    return {"secret": seed, "digits": digits, "period": period, "algorithm": algorithm}


def _shown(row, sealed: dict) -> dict:
    return {"id": row.id, "name": row.name, "method": row.method, "username": sealed.get("username", ""),
            "login_url": row.login_url or None, "check_url": row.check_url or None, "notes": row.notes or None, "applies_to": row.applies_to,
            "created_by": row.created_by or None, "created_at": _iso(row.created_at), "updated_at": _iso(row.updated_at),
            "last_used_at": _iso(row.last_used_at)}


def _open(row) -> dict:
    sealed = vault.unseal(row.secret, _purpose(row.domain_id, row.id))
    return sealed if isinstance(sealed, dict) else {}


def _rows(connection, domain_id: str, ids=None):
    query = select(domain_test_users).where(domain_test_users.c.tenant_id == TENANT, domain_test_users.c.domain_id == domain_id)
    if ids is not None:
        query = query.where(domain_test_users.c.id.in_(list(ids)))
    return connection.execute(query.order_by(domain_test_users.c.created_at, domain_test_users.c.id)).all()


def list_users(data_dir: Path, domain_id: str) -> list[dict]:
    """Every test user of the domain, oldest first, without passwords or seeds."""
    with db.transaction(data_dir) as connection:
        rows = _rows(connection, _id(domain_id, "sources.domains.invalid_id"))
    return [_shown(row, _open(row)) for row in rows]


def counts(data_dir: Path) -> dict[str, int]:
    """How many test users each domain has (one query for the whole list)."""
    with db.transaction(data_dir) as connection:
        rows = connection.execute(select(domain_test_users.c.domain_id, func.count()).where(domain_test_users.c.tenant_id == TENANT)
                                  .group_by(domain_test_users.c.domain_id)).all()
    return {row[0]: row[1] for row in rows}


def save(data_dir: Path, record: dict, data: dict, *, by: str = "") -> dict:
    """Adds a test user (no `id`) or changes one. On a change, the password and the seed are kept unless new ones
    come; switching to `password` drops the seed, switching to `password_totp` needs one. Returns the user as listed."""
    domain_id, root = record["id"], record["host"]
    method = data.get("method")
    if method not in METHODS:
        raise TestUserError(msg("sources.domains.test_users.invalid_method"))
    name = check_name(data.get("name"))
    username = _line(data.get("username"), USERNAME_MAX, "sources.domains.test_users.invalid_username")
    applies_to = check_applies_to(data.get("applies_to"), root)
    login_url = check_login_url(data.get("login_url"), root)
    check_url = check_login_url(data.get("check_url"), root, "sources.domains.test_users.invalid_check_url")
    notes = check_notes(data.get("notes"))
    password = data.get("password")
    password = None if password is None else _line(password, PASSWORD_MAX, "sources.domains.test_users.invalid_password", strip=False)
    totp = None if data.get("totp") is None else check_totp(data["totp"])
    user_id = data.get("id")
    now = datetime.now(timezone.utc)
    with db.transaction(data_dir) as connection:
        db.lock(connection, f"domain-test-users:{domain_id}")
        rows = _rows(connection, domain_id)
        if any(row.name.lower() == name.lower() and row.id != user_id for row in rows):
            raise TestUserError(msg("sources.domains.test_users.name_taken", name=name))
        if user_id is None:
            if len(rows) >= LIMIT:
                raise TestUserError(msg("sources.domains.test_users.limit", max=LIMIT))
            if password is None:
                raise TestUserError(msg("sources.domains.test_users.password_required"))
            if method == "password_totp" and totp is None:
                raise TestUserError(msg("sources.domains.test_users.totp_required"))
            user_id = secrets.token_hex(12)
            sealed = {"username": username, "password": password, **({"totp": totp} if method == "password_totp" else {})}
            connection.execute(insert(domain_test_users).values(
                tenant_id=TENANT, id=user_id, domain_id=domain_id, name=name, method=method, login_url=login_url, check_url=check_url, notes=notes,
                applies_to=applies_to, secret=vault.seal(sealed, _purpose(domain_id, user_id)), created_by=by[:200]))
        else:
            current = next((row for row in rows if row.id == _id(user_id)), None)
            if current is None:
                raise TestUserError(msg("sources.domains.test_users.not_found"))
            sealed = _open(current)
            sealed["username"] = username
            if password is not None:
                sealed["password"] = password
            if method == "password_totp":
                sealed["totp"] = totp or sealed.get("totp")
                if not sealed["totp"]:
                    raise TestUserError(msg("sources.domains.test_users.totp_required"))
            else:
                sealed.pop("totp", None)
            connection.execute(update(domain_test_users).where(domain_test_users.c.tenant_id == TENANT, domain_test_users.c.id == user_id)
                               .values(name=name, method=method, login_url=login_url, check_url=check_url, notes=notes, applies_to=applies_to,
                                       secret=vault.seal(sealed, _purpose(domain_id, user_id)), updated_at=now))
        (row,) = _rows(connection, domain_id, [user_id])
    _register(sealed)
    return _shown(row, sealed)


def remove(data_dir: Path, domain_id: str, user_id) -> None:
    with db.transaction(data_dir) as connection:
        gone = connection.execute(delete(domain_test_users).where(
            domain_test_users.c.tenant_id == TENANT, domain_test_users.c.domain_id == domain_id,
            domain_test_users.c.id == _id(user_id)).returning(domain_test_users.c.id)).first()
    if gone is None:
        raise TestUserError(msg("sources.domains.test_users.not_found"))


def check_selection(data_dir: Path, record: dict, ids, scope: dict) -> list[dict]:
    """The chosen test users, as listed, after checking they exist, belong to this domain, are at most PER_SCAN and
    sign in on hosts the scan reaches (the container resolves nothing else)."""
    ids = list(dict.fromkeys(ids or []))
    if len(ids) > PER_SCAN:
        raise TestUserError(msg("sources.domains.test_users.too_many", max=PER_SCAN))
    if not ids:
        return []
    with db.transaction(data_dir) as connection:
        rows = {row.id: row for row in _rows(connection, record["id"], [_id(item) for item in ids])}
    if len(rows) != len(ids):
        raise TestUserError(msg("sources.domains.test_users.not_found"))
    chosen = [_shown(rows[item], {}) for item in ids]
    for user in chosen:
        for host in reached_hosts(user):
            if host not in scope["hosts"]:
                raise TestUserError(msg("sources.domains.test_users.not_in_scope", name=user["name"], host=host))
    return chosen


def credentials(data_dir: Path, record: dict, ids, scope: dict) -> list[dict]:
    """For the scan about to start, and only for it: each chosen user with its username, password and seed. Marks
    them used. Raises TestUserError when one was removed or no longer fits the scope."""
    chosen = check_selection(data_dir, record, ids, scope)
    if not chosen:
        return []
    with db.transaction(data_dir) as connection:
        rows = {row.id: row for row in _rows(connection, record["id"], [user["id"] for user in chosen])}
        if len(rows) != len(chosen):  # removed since it was checked
            raise TestUserError(msg("sources.domains.test_users.not_found"))
        connection.execute(update(domain_test_users).where(domain_test_users.c.tenant_id == TENANT,
                                                           domain_test_users.c.id.in_(list(rows)))
                           .values(last_used_at=datetime.now(timezone.utc)))
    opened = []
    for user in chosen:
        sealed = _open(rows[user["id"]])
        _register(sealed)
        opened.append({**user, "username": sealed.get("username", ""), "password": sealed.get("password", ""), "totp": sealed.get("totp")})
    return opened


def _register(sealed: dict) -> None:
    logging_setup.register_secret(sealed.get("password") or "")
    logging_setup.register_secret((sealed.get("totp") or {}).get("secret") or "")
