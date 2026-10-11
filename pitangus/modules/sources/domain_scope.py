"""The hosts related to a registered domain and the scope saved for them.

Related hosts live strictly under the domain's host: found by discovery (`scanning/discovery.py`) or added by hand.
Each one is in or out of the scope the domain's scans reach, and that choice is saved with the domain, so the next
scan (by hand or scheduled) starts from it. Discovered hosts start out (opt-in). Only a current DNS proof covers
subdomains, so without one nothing can be put in scope and the saved choices are left aside: `saved_hosts` answers
none. Being listed proves nothing either way; the worker checks the proof and every address again before a scan.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert

from pitangus.modules.sources import domains
from pitangus.modules.sources.domains import DomainError
from pitangus.modules.sources.tables import domain_hosts, domain_registry
from pitangus.shared import db
from pitangus.shared.db import TENANT
from pitangus.shared.i18n import msg

STATES = ("in_scope", "out_of_scope")
ORIGINS = ("discovered", "manual")
HOSTS_LIMIT = 100                         # related hosts kept per domain
DISCOVERY_STALE = timedelta(minutes=15)   # a round queued or running this long died with its worker
ACTIVE = ("queued", "running")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def covered(record: dict) -> bool:
    """Whether the domain's proof lets related hosts into its scope: a current DNS proof covers its subdomains."""
    return bool(record["verified"]) and (record.get("proof_method") or "dns") == "dns"


def coverage_reason(record: dict):
    """Why related hosts can't be put in scope, or None when they can."""
    if covered(record):
        return None
    if not record["verified"]:
        return msg("sources.domains.scope.unverified", host=record["host"])
    return msg("sources.domains.scope.dns_only")


def related_host(record: dict, value) -> str:
    """`value` as a host strictly under the domain's host, or DomainError."""
    root = record["host"]
    if not isinstance(value, str) or len(value) > 253:
        raise DomainError(msg("sources.domains.scope.invalid_host", host=str(value)[:80]))
    name = value.strip().lower().rstrip(".")
    if name == root:
        raise DomainError(msg("sources.domains.scope.root", host=root))
    if not domains.valid_host(name):
        raise DomainError(msg("sources.domains.scope.invalid_host", host=name[:80]))
    if not name.endswith("." + root):
        raise DomainError(msg("sources.domains.scope.outside", host=name, root=root))
    return name


def _hosts(connection, domain_id: str) -> list:
    return connection.execute(select(domain_hosts).where(domain_hosts.c.tenant_id == TENANT, domain_hosts.c.domain_id == domain_id)
                              .order_by(domain_hosts.c.host)).all()


def _discovery(row, now: datetime) -> dict:
    status = row.discovery_status or "idle"
    note = row.discovery_note
    if status in ACTIVE and row.discovery_requested_at and now - row.discovery_requested_at > DISCOVERY_STALE:
        status, note = "failed", msg("sources.domains.discovery.interrupted")
    return {"status": status, "requested_at": _iso(row.discovery_requested_at), "finished_at": _iso(row.discovery_finished_at),
            "note": note, "counts": row.discovery_counts}


def view(data_dir: Path, domain_id: str, *, now: datetime | None = None) -> dict:
    """The domain's related hosts with their saved state, whether its proof covers them, and the last discovery."""
    record = domains.get_domain(data_dir, domain_id)
    with db.transaction(data_dir) as connection:
        row = connection.execute(select(domain_registry.c.discovery_status, domain_registry.c.discovery_requested_at,
                                        domain_registry.c.discovery_finished_at, domain_registry.c.discovery_note,
                                        domain_registry.c.discovery_counts)
                                 .where(domain_registry.c.tenant_id == TENANT, domain_registry.c.id == domain_id)).one()
        rows = _hosts(connection, domain_id)
    hosts = [{"host": item.host, "state": item.state, "origin": item.origin, "first_seen": _iso(item.first_seen),
              "last_seen": _iso(item.last_seen), "changed_by": item.changed_by or None} for item in rows]
    return {"domain_id": record["id"], "root": record["host"], "covered": covered(record), "reason": coverage_reason(record),
            "hosts": hosts, "in_scope": sum(1 for item in hosts if item["state"] == "in_scope"),
            "limit": HOSTS_LIMIT, "scope_limit": domains.SCOPE_LIMIT, "discovery": _discovery(row, now or _now())}


def _in_scope_count(connection, domain_id: str) -> int:
    return connection.execute(select(func.count()).select_from(domain_hosts).where(
        domain_hosts.c.tenant_id == TENANT, domain_hosts.c.domain_id == domain_id, domain_hosts.c.state == "in_scope")).scalar_one()


def set_state(data_dir: Path, domain_id: str, host, state: str, *, by: str = "") -> dict:
    """Puts one listed host in or out of the domain's scope. In needs the DNS proof and room under SCOPE_LIMIT."""
    if state not in STATES:
        raise DomainError(msg("sources.domains.invalid_request"))
    record = domains.get_domain(data_dir, domain_id)
    name = related_host(record, host)
    if state == "in_scope" and not covered(record):
        raise DomainError(coverage_reason(record))
    with db.transaction(data_dir) as connection:
        db.lock(connection, "domain-scope", domain_id)
        current = connection.execute(select(domain_hosts.c.state).where(
            domain_hosts.c.tenant_id == TENANT, domain_hosts.c.domain_id == domain_id, domain_hosts.c.host == name)).scalar()
        if current is None:
            raise DomainError(msg("sources.domains.scope.unknown_host", host=name))
        if state == "in_scope" and current != "in_scope" and _in_scope_count(connection, domain_id) >= domains.SCOPE_LIMIT:
            raise DomainError(msg("sources.domains.scope.too_many", max=domains.SCOPE_LIMIT))
        connection.execute(update(domain_hosts).where(domain_hosts.c.tenant_id == TENANT, domain_hosts.c.domain_id == domain_id,
                                                      domain_hosts.c.host == name).values(state=state, changed_by=by[:200]))
    return view(data_dir, domain_id)


def exclude_all(data_dir: Path, domain_id: str, *, by: str = "") -> dict:
    domains.get_domain(data_dir, domain_id)
    with db.transaction(data_dir) as connection:
        connection.execute(update(domain_hosts).where(domain_hosts.c.tenant_id == TENANT, domain_hosts.c.domain_id == domain_id,
                                                      domain_hosts.c.state == "in_scope").values(state="out_of_scope", changed_by=by[:200]))
    return view(data_dir, domain_id)


def add_host(data_dir: Path, domain_id: str, host, *, by: str = "") -> dict:
    """Adds a host under the domain by hand, in scope (whoever types it wants it analyzed). Needs the DNS proof."""
    record = domains.get_domain(data_dir, domain_id)
    name = related_host(record, host)
    if not covered(record):
        raise DomainError(coverage_reason(record))
    with db.transaction(data_dir) as connection:
        db.lock(connection, "domain-scope", domain_id)
        listed = {item.host: item.state for item in _hosts(connection, domain_id)}
        if listed.get(name) == "in_scope":
            return view(data_dir, domain_id)
        if name not in listed and len(listed) >= HOSTS_LIMIT:
            raise DomainError(msg("sources.domains.scope.hosts_full", max=HOSTS_LIMIT))
        if sum(1 for state in listed.values() if state == "in_scope") >= domains.SCOPE_LIMIT:
            raise DomainError(msg("sources.domains.scope.too_many", max=domains.SCOPE_LIMIT))
        connection.execute(insert(domain_hosts).values(tenant_id=TENANT, domain_id=domain_id, host=name, state="in_scope",
                                                       origin="manual", changed_by=by[:200])
                           .on_conflict_do_update(index_elements=[domain_hosts.c.tenant_id, domain_hosts.c.domain_id, domain_hosts.c.host],
                                                  set_={"state": "in_scope", "changed_by": by[:200]}))
    return view(data_dir, domain_id)


def remove_host(data_dir: Path, domain_id: str, host) -> dict:
    """Forgets a host added by hand. A discovered one stays listed (the next round would bring it back): exclude it."""
    record = domains.get_domain(data_dir, domain_id)
    name = related_host(record, host)
    with db.transaction(data_dir) as connection:
        removed = connection.execute(delete(domain_hosts).where(
            domain_hosts.c.tenant_id == TENANT, domain_hosts.c.domain_id == domain_id, domain_hosts.c.host == name,
            domain_hosts.c.origin == "manual").returning(domain_hosts.c.host)).first()
    if removed is None:
        raise DomainError(msg("sources.domains.scope.not_manual", host=name))
    return view(data_dir, domain_id)


def saved_hosts(data_dir: Path, record: dict) -> list[str]:
    """The hosts saved in scope, when the domain's proof covers them; none otherwise."""
    if not covered(record):
        return []
    with db.transaction(data_dir) as connection:
        return list(connection.execute(select(domain_hosts.c.host).where(
            domain_hosts.c.tenant_id == TENANT, domain_hosts.c.domain_id == record["id"], domain_hosts.c.state == "in_scope")
            .order_by(domain_hosts.c.host).limit(domains.SCOPE_LIMIT)).scalars())


def excluded_hosts(data_dir: Path, record: dict) -> list[str]:
    with db.transaction(data_dir) as connection:
        return list(connection.execute(select(domain_hosts.c.host).where(
            domain_hosts.c.tenant_id == TENANT, domain_hosts.c.domain_id == record["id"], domain_hosts.c.state == "out_of_scope")
            .order_by(domain_hosts.c.host)).scalars())


def _set_discovery(data_dir: Path, domain_id: str, **values) -> None:
    with db.transaction(data_dir) as connection:
        connection.execute(update(domain_registry).where(domain_registry.c.tenant_id == TENANT, domain_registry.c.id == domain_id)
                           .values(**values))


def request_discovery(data_dir: Path, domain_id: str, *, now: datetime | None = None) -> bool:
    """Marks a discovery round as queued; False when one is already queued or running (and not stale)."""
    now = now or _now()
    with db.transaction(data_dir) as connection:
        db.lock(connection, "domain-discovery", domain_id)
        row = connection.execute(select(domain_registry.c.discovery_status, domain_registry.c.discovery_requested_at)
                                 .where(domain_registry.c.tenant_id == TENANT, domain_registry.c.id == domain_id)).first()
        if row is None:
            raise DomainError(msg("sources.domains.not_found"))
        if row.discovery_status in ACTIVE and row.discovery_requested_at and now - row.discovery_requested_at <= DISCOVERY_STALE:
            return False
        connection.execute(update(domain_registry).where(domain_registry.c.tenant_id == TENANT, domain_registry.c.id == domain_id)
                           .values(discovery_status="queued", discovery_requested_at=now, discovery_note=None))
    return True


def discovery_started(data_dir: Path, domain_id: str) -> None:
    _set_discovery(data_dir, domain_id, discovery_status="running")


def discovery_failed(data_dir: Path, domain_id: str, note, *, now: datetime | None = None) -> None:
    _set_discovery(data_dir, domain_id, discovery_status="failed", discovery_note=note, discovery_finished_at=now or _now())


def discovery_finished(data_dir: Path, domain_id: str, found: list[str], counts: dict, *, now: datetime | None = None) -> dict:
    """Stores a round's hosts: new ones out of scope, known ones seen again; none is ever put in scope here. Hosts
    the round didn't find stay, with their last sighting. Beyond HOSTS_LIMIT, new hosts are left out (and counted)."""
    now = now or _now()
    record = domains.get_domain(data_dir, domain_id)
    names = []
    for value in found:
        try:
            names.append(related_host(record, value))
        except DomainError:
            continue
    with db.transaction(data_dir) as connection:
        db.lock(connection, "domain-scope", domain_id)
        listed = {item.host for item in _hosts(connection, domain_id)}
        room = max(0, HOSTS_LIMIT - len(listed))
        fresh = [name for name in dict.fromkeys(names) if name not in listed]
        if listed & set(names):
            connection.execute(update(domain_hosts).where(domain_hosts.c.tenant_id == TENANT, domain_hosts.c.domain_id == domain_id,
                                                          domain_hosts.c.host.in_(sorted(listed & set(names)))).values(last_seen=now))
        for name in fresh[:room]:
            connection.execute(insert(domain_hosts).values(tenant_id=TENANT, domain_id=domain_id, host=name, state="out_of_scope",
                                                           origin="discovered", first_seen=now, last_seen=now))
        counts = {**counts, "new": len(fresh[:room]), "capped": max(0, len(fresh) - room)}
        connection.execute(update(domain_registry).where(domain_registry.c.tenant_id == TENANT, domain_registry.c.id == domain_id)
                           .values(discovery_status="done", discovery_finished_at=now, discovery_note=None, discovery_counts=counts))
    return counts
