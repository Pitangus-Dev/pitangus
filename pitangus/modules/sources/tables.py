"""The repository registry: one row per repository (its name, scan branch and retirement mark). It replaces the
`repo-registry` document, rewritten whole on every reconciliation. The container images registered by hand, the
domains registered with their proof, the hosts related to each domain with their saved scope, and the test users
its web scans sign in with."""

from sqlalchemy import Column, DateTime, ForeignKeyConstraint, String, Table, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB

from pitangus.shared.db import TENANT, metadata

repo_registry = Table(
    "repo_registry", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("uid", Text, primary_key=True),
    Column("entry", JSONB, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)

# Container images registered by hand, before (or without) a scan. The key is the asset key a scan of the reference
# produces (`image:<registry>/<repository>`), so the first scan lands on the same asset.
image_registry = Table(
    "image_registry", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("asset_key", Text, primary_key=True),
    Column("reference", Text, nullable=False),
    Column("name", Text, nullable=False),
    Column("added_by", Text, nullable=False),
    Column("added_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)

# Domains registered as HTTPS targets, with the TXT record that proves control of each (`_pitangus.<host>`). It
# replaces the `domains` document. A domain is an asset (`domain:<host>`) only while `verified_until` lies ahead.
domain_registry = Table(
    "domain_registry", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("id", String(24), primary_key=True),
    Column("host", Text, nullable=False),
    Column("url", Text, nullable=False),
    Column("kind", Text, nullable=False, server_default="web"),
    Column("context", Text, nullable=False, server_default=""),
    Column("txt_name", Text, nullable=False),
    Column("txt_value", Text, nullable=False),
    Column("registered_by", Text, nullable=False, server_default=""),
    Column("registered_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("verified_at", DateTime(timezone=True)),
    Column("verified_until", DateTime(timezone=True)),
    Column("checked_at", DateTime(timezone=True)),
    # Which proof made it verified (dns · file · meta); only a DNS proof covers the host's subdomains.
    Column("proof_method", Text, nullable=False, server_default="dns"),
    # A page that only opens with a live session: asked for with the saved headers before and after a scan that sends
    # them (sources/domain_headers.py); empty when nobody set one.
    Column("session_check", Text, nullable=False, server_default=""),
    # The scheduled passive web scan, queued by the periodic task: null (off) or the rule's frequency (daily · weekly ·
    # monthly), the rule itself (sources/domain_schedule.py) and its next run in UTC.
    Column("schedule", Text),
    Column("schedule_rule", JSONB),
    Column("schedule_next_at", DateTime(timezone=True)),
    Column("schedule_last_at", DateTime(timezone=True)),
    Column("schedule_last_run", String(32)),
    Column("schedule_note", JSONB),  # why the last scheduled scan was skipped (a stored message)
    # Related-host discovery (subfinder, passive sources): null · queued · running · done · failed; why it failed or
    # couldn't run (a stored message) and what the last round found and kept.
    Column("discovery_status", Text),
    Column("discovery_requested_at", DateTime(timezone=True)),
    Column("discovery_finished_at", DateTime(timezone=True)),
    Column("discovery_note", JSONB),
    Column("discovery_counts", JSONB),
    UniqueConstraint("tenant_id", "host", name="uq_domain_registry_host"),
)

# Hosts related to a domain, under its own host: found by discovery or added by hand, each in or out of the scope its
# scans reach. Discovered hosts start out of scope (opt-in); only a DNS proof lets any of them in.
domain_hosts = Table(
    "domain_hosts", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("domain_id", String(24), primary_key=True),
    Column("host", Text, primary_key=True),
    Column("state", Text, nullable=False, server_default="out_of_scope"),  # in_scope · out_of_scope
    Column("origin", Text, nullable=False, server_default="discovered"),   # discovered · manual
    Column("first_seen", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("last_seen", DateTime(timezone=True)),  # the last discovery that found it (null: added by hand, never found)
    Column("changed_by", Text, nullable=False, server_default=""),
    ForeignKeyConstraint(["tenant_id", "domain_id"], ["domain_registry.tenant_id", "domain_registry.id"],
                         name="fk_domain_hosts_domain", ondelete="CASCADE"),
)

# Accounts a domain's web scans may sign in with. What identifies them for people (name, method, login page, notes,
# host) is plain; the username, password and TOTP seed are one sealed value (`secret`, AES-GCM with the master key,
# bound to the row), never answered back.
domain_test_users = Table(
    "domain_test_users", metadata,
    Column("tenant_id", Text, primary_key=True, server_default=TENANT),
    Column("id", String(24), primary_key=True),
    Column("domain_id", String(24), nullable=False),
    Column("name", Text, nullable=False),
    Column("method", Text, nullable=False),  # password · password_totp
    Column("login_url", Text, nullable=False, server_default=""),
    Column("check_url", Text, nullable=False, server_default=""),  # a page only a signed-in user sees
    Column("notes", Text, nullable=False, server_default=""),
    Column("applies_to", Text, nullable=False),
    Column("secret", Text, nullable=False),
    Column("created_by", Text, nullable=False, server_default=""),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("last_used_at", DateTime(timezone=True)),
    ForeignKeyConstraint(["tenant_id", "domain_id"], ["domain_registry.tenant_id", "domain_registry.id"],
                         name="fk_domain_test_users_domain", ondelete="CASCADE"),
    UniqueConstraint("tenant_id", "domain_id", "name", name="uq_domain_test_users_name"),
)
