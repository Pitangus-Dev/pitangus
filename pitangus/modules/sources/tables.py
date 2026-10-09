"""The repository registry: one row per repository (its name, scan branch and retirement mark). It replaces the
`repo-registry` document, rewritten whole on every reconciliation. The container images registered by hand, and the
domains registered with their DNS TXT proof."""

from sqlalchemy import Column, DateTime, String, Table, Text, UniqueConstraint, func
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
    UniqueConstraint("tenant_id", "host", name="uq_domain_registry_host"),
)
