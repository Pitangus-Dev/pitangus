"""The repository registry: one row per repository (its name, scan branch and retirement mark). It replaces the
`repo-registry` document, rewritten whole on every reconciliation. And the container images registered by hand."""

from sqlalchemy import Column, DateTime, Table, Text, func
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
