"""Container images registered by hand: on the Images page (and linkable to a repository) before they are scanned.

The key is the asset key a scan of the reference produces (`image:<registry>/<repository>`, see
`scanning.image.parse_reference`), so the first scan lands on the same asset. A registration stays after the image is
scanned (the Images page then shows the scanned asset) but no longer counts toward `LIMIT`.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert

from pitangus.modules.sources.tables import image_registry
from pitangus.shared import db
from pitangus.shared.db import TENANT

LIMIT = 5000  # images added and not scanned yet, per workspace


def _row(row) -> dict:
    return {"key": row.asset_key, "reference": row.reference, "name": row.name, "added_by": row.added_by,
            "added_at": row.added_at.isoformat(timespec="seconds")}


def registered(data_dir: Path) -> list[dict]:
    """Every registered image, most recently added first."""
    with db.transaction(data_dir) as connection:
        rows = connection.execute(select(image_registry).where(image_registry.c.tenant_id == TENANT)
                                  .order_by(image_registry.c.added_at.desc(), image_registry.c.asset_key)).all()
    return [_row(row) for row in rows]


def get(data_dir: Path, key: str) -> dict | None:
    with db.transaction(data_dir) as connection:
        row = connection.execute(select(image_registry).where(image_registry.c.tenant_id == TENANT, image_registry.c.asset_key == key)).first()
    return _row(row) if row else None


def register(data_dir: Path, image: dict, *, by: str) -> None:
    """`image` as `parse_reference` returns it. Registered already: its reference (and name) become this one's."""
    statement = insert(image_registry).values(tenant_id=TENANT, asset_key=image["asset"], reference=image["reference"], name=image["name"], added_by=by)
    with db.transaction(data_dir) as connection:
        connection.execute(statement.on_conflict_do_update(index_elements=[image_registry.c.tenant_id, image_registry.c.asset_key],
                                                           set_={"reference": statement.excluded.reference, "name": statement.excluded.name}))


def forget(data_dir: Path, key: str) -> bool:
    with db.transaction(data_dir) as connection:
        removed = delete(image_registry).where(image_registry.c.tenant_id == TENANT, image_registry.c.asset_key == key).returning(image_registry.c.asset_key)
        return connection.execute(removed).first() is not None
