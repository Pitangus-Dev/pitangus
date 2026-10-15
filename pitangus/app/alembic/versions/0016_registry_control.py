"""what the registry keeps about how it fixes an asset's findings

`control`: the fixes held back by the fix hold (and what releases them), the last shadow comparison of the coverage
rules, and the identity version the asset's fingerprints follow. Empty for every asset until a scan writes it.

Revision ID: 0016
Revises: 0015
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0016'
down_revision = '0015'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('registry_assets', sa.Column('control', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False))


def downgrade() -> None:
    op.drop_column('registry_assets', 'control')
