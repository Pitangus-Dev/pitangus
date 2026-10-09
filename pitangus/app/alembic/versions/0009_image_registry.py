"""container images registered without a scan

An image can be added to the Images page (and linked to the repository it is built from) before it is analyzed. One
row per image, keyed by the asset key its first scan will use.

Revision ID: 0009
Revises: 0008
"""

from alembic import op
import sqlalchemy as sa

revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('image_registry',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('asset_key', sa.Text(), nullable=False),
    sa.Column('reference', sa.Text(), nullable=False),
    sa.Column('name', sa.Text(), nullable=False),
    sa.Column('added_by', sa.Text(), nullable=False),
    sa.Column('added_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('tenant_id', 'asset_key', name=op.f('pk_image_registry'))
    )


def downgrade() -> None:
    op.drop_table('image_registry')
