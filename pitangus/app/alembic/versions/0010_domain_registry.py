"""domains registered with their DNS TXT proof

The `domains` document becomes a table: one row per domain, with when its TXT record was last seen and until when
that proof counts (data migration `domains_to_table`).

Revision ID: 0010
Revises: 0009
"""

from alembic import op
import sqlalchemy as sa

revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('domain_registry',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('id', sa.String(length=24), nullable=False),
    sa.Column('host', sa.Text(), nullable=False),
    sa.Column('url', sa.Text(), nullable=False),
    sa.Column('kind', sa.Text(), server_default='web', nullable=False),
    sa.Column('context', sa.Text(), server_default='', nullable=False),
    sa.Column('txt_name', sa.Text(), nullable=False),
    sa.Column('txt_value', sa.Text(), nullable=False),
    sa.Column('registered_by', sa.Text(), server_default='', nullable=False),
    sa.Column('registered_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('verified_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('checked_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('tenant_id', 'id', name=op.f('pk_domain_registry')),
    sa.UniqueConstraint('tenant_id', 'host', name='uq_domain_registry_host')
    )


def downgrade() -> None:
    op.drop_table('domain_registry')
