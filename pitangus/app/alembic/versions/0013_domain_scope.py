"""related hosts of a domain and the scope saved for them

`domain_hosts` holds the hosts under a domain found by discovery (subfinder over passive sources) or added by hand,
each in or out of the scope its scans reach. The `discovery_*` columns hold the state of the last discovery round.

Revision ID: 0013
Revises: 0012
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0013'
down_revision = '0012'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('domain_registry', sa.Column('discovery_status', sa.Text(), nullable=True))
    op.add_column('domain_registry', sa.Column('discovery_requested_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('domain_registry', sa.Column('discovery_finished_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('domain_registry', sa.Column('discovery_note', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('domain_registry', sa.Column('discovery_counts', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.create_table('domain_hosts',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('domain_id', sa.String(length=24), nullable=False),
    sa.Column('host', sa.Text(), nullable=False),
    sa.Column('state', sa.Text(), server_default='out_of_scope', nullable=False),
    sa.Column('origin', sa.Text(), server_default='discovered', nullable=False),
    sa.Column('first_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
    sa.Column('changed_by', sa.Text(), server_default='', nullable=False),
    sa.ForeignKeyConstraint(['tenant_id', 'domain_id'], ['domain_registry.tenant_id', 'domain_registry.id'],
                            name='fk_domain_hosts_domain', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('tenant_id', 'domain_id', 'host', name=op.f('pk_domain_hosts'))
    )


def downgrade() -> None:
    op.drop_table('domain_hosts')
    for column in ('discovery_counts', 'discovery_note', 'discovery_finished_at', 'discovery_requested_at', 'discovery_status'):
        op.drop_column('domain_registry', column)
