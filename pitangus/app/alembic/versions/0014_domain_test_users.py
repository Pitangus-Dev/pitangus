"""test users a domain's web scans sign in with

One row per account: its name, sign-in method, login and check pages, notes and host in clear; the username, password and TOTP
seed sealed together with the master key (`secret`). Removing the domain removes them.

Revision ID: 0014
Revises: 0013
"""

from alembic import op
import sqlalchemy as sa

revision = '0014'
down_revision = '0013'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('domain_test_users',
    sa.Column('tenant_id', sa.Text(), server_default='default', nullable=False),
    sa.Column('id', sa.String(length=24), nullable=False),
    sa.Column('domain_id', sa.String(length=24), nullable=False),
    sa.Column('name', sa.Text(), nullable=False),
    sa.Column('method', sa.Text(), nullable=False),
    sa.Column('login_url', sa.Text(), server_default='', nullable=False),
    sa.Column('check_url', sa.Text(), server_default='', nullable=False),
    sa.Column('notes', sa.Text(), server_default='', nullable=False),
    sa.Column('applies_to', sa.Text(), nullable=False),
    sa.Column('secret', sa.Text(), nullable=False),
    sa.Column('created_by', sa.Text(), server_default='', nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['tenant_id', 'domain_id'], ['domain_registry.tenant_id', 'domain_registry.id'],
                            name='fk_domain_test_users_domain', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('tenant_id', 'id', name=op.f('pk_domain_test_users')),
    sa.UniqueConstraint('tenant_id', 'domain_id', 'name', name='uq_domain_test_users_name')
    )


def downgrade() -> None:
    op.drop_table('domain_test_users')
