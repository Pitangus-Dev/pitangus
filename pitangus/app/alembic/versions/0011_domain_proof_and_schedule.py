"""how a domain's control was proved, and its weekly passive scan

`proof_method` says which proof (DNS TXT, a file under /.well-known, or a meta tag) made the domain verified; the
daily re-check asks the same one again. Existing proofs are DNS ones. The `schedule_*` columns hold the weekly
passive web scan: when it is due next, when the scheduler last acted, the run it queued and, when it skipped one,
why (a stored message).

Revision ID: 0011
Revises: 0010
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0011'
down_revision = '0010'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('domain_registry', sa.Column('proof_method', sa.Text(), server_default='dns', nullable=False))
    op.add_column('domain_registry', sa.Column('schedule', sa.Text(), nullable=True))
    op.add_column('domain_registry', sa.Column('schedule_next_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('domain_registry', sa.Column('schedule_last_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('domain_registry', sa.Column('schedule_last_run', sa.String(length=32), nullable=True))
    op.add_column('domain_registry', sa.Column('schedule_note', postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade() -> None:
    for column in ('schedule_note', 'schedule_last_run', 'schedule_last_at', 'schedule_next_at', 'schedule', 'proof_method'):
        op.drop_column('domain_registry', column)
