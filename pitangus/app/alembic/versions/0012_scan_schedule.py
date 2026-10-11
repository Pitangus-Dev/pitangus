"""a domain's scheduled scan follows a rule

`schedule_rule` holds when the passive web scan runs: daily, on some weekdays or on some days of the month, at a time
of day in an IANA timezone. `schedule` keeps the frequency and `schedule_next_at` the next run, in UTC. The weekly
schedules from before get the weekday and time of their next run, in UTC (data migration `scan_schedule_rules`).

Revision ID: 0012
Revises: 0011
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0012'
down_revision = '0011'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('domain_registry', sa.Column('schedule_rule', postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade() -> None:
    op.drop_column('domain_registry', 'schedule_rule')
