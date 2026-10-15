"""the page that proves a domain's saved headers still carry a session

`session_check`: an HTTPS page of the domain that only opens signed in; a scan that sends the saved headers asks for it
before and after, and without a 2xx the scan is incomplete. Empty when nobody set one.

Revision ID: 0015
Revises: 0014
"""

from alembic import op
import sqlalchemy as sa

revision = '0015'
down_revision = '0014'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('domain_registry', sa.Column('session_check', sa.Text(), server_default='', nullable=False))


def downgrade() -> None:
    op.drop_column('domain_registry', 'session_check')
