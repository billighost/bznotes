"""Fix like weight system

Revision ID: 2dc95e39918b
Revises: 6d3b9ec05f1d
Create Date: 2025-02-27 21:37:44.904614

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2dc95e39918b'
down_revision = '6d3b9ec05f1d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_unique_constraint(None, 'likes', ['user_id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'likes', type_='unique')
    # ### end Alembic commands ###
