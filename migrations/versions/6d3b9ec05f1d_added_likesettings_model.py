"""Added LikeSettings model

Revision ID: 6d3b9ec05f1d
Revises: 
Create Date: 2025-02-27 19:26:04.070940

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6d3b9ec05f1d'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('site_settings')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('site_settings',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('head_likes', sa.INTEGER(), nullable=True),
    sa.Column('admin_likes', sa.INTEGER(), nullable=True),
    sa.Column('user_likes', sa.INTEGER(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###
