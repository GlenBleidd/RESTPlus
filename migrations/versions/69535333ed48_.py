"""empty message

Revision ID: 69535333ed48
Revises: cf2b7fd92ce4
Create Date: 2019-03-13 23:14:57.270845

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '69535333ed48'
down_revision = 'cf2b7fd92ce4'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('blacklist_tokens',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('token', sa.String(length=500), nullable=False),
    sa.Column('blacklisted_on', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('blacklist_tokens')
    # ### end Alembic commands ###
