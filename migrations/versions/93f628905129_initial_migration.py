"""Initial migration

Revision ID: 93f628905129
Revises: 
Create Date: 2024-11-24 04:27:51.300573

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '93f628905129'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=20), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('password', sa.String(length=60), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('username')
    )
    op.create_table('file',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('filename', sa.String(length=120), nullable=False),
    sa.Column('encrypted_file', sa.LargeBinary(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('upload_date', sa.DateTime(), nullable=True),
    sa.Column('is_malicious', sa.Boolean(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('file')
    op.drop_table('user')
    # ### end Alembic commands ###