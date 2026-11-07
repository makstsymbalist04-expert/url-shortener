"""Initial users, links and OAuth credentials schema."""

from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(100), nullable=False, unique=True),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("role", sa.String(10), nullable=False, server_default="user"),
        sa.CheckConstraint("role IN ('user', 'premium')"),
    )
    op.create_table(
        "links",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("original_url", sa.Text(), nullable=False),
        sa.Column("code", sa.Uuid(), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("clicks", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_clicks", sa.Integer()),
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("clicks >= 0"),
        sa.CheckConstraint("max_clicks IS NULL OR max_clicks > 0"),
    )
    op.create_index("ix_links_user_id", "links", ["user_id"])
    op.create_table(
        "authorization_codes",
        sa.Column("digest", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("client_id", sa.String(100), nullable=False),
        sa.Column("redirect_uri", sa.Text(), nullable=False),
        sa.Column("challenge", sa.String(43), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "access_tokens",
        sa.Column("digest", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade():
    for table in ("access_tokens", "authorization_codes", "links", "users"):
        op.drop_table(table)
