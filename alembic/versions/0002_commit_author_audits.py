"""Persist the GitHub author and signature metadata for each pushed SHA."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

revision = "0002_commit_author_audits"
down_revision = "0001_create_v1_tables"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "commit_author_audits",
        sa.Column("repo_id", mysql.BIGINT(), sa.ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False),
        sa.Column("commit_sha", sa.String(40), nullable=False),
        sa.Column("author_name", sa.Text(), nullable=False),
        sa.Column("author_email", sa.Text(), nullable=False),
        sa.Column("author_domain", sa.String(253), nullable=False),
        sa.Column("committer_name", sa.Text(), nullable=False),
        sa.Column("committer_email", sa.Text(), nullable=False),
        sa.Column("signature_verified", sa.Boolean(), nullable=False),
        sa.Column("detected_at", sa.DateTime(), server_default=sa.func.current_timestamp(), nullable=False),
        sa.PrimaryKeyConstraint("repo_id", "commit_sha"),
        mysql_engine="InnoDB", mysql_charset="utf8mb4", mysql_collate="utf8mb4_unicode_ci",
    )


def downgrade():
    op.drop_table("commit_author_audits")
