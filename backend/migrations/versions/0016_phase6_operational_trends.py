"""Add operational reporting thresholds."""
from alembic import op
import sqlalchemy as sa

revision = "0016_phase6_trends"
down_revision = "0015_phase6_approval"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "operational_thresholds",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("collection_failure_rate_percent", sa.Integer(), nullable=False, server_default="20"),
        sa.Column("source_stale_after_minutes", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("detection_to_incident_minutes", sa.Integer(), nullable=False, server_default="15"),
        sa.Column("incident_resolution_minutes", sa.Integer(), nullable=False, server_default="240"),
        sa.Column("updated_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("operational_thresholds")
