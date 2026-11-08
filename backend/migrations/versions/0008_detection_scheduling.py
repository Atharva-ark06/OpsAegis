"""Add scheduled detection runs, lifecycle state and notifications."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0008_detection_scheduling"
down_revision = "0007_security_correlation"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("correlated_detections", sa.Column("status", sa.String(24), nullable=False, server_default="new"))
    op.add_column("correlated_detections", sa.Column("acknowledged_at", sa.DateTime(timezone=True)))
    op.add_column("correlated_detections", sa.Column("resolved_at", sa.DateTime(timezone=True)))
    op.add_column("correlated_detections", sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE correlated_detections SET updated_at = created_at WHERE updated_at IS NULL")
    with op.batch_alter_table("correlated_detections") as batch:
        batch.alter_column("updated_at", existing_type=sa.DateTime(timezone=True), nullable=False)

    op.create_table(
        "detection_schedules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("interval_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("window_minutes", sa.Integer(), nullable=False, server_default="15"),
        sa.Column("auth_threshold", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("updated_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_scheduled_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "scheduled_detection_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("schedule_slot", sa.String(64), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="queued"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("window_minutes", sa.Integer(), nullable=False),
        sa.Column("auth_threshold", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("error_code", sa.String(80)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("schedule_slot", name="uq_scheduled_detection_runs_slot"),
    )
    op.create_index("ix_scheduled_detection_runs_status", "scheduled_detection_runs", ["status"])
    op.create_table(
        "detection_notifications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("detection_id", sa.Integer(), sa.ForeignKey("correlated_detections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("severity", postgresql.ENUM(
            "informational", "low", "medium", "high", "critical", "unknown",
            name="findingseverity", create_type=False,
        ).with_variant(sa.String(20), "sqlite"), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("user_id", "detection_id", name="uq_detection_notification_user_detection"),
    )
    op.create_index("ix_detection_notifications_user_id", "detection_notifications", ["user_id"])


def downgrade():
    op.drop_index("ix_detection_notifications_user_id", table_name="detection_notifications")
    op.drop_table("detection_notifications")
    op.drop_index("ix_scheduled_detection_runs_status", table_name="scheduled_detection_runs")
    op.drop_table("scheduled_detection_runs")
    op.drop_table("detection_schedules")
    with op.batch_alter_table("correlated_detections") as batch:
        batch.drop_column("updated_at")
        batch.drop_column("resolved_at")
        batch.drop_column("acknowledged_at")
        batch.drop_column("status")
