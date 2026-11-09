"""Durable Phase 6 collection runs and incident analyst notes."""

from alembic import op
import sqlalchemy as sa

revision = "0014_phase6_collection_investigation"
down_revision = "0013_detection_worker_fencing"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "integration_schedules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("interval_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("lookback_minutes", sa.Integer(), nullable=False, server_default="15"),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("source", name="uq_integration_schedules_source"),
    )
    op.create_table(
        "integration_collection_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("schedule_id", sa.Integer(), sa.ForeignKey("integration_schedules.id", ondelete="CASCADE"), nullable=False),
        sa.Column("schedule_slot", sa.String(length=128), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("lookback_minutes", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False, server_default="queued"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("requested_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("window_start_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("window_end_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("received", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("skipped_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("truncated_possible", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column("worker_token", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("schedule_slot", name="uq_integration_collection_run_slot"),
    )
    op.create_index("ix_integration_collection_runs_schedule_id", "integration_collection_runs", ["schedule_id"])
    op.create_index("ix_integration_collection_runs_source", "integration_collection_runs", ["source"])
    op.create_index("ix_integration_collection_runs_status", "integration_collection_runs", ["status"])
    op.create_index("ix_integration_collection_runs_created_at", "integration_collection_runs", ["created_at"])
    op.create_table(
        "incident_notes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("author_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_incident_notes_incident_id", "incident_notes", ["incident_id"])


def downgrade() -> None:
    op.drop_index("ix_incident_notes_incident_id", table_name="incident_notes")
    op.drop_table("incident_notes")
    op.drop_index("ix_integration_collection_runs_created_at", table_name="integration_collection_runs")
    op.drop_index("ix_integration_collection_runs_schedule_id", table_name="integration_collection_runs")
    op.drop_index("ix_integration_collection_runs_status", table_name="integration_collection_runs")
    op.drop_index("ix_integration_collection_runs_source", table_name="integration_collection_runs")
    op.drop_table("integration_collection_runs")
    op.drop_table("integration_schedules")
