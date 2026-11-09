"""Add a durable, non-executable playbook action ledger."""

from alembic import op
import sqlalchemy as sa

revision = "0017_phase6_exec_ledger"
down_revision = "0016_phase6_trends"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "playbook_executions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "approval_id",
            sa.Integer(),
            sa.ForeignKey("playbook_approvals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("action_id", sa.String(length=100), nullable=False),
        sa.Column("action_version", sa.String(length=32), nullable=False),
        sa.Column("target_id", sa.String(length=255), nullable=False),
        sa.Column("parameters_sha256", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False, server_default="pending"),
        sa.Column(
            "compensation_status",
            sa.String(length=24),
            nullable=False,
            server_default="not_requested",
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("provider_reference", sa.String(length=200), nullable=True),
        sa.Column("safe_summary", sa.Text(), nullable=True),
        sa.UniqueConstraint("idempotency_key", name="uq_playbook_executions_idempotency_key"),
        sa.UniqueConstraint("approval_id", "action_id", name="uq_playbook_executions_approval_action"),
        sa.CheckConstraint(
            "status IN ('pending', 'claimed', 'executing', 'succeeded', 'failed', 'outcome_unknown')",
            name="ck_playbook_executions_status",
        ),
        sa.CheckConstraint(
            "compensation_status IN ('not_requested', 'requested', 'executing', 'succeeded', 'failed', 'outcome_unknown')",
            name="ck_playbook_executions_compensation_status",
        ),
    )
    op.create_index(
        "ix_playbook_executions_status_created_at",
        "playbook_executions",
        ["status", "created_at"],
    )
    op.create_index(
        "ix_playbook_executions_approval_id",
        "playbook_executions",
        ["approval_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_playbook_executions_approval_id", table_name="playbook_executions")
    op.drop_index("ix_playbook_executions_status_created_at", table_name="playbook_executions")
    op.drop_table("playbook_executions")
