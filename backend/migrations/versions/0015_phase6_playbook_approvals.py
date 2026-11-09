"""Persist Phase 6 playbook approval requests and decisions."""

from alembic import op
import sqlalchemy as sa

revision = "0015_phase6_approval"
down_revision = "0014_phase6_collect"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "playbook_approvals",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("playbook_id", sa.String(length=100), nullable=False),
        sa.Column("playbook_version", sa.String(length=32), nullable=False),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("requested_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("reviewed_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("input_parameters", sa.JSON(), nullable=False),
        sa.Column("request_reason", sa.Text(), nullable=False),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_playbook_approvals_status", "playbook_approvals", ["status"])
    op.create_index("ix_playbook_approvals_status_expires_at", "playbook_approvals", ["status", "expires_at"])
    op.create_index("ix_playbook_approvals_incident_id", "playbook_approvals", ["incident_id"])


def downgrade() -> None:
    op.drop_index("ix_playbook_approvals_incident_id", table_name="playbook_approvals")
    op.drop_index("ix_playbook_approvals_status_expires_at", table_name="playbook_approvals")
    op.drop_index("ix_playbook_approvals_status", table_name="playbook_approvals")
    op.drop_table("playbook_approvals")
