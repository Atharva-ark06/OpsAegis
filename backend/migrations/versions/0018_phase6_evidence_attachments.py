"""Add bounded incident evidence attachment metadata."""

from alembic import op
import sqlalchemy as sa

revision = "0018_phase6_evidence"
down_revision = "0017_phase6_exec_ledger"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "incident_evidence_attachments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("uploaded_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("storage_key", sa.String(length=64), nullable=False, unique=True),
        sa.Column("original_filename", sa.String(length=160), nullable=False),
        sa.Column("media_type", sa.String(length=80), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("size_bytes > 0", name="ck_incident_evidence_size_positive"),
    )
    op.create_index("ix_incident_evidence_incident_created", "incident_evidence_attachments", ["incident_id", "created_at"])
    op.create_index("ix_incident_evidence_expires_at", "incident_evidence_attachments", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_incident_evidence_expires_at", table_name="incident_evidence_attachments")
    op.drop_index("ix_incident_evidence_incident_created", table_name="incident_evidence_attachments")
    op.drop_table("incident_evidence_attachments")
