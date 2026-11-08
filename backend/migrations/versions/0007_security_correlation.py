"""Persist correlated detections and their incident provenance."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0007_security_correlation"
down_revision = "0006_incident_response_workflows"
branch_labels = None
depends_on = None


def upgrade():
    severity_type = postgresql.ENUM(
        "informational", "low", "medium", "high", "critical", "unknown",
        name="findingseverity", create_type=False,
    ).with_variant(sa.String(20), "sqlite")
    op.create_table(
        "correlated_detections",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("rule_key", sa.String(80), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", severity_type, nullable=False),
        sa.Column("finding_ids", sa.JSON(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("fingerprint", name="uq_correlated_detections_fingerprint"),
    )
    op.create_index("ix_correlated_detections_rule_key", "correlated_detections", ["rule_key"])
    op.create_index("ix_correlated_detections_last_seen_at", "correlated_detections", ["last_seen_at"])


def downgrade():
    op.drop_index("ix_correlated_detections_last_seen_at", table_name="correlated_detections")
    op.drop_index("ix_correlated_detections_rule_key", table_name="correlated_detections")
    op.drop_table("correlated_detections")
