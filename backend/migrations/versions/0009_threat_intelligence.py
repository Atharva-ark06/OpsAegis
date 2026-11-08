"""Add persisted threat intelligence IOC enrichment records."""
from alembic import op
import sqlalchemy as sa
revision="0009_threat_intelligence"
down_revision="0008_detection_scheduling"
branch_labels=None
depends_on=None
def upgrade():
    op.create_table("threat_intel_iocs",sa.Column("id",sa.Integer(),primary_key=True),
        sa.Column("indicator_type",sa.String(16),nullable=False),sa.Column("indicator_value",sa.String(2048),nullable=False),
        sa.Column("indicator_hash",sa.String(64),nullable=False),sa.Column("verdict",sa.String(24),nullable=False,server_default="unknown"),
        sa.Column("risk_score",sa.Integer(),nullable=True),sa.Column("provider_results",sa.JSON(),nullable=False),
        sa.Column("enriched_at",sa.DateTime(timezone=True),nullable=True),
        sa.Column("created_by_user_id",sa.Integer(),sa.ForeignKey("users.id",ondelete="SET NULL"),nullable=True),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False),
        sa.UniqueConstraint("indicator_hash",name="uq_threat_intel_iocs_indicator_hash"))
    op.create_index("ix_threat_intel_iocs_indicator_type","threat_intel_iocs",["indicator_type"])
    op.create_index("ix_threat_intel_iocs_created_at","threat_intel_iocs",["created_at"])
def downgrade():
    op.drop_index("ix_threat_intel_iocs_created_at",table_name="threat_intel_iocs")
    op.drop_index("ix_threat_intel_iocs_indicator_type",table_name="threat_intel_iocs")
    op.drop_table("threat_intel_iocs")
