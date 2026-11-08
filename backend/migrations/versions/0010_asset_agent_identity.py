"""Add source identity and observation metadata to assets."""
from alembic import op
import sqlalchemy as sa

revision = "0010_asset_agent_identity"
down_revision = "0009_threat_intelligence"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.add_column("assets", sa.Column("source_engine", sa.String(length=40), nullable=True))
    op.add_column("assets", sa.Column("external_id", sa.String(length=255), nullable=True))
    op.add_column("assets", sa.Column("ip_address", sa.String(length=64), nullable=True))
    op.add_column("assets", sa.Column("os_name", sa.String(length=255), nullable=True))
    op.add_column("assets", sa.Column("agent_status", sa.String(length=40), nullable=True))
    op.add_column("assets", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_assets_source_engine", "assets", ["source_engine"], unique=False)
    op.create_index("uq_assets_source_external_id", "assets", ["source_engine", "external_id"], unique=True)

def downgrade() -> None:
    op.drop_index("uq_assets_source_external_id", table_name="assets")
    op.drop_index("ix_assets_source_engine", table_name="assets")
    op.drop_column("assets", "last_seen_at")
    op.drop_column("assets", "agent_status")
    op.drop_column("assets", "os_name")
    op.drop_column("assets", "ip_address")
    op.drop_column("assets", "external_id")
    op.drop_column("assets", "source_engine")
