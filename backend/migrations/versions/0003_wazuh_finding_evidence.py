"""Add bounded evidence metadata and source-event deduplication."""
from alembic import op
import sqlalchemy as sa

revision = "0003_wazuh_finding_evidence"
down_revision = "0002_auth_and_audit"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("findings", sa.Column("evidence", sa.JSON(), nullable=True))
    op.create_index(
        "uq_findings_source_native_id",
        "findings",
        ["source_engine", "source_native_id"],
        unique=True,
    )


def downgrade():
    op.drop_index("uq_findings_source_native_id", table_name="findings")
    op.drop_column("findings", "evidence")
