"""Add bounded evidence metadata and source-event deduplication."""
from alembic import op
import sqlalchemy as sa

revision = "0003_wazuh_finding_evidence"
down_revision = "0002_auth_and_audit"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("findings", sa.Column("evidence", sa.JSON(), nullable=True))
    duplicates = op.get_bind().execute(sa.text(
        "SELECT source_engine, source_native_id, COUNT(*) AS total "
        "FROM findings WHERE source_native_id IS NOT NULL "
        "GROUP BY source_engine, source_native_id HAVING COUNT(*) > 1"
    )).first()
    if duplicates:
        raise RuntimeError(
            "Cannot add finding deduplication index: duplicate non-null "
            "(source_engine, source_native_id) records already exist. "
            "Resolve duplicates before retrying this migration."
        )
    op.create_index(
        "uq_findings_source_native_id",
        "findings",
        ["source_engine", "source_native_id"],
        unique=True,
    )


def downgrade():
    op.drop_index("uq_findings_source_native_id", table_name="findings")
    op.drop_column("findings", "evidence")
