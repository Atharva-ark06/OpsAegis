"""Add Shannon authorized target registry and external runner scan history."""
from alembic import op
import sqlalchemy as sa
revision = "0005_shannon_runner"
down_revision = "0004_nuclei_scan_registry"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("shannon_targets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("target_url", sa.String(2048), nullable=False),
        sa.Column("source_repository", sa.String(500), nullable=False),
        sa.Column("authorization_reference", sa.String(500), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("target_url", "source_repository", name="uq_shannon_target_repo"))
    op.create_table("shannon_scan_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("shannon_targets.id"), nullable=False),
        sa.Column("requested_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("runner_job_id", sa.String(128), unique=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("error_code", sa.String(80)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_shannon_scan_runs_target_id", "shannon_scan_runs", ["target_id"])

def downgrade():
    op.drop_index("ix_shannon_scan_runs_target_id", table_name="shannon_scan_runs")
    op.drop_table("shannon_scan_runs")
    op.drop_table("shannon_targets")
