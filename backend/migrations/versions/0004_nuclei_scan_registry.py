"""Add Nuclei target registry and scan history."""
from alembic import op
import sqlalchemy as sa
revision="0004_nuclei_scan_registry"
down_revision="0003_wazuh_finding_evidence"
branch_labels=None
depends_on=None
def upgrade():
 op.create_table("nuclei_targets",sa.Column("id",sa.Integer(),primary_key=True),sa.Column("name",sa.String(120),nullable=False),sa.Column("url",sa.String(2048),nullable=False,unique=True),sa.Column("authorization_reference",sa.String(500),nullable=False),sa.Column("enabled",sa.Boolean(),nullable=False,server_default=sa.true()),sa.Column("created_by",sa.Integer(),sa.ForeignKey("users.id"),nullable=False),sa.Column("created_at",sa.DateTime(timezone=True),nullable=False))
 op.create_table("nuclei_scan_runs",sa.Column("id",sa.Integer(),primary_key=True),sa.Column("target_id",sa.Integer(),sa.ForeignKey("nuclei_targets.id"),nullable=False),sa.Column("requested_by",sa.Integer(),sa.ForeignKey("users.id"),nullable=False),sa.Column("status",sa.String(20),nullable=False),sa.Column("profile",sa.String(30),nullable=False),sa.Column("started_at",sa.DateTime(timezone=True)),sa.Column("finished_at",sa.DateTime(timezone=True)),sa.Column("findings_count",sa.Integer(),nullable=False,server_default="0"),sa.Column("error_code",sa.String(80)),sa.Column("created_at",sa.DateTime(timezone=True),nullable=False))
 op.create_index("ix_nuclei_scan_runs_target_id","nuclei_scan_runs",["target_id"])
def downgrade():
 op.drop_index("ix_nuclei_scan_runs_target_id",table_name="nuclei_scan_runs");op.drop_table("nuclei_scan_runs");op.drop_table("nuclei_targets")
