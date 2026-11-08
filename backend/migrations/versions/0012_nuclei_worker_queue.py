"""Add durable queue and retry metadata for isolated Nuclei scans."""
from alembic import op
import sqlalchemy as sa
revision="0012_nuclei_worker_queue"
down_revision="0011_vulnerability_management"
branch_labels=None
depends_on=None
def upgrade():
 with op.batch_alter_table("nuclei_scan_runs") as batch:
  batch.add_column(sa.Column("attempts",sa.Integer(),nullable=False,server_default="0"))
  batch.add_column(sa.Column("next_attempt_at",sa.DateTime(timezone=True),nullable=True))
  batch.create_index("ix_nuclei_scan_runs_next_attempt_at",["next_attempt_at"])
def downgrade():
 with op.batch_alter_table("nuclei_scan_runs") as batch:
  batch.drop_index("ix_nuclei_scan_runs_next_attempt_at")
  batch.drop_column("next_attempt_at")
  batch.drop_column("attempts")
