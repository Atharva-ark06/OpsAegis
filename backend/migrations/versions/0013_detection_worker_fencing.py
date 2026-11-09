"""Add fencing tokens to scheduled detection worker runs."""

from alembic import op
import sqlalchemy as sa

revision = "0013_detection_worker_fencing"
down_revision = "0012_nuclei_worker_queue"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("scheduled_detection_runs") as batch:
        batch.add_column(sa.Column("worker_token", sa.String(length=128), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("scheduled_detection_runs") as batch:
        batch.drop_column("worker_token")
