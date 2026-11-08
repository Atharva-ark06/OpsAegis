"""Add audited finding triage and incident response workflow fields."""
from alembic import op
import sqlalchemy as sa

revision = "0006_incident_response_workflows"
down_revision = "0005_shannon_runner"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("incidents", sa.Column("assigned_to_user_id", sa.Integer(), nullable=True))
    op.add_column("incidents", sa.Column("resolution", sa.Text(), nullable=True))
    op.add_column("incidents", sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("incidents", sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True))
    op.create_foreign_key("fk_incidents_assigned_to_user_id_users", "incidents", "users",
                          ["assigned_to_user_id"], ["id"])
    op.create_index("ix_incidents_assigned_to_user_id", "incidents", ["assigned_to_user_id"])
    op.execute("UPDATE incidents SET updated_at = created_at WHERE updated_at IS NULL")
    with op.batch_alter_table("incidents") as batch:
        batch.alter_column("updated_at", existing_type=sa.DateTime(timezone=True), nullable=False)

def downgrade():
    op.drop_index("ix_incidents_assigned_to_user_id", table_name="incidents")
    op.drop_constraint("fk_incidents_assigned_to_user_id_users", "incidents", type_="foreignkey")
    op.drop_column("incidents", "closed_at")
    op.drop_column("incidents", "updated_at")
    op.drop_column("incidents", "resolution")
    op.drop_column("incidents", "assigned_to_user_id")
