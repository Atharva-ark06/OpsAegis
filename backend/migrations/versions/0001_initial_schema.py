"""Create initial OpsAegis persistence schema."""
from alembic import op
import sqlalchemy as sa
revision="0001_initial_schema"
down_revision=None
branch_labels=None
depends_on=None
def upgrade():
    severity=sa.Enum("informational","low","medium","high","critical","unknown",name="findingseverity")
    status=sa.Enum("new","triaged","accepted","false_positive","resolved",name="findingstatus")
    op.create_table("assets",sa.Column("id",sa.Integer,primary_key=True),sa.Column("name",sa.String(255),nullable=False),sa.Column("asset_type",sa.String(80),nullable=False),sa.Column("environment",sa.String(80),nullable=False),sa.Column("created_at",sa.DateTime(timezone=True),nullable=False))
    op.create_index("ix_assets_name","assets",["name"])
    op.create_table("findings",sa.Column("id",sa.Integer,primary_key=True),sa.Column("source_engine",sa.String(40),nullable=False),sa.Column("source_native_id",sa.String(255)),sa.Column("title",sa.String(500),nullable=False),sa.Column("description",sa.Text),sa.Column("severity",severity,nullable=False),sa.Column("status",status,nullable=False),sa.Column("asset_id",sa.Integer,sa.ForeignKey("assets.id")),sa.Column("first_seen_at",sa.DateTime(timezone=True),nullable=False),sa.Column("last_seen_at",sa.DateTime(timezone=True),nullable=False),sa.Column("evidence_uri",sa.String(1024)))
    op.create_index("ix_findings_source_engine","findings",["source_engine"])
    op.create_table("incidents",sa.Column("id",sa.Integer,primary_key=True),sa.Column("title",sa.String(500),nullable=False),sa.Column("severity",severity,nullable=False),sa.Column("status",sa.String(40),nullable=False),sa.Column("description",sa.Text),sa.Column("created_at",sa.DateTime(timezone=True),nullable=False))
def downgrade():
    op.drop_table("incidents")
    op.drop_index("ix_findings_source_engine",table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_assets_name",table_name="assets")
    op.drop_table("assets")
