"""Add threat entity correlation and ATT&CK mappings."""
from alembic import op
import sqlalchemy as sa

revision = "0002_threat_correlation"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "threat_entities",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("entity_type", sa.String(40), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("normalized_name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "entity_type", "normalized_name"),
    )
    op.create_index("ix_threat_entities_organization_id", "threat_entities", ["organization_id"])
    op.create_index("ix_threat_entities_org_type", "threat_entities", ["organization_id", "entity_type"])

    op.create_table(
        "intel_entity_links",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("record_id", sa.Uuid(), nullable=False),
        sa.Column("entity_id", sa.Uuid(), nullable=False),
        sa.Column("relationship_type", sa.String(40), nullable=False),
        sa.Column("rationale", sa.String(1000), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["record_id"], ["intel_records.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["entity_id"], ["threat_entities.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "record_id", "entity_id", "relationship_type"),
    )
    op.create_index("ix_intel_entity_links_organization_id", "intel_entity_links", ["organization_id"])
    op.create_index("ix_intel_entity_links_record_id", "intel_entity_links", ["record_id"])
    op.create_index("ix_intel_entity_links_entity_id", "intel_entity_links", ["entity_id"])
    op.create_index("ix_intel_entity_links_entity", "intel_entity_links", ["organization_id", "entity_id"])

    op.create_table(
        "attack_technique_mappings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("entity_id", sa.Uuid(), nullable=False),
        sa.Column("technique_id", sa.String(16), nullable=False),
        sa.Column("technique_name", sa.String(255), nullable=False),
        sa.Column("rationale", sa.String(1000), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("mapping_status", sa.String(24), nullable=False),
        sa.Column("source_reference", sa.String(2048), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["entity_id"], ["threat_entities.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "entity_id", "technique_id"),
    )
    op.create_index("ix_attack_technique_mappings_organization_id", "attack_technique_mappings", ["organization_id"])
    op.create_index("ix_attack_technique_mappings_entity_id", "attack_technique_mappings", ["entity_id"])
    op.create_index("ix_attack_mappings_org_technique", "attack_technique_mappings", ["organization_id", "technique_id"])


def downgrade() -> None:
    op.drop_table("attack_technique_mappings")
    op.drop_table("intel_entity_links")
    op.drop_table("threat_entities")
