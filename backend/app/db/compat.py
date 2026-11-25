"""Small, idempotent compatibility migration for the evolving threat graph schema.

The production database predates the current ThreatEntity model. SQLAlchemy
create_all() creates missing tables but intentionally does not alter existing
ones, so this migration adds the current columns without dropping legacy data.
"""
from sqlalchemy import inspect
from sqlalchemy.engine import Engine


def ensure_threat_graph_schema(engine: Engine) -> None:
    """Bring the PostgreSQL threat graph tables up to the current ORM shape."""
    if engine.dialect.name != "postgresql":
        return

    column_definitions = {
        "external_id": "VARCHAR(255) NOT NULL DEFAULT ''",
        "confidence": "INTEGER NOT NULL DEFAULT 50",
        "source_name": "VARCHAR(100) NOT NULL DEFAULT 'legacy'",
        "source_reference": "VARCHAR(512) NOT NULL DEFAULT 'legacy'",
        "source_url": "VARCHAR(2048)",
        "revoked": "BOOLEAN NOT NULL DEFAULT FALSE",
        "deprecated": "BOOLEAN NOT NULL DEFAULT FALSE",
        "first_seen": "TIMESTAMP WITH TIME ZONE",
        "last_seen": "TIMESTAMP WITH TIME ZONE",
        "updated_at": "TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()",
    }

    with engine.begin() as connection:
        inspector = inspect(connection)
        if not inspector.has_table("threat_entities"):
            return

        existing = {
            column["name"]
            for column in inspector.get_columns("threat_entities")
        }
        for name, definition in column_definitions.items():
            if name not in existing:
                connection.exec_driver_sql(
                    f"ALTER TABLE threat_entities ADD COLUMN {name} {definition}"
                )

        # These columns belonged to the previous multi-tenant entity schema.
        # Keep them and their data, but make them optional because the current
        # source-backed STIX model no longer supplies organization_id or
        # normalized_name.
        for legacy_column in ("organization_id", "normalized_name"):
            if legacy_column in existing:
                connection.exec_driver_sql(
                    f"ALTER TABLE threat_entities ALTER COLUMN {legacy_column} DROP NOT NULL"
                )

        # Backfill old rows before enforcing the current natural key. This is
        # idempotent and preserves legacy names as their external identifiers.
        if "normalized_name" in existing:
            connection.exec_driver_sql(
                """
                UPDATE threat_entities
                SET external_id = COALESCE(NULLIF(normalized_name, ''), id::text)
                WHERE external_id = ''
                """
            )
        else:
            connection.exec_driver_sql(
                "UPDATE threat_entities SET external_id = id::text WHERE external_id = ''"
            )

        unique_names = {
            constraint["name"]
            for constraint in inspect(connection).get_unique_constraints("threat_entities")
        }
        if "uq_threat_entity_type_external_id" not in unique_names:
            connection.exec_driver_sql(
                """
                ALTER TABLE threat_entities
                ADD CONSTRAINT uq_threat_entity_type_external_id
                UNIQUE (entity_type, external_id)
                """
            )

        indexes = {
            index["name"]
            for index in inspect(connection).get_indexes("threat_entities")
        }
        if "ix_threat_entities_type_name" not in indexes:
            connection.exec_driver_sql(
                "CREATE INDEX ix_threat_entities_type_name "
                "ON threat_entities (entity_type, name)"
            )
