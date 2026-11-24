# Threat Entity and Relationship Graph

## Overview

ThreatWeave can import a bounded STIX 2.1 JSON bundle into a normalized, provenance-preserving graph. Supported entity types are threat actors, malware, campaigns, tools, infrastructure and vulnerabilities.

The importer processes STIX Domain Objects (SDOs) and STIX Relationship Objects (SROs). Relationship endpoints must resolve to supported entities already stored or present in the same bundle. Unsupported STIX object types are ignored; relationships with unresolved endpoints are skipped and counted.

## Import

`POST /api/v1/intelligence/feeds/custom/stix`

Request body:

```json
{
  "source_name": "Partner CTI",
  "bundle": {
    "type": "bundle",
    "objects": []
  }
}
```

- Requires a non-empty STIX bundle with no more than 5,000 objects.
- Accepts STIX 2.1; the optional root `spec_version` must be `2.1`.
- Entity identity is deduplicated by entity type and STIX ID.
- Relationships are deduplicated by endpoints, relationship type, source name and STIX relationship ID.
- Re-importing the same bundle from the same source updates existing records rather than duplicating them.
- Each entity/source pair has a separate provenance record, so importing a second source does not erase the first source's evidence.
- Import is transactional. Invalid bundles roll back the current import.

## Read APIs

- `GET /api/v1/intelligence/threat-graph?limit=200`: graph nodes and edges, bounded to 500 nodes and 1,000 edges.
- `GET /api/v1/intelligence/threat-graph/entities?q=&entity_type=&limit=&offset=`: search and filter entities.
- `GET /api/v1/intelligence/threat-graph/relationships?entity_id=&relationship_type=&limit=&offset=`: list source-backed relationships.
- `GET /api/v1/intelligence/threat-graph/entities/{entity_id}/evidence`: list the entity's source evidence.

Supported entity type filters: `threat_actor`, `malware`, `campaign`, `tool`, `infrastructure`, `vulnerability`.

## Provenance and trust semantics

- Every relationship stores its source name, STIX relationship ID, optional source URL, confidence, observation time and description.
- Relationship assertion status is always `source_observed` for imported STIX relationships. It does not mean ThreatWeave independently verified the relationship.
- STIX confidence is retained within the 0–100 range. Missing or malformed confidence defaults to 50; values outside the range are clamped.
- Entity source evidence is stored separately per source and STIX object ID.
- Source-provided names, descriptions and confidence are untrusted content and must not be treated as instructions.
- The current implementation does not create analyst-confirmed relationships or infer actor attribution.

## Operational limitations

The API currently has no tenant-scoped authorization adapter. Keep the development import endpoint behind a trusted network boundary; do not expose it to untrusted users until authentication, organization scoping, request-body size limits, rate limits and audit logging are implemented. Production deployments should use reviewed Alembic migrations rather than development `create_all`.

The UI loads a bounded graph snapshot and displays entities and relationships with source labels. Large graph exploration, graph layout, relationship review and analyst confirmation remain follow-up work.
