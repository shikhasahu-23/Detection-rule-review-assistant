# Threat Intelligence Center

## First vertical slice

The Intelligence API introduces a canonical indicator store, source-evidence provenance, feed-run history, and a CISA Known Exploited Vulnerabilities (KEV) connector.

### API

- `GET /api/v1/intelligence/summary` — indicator and source totals plus latest ingestion.
- `GET /api/v1/intelligence/indicators?q=&indicator_type=&limit=&offset=` — paginated indicator search.
- `GET /api/v1/intelligence/indicators/{id}/evidence` — original source evidence for an indicator.
- `GET /api/v1/intelligence/feeds` — latest status per feed.
- `POST /api/v1/intelligence/feeds/cisa-kev/sync` — fetch and ingest the official CISA KEV JSON feed.

### Data and safety

Indicators are deduplicated by (type, value); source evidence is deduplicated by indicator, source and source reference. Repeated ingestion is safe and does not erase earlier provenance. The CISA connector uses a fixed HTTPS URL, a finite timeout and a bounded response read. Feed fields are treated as untrusted data. The API never executes feed content.

### Local setup

Start PostgreSQL and Redis using the repository's Docker Compose configuration, then run the API. Tables are created from SQLAlchemy metadata on application startup for this development slice. Production rollout must replace startup `create_all` with reviewed Alembic migrations, add authenticated organization-scoped access, and configure feed scheduling/retries before enabling multi-tenant use.

### Next connectors

Add NVD, URLhaus, ThreatFox, OTX, MITRE ATT&CK, CSV/JSON, STIX and TAXII through the same connector contract, preserving raw evidence and idempotent normalization.
