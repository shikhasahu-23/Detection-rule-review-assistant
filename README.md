# Detection Rule Review Assistant

A team-oriented, threat-intelligence-driven detection engineering platform.

## Confirmed product decisions
- **AI:** Hybrid generation with deterministic validation.
- **Intelligence:** Reputable public sources plus configurable custom feeds.
- **Rule lifecycle:** Automatically generate candidate rules and proposed updates; require human review and approval.
- **Audience:** Security engineering teams with role-based access and audit history.
- **Targets:** Splunk SPL, Google SecOps / Chronicle YARA-L 2.0, Microsoft Sentinel KQL, and CrowdStrike Next-Gen SIEM query language.
- **Refresh:** Daily scheduled ingestion.
- **Deployment:** Only approved rule versions may be exported or deployed. No automatic production deployment of unreviewed rules.

## Workflow
Threat intelligence → normalization and enrichment → correlation → platform-neutral detection intent → platform-specific generation → deterministic validation → human review → approved rule library → controlled export/deployment.

## Documentation
- [Architecture](docs/ARCHITECTURE.md)
- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Security and governance](docs/SECURITY_AND_GOVERNANCE.md)

## Proposed technology stack
React + TypeScript, Python + FastAPI, PostgreSQL, Celery + Redis, STIX 2.x / TAXII support, Docker Compose, and automated tests.

## Current status
The repository is being initialized with architecture and implementation planning. Application code and production integrations are not yet implemented.
