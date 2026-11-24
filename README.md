# Detection Rule Review Assistant

A team-oriented, threat-intelligence-driven detection engineering platform.

## Product decisions
- Hybrid AI generation with deterministic validation.
- Multi-provider LLM architecture (OpenAI selected as the initial provider; provider abstraction allows future approved providers).
- Reputable public intelligence sources plus configurable custom feeds.
- Daily ingestion and enrichment.
- Automatically generate candidate rules and proposed updates; require human review and approval.
- Team access with role-based permissions and audit history.
- Targets: Splunk SPL, Chronicle YARA-L 2.0, Sentinel KQL, and CrowdStrike Next-Gen SIEM query language.
- Only approved rule versions may be exported/deployed.

## Current foundation
- React + TypeScript + Vite dashboard with API/database readiness status.
- Python 3.12 + FastAPI API, PostgreSQL models and Alembic migration foundation.
- Organization-scoped identity and role authorization checks. Authentication-provider middleware is not configured; protected business APIs intentionally return 401 until trusted identity integration is implemented.
- Canonical intelligence schemas, source-evidence persistence, deduplication, quarantine and ingestion history.
- Connector implementations for CISA KEV, NVD, URLhaus and ThreatFox, with unit tests using mocked HTTP responses.
- Celery ingestion tasks and a daily 02:00 UTC Beat schedule for a separately running worker/scheduler.
- Docker Compose local stack, API health/readiness endpoints and GitHub Actions checks.

## Deployment limitations
The current Render Blueprint deploys the API and static frontend only. It does not deploy the Celery worker or scheduler, so scheduled ingestion does not run on Render. No production identity provider, feed credentials, LLM provider, rule generation, validation or approval workflow is enabled. The dashboard deliberately keeps protected areas locked while authentication is deferred. See [Deployment notes](docs/DEPLOYMENT.md).

## Run locally

1. Install Docker Compose and Node.js 22+ (for local frontend development outside Compose).
2. Copy `.env.example` to `.env` and replace the local database password with a private development value.
3. Start the stack:

   ```bash
   docker compose up --build
   ```

4. Open the frontend at `http://localhost:5173` and API docs at `http://localhost:8000/docs`.
5. Check API health at `http://localhost:8000/health` and readiness at `http://localhost:8000/ready`.

Do not commit `.env` or real API credentials. LLM keys are intentionally not required for the Phase 0 dashboard; configure them only when the generation service is implemented and the provider's data handling is approved.

## Documentation
- [Architecture](docs/ARCHITECTURE.md)
- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Security and governance](docs/SECURITY_AND_GOVERNANCE.md)

## Current status
Phase 0 scaffolding is on the `feature/phase-0-foundation` branch. This is a foundation build, not a production-ready application. Authentication, database migrations/models, feed connectors, LLM calls, platform rule adapters, and deployment integrations remain future work.
