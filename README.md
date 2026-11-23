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

## Phase 0 foundation
- React + TypeScript + Vite dashboard scaffold.
- Python 3.12 + FastAPI API scaffold.
- PostgreSQL and Redis services in Docker Compose.
- Celery dependency and configuration foundation for later background jobs.
- Environment template, `.gitignore`, API health/readiness endpoints, and starter tests.

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
