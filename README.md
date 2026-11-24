# ThreatWeave

A team-oriented, threat-intelligence-driven detection engineering platform.

ThreatWeave brings the threat intelligence and detection engineering lifecycle together: intelligence ingestion, enrichment and correlation, AI-assisted detection generation, deterministic validation, human review, versioned rule management, and controlled export.

## Product decisions
- Hybrid AI generation with deterministic validation.
- Multi-provider LLM architecture (OpenAI selected as the initial provider; provider abstraction allows future approved providers).
- Reputable public intelligence sources plus configurable custom feeds (CISA KEV and NVD CVE connectors currently implemented).
- Daily ingestion and enrichment.
- Automatically generate candidate rules and proposed updates; require human review and approval.
- Team access with role-based permissions and audit history.
- Targets: Splunk SPL, Chronicle YARA-L 2.0, Sentinel KQL, and CrowdStrike Next-Gen SIEM query language.
- Only approved rule versions may be exported/deployed.

## Run locally

1. Install Docker Compose and Node.js 22+ (for local frontend development outside Compose).
2. Copy `.env.example` to `.env` and replace the local database password with a private development value.
3. Start the stack:

   ```bash
   docker compose up --build
   ```

4. Open the frontend at `http://localhost:5173` and API docs at `http://localhost:8000/docs`.
5. Check API health at `http://localhost:8000/health` and readiness at `http://localhost:8000/ready`.
6. Celery Beat schedules daily CISA KEV (02:00 UTC) and NVD CVE (03:00 UTC) ingestion; the worker executes jobs. Keep a single Beat instance.

Do not commit `.env` or real API credentials. To use AI-assisted detection generation, set `OPENAI_API_KEY` and optionally `OPENAI_MODEL` in the local `.env` after reviewing the provider's data-handling terms. The Rule Generator creates draft candidates only; every candidate requires analyst review and vendor-side validation.

## Documentation
- [Architecture](docs/ARCHITECTURE.md)
- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Security and governance](docs/SECURITY_AND_GOVERNANCE.md)
- [Detection intent API](docs/DETECTION_INTENTS.md)
- [Rule candidate validation](docs/RULE_VALIDATION.md)
- [LLM generation](docs/LLM_GENERATION.md)
- [NVD CVE feed](docs/NVD_FEED.md)

The product scope and implementation roadmap remain unchanged; ThreatWeave is the product name for the complete platform, not a single detection-review feature.
