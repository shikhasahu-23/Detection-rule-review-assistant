# Automated Intelligence-to-Detection Pipeline

## Daily schedule (UTC)

| Time | Job |
|---|---|
| 02:00 | CISA KEV ingestion |
| 03:00 | NVD CVE ingestion |
| 04:00 | MITRE ATT&CK catalog synchronization |
| 05:00 | Enrichment, correlation and draft candidate generation |

Celery Beat publishes the jobs. Celery workers must be running to execute them. Redis is used as broker and result backend.

## End-to-end flow

1. **Ingest:** The existing CISA KEV, NVD CVE and MITRE ATT&CK jobs run independently, retaining their feed-run status and source evidence.
2. **Enrich:** The pipeline processes up to 1,000 active indicators per run and resolves explicit ATT&CK technique references against the local catalog.
3. **Correlate:** Existing correlation logic matches exact ATT&CK technique IDs and CVE references shared with detection intents. It does not infer actor attribution from keyword similarity.
4. **Generate:** For matched intents, the configured generation provider drafts a query for each target platform. A candidate already created by the pipeline for that intent/platform is skipped on subsequent runs.
5. **Validate:** Each draft passes through the conservative static validator. Candidates remain in `candidate` status and `is_deployable=false`.

## Trigger and status APIs

- `POST /api/v1/intelligence/pipeline/runs` queues a full manual run including feed synchronization. Returns HTTP 202 and a Celery task ID.
- `GET /api/v1/intelligence/pipeline/runs?limit=20` lists persisted run history.
- `GET /api/v1/intelligence/pipeline/runs/{run_id}` retrieves an individual run.

The Intelligence Center provides a Run full pipeline control and a history view. Scheduled runs consume the feed data produced by the preceding 02:00–04:00 UTC jobs and do not re-fetch those feeds.

## Execution and failure semantics

- Feed ingestion, enrichment, correlation and generation outcomes are recorded per stage.
- Feed failures do not prevent downstream processing of previously ingested intelligence.
- A run is marked `partial_success` if one or more stages fail but other stages complete; it is `failed` when all recorded stages fail.
- Provider failures are recorded per intent/platform; they do not stop other candidates from being processed.
- Pipeline-generated candidates are deduplicated by intent, platform and generator marker.
- Celery retries task-level unhandled failures with exponential backoff (two retries for the orchestration task).

## Configuration and deployment

- Set `OPENAI_API_KEY` and `OPENAI_MODEL` (or the configured settings equivalents) on the worker environment to enable generation.
- Run the API, Redis, Celery worker and Celery Beat processes. The API's queue endpoint only enqueues work; it does not execute a pipeline in the request process.
- The development app uses `Base.metadata.create_all`. Production needs a reviewed Alembic migration for the `pipeline_runs` table before rollout.
- This is not a tenant-isolated production service yet. Keep manual pipeline triggering and feed import behind trusted network access until authentication, organization scoping, rate limiting and audit controls are enforced.

## Current limitations

- Enrichment is computed from stored evidence during each run; the current milestone does not persist a separate enrichment snapshot per indicator.
- The daily job has a bounded 1,000-indicator enrichment pass and 500-opportunity correlation response.
- Candidate generation depends on a configured LLM provider and costs provider tokens. Configure budgets and usage monitoring before enabling it in production.
- Static query validation is not equivalent to running platform compilers or executing detection tests.
- No approval, export, deployment or automatic rule activation is performed.
