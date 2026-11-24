# Daily intelligence ingestion

Celery Beat schedules two independent jobs in UTC:

- CISA KEV daily at 02:00 UTC.
- NVD CVE daily at 03:00 UTC.

The worker uses the same connector functions as the manual API endpoints, so both paths share normalization, deduplication, source evidence and feed-run history. Transient task exceptions are retried with exponential backoff up to three times. Connector failures are recorded as failed feed runs before the task retries.

Run locally with Docker Compose. The `worker` service executes queued tasks and the `beat` service publishes the daily schedule. Do not run multiple Beat instances against the same schedule. For production, use a single scheduler instance, monitor Celery task failures and NVD rate limits, and migrate the development `create_all` bootstrap to reviewed Alembic migrations.
