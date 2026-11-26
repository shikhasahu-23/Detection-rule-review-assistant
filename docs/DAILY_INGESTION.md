> **Current public deployment:** the GitHub Pages portfolio does not run Celery, Redis or the API. Its active scheduled refresh is GitHub Actions at 02:30 UTC (08:00 IST), refreshing CISA KEV and MITRE ATT&CK static JSON only. The Celery schedule below applies only to the optional local backend stack and is not active on the public site. See [GitHub Pages portfolio operations](GITHUB_PAGES_PORTFOLIO.md).

# Daily intelligence ingestion

Celery Beat schedules two independent jobs in UTC:

- CISA KEV daily at 02:00 UTC.
- NVD CVE daily at 03:00 UTC.
- MITRE ATT&CK Enterprise catalog daily at 04:00 UTC.

The worker uses the same connector functions as the manual API endpoints, so both paths share normalization, deduplication, source evidence and feed-run history. Transient task exceptions are retried with exponential backoff up to three times. Connector failures are recorded as failed feed runs before the task retries.

Run locally with Docker Compose. The `worker` service executes queued tasks and the `beat` service publishes the daily schedule. Do not run multiple Beat instances against the same schedule. For production, use a single scheduler instance, monitor Celery task failures and NVD rate limits, and migrate the development `create_all` bootstrap to reviewed Alembic migrations.
