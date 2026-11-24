# Render deployment notes

## Scope

The current Render Blueprint provisions:
- `detectionops-api`: FastAPI Docker web service.
- `detectionops-web`: Vite-built static frontend.
- `detectionops-db`: PostgreSQL.
- `detectionops-redis`: Key Value.

It does **not** provision a Celery worker or Celery Beat scheduler. The daily ingestion schedule in `backend/app/workers/celery_app.py` runs only when a worker and scheduler are started separately. Therefore, a green API health check does not mean intelligence feeds are being ingested.

## Required service configuration

Configure the following values in the Render dashboard. Do not paste credentials into Git, source files, issues or chat.

### API service

| Environment variable | Value |
|---|---|
| `APP_ENV` | `production` (set by Blueprint) |
| `DATABASE_URL` | Internal connection string from `detectionops-db` (set by Blueprint) |
| `REDIS_URL` | Connection string from `detectionops-redis` (set by Blueprint) |
| `CORS_ORIGINS` | Exact public origin of the frontend, e.g. `https://detectionops-web.onrender.com` |

### Static frontend

| Environment variable | Value |
|---|---|
| `VITE_API_BASE_URL` | API base URL, e.g. `https://detectionops-api.onrender.com` |

Vite variables are embedded at build time. After changing `VITE_API_BASE_URL`, trigger a new static-site build/deploy.

## Post-deploy verification

1. Open `/health` on the API. Expect HTTP 200 and a JSON status of `ok`.
2. Open `/ready` on the API. Expect HTTP 200 and a JSON status of `ready`. This includes a database connectivity check.
3. Open `/docs` to confirm the API schema is served.
4. Open the frontend and confirm the header reports API/database readiness and displays the environment returned by `/health`.
5. Confirm the browser console has no CORS or failed-request errors.

A successful readiness check verifies API and database connectivity only. It does not verify authentication, worker execution, feed ingestion, LLM access or detection workflows.

## Security and feature gates

- Authentication is intentionally deferred. Do not add identity headers, a development bypass or a hard-coded user to make protected APIs accessible.
- Protected identity and intelligence routes must continue to reject unauthenticated requests.
- Do not configure live feed credentials until a secure source-configuration path and secret-handling design are approved.
- Do not enable LLM calls or SIEM export/deployment integrations until their data handling, credentials and approval gates are implemented and reviewed.
- The current Render plan is a prototype configuration. Review current provider limits, persistence, backups and retention before relying on it for operational data.

## Background ingestion

Local Docker Compose includes worker and scheduler processes. The current Render Blueprint does not. Do not describe the daily schedule as active in the hosted environment. Before enabling hosted ingestion, select an appropriate worker/scheduler hosting approach, configure credentials securely, add operational monitoring and test retry/idempotency behavior. Any paid service or plan change requires explicit approval.
