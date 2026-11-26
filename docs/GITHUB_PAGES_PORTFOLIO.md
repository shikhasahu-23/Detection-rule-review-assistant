# GitHub Pages portfolio: operations and data contract

## Deployment architecture

```text
CISA KEV ───────┐
                ├─ GitHub Actions (daily, 02:30 UTC) ─ validate ─ commit JSON
MITRE ATT&CK ───┘                                           │
                                                            ▼
                                                GitHub Pages static site
                                                /ThreatWeave/
```

GitHub Pages hosts only static assets. There is no API server, database, Redis/Valkey instance, worker, scheduler process, authentication layer or persistent write path in this deployment. The FastAPI/PostgreSQL/Celery source remains in the repository for local development and possible future hosting.

## Data files

All public datasets are stored under `frontend/public/data/` and served below `/ThreatWeave/data/`.

| File | Purpose | Update behavior |
|---|---|---|
| `summary.json` | Portfolio totals and latest refresh metadata | Rebuilt daily |
| `indicators.json` | Current CISA KEV indicator set | Replaced daily |
| `attack-techniques.json` | MITRE ATT&CK Enterprise techniques | Replaced daily |
| `feeds.json` | Status of CISA KEV and MITRE ATT&CK | Rebuilt daily |\n| `cyber-news.json` | Attributed CISA, BleepingComputer and The Hacker News RSS headlines | Rebuilt daily; last good snapshot retained if all feeds fail |
| `indicators-history-*.json` | Historical indicator export | Migration snapshot; not refreshed |
| `detection-intents.json` | Exported production detection intents | Migration snapshot; not refreshed |
| `rules-1.json` … `rules-6.json` | Exported rule candidates in bounded batches | Migration snapshot; not refreshed |
| `threat-graph.json` | Exported entities and relationships | Migration snapshot; not refreshed |
| `pipeline-runs.json` | Exported pipeline history | Migration snapshot; not refreshed |

The initial export captured 5,225 historical indicators, 69 detection intents, 344 rule candidates, 706 ATT&CK techniques, 102 entities and 108 relationships. The historical files are public repository content; only publish public-source or explicitly sanitized information.

## Source provenance and scoring

- CISA KEV source: [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Each KEV item includes its CVE ID, CISA short description/vendor/product and source attribution.
- MITRE source: [MITRE ATT&CK Enterprise STIX data](https://github.com/mitre-attack/attack-stix-data). Technique records include ATT&CK ID, name, description, platforms, tactics and source URL.
- KEV membership is not a CVSS rating. Current portfolio severity is a simple operational heuristic: High for entries where CISA flags known ransomware campaign use; Medium for other KEV entries.
- Confidence is not a universal probability. CVSS is null unless explicitly provided by a CVSS-bearing source. Do not convert missing values to zero.
- The static refresh does not ingest NVD CVSS, URLhaus, ThreatFox, custom feeds or user uploads. The archived historical snapshot may contain other source names, but these sources are not part of the current scheduled refresh.\n- Cyber-news severity is a keyword-based triage label, not CVSS or a verified incident severity. Impact text is a generic analyst prompt; always open the linked publisher source.\n- Correlation is computed in the browser using exact CVE/indicator references in archived detection-intent evidence matched against the public indicator snapshot. It does not infer actor attribution or create new source relationships.

## Scheduled refresh

Workflow: `.github/workflows/refresh-static-intelligence.yml`

- Schedule: `30 2 * * *` UTC = 08:00 IST.
- Manual run: GitHub → Actions → Refresh public threat intelligence → Run workflow.
- Permissions: repository contents write, scoped to the workflow.
- Steps: fetch CISA KEV and MITRE ATT&CK; fetch public RSS headlines; normalize; write compact JSON; validate schemas; commit only when data changes. If every RSS source fails, preserve the last published news items.
- A successful data commit triggers the GitHub Pages deployment workflow.

Do not add API keys to frontend environment variables or static files. Public feeds used by this workflow do not require a secret. Never place a GitHub token in browser code.

## Local checks

```bash
python -m py_compile scripts/refresh_static_intelligence.py scripts/refresh_public_news.py
python - <<'PY'
import json
from pathlib import Path
root = Path("frontend/public/data")
for name in ("summary.json", "indicators.json", "feeds.json", "attack-techniques.json", "cyber-news.json"):
    json.loads((root / name).read_text())
print("Public datasets parse successfully")
PY
cd frontend
npm install
VITE_BASE_PATH=/ThreatWeave/ npm run build
```

CI also verifies the frontend build and absence of the legacy Render API URL in the generated bundle. The deployment workflow checks the published site and key JSON URLs.

## Known limitations

- Static data is read-only and is refreshed on a schedule, not continuously.
- Detection intents, rules, graph and pipeline history are snapshots; they are not updated by the daily CISA/MITRE job.
- Rule creation/generation, CSV/STIX imports, test execution, feed sync and other write actions require a backend and are not available on Pages.
- Cyber-news is a daily public RSS snapshot, not a live news search. Detection-effectiveness metrics still require the backend and are not recalculated on Pages.
- Static content is public. Do not commit customer data, private indicators, credentials, access tokens or confidential detection logic.
- The archived backend is not automatically deployed. A future backend requires a separately funded/free hosting decision, database migrations, auth, secret management, backups and security review.

## Troubleshooting

- **Site shows old data:** check the latest refresh workflow run, then the Pages deployment run. A refresh only publishes when the JSON changes.
- **JSON 404:** confirm the file exists under `frontend/public/data/` and that the Pages base path remains `/ThreatWeave/`.
- **Build fails:** run the local checks above and inspect the CI / Deploy frontend to GitHub Pages logs.
- **A write action fails:** expected on the read-only site; use a local backend development environment or plan a backend deployment before enabling it.
