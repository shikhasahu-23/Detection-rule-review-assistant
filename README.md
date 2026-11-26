# ThreatWeave

**ThreatWeave is a threat-intelligence and detection-engineering portfolio.** The public site is hosted on GitHub Pages and serves static, read-only data snapshots. The repository also retains the FastAPI/PostgreSQL/worker backend source for local development and future reactivation.

- **Live portfolio:** https://shikhasahu-23.github.io/ThreatWeave/
- **Source:** https://github.com/shikhasahu-23/ThreatWeave
- **Hosting cost:** GitHub Pages and GitHub Actions (within GitHub's usage limits); no Render runtime is required for the public portfolio.

## What the public portfolio does

- Browse threat-intelligence indicators with source attribution.
- Explore the MITRE ATT&CK Enterprise catalog and threat-relationship graph.
- Review exported detection intents and rule candidates for Splunk, Chronicle, Sentinel and Sigma.
- Inspect historical feed and pipeline snapshots.
- Read attributed cybersecurity headlines from public RSS sources.
- Explore local, evidence-backed correlation between archived detection intents and indicator references.

The site is **read-only**. It does not provide accounts, shared writes, live API queries, CSV/STIX imports, on-demand feed sync, persistent rule creation, rule generation, test execution, or on-demand news ingestion. Controls that require backend writes are unavailable in the static deployment. Do not use it as a live SOC/SIEM console or as the sole source of operational intelligence.

## Public data and refresh schedule

GitHub Actions refreshes these public sources every day at **08:00 India Standard Time (02:30 UTC)**:

- CISA Known Exploited Vulnerabilities (KEV).
- MITRE ATT&CK Enterprise.
- Public RSS headlines from CISA Advisories, BleepingComputer and The Hacker News.

Cyber-news severity is a keyword-based triage label (not CVSS or a verified incident rating); impact text is a generic analyst prompt. Correlation is calculated in the browser only from exact CVE/indicator references present in exported detection-intent evidence and the published indicator snapshot.

The refresh commits validated JSON to `frontend/public/data/`; GitHub Pages then republishes the updated static site. See [GitHub Pages portfolio operations](docs/GITHUB_PAGES_PORTFOLIO.md) for the data contract, provenance and troubleshooting.

The initial migration snapshot also preserves the available production archive: 5,225 historical indicators, 69 detection intents, 344 rule candidates, 706 ATT&CK techniques, 102 threat entities and 108 relationships, plus feed/pipeline history. These are a point-in-time export, not a live database. The public refresh currently replaces the indicator and ATT&CK catalog datasets with current CISA KEV and MITRE data; it does not recreate historical detection-intent/rule writes.

### Severity and confidence

- CISA KEV membership means the vulnerability is listed as known exploited; it is not itself a CVSS score.
- The refresh labels KEV items **High** when CISA flags known ransomware campaign use and **Medium** otherwise. This is a portfolio prioritization heuristic, not a vendor severity or CVSS calculation.
- CVSS is shown only when a source provides a CVSS score. A blank score means unavailable, not zero.
- Confidence values are source/ingestion metadata and must not be interpreted as a universal probability of compromise.

## Run the static frontend locally

Requirements: Node.js 22+ and npm.

```bash
cd frontend
npm install
VITE_BASE_PATH=/ npm run dev
```

Open the local Vite URL. To build the GitHub Pages artifact:

```bash
VITE_BASE_PATH=/ThreatWeave/ npm run build
```

The frontend reads static JSON from `frontend/public/data/`; it does not need the Render API.

## Backend source (optional local development)

The backend source remains in the repository but is not deployed by the public GitHub Pages site. To run the full historical development stack, install Docker Compose, copy `.env.example` to `.env`, set a private development password, then run:

```bash
docker compose up --build
```

The local API is available at `http://localhost:8000` and frontend at `http://localhost:5173`. Backend features, authentication, authorization, migrations and integrations must be configured and tested before exposing a backend publicly. Never commit `.env`, tokens, private IOCs or organization-specific data.

## Repository documentation

- [GitHub Pages portfolio operations](docs/GITHUB_PAGES_PORTFOLIO.md) — live architecture, data contract, refresh and troubleshooting.
- [System architecture (backend design)](docs/ARCHITECTURE.md)
- [Security and governance](docs/SECURITY_AND_GOVERNANCE.md)
- [Detection intent API](docs/DETECTION_INTENTS.md)
- [Rule candidate validation](docs/RULE_VALIDATION.md)
- [Rule generation](docs/FREE_RULE_GENERATION.md)
- [MITRE ATT&CK catalog](docs/ATTACK_CATALOG.md)
- [Custom feed import (backend/local only)](docs/CUSTOM_FEED_IMPORT.md)
- [NVD feed (backend/local only)](docs/NVD_FEED.md)

The backend design documents describe source-code capabilities and intended architecture; they do not imply those write workflows are available on the static public site.
