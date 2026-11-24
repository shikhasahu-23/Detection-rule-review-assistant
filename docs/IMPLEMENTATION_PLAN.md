# Implementation Plan

## Delivery objective

Deliver a team application that ingests threat intelligence daily, enriches and correlates it, generates candidate detections for four platforms, validates them deterministically, and routes every new or changed rule through human approval.

## Phase 0 — Repository foundation

**Deliverables**
- React + TypeScript frontend scaffold.
- Python + FastAPI backend scaffold with versioned API.
- PostgreSQL and Alembic migrations.
- Redis, Celery worker and scheduler.
- Docker Compose local environment.
- CI for formatting, linting, typing, tests and dependency/security checks.
- Environment configuration and safe `.env.example`.
- Structured logging and health/readiness endpoints.

**Acceptance criteria**
- Full stack starts from documented commands.
- Health checks pass and migrations create a clean schema.
- CI runs on pull requests.
- No secrets are committed.

## Phase 1 — Team identity, authorization and audit

**Deliverables**
- Organization, user and team membership models.
- Roles: Admin, Detection Engineer, Reviewer/Approver, Viewer.
- Authentication abstraction; confirm OIDC/SSO provider before production.
- API authorization and organization-scoped queries.
- Append-only audit event service.
- Basic team administration screens.

**Acceptance criteria**
- Automated tests prove cross-organization access is denied.
- Viewers cannot create, edit, approve or configure connectors.
- Sensitive connector and rule lifecycle changes are audited.
- Secrets are never logged.

## Phase 2 — Intelligence ingestion and Intelligence Center

**Deliverables**
- Connector interface: configure, fetch, checkpoint, parse, normalize and health.
- Candidate connectors: CISA KEV/advisories, NVD, URLhaus, ThreatFox, OTX and MITRE ATT&CK; prioritize based on verified API access and terms.
- CSV/JSON uploads, STIX bundle support and configurable TAXII sources.
- Canonical intelligence and source-evidence persistence.
- Deduplication, provenance, confidence, timestamps, expiry and quarantine.
- Daily Celery schedules, retries, checkpoints and ingestion history.
- Intelligence Center UI with filters, detail view and source health.

**Acceptance criteria**
- Re-running a feed window is idempotent.
- Every indicator links to one or more source evidence records.
- Invalid records are quarantined with diagnostic details.
- Daily job status and last successful run are visible.
- Upload results report accepted, duplicate and rejected counts.
- Connector terms, rate limits and credentials are documented.

## Phase 3 — Enrichment, correlation and detection intent

**Delivered foundation**
- Read-only indicator enrichment joins source evidence to the synchronized ATT&CK catalog using exact technique IDs found in indicator metadata or source evidence.
- Detection opportunities are grouped by detection intent only when an exact ATT&CK technique ID or CVE identifier is shared with indicator evidence.
- Results expose provenance, evidence counts, confidence, severity, freshness, platform targets and an explicit correlation rationale.
- Heuristic actor, malware and campaign attribution is deliberately not inferred.
- Platform-neutral detection intent schema and preview.

**Remaining deliverables**
- Threat entity models for actors, malware, campaigns, tools and infrastructure.
- Additional relationship evidence and analyst-confirmed associations.
- Configurable lifecycle scoring and expiry policies.
- Organization-configurable data-source and field catalog.

**Acceptance criteria**
- Correlation results retain links to contributing indicators and their evidence counts.
- Uncertain or inferred mappings are not presented as confirmed.
- Detection intent includes required telemetry, behavior, test scenarios and evidence.
- Analysts can inspect and edit intent before generation.

## Phase 4 — Hybrid multi-platform generation

**Deliverables**
- LLM provider abstraction with structured output and prompt-template versioning.
- Guardrails for untrusted feed content.
- Platform adapter interface and capability matrix.
- Splunk SPL adapter.
- Chronicle YARA-L 2.0 adapter.
- Sentinel KQL adapter.
- CrowdStrike NG-SIEM adapter, built against the verified current contract.
- Immutable RuleVersion records with evidence and generator metadata.
- Rule Generator UI with platform selector and comparison.

**Acceptance criteria**
- One detection intent can generate separate platform candidates.
- Each candidate includes rationale, evidence, severity, ATT&CK mapping, required data, limitations and test suggestions.
- Unsupported fields and assumptions are explicit.
- Adapter tests include representative fixtures.
- Provider/model and prompt-template versions are recorded.
- Invalid model output cannot be stored as a valid candidate.

## Phase 5 — Deterministic validation and human review

**Deliverables**
- Validation pipeline: schema, metadata, evidence, freshness, field mapping, duplicates, supported syntax checks and fixture tests.
- Findings with severity and remediation guidance.
- Review queue, assignment, comments, request changes, approve and reject.
- Rule state machine, immutable versions and diff view.
- Review notifications and audit history.

**Acceptance criteria**
- Generated/changed rules remain candidates until approved.
- Approval binds to exact immutable version and validation evidence.
- Mandatory failed checks block approval unless an authorized, audited exception exists.
- Editing approved content creates a new candidate and requires fresh validation/approval.
- No unreviewed version can be exported or deployed.

## Phase 6 — Rule library, dashboard and daily automation

**Deliverables**
- Searchable Rule Library with platform, status, severity, ATT&CK, source, owner and freshness filters.
- Dashboard: active/new intel, candidates, pending reviews, validation failures, approved rules, feed health and ATT&CK coverage.
- Daily workflow: ingest → normalize → enrich → correlate → generate candidates → validate → create review tasks.
- Approved rule export with evidence manifest and validation report.
- Stale-intel impact analysis and daily team digest.

**Acceptance criteria**
- Daily configured jobs create review items without manual intervention.
- Approved rules are not overwritten; updates create new versions.
- Stale intel identifies affected rules.
- Export is denied for unapproved versions.
- Dashboard metrics reconcile with persisted records and job history.

## Phase 7 — Production hardening and controlled integrations

**Deliverables**
- OIDC/SSO and identity-provider MFA.
- Production secrets manager integration.
- Security review and threat model.
- Load, resilience, backup/restore and disaster recovery tests.
- Optional SIEM deployment connectors behind feature flags and approval gates.
- Deployment rollback, post-deployment verification and operator runbooks.

**Acceptance criteria**
- Production deployment requires explicit authorization and least-privilege credentials.
- Actor, target, rule version hash and outcome are audited.
- Rollback is tested before enabling deployment.
- Backup restoration is demonstrated.
- Critical/high security findings are addressed before production.

## Initial backlog

| ID | Work item | Priority | Phase |
|---|---|---:|---:|
| PLAT-001 | Scaffold frontend, API, worker, scheduler, DB and Docker Compose | P0 | 0 |
| PLAT-002 | CI, linting, typing and test conventions | P0 | 0 |
| IAM-001 | Organization/user/team/role model | P0 | 1 |
| IAM-002 | Organization scoping and API RBAC | P0 | 1 |
| AUD-001 | Append-only audit service | P0 | 1 |
| INT-001 | Connector interface and canonical intel schema | P0 | 2 |
| INT-002 | CISA KEV and NVD connectors | P0 | 2 |
| INT-003 | URLhaus and ThreatFox connectors | P1 | 2 |
| INT-004 | OTX, CISA advisories and ATT&CK ingestion | P1 | 2 |
| INT-005 | CSV/JSON/STIX upload | P1 | 2 |
| INT-006 | Daily schedules, checkpoints, retries and feed health | P0 | 2 |
| ENR-001 | Provenance, confidence, expiry and deduplication | P0 | 2 |
| ENR-002 | Threat entity correlation and ATT&CK mapping | P1 | 3 |
| DET-001 | Platform-neutral detection intent schema | P0 | 3 |
| AI-001 | Structured LLM abstraction and prompt versioning | P0 | 4 |
| ADP-001 | Splunk SPL adapter and fixtures | P0 | 4 |
| ADP-002 | Chronicle YARA-L 2.0 adapter and fixtures | P0 | 4 |
| ADP-003 | Sentinel KQL adapter and fixtures | P0 | 4 |
| ADP-004 | Verify and implement CrowdStrike NG-SIEM adapter | P0 | 4 |
| VAL-001 | Deterministic validation pipeline | P0 | 5 |
| REV-001 | Review queue, decisions and immutable versions | P0 | 5 |
| LIB-001 | Searchable rule library and version diff | P1 | 6 |
| AUTO-001 | Daily ingestion-to-review automation | P0 | 6 |
| EXP-001 | Approved rule export and evidence manifest | P1 | 6 |
| OPS-001 | Metrics, alerts, backup/restore and runbooks | P0 | 7 |

## Milestones

- **MVP 1:** Team foundation, initial intelligence connectors and Intelligence Center.
- **MVP 2:** Detection intent, first platform adapter and review workflow.
- **MVP 3:** Four adapters, deterministic validation, rule library and approved exports.
- **MVP 4:** Daily end-to-end automation, dashboard and stale-intel impact analysis.
- **Production readiness:** SSO, security controls, operations, resilience and optional controlled deployment.

Delivery dates require confirmation of team capacity, identity provider, LLM provider and hosting environment.

## Definition of done

Every feature includes documented acceptance criteria and failure modes, unit/integration tests, authorization tests, safe logs/metrics, migrations where needed, updated documentation, and proof that approval gates cannot be bypassed.
