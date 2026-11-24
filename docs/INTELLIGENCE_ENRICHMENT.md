# Intelligence Enrichment and Correlation

## Purpose

ThreatWeave exposes explainable enrichment and detection-opportunity results using existing indicator, source-evidence, ATT&CK technique and detection-intent records. The first implementation is read-only and does not alter source intelligence or approve detections.

## API

### Indicator enrichment

`GET /api/v1/intelligence/indicators/{indicator_id}/enrichment`

Returns:
- Indicator identity, type, value, status, confidence and severity.
- Freshness classification derived from last-seen/first-seen timestamps: fresh (0–7 days), aging (8–30 days), stale (over 30 days), or unknown.
- Source names and source-evidence count.
- ATT&CK catalog entries only when an exact technique ID is present in indicator metadata or source evidence.
- Detection intents only when an exact ATT&CK technique ID or CVE identifier is shared with the intent's explicit references.
- Rationale and correlation method.

Returns 404 when the indicator does not exist.

### Detection opportunities

`GET /api/v1/intelligence/detection-opportunities?limit=100`

Groups active indicators by detection intent where an exact reference match exists. The limit is bounded to 1–500. Each result includes matched indicator summaries, source-evidence counts, matching ATT&CK IDs/CVEs, target platforms and a human-readable rationale.

## Correlation rules and limitations

- ATT&CK matches are exact technique ID matches, not semantic similarity.
- CVE matches are exact CVE identifier matches in indicator evidence and explicit detection-intent evidence references.
- Source evidence remains the provenance record; the API does not rewrite it.
- No actor, malware, campaign, infrastructure or attribution relationships are inferred.
- Freshness is a transparent age band, not a threat score or confidence adjustment.
- A correlation is a triage opportunity, not proof of exploitation or a production-ready detection.
- Existing detection candidates remain unapproved and non-deployable.

## Operational notes

The current implementation computes results on read and does not persist derived enrichment. The opportunity endpoint evaluates up to 1,000 most recently created active indicators per request before applying its output limit. Production scale may require indexed relationship tables, background materialization, tenant-scoped authorization and pagination.

## Tests

Service tests cover exact ATT&CK/CVE matching, grouping into opportunities, and the absence of heuristic associations for unrelated indicators.
