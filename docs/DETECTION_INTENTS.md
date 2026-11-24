# Detection Intent API

Detection intents capture platform-neutral behavior before any query language is generated. This separates the analyst's detection objective from vendor-specific syntax.

## Endpoints

- `POST /api/v1/detection-intents` — create a draft intent.
- `GET /api/v1/detection-intents?q=&limit=&offset=` — search/list intents.
- `GET /api/v1/detection-intents/{id}` — retrieve one intent.

## Required content

Each intent includes a behavior statement, severity, one or more telemetry requirements, target platforms, optional ATT&CK technique IDs, evidence references with confidence, and test scenarios. The API validates field lengths, collection sizes, platform names, severity and ATT&CK ID shape. New intents are always created as `draft`; this endpoint does not generate or approve rules.

## Next implementation

The next increment will add structured LLM provider contracts, platform capability checks, per-platform candidate versions and deterministic validation. CrowdStrike query syntax must be implemented against the current vendor contract rather than guessed.
