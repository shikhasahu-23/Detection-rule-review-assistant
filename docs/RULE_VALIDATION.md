# Rule candidate validation

Rule candidates are stored as immutable-in-practice draft records with per-platform version numbers. The API does not expose update, approval, export or deployment operations in this increment.

## Static validation

- Splunk: validates a conservative search entrypoint and warns that SPL syntax and field availability need a representative Splunk test.
- Sentinel: checks for a pipe-delimited KQL pipeline and warns that table/column compatibility must be tested in the target workspace.
- Chronicle: checks for the required YARA-L rule/events/condition sections and warns that compilation and UDM compatibility must be checked in Chronicle.
- CrowdStrike: records a pending-validation warning; no grammar assumptions are made until the current NG-SIEM query contract is verified.

A passing static check is not a production-ready or deployable rule. Every report includes `is_deployable: false`. Full parser/compiler validation, fixture execution, evidence coverage and approval gates remain required before export.


## Searchable rule library

The read-only rule library endpoint is `GET /api/v1/rules`. It searches candidate versions across detection intents and supports:

- `q`: case-insensitive substring search over rule name and query text.
- `platform`: exact platform filter (`splunk`, `sentinel`, `chronicle`, `crowdstrike`).
- `validation_status`: exact validation outcome filter.
- `candidate_status`: lifecycle status filter.
- `intent_id`: scope results to one detection intent.
- `limit` and `offset`: pagination (limit 1–500; offset 0 or greater).

The Rule Library UI exposes search, platform and validation filters, refresh, and pagination. It displays the candidate's validation findings and explicitly labels each version as not approved and not deployable. This feature does not add approval, export, deployment, IAM, or audit workflow behavior.
