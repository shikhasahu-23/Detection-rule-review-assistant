# Rule candidate validation

Rule candidates are stored as immutable-in-practice draft records with per-platform version numbers. The API does not expose update, approval, export or deployment operations in this increment.

## Static validation

- Splunk: validates a conservative search entrypoint and warns that SPL syntax and field availability need a representative Splunk test.
- Sentinel: checks for a pipe-delimited KQL pipeline and warns that table/column compatibility must be tested in the target workspace.
- Chronicle: checks for the required YARA-L rule/events/condition sections and warns that compilation and UDM compatibility must be checked in Chronicle.
- CrowdStrike: records a pending-validation warning; no grammar assumptions are made until the current NG-SIEM query contract is verified.

A passing static check is not a production-ready or deployable rule. Every report includes `is_deployable: false`. Full parser/compiler validation, fixture execution, evidence coverage and approval gates remain required before export.
