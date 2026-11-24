# Detection generation hardening

## Versioned platform contracts

Every supported platform has a prompt contract with an explicit version and validation scope:

- Splunk: native SPL, conservative entrypoint and no invented index, sourcetype, macro or field names.
- Microsoft Sentinel: native KQL with a tabular source; table and column compatibility must be verified in the target workspace.
- Google SecOps / Chronicle: YARA-L 2.0 structure, with UDM field compatibility and compilation still requiring target-platform validation.
- CrowdStrike Falcon Next-Gen SIEM: cautious mode only. The current grammar is not asserted as verified; drafts must be treated as non-operational until the vendor contract and approved templates are available.

The OpenAI provider includes the platform contract and treats intent content as untrusted data. Each generated candidate stores provider, model, prompt-contract version, generation timestamp and validation scope in `generation_metadata`.

## Telemetry coverage

The validator checks whether explicitly required telemetry fields occur as whole tokens in the generated query. It reports a score, matched/total counts and individual fields in `validation_report.telemetry_coverage`. This is a lexical indicator only; it cannot verify schema availability, data source health, field semantics or runtime behavior. No explicit fields means `not_assessed`, not 100%.

## Fixtures and safety

Platform query fixtures exercise the current static checks. Fixtures are examples, not vendor compiler certification. Every report continues to return `is_deployable=false`. No approval, export, deployment or activation is introduced.

## Schema rollout

The new `generation_metadata` JSON column is added to the SQLAlchemy model. Development bootstrap creates it for fresh databases; existing deployments must apply a reviewed Alembic migration before using the new API response model.
