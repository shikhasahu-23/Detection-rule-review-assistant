# Detection quality and effectiveness dashboard

## Metrics

- **ATT&CK coverage:** an active Enterprise ATT&CK technique counts as covered only when its exact external ID is explicitly assigned to a detection intent.
- **Tactic coverage:** covered techniques divided by active catalog techniques for each tactic.
- **Detection readiness:** equal-weight average of four dimensions: explicit ATT&CK mapping, lexical telemetry coverage, static validation status, and latest offline query-contract test score for each current platform candidate.
- **Coverage gaps:** active catalog techniques without an explicit detection-intent mapping.

## Interpretation and limitations

This is a prioritization dashboard, not an effectiveness benchmark. It does not infer mappings from query text, and does not claim that an intent detects a behavior. Telemetry coverage is lexical matching, static validation is not a vendor compiler, and offline tests do not execute events or queries. It does not measure true-positive rate, false-positive rate, precision, recall, or production efficacy.

Coverage is limited to the currently synced active Enterprise ATT&CK catalog. Technique mappings are explicit intent metadata. Readiness components without measurements score zero, so missing evidence lowers readiness rather than being treated as success. All candidate statuses remain unchanged; the dashboard does not approve, export, or deploy rules.
