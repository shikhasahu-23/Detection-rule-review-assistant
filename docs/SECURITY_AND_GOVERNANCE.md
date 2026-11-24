# Security and Governance

## Security principles

- Enforce least privilege for users, service accounts, feed credentials and SIEM credentials.
- Enforce organization boundaries in backend authorization and database queries.
- Store secrets in a dedicated secret manager or secure deployment secret store; never commit secrets or log them.
- Use TLS for service-to-service and external connections.
- Validate and size-limit uploads; quarantine malformed or suspicious files.
- Treat feed content, uploaded files and model output as untrusted.
- Protect AI workflows against prompt injection: delimit source text as evidence, separate data from instructions, restrict tools, and validate structured output.
- Apply timeouts, rate limits, retry caps and circuit breakers to connectors and model providers.
- Audit connector changes, generation, validation, review, approval, export and deployment.

## AI governance

- AI proposes detection content; humans approve it.
- Enforce strict structured output schemas and reject invalid responses.
- Record provider/model identifier, prompt-template version, adapter version and generation timestamp.
- Do not send customer-sensitive telemetry or secrets to an LLM provider.
- Review data residency, retention, training-use policy, contracts and organizational approval before enabling a provider.
- Show assumptions, unsupported fields and confidence limitations to reviewers.
- A syntax check or model explanation is not proof of detection effectiveness.

## Rule approval and deployment

- Generated rules begin as candidates.
- Approval applies to an exact immutable version.
- Any content change creates a new version and requires fresh validation and approval.
- Only approved versions can be exported.
- Production deployment, if added, requires an explicit authorized action, least-privilege credentials, audit logging, post-deployment verification and rollback.
- Expired intelligence flags affected rules for review; it does not silently delete or disable them.

## Intelligence provenance

- Preserve source references, source timestamps, ingestion timestamps, parser versions and payload hashes.
- Track confidence, source reliability, first/last seen, expiry and lifecycle state where available.
- Retain multiple source-evidence links for deduplicated indicators.
- Document licensing, terms and rate limits for every feed.
- Quarantine malformed records with diagnostic metadata.
- Quarantine payloads are size-bounded, recursively normalized to JSON-safe values, and redact common credential-like keys (authorization, API keys, secrets, passwords, tokens and credentials). This is defense in depth, not a substitute for excluding secrets from feed payloads.

## Audit and retention

- Audit records are append-only from the application perspective.
- Capture actor, organization, action, target, timestamp, correlation ID and safe metadata.
- Define configurable retention for raw payloads, intelligence, rules, audit events and model metadata.
- Encrypt backups and test restoration.
- Avoid logging full prompts, uploaded payloads, credentials or sensitive customer data by default.

## Minimum security test cases

1. A user in organization A cannot read or mutate organization B data.
2. A Viewer cannot create, edit, approve, configure, export or deploy rules without explicit permission.
3. A Detection Engineer cannot approve their own rule by default; any exception is configurable and documented.
4. A candidate cannot be exported before approval.
5. Editing an approved rule creates a new version and invalidates approval for the changed content.
6. Prompt-injection-bearing feed text cannot change system instructions or trigger tools.
7. Connector secrets never appear in API responses, logs, traces or export manifests.
8. Rate-limited/unavailable feeds retry safely without duplicating records.
9. Expired intelligence flags affected rules but does not silently delete them.
10. Audit history records review, approval, export and deployment transitions.
