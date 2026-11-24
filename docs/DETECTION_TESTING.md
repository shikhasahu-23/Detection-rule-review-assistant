# Detection testing and simulation

## Current test mode: offline query-contract checks

ThreatWeave accepts positive, negative and edge scenario records with fixture context and explicit query-text assertions. Assertions support:

- `contains`: the candidate query must include a whole-token term.
- `not_contains`: the candidate query must not include a whole-token term.

Runs persist the test suite fingerprint, exact query SHA-256 fingerprint, case-level results and summary. When the same test suite is run against a later candidate version for the same intent and platform, ThreatWeave compares case results and reports regressions and improvements.

## Important boundary

This is a deterministic offline query-contract harness. It does **not** execute SPL, KQL, YARA-L or CrowdStrike queries; it does not execute fixture events, emulate a SIEM, or measure runtime false-positive/true-positive rates. Scenario fixtures are retained as context for review only. A passed result means the authored query-text assertions passed, not that the detection works in a target platform.

Native query execution requires isolated platform adapters, credentials, representative data, and explicit safeguards. Those are separate future integrations. Every rule candidate remains unapproved and non-deployable.
