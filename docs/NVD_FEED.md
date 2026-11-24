# NVD CVE feed

ThreatWeave includes an NVD CVE API 2.0 connector. It queries CVEs modified in the most recent seven-day window, requests up to 2,000 results in one bounded HTTPS request, normalizes CVE identifiers, captures English descriptions and CVSS severity, and stores source evidence with an NVD reference URL.

Endpoint: `POST /api/v1/intelligence/feeds/nvd/sync`.

The connector is idempotent for indicator and source-evidence records. When a CVE already exists (for example from CISA KEV), NVD evidence is attached to the same canonical CVE indicator instead of creating a duplicate. The response reports `total_results` and `complete_window`; a false `complete_window` means more than the one-page cap matched and this run did not ingest the entire seven-day window. NVD rate limits apply; do not schedule overlapping syncs. An NVD API key can be added later for higher request limits.
