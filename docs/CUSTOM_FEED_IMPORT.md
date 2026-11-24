# Custom CSV indicator import

Endpoint: `POST /api/v1/intelligence/feeds/custom/csv` with `Content-Type: text/csv` and the CSV bytes as the raw request body.

Required columns: `indicator_type,value`.

Optional columns: `confidence,severity,status,description,tags,source_name,source_reference,source_url`.

Supported indicator types: IP/IPv4/IPv6, domain, URL, MD5, SHA-1, SHA-256, generic hash (length-inferred), email and CVE. Values are normalized and validated; malformed rows are rejected with row-level diagnostics. The import is capped at 5,000 rows and 2 MB at the API boundary. Each accepted row creates or reuses a canonical indicator and attaches source evidence. Re-running the same source reference is idempotent.

Source URLs are stored as provenance only; ThreatWeave does not fetch them. Only absolute HTTP(S) URLs are accepted. CSV values are treated as untrusted data, not instructions. The endpoint is intended for a trusted development workspace; production use requires authenticated, tenant-scoped authorization and rate limiting.
