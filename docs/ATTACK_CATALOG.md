# MITRE ATT&CK Enterprise catalog

ThreatWeave can synchronize the official MITRE ATT&CK Enterprise STIX bundle from the fixed MITRE ATT&CK data repository. The connector imports attack-pattern objects with a valid `mitre-attack` external reference, preserving technique/sub-technique ID, name, description, tactics, platforms, deprecated/revoked state, source URL and modified time.

Endpoint: `POST /api/v1/intelligence/feeds/mitre-attack/sync`.

The catalog is idempotently upserted by ATT&CK external ID. Deprecated and revoked techniques remain available for historical references; consumers should treat their flags as lifecycle metadata. The bundle is untrusted reference data and is never executed. This increment provides a local technique catalog; automatic technique recommendation and evidence-backed mapping to detections remain future work.
