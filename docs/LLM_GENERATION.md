# LLM-assisted detection generation

ThreatWeave uses a provider boundary and currently includes an OpenAI Chat Completions adapter. Configure the API service with:

- `OPENAI_API_KEY` — secret API key, supplied through the deployment secret manager or local untracked `.env`.
- `OPENAI_MODEL` — optional model name; defaults to `gpt-4.1-mini`.

The API endpoint is `POST /api/v1/detection-intents/{id}/generate`. The optional `target_platforms` array can select one or more platforms already listed in the intent. If omitted, all platforms in the intent are requested.

Generation produces candidate records only. Each response is passed through the static validation engine, stored with a platform-specific version and marked `candidate`; the validation report always keeps `is_deployable=false`. Generation does not approve, export or deploy a rule. The provider uses a fixed HTTPS endpoint, bounded request timeout and structured JSON response mode. Provider credentials are never returned by the API.

The CrowdStrike prompt explicitly avoids asserting unverified query grammar; vendor-specific compiler validation is still required before operational use. LLM output is untrusted and must be reviewed by an analyst.
