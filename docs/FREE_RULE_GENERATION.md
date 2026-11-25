# Free rule generation

ThreatWeave's default rule generator is deterministic and does not call an external AI API.

## How to use it

1. Open **Rule generator**.
2. Create a detection intent with a clear name, description and behavior.
3. Add the MITRE ATT&CK technique IDs when known.
4. Select Splunk, Sentinel or Chronicle.
5. Save the intent, select it in **Generate candidates**, and generate.
6. Inspect the query and validation warnings. Run the offline checks from **Validation**.
7. Keep the rule in the review queue until a human has confirmed field mappings and tested it in the target SIEM.

## What the free templates do

- **Splunk:** starts a search using only the required telemetry fields supplied in the intent; adds conservative behavior filters for a small set of recognizable command/tool keywords.
- **Sentinel:** maps common endpoint/network field names to the documented DeviceProcessEvents columns.
- **Chronicle:** creates a conservative YARA-L 2.0 process-event skeleton.
- **CrowdStrike:** intentionally disabled until the target query grammar can be verified.

The templates are not an LLM. They do not infer missing telemetry, guarantee detection efficacy, or compile against your SIEM. Validation is static and every candidate remains non-deployable until reviewed.

## Automation and cost

The scheduled GitHub Actions workflow runs the existing intelligence pipeline every Monday at 08:00 India time (02:30 UTC). It can also be started manually from **GitHub → Actions → Scheduled rule generation → Run workflow**. The workflow does not use an OpenAI key. GitHub Actions usage and Render hosting remain subject to the limits and billing of the plans already attached to those accounts.
