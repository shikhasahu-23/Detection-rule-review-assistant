"""Versioned platform-specific generation contracts.

The contracts describe the output dialect and safety constraints. They are prompt
guidance, not vendor compiler integrations.
"""
from dataclasses import dataclass

from app.schemas.detection import TargetPlatform


@dataclass(frozen=True)
class PlatformContract:
    platform: TargetPlatform
    prompt_version: str
    instructions: str
    validation_scope: str


CONTRACTS = {
    TargetPlatform.SPLUNK: PlatformContract(
        platform=TargetPlatform.SPLUNK,
        prompt_version="splunk-v1",
        instructions=(
            "Output native Splunk SPL only. Begin with a valid search command or "
            "generating command. Use only telemetry fields supplied in the intent. "
            "Use pipe-delimited SPL commands and explicit time-independent logic. "
            "Do not invent index names, sourcetypes, macros, lookups, or field aliases. "
            "If the intent lacks a required field, state that limitation in the query "
            "name only and keep the query conservative."
        ),
        validation_scope="entrypoint and delimiter checks; execute in a representative Splunk environment",
    ),
    TargetPlatform.SENTINEL: PlatformContract(
        platform=TargetPlatform.SENTINEL,
        prompt_version="sentinel-v1",
        instructions=(
            "Output native Microsoft Sentinel KQL only. Start with a tabular source "
            "and use KQL pipe operators. Use only tables and columns explicitly "
            "provided by the intent; do not invent custom tables or schema fields. "
            "Prefer explicit time windows only when supported by the intent."
        ),
        validation_scope="pipeline shape and delimiter checks; compile against target workspace schema",
    ),
    TargetPlatform.CHRONICLE: PlatformContract(
        platform=TargetPlatform.CHRONICLE,
        prompt_version="chronicle-yaral2-v1",
        instructions=(
            "Output Chronicle YARA-L 2.0 only. Include rule, meta when useful, events, "
            "and condition sections. Use UDM event fields only when supported by the "
            "provided telemetry. Avoid unsupported outcome or match constructs. "
            "Do not invent UDM fields."
        ),
        validation_scope="required section and delimiter checks; compile against Chronicle UDM",
    ),
    TargetPlatform.CROWDSTRIKE: PlatformContract(
        platform=TargetPlatform.CROWDSTRIKE,
        prompt_version="crowdstrike-cautious-v1",
        instructions=(
            "CrowdStrike Falcon Next-Gen SIEM query grammar is not enabled for strict "
            "generation in this release. Do not fabricate a query or assert syntax "
            "validity. If the supplied intent does not include an approved query "
            "template and field contract, return a short non-operational draft that "
            "clearly says vendor grammar verification is required."
        ),
        validation_scope="grammar verification pending; manual vendor validation required",
    ),
}


def get_platform_contract(platform: TargetPlatform) -> PlatformContract:
    return CONTRACTS[platform]
