"""Free, deterministic detection-query templates; no external AI service required."""
from __future__ import annotations

import re
from typing import Protocol

from app.schemas.detection import TargetPlatform
from app.schemas.generation import GeneratedRule


class GenerationUnavailable(Exception):
    """The requested platform or telemetry is not supported by the free templates."""


class GenerationProvider(Protocol):
    def generate(self, intent: dict, platform: TargetPlatform) -> GeneratedRule: ...


# Map common intent field names to documented Microsoft Sentinel process columns.
_SENTINEL_FIELDS = {
    "process_name": "FileName",
    "command_line": "ProcessCommandLine",
    "process_path": "FolderPath",
    "parent_process_name": "InitiatingProcessFileName",
    "parent_command_line": "InitiatingProcessCommandLine",
    "destination_ip": "RemoteIP",
    "destination_domain": "RemoteUrl",
    "user": "AccountName",
}
_BEHAVIOR_TERMS = (
    "powershell", "rundll32", "regsvr32", "certutil", "bitsadmin",
    "wscript", "cscript", "mshta", "encodedcommand", "download",
    "invoke-webrequest", "frombase64string",
)


def _fields(intent: dict) -> list[str]:
    fields: list[str] = []
    for requirement in intent.get("required_telemetry", []):
        for value in requirement.get("required_fields", []):
            field = str(value).strip()
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field) and field not in fields:
                fields.append(field)
    if not fields:
        raise GenerationUnavailable(
            "Add at least one required telemetry field to this detection intent before generating a rule."
        )
    return fields[:20]


def _terms(intent: dict) -> list[str]:
    text = " ".join(str(intent.get(key, "")) for key in ("title", "description", "behavior")).lower()
    return [term for term in _BEHAVIOR_TERMS if term in text][:4]


class TemplateGenerationProvider:
    """Build conservative, explainable query drafts from analyst-supplied fields."""

    provider_name = "free-template"
    model = "deterministic-v1"

    def generate(self, intent: dict, platform: TargetPlatform) -> GeneratedRule:
        fields = _fields(intent)
        terms = _terms(intent)
        title = str(intent.get("title") or "Detection intent").strip()[:160]
        suffix = f" ({', '.join(terms)})" if terms else " (telemetry baseline)"
        name = f"{title} — {platform.value.upper()} template"

        if platform is TargetPlatform.SPLUNK:
            predicates = [f'{field}=*' for field in fields]
            query = "search " + " ".join(predicates)
            command_field = next((f for f in fields if f.lower() in {"command_line", "process_command_line"}), None)
            if command_field and terms:
                query += " | where " + " OR ".join(
                    f'like(lower({command_field}), "%{term}%")' for term in terms
                )
            query += " | table " + " ".join(fields)
        elif platform is TargetPlatform.SENTINEL:
            mapped = [_SENTINEL_FIELDS.get(field.lower()) for field in fields]
            mapped_fields = list(dict.fromkeys(value for value in mapped if value))
            if not mapped_fields:
                raise GenerationUnavailable(
                    "The free Sentinel template currently supports common process/network fields "
                    "(process_name, command_line, process_path, parent_process_name, "
                    "parent_command_line, destination_ip, destination_domain, user)."
                )
            query = "DeviceProcessEvents"
            command_field = "ProcessCommandLine" if "command_line" in fields else None
            if command_field:
                query += f"\n| where isnotempty({command_field})"
                if terms:
                    quoted = ", ".join(f'"{term}"' for term in terms)
                    query += f"\n| where {command_field} has_any ({quoted})"
            query += "\n| project " + ", ".join(mapped_fields)
        elif platform is TargetPlatform.CHRONICLE:
            command_filter = ""
            if "command_line" in fields and terms:
                command_filter = "\n  $e.target.process.command_line = /" + "|".join(
                    re.escape(term) for term in terms
                ) + "/"
            query = (
                "rule threatweave_template_rule {\n"
                "  meta:\n"
                '    author = "ThreatWeave"\n'
                f'    description = "Free template for {title.replace(chr(34), chr(39))}"\n'
                "  events:\n"
                '    $e.metadata.event_type = "PROCESS_LAUNCH"'
                f"{command_filter}\n"
                "  condition:\n"
                "    $e\n"
                "}"
            )
        else:
            raise GenerationUnavailable(
                "A verified free CrowdStrike query template is not available yet. "
                "Choose Splunk, Sentinel, or Chronicle instead."
            )

        # Keep the title honest: these are starting points, not verified detections.
        return GeneratedRule(name=name + suffix, query=query)


def get_generation_provider() -> GenerationProvider:
    """Use the free provider by default; never require an API key."""
    return TemplateGenerationProvider()
