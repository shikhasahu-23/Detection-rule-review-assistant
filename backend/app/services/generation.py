"""Free, deterministic SIEM and Sigma templates; no external AI service required."""
from __future__ import annotations

import json
import re
from typing import Protocol

from app.schemas.detection import TargetPlatform
from app.schemas.generation import GeneratedRule


class GenerationUnavailable(Exception):
    """The requested platform or telemetry is not supported by the free templates."""


class GenerationProvider(Protocol):
    def generate(self, intent: dict, platform: TargetPlatform) -> GeneratedRule: ...


_SENTINEL_FIELDS = {
    "process_name": "FileName", "command_line": "ProcessCommandLine",
    "process_path": "FolderPath", "parent_process_name": "InitiatingProcessFileName",
    "parent_command_line": "InitiatingProcessCommandLine", "destination_ip": "RemoteIP",
    "destination_domain": "RemoteUrl", "user": "AccountName",
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
        raise GenerationUnavailable("Add at least one required telemetry field before generating.")
    return fields[:20]


def _terms(intent: dict) -> list[str]:
    text = " ".join(str(intent.get(key, "")) for key in ("title", "description", "behavior")).lower()
    return [term for term in _BEHAVIOR_TERMS if term in text][:4]


def _ioc_values(intent: dict) -> tuple[str, list[str]]:
    kind = str(intent.get("indicator_type") or "").lower()
    values = sorted({str(value).strip() for value in intent.get("indicator_values", []) if str(value).strip()})
    if not values:
        raise GenerationUnavailable("No active IOC values were supplied.")
    if kind not in {"ip", "ipv4", "ipv6", "domain", "hostname", "url", "hash", "file_hash"}:
        raise GenerationUnavailable(f"IOC type '{kind}' has no verified event-field mapping yet.")
    return kind, values


def _sigma(kind: str, values: list[str], title: str) -> str:
    if kind in {"ip", "ipv4", "ipv6"}:
        fields, category = {"DestinationIp": values, "SourceIp": values}, "network_connection"
    elif kind in {"domain", "hostname"}:
        fields, category = {"DestinationHostname": values, "QueryName": values}, "dns"
    elif kind == "url":
        fields, category = {"Url": values}, "proxy"
    else:
        fields, category = {"Hashes|contains": values}, "process_creation"
    lines = [
        "title: " + json.dumps(title),
        'id: "b6d1a8d4-5b22-4b4e-9a3e-7f8c2e5a1d90"',
        "status: experimental",
        "description: " + json.dumps(f"Matches {len(values)} active {kind} threat-intelligence indicators."),
        "author: ThreatWeave",
        "logsource:",
        f"    category: {category}",
        "detection:",
        "    selection:",
    ]
    for field, entries in fields.items():
        lines.append(f"        {field}:")
        lines.extend("            - " + json.dumps(value) for value in entries)
    lines.extend(["    condition: selection", "falsepositives:", "    - Validate against local telemetry and allowlists", "level: high"])
    return "\n".join(lines)


def _ioc_query(kind: str, values: list[str], platform: TargetPlatform) -> str:
    quoted = [json.dumps(value) for value in values]
    if kind in {"ip", "ipv4", "ipv6"}:
        if platform is TargetPlatform.SPLUNK:
            return "search (" + " OR ".join(f"src_ip={v} OR dest_ip={v}" for v in quoted) + ")"
        if platform is TargetPlatform.SENTINEL:
            return "DeviceNetworkEvents\n| where RemoteIP in (" + ", ".join(quoted) + ")\n| project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName"
        expr = " or ".join(f"$e.principal.ip = {v} or $e.target.ip = {v}" for v in quoted)
    elif kind in {"domain", "hostname"}:
        if platform is TargetPlatform.SPLUNK:
            return "search (" + " OR ".join(f"dest_domain={v} OR query={v}" for v in quoted) + ")"
        if platform is TargetPlatform.SENTINEL:
            return "DeviceNetworkEvents\n| where RemoteUrl has_any (" + ", ".join(quoted) + ")\n| project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName"
        expr = " or ".join(f"$e.target.hostname = {v}" for v in quoted)
    elif kind == "url":
        if platform is TargetPlatform.SPLUNK:
            return "search (" + " OR ".join(f"url={v} OR uri={v}" for v in quoted) + ")"
        if platform is TargetPlatform.SENTINEL:
            return "DeviceNetworkEvents\n| where RemoteUrl in (" + ", ".join(quoted) + ")\n| project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName"
        expr = " or ".join(f"$e.target.url = {v}" for v in quoted)
    else:
        if platform is TargetPlatform.SPLUNK:
            return "search (" + " OR ".join(f"file_hash={v} OR sha256={v} OR md5={v} OR sha1={v}" for v in quoted) + ")"
        if platform is TargetPlatform.SENTINEL:
            return "DeviceFileEvents\n| where SHA256 in (" + ", ".join(quoted) + ") or SHA1 in (" + ", ".join(quoted) + ")\n| project Timestamp, DeviceName, FileName, FolderPath, SHA256, SHA1"
        expr = " or ".join(f"$e.target.file.sha256 = {v} or $e.target.file.md5 = {v} or $e.target.file.sha1 = {v}" for v in quoted)
    name = re.sub(r"[^a-zA-Z0-9_]", "_", "threatweave_ioc_" + kind).strip("_")
    return (
        f"rule {name} {{\n  meta:\n    author = \"ThreatWeave\"\n"
        f'    description = "Active {kind} IOC matches; verify UDM field coverage"\n'
        "  events:\n    $e.metadata.event_type = \"NETWORK_CONNECTION\"\n"
        f"    ({expr})\n  condition:\n    $e\n}}"
    )


class TemplateGenerationProvider:
    """Build explainable query drafts from analyst-supplied fields or active IOCs."""

    provider_name = "free-template"
    model = "deterministic-v2"

    def generate(self, intent: dict, platform: TargetPlatform) -> GeneratedRule:
        title = str(intent.get("title") or "Detection intent").strip()[:160]
        if intent.get("indicator_values") is not None:
            kind, values = _ioc_values(intent)
            if platform is TargetPlatform.SIGMA:
                query = _sigma(kind, values, f"ThreatWeave active {kind} IOC coverage")
            elif platform in {TargetPlatform.SPLUNK, TargetPlatform.SENTINEL, TargetPlatform.CHRONICLE}:
                query = _ioc_query(kind, values, platform)
            else:
                raise GenerationUnavailable("CrowdStrike grammar verification is pending.")
            return GeneratedRule(name=f"Active {kind} IOC coverage — {platform.value.upper()}", query=query)

        fields, terms = _fields(intent), _terms(intent)
        suffix = f" ({', '.join(terms)})" if terms else " (telemetry baseline)"
        name = f"{title} — {platform.value.upper()} template"
        if platform is TargetPlatform.SPLUNK:
            query = "search " + " ".join(f"{field}=*" for field in fields)
            command_field = next((f for f in fields if f.lower() in {"command_line", "process_command_line"}), None)
            if command_field and terms:
                query += " | where " + " OR ".join(f'like(lower({command_field}), "%{term}%")' for term in terms)
            query += " | table " + " ".join(fields)
        elif platform is TargetPlatform.SENTINEL:
            mapped = list(dict.fromkeys(_SENTINEL_FIELDS.get(f.lower()) for f in fields if _SENTINEL_FIELDS.get(f.lower())))
            if not mapped:
                raise GenerationUnavailable("Sentinel template requires supported process/network fields.")
            query = "DeviceProcessEvents\n| where isnotempty(ProcessCommandLine)\n| project " + ", ".join(mapped)
        elif platform is TargetPlatform.CHRONICLE:
            query = (
                "rule threatweave_template_rule {\n  meta:\n    author = \"ThreatWeave\"\n"
                f'    description = "Free template for {title.replace(chr(34), chr(39))}"\n'
                '  events:\n    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
                "  condition:\n    $e\n}"
            )
        elif platform is TargetPlatform.SIGMA:
            query = _sigma("hash", ["replace-with-real-hash"], title)
        else:
            raise GenerationUnavailable("CrowdStrike query grammar verification is pending.")
        return GeneratedRule(name=name + suffix, query=query)


def get_generation_provider() -> GenerationProvider:
    return TemplateGenerationProvider()
