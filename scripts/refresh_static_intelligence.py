#!/usr/bin/env python3
"""Refresh public ThreatWeave static intelligence datasets from authoritative feeds."""
from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "frontend" / "public" / "data"
USER_AGENT = "ThreatWeave-Static-Intel/1.0 (+https://github.com/shikhasahu-23/ThreatWeave)"


def get_json(url: str) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=90) as response:
        return json.loads(response.read().decode("utf-8"))


def write_json(name: str, value: object) -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    (ROOT / name).write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")


def refresh_kev() -> tuple[list[dict], dict]:
    payload = get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    now = datetime.now(timezone.utc).isoformat()
    rows = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cveID")
        if not cve:
            continue
        rows.append({
            "id": cve,
            "indicator_type": "cve",
            "value": cve,
            "confidence": 100,
            "cvss_score": None,
            "severity": "high" if item.get("knownRansomwareCampaignUse") == "Known" else "medium",
            "status": "active",
            "description": item.get("shortDescription") or item.get("vulnerabilityName") or "",
            "tags": ["cisa-kev", "known-exploited"] + (["known-ransomware-use"] if item.get("knownRansomwareCampaignUse") == "Known" else []),
            "sources": [{
                "name": "CISA Known Exploited Vulnerabilities",
                "reference": cve,
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            }],
            "vendor_project": item.get("vendorProject"),
            "product": item.get("product"),
            "date_added": item.get("dateAdded"),
            "due_date": item.get("dueDate"),
            "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"),
            "last_seen": now,
        })
    return rows, {"name": "CISA KEV", "status": "succeeded", "last_run": now, "records_seen": len(rows), "indicators_created": len(rows)}


def refresh_attack() -> tuple[list[dict], dict]:
    bundle = get_json("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json")
    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        external_id = next((ref.get("external_id") for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"), None)
        if not external_id:
            continue
        techniques.append({
            "id": obj.get("id"),
            "external_id": external_id,
            "name": obj.get("name", ""),
            "description": (obj.get("description") or "")[:500],
            "platforms": obj.get("x_mitre_platforms", []),
            "tactics": sorted({phase.get("phase_name", "").replace("-", " ").title() for phase in obj.get("kill_chain_phases", []) if phase.get("kill_chain_name") == "mitre-attack"}),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "revoked": False,
            "deprecated": False,
            "source_url": next((ref.get("url") for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"), ""),
        })
    techniques.sort(key=lambda row: row["external_id"])
    now = datetime.now(timezone.utc).isoformat()
    return techniques, {"name": "MITRE ATT&CK Enterprise", "status": "succeeded", "last_run": now, "records_seen": len(techniques), "indicators_created": 0}


def main() -> None:
    indicators, kev_feed = refresh_kev()
    techniques, attack_feed = refresh_attack()
    now = datetime.now(timezone.utc).isoformat()
    write_json("indicators.json", indicators)
    write_json("attack-techniques.json", techniques)
    write_json("feeds.json", [kev_feed, attack_feed])
    write_json("summary.json", {
        "indicators_total": len(indicators),
        "active_indicators": len(indicators),
        "sources_total": 2,
        "latest_run": {"source": "CISA KEV + MITRE ATT&CK", "status": "succeeded", "started_at": now, "records_seen": len(indicators) + len(techniques), "indicators_created": len(indicators)},
    })
    print(f"Updated {len(indicators)} CISA KEV records and {len(techniques)} MITRE ATT&CK techniques")


if __name__ == "__main__":
    main()
