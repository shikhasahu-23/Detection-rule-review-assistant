#!/usr/bin/env python3
"""Build a small, attributed public cyber-news snapshot from publisher RSS feeds."""
from __future__ import annotations

import json
import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html import unescape
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "frontend" / "public" / "data"
UA = "ThreatWeave-News-Snapshot/1.0 (+https://github.com/shikhasahu-23/ThreatWeave)"
SOURCES = [
    ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
]

class TextOnly(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
    def handle_data(self, data: str) -> None:
        self.parts.append(data)

def plain(value: str) -> str:
    parser = TextOnly()
    try:
        parser.feed(unescape(value or ""))
    except Exception:
        pass
    return re.sub(r"\s+", " ", " ".join(parser.parts)).strip()

def tag_text(node: ET.Element, names: tuple[str, ...]) -> str:
    for child in node.iter():
        tag = child.tag.split("}")[-1].lower()
        if tag in names and child.text:
            return child.text.strip()
    return ""

def classify(headline: str, summary: str) -> tuple[str, str]:
    text = f"{headline} {summary}".lower()
    if any(word in text for word in ("actively exploited", "zero-day", "zero day", "ransomware", "critical vulnerability", "remote code execution")):
        severity = "critical" if any(word in text for word in ("actively exploited", "zero-day", "zero day", "ransomware")) else "high"
    elif any(word in text for word in ("vulnerability", "breach", "data leak", "malware", "phishing", "botnet", "exploit", "hacked", "stolen", "unauthorized access", "compromise")):
        severity = "high"
    elif any(word in text for word in ("patch", "security update", "advisory", "cyberattack")):
        severity = "medium"
    else:
        severity = "low"
    if any(word in text for word in ("ransomware", "data breach", "data leak", "hacked", "stolen", "unauthorized access")):
        impact = "Potential operational disruption, data exposure or recovery costs; validate affected organisations and scope in the source advisory."
    elif any(word in text for word in ("zero-day", "actively exploited", "remote code execution", "exploit")):
        impact = "Potential unauthorised access or code execution on affected systems; verify exposure and patch status."
    elif any(word in text for word in ("malware", "infostealer", "spyware", "backdoor", "botnet")):
        impact = "Potential endpoint compromise, data theft or unauthorised activity; review affected hosts, execution telemetry and network connections."
        impact = "Potential credential theft or account compromise; review identity and email telemetry."
    elif any(word in text for word in ("vulnerability", "patch", "security update")):
        impact = "Potential exposure of affected products; confirm versions and apply vendor guidance."
    else:
        impact = "Review the original report to determine relevance to your environment and defensive actions."
    return severity, impact

def enrich(headline: str, summary: str) -> dict:
    """Extract cautious, source-text-backed context; never invent attribution."""
    text = f"{headline}. {summary}"
    lower = text.lower()
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", text, re.I)))
    actors = sorted(set(re.findall(r"\b(?:APT\s?\d{1,3}|FIN\d{1,3}|Lazarus Group|Sandworm|Volt Typhoon|Scattered Spider|Cl0p|LockBit|Akira|Rhysida|Qilin|BlackCat)\b", text, re.I)))
    malware = sorted(set(re.findall(r"\b(?:ransomware|infostealer|trojan|backdoor|botnet|rootkit|spyware|loader)\b", text, re.I)))
    event = "Malware / intrusion" if any(x in lower for x in ("malware", "ransomware", "backdoor", "botnet", "infostealer", "malicious package", "loader")) else "Data breach / exposure" if any(x in lower for x in ("breach", "data leak", "stolen", "exposed", "unauthorized access")) else "Vulnerability / exploitation" if any(x in lower for x in ("cve-", "vulnerability", "zero-day", "zero day", "exploit")) else "Security advisory / research"
    vector = []
    for term, label in (("phishing", "Phishing"), ("ransomware", "Ransomware"), ("remote code execution", "Remote code execution"), ("sql injection", "SQL injection"), ("zero-day", "Zero-day exploitation"), ("supply chain", "Software supply chain"), ("credential", "Credential compromise"), ("malicious package", "Malicious software package"), ("path traversal", "Path traversal")):
        if term in lower:
            vector.append(label)
    action = []
    if cves or "vulnerability" in lower or "zero-day" in lower:
        action += ["Identify affected product versions and internet-facing assets", "Apply the vendor fix or documented mitigation; track remediation"]
    if any(x in lower for x in ("breach", "stolen", "exposed", "unauthorized access")):
        action += ["Review access, identity and data-exfiltration logs for the reported period", "Validate the affected data and follow the organisation's incident-response process"]
    if any(x in lower for x in ("phishing", "credential", "infostealer")):
        action += ["Hunt for suspicious sign-ins, mailbox rules and credential theft indicators"]
    if not action:
        action = ["Read the source advisory and assess relevance to your environment"]
    return {
        "event_type": event,
        "related_cves": cves,
        "mentioned_threat_actors": actors,
        "malware_or_tooling": malware,
        "attack_vectors": vector,
        "defender_actions": list(dict.fromkeys(action)),
        "analysis_note": "Extracted from the published headline and RSS description. Missing fields mean the source snippet did not provide enough evidence; verify details in the original report.",
    }

def main() -> None:
    now = datetime.now(timezone.utc).isoformat()
    items: dict[str, dict] = {}
    failed: list[str] = []
    statuses: list[dict] = []
    for source, url in SOURCES:
        try:
            request = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml"})
            with urllib.request.urlopen(request, timeout=35) as response:
                root = ET.fromstring(response.read())
            entries = [node for node in root.iter() if node.tag.split("}")[-1].lower() in ("item", "entry")]
            count = 0
            for entry in entries:
                headline = plain(tag_text(entry, ("title",)))
                link = tag_text(entry, ("link",))
                if not link:
                    for child in entry:
                        if child.tag.split("}")[-1].lower() == "link":
                            link = child.attrib.get("href", "")
                            if link:
                                break
                description = plain(tag_text(entry, ("encoded", "description", "summary", "content")))
                if not headline or not link:
                    continue
                published_raw = tag_text(entry, ("pubdate", "published", "updated", "date"))
                try:
                    published = parsedate_to_datetime(published_raw).astimezone(timezone.utc).isoformat()
                except (TypeError, ValueError, OverflowError):
                    try:
                        published = datetime.fromisoformat(published_raw.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
                    except (ValueError, TypeError):
                        published = now
                severity, impact = classify(headline, description)
                key = link.split("#", 1)[0]
                items[key] = {
                    "id": key, "headline": headline[:300],
                    "summary": (description or headline)[:1200],
                    "impact": impact, "severity": severity, **enrich(headline, description), "source": source,
                    "url": link, "published_at": published,
                }
                count += 1
            statuses.append({"name": source, "status": "succeeded", "records_seen": count})
        except Exception as exc:
            failed.append(source)
            statuses.append({"name": source, "status": "failed", "error": str(exc)[:240]})
            print(f"WARNING: {source} RSS fetch failed: {exc}")
    rows = sorted(items.values(), key=lambda item: item["published_at"], reverse=True)[:120]
    ROOT.mkdir(parents=True, exist_ok=True)
    output = ROOT / "cyber-news.json"
    if not rows and output.exists():
        previous = json.loads(output.read_text(encoding="utf-8"))
        rows = previous.get("items", [])
        print("No RSS source responded; preserving the last published cyber-news snapshot.")
    payload = {"fetched_at": now, "items": rows, "sources_failed": failed, "source_status": statuses, "classification_note": "Severity is a keyword-based triage label, not a CVSS score or verified incident rating. Impact is a generic analyst prompt; read the linked source."}
    (ROOT / "cyber-news.json").write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"Published {len(rows)} cyber-news stories from {len(SOURCES) - len(failed)} of {len(SOURCES)} RSS sources.")

if __name__ == "__main__":
    main()
