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
    if any(word in text for word in ("actively exploited", "zero-day", "zero day", "ransomware")):
        severity = "critical"
    elif any(word in text for word in ("vulnerability", "breach", "data leak", "malware", "phishing", "botnet", "exploit", "hacked", "stolen", "unauthorized access", "compromise")):
        severity = "high"
    elif any(word in text for word in ("patch", "security update", "advisory", "cyberattack")):
        severity = "medium"
    else:
        severity = "low"

    # Keep impact aligned with the actual story category; never overwrite a
    # malware-specific assessment with a generic credential-theft statement.
    if any(word in text for word in ("ransomware", "data breach", "data leak", "hacked", "stolen", "unauthorized access")):
        impact = "The report describes data theft, exposure or service disruption. Establish the affected data/systems and whether the activity touches your environment."
    elif any(word in text for word in ("malware", "infostealer", "spyware", "backdoor", "botnet", "malicious extension", "loader")):
        impact = "The report describes malicious code or tooling. Assess whether the named delivery path, software or affected accounts exist in your environment."
    elif any(word in text for word in ("zero-day", "actively exploited", "remote code execution", "exploit")):
        impact = "The report describes exploitation risk. Identify exposed product versions and confirm vendor mitigation and patch status."
    elif any(word in text for word in ("vulnerability", "patch", "security update")):
        impact = "The report concerns a product weakness or security fix. Check whether affected versions are deployed and prioritise vendor remediation guidance."
    elif "phishing" in text:
        impact = "The report describes a social-engineering route. Review email/web controls and identity telemetry for matching activity."
    else:
        impact = "The feed summary does not establish a direct operational impact. Review the original report before assigning relevance or priority."
    return severity, impact


def enrich(headline: str, summary: str) -> dict:
    """Extract story-specific facts and defensive checks from the available RSS text."""
    text = f"{headline}. {summary}"
    lower = text.lower()
    cves = sorted(set(re.findall(r"CVE-\\d{4}-\\d{4,}", text, re.I)))
    actor_pattern = r"\\b(?:APT\\s?\\d{1,3}|FIN\\d{1,3}|Lazarus Group|Sandworm|Volt Typhoon|Scattered Spider|Cl0p|LockBit|Akira|Rhysida|Qilin|BlackCat|North Korea)\\b"
    actors = sorted(set(re.findall(actor_pattern, text, re.I)))
    malware_terms = ("Remus", "PolinRider", "SYS01", "SYS010", "LockBit", "Akira", "Qilin", "BlackCat")
    named_tools = sorted({name for name in malware_terms if re.search(r"\\b" + re.escape(name) + r"\\b", text, re.I)})
    malware_types = sorted(set(re.findall(r"\\b(?:ransomware|infostealer|trojan|backdoor|botnet|rootkit|spyware|loader)\\b", text, re.I)))
    malware = named_tools + [term for term in malware_types if term.lower() not in {x.lower() for x in named_tools}]

    if any(x in lower for x in ("malware", "ransomware", "backdoor", "botnet", "infostealer", "malicious package", "loader", "malicious extension")):
        event = "Malware / intrusion"
    elif any(x in lower for x in ("breach", "data leak", "stolen", "exposed", "unauthorized access")):
        event = "Data breach / exposure"
    elif any(x in lower for x in ("cve-", "vulnerability", "zero-day", "zero day", "exploit")):
        event = "Vulnerability / exploitation"
    elif "phishing" in lower:
        event = "Phishing / social engineering"
    else:
        event = "Security research / advisory"

    vectors = []
    for term, label in (
        ("fake google sheets extension", "Trojanised browser extension"),
        ("chrome extension", "Malicious Chrome extension"),
        ("github repositories", "Compromised / poisoned GitHub repositories"),
        ("python loader", "Python loader execution"),
        ("meta ads", "Malvertising / malicious advertisements"),
        ("phishing", "Phishing"),
        ("ransomware", "Ransomware"),
        ("remote code execution", "Remote code execution"),
        ("sql injection", "SQL injection"),
        ("zero-day", "Zero-day exploitation"),
        ("supply chain", "Software supply-chain compromise"),
        ("credential", "Credential theft / compromise"),
        ("malicious package", "Malicious software package"),
        ("path traversal", "Path traversal"),
    ):
        if term in lower and label not in vectors:
            vectors.append(label)

    surfaces = []
    for term, label in (
        ("gmail", "Gmail / email accounts"),
        ("outlook", "Outlook / email accounts"),
        ("chrome", "Chrome browsers and extensions"),
        ("browser", "Managed browser configuration"),
        ("github", "GitHub repositories and developer workflows"),
        ("python", "Python projects and dependencies"),
        ("microsoft 365", "Microsoft 365"),
        ("vpn", "Remote-access infrastructure"),
        ("firewall", "Network perimeter"),
    ):
        if term in lower and label not in surfaces:
            surfaces.append(label)

    actions = []
    if "chrome extension" in lower or "browser" in lower:
        actions += ["Inventory browser extensions and enterprise browser policies; identify extensions installed outside the approved list."]
    if "gmail" in lower or "outlook" in lower:
        actions += ["Review unusual mailbox access, OAuth grants, forwarding rules and sign-ins for affected accounts."]
    if "github" in lower or "python" in lower:
        actions += ["Inspect affected repositories and Python dependency/import paths for unexpected loader code; verify package provenance before execution."]
    if "meta ads" in lower or "malvertising" in lower:
        actions += ["Review browser download and endpoint execution telemetry for activity originating from advertising or redirected landing pages."]
    if "phishing" in lower:
        actions += ["Hunt for matching sender, URL and attachment indicators; review user clicks and subsequent authentication events."]
    if cves or "vulnerability" in lower or "zero-day" in lower:
        actions += ["Identify affected product versions and exposed assets; apply the vendor's fix or documented mitigation."]
    if any(x in lower for x in ("breach", "stolen", "exposed", "unauthorized access")):
        actions += ["Review access and data-transfer logs for the reported period; preserve relevant evidence and follow incident-response procedures."]
    if not actions:
        actions = ["Read the linked report and identify the affected technology, observable artefacts and recommended mitigations before creating a hunt."]
    return {
        "event_type": event,
        "related_cves": cves,
        "mentioned_threat_actors": actors,
        "malware_or_tooling": malware,
        "attack_vectors": vectors,
        "affected_surfaces": surfaces,
        "defender_actions": list(dict.fromkeys(actions)),
        "analyst_takeaway": (summary or headline).strip()[:900],
        "analysis_note": "Facts are extracted from the publisher headline and RSS description. SOC actions are suggested checks, not claims that the activity is present in your environment. Confirm technical details in the linked report.",
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
    payload = {"fetched_at": now, "items": rows, "sources_failed": failed, "source_status": statuses, "classification_note": "Severity is a preliminary keyword-based triage label, not a CVSS score or verified incident rating. Impact and SOC checks are derived from the publisher headline and RSS description; validate against the linked report."}
    (ROOT / "cyber-news.json").write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"Published {len(rows)} cyber-news stories from {len(SOURCES) - len(failed)} of {len(SOURCES)} RSS sources.")

if __name__ == "__main__":
    main()
