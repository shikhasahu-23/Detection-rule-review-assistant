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
    ("CISA Advisories", "https://www.cisa.gov/news-events/cybersecurity-advisories.xml"),
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
    return re.sub(r"\\s+", " ", " ".join(parser.parts)).strip()

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
    elif any(word in text for word in ("vulnerability", "breach", "data leak", "malware", "phishing", "botnet", "exploit")):
        severity = "high"
    elif any(word in text for word in ("patch", "security update", "advisory", "cyberattack")):
        severity = "medium"
    else:
        severity = "low"
    if any(word in text for word in ("ransomware", "data breach", "data leak")):
        impact = "Potential operational disruption, data exposure or recovery costs; validate affected organisations and scope in the source advisory."
    elif any(word in text for word in ("zero-day", "actively exploited", "remote code execution", "exploit")):
        impact = "Potential unauthorised access or code execution on affected systems; verify exposure and patch status."
    elif any(word in text for word in ("phishing", "credential", "identity")):
        impact = "Potential credential theft or account compromise; review identity and email telemetry."
    elif any(word in text for word in ("vulnerability", "patch", "security update")):
        impact = "Potential exposure of affected products; confirm versions and apply vendor guidance."
    else:
        impact = "Review the original report to determine relevance to your environment and defensive actions."
    return severity, impact

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
                    "impact": impact, "severity": severity, "source": source,
                    "url": link, "published_at": published,
                }
                count += 1
            statuses.append({"name": source, "status": "succeeded", "records_seen": count})
        except Exception as exc:
            failed.append(source)
            statuses.append({"name": source, "status": "failed", "error": str(exc)[:240]})
            print(f"WARNING: {source} RSS fetch failed: {exc}")
    rows = sorted(items.values(), key=lambda item: item["published_at"], reverse=True)[:120]
    if not rows:
        raise RuntimeError("No RSS publisher returned articles; refusing to replace the last good cyber-news snapshot.")
    ROOT.mkdir(parents=True, exist_ok=True)
    payload = {"fetched_at": now, "items": rows, "sources_failed": failed, "source_status": statuses, "classification_note": "Severity is a keyword-based triage label, not a CVSS score or verified incident rating. Impact is a generic analyst prompt; read the linked source."}
    (ROOT / "cyber-news.json").write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\\n", encoding="utf-8")
    print(f"Published {len(rows)} cyber-news stories from {len(SOURCES) - len(failed)} of {len(SOURCES)} RSS sources.")

if __name__ == "__main__":
    main()
